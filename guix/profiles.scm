;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2014, 2016 Alex Kost <alezost@gmail.com>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Sou Bunnbu <iyzsong@gmail.com>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Chris Marusich <cmmarusich@gmail.com>
;;;
;;; This file is part of GNU Guix.
;;;
;;; GNU Guix is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 3 of the License, or (at
;;; your option) any later version.
;;;
;;; GNU Guix is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

(define-module (guix profiles)
  #:use-module ((guix utils) #:hide (package-name->name+version))
  #:use-module ((guix build utils)
                #:select (package-name->name+version))
  #:use-module (guix records)
  #:use-module (guix packages)
  #:use-module (guix derivations)
  #:use-module (guix search-paths)
  #:use-module (guix gexp)
  #:use-module (guix monads)
  #:use-module (guix store)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-19)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:export (&profile-error
            profile-error?
            profile-error-profile
            &profile-not-found-error
            profile-not-found-error?
            &missing-generation-error
            missing-generation-error?
            missing-generation-error-generation

            manifest make-manifest
            manifest?
            manifest-entries

            <manifest-entry>              ; FIXME: eventually make it internal
            manifest-entry
            manifest-entry?
            manifest-entry-name
            manifest-entry-version
            manifest-entry-output
            manifest-entry-item
            manifest-entry-dependencies
            manifest-entry-search-paths

            manifest-pattern
            manifest-pattern?
            manifest-pattern-name
            manifest-pattern-version
            manifest-pattern-output

            manifest-remove
            manifest-add
            manifest-lookup
            manifest-installed?
            manifest-matching-entries

            manifest-transaction
            manifest-transaction?
            manifest-transaction-install
            manifest-transaction-remove
            manifest-transaction-install-entry
            manifest-transaction-remove-pattern
            manifest-transaction-null?
            manifest-perform-transaction
            manifest-transaction-effects

            profile-manifest
            package->manifest-entry
            packages->manifest
            %default-profile-hooks
            profile-derivation

            generation-number
            generation-numbers
            profile-generations
            relative-generation-spec->number
            relative-generation
            previous-generation-number
            generation-time
            generation-file-name
            switch-to-generation
            roll-back
            delete-generation))

;;; Commentary:
;;;
;;; Tools to create and manipulate profiles---i.e., the representation of a
;;; set of installed packages.
;;;
;;; Code:


;;;
;;; Condition types.
;;;

(define-condition-type &profile-error &error
  profile-error?
  (profile profile-error-profile))

(define-condition-type &profile-not-found-error &profile-error
  profile-not-found-error?)

(define-condition-type &missing-generation-error &profile-error
  missing-generation-error?
  (generation missing-generation-error-generation))


;;;
;;; Manifests.
;;;

(define-record-type <manifest>
  (manifest entries)
  manifest?
  (entries manifest-entries))                     ; list of <manifest-entry>

;; Convenient alias, to avoid name clashes.
(define make-manifest manifest)

(define-record-type* <manifest-entry> manifest-entry
  make-manifest-entry
  manifest-entry?
  (name         manifest-entry-name)              ; string
  (version      manifest-entry-version)           ; string
  (output       manifest-entry-output             ; string
                (default "out"))
  (item         manifest-entry-item)              ; package | store path
  (dependencies manifest-entry-dependencies       ; (store path | package)*
                (default '()))
  (search-paths manifest-entry-search-paths       ; search-path-specification*
                (default '())))

(define-record-type* <manifest-pattern> manifest-pattern
  make-manifest-pattern
  manifest-pattern?
  (name         manifest-pattern-name)            ; string
  (version      manifest-pattern-version          ; string | #f
                (default #f))
  (output       manifest-pattern-output           ; string | #f
                (default "out")))

(define (profile-manifest profile)
  "Return the PROFILE's manifest."
  (let ((file (string-append profile "/manifest")))
    (if (file-exists? file)
        (call-with-input-file file read-manifest)
        (manifest '()))))

(define* (package->manifest-entry package #:optional (output "out"))
  "Return a manifest entry for the OUTPUT of package PACKAGE."
  (let ((deps (map (match-lambda
                    ((label package)
                     (gexp-input package))
                    ((label package output)
                     (gexp-input package output)))
                   (package-transitive-propagated-inputs package))))
    (manifest-entry
     (name (package-name package))
     (version (package-version package))
     (output output)
     (item package)
     (dependencies (delete-duplicates deps))
     (search-paths (package-transitive-native-search-paths package)))))

(define (packages->manifest packages)
  "Return a list of manifest entries, one for each item listed in PACKAGES.
Elements of PACKAGES can be either package objects or package/string tuples
denoting a specific output of a package."
  (manifest
   (map (match-lambda
         ((package output)
          (package->manifest-entry package output))
         ((? package? package)
          (package->manifest-entry package)))
        packages)))

(define (manifest->gexp manifest)
  "Return a representation of MANIFEST as a gexp."
  (define (entry->gexp entry)
    (match entry
      (($ <manifest-entry> name version output (? string? path)
                           (deps ...) (search-paths ...))
       #~(#$name #$version #$output #$path
                 (propagated-inputs #$deps)
                 (search-paths #$(map search-path-specification->sexp
                                      search-paths))))
      (($ <manifest-entry> name version output (? package? package)
                           (deps ...) (search-paths ...))
       #~(#$name #$version #$output
                 (ungexp package (or output "out"))
                 (propagated-inputs #$deps)
                 (search-paths #$(map search-path-specification->sexp
                                      search-paths))))))

  (match manifest
    (($ <manifest> (entries ...))
     #~(manifest (version 2)
                 (packages #$(map entry->gexp entries))))))

(define (find-package name version)
  "Return a package from the distro matching NAME and possibly VERSION.  This
procedure is here for backward-compatibility and will eventually vanish."
  (define find-best-packages-by-name              ;break abstractions
    (module-ref (resolve-interface '(gnu packages))
                'find-best-packages-by-name))

   ;; Use 'find-best-packages-by-name' and not 'find-packages-by-name'; the
   ;; former traverses the module tree only once and then allows for efficient
   ;; access via a vhash.
   (match (find-best-packages-by-name name version)
     ((p _ ...) p)
     (_
      (match (find-best-packages-by-name name #f)
        ((p _ ...) p)
        (_ #f)))))

(define (sexp->manifest sexp)
  "Parse SEXP as a manifest."
  (define (infer-search-paths name version)
    ;; Infer the search path specifications for NAME-VERSION by looking up a
    ;; same-named package in the distro.  Useful for the old manifest formats
    ;; that did not store search path info.
    (let ((package (find-package name version)))
      (if package
          (package-native-search-paths package)
          '())))

  (match sexp
    (('manifest ('version 0)
                ('packages ((name version output path) ...)))
     (manifest
      (map (lambda (name version output path)
             (manifest-entry
              (name name)
              (version version)
              (output output)
              (item path)
              (search-paths (infer-search-paths name version))))
           name version output path)))

    ;; Version 1 adds a list of propagated inputs to the
    ;; name/version/output/path tuples.
    (('manifest ('version 1)
                ('packages ((name version output path deps) ...)))
     (manifest
      (map (lambda (name version output path deps)
             ;; Up to Guix 0.7 included, dependencies were listed as ("gmp"
             ;; "/gnu/store/...-gmp") for instance.  Discard the 'label' in
             ;; such lists.
             (let ((deps (match deps
                           (((labels directories) ...)
                            directories)
                           ((directories ...)
                            directories))))
               (manifest-entry
                 (name name)
                 (version version)
                 (output output)
                 (item path)
                 (dependencies deps)
                 (search-paths (infer-search-paths name version)))))
           name version output path deps)))

    ;; Version 2 adds search paths and is slightly more verbose.
    (('manifest ('version 2 minor-version ...)
                ('packages ((name version output path
                                  ('propagated-inputs deps)
                                  ('search-paths search-paths)
                                  extra-stuff ...)
                            ...)))
     (manifest
      (map (lambda (name version output path deps search-paths)
             (manifest-entry
               (name name)
               (version version)
               (output output)
               (item path)
               (dependencies deps)
               (search-paths (map sexp->search-path-specification
                                  search-paths))))
           name version output path deps search-paths)))
    (_
     (raise (condition
             (&message (message "unsupported manifest format")))))))

(define (read-manifest port)
  "Return the packages listed in MANIFEST."
  (sexp->manifest (read port)))

(define (entry-predicate pattern)
  "Return a procedure that returns #t when passed a manifest entry that
matches NAME/OUTPUT/VERSION.  OUTPUT and VERSION may be #f, in which case they
are ignored."
  (match pattern
    (($ <manifest-pattern> name version output)
     (match-lambda
      (($ <manifest-entry> entry-name entry-version entry-output)
       (and (string=? entry-name name)
            (or (not entry-output) (not output)
                (string=? entry-output output))
            (or (not version)
                (string=? entry-version version))))))))

(define (manifest-remove manifest patterns)
  "Remove entries for each of PATTERNS from MANIFEST.  Each item in PATTERNS
must be a manifest-pattern."
  (define (remove-entry pattern lst)
    (remove (entry-predicate pattern) lst))

  (make-manifest (fold remove-entry
                       (manifest-entries manifest)
                       patterns)))

(define (manifest-add manifest entries)
  "Add a list of manifest ENTRIES to MANIFEST and return new manifest.
Remove MANIFEST entries that have the same name and output as ENTRIES."
  (define (same-entry? entry name output)
    (match entry
      (($ <manifest-entry> entry-name _ entry-output _ ...)
       (and (equal? name entry-name)
            (equal? output entry-output)))))

  (make-manifest
   (append entries
           (fold (lambda (entry result)
                   (match entry
                     (($ <manifest-entry> name _ out _ ...)
                      (filter (negate (cut same-entry? <> name out))
                              result))))
                 (manifest-entries manifest)
                 entries))))

(define (manifest-lookup manifest pattern)
  "Return the first item of MANIFEST that matches PATTERN, or #f if there is
no match.."
  (find (entry-predicate pattern)
        (manifest-entries manifest)))

(define (manifest-installed? manifest pattern)
  "Return #t if MANIFEST has an entry matching PATTERN (a manifest-pattern),
#f otherwise."
  (->bool (manifest-lookup manifest pattern)))

(define (manifest-matching-entries manifest patterns)
  "Return all the entries of MANIFEST that match one of the PATTERNS."
  (define predicates
    (map entry-predicate patterns))

  (define (matches? entry)
    (any (lambda (pred)
           (pred entry))
         predicates))

  (filter matches? (manifest-entries manifest)))


;;;
;;; Manifest transactions.
;;;

(define-record-type* <manifest-transaction> manifest-transaction
  make-manifest-transaction
  manifest-transaction?
  (install manifest-transaction-install ; list of <manifest-entry>
           (default '()))
  (remove  manifest-transaction-remove  ; list of <manifest-pattern>
           (default '())))

(define (manifest-transaction-install-entry entry transaction)
  "Augment TRANSACTION's set of installed packages with ENTRY, a
<manifest-entry>."
  (manifest-transaction
   (inherit transaction)
   (install
    (cons entry (manifest-transaction-install transaction)))))

(define (manifest-transaction-remove-pattern pattern transaction)
  "Add PATTERN to TRANSACTION's list of packages to remove."
  (manifest-transaction
   (inherit transaction)
   (remove
    (cons pattern (manifest-transaction-remove transaction)))))

(define (manifest-transaction-null? transaction)
  "Return true if TRANSACTION has no effect---i.e., it neither installs nor
remove software."
  (match transaction
    (($ <manifest-transaction> () ()) #t)
    (($ <manifest-transaction> _ _)   #f)))

(define (manifest-transaction-effects manifest transaction)
  "Compute the effect of applying TRANSACTION to MANIFEST.  Return 4 values:
the list of packages that would be removed, installed, upgraded, or downgraded
when applying TRANSACTION to MANIFEST.  Upgrades are represented as pairs
where the head is the entry being upgraded and the tail is the entry that will
replace it."
  (define (manifest-entry->pattern entry)
    (manifest-pattern
      (name   (manifest-entry-name entry))
      (output (manifest-entry-output entry))))

  (let loop ((input     (manifest-transaction-install transaction))
             (install   '())
             (upgrade   '())
             (downgrade '()))
    (match input
      (()
       (let ((remove (manifest-transaction-remove transaction)))
         (values (manifest-matching-entries manifest remove)
                 (reverse install) (reverse upgrade) (reverse downgrade))))
      ((entry rest ...)
       ;; Check whether installing ENTRY corresponds to the installation of a
       ;; new package or to an upgrade.

       ;; XXX: When the exact same output directory is installed, we're not
       ;; really upgrading anything.  Add a check for that case.
       (let* ((pattern  (manifest-entry->pattern entry))
              (previous (manifest-lookup manifest pattern))
              (newer?   (and previous
                             (version>=? (manifest-entry-version entry)
                                         (manifest-entry-version previous)))))
         (loop rest
               (if previous install (cons entry install))
               (if (and previous newer?)
                   (alist-cons previous entry upgrade)
                   upgrade)
               (if (and previous (not newer?))
                   (alist-cons previous entry downgrade)
                   downgrade)))))))

(define (manifest-perform-transaction manifest transaction)
  "Perform TRANSACTION on MANIFEST and return the new manifest."
  (let ((install (manifest-transaction-install transaction))
        (remove  (manifest-transaction-remove transaction)))
    (manifest-add (manifest-remove manifest remove)
                  install)))


;;;
;;; Profiles.
;;;

(define (manifest-inputs manifest)
  "Return a list of <gexp-input> objects for MANIFEST."
  (append-map (match-lambda
               (($ <manifest-entry> name version output thing deps)
                ;; THING may be a package or a file name.  In the latter case,
                ;; assume it's already valid.  Ditto for DEPS.
                (cons (gexp-input thing output) deps)))
              (manifest-entries manifest)))

(define* (manifest-lookup-package manifest name #:optional version)
  "Return as a monadic value the first package or store path referenced by
MANIFEST that is named NAME and optionally has the given VERSION prefix, or #f
if not found."
  ;; Return as a monadic value the package or store path referenced by the
  ;; manifest ENTRY, or #f if not referenced.
  (define (entry-lookup-package entry)
    (define (find-among-inputs inputs)
      (find (lambda (input)
              (and (package? input)
                   (equal? name (package-name input))
                   (if version
                       (string-prefix? version (package-version input))
                       #t)))
            inputs))
    (define (find-among-store-items items)
      (find (lambda (item)
              (let-values (((name* version*)
                            (package-name->name+version
                             (store-path-package-name item))))
                (and (string=? name name*)
                     (if version
                         (string-prefix? version version*)
                         #t))))
            items))

    (with-monad %store-monad
      (match (manifest-entry-item entry)
        ((? package? package)
         (match (cons (list (package-name package) package)
                      (package-transitive-inputs package))
           (((labels inputs . _) ...)
            (return (find-among-inputs inputs)))))
        ((? string? item)
         (mlet %store-monad ((refs (references* item)))
           (return (find-among-store-items refs)))))))

  (anym %store-monad
        entry-lookup-package (manifest-entries manifest)))

(define (info-dir-file manifest)
  "Return a derivation that builds the 'dir' file for all the entries of
MANIFEST."
  (define texinfo                                 ;lazy reference
    (module-ref (resolve-interface '(gnu packages texinfo)) 'texinfo))
  (define gzip                                    ;lazy reference
    (module-ref (resolve-interface '(gnu packages compression)) 'gzip))

  (define build
    (with-imported-modules '((guix build utils))
      #~(begin
          (use-modules (guix build utils)
                       (srfi srfi-1) (srfi srfi-26)
                       (ice-9 ftw))

          (define (info-file? file)
            (or (string-suffix? ".info" file)
                (string-suffix? ".info.gz" file)))

          (define (info-files top)
            (let ((infodir (string-append top "/share/info")))
              (map (cut string-append infodir "/" <>)
                   (or (scandir infodir info-file?) '()))))

          (define (install-info info)
            (setenv "PATH" (string-append #+gzip "/bin")) ;for info.gz files
            (zero?
             (system* (string-append #+texinfo "/bin/install-info") "--silent"
                      info (string-append #$output "/share/info/dir"))))

          (mkdir-p (string-append #$output "/share/info"))
          (exit (every install-info
                       (append-map info-files
                                   '#$(manifest-inputs manifest)))))))

  (gexp->derivation "info-dir" build
                    #:local-build? #t
                    #:substitutable? #f))

(define (ghc-package-cache-file manifest)
  "Return a derivation that builds the GHC 'package.cache' file for all the
entries of MANIFEST, or #f if MANIFEST does not have any GHC packages."
  (define ghc                                     ;lazy reference
    (module-ref (resolve-interface '(gnu packages haskell)) 'ghc))

  (define build
    (with-imported-modules '((guix build utils))
      #~(begin
          (use-modules (guix build utils)
                       (srfi srfi-1) (srfi srfi-26)
                       (ice-9 ftw))

          (define ghc-name-version
            (let* ((base (basename #+ghc)))
              (string-drop base
                           (+ 1 (string-index base #\-)))))

          (define db-subdir
            (string-append "lib/" ghc-name-version "/package.conf.d"))

          (define db-dir
            (string-append #$output "/" db-subdir))

          (define (conf-files top)
            (let ((db (string-append top "/" db-subdir)))
              (if (file-exists? db)
                  (find-files db "\\.conf$")
                  '())))

          (define (copy-conf-file conf)
            (let ((base (basename conf)))
              (copy-file conf (string-append db-dir "/" base))))

          (system* (string-append #+ghc "/bin/ghc-pkg") "init" db-dir)
          (for-each copy-conf-file
                    (append-map conf-files
                                (delete-duplicates
                                 '#$(manifest-inputs manifest))))
          (let ((success
                 (zero?
                  (system* (string-append #+ghc "/bin/ghc-pkg") "recache"
                           (string-append "--package-db=" db-dir)))))
            (for-each delete-file (find-files db-dir "\\.conf$"))
            (exit success)))))

  (with-monad %store-monad
    ;; Don't depend on GHC when there's nothing to do.
    (if (any (cut string-prefix? "ghc" <>)
             (map manifest-entry-name (manifest-entries manifest)))
        (gexp->derivation "ghc-package-cache" build
                          #:local-build? #t
                          #:substitutable? #f)
        (return #f))))

(define (ca-certificate-bundle manifest)
  "Return a derivation that builds a single-file bundle containing the CA
certificates in the /etc/ssl/certs sub-directories of the packages in
MANIFEST.  Single-file bundles are required by programs such as Git and Lynx."
  ;; See <http://lists.gnu.org/archive/html/guix-devel/2015-02/msg00429.html>
  ;; for a discussion.

  (define glibc-utf8-locales                      ;lazy reference
    (module-ref (resolve-interface '(gnu packages base)) 'glibc-utf8-locales))

  (define build
    (with-imported-modules '((guix build utils))
      #~(begin
          (use-modules (guix build utils)
                       (rnrs io ports)
                       (srfi srfi-1)
                       (srfi srfi-26)
                       (ice-9 ftw)
                       (ice-9 match))

          (define (pem-file? file)
            (string-suffix? ".pem" file))

          (define (ca-files top)
            (let ((cert-dir (string-append top "/etc/ssl/certs")))
              (map (cut string-append cert-dir "/" <>)
                   (or (scandir cert-dir pem-file?) '()))))

          (define (concatenate-files files result)
            "Make RESULT the concatenation of all of FILES."
            (define (dump file port)
              (display (call-with-input-file file get-string-all)
                       port)
              (newline port))  ;required, see <https://bugs.debian.org/635570>

            (call-with-output-file result
              (lambda (port)
                (for-each (cut dump <> port) files))))

          ;; Some file names in the NSS certificates are UTF-8 encoded so
          ;; install a UTF-8 locale.
          (setenv "LOCPATH"
                  (string-append #+glibc-utf8-locales "/lib/locale/"
                                 #+(package-version glibc-utf8-locales)))
          (setlocale LC_ALL "en_US.utf8")

          (match (append-map ca-files '#$(manifest-inputs manifest))
            (()
             ;; Since there are no CA files, just create an empty directory.  Do
             ;; not create the etc/ssl/certs sub-directory, since that would
             ;; wrongfully lead to a message about 'SSL_CERT_DIR' needing to be
             ;; defined.
             (mkdir #$output)
             #t)
            ((ca-files ...)
             (let ((result (string-append #$output "/etc/ssl/certs")))
               (mkdir-p result)
               (concatenate-files ca-files
                                  (string-append result
                                                 "/ca-certificates.crt"))
               #t))))))

  (gexp->derivation "ca-certificate-bundle" build
                    #:local-build? #t
                    #:substitutable? #f))

(define (gtk-icon-themes manifest)
  "Return a derivation that unions all icon themes from manifest entries and
creates the GTK+ 'icon-theme.cache' file for each theme."
  (define gtk+  ; lazy reference
    (module-ref (resolve-interface '(gnu packages gtk)) 'gtk+))

  (mlet %store-monad ((%gtk+ (manifest-lookup-package manifest "gtk+"))
                      ;; XXX: Can't use gtk-update-icon-cache corresponding
                      ;; to the gtk+ referenced by 'manifest'.  Because
                      ;; '%gtk+' can be either a package or store path, and
                      ;; there's no way to get the "bin" output for the later.
                      (gtk-update-icon-cache
                       -> #~(string-append #+gtk+:bin
                                           "/bin/gtk-update-icon-cache")))

    (define build
      (with-imported-modules '((guix build utils)
                               (guix build union)
                               (guix build profiles)
                               (guix search-paths)
                               (guix records))
        #~(begin
            (use-modules (guix build utils)
                         (guix build union)
                         (guix build profiles)
                         (srfi srfi-26)
                         (ice-9 ftw))

            (let* ((destdir  (string-append #$output "/share/icons"))
                   (icondirs (filter file-exists?
                                     (map (cut string-append <> "/share/icons")
                                          '#$(manifest-inputs manifest)))))

              ;; Union all the icons.
              (mkdir-p (string-append #$output "/share"))
              (union-build destdir icondirs
                           #:log-port (%make-void-port "w"))

              ;; Update the 'icon-theme.cache' file for each icon theme.
              (for-each
               (lambda (theme)
                 (let ((dir (string-append destdir "/" theme)))
                   ;; Occasionally DESTDIR contains plain files, such as
                   ;; "abiword_48.png".  Ignore these.
                   (when (file-is-directory? dir)
                     (ensure-writable-directory dir)
                     (system* #+gtk-update-icon-cache "-t" dir "--quiet"))))
               (scandir destdir (negate (cut member <> '("." "..")))))))))

    ;; Don't run the hook when there's nothing to do.
    (if %gtk+
        (gexp->derivation "gtk-icon-themes" build
                          #:local-build? #t
                          #:substitutable? #f)
        (return #f))))

(define (gtk-im-modules manifest)
  "Return a derivation that builds the cache files for input method modules
for both major versions of GTK+."

  (mlet %store-monad ((gtk+   (manifest-lookup-package manifest "gtk+" "3"))
                      (gtk+-2 (manifest-lookup-package manifest "gtk+" "2")))

    (define (build gtk gtk-version)
      (let ((major (string-take gtk-version 1)))
        (with-imported-modules '((guix build utils)
                                 (guix build union)
                                 (guix build profiles)
                                 (guix search-paths)
                                 (guix records))
          #~(begin
              (use-modules (guix build utils)
                           (guix build union)
                           (guix build profiles)
                           (ice-9 popen)
                           (srfi srfi-1)
                           (srfi srfi-26))

              (let* ((prefix  (string-append "/lib/gtk-" #$major ".0/"
                                             #$gtk-version))
                     (query   (string-append #$gtk "/bin/gtk-query-immodules-"
                                             #$major ".0"))
                     (destdir (string-append #$output prefix))
                     (moddirs (cons (string-append #$gtk prefix "/immodules")
                                    (filter file-exists?
                                            (map (cut string-append <> prefix "/immodules")
                                                 '#$(manifest-inputs manifest)))))
                     (modules (append-map (cut find-files <> "\\.so$")
                                          moddirs)))

                ;; Generate a new immodules cache file.
                (mkdir-p (string-append #$output prefix))
                (let ((pipe    (apply open-pipe* OPEN_READ query modules))
                      (outfile (string-append #$output prefix
                                              "/immodules-gtk" #$major ".cache")))
                  (dynamic-wind
                    (const #t)
                    (lambda ()
                      (call-with-output-file outfile
                        (lambda (out)
                          (while (not (eof-object? (peek-char pipe)))
                            (write-char (read-char pipe) out))))
                      #t)
                    (lambda ()
                      (close-pipe pipe)))))))))

    ;; Don't run the hook when there's nothing to do.
    (let ((gexp #~(begin
                    #$(if gtk+   (build gtk+   "3.0.0")  #t)
                    #$(if gtk+-2 (build gtk+-2 "2.10.0") #t))))
      (if (or gtk+ gtk+-2)
          (gexp->derivation "gtk-im-modules" gexp
                            #:local-build? #t
                            #:substitutable? #f)
          (return #f)))))

(define (xdg-desktop-database manifest)
  "Return a derivation that builds the @file{mimeinfo.cache} database from
desktop files.  It's used to query what applications can handle a given
MIME type."
  (mlet %store-monad ((desktop-file-utils
                       (manifest-lookup-package
                        manifest "desktop-file-utils")))
    (define build
      (with-imported-modules '((guix build utils)
                               (guix build union))
        #~(begin
            (use-modules (srfi srfi-26)
                         (guix build utils)
                         (guix build union))
            (let* ((destdir (string-append #$output "/share/applications"))
                   (appdirs (filter file-exists?
                                    (map (cut string-append <>
                                              "/share/applications")
                                         '#$(manifest-inputs manifest))))
                   (update-desktop-database (string-append
                                             #+desktop-file-utils
                                             "/bin/update-desktop-database")))
              (mkdir-p (string-append #$output "/share"))
              (union-build destdir appdirs
                           #:log-port (%make-void-port "w"))
              (exit (zero? (system* update-desktop-database destdir)))))))

    ;; Don't run the hook when 'desktop-file-utils' is not referenced.
    (if desktop-file-utils
        (gexp->derivation "xdg-desktop-database" build
                          #:local-build? #t
                          #:substitutable? #f)
        (return #f))))

(define (xdg-mime-database manifest)
  "Return a derivation that builds the @file{mime.cache} database from manifest
entries.  It's used to query the MIME type of a given file."
  (define shared-mime-info  ; lazy reference
    (module-ref (resolve-interface '(gnu packages gnome)) 'shared-mime-info))

  (mlet %store-monad ((glib
                       (manifest-lookup-package
                        manifest "glib")))
    (define build
      (with-imported-modules  '((guix build utils)
                                (guix build union))
        #~(begin
            (use-modules (srfi srfi-26)
                         (guix build utils)
                         (guix build union))
            (let* ((datadir (string-append #$output "/share"))
                   (destdir (string-append datadir "/mime"))
                   (pkgdirs (filter file-exists?
                                    (map (cut string-append <>
                                              "/share/mime/packages")
                                         (cons #+shared-mime-info
                                               '#$(manifest-inputs manifest)))))
                   (update-mime-database (string-append
                                          #+shared-mime-info
                                          "/bin/update-mime-database")))
              (mkdir-p destdir)
              (union-build (string-append destdir "/packages") pkgdirs
                           #:log-port (%make-void-port "w"))
              (setenv "XDG_DATA_HOME" datadir)
              (exit (zero? (system* update-mime-database destdir)))))))

    ;; Don't run the hook when there are no GLib based applications.
    (if glib
        (gexp->derivation "xdg-mime-database" build
                          #:local-build? #t
                          #:substitutable? #f)
        (return #f))))

(define (fonts-dir-file manifest)
  "Return a derivation that builds the @file{fonts.dir} and @file{fonts.scale}
files for the truetype fonts of the @var{manifest} entries."
  (define mkfontscale
    (module-ref (resolve-interface '(gnu packages xorg)) 'mkfontscale))

  (define mkfontdir
    (module-ref (resolve-interface '(gnu packages xorg)) 'mkfontdir))

  (define build
    #~(begin
        (use-modules (srfi srfi-26)
                     (guix build utils)
                     (guix build union))
        (let ((ttf-dirs (filter file-exists?
                                (map (cut string-append <>
                                          "/share/fonts/truetype")
                                     '#$(manifest-inputs manifest)))))
          (mkdir #$output)
          (if (null? ttf-dirs)
              (exit #t)
              (let* ((fonts-dir   (string-append #$output "/share/fonts"))
                     (ttf-dir     (string-append fonts-dir "/truetype"))
                     (mkfontscale (string-append #+mkfontscale
                                                 "/bin/mkfontscale"))
                     (mkfontdir   (string-append #+mkfontdir
                                                 "/bin/mkfontdir")))
                (mkdir-p fonts-dir)
                (union-build ttf-dir ttf-dirs
                             #:log-port (%make-void-port "w"))
                (with-directory-excursion ttf-dir
                  (exit (and (zero? (system* mkfontscale))
                             (zero? (system* mkfontdir))))))))))

  (gexp->derivation "fonts-dir" build
                    #:modules '((guix build utils)
                                (guix build union))
                    #:local-build? #t
                    #:substitutable? #f))

(define %default-profile-hooks
  ;; This is the list of derivation-returning procedures that are called by
  ;; default when making a non-empty profile.
  (list info-dir-file
        fonts-dir-file
        ghc-package-cache-file
        ca-certificate-bundle
        gtk-icon-themes
        gtk-im-modules
        xdg-desktop-database
        xdg-mime-database))

(define* (profile-derivation manifest
                             #:key
                             (hooks %default-profile-hooks)
                             (locales? #t)
                             system)
  "Return a derivation that builds a profile (aka. 'user environment') with
the given MANIFEST.  The profile includes additional derivations returned by
the monadic procedures listed in HOOKS--such as an Info 'dir' file, etc.

When LOCALES? is true, the build is performed under a UTF-8 locale; this adds
a dependency on the 'glibc-utf8-locales' package."
  (mlet %store-monad ((system (if system
                                  (return system)
                                  (current-system)))
                      (extras (if (null? (manifest-entries manifest))
                                  (return '())
                                  (sequence %store-monad
                                            (map (lambda (hook)
                                                   (hook manifest))
                                                 hooks)))))
    (define inputs
      (append (filter-map (lambda (drv)
                            (and (derivation? drv)
                                 (gexp-input drv)))
                          extras)
              (manifest-inputs manifest)))

    (define glibc-utf8-locales                    ;lazy reference
      (module-ref (resolve-interface '(gnu packages base))
                  'glibc-utf8-locales))

    (define set-utf8-locale
      ;; Some file names (e.g., in 'nss-certs') are UTF-8 encoded so
      ;; install a UTF-8 locale.
      #~(begin
          (setenv "LOCPATH"
                  #$(file-append glibc-utf8-locales "/lib/locale/"
                                 (package-version glibc-utf8-locales)))
          (setlocale LC_ALL "en_US.utf8")))

    (define builder
      (with-imported-modules '((guix build profiles)
                               (guix build union)
                               (guix build utils)
                               (guix search-paths)
                               (guix records))
        #~(begin
            (use-modules (guix build profiles)
                         (guix search-paths)
                         (srfi srfi-1))

            (setvbuf (current-output-port) _IOLBF)
            (setvbuf (current-error-port) _IOLBF)

            #+(if locales? set-utf8-locale #t)

            (define search-paths
              ;; Search paths of MANIFEST's packages, converted back to their
              ;; record form.
              (map sexp->search-path-specification
                   (delete-duplicates
                    '#$(map search-path-specification->sexp
                            (append-map manifest-entry-search-paths
                                        (manifest-entries manifest))))))

            (build-profile #$output '#$inputs
                           #:manifest '#$(manifest->gexp manifest)
                           #:search-paths search-paths))))

    (gexp->derivation "profile" builder
                      #:system system

                      ;; Not worth offloading.
                      #:local-build? #t

                      ;; Disable substitution because it would trigger a
                      ;; connection to the substitute server, which is likely
                      ;; to have no substitute to offer.
                      #:substitutable? #f)))

(define (profile-regexp profile)
  "Return a regular expression that matches PROFILE's name and number."
  (make-regexp (string-append "^" (regexp-quote (basename profile))
                              "-([0-9]+)")))

(define (generation-number profile)
  "Return PROFILE's number or 0.  An absolute file name must be used."
  (or (and=> (false-if-exception (regexp-exec (profile-regexp profile)
                                              (basename (readlink profile))))
             (compose string->number (cut match:substring <> 1)))
      0))

(define (generation-numbers profile)
  "Return the sorted list of generation numbers of PROFILE, or '(0) if no
former profiles were found."
  (define* (scandir name #:optional (select? (const #t))
                    (entry<? (@ (ice-9 i18n) string-locale<?)))
    ;; XXX: Bug-fix version introduced in Guile v2.0.6-62-g139ce19.
    (define (enter? dir stat result)
      (and stat (string=? dir name)))

    (define (visit basename result)
      (if (select? basename)
          (cons basename result)
          result))

    (define (leaf name stat result)
      (and result
           (visit (basename name) result)))

    (define (down name stat result)
      (visit "." '()))

    (define (up name stat result)
      (visit ".." result))

    (define (skip name stat result)
      ;; All the sub-directories are skipped.
      (visit (basename name) result))

    (define (error name* stat errno result)
      (if (string=? name name*)             ; top-level NAME is unreadable
          result
          (visit (basename name*) result)))

    (and=> (file-system-fold enter? leaf down up skip error #f name lstat)
           (lambda (files)
             (sort files entry<?))))

  (match (scandir (dirname profile)
                  (cute regexp-exec (profile-regexp profile) <>))
    (#f                                         ; no profile directory
     '(0))
    (()                                         ; no profiles
     '(0))
    ((profiles ...)                             ; former profiles around
     (sort (map (compose string->number
                         (cut match:substring <> 1)
                         (cute regexp-exec (profile-regexp profile) <>))
                profiles)
           <))))

(define (profile-generations profile)
  "Return a list of PROFILE's generations."
  (let ((generations (generation-numbers profile)))
    (if (equal? generations '(0))
        '()
        generations)))

(define (relative-generation-spec->number profile spec)
  "Return PROFILE's generation specified by SPEC, which is a string.  The SPEC
may be a N, -N, or +N, where N is a number.  If the spec is N, then the number
returned is N.  If it is -N, then the number returned is the profile's current
generation number minus N.  If it is +N, then the number returned is the
profile's current generation number plus N.  Return #f if there is no such
generation."
  (let ((number (string->number spec)))
    (and number
         (case (string-ref spec 0)
           ((#\+ #\-)
            (relative-generation profile number))
           (else (if (memv number (profile-generations profile))
                     number
                     #f))))))


(define* (relative-generation profile shift #:optional
                              (current (generation-number profile)))
  "Return PROFILE's generation shifted from the CURRENT generation by SHIFT.
SHIFT is a positive or negative number.
Return #f if there is no such generation."
  (let* ((abs-shift (abs shift))
         (numbers (profile-generations profile))
         (from-current (memq current
                             (if (negative? shift)
                                 (reverse numbers)
                                 numbers))))
    (and from-current
         (< abs-shift (length from-current))
         (list-ref from-current abs-shift))))

(define* (previous-generation-number profile #:optional
                                     (number (generation-number profile)))
  "Return the number of the generation before generation NUMBER of
PROFILE, or 0 if none exists.  It could be NUMBER - 1, but it's not the
case when generations have been deleted (there are \"holes\")."
  (or (relative-generation profile -1 number)
      0))

(define (generation-file-name profile generation)
  "Return the file name for PROFILE's GENERATION."
  (format #f "~a-~a-link" profile generation))

(define (generation-time profile number)
  "Return the creation time of a generation in the UTC format."
  (make-time time-utc 0
             (stat:ctime (stat (generation-file-name profile number)))))

(define (link-to-empty-profile store generation)
  "Link GENERATION, a string, to the empty profile.  An error is raised if
that fails."
  (let* ((drv  (run-with-store store
                 (profile-derivation (manifest '())
                                     #:locales? #f)))
         (prof (derivation->output-path drv "out")))
    (build-derivations store (list drv))
    (switch-symlinks generation prof)))

(define (switch-to-generation profile number)
  "Atomically switch PROFILE to the generation NUMBER.  Return the number of
the generation that was current before switching."
  (let ((current    (generation-number profile))
        (generation (generation-file-name profile number)))
    (cond ((not (file-exists? profile))
           (raise (condition (&profile-not-found-error
                              (profile profile)))))
          ((not (file-exists? generation))
           (raise (condition (&missing-generation-error
                              (profile profile)
                              (generation number)))))
          (else
           (switch-symlinks profile generation)
           current))))

(define (switch-to-previous-generation profile)
  "Atomically switch PROFILE to the previous generation.  Return the former
generation number and the current one."
  (let ((previous (previous-generation-number profile)))
    (values (switch-to-generation profile previous)
            previous)))

(define (roll-back store profile)
  "Roll back to the previous generation of PROFILE.  Return the number of the
generation that was current before switching and the new generation number."
  (let* ((number              (generation-number profile))
         (previous-number     (previous-generation-number profile number))
         (previous-generation (generation-file-name profile previous-number)))
    (cond ((not (file-exists? profile))           ;invalid profile
           (raise (condition (&profile-not-found-error
                              (profile profile)))))
          ((zero? number)                         ;empty profile
           (values number number))
          ((or (zero? previous-number)            ;going to emptiness
               (not (file-exists? previous-generation)))
           (link-to-empty-profile store previous-generation)
           (switch-to-previous-generation profile))
          (else                                   ;anything else
           (switch-to-previous-generation profile)))))

(define (delete-generation store profile number)
  "Delete generation with NUMBER from PROFILE.  Return the file name of the
generation that has been deleted, or #f if nothing was done (for instance
because the NUMBER is zero.)"
  (define (delete-and-return)
    (let ((generation (generation-file-name profile number)))
      (delete-file generation)
      generation))

  (let* ((current-number      (generation-number profile))
         (previous-number     (previous-generation-number profile number))
         (previous-generation (generation-file-name profile previous-number)))
    (cond ((zero? number) #f)                     ;do not delete generation 0
          ((and (= number current-number)
                (not (file-exists? previous-generation)))
           (link-to-empty-profile store previous-generation)
           (switch-to-previous-generation profile)
           (delete-and-return))
          ((= number current-number)
           (roll-back store profile)
           (delete-and-return))
          (else
           (delete-and-return)))))

;;; profiles.scm ends here
