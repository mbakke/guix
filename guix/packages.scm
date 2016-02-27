;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Eric Bavier <bavier@member.fsf.org>
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

(define-module (guix packages)
  #:use-module (guix utils)
  #:use-module (guix records)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix gexp)
  #:use-module (guix base32)
  #:use-module (guix grafts)
  #:use-module (guix derivations)
  #:use-module (guix build-system)
  #:use-module (guix search-paths)
  #:use-module (guix gexp)
  #:use-module (guix sets)
  #:use-module (ice-9 match)
  #:use-module (ice-9 vlist)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9 gnu)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:use-module (web uri)
  #:re-export (%current-system
               %current-target-system
               search-path-specification)         ;for convenience
  #:export (origin
            origin?
            origin-uri
            origin-method
            origin-sha256
            origin-file-name
            origin-actual-file-name
            origin-patches
            origin-patch-flags
            origin-patch-inputs
            origin-patch-guile
            origin-snippet
            origin-modules
            origin-imported-modules
            base32

            package
            package?
            package-name
            package-version
            package-full-name
            package-source
            package-build-system
            package-arguments
            package-inputs
            package-native-inputs
            package-propagated-inputs
            package-outputs
            package-native-search-paths
            package-search-paths
            package-replacement
            package-synopsis
            package-description
            package-license
            package-home-page
            package-supported-systems
            package-maintainers
            package-properties
            package-location
            package-field-location

            package-direct-sources
            package-transitive-sources
            package-direct-inputs
            package-transitive-inputs
            package-transitive-target-inputs
            package-transitive-native-inputs
            package-transitive-propagated-inputs
            package-transitive-native-search-paths
            package-transitive-supported-systems
            package-source-derivation
            package-derivation
            package-cross-derivation
            package-output
            package-grafts

            transitive-input-references

            %supported-systems
            %hurd-systems
            %hydra-supported-systems
            supported-package?

            &package-error
            package-error?
            package-error-package
            &package-input-error
            package-input-error?
            package-error-invalid-input
            &package-cross-build-system-error
            package-cross-build-system-error?

            package->bag
            bag->derivation
            bag-direct-inputs
            bag-transitive-inputs
            bag-transitive-host-inputs
            bag-transitive-build-inputs
            bag-transitive-target-inputs

            default-guile
            default-guile-derivation
            set-guile-for-build
            package-file
            package->derivation
            package->cross-derivation
            origin->derivation))

;;; Commentary:
;;;
;;; This module provides a high-level mechanism to define packages in a
;;; Guix-based distribution.
;;;
;;; Code:

;; The source of a package, such as a tarball URL and fetcher---called
;; "origin" to avoid name clash with `package-source', `source', etc.
(define-record-type* <origin>
  origin make-origin
  origin?
  (uri       origin-uri)                          ; string
  (method    origin-method)                       ; procedure
  (sha256    origin-sha256)                       ; bytevector
  (file-name origin-file-name (default #f))       ; optional file name

  ;; Patches are delayed so that the 'search-patch' calls are made lazily,
  ;; which reduces I/O on startup and allows patch-not-found errors to be
  ;; gracefully handled at run time.
  (patches   origin-patches                       ; list of file names
             (default '()) (delayed))

  (snippet   origin-snippet (default #f))         ; sexp or #f
  (patch-flags  origin-patch-flags                ; list of strings
                (default '("-p1")))

  ;; Patching requires Guile, GNU Patch, and a few more.  These two fields are
  ;; used to specify these dependencies when needed.
  (patch-inputs origin-patch-inputs               ; input list or #f
                (default #f))
  (modules      origin-modules                    ; list of module names
                (default '()))
  (imported-modules origin-imported-modules       ; list of module names
                    (default '()))
  (patch-guile origin-patch-guile                 ; package or #f
               (default #f)))

(define (print-origin origin port)
  "Write a concise representation of ORIGIN to PORT."
  (match origin
    (($ <origin> uri method sha256 file-name patches)
     (simple-format port "#<origin ~s ~a ~s ~a>"
                    uri (bytevector->base32-string sha256)
                    (force patches)
                    (number->string (object-address origin) 16)))))

(set-record-type-printer! <origin> print-origin)

(define-syntax base32
  (lambda (s)
    "Return the bytevector corresponding to the given Nix-base32
representation."
    (syntax-case s ()
      ((_ str)
       (string? (syntax->datum #'str))
       ;; A literal string: do the conversion at expansion time.
       (with-syntax ((bv (nix-base32-string->bytevector
                          (syntax->datum #'str))))
         #''bv))
      ((_ str)
       #'(nix-base32-string->bytevector str)))))

(define (origin-actual-file-name origin)
  "Return the file name of ORIGIN, either its 'file-name' field or the file
name of its URI."
  (define (uri->file-name uri)
    ;; Return the 'base name' of URI or URI itself, where URI is a string.
    (let ((path (and=> (string->uri uri) uri-path)))
      (if path
          (basename path)
          uri)))

  (or (origin-file-name origin)
      (match (origin-uri origin)
        ((head . tail)
         (uri->file-name head))
        ((? string? uri)
         (uri->file-name uri))
        (else
         ;; git, svn, cvs, etc. reference
         #f))))

(define %supported-systems
  ;; This is the list of system types that are supported.  By default, we
  ;; expect all packages to build successfully here.
  '("x86_64-linux" "i686-linux" "armhf-linux" "mips64el-linux"))

(define %hurd-systems
  ;; The GNU/Hurd systems for which support is being developed.
  '("i585-gnu" "i686-gnu"))

(define %hydra-supported-systems
  ;; This is the list of system types for which build slaves are available.
  %supported-systems)


;; A package.
(define-record-type* <package>
  package make-package
  package?
  (name   package-name)                   ; string
  (version package-version)               ; string
  (source package-source)                 ; <origin> instance
  (build-system package-build-system)     ; build system
  (arguments package-arguments            ; arguments for the build method
             (default '()) (thunked))

  (inputs package-inputs                  ; input packages or derivations
          (default '()) (thunked))
  (propagated-inputs package-propagated-inputs    ; same, but propagated
                     (default '()) (thunked))
  (native-inputs package-native-inputs    ; native input packages/derivations
                 (default '()) (thunked))
  (self-native-input? package-self-native-input?  ; whether to use itself as
                                                  ; a native input when cross-
                      (default #f))               ; compiling

  (outputs package-outputs                ; list of strings
           (default '("out")))

                                                  ; lists of
                                                  ; <search-path-specification>,
                                                  ; for native and cross
                                                  ; inputs
  (native-search-paths package-native-search-paths (default '()))
  (search-paths package-search-paths (default '()))
  (replacement package-replacement                ; package | #f
               (default #f) (thunked))

  (synopsis package-synopsis)                    ; one-line description
  (description package-description)              ; one or two paragraphs
  (license package-license)
  (home-page package-home-page)
  (supported-systems package-supported-systems    ; list of strings
                     (default %supported-systems))
  (maintainers package-maintainers (default '()))

  (properties package-properties (default '()))   ; alist for anything else

  (location package-location
            (default (and=> (current-source-location)
                            source-properties->location))
            (innate)))

(set-record-type-printer! <package>
                          (lambda (package port)
                            (let ((loc    (package-location package))
                                  (format simple-format))
                              (format port "#<package ~a@~a ~a~a>"
                                      (package-name package)
                                      (package-version package)
                                      (if loc
                                          (format #f "~a:~a "
                                                  (location-file loc)
                                                  (location-line loc))
                                          "")
                                      (number->string (object-address
                                                       package)
                                                      16)))))

(define (package-field-location package field)
  "Return the source code location of the definition of FIELD for PACKAGE, or
#f if it could not be determined."
  (define (goto port line column)
    (unless (and (= (port-column port) (- column 1))
                 (= (port-line port) (- line 1)))
      (unless (eof-object? (read-char port))
        (goto port line column))))

  (match (package-location package)
    (($ <location> file line column)
     (catch 'system
       (lambda ()
         ;; In general we want to keep relative file names for modules.
         (with-fluids ((%file-port-name-canonicalization 'relative))
           (call-with-input-file (search-path %load-path file)
             (lambda (port)
               (goto port line column)
               (match (read port)
                 (('package inits ...)
                  (let ((field (assoc field inits)))
                    (match field
                      ((_ value)
                       ;; Put the `or' here, and not in the first argument of
                       ;; `and=>', to work around a compiler bug in 2.0.5.
                       (or (and=> (source-properties value)
                                  source-properties->location)
                           (and=> (source-properties field)
                                  source-properties->location)))
                      (_
                       #f))))
                 (_
                  #f))))))
       (lambda _
         #f)))
    (_ #f)))


;; Error conditions.

(define-condition-type &package-error &error
  package-error?
  (package package-error-package))

(define-condition-type &package-input-error &package-error
  package-input-error?
  (input package-error-invalid-input))

(define-condition-type &package-cross-build-system-error &package-error
  package-cross-build-system-error?)


(define (package-full-name package)
  "Return the full name of PACKAGE--i.e., `NAME-VERSION'."
  (string-append (package-name package) "-" (package-version package)))

(define (%standard-patch-inputs)
  (let* ((canonical (module-ref (resolve-interface '(gnu packages base))
                                'canonical-package))
         (ref       (lambda (module var)
                      (canonical
                       (module-ref (resolve-interface module) var)))))
    `(("tar"   ,(ref '(gnu packages base) 'tar))
      ("xz"    ,(ref '(gnu packages compression) 'xz))
      ("bzip2" ,(ref '(gnu packages compression) 'bzip2))
      ("gzip"  ,(ref '(gnu packages compression) 'gzip))
      ("lzip"  ,(ref '(gnu packages compression) 'lzip))
      ("unzip" ,(ref '(gnu packages zip) 'unzip))
      ("patch" ,(ref '(gnu packages base) 'patch))
      ("locales" ,(ref '(gnu packages base) 'glibc-utf8-locales)))))

(define (default-guile)
  "Return the default Guile package used to run the build code of
derivations."
  (let ((distro (resolve-interface '(gnu packages commencement))))
    (module-ref distro 'guile-final)))

(define* (default-guile-derivation #:optional (system (%current-system)))
  "Return the derivation for SYSTEM of the default Guile package used to run
the build code of derivation."
  (package->derivation (default-guile) system
                       #:graft? #f))

(define* (patch-and-repack source patches
                           #:key
                           inputs
                           (snippet #f)
                           (flags '("-p1"))
                           (modules '())
                           (imported-modules '())
                           (guile-for-build (%guile-for-build))
                           (system (%current-system)))
  "Unpack SOURCE (a derivation or store path), apply all of PATCHES, and
repack the tarball using the tools listed in INPUTS.  When SNIPPET is true,
it must be an s-expression that will run from within the directory where
SOURCE was unpacked, after all of PATCHES have been applied.  MODULES and
IMPORTED-MODULES specify modules to use/import for use by SNIPPET."
  (define source-file-name
    ;; SOURCE is usually a derivation, but it could be a store file.
    (if (derivation? source)
        (derivation->output-path source)
        source))

  (define lookup-input
    ;; The default value of the 'patch-inputs' field, and thus INPUTS is #f,
    ;; so deal with that.
    (let ((inputs (or inputs (%standard-patch-inputs))))
      (lambda (name)
        (match (assoc-ref inputs name)
          ((package) package)
          (#f        #f)))))

  (define decompression-type
    (cond ((string-suffix? "gz" source-file-name)  "gzip")
          ((string-suffix? "bz2" source-file-name) "bzip2")
          ((string-suffix? "lz" source-file-name)  "lzip")
          ((string-suffix? "zip" source-file-name) "unzip")
          (else "xz")))

  (define original-file-name
    ;; Remove the store prefix plus the slash, hash, and hyphen.
    (let* ((sans (string-drop source-file-name
                              (+ (string-length (%store-prefix)) 1)))
           (dash (string-index sans #\-)))
      (string-drop sans (+ 1 dash))))

  (define (numeric-extension? file-name)
    ;; Return true if FILE-NAME ends with digits.
    (and=> (file-extension file-name)
           (cut string-every char-set:hex-digit <>)))

  (define (tarxz-name file-name)
    ;; Return a '.tar.xz' file name based on FILE-NAME.
    (let ((base (if (numeric-extension? file-name)
                    original-file-name
                    (file-sans-extension file-name))))
      (string-append base
                     (if (equal? (file-extension base) "tar")
                         ".xz"
                         ".tar.xz"))))

  (define instantiate-patch
    (match-lambda
      ((? string? patch)
       (interned-file patch #:recursive? #t))
      ((? origin? patch)
       (origin->derivation patch system))))

  (mlet %store-monad ((tar ->     (lookup-input "tar"))
                      (xz ->      (lookup-input "xz"))
                      (patch ->   (lookup-input "patch"))
                      (locales -> (lookup-input "locales"))
                      (decomp ->  (lookup-input decompression-type))
                      (patches    (sequence %store-monad
                                            (map instantiate-patch patches))))
    (define build
      #~(begin
          (use-modules (ice-9 ftw)
                       (srfi srfi-1)
                       (guix build utils))

          ;; The --sort option was added to GNU tar in version 1.28, released
          ;; 2014-07-28.  During bootstrap we must cope with older versions.
          (define tar-supports-sort?
            (zero? (system* (string-append #+tar "/bin/tar")
                            "cf" "/dev/null" "--files-from=/dev/null"
                            "--sort=name")))

          (define (apply-patch patch)
            (format (current-error-port) "applying '~a'...~%" patch)

            ;; Use '--force' so that patches that do not apply perfectly are
            ;; rejected.
            (zero? (system* (string-append #+patch "/bin/patch")
                            "--force" #+@flags "--input" patch)))

          (define (first-file directory)
            ;; Return the name of the first file in DIRECTORY.
            (car (scandir directory
                          (lambda (name)
                            (not (member name '("." "..")))))))

          ;; Encoding/decoding errors shouldn't be silent.
          (fluid-set! %default-port-conversion-strategy 'error)

          (when #+locales
            ;; First of all, install a UTF-8 locale so that UTF-8 file names
            ;; are correctly interpreted.  During bootstrap, LOCALES is #f.
            (setenv "LOCPATH"
                    (string-append #+locales "/lib/locale/"
                                   #+(and locales
                                          (package-version locales))))
            (setlocale LC_ALL "en_US.utf8"))

          (setenv "PATH" (string-append #+xz "/bin" ":"
                                        #+decomp "/bin"))

          ;; SOURCE may be either a directory or a tarball.
          (and (if (file-is-directory? #+source)
                   (let* ((store     (%store-directory))
                          (len       (+ 1 (string-length store)))
                          (base      (string-drop #+source len))
                          (dash      (string-index base #\-))
                          (directory (string-drop base (+ 1 dash))))
                     (mkdir directory)
                     (copy-recursively #+source directory)
                     #t)
                   #+(if (string=? decompression-type "unzip")
                         #~(zero? (system* "unzip" #+source))
                         #~(zero? (system* (string-append #+tar "/bin/tar")
                                           "xvf" #+source))))
               (let ((directory (first-file ".")))
                 (format (current-error-port)
                         "source is under '~a'~%" directory)
                 (chdir directory)

                 (and (every apply-patch '#+patches)
                      #+@(if snippet
                             #~((let ((module (make-fresh-user-module)))
                                  (module-use-interfaces! module
                                                          (map resolve-interface
                                                               '#+modules))
                                  ((@ (system base compile) compile)
                                   '#+snippet
                                   #:to 'value
                                   #:opts %auto-compilation-options
                                   #:env module)))
                             #~())

                      (begin (chdir "..") #t)

                      (unless tar-supports-sort?
                        (call-with-output-file ".file_list"
                          (lambda (port)
                            (for-each (lambda (name) (format port "~a~%" name))
                                      (find-files directory
                                                  #:directories? #t
                                                  #:fail-on-error? #t)))))
                      (zero? (apply system* (string-append #+tar "/bin/tar")
                                    "cvfa" #$output
                                    ;; avoid non-determinism in the archive
                                    "--mtime=@0"
                                    "--owner=root:0"
                                    "--group=root:0"
                                    (if tar-supports-sort?
                                        `("--sort=name"
                                          ,directory)
                                        '("--no-recursion"
                                          "--files-from=.file_list")))))))))

    (let ((name    (tarxz-name original-file-name))
          (modules (delete-duplicates (cons '(guix build utils) modules))))
      (gexp->derivation name build
                        #:graft? #f
                        #:system system
                        #:modules modules
                        #:guile-for-build guile-for-build))))

(define (transitive-inputs inputs)
  "Return the closure of INPUTS when considering the 'propagated-inputs'
edges.  Omit duplicate inputs, except for those already present in INPUTS
itself.

This is implemented as a breadth-first traversal such that INPUTS is
preserved, and only duplicate propagated inputs are removed."
  (define (seen? seen item outputs)
    (match (vhash-assq item seen)
      ((_ . o) (equal? o outputs))
      (_       #f)))

  (let loop ((inputs     inputs)
             (result     '())
             (propagated '())
             (first?     #t)
             (seen       vlist-null))
    (match inputs
      (()
       (if (null? propagated)
           (reverse result)
           (loop (reverse (concatenate propagated)) result '() #f seen)))
      (((and input (label (? package? package) outputs ...)) rest ...)
       (if (and (not first?) (seen? seen package outputs))
           (loop rest result propagated first? seen)
           (loop rest
                 (cons input result)
                 (cons (package-propagated-inputs package) propagated)
                 first?
                 (vhash-consq package outputs seen))))
      ((input rest ...)
       (loop rest (cons input result) propagated first? seen)))))

(define (package-direct-sources package)
  "Return all source origins associated with PACKAGE; including origins in
PACKAGE's inputs."
  `(,@(or (and=> (package-source package) list) '())
    ,@(filter-map (match-lambda
                   ((_ (? origin? orig) _ ...)
                    orig)
                   (_ #f))
                  (package-direct-inputs package))))

(define (package-transitive-sources package)
  "Return PACKAGE's direct sources, and their direct sources, recursively."
  (delete-duplicates
   (concatenate (filter-map (match-lambda
                             ((_ (? origin? orig) _ ...)
                              (list orig))
                             ((_ (? package? p) _ ...)
                              (package-direct-sources p))
                             (_ #f))
                            (bag-transitive-inputs
                             (package->bag package))))))

(define (package-direct-inputs package)
  "Return all the direct inputs of PACKAGE---i.e, its direct inputs along
with their propagated inputs."
  (append (package-native-inputs package)
          (package-inputs package)
          (package-propagated-inputs package)))

(define (package-transitive-inputs package)
  "Return the transitive inputs of PACKAGE---i.e., its direct inputs along
with their propagated inputs, recursively."
  (transitive-inputs (package-direct-inputs package)))

(define (package-transitive-target-inputs package)
  "Return the transitive target inputs of PACKAGE---i.e., its direct inputs
along with their propagated inputs, recursively.  This only includes inputs
for the target system, and not native inputs."
  (transitive-inputs (append (package-inputs package)
                             (package-propagated-inputs package))))

(define (package-transitive-native-inputs package)
  "Return the transitive native inputs of PACKAGE---i.e., its direct inputs
along with their propagated inputs, recursively.  This only includes inputs
for the host system (\"native inputs\"), and not target inputs."
  (transitive-inputs (package-native-inputs package)))

(define (package-transitive-propagated-inputs package)
  "Return the propagated inputs of PACKAGE, and their propagated inputs,
recursively."
  (transitive-inputs (package-propagated-inputs package)))

(define (package-transitive-native-search-paths package)
  "Return the list of search paths for PACKAGE and its propagated inputs,
recursively."
  (append (package-native-search-paths package)
          (append-map (match-lambda
                        ((label (? package? p) _ ...)
                         (package-native-search-paths p))
                        (_
                         '()))
                      (package-transitive-propagated-inputs package))))

(define (transitive-input-references alist inputs)
  "Return a list of (assoc-ref ALIST <label>) for each (<label> <package> . _)
in INPUTS and their transitive propagated inputs."
  (define label
    (match-lambda
      ((label . _)
       label)))

  (map (lambda (input)
         `(assoc-ref ,alist ,(label input)))
       (transitive-inputs inputs)))

(define-syntax define-memoized/v
  (lambda (form)
    "Define a memoized single-valued unary procedure with docstring.
The procedure argument is compared to cached keys using `eqv?'."
    (syntax-case form ()
      ((_ (proc arg) docstring body body* ...)
       (string? (syntax->datum #'docstring))
       #'(define proc
           (let ((cache (make-hash-table)))
             (define (proc arg)
               docstring
               (match (hashv-get-handle cache arg)
                 ((_ . value)
                  value)
                 (_
                  (let ((result (let () body body* ...)))
                    (hashv-set! cache arg result)
                    result))))
             proc))))))

(define-memoized/v (package-transitive-supported-systems package)
  "Return the intersection of the systems supported by PACKAGE and those
supported by its dependencies."
  (fold (lambda (input systems)
          (match input
            ((label (? package? p) . _)
             (lset-intersection
              string=? systems (package-transitive-supported-systems p)))
            (_
             systems)))
        (package-supported-systems package)
        (bag-direct-inputs (package->bag package))))

(define* (supported-package? package #:optional (system (%current-system)))
  "Return true if PACKAGE is supported on SYSTEM--i.e., if PACKAGE and all its
dependencies are known to build on SYSTEM."
  (member system (package-transitive-supported-systems package)))

(define (bag-direct-inputs bag)
  "Same as 'package-direct-inputs', but applied to a bag."
  (append (bag-build-inputs bag)
          (bag-host-inputs bag)
          (bag-target-inputs bag)))

(define (bag-transitive-inputs bag)
  "Same as 'package-transitive-inputs', but applied to a bag."
  (transitive-inputs (bag-direct-inputs bag)))

(define (bag-transitive-build-inputs bag)
  "Same as 'package-transitive-native-inputs', but applied to a bag."
  (transitive-inputs (bag-build-inputs bag)))

(define (bag-transitive-host-inputs bag)
  "Same as 'package-transitive-target-inputs', but applied to a bag."
  (transitive-inputs (bag-host-inputs bag)))

(define (bag-transitive-target-inputs bag)
  "Return the \"target inputs\" of BAG, recursively."
  (transitive-inputs (bag-target-inputs bag)))


;;;
;;; Package derivations.
;;;

(define %derivation-cache
  ;; Package to derivation-path mapping.
  (make-weak-key-hash-table 100))

(define (cache package system thunk)
  "Memoize the return values of THUNK as the derivation of PACKAGE on
SYSTEM."
  ;; FIXME: This memoization should be associated with the open store, because
  ;; otherwise it breaks when switching to a different store.
  (let ((vals (call-with-values thunk list)))
    ;; Use `hashq-set!' instead of `hash-set!' because `hash' returns the
    ;; same value for all structs (as of Guile 2.0.6), and because pointer
    ;; equality is sufficient in practice.
    (hashq-set! %derivation-cache package
                `((,system ,@vals)
                  ,@(or (hashq-ref %derivation-cache package)
                        '())))
    (apply values vals)))

(define-syntax-rule (cached package system body ...)
  "Memoize the result of BODY for the arguments PACKAGE and SYSTEM.
Return the cached result when available."
  (let ((thunk (lambda () body ...))
        (key   system))
    (match (hashq-ref %derivation-cache package)
      ((alist (... ...))
       (match (assoc-ref alist key)
         ((vals (... ...))
          (apply values vals))
         (#f
          (cache package key thunk))))
      (#f
       (cache package key thunk)))))

(define* (expand-input store package input system #:optional cross-system)
  "Expand INPUT, an input tuple, such that it contains only references to
derivation paths or store paths.  PACKAGE is only used to provide contextual
information in exceptions."
  (define (intern file)
    ;; Add FILE to the store.  Set the `recursive?' bit to #t, so that
    ;; file permissions are preserved.
    (add-to-store store (basename file) #t "sha256" file))

  (define derivation
    (if cross-system
        (cut package-cross-derivation store <> cross-system system
             #:graft? #f)
        (cut package-derivation store <> system #:graft? #f)))

  (match input
    (((? string? name) (? package? package))
     (list name (derivation package)))
    (((? string? name) (? package? package)
      (? string? sub-drv))
     (list name (derivation package)
           sub-drv))
    (((? string? name)
      (and (? string?) (? derivation-path?) drv))
     (list name drv))
    (((? string? name)
      (and (? string?) (? file-exists? file)))
     ;; Add FILE to the store.  When FILE is in the sub-directory of a
     ;; store path, it needs to be added anyway, so it can be used as a
     ;; source.
     (list name (intern file)))
    (((? string? name) (? origin? source))
     (list name (package-source-derivation store source system)))
    (x
     (raise (condition (&package-input-error
                        (package package)
                        (input   x)))))))

(define* (package->bag package #:optional
                       (system (%current-system))
                       (target (%current-target-system))
                       #:key (graft? (%graft?)))
  "Compile PACKAGE into a bag for SYSTEM, possibly cross-compiled to TARGET,
and return it."
  ;; Bind %CURRENT-SYSTEM and %CURRENT-TARGET-SYSTEM so that thunked field
  ;; values can refer to it.
  (parameterize ((%current-system system)
                 (%current-target-system target))
    (match (if graft?
               (or (package-replacement package) package)
               package)
      (($ <package> name version source build-system
                    args inputs propagated-inputs native-inputs self-native-input?
                    outputs)
       (or (make-bag build-system (string-append name "-" version)
                     #:system system
                     #:target target
                     #:source source
                     #:inputs (append (inputs)
                                      (propagated-inputs))
                     #:outputs outputs
                     #:native-inputs `(,@(if (and target self-native-input?)
                                             `(("self" ,package))
                                             '())
                                       ,@(native-inputs))
                     #:arguments (args))
           (raise (if target
                      (condition
                       (&package-cross-build-system-error
                        (package package)))
                      (condition
                       (&package-error
                        (package package))))))))))

(define (input-graft store system)
  "Return a procedure that, given a package with a graft, returns a graft, and
#f otherwise."
  (match-lambda
    ((? package? package)
     (let ((replacement (package-replacement package)))
       (and replacement
            (let ((orig (package-derivation store package system
                                            #:graft? #f))
                  (new  (package-derivation store replacement system)))
              (graft
                (origin orig)
                (replacement new))))))
    (x
     #f)))

(define (input-cross-graft store target system)
  "Same as 'input-graft', but for cross-compilation inputs."
  (match-lambda
    ((? package? package)
    (let ((replacement (package-replacement package)))
      (and replacement
           (let ((orig (package-cross-derivation store package target system
                                                 #:graft? #f))
                 (new  (package-cross-derivation store replacement
                                                 target system)))
             (graft
               (origin orig)
               (replacement new))))))
   (_
    #f)))

(define* (fold-bag-dependencies proc seed bag
                                #:key (native? #t))
  "Fold PROC over the packages BAG depends on.  Each package is visited only
once, in depth-first order.  If NATIVE? is true, restrict to native
dependencies; otherwise, restrict to target dependencies."
  (define nodes
    (match (if native?
               (append (bag-build-inputs bag)
                       (bag-target-inputs bag)
                       (if (bag-target bag)
                           '()
                           (bag-host-inputs bag)))
               (bag-host-inputs bag))
      (((labels things _ ...) ...)
       things)))

  (let loop ((nodes nodes)
             (result seed)
             (visited (setq)))
    (match nodes
      (()
       result)
      (((? package? head) . tail)
       (if (set-contains? visited head)
           (loop tail result visited)
           (let ((inputs (bag-direct-inputs (package->bag head))))
             (loop (match inputs
                     (((labels things _ ...) ...)
                      (append things tail)))
                   (proc head result)
                   (set-insert head visited)))))
      ((head . tail)
       (loop tail result visited)))))

(define* (bag-grafts store bag)
  "Return the list of grafts potentially applicable to BAG.  Potentially
applicable grafts are collected by looking at direct or indirect dependencies
of BAG that have a 'replacement'.  Whether a graft is actually applicable
depends on whether the outputs of BAG depend on the items the grafts refer
to (see 'graft-derivation'.)"
  (define system (bag-system bag))
  (define target (bag-target bag))

  (define native-grafts
    (let ((->graft (input-graft store system)))
      (fold-bag-dependencies (lambda (package grafts)
                               (match (->graft package)
                                 (#f    grafts)
                                 (graft (cons graft grafts))))
                             '()
                             bag)))

  (define target-grafts
    (if target
        (let ((->graft (input-cross-graft store target system)))
          (fold-bag-dependencies (lambda (package grafts)
                                   (match (->graft package)
                                     (#f    grafts)
                                     (graft (cons graft grafts))))
                                 '()
                                 bag
                                 #:native? #f))
        '()))

  (append native-grafts target-grafts))

(define* (package-grafts store package
                         #:optional (system (%current-system))
                         #:key target)
  "Return the list of grafts applicable to PACKAGE as built for SYSTEM and
TARGET."
  (let* ((package (or (package-replacement package) package))
         (bag     (package->bag package system target)))
    (bag-grafts store bag)))

(define* (bag->derivation store bag
                          #:optional context)
  "Return the derivation to build BAG for SYSTEM.  Optionally, CONTEXT can be
a package object describing the context in which the call occurs, for improved
error reporting."
  (if (bag-target bag)
      (bag->cross-derivation store bag)
      (let* ((system     (bag-system bag))
             (inputs     (bag-transitive-inputs bag))
             (input-drvs (map (cut expand-input store context <> system)
                              inputs))
             (paths      (delete-duplicates
                          (append-map (match-lambda
                                       ((_ (? package? p) _ ...)
                                        (package-native-search-paths
                                         p))
                                       (_ '()))
                                      inputs))))

        (apply (bag-build bag)
               store (bag-name bag) input-drvs
               #:search-paths paths
               #:outputs (bag-outputs bag) #:system system
               (bag-arguments bag)))))

(define* (bag->cross-derivation store bag
                                #:optional context)
  "Return the derivation to build BAG, which is actually a cross build.
Optionally, CONTEXT can be a package object denoting the context of the call.
This is an internal procedure."
  (let* ((system      (bag-system bag))
         (target      (bag-target bag))
         (host        (bag-transitive-host-inputs bag))
         (host-drvs   (map (cut expand-input store context <> system target)
                           host))
         (target*     (bag-transitive-target-inputs bag))
         (target-drvs (map (cut expand-input store context <> system)
                           target*))
         (build       (bag-transitive-build-inputs bag))
         (build-drvs  (map (cut expand-input store context <> system)
                           build))
         (all         (append build target* host))
         (paths       (delete-duplicates
                       (append-map (match-lambda
                                    ((_ (? package? p) _ ...)
                                     (package-search-paths p))
                                    (_ '()))
                                   all)))
         (npaths      (delete-duplicates
                       (append-map (match-lambda
                                    ((_ (? package? p) _ ...)
                                     (package-native-search-paths
                                      p))
                                    (_ '()))
                                   all))))

    (apply (bag-build bag)
           store (bag-name bag)
           #:native-drvs build-drvs
           #:target-drvs (append host-drvs target-drvs)
           #:search-paths paths
           #:native-search-paths npaths
           #:outputs (bag-outputs bag)
           #:system system #:target target
           (bag-arguments bag))))

(define* (package-derivation store package
                             #:optional (system (%current-system))
                             #:key (graft? (%graft?)))
  "Return the <derivation> object of PACKAGE for SYSTEM."

  ;; Compute the derivation and cache the result.  Caching is important
  ;; because some derivations, such as the implicit inputs of the GNU build
  ;; system, will be queried many, many times in a row.
  (cached package (cons system graft?)
          (let* ((bag (package->bag package system #f #:graft? graft?))
                 (drv (bag->derivation store bag package)))
            (if graft?
                (match (bag-grafts store bag)
                  (()
                   drv)
                  (grafts
                   (let ((guile (package-derivation store (default-guile)
                                                    system #:graft? #f)))
                     ;; TODO: As an optimization, we can simply graft the tip
                     ;; of the derivation graph since 'graft-derivation'
                     ;; recurses anyway.
                     (graft-derivation store drv grafts
                                       #:system system
                                       #:guile guile))))
                drv))))

(define* (package-cross-derivation store package target
                                   #:optional (system (%current-system))
                                   #:key (graft? (%graft?)))
  "Cross-build PACKAGE for TARGET (a GNU triplet) from host SYSTEM (a Guix
system identifying string)."
  (cached package (list system target graft?)
          (let* ((bag (package->bag package system target #:graft? graft?))
                 (drv (bag->derivation store bag package)))
            (if graft?
                (match (bag-grafts store bag)
                  (()
                   drv)
                  (grafts
                   (graft-derivation store drv grafts
                                     #:system system
                                     #:guile
                                     (package-derivation store (default-guile)
                                                         system #:graft? #f))))
                drv))))

(define* (package-output store package
                         #:optional (output "out") (system (%current-system)))
  "Return the output path of PACKAGE's OUTPUT for SYSTEM---where OUTPUT is the
symbolic output name, such as \"out\".  Note that this procedure calls
`package-derivation', which is costly."
  (let ((drv (package-derivation store package system)))
    (derivation->output-path drv output)))


;;;
;;; Monadic interface.
;;;

(define (set-guile-for-build guile)
  "This monadic procedure changes the Guile currently used to run the build
code of derivations to GUILE, a package object."
  (lambda (store)
    (let ((guile (package-derivation store guile)))
      (values (%guile-for-build guile) store))))

(define* (package-file package
                       #:optional file
                       #:key
                       system (output "out") target)
  "Return as a monadic value the absolute file name of FILE within the
OUTPUT directory of PACKAGE.  When FILE is omitted, return the name of the
OUTPUT directory of PACKAGE.  When TARGET is true, use it as a
cross-compilation target triplet."
  (lambda (store)
    (define compute-derivation
      (if target
          (cut package-cross-derivation <> <> target <>)
          package-derivation))

    (let* ((system (or system (%current-system)))
           (drv    (compute-derivation store package system))
           (out    (derivation->output-path drv output)))
      (values (if file
                  (string-append out "/" file)
                  out)
              store))))

(define package->derivation
  (store-lift package-derivation))

(define package->cross-derivation
  (store-lift package-cross-derivation))

(define-gexp-compiler (package-compiler (package package?) system target)
  ;; Compile PACKAGE to a derivation for SYSTEM, optionally cross-compiled for
  ;; TARGET.  This is used when referring to a package from within a gexp.
  (if target
      (package->cross-derivation package target system)
      (package->derivation package system)))

(define* (origin->derivation source
                             #:optional (system (%current-system)))
  "When SOURCE is an <origin> object, return its derivation for SYSTEM.  When
SOURCE is a file name, return either the interned file name (if SOURCE is
outside of the store) or SOURCE itself (if SOURCE is already a store item.)"
  (match source
    (($ <origin> uri method sha256 name (= force ()) #f)
     ;; No patches, no snippet: this is a fixed-output derivation.
     (method uri 'sha256 sha256 name #:system system))
    (($ <origin> uri method sha256 name (= force (patches ...)) snippet
        (flags ...) inputs (modules ...) (imported-modules ...)
        guile-for-build)
     ;; Patches and/or a snippet.
     (mlet %store-monad ((source (method uri 'sha256 sha256 name
                                         #:system system))
                         (guile  (package->derivation (or guile-for-build
                                                          (default-guile))
                                                      system
                                                      #:graft? #f)))
       (patch-and-repack source patches
                         #:inputs inputs
                         #:snippet snippet
                         #:flags flags
                         #:system system
                         #:modules modules
                         #:imported-modules modules
                         #:guile-for-build guile)))
    ((and (? string?) (? direct-store-path?) file)
     (with-monad %store-monad
       (return file)))
    ((? string? file)
     (interned-file file (basename file)
                    #:recursive? #t))))

(define-gexp-compiler (origin-compiler (origin origin?) system target)
  ;; Compile ORIGIN to a derivation for SYSTEM.  This is used when referring
  ;; to an origin from within a gexp.
  (origin->derivation origin system))

(define package-source-derivation
  (store-lower origin->derivation))
