;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Alex Kost <alezost@gmail.com>
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

;;; Commentary:

;; Information about packages and generations is passed to the elisp
;; side in the form of alists of parameters (such as ‘name’ or
;; ‘version’) and their values.

;; ‘entries’ procedure is the “entry point” for the elisp side to get
;; information about packages and generations.

;; Since name/version pair is not necessarily unique, we use
;; `object-address' to identify a package (for ‘id’ parameter), if
;; possible.  However for the obsolete packages (that can be found in
;; installed manifest but not in a package directory), ‘id’ parameter is
;; still "name-version" string.  So ‘id’ package parameter in the code
;; below is either an object-address number or a full-name string.

;;; Code:

(use-modules
 (ice-9 vlist)
 (ice-9 match)
 (ice-9 popen)
 (srfi srfi-1)
 (srfi srfi-2)
 (srfi srfi-11)
 (srfi srfi-19)
 (srfi srfi-26)
 (guix)
 (guix combinators)
 (guix git-download)
 (guix grafts)
 (guix packages)
 (guix profiles)
 (guix licenses)
 (guix utils)
 (guix ui)
 (guix scripts)
 (guix scripts package)
 (gnu packages)
 (gnu system))

(define-syntax-rule (first-or-false lst)
  (and (not (null? lst))
       (first lst)))

(define (list-maybe obj)
  (if (list? obj) obj (list obj)))

(define (output+error thunk)
  "Call THUNK and return 2 values: output and error output as strings."
  (let ((output-port (open-output-string))
        (error-port  (open-output-string)))
    (with-output-to-port output-port
      (lambda () (with-error-to-port error-port thunk)))
    (let ((strings (list (get-output-string output-port)
                         (get-output-string error-port))))
      (close-output-port output-port)
      (close-output-port error-port)
      (apply values strings))))

(define (full-name->name+version spec)
  "Given package specification SPEC with or without output,
return two values: name and version.  For example, for SPEC
\"foo@0.9.1b:lib\", return \"foo\" and \"0.9.1b\"."
  (let-values (((name version output)
                (package-specification->name+version+output spec)))
    (values name version)))

(define (name+version->full-name name version)
  (string-append name "@" version))

(define* (make-package-specification name #:optional version output)
  (let ((full-name (if version
                       (name+version->full-name name version)
                       name)))
    (if output
        (string-append full-name ":" output)
        full-name)))

(define (manifest-entry->name+version+output entry)
  (values
   (manifest-entry-name    entry)
   (manifest-entry-version entry)
   (manifest-entry-output  entry)))

(define (manifest-entry->package-specification entry)
  (call-with-values
      (lambda () (manifest-entry->name+version+output entry))
    make-package-specification))

(define (manifest-entries->package-specifications entries)
  (map manifest-entry->package-specification entries))

(define (profile-package-specifications profile)
  "Return a list of package specifications for PROFILE."
  (let ((manifest (profile-manifest profile)))
    (manifest-entries->package-specifications
     (manifest-entries manifest))))

(define (profile->specifications+paths profile)
  "Return a list of package specifications and paths for PROFILE.
Each element of the list is a list of the package specification and its path."
  (let ((manifest (profile-manifest profile)))
    (map (lambda (entry)
           (list (manifest-entry->package-specification entry)
                 (manifest-entry-item entry)))
         (manifest-entries manifest))))

(define (profile-difference profile1 profile2)
  "Return a list of package specifications for outputs installed in PROFILE1
and not installed in PROFILE2."
  (let ((specs1 (profile-package-specifications profile1))
        (specs2 (profile-package-specifications profile2)))
    (lset-difference string=? specs1 specs2)))

(define (manifest-entries->hash-table entries)
  "Return a hash table of name keys and lists of matching manifest ENTRIES."
  (let ((table (make-hash-table (length entries))))
    (for-each (lambda (entry)
                (let* ((key (manifest-entry-name entry))
                       (ref (hash-ref table key)))
                  (hash-set! table key
                             (if ref (cons entry ref) (list entry)))))
              entries)
    table))

(define (manifest=? m1 m2)
  (or (eq? m1 m2)
      (equal? m1 m2)))

(define manifest->hash-table
  (let ((current-manifest #f)
        (current-table #f))
    (lambda (manifest)
      "Return a hash table of name keys and matching MANIFEST entries."
      (unless (manifest=? manifest current-manifest)
        (set! current-manifest manifest)
        (set! current-table (manifest-entries->hash-table
                             (manifest-entries manifest))))
      current-table)))

(define* (manifest-entries-by-name manifest name #:optional version output)
  "Return a list of MANIFEST entries matching NAME, VERSION and OUTPUT."
  (let ((entries (or (hash-ref (manifest->hash-table manifest) name)
                     '())))
    (if (or version output)
        (filter (lambda (entry)
                  (and (or (not version)
                           (equal? version (manifest-entry-version entry)))
                       (or (not output)
                           (equal? output  (manifest-entry-output entry)))))
                entries)
        entries)))

(define (manifest-entry-by-output entries output)
  "Return a manifest entry from ENTRIES matching OUTPUT."
  (find (lambda (entry)
          (string= output (manifest-entry-output entry)))
        entries))

(define (fold-manifest-by-name manifest proc init)
  "Fold over MANIFEST entries.
Call (PROC NAME VERSION ENTRIES RESULT), using INIT as the initial value
of RESULT.  ENTRIES is a list of manifest entries with NAME/VERSION."
  (hash-fold (lambda (name entries res)
               (proc name (manifest-entry-version (car entries))
                     entries res))
             init
             (manifest->hash-table manifest)))

(define* (object-transformer param-alist #:optional (params '()))
  "Return procedure transforming objects into alist of parameter/value pairs.

PARAM-ALIST is alist of available parameters (symbols) and procedures
returning values of these parameters.  Each procedure is applied to
objects.

PARAMS is list of parameters from PARAM-ALIST that should be returned by
a resulting procedure.  If PARAMS is not specified or is an empty list,
use all available parameters.

Example:

  (let* ((alist `((plus1 . ,1+) (minus1 . ,1-) (mul2 . ,(cut * 2 <>))))
         (number->alist (object-transformer alist '(plus1 mul2))))
    (number->alist 8))
  =>
  ((plus1 . 9) (mul2 . 16))
"
  (let* ((use-all-params (null? params))
         (alist (filter-map (match-lambda
                             ((param . proc)
                              (and (or use-all-params
                                       (memq param params))
                                   (cons param proc)))
                             (_ #f))
                            param-alist)))
    (lambda objects
      (map (match-lambda
            ((param . proc)
             (cons param (apply proc objects))))
           alist))))

(define %manifest-entry-param-alist
  `((output       . ,manifest-entry-output)
    (path         . ,manifest-entry-item)
    (dependencies . ,manifest-entry-dependencies)))

(define manifest-entry->sexp
  (object-transformer %manifest-entry-param-alist))

(define (manifest-entries->sexps entries)
  (map manifest-entry->sexp entries))

(define (package-inputs-names inputs)
  "Return a list of full names of the packages from package INPUTS."
  (filter-map (match-lambda
               ((_ (? package? package))
                (make-package-specification (package-name package)
                                            (package-version package)))
               ((_ (? package? package) output)
                (make-package-specification (package-name package)
                                            (package-version package)
                                            output))
               (_ #f))
              inputs))

(define (package-license-names package)
  "Return a list of license names of the PACKAGE."
  (filter-map (lambda (license)
                (and (license? license)
                     (license-name license)))
              (list-maybe (package-license package))))

(define (package-source-names package)
  "Return a list of source names (URLs) of the PACKAGE."
  (let ((source (package-source package)))
    (and (origin? source)
         (filter-map (lambda (uri)
                       (cond ((string? uri)
                              uri)
                             ((git-reference? uri)
                              (git-reference-url uri))
                             (else "Unknown source type")))
                     (list-maybe (origin-uri source))))))

(define (package-unique? package)
  "Return #t if PACKAGE is a single package with such name/version."
  (match (packages-by-name (package-name package)
                           (package-version package))
    ((package) #t)
    (_ #f)))

(define %package-param-alist
  `((id                . ,object-address)
    (package-id        . ,object-address)
    (name              . ,package-name)
    (version           . ,package-version)
    (license           . ,package-license-names)
    (source            . ,package-source-names)
    (synopsis          . ,package-synopsis)
    (description       . ,package-description-string)
    (home-url          . ,package-home-page)
    (outputs           . ,package-outputs)
    (systems           . ,package-supported-systems)
    (non-unique        . ,(negate package-unique?))
    (inputs            . ,(lambda (pkg)
                            (package-inputs-names
                             (package-inputs pkg))))
    (native-inputs     . ,(lambda (pkg)
                            (package-inputs-names
                             (package-native-inputs pkg))))
    (propagated-inputs . ,(lambda (pkg)
                            (package-inputs-names
                             (package-propagated-inputs pkg))))
    (location          . ,(lambda (pkg)
                            (location->string (package-location pkg))))))

(define (package-param package param)
  "Return a value of a PACKAGE PARAM."
  (and=> (assq-ref %package-param-alist param)
         (cut <> package)))


;;; Finding packages.

(define-values (package-by-address
                register-package)
  (let ((table (delay (fold-packages
                       (lambda (package table)
                         (vhash-consq (object-address package)
                                      package table))
                       vlist-null))))
    (values
     (lambda (address)
       "Return package by its object ADDRESS."
       (match (vhash-assq address (force table))
         ((_ . package) package)
         (_ #f)))
     (lambda (package)
       "Register PACKAGE by its 'object-address', so that later
'package-by-address' can be used to access it."
       (let ((table* (force table)))
         (set! table
               (delay (vhash-consq (object-address package)
                                   package table*))))))))

(define packages-by-name+version
  (let ((table (delay (fold-packages
                       (lambda (package table)
                         (let ((file (location-file
                                      (package-location package))))
                           (vhash-cons (cons (package-name package)
                                             (package-version package))
                                       package table)))
                       vlist-null))))
    (lambda (name version)
      "Return packages matching NAME and VERSION."
      (vhash-fold* cons '() (cons name version) (force table)))))

(define (packages-by-full-name full-name)
  (call-with-values
      (lambda () (full-name->name+version full-name))
    packages-by-name+version))

(define (packages-by-id id)
  (if (integer? id)
      (let ((pkg (package-by-address id)))
        (if pkg (list pkg) '()))
      (packages-by-full-name id)))

(define (id->name+version id)
  (if (integer? id)
      (and=> (package-by-address id)
             (lambda (pkg)
               (values (package-name pkg)
                       (package-version pkg))))
      (full-name->name+version id)))

(define (package-by-id id)
  (first-or-false (packages-by-id id)))

(define (newest-package-by-id id)
  (and=> (id->name+version id)
         (lambda (name)
           (first-or-false (find-best-packages-by-name name #f)))))

(define (matching-packages predicate)
  (fold-packages (lambda (pkg res)
                   (if (predicate pkg)
                       (cons pkg res)
                       res))
                 '()))

(define (filter-packages-by-output packages output)
  (filter (lambda (package)
            (member output (package-outputs package)))
          packages))

(define* (packages-by-name name #:optional version output)
  "Return a list of packages matching NAME, VERSION and OUTPUT."
  (let ((packages (if version
                      (packages-by-name+version name version)
                      (matching-packages
                       (lambda (pkg) (string=? name (package-name pkg)))))))
    (if output
        (filter-packages-by-output packages output)
        packages)))

(define (manifest-entry->packages entry)
  (call-with-values
      (lambda () (manifest-entry->name+version+output entry))
    packages-by-name))

(define (packages-by-regexp regexp match-params)
  "Return a list of packages matching REGEXP string.
MATCH-PARAMS is a list of parameters that REGEXP can match."
  (define (package-match? package regexp)
    (any (lambda (param)
           (let ((val (package-param package param)))
             (and (string? val) (regexp-exec regexp val))))
         match-params))

  (let ((re (make-regexp regexp regexp/icase)))
    (matching-packages (cut package-match? <> re))))

(define (packages-by-license license)
  "Return a list of packages with LICENSE."
  (matching-packages
   (lambda (package)
     (memq license (list-maybe (package-license package))))))

(define (all-available-packages)
  "Return a list of all available packages."
  (matching-packages (const #t)))

(define (newest-available-packages)
  "Return a list of the newest available packages."
  (vhash-fold (lambda (name elem res)
                (match elem
                  ((_ newest pkgs ...)
                   (cons newest res))))
              '()
              (find-newest-available-packages)))

(define (packages-from-file file)
  "Return a list of packages from FILE."
  (let ((package (load (canonicalize-path file))))
    (if (package? package)
        (begin
          (register-package package)
          (list package))
        '())))


;;; Making package/output patterns.

(define (specification->package-pattern specification)
  (call-with-values
      (lambda ()
        (full-name->name+version specification))
    list))

(define (specification->output-pattern specification)
  (call-with-values
      (lambda ()
        (package-specification->name+version+output specification #f))
    list))

(define (id->package-pattern id)
  (if (integer? id)
      (package-by-address id)
      (specification->package-pattern id)))

(define (id->output-pattern id)
  "Return an output pattern by output ID.
ID should be '<package-address>:<output>' or '<name>-<version>:<output>'."
  (let-values (((name version output)
                (package-specification->name+version+output id)))
    (if version
        (list name version output)
        (list (package-by-address (string->number name))
              output))))

(define (specifications->package-patterns . specifications)
  (map specification->package-pattern specifications))

(define (specifications->output-patterns . specifications)
  (map specification->output-pattern specifications))

(define (ids->package-patterns . ids)
  (map id->package-pattern ids))

(define (ids->output-patterns . ids)
  (map id->output-pattern ids))

(define* (manifest-patterns-result packages res obsolete-pattern
                                   #:optional installed-pattern)
  "Auxiliary procedure for 'manifest-package-patterns' and
'manifest-output-patterns'."
  (if (null? packages)
      (cons (obsolete-pattern) res)
      (if installed-pattern
          ;; We don't need duplicates for a list of installed packages,
          ;; so just take any (car) package.
          (cons (installed-pattern (car packages)) res)
          res)))

(define* (manifest-package-patterns manifest #:optional obsolete-only?)
  "Return a list of package patterns for MANIFEST entries.
If OBSOLETE-ONLY? is #f, use all entries, otherwise make patterns only
for obsolete packages."
  (fold-manifest-by-name
   manifest
   (lambda (name version entries res)
     (manifest-patterns-result (packages-by-name name version)
                               res
                               (lambda () (list name version entries))
                               (and (not obsolete-only?)
                                    (cut list <> entries))))
   '()))

(define* (manifest-output-patterns manifest #:optional obsolete-only?)
  "Return a list of output patterns for MANIFEST entries.
If OBSOLETE-ONLY? is #f, use all entries, otherwise make patterns only
for obsolete packages."
  (fold (lambda (entry res)
          (manifest-patterns-result (manifest-entry->packages entry)
                                    res
                                    (lambda () entry)
                                    (and (not obsolete-only?)
                                         (cut list <> entry))))
        '()
        (manifest-entries manifest)))

(define (obsolete-package-patterns manifest)
  (manifest-package-patterns manifest #t))

(define (obsolete-output-patterns manifest)
  (manifest-output-patterns manifest #t))


;;; Transforming package/output patterns into alists.

(define (obsolete-package-sexp name version entries)
  "Return an alist with information about obsolete package.
ENTRIES is a list of installed manifest entries."
  `((id        . ,(name+version->full-name name version))
    (name      . ,name)
    (version   . ,version)
    (outputs   . ,(map manifest-entry-output entries))
    (obsolete  . #t)
    (installed . ,(manifest-entries->sexps entries))))

(define (package-pattern-transformer manifest params)
  "Return 'package-pattern->package-sexps' procedure."
  (define package->sexp
    (object-transformer %package-param-alist params))

  (define* (sexp-by-package package #:optional
                            (entries (manifest-entries-by-name
                                      manifest
                                      (package-name package)
                                      (package-version package))))
    (cons (cons 'installed (manifest-entries->sexps entries))
          (package->sexp package)))

  (define (->sexps pattern)
    (match pattern
      ((? package? package)
       (list (sexp-by-package package)))
      (((? package? package) entries)
       (list (sexp-by-package package entries)))
      ((name version entries)
       (list (obsolete-package-sexp
              name version entries)))
      ((name version)
       (let ((packages (packages-by-name name version)))
         (if (null? packages)
             (let ((entries (manifest-entries-by-name
                             manifest name version)))
               (if (null? entries)
                   '()
                   (list (obsolete-package-sexp
                          name version entries))))
             (map sexp-by-package packages))))
      (_ '())))

  ->sexps)

(define (output-pattern-transformer manifest params)
  "Return 'output-pattern->output-sexps' procedure."
  (define package->sexp
    (object-transformer (alist-delete 'id %package-param-alist)
                        params))

  (define manifest-entry->sexp
    (object-transformer (alist-delete 'output %manifest-entry-param-alist)
                        params))

  (define* (output-sexp pkg-alist pkg-address output
                        #:optional entry)
    (let ((entry-alist (if entry
                           (manifest-entry->sexp entry)
                           '()))
          (base `((id        . ,(string-append
                                 (number->string pkg-address)
                                 ":" output))
                  (output    . ,output)
                  (installed . ,(->bool entry)))))
      (append entry-alist base pkg-alist)))

  (define (obsolete-output-sexp entry)
    (let-values (((name version output)
                  (manifest-entry->name+version+output entry)))
      (let ((base `((id         . ,(make-package-specification
                                    name version output))
                    (package-id . ,(name+version->full-name name version))
                    (name       . ,name)
                    (version    . ,version)
                    (output     . ,output)
                    (obsolete   . #t)
                    (installed  . #t))))
        (append (manifest-entry->sexp entry) base))))

  (define* (sexps-by-package package #:optional output
                             (entries (manifest-entries-by-name
                                       manifest
                                       (package-name package)
                                       (package-version package))))
    ;; Assuming that PACKAGE has this OUTPUT.
    (let ((pkg-alist (package->sexp package))
          (address (object-address package))
          (outputs (if output
                       (list output)
                       (package-outputs package))))
      (map (lambda (output)
             (output-sexp pkg-alist address output
                          (manifest-entry-by-output entries output)))
           outputs)))

  (define* (sexps-by-manifest-entry entry #:optional
                                    (packages (manifest-entry->packages
                                               entry)))
    (if (null? packages)
        (list (obsolete-output-sexp entry))
        (map (lambda (package)
               (output-sexp (package->sexp package)
                            (object-address package)
                            (manifest-entry-output entry)
                            entry))
             packages)))

  (define (->sexps pattern)
    (match pattern
      ((? package? package)
       (sexps-by-package package))
      ((package (? string? output))
       (sexps-by-package package output))
      ((? manifest-entry? entry)
       (list (obsolete-output-sexp entry)))
      ((package entry)
       (sexps-by-manifest-entry entry (list package)))
      ((name version output)
       (let ((packages (packages-by-name name version output)))
         (if (null? packages)
             (let ((entries (manifest-entries-by-name
                             manifest name version output)))
               (append-map (cut sexps-by-manifest-entry <>)
                           entries))
             (append-map (cut sexps-by-package <> output)
                         packages))))
      (_ '())))

  ->sexps)

(define (entry-type-error entry-type)
  (error (format #f "Wrong entry-type '~a'" entry-type)))

(define (search-type-error entry-type search-type)
  (error (format #f "Wrong search type '~a' for entry-type '~a'"
                 search-type entry-type)))

(define %pattern-transformers
  `((package . ,package-pattern-transformer)
    (output  . ,output-pattern-transformer)))

(define (pattern-transformer entry-type)
  (assq-ref %pattern-transformers entry-type))

;; All procedures from inner alists are called with (MANIFEST . SEARCH-VALS)
;; as arguments; see `package/output-sexps'.
(define %patterns-makers
  (let* ((apply-to-rest         (lambda (proc)
                                  (lambda (_ . rest) (apply proc rest))))
         (apply-to-first        (lambda (proc)
                                  (lambda (first . _) (proc first))))
         (manifest-package-proc (apply-to-first manifest-package-patterns))
         (manifest-output-proc  (apply-to-first manifest-output-patterns))
         (regexp-proc           (lambda (_ regexp params . __)
                                  (packages-by-regexp regexp params)))
         (license-proc          (lambda (_ license-name)
                                  (packages-by-license
                                   (lookup-license license-name))))
         (location-proc         (lambda (_ location)
                                  (packages-by-location-file location)))
         (file-proc             (lambda (_ file)
                                  (packages-from-file file)))
         (all-proc              (lambda _ (all-available-packages)))
         (newest-proc           (lambda _ (newest-available-packages))))
    `((package
       (id               . ,(apply-to-rest ids->package-patterns))
       (name             . ,(apply-to-rest specifications->package-patterns))
       (installed        . ,manifest-package-proc)
       (obsolete         . ,(apply-to-first obsolete-package-patterns))
       (regexp           . ,regexp-proc)
       (license          . ,license-proc)
       (location         . ,location-proc)
       (from-file        . ,file-proc)
       (all-available    . ,all-proc)
       (newest-available . ,newest-proc))
      (output
       (id               . ,(apply-to-rest ids->output-patterns))
       (name             . ,(apply-to-rest specifications->output-patterns))
       (installed        . ,manifest-output-proc)
       (obsolete         . ,(apply-to-first obsolete-output-patterns))
       (regexp           . ,regexp-proc)
       (license          . ,license-proc)
       (location         . ,location-proc)
       (from-file        . ,file-proc)
       (all-available    . ,all-proc)
       (newest-available . ,newest-proc)))))

(define (patterns-maker entry-type search-type)
  (or (and=> (assq-ref %patterns-makers entry-type)
             (cut assq-ref <> search-type))
      (search-type-error entry-type search-type)))

(define (package/output-sexps profile params entry-type
                              search-type search-vals)
  "Return information about packages or package outputs.
See 'entry-sexps' for details."
  (let* ((manifest (profile-manifest profile))
         (patterns (if (and (eq? entry-type 'output)
                            (eq? search-type 'profile-diff))
                       (match search-vals
                         ((p1 p2)
                          (map specification->output-pattern
                               (profile-difference p1 p2)))
                         (_ '()))
                       (apply (patterns-maker entry-type search-type)
                              manifest search-vals)))
         (->sexps ((pattern-transformer entry-type) manifest params)))
    (append-map ->sexps patterns)))


;;; Getting information about generations.

(define (generation-param-alist profile)
  "Return an alist of generation parameters and procedures for PROFILE."
  (let ((current (generation-number profile)))
    `((id          . ,identity)
      (number      . ,identity)
      (prev-number . ,(cut previous-generation-number profile <>))
      (current     . ,(cut = current <>))
      (path        . ,(cut generation-file-name profile <>))
      (time        . ,(lambda (gen)
                        (time-second (generation-time profile gen)))))))

(define (matching-generations profile predicate)
  "Return a list of PROFILE generations matching PREDICATE."
  (filter predicate (profile-generations profile)))

(define (last-generations profile number)
  "Return a list of last NUMBER generations.
If NUMBER is 0 or less, return all generations."
  (let ((generations (profile-generations profile))
        (number (if (<= number 0) +inf.0 number)))
    (if (> (length generations) number)
        (list-head  (reverse generations) number)
        generations)))

(define (find-generations profile search-type search-vals)
  "Find PROFILE's generations matching SEARCH-TYPE and SEARCH-VALS."
  (case search-type
    ((id)
     (matching-generations profile (cut memq <> search-vals)))
    ((last)
     (last-generations profile (car search-vals)))
    ((all)
     (last-generations profile +inf.0))
    ((time)
     (match search-vals
       ((from to)
        (matching-generations
         profile
         (lambda (gen)
           (let ((time (time-second (generation-time profile gen))))
             (< from time to)))))
       (_ '())))
    (else (search-type-error "generation" search-type))))

(define (generation-sexps profile params search-type search-vals)
  "Return information about generations.
See 'entry-sexps' for details."
  (let ((generations (find-generations profile search-type search-vals))
        (->sexp (object-transformer (generation-param-alist profile)
                                    params)))
    (map ->sexp generations)))

(define system-generation-boot-parameters
  (memoize
   (lambda (profile generation)
     "Return boot parameters for PROFILE's system GENERATION."
     (let* ((gen-file   (generation-file-name profile generation))
            (param-file (string-append gen-file "/parameters")))
       (call-with-input-file param-file read-boot-parameters)))))

(define (system-generation-param-alist profile)
  "Return an alist of system generation parameters and procedures for
PROFILE."
  (append (generation-param-alist profile)
          `((label       . ,(lambda (gen)
                              (boot-parameters-label
                               (system-generation-boot-parameters
                                profile gen))))
            (root-device . ,(lambda (gen)
                              (boot-parameters-root-device
                               (system-generation-boot-parameters
                                profile gen))))
            (kernel      . ,(lambda (gen)
                              (boot-parameters-kernel
                               (system-generation-boot-parameters
                                profile gen)))))))

(define (system-generation-sexps profile params search-type search-vals)
  "Return an alist with information about system generations."
  (let ((generations (find-generations profile search-type search-vals))
        (->sexp (object-transformer (system-generation-param-alist profile)
                                    params)))
    (map ->sexp generations)))


;;; Getting package/output/generation entries (alists).

(define (entries profile params entry-type search-type search-vals)
  "Return information about entries.

ENTRY-TYPE is a symbol defining a type of returning information.  Should
be: 'package', 'output' or 'generation'.

SEARCH-TYPE and SEARCH-VALS define how to get the information.
SEARCH-TYPE should be one of the following symbols:

- If ENTRY-TYPE is 'package' or 'output':
  'id', 'name', 'regexp', 'all-available', 'newest-available',
  'installed', 'obsolete', 'generation'.

- If ENTRY-TYPE is 'generation':
  'id', 'last', 'all', 'time'.

PARAMS is a list of parameters for receiving.  If it is an empty list,
get information with all available parameters, which are:

- If ENTRY-TYPE is 'package':
  'id', 'name', 'version', 'outputs', 'license', 'synopsis',
  'description', 'home-url', 'inputs', 'native-inputs',
  'propagated-inputs', 'location', 'installed'.

- If ENTRY-TYPE is 'output':
  'id', 'package-id', 'name', 'version', 'output', 'license',
  'synopsis', 'description', 'home-url', 'inputs', 'native-inputs',
  'propagated-inputs', 'location', 'installed', 'path', 'dependencies'.

- If ENTRY-TYPE is 'generation':
  'id', 'number', 'prev-number', 'path', 'time'.

Returning value is a list of alists.  Each alist consists of
parameter/value pairs."
  (case entry-type
    ((package output)
     (package/output-sexps profile params entry-type
                           search-type search-vals))
    ((generation)
     (generation-sexps profile params
                       search-type search-vals))
    ((system-generation)
     (system-generation-sexps profile params
                              search-type search-vals))
    (else (entry-type-error entry-type))))


;;; Package actions.

(define* (package->manifest-entry* package #:optional output)
  (and package
       (package->manifest-entry package output)))

(define* (make-install-manifest-entries id #:optional output)
  (package->manifest-entry* (package-by-id id) output))

(define* (make-upgrade-manifest-entries id #:optional output)
  (package->manifest-entry* (newest-package-by-id id) output))

(define* (make-manifest-pattern id #:optional output)
  "Make manifest pattern from a package ID and OUTPUT."
  (let-values (((name version)
                (id->name+version id)))
    (and name version
         (manifest-pattern
          (name name)
          (version version)
          (output output)))))

(define (convert-action-pattern pattern proc)
  "Convert action PATTERN into a list of objects returned by PROC.
PROC is called: (PROC ID) or (PROC ID OUTPUT)."
  (match pattern
    ((id . outputs)
     (if (null? outputs)
         (let ((obj (proc id)))
           (if obj (list obj) '()))
         (filter-map (cut proc id <>)
                     outputs)))
    (_ '())))

(define (convert-action-patterns patterns proc)
  (append-map (cut convert-action-pattern <> proc)
              patterns))

(define* (process-package-actions
          profile #:key (install '()) (upgrade '()) (remove '())
          (use-substitutes? #t) dry-run?)
  "Perform package actions.

INSTALL, UPGRADE, REMOVE are lists of 'package action patterns'.
Each pattern should have the following form:

  (ID . OUTPUTS)

ID is an object address or a full-name of a package.
OUTPUTS is a list of package outputs (may be an empty list)."
  (format #t "The process begins ...~%")
  (let* ((install (append
                   (convert-action-patterns
                    install make-install-manifest-entries)
                   (convert-action-patterns
                    upgrade make-upgrade-manifest-entries)))
         (remove (convert-action-patterns remove make-manifest-pattern))
         (transaction (manifest-transaction (install install)
                                            (remove remove)))
         (manifest (profile-manifest profile))
         (new-manifest (manifest-perform-transaction
                        manifest transaction)))
    (unless (and (null? install) (null? remove))
      (parameterize ((%graft? (not dry-run?)))
        (with-store store
          (set-build-options store
                             #:print-build-trace #f
                             #:use-substitutes? use-substitutes?)
          (show-manifest-transaction store manifest transaction
                                     #:dry-run? dry-run?)
          (build-and-use-profile store profile new-manifest
                                 #:use-substitutes? use-substitutes?
                                 #:dry-run? dry-run?))))))

(define (delete-generations* profile generations)
  "Delete GENERATIONS from PROFILE.
GENERATIONS is a list of generation numbers."
  (with-store store
    (delete-generations store profile generations)))

(define (package-location-string id-or-name)
  "Return a location string of a package with ID-OR-NAME."
  (and=> (or (package-by-id id-or-name)
             (match (packages-by-name id-or-name)
               (()              #f)
               ((package _ ...) package)))
         (compose location->string package-location)))

(define (package-store-path package-id)
  "Return a list of store directories of outputs of package PACKAGE-ID."
  (match (package-by-id package-id)
    (#f '())
    (package
      (with-store store
        (map (match-lambda
               ((_ . drv)
                (derivation-output-path drv)))
             (derivation-outputs (package-derivation store package)))))))

(define (package-source-derivation->store-path derivation)
  "Return a store path of the package source DERIVATION."
  (match (derivation-outputs derivation)
    ;; Source derivation is always (("out" . derivation)).
    (((_ . output-drv))
     (derivation-output-path output-drv))
    (_ #f)))

(define (package-source-path package-id)
  "Return a store file path to a source of a package PACKAGE-ID."
  (and-let* ((package (package-by-id package-id))
             (source  (package-source package)))
    (with-store store
      (package-source-derivation->store-path
       (package-source-derivation store source)))))

(define* (package-source-build-derivation package-id #:key dry-run?
                                          (use-substitutes? #t))
  "Build source derivation of a package PACKAGE-ID."
  (and-let* ((package (package-by-id package-id))
             (source  (package-source package)))
    (with-store store
      (let* ((derivation  (package-source-derivation store source))
             (derivations (list derivation)))
        (set-build-options store
                           #:print-build-trace #f
                           #:use-substitutes? use-substitutes?)
        (show-what-to-build store derivations
                            #:use-substitutes? use-substitutes?
                            #:dry-run? dry-run?)
        (unless dry-run?
          (build-derivations store derivations))
        (format #t "The source store path: ~a~%"
                (package-source-derivation->store-path derivation))))))

(define (package-build-log-file package-id)
  "Return the build log file of a package PACKAGE-ID.
Return #f if the build log is not found."
  (and-let* ((package (package-by-id package-id)))
    (with-store store
      (let* ((derivation (package-derivation store package))
             (file       (derivation-file-name derivation)))
        (or (log-file store file)
            ((@@ (guix scripts build) log-url) store file))))))


;;; Executing guix commands

(define (guix-command . args)
  "Run 'guix ARGS ...' command."
  (catch 'quit
    (lambda () (apply run-guix args))
    (const #t)))

(define (guix-command-output . args)
  "Return 2 strings with 'guix ARGS ...' output and error output."
  (output+error
   (lambda ()
     (parameterize ((guix-warning-port (current-error-port)))
       (apply guix-command args)))))

(define (help-string . commands)
  "Return string with 'guix COMMANDS ... --help' output."
  (apply guix-command-output `(,@commands "--help")))

(define (pipe-guix-output guix-args command-args)
  "Run 'guix GUIX-ARGS ...' command and pipe its output to a shell command
defined by COMMAND-ARGS.
Return #t if the shell command was executed successfully."
  (let ((pipe (apply open-pipe* OPEN_WRITE command-args)))
    (with-output-to-port pipe
      (lambda () (apply guix-command guix-args)))
    (zero? (status:exit-val (close-pipe pipe)))))


;;; Lists of packages, lint checkers, etc.

(define (graph-type-names)
  "Return a list of names of available graph node types."
  (map (@ (guix graph) node-type-name)
       (@ (guix scripts graph) %node-types)))

(define (refresh-updater-names)
  "Return a list of names of available refresh updater types."
  (map (@ (guix upstream) upstream-updater-name)
       (@ (guix scripts refresh) %updaters)))

(define (lint-checker-names)
  "Return a list of names of available lint checkers."
  (map (lambda (checker)
         (symbol->string ((@ (guix scripts lint) lint-checker-name)
                          checker)))
       (@ (guix scripts lint) %checkers)))

(define (package-names)
  "Return a list of names of available packages."
  (delete-duplicates
   (fold-packages (lambda (pkg res)
                    (cons (package-name pkg) res))
                  '())))

;; See the comment to 'guix-package-names' function in "guix-popup.el".
(define (package-names-lists)
  (map list (package-names)))


;;; Licenses

(define %licenses
  (delay
    (filter license?
            (module-map (lambda (_ var)
                          (variable-ref var))
                        (resolve-interface '(guix licenses))))))

(define (licenses)
  (force %licenses))

(define (license-names)
  "Return a list of names of available licenses."
  (map license-name (licenses)))

(define lookup-license
  (memoize
   (lambda (name)
     "Return a license by its name."
     (find (lambda (l)
             (string=? name (license-name l)))
           (licenses)))))

(define (lookup-license-uri name)
  "Return a license URI by its name."
  (and=> (lookup-license name)
         license-uri))

(define %license-param-alist
  `((id      . ,license-name)
    (name    . ,license-name)
    (url     . ,license-uri)
    (comment . ,license-comment)))

(define license->sexp
  (object-transformer %license-param-alist))

(define (find-licenses search-type . search-values)
  "Return a list of licenses depending on SEARCH-TYPE and SEARCH-VALUES."
  (case search-type
    ((id name)
     (let ((names search-values))
       (filter-map lookup-license names)))
    ((all)
     (licenses))))

(define (license-entries search-type . search-values)
  (map license->sexp
       (apply find-licenses search-type search-values)))


;;; Package locations

(define-values (packages-by-location-file
                package-location-files)
  (let* ((table (delay (fold-packages
                        (lambda (package table)
                          (let ((file (location-file
                                       (package-location package))))
                            (vhash-cons file package table)))
                        vlist-null)))
         (files (delay (vhash-fold
                        (lambda (file _ result)
                          (if (member file result)
                              result
                              (cons file result)))
                        '()
                        (force table)))))
    (values
     (lambda (file)
       "Return the (possibly empty) list of packages defined in location FILE."
       (vhash-fold* cons '() file (force table)))
     (lambda ()
       "Return the list of file names of all package locations."
       (force files)))))

(define %package-location-param-alist
  `((id       . ,identity)
    (location . ,identity)
    (number-of-packages . ,(lambda (location)
                             (length (packages-by-location-file location))))))

(define package-location->sexp
  (object-transformer %package-location-param-alist))

(define (package-location-entries)
  (map package-location->sexp (package-location-files)))
