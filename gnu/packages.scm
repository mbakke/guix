;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2016 Alex Kost <alezost@gmail.com>
;;; Copyright © 2016 Mathieu Lirzin <mthl@gnu.org>
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

(define-module (gnu packages)
  #:use-module (guix packages)
  #:use-module (guix ui)
  #:use-module (guix utils)
  #:use-module (guix combinators)
  #:use-module ((guix build utils)
                #:select ((package-name->name+version
                           . hyphen-separated-name->name+version)))
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 vlist)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:use-module (srfi srfi-39)
  #:export (search-patch
            search-patches
            search-bootstrap-binary
            %patch-path
            %bootstrap-binaries-path
            %package-module-path

            fold-packages
            scheme-modules                    ;XXX: for lack of a better place

            find-packages-by-name
            find-best-packages-by-name
            find-newest-available-packages

            specification->package
            specification->package+output))

;;; Commentary:
;;;
;;; General utilities for the software distribution---i.e., the modules under
;;; (gnu packages ...).
;;;
;;; Code:

;; By default, we store patches and bootstrap binaries alongside Guile
;; modules.  This is so that these extra files can be found without
;; requiring a special setup, such as a specific installation directory
;; and an extra environment variable.  One advantage of this setup is
;; that everything just works in an auto-compilation setting.

(define %bootstrap-binaries-path
  (make-parameter
   (map (cut string-append <> "/gnu/packages/bootstrap")
        %load-path)))

(define (search-patch file-name)
  "Search the patch FILE-NAME.  Raise an error if not found."
  (or (search-path (%patch-path) file-name)
      (raise (condition
              (&message (message (format #f (_ "~a: patch not found")
                                         file-name)))))))

(define-syntax-rule (search-patches file-name ...)
  "Return the list of absolute file names corresponding to each
FILE-NAME found in %PATCH-PATH."
  (list (search-patch file-name) ...))

(define (search-bootstrap-binary file-name system)
  "Search the bootstrap binary FILE-NAME for SYSTEM.  Raise an error if not
found."
  (or (search-path (%bootstrap-binaries-path)
                   (string-append system "/" file-name))
      (raise (condition
              (&message
               (message
                (format #f (_ "could not find bootstrap binary '~a' \
for system '~a'")
                        file-name system)))))))

(define %distro-root-directory
  ;; Absolute file name of the module hierarchy.
  (dirname (search-path %load-path "guix.scm")))

(define %package-module-path
  ;; Search path for package modules.  Each item must be either a directory
  ;; name or a pair whose car is a directory and whose cdr is a sub-directory
  ;; to narrow the search.
  (let* ((not-colon   (char-set-complement (char-set #\:)))
         (environment (string-tokenize (or (getenv "GUIX_PACKAGE_PATH") "")
                                       not-colon)))
    ;; Automatically add items from $GUIX_PACKAGE_PATH to Guile's search path.
    (for-each (lambda (directory)
                (set! %load-path (cons directory %load-path))
                (set! %load-compiled-path
                      (cons directory %load-compiled-path)))
              environment)

    (make-parameter
     (append environment `((,%distro-root-directory . "gnu/packages"))))))

(define %patch-path
  ;; Define it after '%package-module-path' so that '%load-path' contains user
  ;; directories, allowing patches in $GUIX_PACKAGE_PATH to be found.
  (make-parameter
   (map (lambda (directory)
          (if (string=? directory %distro-root-directory)
              (string-append directory "/gnu/packages/patches")
              directory))
        %load-path)))

(define* (scheme-files directory)
  "Return the list of Scheme files found under DIRECTORY, recursively.  The
returned list is sorted in alphabetical order."

  ;; Sort entries so that 'fold-packages' works in a deterministic fashion
  ;; regardless of details of the underlying file system.
  (sort (file-system-fold (const #t)                   ; enter?
                          (lambda (path stat result)   ; leaf
                            (if (string-suffix? ".scm" path)
                                (cons path result)
                                result))
                          (lambda (path stat result)   ; down
                            result)
                          (lambda (path stat result)   ; up
                            result)
                          (const #f)                   ; skip
                          (lambda (path stat errno result)
                            (warning (_ "cannot access `~a': ~a~%")
                                     path (strerror errno))
                            result)
                          '()
                          directory
                          stat)
        string<?))

(define file-name->module-name
  (let ((not-slash (char-set-complement (char-set #\/))))
    (lambda (file)
      "Return the module name (a list of symbols) corresponding to FILE."
      (map string->symbol
           (string-tokenize (string-drop-right file 4) not-slash)))))

(define* (scheme-modules directory #:optional sub-directory)
  "Return the list of Scheme modules available under DIRECTORY.
Optionally, narrow the search to SUB-DIRECTORY."
  (define prefix-len
    (string-length directory))

  (filter-map (lambda (file)
                (let* ((file   (substring file prefix-len))
                       (module (file-name->module-name file)))
                  (catch #t
                    (lambda ()
                      (resolve-interface module))
                    (lambda args
                      ;; Report the error, but keep going.
                      (warn-about-load-error module args)
                      #f))))
              (scheme-files (if sub-directory
                                (string-append directory "/" sub-directory)
                                directory))))

(define* (all-package-modules #:optional (path (%package-module-path)))
  "Return the list of package modules found in PATH, a list of directories to
search."
  (fold-right (lambda (spec result)
                (match spec
                  ((? string? directory)
                   (append (scheme-modules directory) result))
                  ((directory . sub-directory)
                   (append (scheme-modules directory sub-directory)
                           result))))
              '()
              path))

(define (fold-packages proc init)
  "Call (PROC PACKAGE RESULT) for each available package, using INIT as
the initial value of RESULT.  It is guaranteed to never traverse the
same package twice."
  (identity   ; discard second return value
   (fold2 (lambda (module result seen)
            (fold2 (lambda (var result seen)
                     (if (and (package? var)
                              (not (vhash-assq var seen))
                              (not (hidden-package? var)))
                         (values (proc var result)
                                 (vhash-consq var #t seen))
                         (values result seen)))
                   result
                   seen
                   (module-map (lambda (sym var)
                                 (false-if-exception (variable-ref var)))
                               module)))
          init
          vlist-null
          (all-package-modules))))

(define find-packages-by-name
  (let ((packages (delay
                    (fold-packages (lambda (p r)
                                     (vhash-cons (package-name p) p r))
                                   vlist-null)))
        (version>? (lambda (p1 p2)
                     (version>? (package-version p1) (package-version p2)))))
    (lambda* (name #:optional version)
      "Return the list of packages with the given NAME.  If VERSION is not #f,
then only return packages whose version is prefixed by VERSION, sorted in
decreasing version order."
      (let ((matching (sort (vhash-fold* cons '() name (force packages))
                            version>?)))
        (if version
            (filter (lambda (package)
                      (string-prefix? version (package-version package)))
                    matching)
            matching)))))

(define find-newest-available-packages
  (memoize
   (lambda ()
     "Return a vhash keyed by package names, and with
associated values of the form

  (newest-version newest-package ...)

where the preferred package is listed first."

     ;; FIXME: Currently, the preferred package is whichever one
     ;; was found last by 'fold-packages'.  Find a better solution.
     (fold-packages (lambda (p r)
                      (let ((name    (package-name p))
                            (version (package-version p)))
                        (match (vhash-assoc name r)
                          ((_ newest-so-far . pkgs)
                           (case (version-compare version newest-so-far)
                             ((>) (vhash-cons name `(,version ,p) r))
                             ((=) (vhash-cons name `(,version ,p ,@pkgs) r))
                             ((<) r)))
                          (#f (vhash-cons name `(,version ,p) r)))))
                    vlist-null))))

(define (find-best-packages-by-name name version)
  "If version is #f, return the list of packages named NAME with the highest
version numbers; otherwise, return the list of packages named NAME and at
VERSION."
  (if version
      (find-packages-by-name name version)
      (match (vhash-assoc name (find-newest-available-packages))
        ((_ version pkgs ...) pkgs)
        (#f '()))))


(define %sigint-prompt
  ;; The prompt to jump to upon SIGINT.
  (make-prompt-tag "interruptible"))

(define (call-with-sigint-handler thunk handler)
  "Call THUNK and return its value.  Upon SIGINT, call HANDLER with the signal
number in the context of the continuation of the call to this function, and
return its return value."
  (call-with-prompt %sigint-prompt
                    (lambda ()
                      (sigaction SIGINT
                        (lambda (signum)
                          (sigaction SIGINT SIG_DFL)
                          (abort-to-prompt %sigint-prompt signum)))
                      (dynamic-wind
                        (const #t)
                        thunk
                        (cut sigaction SIGINT SIG_DFL)))
                    (lambda (k signum)
                      (handler signum))))


;;;
;;; Package specification.
;;;

(define* (%find-package spec name version #:key fallback?)
  (match (find-best-packages-by-name name version)
    ((pkg . pkg*)
     (unless (null? pkg*)
       (warning (_ "ambiguous package specification `~a'~%") spec)
       (warning (_ "choosing ~a from ~a~%")
                (package-full-name pkg)
                (location->string (package-location pkg))))
     (when fallback?
       (warning (_ "deprecated NAME-VERSION syntax; \
use NAME@VERSION instead~%")))
     pkg)
    (_
     (if version
         (leave (_ "~A: package not found for version ~a~%") name version)
         (if (not fallback?)
             ;; XXX: Fallback to the older specification style with an hyphen
             ;; between NAME and VERSION, for backward compatibility.
             (call-with-values
                 (lambda ()
                   (hyphen-separated-name->name+version name))
               (cut %find-package spec <> <> #:fallback? #t))

             ;; The fallback case didn't find anything either, so bail out.
             (leave (_ "~A: unknown package~%") name))))))

(define (specification->package spec)
  "Return a package matching SPEC.  SPEC may be a package name, or a package
name followed by an at-sign and a version number.  If the version number is not
present, return the preferred newest version."
  (let-values (((name version) (package-name->name+version spec)))
    (%find-package spec name version)))

(define* (specification->package+output spec #:optional (output "out"))
  "Return the package and output specified by SPEC, or #f and #f; SPEC may
optionally contain a version number and an output name, as in these examples:

  guile
  guile@2.0.9
  guile:debug
  guile@2.0.9:debug

If SPEC does not specify a version number, return the preferred newest
version; if SPEC does not specify an output, return OUTPUT."
  (let-values (((name version sub-drv)
                (package-specification->name+version+output spec output)))
    (match (%find-package spec name version)
      (#f
       (values #f #f))
      (package
       (if (member sub-drv (package-outputs package))
           (values package sub-drv)
           (leave (_ "package `~a' lacks output `~a'~%")
                  (package-full-name package)
                  sub-drv))))))
