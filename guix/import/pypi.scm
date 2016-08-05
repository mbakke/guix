;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 David Thompson <davet@gnu.org>
;;; Copyright © 2015 Cyril Roelandt <tipecaml@gmail.com>
;;; Copyright © 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (guix import pypi)
  #:use-module (ice-9 binary-ports)
  #:use-module (ice-9 match)
  #:use-module (ice-9 pretty-print)
  #:use-module (ice-9 regex)
  #:use-module ((ice-9 rdelim) #:select (read-line))
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:use-module (rnrs bytevectors)
  #:use-module (json)
  #:use-module (web uri)
  #:use-module (guix ui)
  #:use-module (guix utils)
  #:use-module ((guix build utils)
                #:select ((package-name->name+version
                           . hyphen-package-name->name+version)))
  #:use-module (guix import utils)
  #:use-module ((guix download) #:prefix download:)
  #:use-module (guix import json)
  #:use-module (guix packages)
  #:use-module (guix upstream)
  #:use-module (guix licenses)
  #:use-module (guix build-system python)
  #:use-module (gnu packages python)
  #:export (guix-package->pypi-name
            pypi->guix-package
            %pypi-updater))

(define (pypi-fetch name)
  "Return an alist representation of the PyPI metadata for the package NAME,
or #f on failure."
  ;; XXX: We want to silence the download progress report, which is especially
  ;; annoying for 'guix refresh', but we have to use a file port.
  (call-with-output-file "/dev/null"
    (lambda (null)
      (with-error-to-port null
        (lambda ()
          (json-fetch (string-append "https://pypi.python.org/pypi/"
                                     name "/json")))))))

;; For packages found on PyPI that lack a source distribution.
(define-condition-type &missing-source-error &error
  missing-source-error?
  (package  missing-source-error-package))

(define (latest-source-release pypi-package)
  "Return the latest source release for PYPI-PACKAGE."
  (let ((releases (assoc-ref* pypi-package "releases"
                              (assoc-ref* pypi-package "info" "version"))))
    (or (find (lambda (release)
                (string=? "sdist" (assoc-ref release "packagetype")))
              releases)
        (raise (condition (&missing-source-error
                           (package pypi-package)))))))

(define (latest-wheel-release pypi-package)
  "Return the url of the wheel for the latest release of pypi-package,
or #f if there isn't any."
  (let ((releases (assoc-ref* pypi-package "releases"
                              (assoc-ref* pypi-package "info" "version"))))
    (or (find (lambda (release)
                (string=? "bdist_wheel" (assoc-ref release "packagetype")))
              releases)
        #f)))

(define (python->package-name name)
  "Given the NAME of a package on PyPI, return a Guix-compliant name for the
package."
  (if (string-prefix? "python-" name)
      (snake-case name)
      (string-append "python-" (snake-case name))))

(define (guix-package->pypi-name package)
  "Given a Python PACKAGE built from pypi.python.org, return the name of the
package on PyPI."
  (let ((source-url (and=> (package-source package) origin-uri)))
    (hyphen-package-name->name+version
     (basename (file-sans-extension source-url)))))

(define (wheel-url->extracted-directory wheel-url)
  (match (string-split (basename wheel-url) #\-)
    ((name version _ ...)
     (string-append name "-" version ".dist-info"))))

(define (maybe-inputs package-inputs)
  "Given a list of PACKAGE-INPUTS, tries to generate the 'inputs' field of a
package definition."
  (match package-inputs
    (()
     '())
    ((package-inputs ...)
     `((inputs (,'quasiquote ,package-inputs))))))

(define (guess-requirements source-url wheel-url tarball)
  "Given SOURCE-URL, WHEEL-URL and a TARBALL of the package, return a list of
the required packages specified in the requirements.txt file. TARBALL will be
extracted in the current directory, and will be deleted."

  (define (tarball-directory url)
    ;; Given the URL of the package's tarball, return the name of the directory
    ;; that will be created upon decompressing it. If the filetype is not
    ;; supported, return #f.
    ;; TODO: Support more archive formats.
    (let ((basename (substring url (+ 1 (string-rindex url #\/)))))
      (cond
       ((string-suffix? ".tar.gz" basename)
        (string-drop-right basename 7))
       ((string-suffix? ".tar.bz2" basename)
        (string-drop-right basename 8))
       (else
        (begin
          (warning (_ "Unsupported archive format: \
cannot determine package dependencies"))
          #f)))))

  (define (clean-requirement s)
    ;; Given a requirement LINE, as can be found in a Python requirements.txt
    ;; file, remove everything other than the actual name of the required
    ;; package, and return it.
    (string-take s
     (or (string-index s #\space)
         (string-length s))))

  (define (comment? line)
    ;; Return #t if the given LINE is a comment, #f otherwise.
    (eq? (string-ref (string-trim line) 0) #\#))

  (define (read-requirements requirements-file)
    ;; Given REQUIREMENTS-FILE, a Python requirements.txt file, return a list
    ;; of name/variable pairs describing the requirements.
    (call-with-input-file requirements-file
      (lambda (port)
        (let loop ((result '()))
          (let ((line (read-line port)))
            (if (eof-object? line)
                result
                (cond
                 ((or (string-null? line) (comment? line))
                  (loop result))
                 (else
                  (loop (cons (python->package-name (clean-requirement line))
                              result))))))))))

  (define (read-wheel-metadata wheel-archive)
    ;; Given WHEEL-ARCHIVE, a ZIP Python wheel archive, return the package's
    ;; requirements.
    (let* ((dirname (wheel-url->extracted-directory wheel-url))
           (json-file (string-append dirname "/metadata.json")))
      (and (zero? (system* "unzip" "-q" wheel-archive json-file))
           (dynamic-wind
             (const #t)
             (lambda ()
               (call-with-input-file json-file
                 (lambda (port)
                   (let* ((metadata (json->scm port))
                          (run_requires (hash-ref metadata "run_requires"))
                          (requirements (if run_requires
                                            (hash-ref (list-ref run_requires 0)
                                                       "requires")
                                            '())))
                     (map (lambda (r)
                            (python->package-name (clean-requirement r)))
                          requirements)))))
             (lambda ()
               (delete-file json-file)
               (rmdir dirname))))))

  (define (guess-requirements-from-wheel)
    ;; Return the package's requirements using the wheel, or #f if an error
    ;; occurs.
    (call-with-temporary-output-file
     (lambda (temp port)
       (if wheel-url
         (and (url-fetch wheel-url temp)
              (read-wheel-metadata temp))
         #f))))


  (define (guess-requirements-from-source)
    ;; Return the package's requirements by guessing them from the source.
    (let ((dirname (tarball-directory source-url)))
      (if (string? dirname)
          (let* ((req-file (string-append dirname "/requirements.txt"))
                 (exit-code (system* "tar" "xf" tarball req-file)))
            ;; TODO: support more formats.
            (if (zero? exit-code)
                (dynamic-wind
                  (const #t)
                  (lambda ()
                    (read-requirements req-file))
                  (lambda ()
                    (delete-file req-file)
                    (rmdir dirname)))
                (begin
                  (warning (_ "'tar xf' failed with exit code ~a\n")
                           exit-code)
                  '())))
          '())))

  ;; First, try to compute the requirements using the wheel, since that is the
  ;; most reliable option. If a wheel is not provided for this package, try
  ;; getting them by reading the "requirements.txt" file from the source. Note
  ;; that "requirements.txt" is not mandatory, so this is likely to fail.
  (or (guess-requirements-from-wheel)
      (guess-requirements-from-source)))


(define (compute-inputs source-url wheel-url tarball)
  "Given the SOURCE-URL of an already downloaded TARBALL, return a list of
name/variable pairs describing the required inputs of this package."
  (sort
    (map (lambda (input)
           (list input (list 'unquote (string->symbol input))))
         (append '("python-setuptools")
                 ;; Argparse has been part of Python since 2.7.
                 (remove (cut string=? "python-argparse" <>)
                         (guess-requirements source-url wheel-url tarball))))
    (lambda args
      (match args
        (((a _ ...) (b _ ...))
         (string-ci<? a b))))))

(define (make-pypi-sexp name version source-url wheel-url home-page synopsis
                        description license)
  "Return the `package' s-expression for a python package with the given NAME,
VERSION, SOURCE-URL, HOME-PAGE, SYNOPSIS, DESCRIPTION, and LICENSE."
  (call-with-temporary-output-file
   (lambda (temp port)
     (and (url-fetch source-url temp)
          `(package
             (name ,(python->package-name name))
             (version ,version)
             (source (origin
                       (method url-fetch)

                       ;; Sometimes 'pypi-uri' doesn't quite work due to mixed
                       ;; cases in NAME, for instance, as is the case with
                       ;; "uwsgi".  In that case, fall back to a full URL.
                       (uri ,(if (equal? (pypi-uri name version) source-url)
                                 `(pypi-uri ,name version)
                                 `(string-append
                                   ,@(factorize-uri source-url version))))

                       (sha256
                        (base32
                         ,(guix-hash-url temp)))))
             (build-system python-build-system)
             ,@(maybe-inputs (compute-inputs source-url wheel-url temp))
             (home-page ,home-page)
             (synopsis ,synopsis)
             (description ,description)
             (license ,(license->symbol license)))))))

(define (pypi->guix-package package-name)
  "Fetch the metadata for PACKAGE-NAME from pypi.python.org, and return the
`package' s-expression corresponding to that package, or #f on failure."
  (let ((package (pypi-fetch package-name)))
    (and package
         (guard (c ((missing-source-error? c)
                    (let ((package (missing-source-error-package c)))
                      (leave (_ "no source release for pypi package ~a ~a~%")
                             (assoc-ref* package "info" "name")
                             (assoc-ref* package "info" "version")))))
           (let ((name (assoc-ref* package "info" "name"))
                 (version (assoc-ref* package "info" "version"))
                 (release (assoc-ref (latest-source-release package) "url"))
                 (wheel (assoc-ref (latest-wheel-release package) "url"))
                 (synopsis (assoc-ref* package "info" "summary"))
                 (description (assoc-ref* package "info" "summary"))
                 (home-page (assoc-ref* package "info" "home_page"))
                 (license (string->license (assoc-ref* package "info" "license"))))
             (make-pypi-sexp name version release wheel home-page synopsis
                             description license))))))

(define (pypi-package? package)
  "Return true if PACKAGE is a Python package from PyPI."

  (define (pypi-url? url)
    (string-prefix? "https://pypi.python.org/" url))

  (let ((source-url (and=> (package-source package) origin-uri))
        (fetch-method (and=> (package-source package) origin-method)))
    (and (eq? fetch-method download:url-fetch)
         (match source-url
           ((? string?)
            (pypi-url? source-url))
           ((source-url ...)
            (any pypi-url? source-url))))))

(define (latest-release package)
  "Return an <upstream-source> for the latest release of PACKAGE."
  (guard (c ((missing-source-error? c) #f))
    (let* ((pypi-name (guix-package->pypi-name package))
           (metadata (pypi-fetch pypi-name))
           (version (assoc-ref* metadata "info" "version"))
           (url (assoc-ref (latest-source-release metadata) "url")))
      (upstream-source
       (package (package-name package))
       (version version)
       (urls (list url))))))

(define %pypi-updater
  (upstream-updater
   (name 'pypi)
   (description "Updater for PyPI packages")
   (pred pypi-package?)
   (latest latest-release)))
