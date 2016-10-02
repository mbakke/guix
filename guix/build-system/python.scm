;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2013 Nikita Karetnikov <nikita@karetnikov.org>
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

(define-module (guix build-system python)
  #:use-module (guix store)
  #:use-module (guix utils)
  #:use-module (guix combinators)
  #:use-module (guix packages)
  #:use-module (guix derivations)
  #:use-module (guix search-paths)
  #:use-module (guix build-system)
  #:use-module (guix build-system gnu)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (%python-build-system-modules
            package-with-python2
            strip-python2-variant
            default-python
            default-python2
            python-build
            python-build-system
            pypi-uri))

;; Commentary:
;;
;; Standard build procedure for Python packages using 'setup.py'.  This is
;; implemented as an extension of 'gnu-build-system'.
;;
;; Code:

(define* (pypi-uri name version #:optional (extension ".tar.gz"))
  "Return a URI string for the Python package hosted on the Python Package
Index (PyPI) corresponding to NAME and VERSION.  EXTENSION is the file name
extension, such as '.tar.gz'."
  (string-append "https://pypi.io/packages/source/"
                 (string-take name 1) "/" name "/"
                 name "-" version extension))

(define %python-build-system-modules
  ;; Build-side modules imported by default.
  `((guix build python-build-system)
    ,@%gnu-build-system-modules))

(define (default-python)
  "Return the default Python package."
  ;; Lazily resolve the binding to avoid a circular dependency.
  (let ((python (resolve-interface '(gnu packages python))))
    (module-ref python 'python-wrapper)))

(define (default-python2)
  "Return the default Python 2 package."
  (let ((python (resolve-interface '(gnu packages python))))
    (module-ref python 'python-2)))

(define* (package-with-explicit-python python old-prefix new-prefix
                                       #:key variant-property)
  "Return a procedure of one argument, P.  The procedure creates a package with
the same fields as P, which is assumed to use PYTHON-BUILD-SYSTEM, such that
it is compiled with PYTHON instead.  The inputs are changed recursively
accordingly.  If the name of P starts with OLD-PREFIX, this is replaced by
NEW-PREFIX; otherwise, NEW-PREFIX is prepended to the name.

When VARIANT-PROPERTY is present, it is used as a key to search for
pre-defined variants of this transformation recorded in the 'properties' field
of packages.  The property value must be the promise of a package.  This is a
convenient way for package writers to force the transformation to use
pre-defined variants."
  (define transform
    ;; Memoize the transformations.  Failing to do that, we would build a huge
    ;; object graph with lots of duplicates, which in turns prevents us from
    ;; benefiting from memoization in 'package-derivation'.
    (memoize                                      ;FIXME: use 'eq?'
     (lambda (p)
       (let* ((rewrite-if-package
               (lambda (content)
                 ;; CONTENT may be a file name, in which case it is returned,
                 ;; or a package, which is rewritten with the new PYTHON and
                 ;; NEW-PREFIX.
                 (if (package? content)
                     (transform content)
                     content)))
              (rewrite
               (match-lambda
                 ((name content . rest)
                  (append (list name (rewrite-if-package content)) rest)))))

         (cond
          ;; If VARIANT-PROPERTY is present, use that.
          ((and variant-property
                (assoc-ref (package-properties p) variant-property))
           => force)

          ;; Otherwise build the new package object graph.
          ((eq? (package-build-system p) python-build-system)
           (package
             (inherit p)
             (location (package-location p))
             (name (let ((name (package-name p)))
                     (string-append new-prefix
                                    (if (string-prefix? old-prefix name)
                                        (substring name
                                                   (string-length old-prefix))
                                        name))))
             (arguments
              (let ((python (if (promise? python)
                                (force python)
                                python)))
                (ensure-keyword-arguments (package-arguments p)
                                          `(#:python ,python))))
             (inputs (map rewrite (package-inputs p)))
             (propagated-inputs (map rewrite (package-propagated-inputs p)))
             (native-inputs (map rewrite (package-native-inputs p)))))
          (else
           p))))))

  transform)

(define package-with-python2
  ;; Note: delay call to 'default-python2' until after the 'arguments' field
  ;; of packages is accessed to avoid a circular dependency when evaluating
  ;; the top-level of (gnu packages python).
  (package-with-explicit-python (delay (default-python2))
                                "python-" "python2-"
                                #:variant-property 'python2-variant))

(define (strip-python2-variant p)
  "Remove the 'python2-variant' property from P."
  (package
    (inherit p)
    (properties (alist-delete 'python2-variant (package-properties p)))))

(define* (lower name
                #:key source inputs native-inputs outputs system target
                (python (default-python))
                #:allow-other-keys
                #:rest arguments)
  "Return a bag for NAME."
  (define private-keywords
    '(#:source #:target #:python #:inputs #:native-inputs))

  (and (not target)                               ;XXX: no cross-compilation
       (bag
         (name name)
         (system system)
         (host-inputs `(,@(if source
                              `(("source" ,source))
                              '())
                        ,@inputs

                        ;; Keep the standard inputs of 'gnu-build-system'.
                        ,@(standard-packages)))
         (build-inputs `(("python" ,python)
                         ,@native-inputs))
         (outputs outputs)
         (build python-build)
         (arguments (strip-keyword-arguments private-keywords arguments)))))

(define* (python-build store name inputs
                       #:key
                       (tests? #t)
                       (test-target "test")
                       (use-setuptools? #t)
                       (configure-flags ''())
                       (phases '(@ (guix build python-build-system)
                                   %standard-phases))
                       (outputs '("out"))
                       (search-paths '())
                       (system (%current-system))
                       (guile #f)
                       (imported-modules %python-build-system-modules)
                       (modules '((guix build python-build-system)
                                  (guix build utils))))
  "Build SOURCE using PYTHON, and with INPUTS.  This assumes that SOURCE
provides a 'setup.py' file as its build system."
  (define builder
    `(begin
       (use-modules ,@modules)
       (python-build #:name ,name
                     #:source ,(match (assoc-ref inputs "source")
                                 (((? derivation? source))
                                  (derivation->output-path source))
                                 ((source)
                                  source)
                                 (source
                                  source))
                     #:configure-flags ,configure-flags
                     #:system ,system
                     #:test-target ,test-target
                     #:tests? ,tests?
                     #:use-setuptools? ,use-setuptools?
                     #:phases ,phases
                     #:outputs %outputs
                     #:search-paths ',(map search-path-specification->sexp
                                           search-paths)
                     #:inputs %build-inputs)))

  (define guile-for-build
    (match guile
      ((? package?)
       (package-derivation store guile system #:graft? #f))
      (#f                                         ; the default
       (let* ((distro (resolve-interface '(gnu packages commencement)))
              (guile  (module-ref distro 'guile-final)))
         (package-derivation store guile system #:graft? #f)))))

  (build-expression->derivation store name builder
                                #:inputs inputs
                                #:system system
                                #:modules imported-modules
                                #:outputs outputs
                                #:guile-for-build guile-for-build))

(define python-build-system
  (build-system
    (name 'python)
    (description "The standard Python build system")
    (lower lower)))

;;; python.scm ends here
