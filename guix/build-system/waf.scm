;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Ricardo Wurmus <rekado@elephly.net>
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

(define-module (guix build-system waf)
  #:use-module (guix store)
  #:use-module (guix utils)
  #:use-module (guix gexp)
  #:use-module (guix monads)
  #:use-module (guix packages)
  #:use-module (guix derivations)
  #:use-module (guix search-paths)
  #:use-module (guix build-system)
  #:use-module (guix build-system gnu)
  #:use-module ((guix build-system python)
                #:select (default-python default-python2))
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-26)
  #:export (%waf-build-system-modules
            waf-build
            waf-build-system))

;; Commentary:
;;
;; Standard build procedure for applications using 'waf'.  This is very
;; similar to the 'python-build-system' and is implemented as an extension of
;; 'gnu-build-system'.
;;
;; Code:

(define %waf-build-system-modules
  ;; Build-side modules imported by default.
  `((guix build waf-build-system)
    ,@%gnu-build-system-modules))

(define* (lower name
                #:key source inputs native-inputs outputs system target
                (python (default-python))
                #:allow-other-keys
                #:rest arguments)
  "Return a bag for NAME."
  (define private-keywords
    '(#:target #:python #:inputs #:native-inputs))

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
         (build waf-build) ; only change compared to 'lower' in python.scm
         (arguments (strip-keyword-arguments private-keywords arguments)))))

(define* (waf-build name inputs
                    #:key source
                    (tests? #t)
                    (test-target "check")
                    (configure-flags ''())
                    (phases '(@ (guix build waf-build-system)
                                %standard-phases))
                    (outputs '("out"))
                    (search-paths '())
                    (system (%current-system))
                    (guile #f)
                    (imported-modules %waf-build-system-modules)
                    (modules '((guix build waf-build-system)
                               (guix build utils))))
  "Build SOURCE with INPUTS.  This assumes that SOURCE provides a 'waf' file
as its build system."
  (define build
    #~(begin
        (use-modules #$@modules)

        #$(with-build-variables inputs outputs
            #~(waf-build #:name #$name
                         #:source #+source
                         #:configure-flags #$configure-flags
                         #:system #$system
                         #:test-target #$test-target
                         #:tests? #$tests?
                         #:phases #$phases
                         #:outputs %outputs
                         #:search-paths '#$(map search-path-specification->sexp
                                                search-paths)
                         #:inputs %build-inputs))))

  (mlet %store-monad ((guile (package->derivation (or guile (default-guile))
                                                  system #:graft? #f)))
    (gexp->derivation name build
                      #:system system
                      #:modules imported-modules
                      #:guile-for-build guile)))

(define waf-build-system
  (build-system
    (name 'waf)
    (description "The standard waf build system")
    (lower lower)))

;;; waf.scm ends here
