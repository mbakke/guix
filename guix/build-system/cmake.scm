;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013 Cyril Roelandt <tipecaml@gmail.com>
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

(define-module (guix build-system cmake)
  #:use-module (guix store)
  #:use-module (guix gexp)
  #:use-module (guix utils)
  #:use-module (guix monads)
  #:use-module (guix derivations)
  #:use-module (guix search-paths)
  #:use-module (guix build-system)
  #:use-module (guix build-system gnu)
  #:use-module (guix packages)
  #:use-module (ice-9 match)
  #:export (%cmake-build-system-modules
            cmake-build
            cmake-build-system))

;; Commentary:
;;
;; Standard build procedure for packages using CMake. This is implemented as an
;; extension of `gnu-build-system'.
;;
;; Code:

(define %cmake-build-system-modules
  ;; Build-side modules imported by default.
  `((guix build cmake-build-system)
    ,@%gnu-build-system-modules))

(define (default-cmake)
  "Return the default CMake package."

  ;; Do not use `@' to avoid introducing circular dependencies.
  (let ((module (resolve-interface '(gnu packages cmake))))
    (module-ref module 'cmake)))

(define* (lower name
                #:key source inputs native-inputs outputs system target
                (cmake (default-cmake))
                #:allow-other-keys
                #:rest arguments)
  "Return a bag for NAME."
  (define private-keywords
    '(#:target #:cmake #:inputs #:native-inputs))

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
         (build-inputs `(("cmake" ,cmake)
                         ,@native-inputs))
         (outputs outputs)
         (build cmake-build)
         (arguments (strip-keyword-arguments private-keywords arguments)))))

(define* (cmake-build name inputs
                      #:key guile source
                      (outputs '("out")) (configure-flags ''())
                      (search-paths '())
                      (make-flags ''())
                      (out-of-source? #t)
                      (build-type "RelWithDebInfo")
                      (tests? #t)
                      (test-target "test")
                      (parallel-build? #t) (parallel-tests? #f)
                      (validate-runpath? #t)
                      (patch-shebangs? #t)
                      (strip-binaries? #t)
                      (strip-flags ''("--strip-debug"))
                      (strip-directories ''("lib" "lib64" "libexec"
                                            "bin" "sbin"))
                      (phases '(@ (guix build cmake-build-system)
                                  %standard-phases))
                      (system (%current-system))
                      (imported-modules %cmake-build-system-modules)
                      (modules '((guix build cmake-build-system)
                                 (guix build utils))))
  "Build SOURCE using CMAKE, and with INPUTS. This assumes that SOURCE
provides a 'CMakeLists.txt' file as its build system."
  (define build
    #~(begin
        (use-modules ,@modules)

        #$(with-build-variables inputs outputs
            #~(cmake-build #:source #+source
                           #:system #$system
                           #:outputs %outputs
                           #:inputs %build-inputs
                           #:search-paths '#$(map search-path-specification->sexp
                                                  search-paths)
                           #:phases #$phases
                           #:configure-flags #$configure-flags
                           #:make-flags #$make-flags
                           #:out-of-source? #$out-of-source?
                           #:build-type #$build-type
                           #:tests? #$tests?
                           #:test-target #$test-target
                           #:parallel-build? #$parallel-build?
                           #:parallel-tests? #$parallel-tests?
                           #:validate-runpath? #$validate-runpath?
                           #:patch-shebangs? #$patch-shebangs?
                           #:strip-binaries? #$strip-binaries?
                           #:strip-flags #$strip-flags
                           #:strip-directories #$strip-directories))))

  (mlet %store-monad ((guile (package->derivation (or guile (default-guile))
                                                  system #:graft? #f)))
    (gexp->derivation name build
                      #:system system
                      #:modules imported-modules
                      #:guile-for-build guile)))

(define cmake-build-system
  (build-system
    (name 'cmake)
    (description "The standard CMake build system")
    (lower lower)))

;;; cmake.scm ends here
