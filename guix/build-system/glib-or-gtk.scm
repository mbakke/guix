;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013 Cyril Roelandt <tipecaml@gmail.com>
;;; Copyright © 2014 Federico Beffa <beffa@fbengineering.ch>
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

(define-module (guix build-system glib-or-gtk)
  #:use-module (guix store)
  #:use-module (guix utils)
  #:use-module (guix gexp)
  #:use-module (guix monads)
  #:use-module (guix derivations)
  #:use-module (guix search-paths)
  #:use-module (guix build-system)
  #:use-module (guix build-system gnu)
  #:use-module (guix packages)
  #:use-module (ice-9 match)
  #:export (%glib-or-gtk-build-system-modules
            glib-or-gtk-build
            glib-or-gtk-build-system))

;; Commentary:
;;
;; This build system is an extension of the 'gnu-build-system'.  It
;; accomodates the needs of applications making use of glib or gtk+ (with "or"
;; to be interpreted in the mathematical sense).  This is achieved by adding
;; two phases run after the 'install' phase:
;;
;; 'glib-or-gtk-wrap' phase:
;;
;; a) This phase looks for GSettings schemas, GIO modules and theming data.
;; If any of these is found in any input package, then all programs in
;; "out/bin" are wrapped in scripts defining the nedessary environment
;; variables.
;;
;; b) Looks for the existence of "libdir/gtk-3.0" directories in all input
;; packages.  If any is found, then the environment variable "GTK_PATH" is
;; suitably set and added to the wrappers.  The variable "GTK_PATH" has been
;; preferred over "GTK_EXE_PREFIX" because the latter can only point to a
;; single directory, while we may need to point to several ones.
;;
;; 'glib-or-gtk-compile-schemas' phase:
;;
;; Looks for the presence of "out/share/glib-2.0/schemas".  If that directory
;; exists and does not include a file named "gschemas.compiled", then
;; "glib-compile-schemas" is run in that directory.
;;
;; Code:

(define %default-modules
  ;; Build-side modules made available in the build environment.
  '((guix build glib-or-gtk-build-system)
    (guix build utils)))

(define %glib-or-gtk-build-system-modules
  ;; Build-side modules imported and used by default.
  `((guix build glib-or-gtk-build-system)
    ,@%gnu-build-system-modules))

(define (default-glib)
  "Return the default glib package from which we use
\"glib-compile-schemas\"."
  ;; Do not use `@' to avoid introducing circular dependencies.
  (let ((module (resolve-interface '(gnu packages glib))))
    (module-ref module 'glib)))

(define* (lower name
                #:key source inputs native-inputs outputs system target
                (glib (default-glib))
                (implicit-inputs? #t)
                (strip-binaries? #t)
                #:allow-other-keys
                #:rest arguments)
  "Return a bag for NAME."
  (define private-keywords
    '(#:target #:glib #:inputs #:native-inputs
      #:outputs #:implicit-inputs?))

  (and (not target)                               ;XXX: no cross-compilation
       (bag
         (name name)
         (system system)
         (host-inputs `(,@(if source
                              `(("source" ,source))
                              '())
                        ,@inputs))
         (build-inputs `(("glib:bin" ,glib "bin") ; to compile schemas
                         ,@(if implicit-inputs?
                               (standard-packages)
                               '())
                         ,@native-inputs))
         (outputs outputs)
         (build glib-or-gtk-build)
         (arguments (strip-keyword-arguments private-keywords arguments)))))

(define* (glib-or-gtk-build name inputs
                            #:key guile source
                            (outputs '("out"))
                            (search-paths '())
                            (configure-flags ''())
                            (make-flags ''())
                            (out-of-source? #t)
                            (tests? #t)
                            (test-target "check")
                            (parallel-build? #t)
                            (parallel-tests? #t)
                            (validate-runpath? #t)
                            (patch-shebangs? #t)
                            (strip-binaries? #t)
                            (strip-flags ''("--strip-debug"))
                            (strip-directories ''("lib" "lib64" "libexec"
                                                  "bin" "sbin"))
                            (phases '(@ (guix build glib-or-gtk-build-system)
                                        %standard-phases))
                            (glib-or-gtk-wrap-excluded-outputs ''())
                            (system (%current-system))
                            (imported-modules %glib-or-gtk-build-system-modules)
                            (modules %default-modules)
                            allowed-references)
  "Build SOURCE with INPUTS.  See GNU-BUILD for more details."
  (define build
    #~(begin
        (use-modules #$modules)

        #$(with-build-variables inputs outputs
            #~(glib-or-gtk-build #:source #+source
                                 #:system #$system
                                 #:outputs %outputs
                                 #:inputs %build-inputs
                                 #:search-paths '#$(map search-path-specification->sexp
                                                        search-paths)
                                 #:phases #$phases
                                 #:glib-or-gtk-wrap-excluded-outputs
                                 #$glib-or-gtk-wrap-excluded-outputs
                                 #:configure-flags #$configure-flags
                                 #:make-flags #$make-flags
                                 #:out-of-source? #$out-of-source?
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
                      #:allowed-references allowed-references
                      #:guile-for-build guile)))

(define glib-or-gtk-build-system
  (build-system
    (name 'glib-or-gtk)
    (description
     "The GNU Build System—i.e., ./configure && make && make install,
augmented with definition of suitable environment variables for glib and gtk+
in program wrappers.")
    (lower lower)))
