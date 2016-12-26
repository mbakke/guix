;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2013 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2016 David Craven <david@craven.ch>
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

(define-module (guix build-system cargo)
  #:use-module (guix search-paths)
  #:use-module (guix store)
  #:use-module (guix utils)
  #:use-module (guix derivations)
  #:use-module (guix packages)
  #:use-module (guix build-system)
  #:use-module (guix build-system gnu)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-26)
  #:export (cargo-build-system
            crate-url
            crate-url?
            crate-uri))

(define crate-url "https://crates.io/api/v1/crates/")
(define crate-url? (cut string-prefix? crate-url <>))

(define (crate-uri name version)
  "Return a URI string for the crate package hosted at crates.io corresponding
to NAME and VERSION."
  (string-append crate-url name "/" version "/download"))

(define (default-cargo)
  "Return the default Cargo package."
  ;; Lazily resolve the binding to avoid a circular dependency.
  (let ((rust (resolve-interface '(gnu packages rust))))
    ;; FIXME: Package cargo and replace cargo-bootstrap with cargo.
    (module-ref rust 'cargo-bootstrap)))

(define (default-rustc)
  "Return the default Rustc package."
  ;; Lazily resolve the binding to avoid a circular dependency.
  (let ((rust (resolve-interface '(gnu packages rust))))
    (module-ref rust 'rustc)))

(define %cargo-build-system-modules
  ;; Build-side modules imported by default.
  `((guix build cargo-build-system)
    ,@%gnu-build-system-modules))

(define* (cargo-build store name inputs
                      #:key
                      (tests? #t)
                      (test-target #f)
                      (configure-flags #f)
                      (phases '(@ (guix build cargo-build-system)
                                  %standard-phases))
                      (outputs '("out"))
                      (search-paths '())
                      (system (%current-system))
                      (guile #f)
                      (imported-modules %cargo-build-system-modules)
                      (modules '((guix build cargo-build-system)
                                 (guix build utils))))
  "Build SOURCE using CARGO, and with INPUTS."

  (define builder
    `(begin
       (use-modules ,@modules)
       (cargo-build #:name ,name
                    #:source ,(match (assoc-ref inputs "source")
                                (((? derivation? source))
                                 (derivation->output-path source))
                                ((source)
                                 source)
                                (source
                                 source))
                    #:system ,system
                    #:test-target ,test-target
                    #:tests? ,tests?
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

(define* (lower name
                #:key source inputs native-inputs outputs system target
                (cargo (default-cargo))
                (rustc (default-rustc))
                #:allow-other-keys
                #:rest arguments)
  "Return a bag for NAME."

  (define private-keywords
    '(#:source #:target #:cargo #:rustc #:inputs #:native-inputs))

  (and (not target) ;; TODO: support cross-compilation
       (bag
         (name name)
         (system system)
         (target target)
         (host-inputs `(,@(if source
                              `(("source" ,source))
                              '())
                        ,@inputs

                        ;; Keep the standard inputs of 'gnu-build-system'
                        ,@(standard-packages)))
         (build-inputs `(("cargo" ,cargo)
                         ("rustc" ,rustc)
                         ,@native-inputs))
         (outputs outputs)
         (build cargo-build)
         (arguments (strip-keyword-arguments private-keywords arguments)))))

(define cargo-build-system
  (build-system
    (name 'cargo)
    (description
     "Cargo build system, to build Rust crates")
    (lower lower)))
