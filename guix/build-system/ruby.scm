;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 David Thompson <davet@gnu.org>
;;; Copyright © 2014, 2015 Ludovic Courtès <ludo@gnu.org>
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

(define-module (guix build-system ruby)
  #:use-module (guix store)
  #:use-module (guix utils)
  #:use-module (guix gexp)
  #:use-module (guix monads)
  #:use-module (guix packages)
  #:use-module (guix derivations)
  #:use-module (guix search-paths)
  #:use-module (guix build-system)
  #:use-module (guix build-system gnu)
  #:use-module (ice-9 match)
  #:export (rubygems-uri
            %ruby-build-system-modules
            ruby-build
            ruby-build-system))

(define (rubygems-uri name version)
  "Return a URI string for the gem archive for the release corresponding to
NAME and VERSION."
  (string-append "https://rubygems.org/downloads/" name "-" version ".gem"))

(define %ruby-build-system-modules
  ;; Build-side modules imported by default.
  `((guix build ruby-build-system)
    ,@%gnu-build-system-modules))

(define (default-ruby)
  "Return the default Ruby package."
  ;; Lazily resolve the binding to avoid a circular dependency.
  (let ((ruby (resolve-interface '(gnu packages ruby))))
    (module-ref ruby 'ruby)))

(define* (lower name
                #:key source inputs native-inputs outputs system target
                (ruby (default-ruby))
                #:allow-other-keys
                #:rest arguments)
  "Return a bag for NAME."
  (define private-keywords
    '(#:target #:ruby #:inputs #:native-inputs))

  (and (not target)                    ;XXX: no cross-compilation
       (bag
         (name name)
         (system system)
         (host-inputs `(,@(if source
                              `(("source" ,source))
                              '())
                        ,@inputs

                        ;; Keep the standard inputs of 'gnu-build-system'.
                        ,@(standard-packages)))
         (build-inputs `(("ruby" ,ruby)
                         ,@native-inputs))
         (outputs outputs)
         (build ruby-build)
         (arguments (strip-keyword-arguments private-keywords arguments)))))

(define* (ruby-build name inputs
                     #:key source
                     (gem-flags ''())
                     (test-target "test")
                     (tests? #t)
                     (phases '(@ (guix build ruby-build-system)
                                 %standard-phases))
                     (outputs '("out"))
                     (search-paths '())
                     (system (%current-system))
                     (guile #f)
                     (imported-modules %ruby-build-system-modules)
                     (modules '((guix build ruby-build-system)
                                (guix build utils))))
  "Build SOURCE using RUBY and INPUTS."
  (define build
    #~(begin
        (use-modules #$@modules)

        #$(with-build-variables inputs outputs
            #~(ruby-build #:name #$name
                          #:source #+source
                          #:system #$system
                          #:gem-flags #$gem-flags
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

(define ruby-build-system
  (build-system
    (name 'ruby)
    (description "The standard Ruby build system")
    (lower lower)))
