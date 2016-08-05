;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014 Deck Pickard <deck.r.pickard@gmail.com>
;;; Copyright © 2015, 2016 Alex Kost <alezost@gmail.com>
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

(define-module (guix scripts)
  #:use-module (guix grafts)
  #:use-module (guix utils)
  #:use-module (guix ui)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix packages)
  #:use-module (guix derivations)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-37)
  #:use-module (ice-9 match)
  #:export (args-fold*
            parse-command-line
            maybe-build
            build-package
            build-package-source))

;;; Commentary:
;;;
;;; General code for Guix scripts.
;;;
;;; Code:

(define (args-fold* options unrecognized-option-proc operand-proc . seeds)
  "A wrapper on top of `args-fold' that does proper user-facing error
reporting."
  (catch 'misc-error
    (lambda ()
      (apply args-fold options unrecognized-option-proc
             operand-proc seeds))
    (lambda (key proc msg args . rest)
      ;; XXX: MSG is not i18n'd.
      (leave (_ "invalid argument: ~a~%")
             (apply format #f msg args)))))

(define (environment-build-options)
  "Return additional build options passed as environment variables."
  (arguments-from-environment-variable "GUIX_BUILD_OPTIONS"))

(define %default-argument-handler
  ;; The default handler for non-option command-line arguments.
  (lambda (arg result)
    (alist-cons 'argument arg result)))

(define* (parse-command-line args options seeds
                             #:key
                             (argument-handler %default-argument-handler))
  "Parse the command-line arguments ARGS as well as arguments passed via the
'GUIX_BUILD_OPTIONS' environment variable according to OPTIONS (a list of
SRFI-37 options) and return the result, seeded by SEEDS.
Command-line options take precedence those passed via 'GUIX_BUILD_OPTIONS'.

ARGUMENT-HANDLER is called for non-option arguments, like the 'operand-proc'
parameter of 'args-fold'."
  (define (parse-options-from args seeds)
    ;; Actual parsing takes place here.
    (apply args-fold* args options
           (lambda (opt name arg . rest)
             (leave (_ "~A: unrecognized option~%") name))
           argument-handler
           seeds))

  (call-with-values
      (lambda ()
        (parse-options-from (environment-build-options) seeds))
    (lambda seeds
      ;; ARGS take precedence over what the environment variable specifies.
      (parse-options-from args seeds))))

(define* (maybe-build drvs
                      #:key dry-run? use-substitutes?)
  "Show what will/would be built, and actually build DRVS, unless DRY-RUN? is
true."
  (with-monad %store-monad
    (>>= (show-what-to-build* drvs
                              #:dry-run? dry-run?
                              #:use-substitutes? use-substitutes?)
         (lambda (_)
           (if dry-run?
               (return #f)
               (built-derivations drvs))))))

(define* (build-package package
                        #:key dry-run? (use-substitutes? #t)
                        #:allow-other-keys
                        #:rest build-options)
  "Build PACKAGE using BUILD-OPTIONS acceptable by 'set-build-options'.
Show what and how will/would be built."
  (mlet %store-monad ((grafting? ((lift0 %graft? %store-monad))))
    (apply set-build-options*
           #:use-substitutes? use-substitutes?
           (strip-keyword-arguments '(#:dry-run?) build-options))
    (mlet %store-monad ((derivation (package->derivation
                                     package #:graft? (and (not dry-run?)
                                                           grafting?))))
      (mbegin %store-monad
        (maybe-build (list derivation)
                     #:use-substitutes? use-substitutes?
                     #:dry-run? dry-run?)
        (return (show-derivation-outputs derivation))))))

(define* (build-package-source package
                               #:key dry-run? (use-substitutes? #t)
                               #:allow-other-keys
                               #:rest build-options)
  "Build PACKAGE source using BUILD-OPTIONS."
  (mbegin %store-monad
    (apply set-build-options*
           #:use-substitutes? use-substitutes?
           (strip-keyword-arguments '(#:dry-run?) build-options))
    (mlet %store-monad ((derivation (origin->derivation
                                     (package-source package))))
      (mbegin %store-monad
        (maybe-build (list derivation)
                     #:use-substitutes? use-substitutes?
                     #:dry-run? dry-run?)
        (return (show-derivation-outputs derivation))))))

;;; scripts.scm ends here
