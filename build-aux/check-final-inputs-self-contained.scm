;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

;;;
;;; Check whether important binaries are available at hydra.gnu.org.
;;;

(use-modules (guix store)
             (guix grafts)
             (guix packages)
             (guix derivations)
             (guix ui)
             (gnu packages commencement)
             (ice-9 match)
             (srfi srfi-1)
             (srfi srfi-26))

(define (final-inputs store system)
  "Return the list of outputs directories of the final inputs for SYSTEM."
  (append-map (match-lambda
               ((name package)
                (let ((drv (package-derivation store package system)))
                  ;; Libc's 'debug' output refers to gcc-cross-boot0, but it's
                  ;; hard to avoid, so we tolerate it.  This should be the
                  ;; only exception.  Likewise, 'bash:include' depends on
                  ;; bootstrap-binaries via its 'Makefile.inc' (FIXME).
                  (filter-map (match-lambda
                               (("debug" . directory)
                                (if (string=? "glibc" (package-name package))
                                    #f
                                    directory))
                               (("include" . directory)
                                (if (string=? "bash" (package-name package))
                                    #f
                                    directory))
                               ((_ . directory) directory))
                              (derivation->output-paths drv)))))
              %final-inputs))

(define (assert-valid-substitute substitute)
  "Make sure SUBSTITUTE does not refer to any bootstrap inputs, and bail out
if it does."
  (let ((references (substitutable-references substitute)))
    (when (any (cut string-contains <> "boot") references)
      (leave (_ "'~a' refers to bootstrap inputs: ~s~%")
             (substitutable-path substitute) references))))

(define (test-final-inputs store system)
  "Check whether the final inputs for SYSTEM are clean---i.e., they don't
refer to the bootstrap tools."
  (format #t "checking final inputs for '~a'...~%" system)
  (let* ((inputs    (final-inputs store system))
         (available (substitutable-path-info store inputs)))
    (for-each (lambda (dir)
                (unless (find (lambda (substitute)
                                (string=? (substitutable-path substitute)
                                          dir))
                              available)
                  (leave (_ "~a (system: ~a) has no substitute~%")
                         dir system)))
              inputs)

    (for-each assert-valid-substitute available)))

;; Entry point.
(with-store store
  (parameterize ((%graft? #f))
    (set-build-options store #:use-substitutes? #t)

    (for-each (cut test-final-inputs store <>)
              %hydra-supported-systems)))

