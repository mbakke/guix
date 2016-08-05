;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (test-zlib)
  #:use-module (guix zlib)
  #:use-module (guix tests)
  #:use-module (srfi srfi-64)
  #:use-module (rnrs bytevectors)
  #:use-module (rnrs io ports)
  #:use-module (ice-9 match))

;; Test the (guix zlib) module.

(unless (zlib-available?)
  (exit 77))

(test-begin "zlib")

(test-assert "compression/decompression pipe"
  (let ((data (random-bytevector (+ (random 10000)
                                    (* 20 1024)))))
    (match (pipe)
      ((parent . child)
       (match (primitive-fork)
         (0                                       ;compress
          (dynamic-wind
            (const #t)
            (lambda ()
              (close-port parent)
              (call-with-gzip-output-port child
                (lambda (port)
                  (put-bytevector port data))))
            (lambda ()
              (primitive-exit 0))))
         (pid                                     ;decompress
          (begin
            (close-port child)
            (let ((received (call-with-gzip-input-port parent
                              (lambda (port)
                                (get-bytevector-all port))
                              #:buffer-size (* 64 1024))))
              (match (waitpid pid)
                ((_ . status)
                 (and (zero? status)
                      (port-closed? parent)
                      (bytevector=? received data))))))))))))

(test-end)
