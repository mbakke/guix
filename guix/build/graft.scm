;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Mark H Weaver <mhw@netris.org>
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

(define-module (guix build graft)
  #:use-module (guix build utils)
  #:use-module (rnrs bytevectors)
  #:use-module (rnrs io ports)
  #:use-module (ice-9 match)
  #:use-module (ice-9 threads)
  #:use-module (ice-9 binary-ports)
  #:use-module (srfi srfi-1)   ; list library
  #:use-module (srfi srfi-26)  ; cut and cute
  #:export (replace-store-references
            rewrite-directory))

;;; Commentary:
;;;
;;; This module supports "grafts".  Grafting a directory means rewriting it,
;;; with references to some specific items replaced by references to other
;;; store items---the grafts.
;;;
;;; This method is used to provide fast security updates as only the leaves of
;;; the dependency graph need to be grafted, even when the security updates
;;; affect a core component such as Bash or libc.  It is based on the idea of
;;; 'replace-dependency' implemented by Shea Levy in Nixpkgs.
;;;
;;; Code:

(define hash-length 32)

(define nix-base32-char?
  (cute char-set-contains?
        ;; ASCII digits and lower case letters except e o t u
        (string->char-set "0123456789abcdfghijklmnpqrsvwxyz")
        <>))

(define* (replace-store-references input output lookup-replacement
                                   #:optional (store (%store-directory)))
  "Read data from INPUT, replacing store references according to
LOOKUP-REPLACEMENT, and writing the result to OUTPUT."

  (define request-size (expt 2 20))  ; 1 MB

  (define (optimize-u8-predicate pred)
    (cute vector-ref
          (list->vector (map pred (iota 256)))
          <>))

  (define nix-base32-byte?
    (optimize-u8-predicate
     (compose nix-base32-char?
              integer->char)))

  (define (dash? byte) (= byte 45))

  (let ((buffer (make-bytevector request-size)))
    (let loop ()
      ;; Note: work around <http://bugs.gnu.org/17466>.
      (match (get-bytevector-n! input buffer 0 request-size)
        ((? eof-object?) 'done)
        (end
         ;; Scan the buffer for dashes preceded by a valid nix hash.
         (let scan-from ((i hash-length) (written 0))
           (if (< i end)
               (let ((byte (bytevector-u8-ref buffer i)))
                 (cond ((and (dash? byte)
                             (lookup-replacement
                              (string-tabulate (lambda (j)
                                                 (integer->char
                                                  (bytevector-u8-ref buffer
                                                   (+ j (- i hash-length)))))
                                               hash-length)))
                        => (lambda (replacement)
                             (put-bytevector output buffer written
                                             (- i hash-length written))
                             (put-bytevector output replacement)
                             (scan-from (+ i 1 hash-length) i)))
                       ((nix-base32-byte? byte)
                        (scan-from (+ i 1) written))
                       (else
                        (scan-from (+ i 1 hash-length) written))))
               (let* ((unwritten   (- end written))
                      (unget-size  (if (= end request-size)
                                       (min hash-length unwritten)
                                       0))
                      (write-size  (- unwritten unget-size)))
                 (put-bytevector output buffer written write-size)
                 (unget-bytevector input buffer (+ written write-size)
                                   unget-size)
                 (loop)))))))))

(define* (rewrite-directory directory output mapping
                            #:optional (store (%store-directory)))
  "Copy DIRECTORY to OUTPUT, replacing strings according to MAPPING, a list of
file name pairs."

  (define lookup-replacement
    (let* ((prefix (string-append store "/"))
           (start  (string-length prefix))
           (end    (+ start hash-length))
           (table  (make-hash-table)))
      (define (valid-prefix? p) (string=? p prefix))
      (define (valid-suffix? s) (string-prefix? "-" s))
      (define (valid-hash? h)
        (and (= hash-length (string-length h))
             (every nix-base32-char?
                    (string->list h))))
      (define (components s)
        (and (< end (string-length s))
             (list (substring s 0 start)
                   (substring s start end)
                   (substring s end))))
      (for-each (match-lambda
                  (((= components ((? valid-prefix?)
                                   (? valid-hash? origin-hash)
                                   (? valid-suffix? suffix)))
                    .
                    (= components ((? valid-prefix?)
                                   (? valid-hash? replacement-hash)
                                   (? valid-suffix? suffix))))
                   (hash-set! table origin-hash
                              (string->utf8 replacement-hash)))
                  ((origin . replacement)
                   (error "invalid replacement" origin replacement)))
                mapping)
      (cut hash-ref table <>)))

  (define prefix-len
    (string-length directory))

  (define (destination file)
    (string-append output (string-drop file prefix-len)))

  (define (rewrite-leaf file)
    (let ((stat (lstat file))
          (dest (destination file)))
      (mkdir-p (dirname dest))
      (case (stat:type stat)
        ((symlink)
         (let ((target (readlink file)))
           (symlink (call-with-output-string
                      (lambda (output)
                        (replace-store-references (open-input-string target)
                                                  output lookup-replacement
                                                  store)))
                    dest)))
        ((regular)
         (call-with-input-file file
           (lambda (input)
             (call-with-output-file dest
               (lambda (output)
                 (replace-store-references input output lookup-replacement
                                           store)
                 (chmod output (stat:perms stat)))))))
        (else
         (error "unsupported file type" stat)))))

  ;; XXX: Work around occasional "suspicious ownership or permission" daemon
  ;; errors that arise when we create the top-level /gnu/store/… directory as
  ;; #o777.
  (umask #o022)

  (n-par-for-each (parallel-job-count)
                  rewrite-leaf (find-files directory)))

;;; graft.scm ends here
