;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (guix scripts download)
  #:use-module (guix ui)
  #:use-module (guix scripts)
  #:use-module (guix store)
  #:use-module (guix hash)
  #:use-module (guix utils)
  #:use-module (guix base32)
  #:use-module ((guix download) #:hide (url-fetch))
  #:use-module ((guix build download)
                #:select (url-fetch current-terminal-columns))
  #:use-module ((guix build syscalls)
                #:select (terminal-columns))
  #:use-module (web uri)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-37)
  #:use-module (rnrs bytevectors)
  #:use-module (ice-9 binary-ports)
  #:export (guix-download))


;;;
;;; Command-line options.
;;;

(define (download-to-file url file)
  "Download the file at URI to FILE.  Return FILE."
  (let ((uri (string->uri url)))
    (match (uri-scheme uri)
      ((or 'file #f)
       (copy-file (uri-path uri) file))
      (_
       (url-fetch url file)))
    file))

(define* (download-to-store* url #:key (verify-certificate? #t))
  (with-store store
    (download-to-store store url
                       #:verify-certificate? verify-certificate?)))

(define %default-options
  ;; Alist of default option values.
  `((format . ,bytevector->nix-base32-string)
    (verify-certificate? . #t)
    (download-proc . ,download-to-store*)))

(define (show-help)
  (display (_ "Usage: guix download [OPTION] URL
Download the file at URL to the store or to the given file, and print its
file name and the hash of its contents.

Supported formats: 'nix-base32' (default), 'base32', and 'base16'
('hex' and 'hexadecimal' can be used as well).\n"))
  (format #t (_ "
  -f, --format=FMT       write the hash in the given format"))
  (format #t (_ "
      --no-check-certificate
                         do not validate the certificate of HTTPS servers "))
  (format #f (_ "
  -o, --output=FILE      download to FILE"))
  (newline)
  (display (_ "
  -h, --help             display this help and exit"))
  (display (_ "
  -V, --version          display version information and exit"))
  (newline)
  (show-bug-report-information))

(define %options
  ;; Specifications of the command-line options.
  (list (option '(#\f "format") #t #f
                (lambda (opt name arg result)
                  (define fmt-proc
                    (match arg
                      ("nix-base32"
                       bytevector->nix-base32-string)
                      ("base32"
                       bytevector->base32-string)
                      ((or "base16" "hex" "hexadecimal")
                       bytevector->base16-string)
                      (x
                       (leave (_ "unsupported hash format: ~a~%") arg))))

                  (alist-cons 'format fmt-proc
                              (alist-delete 'format result))))
        (option '("no-check-certificate") #f #f
                (lambda (opt name arg result)
                  (alist-cons 'verify-certificate? #f result)))
        (option '(#\o "output") #t #f
                (lambda (opt name arg result)
                  (alist-cons 'download-proc
                              (lambda* (url #:key verify-certificate?)
                                (download-to-file url arg))
                              (alist-delete 'download result))))

        (option '(#\h "help") #f #f
                (lambda args
                  (show-help)
                  (exit 0)))
        (option '(#\V "version") #f #f
                (lambda args
                  (show-version-and-exit "guix download")))))


;;;
;;; Entry point.
;;;

(define (guix-download . args)
  (define (parse-options)
    ;; Return the alist of option values.
    (args-fold* args %options
                (lambda (opt name arg result)
                  (leave (_ "~A: unrecognized option~%") name))
                (lambda (arg result)
                  (when (assq 'argument result)
                    (leave (_ "~A: extraneous argument~%") arg))

                  (alist-cons 'argument arg result))
                %default-options))

  (with-error-handling
    (let* ((opts  (parse-options))
           (arg   (or (assq-ref opts 'argument)
                      (leave (_ "no download URI was specified~%"))))
           (uri   (or (string->uri arg)
                      (leave (_ "~a: failed to parse URI~%")
                             arg)))
           (fetch (assq-ref opts 'download-proc))
           (path  (parameterize ((current-terminal-columns
                                  (terminal-columns)))
                    (fetch arg
                           #:verify-certificate?
                           (assq-ref opts 'verify-certificate?))))
           (hash  (call-with-input-file
                      (or path
                          (leave (_ "~a: download failed~%")
                                 arg))
                    port-sha256))
           (fmt   (assq-ref opts 'format)))
      (format #t "~a~%~a~%" path (fmt hash))
      #t)))
