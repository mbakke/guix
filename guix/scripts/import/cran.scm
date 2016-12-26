;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
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

(define-module (guix scripts import cran)
  #:use-module (guix ui)
  #:use-module (guix utils)
  #:use-module (guix scripts)
  #:use-module (guix import cran)
  #:use-module (guix scripts import)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-37)
  #:use-module (srfi srfi-41)
  #:use-module (ice-9 match)
  #:use-module (ice-9 format)
  #:export (guix-import-cran))


;;;
;;; Command-line options.
;;;

(define %default-options
  '())

(define (show-help)
  (display (_ "Usage: guix import cran PACKAGE-NAME
Import and convert the CRAN package for PACKAGE-NAME.\n"))
  (display (_ "
  -a, --archive=ARCHIVE  specify the archive repository"))
  (display (_ "
  -h, --help             display this help and exit"))
  (display (_ "
  -V, --version          display version information and exit"))
  (newline)
  (show-bug-report-information))

(define %options
  ;; Specification of the command-line options.
  (cons* (option '(#\h "help") #f #f
                 (lambda args
                   (show-help)
                   (exit 0)))
         (option '(#\V "version") #f #f
                 (lambda args
                   (show-version-and-exit "guix import cran")))
         (option '(#\a "archive") #t #f
                 (lambda (opt name arg result)
                   (alist-cons 'repo (string->symbol arg)
                               (alist-delete 'repo result))))
         (option '(#\r "recursive") #f #f
                 (lambda (opt name arg result)
                   (alist-cons 'recursive #t result)))
         %standard-import-options))


;;;
;;; Entry point.
;;;

(define (guix-import-cran . args)
  (define (parse-options)
    ;; Return the alist of option values.
    (args-fold* args %options
                (lambda (opt name arg result)
                  (leave (_ "~A: unrecognized option~%") name))
                (lambda (arg result)
                  (alist-cons 'argument arg result))
                %default-options))

  (let* ((opts (parse-options))
         (args (filter-map (match-lambda
                            (('argument . value)
                             value)
                            (_ #f))
                           (reverse opts))))
    (match args
      ((package-name)
       (if (assoc-ref opts 'recursive)
           ;; Recursive import
           (map (match-lambda
                  ((and ('package ('name name) . rest) pkg)
                   `(define-public ,(string->symbol name)
                      ,pkg))
                  (_ #f))
                (stream->list (recursive-import package-name
                                                (or (assoc-ref opts 'repo) 'cran))))
           ;; Single import
           (let ((sexp (cran->guix-package package-name
                                           (or (assoc-ref opts 'repo) 'cran))))
             (unless sexp
               (leave (_ "failed to download description for package '~a'~%")
                      package-name))
             sexp)))
      (()
       (leave (_ "too few arguments~%")))
      ((many ...)
       (leave (_ "too many arguments~%"))))))
