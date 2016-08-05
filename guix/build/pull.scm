;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Taylan Ulrich Bayırlı/Kammer <taylanbayirli@gmail.com>
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

(define-module (guix build pull)
  #:use-module (guix build utils)
  #:use-module (system base compile)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 match)
  #:use-module (ice-9 format)
  #:use-module (ice-9 threads)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-26)
  #:export (build-guix))

;;; Commentary:
;;;
;;; Helpers for the 'guix pull' command to unpack and build Guix.
;;;
;;; Code:

(define* (build-guix out source
                     #:key
                     system
                     storedir localstatedir sysconfdir sbindir

                     (package-name "GNU Guix")
                     (package-version "0")
                     (bug-report-address "bug-guix@gnu.org")
                     (home-page-url "https://gnu.org/s/guix")

                     libgcrypt zlib gzip bzip2 xz

                     (debug-port (%make-void-port "w"))
                     (log-port (current-error-port)))
  "Build and install Guix in directory OUT using SOURCE, a directory
containing the source code.  Write any debugging output to DEBUG-PORT."
  (setvbuf (current-output-port) _IOLBF)
  (setvbuf (current-error-port) _IOLBF)

  (with-directory-excursion source
    (format #t "copying and compiling to '~a'...~%" out)

    ;; Copy everything under guix/ and gnu/ plus {guix,gnu}.scm.
    (copy-recursively "guix" (string-append out "/guix")
                      #:log debug-port)
    (copy-recursively "gnu" (string-append out "/gnu")
                      #:log debug-port)
    (copy-file "guix.scm" (string-append out "/guix.scm"))
    (copy-file "gnu.scm" (string-append out "/gnu.scm"))

    ;; Instantiate a (guix config) module that preserves the original
    ;; settings.
    (copy-file "guix/config.scm.in"
               (string-append out "/guix/config.scm"))
    (substitute* (string-append out "/guix/config.scm")
      (("@PACKAGE_NAME@") package-name)
      (("@PACKAGE_VERSION@") package-version)
      (("@PACKAGE_BUGREPORT@") bug-report-address)
      (("@PACKAGE_URL@") home-page-url)
      (("@storedir@") storedir)
      (("@guix_localstatedir@") localstatedir)
      (("@guix_sysconfdir@") sysconfdir)
      (("@guix_sbindir@") sbindir)
      (("@guix_system@") system)
      (("@LIBGCRYPT@") (string-append libgcrypt "/lib/libgcrypt"))
      (("@LIBZ@") (string-append zlib "/lib/libz"))
      (("@GZIP@") (string-append gzip "/bin/gzip"))
      (("@BZIP2@") (string-append bzip2 "/bin/bzip2"))
      (("@XZ@") (string-append xz "/bin/xz"))
      (("@NIX_INSTANTIATE@") ""))                 ;remnants from the past

    ;; Augment the search path so Scheme code can be compiled.
    (set! %load-path (cons out %load-path))
    (set! %load-compiled-path (cons out %load-compiled-path))

    ;; Compile the .scm files.  Load all the files before compiling them to
    ;; work around <http://bugs.gnu.org/15602> (FIXME).
    (let* ((files
            ;; Load guix/ modules before gnu/ modules to get somewhat steadier
            ;; progress reporting.
            (sort (filter (cut string-suffix? ".scm" <>)
                          (find-files out "\\.scm"))
                  (let ((guix (string-append out "/guix"))
                        (gnu  (string-append out "/gnu")))
                    (lambda (a b)
                      (or (and (string-prefix? guix a)
                               (string-prefix? gnu  b))
                          (string<? a b))))))
           (total (length files)))
      (let loop ((files files)
                 (completed 0))
        (match files
          (() *unspecified*)
          ((file . files)
           (display #\cr log-port)
           (format log-port "loading...\t~5,1f% of ~d files" ;FIXME: i18n
                   (* 100. (/ completed total)) total)
           (force-output log-port)
           (format debug-port "~%loading '~a'...~%" file)
           ;; Turn "<out>/foo/bar.scm" into (foo bar).
           (let* ((relative-file (string-drop file (+ (string-length out) 1)))
                  (module-path (string-drop-right relative-file 4))
                  (module-name (map string->symbol
                                    (string-split module-path #\/))))
             (parameterize ((current-warning-port debug-port))
               (resolve-interface module-name)))
           (loop files (+ 1 completed)))))
      (newline)
      (let ((mutex (make-mutex))
            (completed 0))
        (par-for-each
         (lambda (file)
           (with-mutex mutex
             (display #\cr log-port)
             (format log-port "compiling...\t~5,1f% of ~d files" ;FIXME: i18n
                     (* 100. (/ completed total)) total)
             (force-output log-port)
             (format debug-port "~%compiling '~a'...~%" file))
           (let ((go (string-append (string-drop-right file 4) ".go")))
             (parameterize ((current-warning-port (%make-void-port "w")))
               (compile-file file
                             #:output-file go
                             #:opts %auto-compilation-options)))
           (with-mutex mutex
             (set! completed (+ 1 completed))))
         files))))

  (newline)
  #t)

;;; pull.scm ends here
