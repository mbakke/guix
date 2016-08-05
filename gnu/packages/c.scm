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

(define-module (gnu packages c)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (gnu packages bootstrap)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages guile))

(define-public tcc
  (package
    (name "tcc")                                  ;aka. "tinycc"
    (version "0.9.26")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://savannah/tinycc/tcc-"
                                  version ".tar.bz2"))
              (sha256
               (base32
                "0wbdbdq6090ayw8bxnbikiv989kykff3m5rzbia05hrnwhd707jj"))))
    (build-system gnu-build-system)
    (native-inputs `(("perl" ,perl)
                     ("texinfo" ,texinfo)))
    (arguments
     `(#:configure-flags (list (string-append "--elfinterp="
                                              (assoc-ref %build-inputs "libc")
                                              ,(glibc-dynamic-linker))
                               (string-append "--crtprefix="
                                              (assoc-ref %build-inputs "libc")
                                              "/lib")
                               (string-append "--sysincludepaths="
                                              (assoc-ref %build-inputs "libc")
                                              "/include:"
                                              (assoc-ref %build-inputs
                                                         "kernel-headers")
                                              "/include:{B}/include")
                               (string-append "--libpaths="
                                              (assoc-ref %build-inputs "libc")
                                              "/lib"))
       #:test-target "test"))
    (synopsis "Tiny and fast C compiler")
    (description
     "TCC, also referred to as \"TinyCC\", is a small and fast C compiler
written in C.  It supports ANSI C with GNU and extensions and most of the C99
standard.")
    (home-page "http://www.tinycc.org/")
    (license license:lgpl2.1+)))

(define-public tcc-wrapper
  (package
    (inherit tcc)
    (name "tcc-wrapper")
    (build-system trivial-build-system)
    (native-inputs '())
    (inputs `(("tcc" ,tcc)
              ("guile" ,guile-2.0)))

    ;; By default TCC does not honor any search path environment variable.
    ;; This wrapper adds them.
    ;;
    ;; FIXME: TCC includes its own linker so our 'ld-wrapper' hack to set the
    ;; RUNPATH is ineffective here.  We should modify TCC itself.
    (native-search-paths
     (list (search-path-specification
            (variable "TCC_CPATH")
            (files '("include")))
           (search-path-specification
            (variable "TCC_LIBRARY_PATH")
            (files '("lib" "lib64")))))

    (arguments
     '(#:builder
       (let* ((out   (assoc-ref %outputs "out"))
              (bin   (string-append out "/bin"))
              (tcc   (assoc-ref %build-inputs "tcc"))
              (guile (assoc-ref %build-inputs "guile")))
         (mkdir out)
         (mkdir bin)
         (call-with-output-file (string-append bin "/cc")
           (lambda (port)
             (format port "#!~a/bin/guile --no-auto-compile~%!#~%" guile)
             (write
              `(begin
                 (use-modules (ice-9 match)
                              (srfi srfi-26))

                 (define (split path)
                   (string-tokenize path (char-set-complement
                                          (char-set #\:))))

                 (apply execl ,(string-append tcc "/bin/tcc")
                        ,(string-append tcc "/bin/tcc") ;argv[0]
                        (append (cdr (command-line))
                                (match (getenv "TCC_CPATH")
                                  (#f '())
                                  (str
                                   (map (cut string-append "-I" <>)
                                        (split str))))
                                (match (getenv "TCC_LIBRARY_PATH")
                                  (#f '())
                                  (str
                                   (map (cut string-append "-L" <>)
                                        (split str)))))))
              port)
             (chmod port #o777)))
         #t)))
    (synopsis "Wrapper providing the 'cc' command for TCC")))
