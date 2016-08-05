;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2016 Nicolas Goaziou <mail@nicolasgoaziou.fr>
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

(define-module (gnu packages multiprecision)
  #:use-module (guix licenses)
  #:use-module (gnu packages)
  #:use-module (gnu packages m4)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu))

(define-public gmp
  (package
   (name "gmp")
   (version "6.1.0")
   (source (origin
            (method url-fetch)
            (uri
             (string-append "mirror://gnu/gmp/gmp-"
                            version ".tar.xz"))
            (sha256
             (base32
              "12b9s4jn48gbar6dbs5qrlmljdmnq43xy3ji9yjzic0mwp6dmnk8"))
            (patches (search-patches "gmp-faulty-test.patch"))))
   (build-system gnu-build-system)
   (native-inputs `(("m4" ,m4)))
   (outputs '("out" "debug"))
   (arguments `(#:parallel-tests? #f ; mpz/reuse fails otherwise
                #:configure-flags
                '(;; Build a "fat binary", with routines for several
                  ;; sub-architectures.
                  "--enable-fat"
                  "--enable-cxx")))
   (synopsis "Multiple-precision arithmetic library")
   (description
    "GMP is a library for arbitrary precision arithmetic, operating on
signed integers, rational numbers and floating point numbers.  The precision
is only limited by the available memory.  The library is highly optimized,
with a design focus on execution speed.  It is aimed at use in, for example,
cryptography and computational algebra.")
   (license lgpl3+)
   (home-page "http://gmplib.org/")))

(define-public gmp-6.0
  ;; We keep this one around to bootstrap GCC, to work around a compilation
  ;; issue on ARM.  See
  ;; <https://gmplib.org/list-archives/gmp-bugs/2015-December/003848.html>.
  (package
    (inherit gmp)
    (version "6.0.0a")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/gmp/gmp-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "0r5pp27cy7ch3dg5v0rsny8bib1zfvrza6027g2mp5f6v8pd6mli"))
              (patches (search-patches "gmp-arm-asm-nothumb.patch"
                                       "gmp-faulty-test.patch"))))))

(define-public mpfr
  (package
   (name "mpfr")
   (version "3.1.4")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/mpfr/mpfr-" version
                                ".tar.xz"))
            (sha256 (base32
                     "1x8pcnpn1vxfzfsr0js07rwhwyq27fmdzcfjpzi5773ldnqi653n"))))
   (build-system gnu-build-system)
   (outputs '("out" "debug"))
   (propagated-inputs `(("gmp" ,gmp)))            ; <mpfr.h> refers to <gmp.h>
   (synopsis "C library for arbitrary precision floating-point arithmetic")
   (description
    "GNU MPFR is a C library for performing multiple-precision,
floating-point computations with correct rounding.")
   (license lgpl3+)
   (home-page "http://www.mpfr.org/")))

(define-public mpc
  (package
   (name "mpc")
   (version "1.0.3")
   (source (origin
            (method url-fetch)
            (uri (string-append
                  "mirror://gnu/mpc/mpc-" version ".tar.gz"))
            (sha256
              (base32
                "1hzci2zrrd7v3g1jk35qindq05hbl0bhjcyyisq9z209xb3fqzb1"))))
   (build-system gnu-build-system)
   (outputs '("out" "debug"))
   (propagated-inputs `(("gmp" ,gmp)              ; <mpc.h> refers to both
                        ("mpfr" ,mpfr)))
   (synopsis "C library for arbitrary precision complex arithmetic")
   (description
    "GNU MPC is a C library for performing arithmetic on complex numbers.
It supports arbitrarily high precision and it correctly rounds the results.")
   (license lgpl3+)
   (home-page "http://mpc.multiprecision.org/")))

(define-public mpfi
  (package
    (name "mpfi")
    (version "1.5.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://gforge.inria.fr/frs/download.php/"
                                  "file/30130/mpfi-" version ".tar.gz"))
              (sha256
               (base32
                "1g2q6i7dqx40p4gw11da6jgfcbzmm26wxc69fwv8zpcdyg32a9za"))))
    (build-system gnu-build-system)
    (propagated-inputs `(("gmp" ,gmp)   ; <mpfi.h> refers to both
                         ("mpfr" ,mpfr)))
    (synopsis "C library for arbitrary precision interval arithmetic")
    (description "MPFI is intended to be a portable library written in C for
arbitrary precision interval arithmetic with intervals represented using MPFR
reliable floating-point numbers.  It is based on the GNU MP library and on the
MPFR library.  The purpose of an arbitrary precision interval arithmetic is on
the one hand to get guaranteed results, thanks to interval computation, and on
the other hand to obtain accurate results, thanks to multiple precision
arithmetic.")
    (license lgpl2.1+)
    (home-page "https://perso.ens-lyon.fr/nathalie.revol/software.html")))
