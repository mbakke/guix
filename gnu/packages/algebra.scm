;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2013, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Nicolas Goaziou <mail@nicolasgoaziou.fr>
;;; Copyright © 2014 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
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

(define-module (gnu packages algebra)
  #:use-module (gnu packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages fltk)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages graphviz)
  #:use-module (gnu packages image)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages mpi)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages python)
  #:use-module (gnu packages shells)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages xiph)
  #:use-module (gnu packages xorg)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system cmake)
  #:use-module (guix utils))


(define-public mpfrcx
  (package
   (name "mpfrcx")
   (version "0.4.2")
   (source (origin
            (method url-fetch)
            (uri (string-append
                  "http://www.multiprecision.org/mpfrcx/download/mpfrcx-"
                  version ".tar.gz"))
            (sha256
             (base32
              "0grw66b255r574lvll1bqccm5myj2m8ajzsjaygcyq9zjnnbnhhy"))))
   (build-system gnu-build-system)
   (propagated-inputs
     `(("gmp" ,gmp)
       ("mpfr" ,mpfr)
       ("mpc"  ,mpc))) ; Header files are included by mpfrcx.h.
   (synopsis "Arithmetic of polynomials over arbitrary precision numbers")
   (description
    "Mpfrcx is a library for the arithmetic of univariate polynomials over
arbitrary precision real (mpfr) or complex (mpc) numbers, without control
on the rounding.  For the time being, only the few functions needed to
implement the floating point approach to complex multiplication are
implemented.  On the other hand, these comprise asymptotically fast
multiplication routines such as Toom–Cook and the FFT.")
   (license license:lgpl2.1+)
   (home-page "http://mpfrcx.multiprecision.org/")))

(define-public cm
  (package
   (name "cm")
   (version "0.3")
   (source (origin
            (method url-fetch)
            (uri (string-append
                  "http://www.multiprecision.org/cm/download/cm-"
                  version ".tar.gz"))
            (sha256
             (base32
              "1nf5kr0nqmhbzrsrinky18z0ighjpsmb5cr8zyg8jf04bfbyrfmc"))))
   (build-system gnu-build-system)
   (propagated-inputs
     `(("mpfrcx" ,mpfrcx)
       ("zlib" ,zlib))) ; Header files included from cm_common.h.
   (inputs
     `(("pari-gp"  ,pari-gp)))
   (synopsis "CM constructions for elliptic curves")
   (description
    "The CM software implements the construction of ring class fields of
imaginary quadratic number fields and of elliptic curves with complex
multiplication via floating point approximations.  It consists of libraries
that can be called from within a C program and of executable command
line applications.")
   (license license:gpl3+)
   (home-page "http://cm.multiprecision.org/")))

(define-public fplll
  (package
   (name "fplll")
   (version "4.0.4")
   (source (origin
            (method url-fetch)
            (uri (string-append
                  "http://perso.ens-lyon.fr/damien.stehle/fplll/libfplll-"
                  version ".tar.gz"))
            (sha256 (base32
                     "1cbiby7ykis4z84swclpysrljmqhfcllpkcbll1m08rzskgb1a6b"))))
   (build-system gnu-build-system)
   (inputs `(("gmp" ,gmp)
             ("mpfr" ,mpfr)))
   (synopsis "Library for LLL-reduction of euclidean lattices")
   (description
    "fplll LLL-reduces euclidean lattices.  Since version 3, it can also
solve the shortest vector problem.")
   (license license:lgpl2.1+)
   (home-page "http://perso.ens-lyon.fr/damien.stehle/fplll/")))

(define-public pari-gp
  (package
   (name "pari-gp")
   (version "2.7.6")
   (source (origin
            (method url-fetch)
            (uri (string-append
                  "http://pari.math.u-bordeaux.fr/pub/pari/unix/pari-"
                  version ".tar.gz"))
            (sha256
              (base32
                "04dqi697czd8mmw8aiwzrkgbvkjassqagg6lfy3lkf1k5qi9g9rr"))))
   (build-system gnu-build-system)
   (native-inputs `(("texlive" ,texlive-minimal)))
   (inputs `(("gmp" ,gmp)
             ("libx11" ,libx11)
             ("perl" ,perl)
             ("readline" ,readline)))
   (arguments
    '(#:make-flags '("all")
      #:test-target "dobench"
      #:phases (modify-phases %standard-phases
                 (replace 'configure
                          (lambda* (#:key outputs #:allow-other-keys)
                           (let ((out (assoc-ref outputs "out")))
                            (zero?
                             (system* "./Configure"
                                      (string-append "--prefix=" out)))))))))
   (synopsis "PARI/GP, a computer algebra system for number theory")
   (description
    "PARI/GP is a widely used computer algebra system designed for fast
computations in number theory (factorisations, algebraic number theory,
elliptic curves...), but it also contains a large number of other useful
functions to compute with mathematical entities such as matrices,
polynomials, power series, algebraic numbers, etc., and a lot of
transcendental functions.
PARI is also available as a C library to allow for faster computations.")
   (license license:gpl2+)
   (home-page "http://pari.math.u-bordeaux.fr/")))

(define-public gp2c
  (package
   (name "gp2c")
   (version "0.0.9pl5")
   (source (origin
            (method url-fetch)
            (uri (string-append
                  "http://pari.math.u-bordeaux.fr/pub/pari/GP2C/gp2c-"
                  version ".tar.gz"))
            (sha256
              (base32
                "1q003mkagc5ib6lqb2xfay7j4ffkwv7xlnznp6wdrq2sbqq4vyak"))))
   (build-system gnu-build-system)
   (native-inputs `(("perl" ,perl)))
   (inputs `(("pari-gp" ,pari-gp)))
   (arguments
    '(#:configure-flags
      (list (string-append "--with-paricfg="
                           (assoc-ref %build-inputs "pari-gp")
                           "/lib/pari/pari.cfg"))))
   (synopsis "PARI/GP, a computer algebra system for number theory")
   (description
    "PARI/GP is a widely used computer algebra system designed for fast
computations in number theory (factorisations, algebraic number theory,
elliptic curves...), but it also contains a large number of other useful
functions to compute with mathematical entities such as matrices,
polynomials, power series, algebraic numbers, etc., and a lot of
transcendental functions.
PARI is also available as a C library to allow for faster computations.

GP2C, the GP to C compiler, translates GP scripts to PARI programs.")
   (license license:gpl2)
   (home-page "http://pari.math.u-bordeaux.fr/")))

(define-public giac-xcas
  (package
    (name "giac-xcas")
    (version "1.2.2-75")
    (source (origin
              (method url-fetch)
              ;; "~parisse/giac" is not used because the maintainer regularly
              ;; overwrites the release tarball there, introducing a checksum
              ;; mismatch every time.  See
              ;; <https://www-fourier.ujf-grenoble.fr/~parisse/debian/dists/stable/main/source/README>
              (uri (string-append "https://www-fourier.ujf-grenoble.fr/"
                                  "~parisse/debian/dists/stable/main/"
                                  "source/giac_" version ".tar.gz"))
              (sha256
               (base32
                "0vs111fkd900wkm7yypaxmplc8i8j63d9shc3fbdhddn7cdj70b1"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-bin-cp
           (lambda _
             ;; Some Makefiles contain hard-coded "/bin/cp".
             (substitute* (find-files "doc" "^Makefile")
               (("/bin/cp") (which "cp")))
             #t))
         (add-after 'unpack 'disable-broken-test
           (lambda _
             ;; Disable failing test.  Actually, the results are correct but
             ;; a sorting discrepancy prevents the test from being validated.
             (substitute* "check/Makefile.in"
               (("chk_fhan16") ""))
             #t)))))
    (inputs
     `(("fltk" ,fltk)
       ("gmp" ,gmp)
       ("gsl" ,gsl)
       ("lapack" ,lapack)
       ("libao" ,ao)
       ("libjpeg" ,libjpeg)
       ("libpng" ,libpng)
       ("libx11" ,libx11)
       ("libxinerama" ,libxinerama)
       ("libxft" ,libxft)
       ("libxt" ,libxt)
       ("mesa" ,mesa)
       ("mpfi" ,mpfi)
       ("mpfr" ,mpfr)
       ("ntl" ,ntl)
       ("perl" ,perl)
       ("pari-gp" ,pari-gp)
       ("tcsh" ,tcsh)
       ("texlive" ,texlive-minimal)))
    (native-inputs `(("readline" ,readline)))
    (home-page "https://www-fourier.ujf-grenoble.fr/~parisse/giac.html")
    (synopsis "Computer algebra system")
    (description
     "Giac/Xcas is a computer algebra system.  It has a compatibility mode for
maple, mupad and the TI89.  It is available as a standalone program (graphic
or text interfaces) or as a C++ library.")
    (license license:gpl3+)))

(define-public flint
  (package
   (name "flint")
   (version "2.5.2")
   (source (origin
            (method url-fetch)
            (uri (string-append
                  "http://flintlib.org/flint-"
                  version ".tar.gz"))
            (sha256 (base32
                     "11syazv1a8rrnac3wj3hnyhhflpqcmq02q8pqk2m6g2k6h0gxwfb"))
            (patches (search-patches "flint-ldconfig.patch"))))
   (build-system gnu-build-system)
   (propagated-inputs
    `(("gmp" ,gmp)
      ("mpfr" ,mpfr))) ; header files from both are included by flint/arith.h
   (arguments
    `(#:parallel-tests? #f ; seems to be necessary on arm
      #:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out"))
                   (gmp (assoc-ref inputs "gmp"))
                   (mpfr (assoc-ref inputs "mpfr")))
               ;; do not pass "--enable-fast-install", which makes the
               ;; homebrew configure process fail
               (zero? (system*
                       "./configure"
                       (string-append "--prefix=" out)
                       (string-append "--with-gmp=" gmp)
                       (string-append "--with-mpfr=" mpfr)))))))))
   (synopsis "Fast library for number theory")
   (description
    "FLINT is a C library for number theory.  It supports arithmetic
with numbers, polynomials, power series and matrices over many base
rings, including multiprecision integers and rationals, integers
modulo n, p-adic numbers, finite fields (prime and non-prime order)
and real and complex numbers (via the Arb extension library).

Operations that can be performed include conversions, arithmetic,
GCDs, factoring, solving linear systems, and evaluating special
functions.  In addition, FLINT provides various low-level routines for
fast arithmetic.")
   (license license:gpl2+)
   (home-page "http://flintlib.org/")))

(define-public arb
  (package
   (name "arb")
   (version "2.8.1")
   (source (origin
            (method url-fetch)
            (uri (string-append
                  "https://github.com/fredrik-johansson/arb/archive/"
                  version ".tar.gz"))
            (file-name (string-append name "-" version ".tar.gz"))
            (sha256
              (base32
                "04hhcpshfkcq9fr4hixbhpps50yf9drk62xgkvlcaj5kb4nyrx7l"))
            (patches (search-patches "arb-ldconfig.patch"))))
   (build-system gnu-build-system)
   (propagated-inputs
    `(("flint" ,flint))) ; flint.h is included by arf.h
   (inputs
    `(("gmp" ,gmp)
      ("mpfr" ,mpfr)))
   (arguments
    `(#:phases
        (alist-replace
         'configure
         (lambda* (#:key inputs outputs #:allow-other-keys)
           (let ((out (assoc-ref outputs "out"))
                 (flint (assoc-ref inputs "flint"))
                 (gmp (assoc-ref inputs "gmp"))
                 (mpfr (assoc-ref inputs "mpfr")))
             ;; do not pass "--enable-fast-install", which makes the
             ;; homebrew configure process fail
             (zero? (system*
                     "./configure"
                     (string-append "--prefix=" out)
                     (string-append "--with-flint=" flint)
                     (string-append "--with-gmp=" gmp)
                     (string-append "--with-mpfr=" mpfr)))))
         %standard-phases)))
   (synopsis "Arbitrary precision floating-point ball arithmetic")
   (description
    "Arb is a C library for arbitrary-precision floating-point ball
arithmetic.  It supports efficient high-precision computation with
polynomials, power series, matrices and special functions over the
real and complex numbers, with automatic, rigorous error control.")
   (license license:gpl2+)
   (home-page "http://fredrikj.net/arb/")))

(define-public ntl
  (package
   (name "ntl")
   (version "9.7.0")
   (source (origin
            (method url-fetch)
            (uri (string-append "http://shoup.net/ntl/ntl-"
                                version ".tar.gz"))
            (sha256 (base32
                     "115frp5flyvw9wghz4zph1b3llmr5nbxk1skgsggckr81fh3gmxq"))))
   (build-system gnu-build-system)
   (native-inputs
    `(("libtool" ,libtool)
      ("perl" ,perl))) ; for configuration
   ;; FIXME: Add optional input gf2x once available; then also add
   ;; configure flag "NTL_GF2X_LIB=on".
   (inputs
    `(("gmp" ,gmp)))
   (arguments
    `(#:phases
      (modify-phases %standard-phases
        (replace 'configure
         (lambda* (#:key outputs #:allow-other-keys)
           (chdir "src")
           (system* "./configure"
                    (string-append "PREFIX=" (assoc-ref outputs "out"))
                    ;; Do not build especially for the build machine.
                    "NATIVE=off"
                    ;; Also do not tune to the build machine.
                    "WIZARD=off"
                    "SHARED=on")
           #t)))))
   (synopsis "C++ library for number theory")
   (description
    "NTL is a C++ library providing data structures and algorithms
for manipulating signed, arbitrary length integers, and for vectors,
matrices, and polynomials over the integers and over finite fields.")
   (license license:gpl2+)
   (home-page "http://shoup.net/ntl/")))

(define-public singular
  (package
   (name "singular")
   (version "4.0.3")
   (source (origin
            (method url-fetch)
            (uri (string-append "http://www.mathematik.uni-kl.de/ftp/pub/"
                                "Math/Singular/SOURCES/"
                                (string-join (string-split version #\.) "-")
                                "/singular-" version ".tar.gz"))
            (sha256 (base32
                     "0viidy2fz62rln9p0s9qfs7fnm55c6fw1agydd1py26gxylp1ksc"))))
   (build-system gnu-build-system)
   (native-inputs
    `(("doxygen" ,doxygen)
      ("graphviz" ,graphviz)
      ("perl" ,perl)))
   (inputs
    `(("cddlib" ,cddlib)
      ("gmp" ,gmp)
      ("flint" ,flint)
      ("mpfr" ,mpfr)
      ("ntl" ,ntl)
      ("python" ,python-2)
      ("readline" ,readline)))
   (arguments
    `(#:configure-flags
      (list (string-append "--with-ntl="
                           (assoc-ref %build-inputs "ntl")))))
   (synopsis "Computer algebra system for polynomial computations")
   (description
    "Singular is a computer algebra system for polynomial computations,
with special emphasis on commutative and non-commutative algebra, algebraic
geometry and singularity theory.")
   ;; Singular itself is dual licensed gpl2 or gpl3, but some of the
   ;; libraries with which it links are licensed under lgpl3+, so the
   ;; combined work becomes gpl3. See COPYING in the source code.
   (license license:gpl3)
   (home-page "http://www.singular.uni-kl.de/index.php")))

(define-public gmp-ecm
  (package
   (name "gmp-ecm")
   (version "7.0")
   (source (origin
            (method url-fetch)
            (uri (string-append "https://gforge.inria.fr/frs/download.php/"
                                "file/35642/ecm-"
                                version ".tar.gz"))
            (sha256 (base32
                     "00jzzwqp49m01vwsr9z1w7bvm8lb69l3f62x7qr8sfz0xiczxnpm"))))
   (build-system gnu-build-system)
   (inputs
    `(("gmp" ,gmp)))
   (arguments
    `(#:configure-flags '("--enable-shared"
                          ;; Disable specific assembly routines, which depend
                          ;; on the subarchitecture of the build machine,
                          ;; and use gmp instead.
                          "--disable-asm-redc")))
   (synopsis "Integer factorization library using the elliptic curve method")
   (description
    "GMP-ECM factors integers using the elliptic curve method (ECM) as well
as the P-1 and P+1 algorithms.  It provides a library and a stand-alone
binary.")
   ;; Most files are under lgpl3+, but some are under gpl3+ or gpl2+,
   ;; so the combined work is under gpl3+.
   (license license:gpl3+)
   (home-page "http://ecm.gforge.inria.fr/")))

(define-public bc
  (package
    (name "bc")
    (version "1.06")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/bc/bc-" version ".tar.gz"))
             (sha256
              (base32
               "0cqf5jkwx6awgd2xc2a0mkpxilzcfmhncdcfg7c9439wgkqxkxjf"))))
    (build-system gnu-build-system)
    (inputs `(("readline" ,readline)))
    (native-inputs `(("flex" ,flex)))
    (arguments
     '(#:phases
       (alist-replace 'configure
                      (lambda* (#:key outputs #:allow-other-keys)
                        ;; This old `configure' script doesn't support
                        ;; variables passed as arguments.
                        (let ((out (assoc-ref outputs "out")))
                          (setenv "CONFIG_SHELL" (which "bash"))
                          (zero?
                           (system*
                            "./configure"
                            (string-append "--prefix=" out)
                            ;; By default, man and info pages are put in
                            ;; PREFIX/{man,info}, but we want them in
                            ;; PREFIX/share/{man,info}.
                            (string-append "--mandir=" out "/share/man")
                            (string-append "--infodir=" out "/share/info")))))
                      %standard-phases)))
    (home-page "http://www.gnu.org/software/bc/")
    (synopsis "Arbitrary precision numeric processing language")
    (description
     "bc is an arbitrary precision numeric processing language.  It includes
an interactive environment for evaluating mathematical statements.  Its
syntax is similar to that of C, so basic usage is familiar.  It also includes
\"dc\", a reverse-polish calculator.")
    (license license:gpl2+)))

(define-public fftw
  (package
    (name "fftw")
    (version "3.3.4")
    (source (origin
             (method url-fetch)
             (uri (string-append "ftp://ftp.fftw.org/pub/fftw/fftw-"
                                 version".tar.gz"))
             (sha256
              (base32
               "10h9mzjxnwlsjziah4lri85scc05rlajz39nqf3mbh4vja8dw34g"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags '("--enable-shared" "--enable-openmp")
       #:phases (alist-cons-before
                 'build 'no-native
                 (lambda _
                   ;; By default '-mtune=native' is used.  However, that may
                   ;; cause the use of ISA extensions (SSE2, etc.) that are
                   ;; not necessarily available on the user's machine when
                   ;; that package is built on a different machine.
                   (substitute* (find-files "." "Makefile$")
                     (("-mtune=native") "")))
                 %standard-phases)))
    (native-inputs `(("perl" ,perl)))
    (home-page "http://fftw.org")
    (synopsis "Computing the discrete Fourier transform")
    (description
     "FFTW is a C subroutine library for computing the discrete Fourier
transform (DFT) in one or more dimensions, of arbitrary input size, and of
both real and complex data (as well as of even/odd data---i.e. the discrete
cosine/ sine transforms or DCT/DST).")
    (license license:gpl2+)))

(define-public fftwf
  (package (inherit fftw)
    (name "fftwf")
    (arguments
     (substitute-keyword-arguments (package-arguments fftw)
       ((#:configure-flags cf)
        `(cons "--enable-float" ,cf))))
    (description
     (string-append (package-description fftw)
                    "  Single-precision version."))))

(define-public fftw-openmpi
  (package (inherit fftw)
    (name "fftw-openmpi")
    (inputs
     `(("openmpi" ,openmpi)
       ,@(package-inputs fftw)))
    (arguments
     (substitute-keyword-arguments (package-arguments fftw)
       ((#:configure-flags cf)
        `(cons "--enable-mpi" ,cf))))
    (description
     (string-append (package-description fftw)
                    "  With OpenMPI parallelism support."))))

(define-public eigen
  (package
    (name "eigen")
    (version "3.2.8")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://bitbucket.org/eigen/eigen/get/"
                                  version ".tar.bz2"))
              (sha256
               (base32
                "0mby6my1djsg8681fcvlaq0i4kd17fja9qn5f713j3xpfbb66akj"))
              (file-name (string-append name "-" version ".tar.bz2"))
              (modules '((guix build utils)))
              (snippet
               ;; There are 3 test failures in the "unsupported" directory,
               ;; but maintainers say it's a known issue and it's unsupported
               ;; anyway, so just skip them.
               '(substitute* "CMakeLists.txt"
                  (("add_subdirectory\\(unsupported\\)")
                   "# Do not build the tests for unsupported features.\n")
                  ;; Work around
                  ;; <http://eigen.tuxfamily.org/bz/show_bug.cgi?id=1114>.
                  (("\"include/eigen3\"")
                   "\"${CMAKE_INSTALL_PREFIX}/include/eigen3\"")))))
    (build-system cmake-build-system)
    (arguments
     '(;; Turn off debugging symbols to save space.
       #:build-type "Release"

       #:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      (let* ((cores  (parallel-job-count))
                             (dash-j (format #f "-j~a" cores)))
                        ;; First build the tests, in parallel.  See
                        ;; <http://eigen.tuxfamily.org/index.php?title=Tests>.
                        (and (zero? (system* "make" "buildtests" dash-j))

                             ;; Then run 'CTest' with -V so we get more
                             ;; details upon failure.
                             (zero? (system* "ctest" "-V" dash-j)))))))))
    (home-page "http://eigen.tuxfamily.org")
    (synopsis "C++ template library for linear algebra")
    (description
     "Eigen is a C++ template library for linear algebra: matrices, vectors,
numerical solvers, and related algorithms.  It provides an elegant API based
on \"expression templates\".  It is versatile: it supports all matrix sizes,
all standard numeric types, various matrix decompositions and geometry
features, and more.")

    ;; Most of the code is MPLv2, with a few files under LGPLv2.1+ or BSD-3.
    ;; See 'COPYING.README' for details.
    (license license:mpl2.0)))
