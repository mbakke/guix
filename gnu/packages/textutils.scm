;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Taylan Ulrich Bayırlı/Kammer <taylanbayirli@gmail.com>
;;; Copyright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015, 2016 Ben Woodcroft <donttrustben@gmail.com>
;;; Copyright © 2015 Roel Janssen <roel@gnu.org>
;;; Copyright © 2016 Jelle Licht <jlicht@fsfe.org>
;;; Copyright © 2016 Alex Griffin <a@ajgrf.com>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
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

(define-module (gnu packages textutils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system trivial)
  #:use-module (gnu packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages python)
  #:use-module (gnu packages zip))

(define-public recode
  (package
    (name "recode")
    ;; Last beta release (3.7-beta2) is from 2008; last commit from Feb 2014.
    ;; So we use that commit instead.
    (version "3.7.0.201402")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/pinard/Recode.git")
             (commit "2d7092a9999194fc0e9449717a8048c8d8e26c18")))
       (sha256
        (base32 "1wssv8z6g3ryrw33sksz4rjhlnhgvvdqszw1ggl4rcwks34n86zm"))
       (file-name (string-append name "-" version "-checkout"))))
    (build-system gnu-build-system)
    (native-inputs `(("python" ,python-2)))
    (arguments
     '(#:phases
       (alist-cons-before
        'check 'pre-check
        (lambda _
          (substitute* "tests/setup.py"
            (("([[:space:]]*)include_dirs=.*" all space)
             (string-append all space "library_dirs=['../src/.libs'],\n")))
          ;; The test extension 'Recode.so' lacks RUNPATH for 'librecode.so'.
          (setenv "LD_LIBRARY_PATH" (string-append (getcwd) "/src/.libs")))
        %standard-phases)))
    (home-page "https://github.com/pinard/Recode")
    (synopsis "Text encoding converter")
    (description "The Recode library converts files between character sets and
usages.  It recognises or produces over 200 different character sets (or about
300 if combined with an iconv library) and transliterates files between almost
any pair.  When exact transliteration are not possible, it gets rid of
offending characters or falls back on approximations.  The recode program is a
handy front-end to the library.")
    (license license:gpl2+)))

(define-public enca
  (package
    (name "enca")
    (version "1.16")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/nijel/enca/archive/" version ".tar.gz"))
       (sha256
        (base32 "1xik00x0yvhswsw2isnclabhv536xk1s42cf5z54gfbpbhc7ni8l"))
       (file-name (string-append name "-" version ".tar.gz"))))
    (build-system gnu-build-system)
    (inputs `(("recode" ,recode)))

    ;; Both 'test-convert-64.sh' and 'test-convert-filter.sh' manipulate a
    ;; 'test.tmp' file, so they have to run in sequence.
    (arguments '(#:parallel-tests? #f))

    (home-page "https://github.com/nijel/enca")
    (synopsis "Text encoding detection tool")
    (description "Enca (Extremely Naive Charset Analyser) consists of libenca,
an encoding detection library, and enca, a command line frontend, integrating
libenca and several charset conversion libraries and tools.")
    (license license:gpl2)))

(define-public utf8proc
  (package
    (name "utf8proc")
    (version "1.3.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/JuliaLang/utf8proc/archive/v"
             version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32 "1k48as5kjkar4yj3dwxyll8ykj4k723ib5a6mnw1g86q3zi0zdl3"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ;no "check" target
       #:make-flags (list "CC=gcc"
                          (string-append "prefix=" (assoc-ref %outputs "out")))
       #:phases
       (modify-phases %standard-phases
         (delete 'configure))))
    (home-page "http://julialang.org/utf8proc/")
    (synopsis "C library for processing UTF-8 Unicode data")
    (description "utf8proc is a small C library that provides Unicode
normalization, case-folding, and other operations for data in the UTF-8
encoding, supporting Unicode version 7.0.")
    (license license:expat)))

(define-public libgtextutils
  (package
    (name "libgtextutils")
    (version "0.7")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/agordon/libgtextutils/releases/download/"
             version "/libgtextutils-" version ".tar.gz"))
       (sha256
        (base32 "0jiybkb2z58wa2msvllnphr4js2hvjvh988pavb3mzkgr6ihwbkr"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (alist-cons-after
        'unpack 'autoreconf
        (lambda _ (zero? (system* "autoreconf" "-vif")))
        %standard-phases)))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)))
    (home-page "https://github.com/agordon/libgtextutils")
    (synopsis "Gordon's text utils library")
    (description
     "libgtextutils is a text utilities library used by the fastx toolkit from
the Hannon Lab.")
    (license license:agpl3+)))

(define-public cityhash
  (let ((commit "8af9b8c"))
    (package
      (name "cityhash")
      (version (string-append "1.1-2." commit))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/google/cityhash.git")
                      (commit commit)))
                (file-name (string-append name "-" version ".tar.gz"))
                (sha256
                 (base32
                  "0n6skf5dv8yfl1ckax8dqhvsbslkwc9158zf2ims0xqdvzsahbi6"))))
      (build-system gnu-build-system)
      (arguments
       '(#:make-flags (list "CXXFLAGS=-g -O3")
         #:phases
         (modify-phases %standard-phases
           ;; citycrc is not installed by default but is used by some
           ;; programs.
           (add-after 'install 'install-citycrc
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out"))
                      (include (string-append out "/include")))
                 (install-file "src/citycrc.h" include))
               #t)))))
      (home-page "https://github.com/google/cityhash")
      (synopsis "C++ hash functions for strings")
      (description
       "CityHash provides hash functions for strings.  The functions mix the
input bits thoroughly but are not suitable for cryptography.")
      (license license:expat))))

(define-public ustr
  (package
    (name "ustr")
    (version "1.0.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.and.org/ustr/" version
                                  "/ustr-" version ".tar.bz2"))
              (sha256
               (base32
                "1i623ygdj7rkizj7985q9d6vj5amwg686aqb5j3ixpkqkyp6xbrx"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags
       (list "CC=gcc"
             "HIDE="
             ;; Override "/sbin/ldconfig" with "echo" because we don't need
             ;; "ldconfig".
             "LDCONFIG=echo"
             (string-append "prefix=" (assoc-ref %outputs "out"))
             "all-shared")
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'disable-check-for-stdint
           (lambda _
             ;; Of course we have stdint.h, just not in /usr/include
             (substitute* '("Makefile"
                            "ustr-import.in")
               (("-f \"/usr/include/stdint.h\"") "-z \"\""))
             #t))
         ;; No configure script
         (delete 'configure))))
    (home-page "http://www.and.org/ustr/")
    (synopsis "String library with very low memory overhead")
    (description
     "Ustr is a string library for C with very low memory overhead.")
    ;; Quoted from the home page: "The License for the code is MIT, new-BSD,
    ;; LGPL, etc. ... if you need another license to help compatibility, just
    ;; ask for it.  It's basically public domain, without all the legal
    ;; problems for everyone that trying to make something public domain
    ;; entails."
    (license license:public-domain)))

(define-public libconfig
  (package
    (name "libconfig")
    (version "1.5")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.hyperrealm.com/libconfig/"
                                  "libconfig-" version ".tar.gz"))
              (sha256
               (base32
                "1xh3hzk63v4y8815lc5209m3s6ms2cpgw4h5hg462i4f1lwsl7g3"))))
    (build-system gnu-build-system)
    (home-page "http://www.hyperrealm.com/libconfig/")
    (synopsis "C/C++ configuration file library")
    (description
     "Libconfig is a simple library for manipulating structured configuration
files.  This file format is more compact and more readable than XML.  And
unlike XML, it is type-aware, so it is not necessary to do string parsing in
application code.")
    (license license:lgpl2.1+)))

(define-public pfff
  (package
    (name "pfff")
    (version "1.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/pfff/pfff/archive/v"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "00m553aa277iarxj6dalmklyb64r7ias49bfwzbacsfg8h3kar8m"))))
    (build-system cmake-build-system)
    (home-page "http://biit.cs.ut.ee/pfff/")
    (synopsis "Probabilistic fast file fingerprinting tool")
    (description
     "pfff is a tool for calculating a compact digital fingerprint of a file
by sampling randomly from the file instead of reading it in full.
Consequently, the computation has a flat performance characteristic,
correlated with data variation rather than file size.  pfff can be as reliable
as existing hashing techniques, with provably negligible risk of collisions.")
    (license license:bsd-3)))

(define-public oniguruma
  (package
    (name "oniguruma")
    (version "5.9.6")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/kkos/"
                                  "oniguruma/releases/download/v" version
                                  "/onig-" version ".tar.gz"))
              (sha256
               (base32
                "19s79vsclqn170mw0ajwv7j37qsbn4f1yjz3yavnhvva6c820r6m"))))
    (build-system gnu-build-system)
    (home-page "https://github.com/kkos/oniguruma")
    (synopsis "Regular expression library")
    (description "Oniguruma is a regular expressions library.  The special
characteristic of this library is that different character encoding for every
regular expression object can be specified.")
    (license license:bsd-2)))

(define-public antiword
  (package
    (name "antiword")
    (version "0.37")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.winfield.demon.nl/linux"
                                  "/antiword-" version ".tar.gz"))
              (sha256
               (base32
                "1b7mi1l20jhj09kyh0bq14qzz8vdhhyf35gzwsq43mn6rc7h0b4f"))
              (patches (search-patches "antiword-CVE-2014-8123.patch"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; There are no tests
       #:make-flags
       (list "-f" "Makefile.Linux"
             (string-append "GLOBAL_INSTALL_DIR="
                            (assoc-ref %outputs "out") "/bin")
             (string-append "GLOBAL_RESOURCES_DIR="
                            (assoc-ref %outputs "out") "/share/antiword"))
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'install
           (lambda* (#:key make-flags #:allow-other-keys)
             (zero? (apply system* "make" `("global_install" ,@make-flags))))))))
    (home-page "http://www.winfield.demon.nl/")
    (synopsis "Microsoft Word document reader")
    (description "Antiword is an application for displaying Microsoft Word
documents.  It can also convert the document to PostScript or XML.  Only
documents made by MS Word version 2 and version 6 or later are supported.  The
name comes from: \"The antidote against people who send Microsoft Word files
to everybody, because they believe that everybody runs Windows and therefore
runs Word\".")
    (license license:gpl2+)))

(define-public utfcpp
  (package
    (name "utfcpp")
    (version "2.3.4")
    (source (origin
              (method url-fetch)
              (uri
               (string-append
                "mirror://sourceforge/utfcpp/utf8cpp_2x/Release%20"
                version "/utf8_v"
                (string-map (lambda (x) (if (eq? x #\.) #\_ x)) version)
                ".zip"))
              (file-name (string-append name "-" version ".zip"))
              (sha256
               (base32
                "1vqhs0aipcvvdrwcs7h3jsryg6mgbmc4s34n5cm6d36q4nxwwwrk"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (let ((source (assoc-ref %build-inputs "source"))
               (out    (assoc-ref %outputs "out"))
               (unzip  (string-append (assoc-ref %build-inputs "unzip")
                                      "/bin/unzip")))
           (mkdir-p out)
           (with-directory-excursion out
             (system* unzip source)
             (mkdir-p "share/doc")
             (rename-file "doc" "share/doc/utfcpp")
             (rename-file "source" "include"))))))
    (native-inputs `(("unzip" ,unzip)))
    (home-page "https://github.com/nemtrif/utfcpp")
    (synopsis "Portable C++ library for handling UTF-8")
    (description "UTF8-CPP is a C++ library for handling UTF-8 encoded text
in a portable way.")
    (license license:boost1.0)))
