;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2015 Paul van der Walt <paul@denknerd.org>
;;; Copyright © 2015 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Roel Janssen <roel@gnu.org>
;;; Copyright © 2016 Lukas Gradl <lgradl@openmailbox.org>
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

(define-module (gnu packages check)
  #:use-module (gnu packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages python)
  #:use-module (guix licenses)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial))

(define-public check
  (package
    (name "check")
    (version "0.10.0")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://github.com/libcheck/check/files/71408/"
                          "/check-" version ".tar.gz"))
      (sha256
       (base32
        "0lhhywf5nxl3dd0hdakra3aasl590756c9kmvyifb3vgm9k0gxgm"))))
    (build-system gnu-build-system)
    (home-page "https://libcheck.github.io/check/")
    (synopsis "Unit test framework for C")
    (description
     "Check is a unit testing framework for C.  It features a simple
interface for defining unit tests, putting little in the way of the
developer.  Tests are run in a separate address space, so Check can
catch both assertion failures and code errors that cause segmentation
faults or other signals.  The output from unit tests can be used within
source code editors and IDEs.")
    (license lgpl2.1+)))

(define-public cunit
  (package
    (name "cunit")
    (version "2.1-3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/cunit/CUnit/"
                           version "/CUnit-" version ".tar.bz2"))
       (sha256
        (base32
         "057j82da9vv4li4z5ri3227ybd18nzyq81f6gsvhifs5z0vr3cpm"))))
    (build-system gnu-build-system)
    (arguments '(#:phases
                 (alist-cons-before
                  'configure 'autoconf
                  (lambda _
                    (zero? (system* "autoreconf" "-vfi")))
                  %standard-phases)))
    (native-inputs
     `(("automake" ,automake)
       ("autoconf" ,autoconf)
       ("libtool" ,libtool)))
    (home-page "http://cunit.sourceforge.net/")
    (synopsis "Automated testing framework for C")
    (description
     "CUnit is a lightweight system for writing, administering, and running
unit tests in C.  It provides C programmers with basic testing functionality
with a flexible variety of user interfaces.")
    (license gpl2+)))

(define-public cppunit
  (package
    (name "cppunit")
    (version "1.13.2")
    (source (origin
             (method url-fetch)
              (uri (string-append "http://dev-www.libreoffice.org/src/"
                                  name "-" version ".tar.gz"))
             (sha256
              (base32
               "17s2kzmkw3kfjhpp72rfppyd7syr7bdq5s69syj2nvrlwd3d4irz"))))
    ;; Explicitly link with libdl. This is expected to be done by packages
    ;; relying on cppunit for their tests. However, not all of them do.
    ;; If we added the linker flag to such packages, we would pollute all
    ;; binaries, not only those used for testing.
    (arguments
     `(#:make-flags '("LDFLAGS=-ldl")))
    (build-system gnu-build-system)
    (home-page "https://wiki.freedesktop.org/www/Software/cppunit/")
    (synopsis "Unit testing framework for C++")
    (description "CppUnit is the C++ port of the famous JUnit framework for
unit testing.  Test output is in XML for automatic testing and GUI based for
supervised tests.")
    (license lgpl2.1))) ; no copyright notices. LGPL2.1 is in the tarball

(define-public catch-framework
  (package
    (name "catch")
    (version "1.3.5")                  ;Sub-minor is the build number
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "https://github.com/philsquared/Catch")
                    ;; Semi-arbitrary.
                    (commit "ae5ee2cf63d6d67bd1369b512d2a7b60b571c907")))
              (file-name (string-append name "-" version))
              (sha256
               (base32
                "1yfb3lxv929szqy1nw9xw3d45wzkppziqshkjxvrb1fdmf46x564"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder (begin
                   (use-modules (guix build utils))
                   (let* ((source (assoc-ref %build-inputs "source"))
                          (output (assoc-ref %outputs "out"))
                          (incdir (string-append output "/include"))
                          (docdir (string-append output "/share/doc/catch-"
                                                 ,version)))
                     (begin
                       (for-each mkdir-p (list incdir docdir))
                       (install-file (string-append source
                                                 "/single_include/catch.hpp")
                                     incdir)
                       (copy-recursively (string-append source "/docs")
                                         docdir))))))
    (home-page "http://catch-lib.net/")
    (synopsis "Automated test framework for C++ and Objective-C")
    (description
     "Catch stands for C++ Automated Test Cases in Headers and is a
multi-paradigm automated test framework for C++ and Objective-C.")
    (license boost1.0)))

(define-public cmocka
  (package
    (name "cmocka")
    (version "1.0.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://cmocka.org/files/1.0/cmocka-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "0fvm6rdalqcxckbddch8ycdw6n2ckldblv117n09chi2l7bm0q5k"))))
    (build-system cmake-build-system)
    (arguments
     `(#:tests? #f)) ; No test target
    (home-page "https://cmocka.org/")
    (synopsis "Unit testing framework for C")
    (description "Cmocka is a unit testing framework for C with support for
mock objects.  It only requires the standard C library, and works with
different compilers.  Cmocka supports several different message output formats
like Test Anything Protocol, Subunit, xUnit XML or the original cmockery output
format.")
    (license asl2.0)))

(define-public cppcheck
  (package
    (name "cppcheck")
    (version "1.72")
    (source (origin
      (method url-fetch)
      (uri (string-append "https://github.com/danmar/cppcheck/archive/"
                          version ".tar.gz"))
      (sha256
       (base32 "0zxaixhqi4vmj7xj56gzadggcbjhbjjm6abyr86qlan23sg98667"))
      (file-name (string-append name "-" version ".tar.gz"))))
    (build-system cmake-build-system)
    (home-page "http://cppcheck.sourceforge.net")
    (synopsis "Static C/C++ code analyzer")
    (description "Cppcheck is a static code analyzer for C and C++.  Unlike
C/C++ compilers and many other analysis tools it does not detect syntax errors
in the code.  Cppcheck primarily detects the types of bugs that the compilers
normally do not detect.  The goal is to detect only real errors in the code
(i.e. have zero false positives).")
    (license gpl3+)))

(define-public googletest
  (package
    (name "googletest")
    (version "1.7.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/google/googletest/archive/"
                           "release-" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1k0nf1l9cb3prdmsvaajl5i31bx86c1mw0d5jgzykz7rzm36afpp"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("python-2" ,python-2)
       ("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'configure 'autoconf
           (lambda _
             (zero? (system* "autoreconf" "-vfi"))))
         (add-before 'autoconf 'generate-headers
           (lambda _
             (begin
               (delete-file "include/gtest/gtest-param-test.h")
               (system* "python2" "scripts/pump.py"
                        "include/gtest/gtest-param-test.h.pump")
               (delete-file "include/gtest/internal/gtest-tuple.h")
               (system* "python2" "scripts/pump.py"
                        "include/gtest//internal/gtest-tuple.h.pump")
               (delete-file
                "include/gtest/internal/gtest-param-util-generated.h")
               (system*
                "python2" "scripts/pump.py"
                "include/gtest/internal/gtest-param-util-generated.h.pump")
               (delete-file "include/gtest/internal/gtest-type-util.h")
               (system* "python2" "scripts/pump.py"
                        "include/gtest/internal/gtest-type-util.h.pump"))))
         (replace 'install
           (lambda _
             (let ((out (assoc-ref %outputs "out")))
               (begin
                 (install-file "lib/.libs/libgtest_main.a"
                               (string-append out "/lib"))
                 (install-file "lib/.libs/libgtest.a"
                               (string-append out "/lib"))
                 (copy-recursively "include"
                  (string-append out "/include")))))))))
    (home-page "https://github.com/google/googletest/")
    (synopsis "Test discovery and XUnit test framework")
    (description "Google Test features an XUnit test framework, automated test
discovery, death tests, assertions, parameterized tests and XML test report
generation.")
    (license bsd-3)))
