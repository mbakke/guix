;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 David Thompson <davet@gnu.org>
;;; Copyright © 2015, 2016 Leo Famulari <leo@famulari.name>
;;; Copyright © 2016 Kei Kebreau <kei@openmailbox.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Troy Sankey <sankeytms@gmail.com>
;;; Copyright © 2016 Stefan Reichoer <stefan@xsteve.at>
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

(define-module (gnu packages calendar)
  #:use-module (gnu packages)
  #:use-module (guix licenses)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system python)
  #:use-module (gnu packages base)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages dav)
  #:use-module (gnu packages freedesktop)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages python)
  #:use-module (srfi srfi-26))

(define-public libical
  (package
    (name "libical")
    (version "2.0.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/libical/libical/releases/download/v"
                    version "/libical-" version ".tar.gz"))
              (sha256
               (base32
                "1njn2kr0rrjqv5g3hdhpdzrhankyj4fl1bgn76z3g4n1b7vi2k35"))))
    (build-system cmake-build-system)
    (arguments
     '(#:tests? #f ; test suite appears broken
       #:configure-flags
       (list (string-append "-DCMAKE_INSTALL_RPATH="
                            (assoc-ref %outputs "out") "/lib:"
                            (assoc-ref %outputs "out") "/lib64"))
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'patch-paths
           (lambda _
             (let ((tzdata (assoc-ref %build-inputs "tzdata")))
               (substitute* "src/libical/icaltz-util.c"
                 (("char \\*search_paths \\[\\] =.*$")
                  (string-append
                   "char *search_paths [] = "
                   "{\"" tzdata "/share/zoneinfo\"};\n"))))
             #t)))))
    (native-inputs
     `(("perl" ,perl)))
    (inputs
     `(("icu4c" ,icu4c)
       ("tzdata" ,tzdata)))
    (home-page "https://libical.github.io/libical/")
    (synopsis "iCalendar protocols and data formats implementation")
    (description
     "Libical is an implementation of the iCalendar protocols and protocol
data units.")
    (license lgpl2.1)))

(define-public khal
  (package
    (name "khal")
    (version "0.8.4")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "khal" version))
             (sha256
              (base32
               "03vy4dp9n43w51mwqjjy08dr5nj7wxqnb085visz3j43vzm42p1f"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
        ;; Building the manpage requires khal to be installed.
        (add-after 'install 'manpage
          (lambda* (#:key inputs outputs #:allow-other-keys)
            ;; Make installed package available for running the tests
            (add-installed-pythonpath inputs outputs)
            (zero? (system* "make" "--directory=doc/" "man"))
            (install-file
              "doc/build/man/khal.1"
              (string-append (assoc-ref outputs "out") "/share/man/man1"))))

        ;; The tests require us to choose a timezone.
        (replace 'check
          (lambda* (#:key inputs #:allow-other-keys)
            (setenv "TZ"
                    (string-append (assoc-ref inputs "tzdata")
                                   "/share/zoneinfo/Zulu"))
            (zero? (system* "py.test" "tests")))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-setuptools-scm" ,python-setuptools-scm)
       ;; Required for tests
       ("tzdata" ,tzdata)
       ("python-freezegun" ,python-freezegun)
       ;; Required to build manpage
       ("python-sphinxcontrib-newsfeed" ,python-sphinxcontrib-newsfeed)
       ("python-sphinx" ,python-sphinx)))
    (inputs
     `(("sqlite" ,sqlite)))
    (propagated-inputs
     `(("python-configobj" ,python-configobj)
       ("python-dateutil-2" ,python-dateutil-2)
       ("python-icalendar" ,python-icalendar)
       ("python-tzlocal" ,python-tzlocal)
       ("python-urwid" ,python-urwid)
       ("python-pyxdg" ,python-pyxdg)
       ("vdirsyncer" ,vdirsyncer)))
    (synopsis "Console calendar program")
    (description "Khal is a standards based console calendar program,
able to synchronize with CalDAV servers through vdirsyncer.")
    (home-page "http://lostpackets.de/khal/")
    (license expat)))

(define-public remind
  (package
    (name "remind")
    (version "3.1.15")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://www.roaringpenguin.com/files/download/"
                           "remind-"
                           (string-join (map (cut string-pad <> 2 #\0)
                                             (string-split version #\.))
                                        ".")
                           ".tar.gz"))
       (sha256
        (base32
         "1hcfcxz5fjzl7606prlb7dgls5kr8z3wb51h48s6qm8ang0b9nla"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f))  ;no "check" target
    (home-page "http://www.roaringpenguin.com/products/remind/")
    (synopsis "Sophisticated calendar and alarm program")
    (description
     "Remind allows you to remind yourself of upcoming events and appointments.
Each reminder or alarm can consist of a message sent to standard output, or a
program to be executed.  It also features: sophisticated date calculation,
moon phases, sunrise/sunset, Hebrew calendar, alarms, PostScript output and
proper handling of holidays.")
    (license gpl2)))

(define-public libhdate
  (package
    (name "libhdate")
    (version "1.6.02")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "mirror://sourceforge/libhdate/libhdate/libhdate-"
                            version "/" name "-" version ".tar.bz2"))
        (sha256
         (base32
          "0qkpq412p78znw8gckwcx3l0wcss9s0dgw1pvjb1ih2pxf6hm4rw"))))
    (build-system gnu-build-system)
    (home-page "http://libhdate.sourceforge.net/")
    (synopsis "Library to use Hebrew dates")
    (description "LibHdate is a small library for the Hebrew calendar and times
of day, written in C, and including bindings for C++, pascal, perl, php, python,
and ruby.  It includes two illustrative command-line programs, @code{hcal} and
@code{hdate}, and some snippets and scripts written in the binding languages.")
    (license gpl3+)))
