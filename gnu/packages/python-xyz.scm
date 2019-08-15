;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2013, 2014, 2015, 2016, 2017, 2018, 2019 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013, 2014, 2015, 2016, 2019 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2014, 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014, 2017 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2014, 2015 Federico Beffa <beffa@fbengineering.ch>
;;; Copyright © 2015 Omar Radwan <toxemicsquire4@gmail.com>
;;; Copyright © 2015 Pierre-Antoine Rault <par@rigelk.eu>
;;; Copyright © 2015, 2016, 2017, 2018, 2019 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015, 2016 Christopher Allan Webber <cwebber@dustycloud.org>
;;; Copyright © 2015 Eric Dvorsak <eric@dvorsak.fr>
;;; Copyright © 2015, 2016 David Thompson <davet@gnu.org>
;;; Copyright © 2015, 2016, 2017, 2019 Leo Famulari <leo@famulari.name>
;;; Copyright © 2015, 2017 Ben Woodcroft <donttrustben@gmail.com>
;;; Copyright © 2015, 2016 Erik Edrosa <erik.edrosa@gmail.com>
;;; Copyright © 2015, 2016, 2017, 2018, 2019 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2015, 2017 Kyle Meyer <kyle@kyleam.com>
;;; Copyright © 2015, 2016 Chris Marusich <cmmarusich@gmail.com>
;;; Copyright © 2016 Danny Milosavljevic <dannym+a@scratchpost.org>
;;; Copyright © 2016 Lukas Gradl <lgradl@openmailbox.org>
;;; Copyright © 2016, 2018 Hartmut Goebel <h.goebel@crazy-compilers.com>
;;; Copyright © 2016 Daniel Pimentel <d4n1@d4n1.org>
;;; Copyright © 2016 Sou Bunnbu <iyzsong@gmail.com>
;;; Copyright © 2016, 2017 Troy Sankey <sankeytms@gmail.com>
;;; Copyright © 2016, 2017 ng0 <ng0@n0.is>
;;; Copyright © 2016 Dylan Jeffers <sapientech@sapientech@openmailbox.org>
;;; Copyright © 2016 David Craven <david@craven.ch>
;;; Copyright © 2016, 2017, 2018, 2019 Marius Bakke <mbakke@fastmail.com>
;;; Copyright © 2016, 2017 Stefan Reichör <stefan@xsteve.at>
;;; Copyright © 2016 Dylan Jeffers <sapientech@sapientech@openmailbox.org>
;;; Copyright © 2016, 2017, 2019 Alex Vong <alexvong1995@gmail.com>
;;; Copyright © 2016, 2017, 2018 Arun Isaac <arunisaac@systemreboot.net>
;;; Copyright © 2016, 2017, 2018 Julien Lepiller <julien@lepiller.eu>
;;; Copyright © 2016, 2017, 2018, 2019 Tobias Geerinckx-Rice <me@tobias.gr>
;;; Copyright © 2016, 2017 Thomas Danckaert <post@thomasdanckaert.be>
;;; Copyright © 2017 Carlo Zancanaro <carlo@zancanaro.id.au>
;;; Copyright © 2017 Frederick M. Muriithi <fredmanglis@gmail.com>
;;; Copyright © 2017, 2018 Adriano Peluso <catonano@gmail.com>
;;; Copyright © 2017 Ben Sturmfels <ben@sturm.com.au>
;;; Copyright © 2017, 2018 Mathieu Othacehe <m.othacehe@gmail.com>
;;; Copyright © 2017 José Miguel Sánchez García <jmi2k@openmailbox.org>
;;; Copyright © 2017 Roel Janssen <roel@gnu.org>
;;; Copyright © 2017, 2018 Kei Kebreau <kkebreau@posteo.net>
;;; Copyright © 2017 Rutger Helling <rhelling@mykolab.com>
;;; Copyright © 2017 Muriithi Frederick Muriuki <fredmanglis@gmail.com>
;;; Copyright © 2017, 2019 Brendan Tildesley <mail@brendan.scot>
;;; Copyright © 2018 Ethan R. Jones <ethanrjones97@gmail.com
;;; Copyright © 2018 Fis Trivial <ybbs.daans@hotmail.com>
;;; Copyright © 2018 Vijayalakshmi Vedantham <vijimay12@gmail.com>
;;; Copyright © 2018 Mathieu Lirzin <mthl@gnu.org>
;;; Copyright © 2018 Adam Massmann <massmannak@gmail.com>
;;; Copyright © 2016, 2018 Tomáš Čech <sleep_walker@gnu.org>
;;; Copyright © 2018, 2019 Nicolas Goaziou <mail@nicolasgoaziou.fr>
;;; Copyright © 2018 Oleg Pykhalov <go.wigust@gmail.com>
;;; Copyright © 2018 Clément Lassieur <clement@lassieur.org>
;;; Copyright © 2018, 2019 Maxim Cournoyer <maxim.cournoyer@gmail.com>
;;; Copyright © 2018 Luther Thompson <lutheroto@gmail.com>
;;; Copyright © 2018 Vagrant Cascadian <vagrant@debian.org>
;;; Copyright © 2019 Brett Gilio <brettg@posteo.net>
;;; Copyright © 2019 Sam <smbaines8@gmail.com>
;;; Copyright © 2019 Jack Hill <jackhill@jackhill.us>
;;; Copyright © 2019 Guillaume Le Vaillant <glv@posteo.net>
;;; Copyright © 2019 Alex Griffin <a@ajgrf.com>
;;; Copyright © 2019 Pierre Langlois <pierre.langlois@gmx.com>
;;; Copyright © 2019 Jacob MacDonald <jaccarmac@gmail.com>
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

(define-module (gnu packages python-xyz)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages adns)
  #:use-module (gnu packages attr)
  #:use-module (gnu packages backup)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages check)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages crypto)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages dbm)
  #:use-module (gnu packages file)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages geo)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages graphviz)
  #:use-module (gnu packages graphics)
  #:use-module (gnu packages gstreamer)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages image)
  #:use-module (gnu packages imagemagick)
  #:use-module (gnu packages libevent)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages llvm)
  #:use-module (gnu packages man)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages monitoring)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages networking)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages openstack)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages python-check)
  #:use-module (gnu packages python-compression)
  #:use-module (gnu packages python-crypto)
  #:use-module (gnu packages python-web)
  #:use-module (gnu packages qt)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages sdl)
  #:use-module (gnu packages search)
  #:use-module (gnu packages shells)
  #:use-module (gnu packages sphinx)
  #:use-module (gnu packages ssh)
  #:use-module (gnu packages terminals)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages time)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages version-control)
  #:use-module (gnu packages video)
  #:use-module (gnu packages web)
  #:use-module (gnu packages base)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages tcl)
  #:use-module (gnu packages bdw-gc)
  #:use-module (gnu packages serialization)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix hg-download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system python)
  #:use-module (guix build-system trivial)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26))

(define-public python-psutil
  (package
    (name "python-psutil")
    (version "5.6.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "psutil" version))
       (sha256
        (base32
         "1v95vb5385qscfdvphv8l2w22bmir3d7yhpi02n58v3mlqy1r3l2"))))
    (build-system python-build-system)
    (arguments
     ;; FIXME: some tests does not return and times out.
     '(#:tests? #f))
    (home-page "https://www.github.com/giampaolo/psutil")
    (synopsis "Library for retrieving information on running processes")
    (description
     "psutil (Python system and process utilities) is a library for retrieving
information on running processes and system utilization (CPU, memory, disks,
network) in Python.  It is useful mainly for system monitoring, profiling and
limiting process resources and management of running processes.  It implements
many functionalities offered by command line tools such as: ps, top, lsof,
netstat, ifconfig, who, df, kill, free, nice, ionice, iostat, iotop, uptime,
pidof, tty, taskset, pmap.")
    (properties `((python2-variant . ,(delay python2-psutil))))
    (license license:bsd-3)))

(define-public python2-psutil
  (let ((base (package-with-python2 (strip-python2-variant python-psutil))))
    (package
      (inherit base)
      (propagated-inputs
       `(("python2-enum34" ,python2-enum34)         ;optional
         ,@(package-propagated-inputs base))))))

(define-public python-shapely
  (package
    (name "python-shapely")
    (version "1.6.4.post2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Shapely" version))
       (sha256
        (base32
         "03r42fmd9alp6r3q95ad6rldq2f7n1wimrw53zy5kpn33yv7pf64"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-cython" ,python-cython)
       ("python-matplotlib" ,python-matplotlib)
       ("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)))
    (inputs
     `(("geos" ,geos)))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-geos-path
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((geos (assoc-ref inputs "geos"))
                   (glibc (assoc-ref inputs ,(if (%current-target-system)
                                                 "cross-libc" "libc"))))
               (substitute* "shapely/geos.py"
                 (("_lgeos = load_dll\\('geos_c', fallbacks=.*\\)")
                  (string-append "_lgeos = load_dll('geos_c', fallbacks=['"
                                 geos "/lib/libgeos_c.so'])"))
                 (("free = load_dll\\('c'\\)\\.free")
                  (string-append "free = load_dll('c', fallbacks=['"
                                 glibc "/lib/libc.so.6']).free"))))
             #t)))))
    (home-page "https://github.com/Toblerity/Shapely")
    (synopsis "Library for the manipulation and analysis of geometric objects")
    (description "Shapely is a Python package for manipulation and analysis of
planar geometric objects.  It is based on the @code{GEOS} library.")
    (license license:bsd-3)))

(define-public python-shortuuid
  (package
    (name "python-shortuuid")
    (version "0.5.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "shortuuid" version))
       (sha256
        (base32
         "1f8i4zwj5vmpzbz6b17bljy4399gx5aq7vsyw63sz2qgyjcd73yh"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pep8" ,python-pep8)))
    (home-page "https://github.com/skorokithakis/shortuuid")
    (synopsis "Generator library for concise, unambiguous and URL-safe UUIDs")
    (description
     "@code{shortuuid} is a Python library for generating concise, unambiguous
and URL-safe UUIDs.  UUIDs are generated using the built-in Python @code{uuid}
module and then similar looking characters are removed.")
    (license license:bsd-3)))

(define-public python-logwrap
  (package
    (name "python-logwrap")
    (version "3.2.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "logwrap" version ".zip"))
       (sha256
        (base32
         "1d2k0hvpbi51vl410y8fbs5m0nxnlh2k7gr2nrh3k81ibhzscsra"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-typing" ,python-typing)))
    (native-inputs
     `(("unzip" ,unzip)
       ("python-cython" ,python-cython)
       ("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-pytest-runner" ,python-pytest-runner)))
    (home-page "https://github.com/penguinolog/logwrap")
    (synopsis "Decorator for logging function arguments")
    (description "This package provides a decorator to log function arguments
and function call return values in a human-readable way.")
    (license license:asl2.0)))

(define-public python2-shapely
  (package-with-python2 python-shapely))

(define-public python-clyent
  (package
    (name "python-clyent")
    (version "1.2.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "clyent" version))
       (sha256
        (base32
         "1r9987qmy1pz3hq54160bapqsywpq14waw4w9x3ly8hmq7kpgfbj"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-mock" ,python-mock)))
    (home-page "https://github.com/binstar/clyent")
    (synopsis "Command line client library")
    (description "Clyent is a Python command line utiliy library.  It is used
by @code{binstar}, @code{binstar-build} and @code{chalmers}.")
    (license license:bsd-3)))

(define-public python2-clyent
  (package-with-python2 python-clyent))

(define-public python-babel
  (package
    (name "python-babel")
    (version "2.7.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "Babel" version))
      (sha256
       (base32
        "0a7wawx8vsg7igvz6p3x909fskhg4b2y1910xk4f4c8y22p3aqg8"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-freezegun" ,python-freezegun)
       ("python-pytest" ,python-pytest)))
    (propagated-inputs
     `(("python-pytz" ,python-pytz)))
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _ (invoke "pytest" "-vv"))))))
    (home-page "http://babel.pocoo.org/")
    (synopsis
     "Tools for internationalizing Python applications")
    (description
     "Babel is composed of two major parts:
- tools to build and work with gettext message catalogs
- a Python interface to the CLDR (Common Locale Data Repository), providing
access to various locale display names, localized number and date formatting,
etc. ")
    (license license:bsd-3)))

(define-public python2-babel
  (package-with-python2 python-babel))

;; Sphinx < 2.0 requires this version.  Remove once no longer needed.
(define-public python2-babel-2.6
  (package
    (inherit python2-babel)
    (version "2.6.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "Babel" version))
              (sha256
               (base32
                "08rxmbx2s4irp0w0gmn498vns5xy0fagm0fg33xa772jiks51flc"))))))

(define-public python2-backport-ssl-match-hostname
  (package
    (name "python2-backport-ssl-match-hostname")
    (version "3.5.0.1")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "backports.ssl_match_hostname" version))
      (sha256
       (base32
        "1wndipik52cyqy0677zdgp90i435pmvwd89cz98lm7ri0y3xjajh"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:tests? #f)) ; no test target
    (home-page "https://bitbucket.org/brandon/backports.ssl_match_hostname")
    (synopsis "Backport of ssl.match_hostname() function from Python 3.5")
    (description
     "This backport brings the ssl.match_hostname() function to users of
earlier versions of Python.  The function checks the hostname in the
certificate returned by the server to which a connection has been established,
and verifies that it matches the intended target hostname.")
    (license license:psfl)))

(define-public python-hdf4
  (package
   (name "python-hdf4")
   (version "0.9")
   (source
    (origin
      (method url-fetch)
      (uri (pypi-uri name version))
      (sha256
       (base32
        "1hjiyrxvxk9817qyqky3nar4y3fs4z8wxz0n884zzb5wi6skrjks"))))
   (build-system python-build-system)
   (native-inputs `(("nose" ,python-nose)))
   (propagated-inputs `(("numpy" ,python-numpy)))
   (inputs
    `(("hdf4" ,hdf4)
      ("libjpeg" ,libjpeg)
      ("zlib" ,zlib)))
   (arguments
    `(#:phases
      (modify-phases %standard-phases
        (replace 'check
          (lambda _
            ;; The 'runexamples' script sets PYTHONPATH to CWD, then goes
            ;; on to import numpy. Somehow this works on their CI system.
            ;; Let's just manage PYTHONPATH here instead.
            (substitute* "runexamples.sh"
              (("export PYTHONPATH=.*") ""))
            (setenv "PYTHONPATH"
                    (string-append (getcwd) ":"
                                   (getenv "PYTHONPATH")))
            (invoke "./runexamples.sh")
            (invoke "nosetests" "-v"))))))
   (home-page "https://github.com/fhs/python-hdf4")
   (synopsis "Python interface to the NCSA HDF4 library")
   (description
    "Python-HDF4 is a python wrapper around the NCSA HDF version 4 library,
which implements the SD (Scientific Dataset), VS (Vdata) and V (Vgroup) API’s.
NetCDF files can also be read and modified.  Python-HDF4 is a fork of
@url{http://hdfeos.org/software/pyhdf.php,pyhdf}.")
   (license license:expat)))

(define-public python2-hdf4
  (package-with-python2 python-hdf4))

(define-public python-h5py
  (package
    (name "python-h5py")
    (version "2.8.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "h5py" version))
      (sha256
       (base32
        "0mdr6wrq02ac93m1aqx9kad0ppfzmm4imlxqgyy1x4l7hmdcc9p6"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f ; no test target
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-hdf5-paths
          (lambda* (#:key inputs #:allow-other-keys)
            (let ((prefix (assoc-ref inputs "hdf5")))
              (substitute* "setup_build.py"
                (("\\['/opt/local/lib', '/usr/local/lib'\\]")
                 (string-append "['" prefix "/lib" "']"))
                (("'/opt/local/include', '/usr/local/include'")
                 (string-append "'" prefix "/include" "'")))
              (substitute* "setup_configure.py"
                (("\\['/usr/local/lib', '/opt/local/lib'\\]")
                 (string-append "['" prefix "/lib" "']")))
              #t))))))
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-numpy" ,python-numpy)))
    (inputs
     `(("hdf5" ,hdf5)))
    (native-inputs
     `(("python-cython" ,python-cython)
       ("python-pkgconfig" ,python-pkgconfig)))
    (home-page "http://www.h5py.org/")
    (synopsis "Read and write HDF5 files from Python")
    (description
     "The h5py package provides both a high- and low-level interface to the
HDF5 library from Python.  The low-level interface is intended to be a
complete wrapping of the HDF5 API, while the high-level component supports
access to HDF5 files, datasets and groups using established Python and NumPy
concepts.")
    (license license:bsd-3)))

(define-public python2-h5py
  (package-with-python2 python-h5py))

(define-public python-sh
  (package
    (name "python-sh")
    (version "1.12.14")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "sh" version))
       (sha256
        (base32
         "1z2hx357xp3v4cv44xmqp7lli3frndqpyfmpbxf7n76h7s1zaaxm"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             ;; XXX: A Python 2 test fails when HOME=/homeless-shelter.
             (setenv "HOME" "/tmp")
             (invoke "python" "sh.py" "test"))))))
    (native-inputs
     `(("python-coverage" ,python-coverage)))
    (home-page "https://github.com/amoffat/sh")
    (synopsis "Python subprocess replacement")
    (description "This package provides a replacement for Python's
@code{subprocess} feature.")
    (license license:expat)))

(define-public python2-sh
  (package-with-python2 python-sh))

(define-public python-cftime
  (package
    (name "python-cftime")
    (version "1.0.3.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "cftime" version))
       (sha256
        (base32
         "0362dhxbzk593walyjz30dll6y2y79wialik647cbwdsf3ad0x6x"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-numpy" ,python-numpy)))
    (native-inputs
     `(("python-coveralls" ,python-coveralls)
       ("python-cython" ,python-cython)
       ("python-pytest-cov" ,python-pytest-cov)))
    (home-page "https://github.com/Unidata/cftime")
    (synopsis "Library for time handling")
    (description
     "This package provides time-handling functionality that used to be part
of the netcdf4 package before.")
    ;; This package claims to include code under the GPLv3 but is released
    ;; under ISC.
    (license (list license:isc license:gpl3+))))

(define-public python-netcdf4
  (package
    (name "python-netcdf4")
    (version "1.4.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "netCDF4" version))
       (sha256
        (base32
         "0c0sklgrmv15ygliin8qq0hp7vanmbi74m6zpi0r1ksr0hssyd5r"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'configure-locations
           (lambda* (#:key inputs #:allow-other-keys)
             (setenv "HDF5_DIR" (assoc-ref inputs "hdf5"))
             #t)))))
    (native-inputs
     `(("python-cython" ,python-cython)))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-cftime" ,python-cftime)))
    (inputs
     `(("netcdf" ,netcdf)
       ("hdf4" ,hdf4)
       ("hdf5" ,hdf5)))
    (home-page "https://github.com/Unidata/netcdf4-python")
    (synopsis "Python/numpy interface to the netCDF library")
    (description "Netcdf4-python is a Python interface to the netCDF C
library.  netCDF version 4 has many features not found in earlier
versions of the library and is implemented on top of HDF5.  This module
can read and write files in both the new netCDF 4 and the old netCDF 3
format, and can create files that are readable by HDF5 clients.  The
API is modelled after @code{Scientific.IO.NetCDF}, and should be familiar
to users of that module.")
    ;; The software is mainly ISC, but includes some files covered
    ;; by the Expat license.
    (license (list license:isc license:expat))))

(define-public python2-netcdf4
  (package-with-python2 python-netcdf4))

(define-public python-lockfile
  (package
    (name "python-lockfile")
    (version "0.12.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "lockfile" version))
       (sha256
        (base32
         "16gpx5hm73ah5n1079ng0vy381hl802v606npkx4x8nb0gg05vba"))))
    (build-system python-build-system)
    (arguments '(#:test-target "check"))
    (native-inputs
     `(("python-pbr" ,python-pbr)))
    (home-page "https://launchpad.net/pylockfile")
    (synopsis "Platform-independent file locking module")
    (description
     "The lockfile package exports a LockFile class which provides a simple
API for locking files.")
    (license license:expat)))

(define-public python2-lockfile
  (package-with-python2 python-lockfile))

(define-public python-semantic-version
  (package
    (name "python-semantic-version")
    (version "2.6.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "semantic_version" version))
       (sha256
        (base32
         "1h2l9xyg1zzsda6kjcmfcgycbvrafwci283vcr1v5sbk01l2hhra"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))                    ; PyPI tarball lacks tests
    (home-page "https://github.com/rbarrois/python-semanticversion")
    (synopsis "Semantic versioning module for Python")
    (description
     "The @code{semantic_version} class is a small library for handling
@uref{https://semver.org/, semantic versioning} (@dfn{SemVer}) in Python.

It can compare versions, generate a new version that represents a bump in one of
the version levels, and check whether any given string is a proper semantic
version identifier.")
    (license license:bsd-3)))

(define-public python2-semantic-version
  (package-with-python2 python-semantic-version))

(define-public python-serpent
  (package
    (name "python-serpent")
    (version "1.28")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "serpent" version))
       (sha256
        (base32 "1arnckykpkvv2qrp49l1k7q5mr5pisswl0rvdx98x8wsl1n361pk"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-attrs" ,python-attrs)
       ("python-pytz" ,python-pytz)))
    (home-page "https://github.com/irmen/Serpent")
    (synopsis "Serializer for literal Python expressions")
    (description
     "Serpent provides @code{ast.literal_eval()}-compatible object tree
serialization.  It serializes an object tree into bytes (an utf-8 encoded
string) that can be decoded and then passed as-is to @code{ast.literal_eval()}
to rebuild the original object tree.

Because only safe literals are encoded, it is safe to send serpent data to
other machines, such as over the network.")
    (license license:expat)))

(define-public python-setuptools
  (package
    (name "python-setuptools")
    (version "41.0.1")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "setuptools" version ".zip"))
      (sha256
       (base32
        "04sns22y2hhsrwfy1mha2lgslvpjsjsz8xws7h2rh5a7ylkd28m2"))
      (modules '((guix build utils)))
      (snippet
       '(begin
          ;; Remove included binaries which are used to build self-extracting
          ;; installers for Windows.
          ;; TODO: Find some way to build them ourself so we can include them.
          (for-each delete-file (find-files "setuptools" "^(cli|gui).*\\.exe$"))
          #t))))
    (build-system python-build-system)
    ;; FIXME: Tests require pytest, which itself relies on setuptools.
    ;; One could bootstrap with an internal untested setuptools.
    (arguments
     `(#:tests? #f))
    (home-page "https://pypi.python.org/pypi/setuptools")
    (synopsis
     "Library designed to facilitate packaging Python projects")
    (description
     "Setuptools is a fully-featured, stable library designed to facilitate
packaging Python projects, where packaging includes:
Python package and module definitions,
distribution package metadata,
test hooks,
project installation,
platform-specific details,
Python 3 support.")
    ;; TODO: setuptools now bundles the following libraries:
    ;; packaging, pyparsing, six and appdirs. How to unbundle?
    (license (list license:psfl        ; setuptools itself
                   license:expat       ; six, appdirs, pyparsing
                   license:asl2.0      ; packaging is dual ASL2/BSD-2
                   license:bsd-2))))

(define-public python2-setuptools
  (package-with-python2 python-setuptools))

(define-public python-uniseg
  (package
    (name "python-uniseg")
    (version "0.7.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "uniseg" version ".zip"))
       (sha256
        (base32
         "05jsazvz6nbmh6l3v1rph5ydkqn1hzx1pyggdyvgp2qgmgrnmiz2"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; The test suite requires network access.
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page
     "https://bitbucket.org/emptypage/uniseg-python")
    (synopsis
     "Python library to determine Unicode text segmentations")
    (description
     "Uniseg is a Python package used to determine Unicode text segmentations.
Supported segmentations include:
@enumerate
@item @dfn{Code point} (any value in the Unicode codespace)
@item @dfn{Grapheme cluster} (user-perceived character made of a single or
multiple Unicode code points, e.g. \"G\" + acute-accent)
@item Word break
@item Sentence break
@item Line break
@end enumerate")
    (license license:expat)))

(define-public python2-uniseg
  (package-with-python2 python-uniseg))

(define-public python-humanfriendly
  (package
    (name "python-humanfriendly")
    (version "4.4.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "humanfriendly" version))
       (sha256
        (base32
         "0pisgizjql86785jchfjv217g0lsgk114g2lja5j4y3lsc3b9szi"))))
    (build-system python-build-system)
    (arguments
     `(;; XXX: Tests depend on coloredlogs, which in turn depends on humanfriendly.
       #:tests? #f))
    (propagated-inputs
     `(("python-monotonic" ,python-monotonic)))
    (home-page "https://humanfriendly.readthedocs.io")
    (synopsis "Human-friendly input and output in Python")
    (description
     "The functions and classes in @code{humanfriendly} can be used to make
text interfaces more user-friendly.  It includes tools to parse and format
numbers, file sizes, and timespans, timers for long-running operations, menus
to allow the user to choose from a list of options, and terminal interaction
helpers.")
    (license license:expat)))

(define-public python2-humanfriendly
  (package-with-python2 python-humanfriendly))

(define-public python-capturer
  (package
    (name "python-capturer")
    (version "2.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "capturer" version))
       (sha256
        (base32
         "05d6ji4j8ipiq0br7bwam38qc6hd9l1djmfxlzrxx19ziyjl4089"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))
    (propagated-inputs
     `(("python-humanfriendly" ,python-humanfriendly)))
    (home-page "https://capturer.readthedocs.io")
    (synopsis "Capture stdout and stderr streams of the current process")
    (description
     "The capturer package makes it easy to capture the stdout and stderr
streams of the current process and subprocesses.  Output can be relayed
to the terminal in real time but is also available to the Python program
for additional processing.")
    (license license:expat)))

(define-public python2-capturer
  (package-with-python2 python-capturer))

(define-public python-case
  (package
    (name "python-case")
    (version "1.5.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "case" version))
       (sha256
        (base32
         "1cagg06vfph864s6l5jb0zqliwxh647bki8j6lf4a4qrv40jnhs8"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-mock" ,python-mock)
       ("python-nose" ,python-nose)
       ("python-six" ,python-six)
       ("python-unittest2" ,python-unittest2)))
    (native-inputs
     `(("python-coverage" ,python-coverage)))
    (home-page "https://github.com/celery/case")
    (synopsis "Unittest utilities and convenience methods")
    (description
     "The @code{case} package provides utilities on top of unittest, including
some helpful Python 2 compatibility convenience methods.")
    (license license:bsd-3)))

(define-public python-verboselogs
  (package
    (name "python-verboselogs")
    (version "1.7")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "verboselogs" version))
       (sha256
        (base32
         "09z4d1jiasn7k1hs5af2ckmnrd0i1d1m04bhfjhv7z6svzfdwgg3"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-astroid" ,python-astroid)
       ("python-pylint" ,python-pylint)))
    (home-page "https://verboselogs.readthedocs.io")
    (synopsis "Verbose logging level for Python's logging module")
    (description
     "The @code{verboselogs} package extends Python's @code{logging} module to
add the log levels NOTICE, SPAM, SUCCESS and VERBOSE.")
    (license license:expat)))

(define-public python2-verboselogs
  (package-with-python2 python-verboselogs))

(define-public python-coloredlogs
  (package
    (name "python-coloredlogs")
    (version "7.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "coloredlogs" version))
       (sha256
        (base32
         "1blcann6dyg5dhps9pg12rn0q0rjrlajpmmil0gy0j4cbvnl2il9"))))
    (build-system python-build-system)
    (arguments
     `(;Tests require some updated modules
       #:tests? #f))
    (propagated-inputs
     `(("python-capturer" ,python-capturer)))
    (home-page "https://coloredlogs.readthedocs.io")
    (synopsis "Colored stream handler for Python's logging module")
    (description
     "The @code{coloredlogs} package enables colored terminal output for
Python's logging module.  The @code{ColoredFormatter} class inherits from
@code{logging.Formatter} and uses ANSI escape sequences to render your logging
messages in color.")
    (license license:expat)))

(define-public python2-coloredlogs
  (package-with-python2 python-coloredlogs))

(define-public python-et-xmlfile
  (package
    (name "python-et-xmlfile")
    (version "1.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "et_xmlfile" version))
       (sha256
        (base32
         "0nrkhcb6jdrlb6pwkvd4rycw34y3s931hjf409ij9xkjsli9fkb1"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      (invoke "pytest"))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-lxml" ,python-lxml)))   ;used for the tests
    (home-page "https://bitbucket.org/openpyxl/et_xmlfile")
    (synopsis "Low memory implementation of @code{lxml.xmlfile}")
    (description "This Python library is based upon the @code{xmlfile} module
from @code{lxml}.  It aims to provide a low memory, compatible implementation
of @code{xmlfile}.")
    (license license:expat)))

(define-public python2-et-xmlfile
  (package-with-python2 python-et-xmlfile))

(define-public python-openpyxl
  (package
    (name "python-openpyxl")
    (version "2.6.2")
    (source
     (origin
       ;; We use the upstream repository, as the tests are not included in the
       ;; PyPI releases.
       (method hg-fetch)
       (uri (hg-reference
             (url "https://bitbucket.org/openpyxl/openpyxl")
             (changeset version)))
       (file-name (string-append name "-" version "-checkout"))
       (sha256
        (base32 "1qhij6kcvdxqjy4g6193nsv4q7fy8n4fwyd3c2z047idlm6s3j4w"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      (invoke "pytest"))))))
    (native-inputs
     ;; For the test suite.
     `(("python-lxml" ,python-lxml)
       ("python-pillow" ,python-pillow)
       ("python-pytest" ,python-pytest)))
    (propagated-inputs
     `(("python-et-xmlfile" ,python-et-xmlfile)
       ("python-jdcal" ,python-jdcal)))
    (home-page "https://openpyxl.readthedocs.io")
    (synopsis "Python library to read/write Excel 2010 XLSX/XLSM files")
    (description "This Python library allows reading and writing to the Excel XLSX, XLSM,
XLTX and XLTM file formats that are defined by the Office Open XML (OOXML)
standard.")
    (license license:expat)))

(define-public python-eventlet
  (package
    (name "python-eventlet")
    (version "0.20.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "eventlet" version))
       (sha256
        (base32
         "0f3q55mq4n021wb7qa53pz3ix6i2py64sap66vsaqm2scjw83m9s"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-greenlet" ,python-greenlet)))
    (arguments
     ;; TODO: Requires unpackaged 'enum-compat'.
     '(#:tests? #f))
    (home-page "http://eventlet.net")
    (synopsis "Concurrent networking library for Python")
    (description
     "Eventlet is a concurrent networking library for Python that
allows you to change how you run your code, not how you write it.
It uses @code{epoll} or @code{libevent} for highly scalable non-blocking I/O.
Coroutines ensure that the developer uses a blocking style of programming
that is similar to threading, but provide the benefits of non-blocking I/O.
The event dispatch is implicit, which means you can easily use @code{Eventlet}
from the Python interpreter, or as a small part of a larger application.")
  (license license:expat)))

(define-public python2-eventlet
  (let ((base (package-with-python2
                (strip-python2-variant python-eventlet))))
    (package (inherit base)
      (propagated-inputs
       `(("python2-enum34" ,python2-enum34)
         ,@(package-propagated-inputs base))))))

(define-public python-six
  (package
    (name "python-six")
    (version "1.11.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "six" version))
      (sha256
       (base32
        "1scqzwc51c875z23phj48gircqjgnn3af8zy2izjwmnlxrxsgs3h"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (invoke "py.test" "-v"))))))
    (native-inputs
     `(("python-py" ,python-py)
       ("python-pytest" ,python-pytest-bootstrap)))
    (home-page "https://pypi.python.org/pypi/six/")
    (synopsis "Python 2 and 3 compatibility utilities")
    (description
     "Six is a Python 2 and 3 compatibility library.  It provides utility
functions for smoothing over the differences between the Python versions with
the goal of writing Python code that is compatible on both Python versions.
Six supports every Python version since 2.5.  It is contained in only one
Python file, so it can be easily copied into your project.")
    (license license:x11)))

(define-public python2-six
  (package-with-python2 python-six))

(define-public python-six-bootstrap
  (package
    (inherit python-six)
    (name "python-six-bootstrap")
    (native-inputs `())
    (arguments `(#:tests? #f))))

(define-public python2-six-bootstrap
  (package-with-python2 python-six-bootstrap))

(define-public python-schedule
  (package
    (name "python-schedule")
    (version "0.4.3")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "schedule" version))
      (sha256
       (base32
        "0vplyjcbfrq50sphlwya749z8p2pcyi2nycw3518i0qpd9a6189i"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-mock" ,python-mock)))
    (home-page "https://github.com/dbader/schedule")
    (synopsis "Schedule periodic function calls in Python")
    (description
     "Schedule is an in-process scheduler for periodic jobs that uses the
builder pattern for configuration.  Schedule lets you run Python functions (or
any other callable) periodically at pre-determined intervals using a simple,
human-friendly syntax.")
    (license license:expat)))

(define-public python2-schedule
  (package-with-python2 python-schedule))

(define-public python-pandas
  (package
    (name "python-pandas")
    (version "0.24.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pandas" version))
       (sha256
        (base32 "18imlm8xbhcbwy4wa957a1fkamrcb0z988z006jpfda3ki09z4ag"))))
    (build-system python-build-system)
    (arguments
     `(#:modules ((guix build utils)
                  (guix build python-build-system)
                  (ice-9 ftw)
                  (srfi srfi-26))
       #:phases (modify-phases %standard-phases
                  (add-after 'unpack 'patch-which
                    (lambda* (#:key inputs #:allow-other-keys)
                      (let ((which (assoc-ref inputs "which")))
                        (substitute* "pandas/io/clipboard/__init__.py"
                          (("^CHECK_CMD = .*")
                           (string-append "CHECK_CMD = \"" which "\"\n"))))
                      #t))
                  (replace 'check
                    (lambda _
                      (let ((build-directory
                             (string-append
                              (getcwd) "/build/"
                              (car (scandir "build"
                                            (cut string-prefix? "lib." <>))))))
                        ;; Disable the "strict data files" option which causes
                        ;; the build to error out if required data files are
                        ;; not available (as is the case with PyPI archives).
                        (substitute* "setup.cfg"
                          (("addopts = --strict-data-files") "addopts = "))
                        (with-directory-excursion build-directory
                          ;; Delete tests that require "moto" which is not yet
                          ;; in Guix.
                          (for-each delete-file
                                    '("pandas/tests/io/conftest.py"
                                      "pandas/tests/io/json/test_compression.py"
                                      "pandas/tests/io/parser/test_network.py"
                                      "pandas/tests/io/test_parquet.py"))
                          (invoke "pytest" "-vv" "pandas" "--skip-slow"
                                  "--skip-network" "-k"
                                  ;; XXX: Due to the deleted tests above.
                                  "not test_read_s3_jsonl"))))))))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-openpyxl" ,python-openpyxl)
       ("python-pytz" ,python-pytz)
       ("python-dateutil" ,python-dateutil)
       ("python-xlrd" ,python-xlrd)))
    (inputs
     `(("which" ,which)))
    (native-inputs
     `(("python-cython" ,python-cython)
       ("python-beautifulsoup4" ,python-beautifulsoup4)
       ("python-lxml" ,python-lxml)
       ("python-html5lib" ,python-html5lib)
       ("python-nose" ,python-nose)
       ("python-pytest" ,python-pytest)
       ("python-pytest-mock" ,python-pytest-mock)))
    (home-page "https://pandas.pydata.org")
    (synopsis "Data structures for data analysis, time series, and statistics")
    (description
     "Pandas is a Python package providing fast, flexible, and expressive data
structures designed to make working with structured (tabular,
multidimensional, potentially heterogeneous) and time series data both easy
and intuitive.  It aims to be the fundamental high-level building block for
doing practical, real world data analysis in Python.")
    (license license:bsd-3)))

(define-public python2-pandas
  (package-with-python2 python-pandas))

(define-public python2-mechanize
  (package
    (name "python2-mechanize")
    (version "0.2.5")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "mechanize" version))
      (sha256
       (base32
        "0rj7r166i1dyrq0ihm5rijfmvhs8a04im28lv05c0c3v206v4rrf"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2 ; apparently incompatible with Python 3
       #:tests? #f))
         ;; test fails with message
         ;; AttributeError: 'module' object has no attribute 'test_pullparser'
         ;; (python-3.3.2) or
         ;; AttributeError: 'module' object has no attribute 'test_urllib2_localnet'
         ;; (python-2.7.5).
         ;; The source code is from March 2011 and probably not up-to-date
         ;; with respect to python unit tests.
    (home-page "http://wwwsearch.sourceforge.net/mechanize/")
    (synopsis
     "Stateful programmatic web browsing in Python")
    (description
     "Mechanize implements stateful programmatic web browsing in Python,
after Andy Lester’s Perl module WWW::Mechanize.")
    (license (license:non-copyleft
              "file://COPYING"
              "See COPYING in the distribution."))))


(define-public python-simplejson
  (package
    (name "python-simplejson")
    (version "3.14.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "simplejson" version))
      (sha256
       (base32
        "1lkv3xlf7ryzi69zqfdbkvpxdfy1rg1rq2yzcnxgf4km5m6difqy"))))
    (build-system python-build-system)
    (home-page "http://simplejson.readthedocs.org/en/latest/")
    (synopsis
     "Json library for Python")
    (description
     "JSON (JavaScript Object Notation) is a subset of JavaScript
syntax (ECMA-262 3rd edition) used as a lightweight data interchange
format.

Simplejson exposes an API familiar to users of the standard library marshal
and pickle modules.  It is the externally maintained version of the json
library contained in Python 2.6, but maintains compatibility with Python 2.5
and (currently) has significant performance advantages, even without using
the optional C extension for speedups.  Simplejson is also supported on
Python 3.3+.")
    (license license:x11)))

(define-public python2-simplejson
  (package-with-python2 python-simplejson))


(define-public python-pyicu
  (package
    (name "python-pyicu")
    (version "2.2")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "PyICU" version))
      (sha256
       (base32
        "0wq9y5fi1ighgf5aws9nr87vi1w44p7q1k83rx2y3qj5d2xyhspa"))))
    (build-system python-build-system)
    (inputs
     `(("icu4c" ,icu4c)))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-six" ,python-six)))
    (home-page "https://github.com/ovalhub/pyicu")
    (synopsis "Python extension wrapping the ICU C++ API")
    (description
     "PyICU is a python extension wrapping the ICU C++ API.")
    (properties `((python2-variant . ,(delay python2-pyicu))))
    (license license:x11)))

(define-public python2-pyicu
  (let ((base (package-with-python2
                (strip-python2-variant python-pyicu))))
    (package
      (inherit base)
      (arguments
       `(,@(package-arguments base)
         #:phases
         (modify-phases %standard-phases
           (add-before 'check 'delete-failing-test
             (λ _
               ;; XXX: This fails due to Unicode issues unique to Python 2,
               ;; it seems: <https://github.com/ovalhub/pyicu/issues/61>.
               (delete-file "test/test_Script.py")
               #t))))))))

(define-public python2-dogtail
  ;; Python 2 only, as it leads to "TabError: inconsistent use of tabs and
  ;; spaces in indentation" with Python 3.
  (package
    (name "python2-dogtail")
    (version "0.9.9")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "dogtail" version))
             (sha256
              (base32
               "0p5wfssvzr9w0bvhllzbbd8fnp4cca2qxcpcsc33dchrmh5n552x"))))
    (build-system python-build-system)
    (arguments `(#:python ,python-2
                 #:tests? #f))                    ; invalid command "test"
    ;; Currently no offical homepage.
    (home-page "https://pypi.python.org/pypi/dogtail/")
    (synopsis "GUI test tool and automation framework written in Python")
    (description
     "Dogtail is a GUI test tool and automation framework written in Python.
It uses Accessibility (a11y) technologies to communicate with desktop
applications. dogtail scripts are written in Python and executed like any
other Python program.")
    (license license:gpl2+)))

(define-public python-empy
  (package
    (name "python-empy")
    (version "3.3.3")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://www.alcyone.com/software/empy/empy-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "1mxfy5mgp473ga1pgz2nvm8ds6z4g3hdky8523z6jzvcs9ny6hcq"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))                    ; python2 only
    (home-page "http://www.alcyone.com/software/empy/")
    (synopsis "Templating system for Python")
    (description
     "EmPy is a system for embedding Python expressions and statements in
template text; it takes an EmPy source file, processes it, and produces
output.  This is accomplished via expansions, which are special signals to the
EmPy system and are set off by a special prefix (by default the at sign, @@).
EmPy can expand arbitrary Python expressions and statements in this way, as
well as a variety of special forms.  Textual data not explicitly delimited in
this way is sent unaffected to the output, allowing Python to be used in
effect as a markup language.  Also supported are callbacks via hooks,
recording and playback via diversions, and dynamic, chainable filters.  The
system is highly configurable via command line options and embedded
commands.")
    (license license:lgpl2.1+)))

(define-public python2-empy
  (let ((base (package-with-python2 (strip-python2-variant python-empy))))
    (package
      (inherit base)
      (arguments `(,@(package-arguments base)
                   #:tests? #t)))))

(define-public python2-element-tree
  (package
    (name "python2-element-tree")
    (version "1.2.6")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://effbot.org/media/downloads/elementtree-"
                    version "-20050316.tar.gz"))
              (sha256
               (base32
                "016bphqnlg0l4vslahhw4r0aanw95bpypy65r1i1acyb2wj5z7dj"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2                       ; seems to be part of Python 3
       #:tests? #f))                            ; no 'test' sub-command
    (synopsis "Toolkit for XML processing in Python")
    (description
     "ElementTree is a Python library supporting lightweight XML processing.")
    (home-page "http://effbot.org/zone/element-index.htm")
    (license (license:x11-style
              "http://docs.python.org/2/license.html"
              "Like \"CWI LICENSE AGREEMENT FOR PYTHON 0.9.0 THROUGH 1.2\"."))))

(define-public python2-pybugz
  (package
    (name "python2-pybugz")
    (version "0.6.11")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://bits.liquidx.net/projects/pybugz/pybugz-"
                    version ".tar.gz"))
              (sha256
               (base32
                "17ni00p08gp5lkxlrrcnvi3x09fmajnlbz4da03qcgl9q21ym4jd"))
              (patches (search-patches "pybugz-stty.patch"
                                       "pybugz-encode-error.patch"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2                         ; SyntaxError with Python 3
       #:tests? #f))                              ; no 'test' sub-command
    (propagated-inputs
     `(("element-tree" ,python2-element-tree)))
    (synopsis "Python and command-line interface to Bugzilla")
    (description
     "PyBugz is a Python library and command-line tool to query the Bugzilla
bug tracking system.  It is meant as an aid to speed up interaction with the
bug tracker.")
    (home-page "http://www.liquidx.net/pybugz/")
    (license license:gpl2)))

(define-public python2-enum
  (package
    (name "python2-enum")
    (version "0.4.6")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "enum" version))
              (sha256
               (base32
                "13lk3yrwj42vl30kw3c194f739nrfrdg64s6i0v2p636n4k8brsl"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2))
    (home-page "http://pypi.python.org/pypi/enum/")
    (synopsis "Robust enumerated type support in Python")
    (description
     "This provides a module for robust enumerations in Python.  It has
been superseded by the Python standard library and is provided only for
compatibility.")
    ;; Choice of either license.
    (license (list license:gpl3+ license:psfl))))

(define-public python-enum34
  (package
    (name "python-enum34")
    (version "1.1.6")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "enum34" version))
      (sha256
       (base32
        "1cgm5ng2gcfrkrm3hc22brl6chdmv67b9zvva9sfs7gn7dwc9n4a"))))
    (build-system python-build-system)
    (home-page "https://pypi.python.org/pypi/enum34")
    (synopsis "Backported Python 3.4 Enum")
    (description
     "Enum34 is the new Python stdlib enum module available in Python 3.4
backported for previous versions of Python from 2.4 to 3.3.")
    (license license:bsd-3)))

(define-public python2-enum34
  (package-with-python2 python-enum34))

(define-public python-parse-type
  (package
    (name "python-parse-type")
    (version "0.4.2")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "parse_type" version))
      (sha256
       (base32
        "0g3b6gsdwnm8dpkh2vn34q6dzxm9gl908ggyzcv31n9xbp3vv5pm"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-parse" ,python-parse)))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)))
    (home-page "https://github.com/jenisys/parse_type")
    (synopsis "Extended parse module")
    (description
     "Parse_type extends the python parse module.")
    (properties
     `((python2-variant . ,(delay python2-parse-type))))
    (license license:bsd-3)))

(define-public python2-parse-type
  (let ((base (package-with-python2
                (strip-python2-variant python-parse-type))))
    (package (inherit base)
      (propagated-inputs
       `(("python2-enum34" ,python2-enum34)
         ,@(package-propagated-inputs base))))))

(define-public python-parse
  (package
    (name "python-parse")
    (version "1.8.4")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "parse" version))
      (sha256
       (base32
        "0f8997xr8nq2nq35iiviq8ningd1zvy59fg503xfpbi2dwhgdkf3"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _ (invoke "python" "test_parse.py"))))))
    (home-page "https://github.com/r1chardj0n3s/parse")
    (synopsis "Parse strings")
    (description
     "Parse strings using a specification based on the Python @code{format()}
syntax.")
    (license license:x11)))

(define-public python-polib
  (package
    (name "python-polib")
    (version "1.0.8")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "polib" version))
               (sha256
                (base32
                  "1pq2hbm3m2q0cjdszk8mc4qa1vl3wcblh5nfyirlfnzb2pcy7zss"))))
    (build-system python-build-system)
    (home-page "https://bitbucket.org/izi/polib/wiki/Home")
    (synopsis "Manipulate, create and modify gettext files")
    (description "Polib can manipulate any gettext format (po, pot and mo)
files.  It can be used to create po files from scratch or to modify
existing ones.")
    (license license:expat)))

(define-public python2-polib
  (let ((base (package-with-python2 (strip-python2-variant python-polib))))
    (package
      (inherit base)
      (arguments `(,@(package-arguments base)
                   ;; Tests don't work with python2.
                   #:tests? #f)))))

(define-public scons
  (package
    (name "scons")
    (version "3.0.4")
    (source (origin
             (method git-fetch)
             (uri (git-reference
                   (url "https://github.com/SCons/scons.git")
                   (commit version)))
             (file-name (git-file-name name version))
             (sha256
              (base32
               "1xy8jrwz87y589ihcld4hv7wn122sjbz914xn8h50ww77wbhk8hn"))))
    (build-system python-build-system)
    (arguments
     `(#:use-setuptools? #f                ; still relies on distutils
       #:tests? #f                         ; no 'python setup.py test' command
       #:phases
       (modify-phases %standard-phases
         (add-before 'build 'bootstrap
           (lambda _
             (substitute* "src/engine/SCons/compat/__init__.py"
               (("sys.modules\\[new\\] = imp.load_module\\(old, \\*imp.find_module\\(old\\)\\)")
                "sys.modules[new] = __import__(old)"))
             (substitute* "src/engine/SCons/Platform/__init__.py"
               (("mod = imp.load_module\\(full_name, file, path, desc\\)")
                "mod = __import__(full_name)"))
             (invoke "python" "bootstrap.py" "build/scons" "DEVELOPER=guix")
             (chdir "build/scons")
             #t)))))
    (home-page "http://scons.org/")
    (synopsis "Software construction tool written in Python")
    (description
     "SCons is a software construction tool.  Think of SCons as an improved,
cross-platform substitute for the classic Make utility with integrated
functionality similar to autoconf/automake and compiler caches such as ccache.
In short, SCons is an easier, more reliable and faster way to build
software.")
    (license license:x11)))

(define-public scons-python2
  (package
    (inherit (package-with-python2 scons))
    (name "scons-python2")))

(define-public python-extras
  (package
    (name "python-extras")
    (version "1.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "extras" version))
       (sha256
        (base32
         "0khvm08rcwm62wc47j8niyl6h13f8w51c8669ifivjdr23g3cbhk"))))
    (build-system python-build-system)
    (arguments
     ;; FIXME: Circular dependency on testtools.
     '(#:tests? #f))
    (home-page "https://github.com/testing-cabal/extras")
    (synopsis "Useful extensions to the Python standard library")
    (description
     "Extras is a set of extensions to the Python standard library.")
    (license license:expat)))

(define-public python2-extras
  (package-with-python2 python-extras))

(define-public python-mimeparse
  (package
    (name "python-mimeparse")
    (version "1.6.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "python-mimeparse" version))
       (sha256
        (base32
         "0y2g6cl660bpz11srgqyvvm8gmywpgyx8g0xfvbiyr0af0yv1r3n"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (invoke "./mimeparse_test.py"))))))
    (home-page
     "https://github.com/dbtsai/python-mimeparse")
    (synopsis "Python library for parsing MIME types")
    (description
     "Mimeparse provides basic functions for parsing MIME type names and
matching them against a list of media-ranges.")
    (license license:expat)))

(define-public python2-mimeparse
  (package-with-python2 python-mimeparse))

(define-public python-miniboa
  (package
    (name "python-miniboa")
    (version "1.0.7")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "miniboa" version))
       (sha256
        (base32
         "09jh3pn4rh7kh7jayanf8jzy6gp03791b5a193w6148cf3i6k9m3"))))
    (build-system python-build-system)
    (home-page "https://github.com/shmup/miniboa")
    (synopsis "Simple, single-threaded Telnet server")
    (description
     "Miniboa is a simple, asynchronous, single-threaded, poll-based Telnet
server.")
    (license license:asl2.0)))

(define-public python2-miniboa
  (package-with-python2 python-miniboa))

(define-public python-pafy
  (package
    (name "python-pafy")
    (version "0.5.3.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pafy" version))
       (sha256
        (base32
         "1a7dxi95m1043rxx1r5x3ngb66nwlq6aqcasyqqjzmmmjps4zrim"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f)) ; Currently pafy can not find itself in the tests
    (propagated-inputs
     ;; Youtube-dl is a python package which is imported in the file
     ;; "backend_youtube_dl.py", therefore it needs to be propagated.
     `(("youtube-dl" ,youtube-dl)))
    (home-page "https://np1.github.io/pafy/")
    (synopsis "Retrieve YouTube content and metadata")
    (description
     "@code{pafy} is a python library to retrieve YouTube content and metadata.")
    (license license:lgpl3+)))

(define-public python2-funcsigs
  (package
    (name "python2-funcsigs")
    (version "1.0.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "funcsigs" version))
              (sha256
               (base32
                "0l4g5818ffyfmfs1a924811azhjj8ax9xd1cffr1mzd3ycn0zfx7"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2))
    (native-inputs
     `(("python2-unittest2" ,python2-unittest2)))
    (home-page "http://funcsigs.readthedocs.org")
    (synopsis "Python function signatures from PEP362")
    (description
     "Backport of @code{funcsigs} which was introduced in Python 3.3.")
    (license license:asl2.0)))

(define-public python2-funcsigs-bootstrap
  (package
    (inherit python2-funcsigs)
    (name "python2-funcsigs-bootstrap")
    (native-inputs `())
    (arguments
     `(#:tests? #f
       ,@(package-arguments python2-funcsigs)))))

(define-public python-py
  (package
    (name "python-py")
    (version "1.5.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "py" version))
       (sha256
        (base32
         "1xxvwfn82457djf55f5n2c94699rfqnk43br8fif2r2q8gvrmm9z"))))
    (build-system python-build-system)
    (arguments
     ;; FIXME: "ImportError: 'test' module incorrectly imported from
     ;; '/gnu/store/...-python-pytest-mimimal-3.0.5/lib/python3.5/site-packages'.
     ;; Expected '/tmp/guix-build-python-py-1.4.31.drv-0/py-1.4.31/py'.
     ;; Is this module globally installed?"
     '(#:tests? #f))
    (native-inputs
     `(("python-setuptools-scm" ,python-setuptools-scm)))
    (home-page "https://github.com/pytest-dev/py")
    (synopsis "Python library for parsing, I/O, instrospection, and logging")
    (description
     "Py is a Python library for file name parsing, .ini file parsing, I/O,
code introspection, and logging.")
    (license license:expat)))

(define-public python2-py
  (package-with-python2 python-py))

;; Recent versions of python-fixtures and python-testrepository need
;; python-pbr for packaging, which itself needs these two packages for
;; testing.
;; To fix this circular dependency, we use a build of python-pbr, based on the
;; same source, just without any test dependencies and with tests disabled.
;; python-pbr-minmal is then used to package python-fixtures and
;; python-testrepository.
;; Strictly speaking we currently could remove the test-requirements from the
;; normal python-pbr package (and save this package) since test are disabled
;; there anyway. But this may change in future.
(define-public python-pbr-minimal
  (package
    (name "python-pbr-minimal")
    (version "3.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pbr" version))
       (sha256
        (base32
         "14fs5acnalnb3h62s7q7av239j541fk0n0z0lawh4h09b1s93s6p"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))
    (home-page "http://docs.openstack.org/developer/pbr/")
    (synopsis "Minimal build of python-pbr used for bootstrapping")
    (description
     "Used only for bootstrapping python2-pbr, you should not need this.")
    (license license:asl2.0)))

(define-public python2-pbr-minimal
  (package-with-python2 python-pbr-minimal))

(define-public python-pbr
  (package
    (inherit python-pbr-minimal)
    (name "python-pbr")
    (arguments
     `(#:tests? #f)) ;; Most tests seem to use the Internet.
    (propagated-inputs
      `(("git" ,git))) ;; pbr actually uses the "git" binary.
    (native-inputs
      `(("python-fixtures" ,python-fixtures-bootstrap)
        ;; discover, coverage, hacking, subunit
        ("python-mock" ,python-mock)
        ("python-six" ,python-six)
        ("python-sphinx" ,python-sphinx)
        ("python-testrepository" ,python-testrepository-bootstrap)
        ("python-testresources" ,python-testresources-bootstrap)
        ("python-testscenarios" ,python-testscenarios-bootstrap)
        ("python-testtools" ,python-testtools-bootstrap)
        ("python-virtualenv" ,python-virtualenv)))
    (synopsis "Enhance the default behavior of Python’s setuptools")
    (description
      "Python Build Reasonableness (PBR) is a library that injects some useful
and sensible default behaviors into your setuptools run.  It will set
versions, process requirements files and generate AUTHORS and ChangeLog file
from git information.
")))

(define-public python2-pbr
  (package-with-python2 python-pbr))

(define-public python-pyrsistent
  (package
    (name "python-pyrsistent")
    (version "0.14.11")
    (home-page "https://github.com/tobgu/pyrsistent")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pyrsistent" version))
              (sha256
               (base32
                "1qkh74bm296mp5g3r11lgsksr6bh4w1bf8pji4nmxdlfj542ga1w"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-hypothesis" ,python-hypothesis)
       ("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)))
    (propagated-inputs
     `(("python-six" ,python-six)))
    (synopsis "Persistent data structures for Python")
    (description
     "Pyrsistent is a number of persistent collections (by some referred to as
functional data structures).  Persistent in the sense that they are immutable.

All methods on a data structure that would normally mutate it instead return a
new copy of the structure containing the requested updates.  The original
structure is left untouched.")
    (license license:expat)))

(define-public python2-pyrsistent
  (package-with-python2 python-pyrsistent))

(define-public python-exif-read
  (package
    (name "python-exif-read")
    (version "2.1.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "ExifRead" version))
              (sha256
               (base32
                "1b90jf6m9vxh9nanhpyvqdq7hmfx5iggw1l8kq10jrs6xgr49qkr"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f)) ; no tests
    (home-page "https://github.com/ianare/exif-py")
    (synopsis "Python library to extract EXIF data from image files")
    (description
     "ExifRead is a Python library to extract EXIF data from tiff and jpeg
files.")
    (license license:bsd-3)))

(define-public python2-exif-read
  (package-with-python2 python-exif-read))

(define-public python-pyld
  (package
    (name "python-pyld")
    (version "1.0.3")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "PyLD" version))
              (sha256
               (base32
                "12i2g6xdj30k7xxcibg3sc5y76snwq8l6n8fy9lyi577kgy0h2pm"))))
    (build-system python-build-system)
    (home-page "https://github.com/digitalbazaar/pyld")
    (synopsis "Python implementation of the JSON-LD specification")
    (description
     "PyLD is an implementation of the JSON-LD specification.")
    (license license:bsd-3)))

(define-public python2-pyld
  (package-with-python2 python-pyld))

(define-public python-click
  (package
    (name "python-click")
    (version "7.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "click" version))
       (sha256
        (base32
         "1mzjixd4vjbjvzb6vylki9w1556a9qmdh35kzmq6cign46av952v"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-paths
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((glibc (assoc-ref inputs ,(if (%current-target-system)
                                                 "cross-libc" "libc"))))
               (substitute* "click/_unicodefun.py"
                 (("'locale'")
                  (string-append "'" glibc "/bin/locale'"))))
             #t))
         (replace 'check
           (lambda _
             (invoke "python" "-m" "pytest"))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://palletsprojects.com/p/click/")
    (synopsis "Command line library for Python")
    (description
     "Click is a Python package for creating command line interfaces in a
composable way with as little code as necessary.  Its name stands for
\"Command Line Interface Creation Kit\".  It's highly configurable but comes
with sensible defaults out of the box.")
    (license license:bsd-3)))

(define-public python2-click
  (package-with-python2 python-click))

(define-public python-wheel
  (package
    (name "python-wheel")
    (version "0.32.3")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "wheel" version))
        (sha256
         (base32
          "1dhxl1bf18bx9szmqcnxbg6204hp3im8089q3hkwh5jfa6zh75q2"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-jsonschema" ,python-jsonschema)
       ("python-pytest-cov" ,python-pytest-cov)))
    (home-page "https://bitbucket.org/pypa/wheel/")
    (synopsis "Format for built Python packages")
    (description
     "A wheel is a ZIP-format archive with a specially formatted filename and
the @code{.whl} extension.  It is designed to contain all the files for a PEP
376 compatible install in a way that is very close to the on-disk format.  Many
packages will be properly installed with only the @code{Unpack} step and the
unpacked archive preserves enough information to @code{Spread} (copy data and
scripts to their final locations) at any later time.  Wheel files can be
installed with a newer @code{pip} or with wheel's own command line utility.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-wheel))))))

(define-public python2-wheel
  (let ((wheel (package-with-python2
                (strip-python2-variant python-wheel))))
    (package (inherit wheel)
      (native-inputs `(("python2-functools32" ,python2-functools32)
                        ,@(package-native-inputs wheel))))))

(define-public python-vcversioner
  (package
    (name "python-vcversioner")
    (version "2.16.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "vcversioner" version))
       (sha256
        (base32
         "16z10sm78jd7ca3jbkgc3q5i8a8q7y1h21q1li21yy3rlhbhrrns"))))
    (build-system python-build-system)
    (synopsis "Python library for version number discovery")
    (description "Vcversioner is a Python library that inspects tagging
information in a variety of version control systems in order to discover
version numbers.")
    (home-page "https://github.com/habnabit/vcversioner")
    (license license:isc)))

(define-public python2-vcversioner
  (package-with-python2 python-vcversioner))

(define-public python-jdcal
  (package
    (name "python-jdcal")
    (version "1.4")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "jdcal" version))
        (sha256
          (base32
            "1ja6j2xq97bsl6rv09mhdx7n0xnrsfx0mj5xqza0mxghqmkm02pa"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      (invoke "pytest"))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/phn/jdcal")
    (synopsis "Functions to convert between Julian dates Gregorian dates")
    (description "This Python library provides functions for converting
between Julian dates and Gregorian dates.")
    (license license:bsd-2)))

(define-public python2-jdcal
  (package-with-python2 python-jdcal))

(define-public python-jsonschema
  (package
    (name "python-jsonschema")
    (version "3.0.1")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "jsonschema" version))
             (sha256
              (base32
               "03g20i1xfg4qdlk4475pl4pp7y0h37g1fbgs5qhy678q9xb822hc"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (setenv "PYTHONPATH" (string-append ".:" (getenv "PYTHONPATH")))
             (invoke "trial" "jsonschema"))))))
    (native-inputs
     `(("python-setuptools_scm" ,python-setuptools-scm)
       ("python-twisted" ,python-twisted)))
    (propagated-inputs
     `(("python-attrs" ,python-attrs)
       ("python-pyrsistent" ,python-pyrsistent)
       ("python-six" ,python-six)))
    (home-page "https://github.com/Julian/jsonschema")
    (synopsis "Implementation of JSON Schema for Python")
    (description
     "Jsonschema is an implementation of JSON Schema for Python.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-jsonschema))))))

(define-public python2-jsonschema
  (let ((jsonschema (package-with-python2
                     (strip-python2-variant python-jsonschema))))
    (package (inherit jsonschema)
             (propagated-inputs
              `(("python2-functools32" ,python2-functools32)
                ,@(package-propagated-inputs jsonschema))))))

;; This old version is still required by docker-compose as of 1.24.0.
(define-public python-jsonschema-2.6
  (package
    (name "python-jsonschema")
    (version "2.6.0")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "jsonschema" version))
             (sha256
              (base32
               "00kf3zmpp9ya4sydffpifn0j0mzm342a2vzh82p6r0vh10cg7xbg"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check (lambda _ (invoke "nosetests"))))))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-vcversioner" ,python-vcversioner)))
    (home-page "https://github.com/Julian/jsonschema")
    (synopsis "Implementation of JSON Schema for Python")
    (description
     "Jsonschema is an implementation of JSON Schema for Python.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-jsonschema))))))

(define-public python-schema
  (package
    (name "python-schema")
    (version "0.6.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "schema" version))
       (sha256
        (base32
         "1lw28j9w9vxyigg7vkfkvi6ic9lgjkdnfvnxdr7pklslqvzmk2vm"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/keleshev/schema")
    (synopsis "Simple data validation library")
    (description
     "@code{python-schema} is a library for validating Python data
structures, such as those obtained from config-files, forms, external
services or command-line parsing, converted from JSON/YAML (or
something else) to Python data-types.")
    (license license:psfl)))

(define-public python2-schema
  (package-with-python2 python-schema))

(define-public python-schema-0.5
  (package (inherit python-schema)
    (version "0.5.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "schema" version))
       (sha256
        (base32
         "10zqvpaky51kgb8nd42bk7jwl8cn2zvayxjpdc1wwmpybj92x67s"))))))

(define-public python2-schema-0.5
  (package-with-python2 python-schema-0.5))

(define-public python-kitchen
  (package
    (name "python-kitchen")
    (version "1.2.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "kitchen" version))
       (sha256
        (base32
         "1zakh6l0yjvwic9p0nkvmbidpnkygkxbigh2skmb5gccyrhbp7xg"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-chardet" ,python-chardet)))
    (home-page "https://github.com/fedora-infra/kitchen")
    (synopsis "Python API for snippets")
    (description "@code{kitchen} module provides a python API for all sorts of
little useful snippets of code that everybody ends up writing for their projects
but never seem big enough to build an independent release.  Use kitchen and stop
cutting and pasting that code over and over.")
    (license (list license:lgpl2.1+
                   ;; subprocess.py, test_subprocess.py,
                   ;; kitchen/pycompat25/defaultdict.py:
                   license:psfl))))

(define-public python2-kitchen
  (package-with-python2 python-kitchen))

(define-public python-unidecode
  (package
    (name "python-unidecode")
    (version "1.1.0")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "Unidecode" version))
             (sha256
              (base32
               "00pi0czzwvbf7djhkkjyvimj60wqdx0llbddzfnax650g9b8yscc"))))
    (build-system python-build-system)
    (home-page "https://pypi.python.org/pypi/Unidecode")
    (synopsis "ASCII transliterations of Unicode text")
    (description
     "Unidecode provides ASCII transliterations of Unicode text.  Unidecode is
useful when integrating with legacy code that doesn't support Unicode, or for
ease of entry of non-Roman names on a US keyboard, or when constructing ASCII
machine identifiers from human-readable Unicode strings that should still be
somewhat intelligible.")
    (license license:gpl2+)))

(define-public python2-unidecode
  (package-with-python2 python-unidecode))

(define-public python-pyjwt
  (package
    (name "python-pyjwt")
    (version "1.5.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "PyJWT" version))
       (sha256
        (base32
         "1rxsg14i33vm2i6lz0my628108c81k43v10n4h3p0gx62xdyf2sh"))
       (modules '((guix build utils)))
       (snippet
        '(begin
           (for-each delete-file-recursively
                     (find-files "." "\\.pyc$"))
           #t))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-pytest-runner" ,python-pytest-runner)))
    (home-page "https://github.com/progrium/pyjwt")
    (synopsis "JSON Web Token implementation in Python")
    (description
     "PyJWT is a JSON Web Token implementation written in Python.")
    (license license:expat)))

(define-public python2-pyjwt
  (package-with-python2 python-pyjwt))

(define-public python-pykka
  (package
    (name "python-pykka")
    (version "1.2.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Pykka" version))
       (sha256
        (base32
         "049w3r0mdnnw7xv19jiq7rvls9k7xs73x05b4qs5d6z4vvmgyiz8"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-nose" ,python-nose)
       ("python-gevent" ,python-gevent)
       ("python-eventlet" ,python-eventlet)))
    (home-page "https://www.pykka.org/")
    (synopsis "Pykka is a Python implementation of the actor model")
    (description
     "Pykka is a Python implementation of the actor model.
The actor model introduces some simple rules to control the sharing
of state and cooperation between execution units, which makes it
easier to build concurrent applications.")
    (license license:asl2.0)))

(define-public python2-pykka
  (package-with-python2 python-pykka))

(define-public python-pymsgbox
  (package
    (name "python-pymsgbox")
    (version "1.0.6")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
              ;; LICENSE.txt is not present on pypi
              (url "https://github.com/asweigart/PyMsgBox")
              (commit "55926b55f46caa969c5ddb87990ebea2737bd66f")))
       (file-name (git-file-name name version))
       (sha256
        (base32
         "0zy7rjfpwlrd8b64j7jk2lb8m2npc21rnpwakpfvwgl4nxdy80rg"))))
    (arguments
     ;; Circular dependency to run tests:
     ;; Tests need pyautogui, which depends on pymsgbox.
     '(#:tests? #f))
    (build-system python-build-system)
    (home-page "https://github.com/asweigart/PyMsgBox")
    (synopsis "Python module for JavaScript-like message boxes")
    (description
     "PyMsgBox is a simple, cross-platform, pure Python module for
JavaScript-like message boxes.  Types of dialog boxes include:
@enumerate
@item alert
@item confirm
@item prompt
@item password
@end enumerate
")
    (license license:bsd-3)))

(define-public python-pympler
  (package
    (name "python-pympler")
    (home-page "https://pythonhosted.org/Pympler/")
    (version "0.5")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "Pympler" version))
              (sha256
               (base32
                "03qwsbilqgvnbl3a1jmpgixbr2kq6m3fvdlzyr3wdp01bwlc85kx"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (delete 'check)
                  (add-after 'install 'check
                    (lambda* (#:key inputs outputs #:allow-other-keys)
                      (add-installed-pythonpath inputs outputs)
                      (invoke "python" "setup.py" "test"))))))
    (synopsis "Measure, monitor and analyze memory behavior")
    (description
     "Pympler is a development tool to measure, monitor and analyze
the memory behavior of Python objects in a running Python application.

By pympling a Python application, detailed insight in the size and the
lifetime of Python objects can be obtained.  Undesirable or unexpected
runtime behavior like memory bloat and other @samp{pymples} can easily
be identified.

A web profiling frontend exposes process statistics, garbage
visualisation and class tracker statistics.")
    (license license:asl2.0)))

(define-public python2-pympler
  (package-with-python2 python-pympler))

(define-public python-itsdangerous
  (package
    (name "python-itsdangerous")
    (version "1.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "itsdangerous" version))
       (sha256
        (base32
         "068zpbksq5q2z4dckh2k1zbcq43ay74ylqn77rni797j0wyh66rj"))))
    (build-system python-build-system)
    (home-page "https://palletsprojects.com/p/itsdangerous/")
    (synopsis "Python library for passing data to/from untrusted environments")
    (description
     "Itsdangerous provides various helpers to pass trusted data to untrusted
environments and back.")
    (license license:bsd-3)))

(define-public python2-itsdangerous
  (package-with-python2 python-itsdangerous))

(define-public python-pyyaml
  (package
    (name "python-pyyaml")
    (version "3.13")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "PyYAML" version))
       (sha256
        (base32
         "1gx603g484z46cb74j9rzr6sjlh2vndxayicvlyhxdz98lhhkwry"))))
    (build-system python-build-system)
    (inputs
     `(("libyaml" ,libyaml)))
    (home-page "http://pyyaml.org/wiki/PyYAML")
    (synopsis "YAML parser and emitter for Python")
    (description
     "PyYAML is a YAML parser and emitter for Python.  PyYAML features a
complete YAML 1.1 parser, Unicode support, pickle support, capable extension
API, and sensible error messages.  PyYAML supports standard YAML tags and
provides Python-specific tags that allow to represent an arbitrary Python
object.")
    (license license:expat)))

(define-public python2-pyyaml
  (package-with-python2 python-pyyaml))

(define-public python-vine
  (package
    (name "python-vine")
    (version "1.1.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "vine" version))
       (sha256
        (base32
         "0wkskb2hb494v9gixqnf4bl972p4ibcmxdykzpwjlfa5picns4aj"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-case" ,python-case)))
    (home-page "https://github.com/celery/vine")
    (synopsis "Promises for Python")
    (description
     "@code{vine} provides a special implementation of promises in that it can
be used both for \"promise of a value\" and lazy evaluation.  The biggest
upside for this is that everything in a promise can also be a promise,
e.g. filters, callbacks and errbacks can all be promises.")
    (license license:bsd-3)))

(define-public python-virtualenv
  (package
    (name "python-virtualenv")
    (version "16.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "virtualenv" version))
       (sha256
        (base32
         "0242cg3hdq3qdvx5flyrki8lpwlgwf5k45c21ks5049fv7ygm6gq"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'disable-failing-test
           (lambda _
             ;; Disable failing test.  See upstream bug report
             ;; https://github.com/pypa/virtualenv/issues/957
             (substitute* "tests/test_virtualenv.py"
               (("skipif.*") "skipif(True, reason=\"Guix\")\n"))
             #t)))))
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-pytest" ,python-pytest)))
    (home-page "https://virtualenv.pypa.io/")
    (synopsis "Virtual Python environment builder")
    (description
     "Virtualenv is a tool to create isolated Python environments.")
    (license license:expat)))

(define-public python2-virtualenv
  (package-with-python2 python-virtualenv))

(define-public python-markupsafe
  (package
    (name "python-markupsafe")
    (version "1.1.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "MarkupSafe" version))
       (sha256
        (base32
         "0sqipg4fk7xbixqd8kq6rlkxj664d157bdwbh93farcphf92x1r9"))))
    (build-system python-build-system)
    (arguments
     `(#:modules ((ice-9 ftw)
                  (srfi srfi-1)
                  (srfi srfi-26)
                  (guix build utils)
                  (guix build python-build-system))
       #:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      (let ((cwd (getcwd))
                            (libdir (find (cut string-prefix? "lib." <>)
                                          (scandir "build"))))
                      (setenv "PYTHONPATH"
                              (string-append cwd "/build/" libdir ":"
                                             (getenv "PYTHONPATH")))
                      (invoke "pytest" "-vv")))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/mitsuhiko/markupsafe")
    (synopsis "XML/HTML/XHTML markup safe string implementation for Python")
    (description
     "Markupsafe provides an XML/HTML/XHTML markup safe string implementation
for Python.")
    (license license:bsd-3)))

(define-public python2-markupsafe
  (package-with-python2 python-markupsafe))

(define-public python-jinja2
  (package
    (name "python-jinja2")
    (version "2.10.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Jinja2" version))
       (sha256
        (base32
         "04shqrs56aj04ipyqykj512rw2l0zfammvj9krawzxz7xc14yp06"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-markupsafe" ,python-markupsafe)))
    (home-page "http://jinja.pocoo.org/")
    (synopsis "Python template engine")
    (description
     "Jinja2 is a small but fast and easy to use stand-alone template engine
written in pure Python.")
    (license license:bsd-3)))

(define-public python2-jinja2
  (package-with-python2 python-jinja2))

(define-public python-pystache
  (package
    (name "python-pystache")
    (version "0.5.4")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pystache" version))
              (sha256
               (base32
                "0nmqsfmiw4arjxqkmf9z66ml950pcdjk6aq4gin4sywmzdjw5fzp"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; FIXME: Python 3 tests are failing.
    (home-page "http://defunkt.io/pystache/")
    (synopsis "Python logic-less template engine")
    (description
     "Pystache is a Python implementation of the framework agnostic,
logic-free templating system Mustache.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-pystache))))))

(define-public python2-pystache
  (package (inherit (package-with-python2
                     (strip-python2-variant python-pystache)))
           (arguments
            `(#:python ,python-2
              #:phases
              (modify-phases %standard-phases
                (replace 'check
                  (lambda _
                    (invoke "python" "test_pystache.py"))))))))

(define-public python-joblib
  (package
    (name "python-joblib")
    (version "0.13.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "joblib" version))
              (sha256
               (base32
                "0612nazad8dxmn3xghfrmjax6456l4xy6hn9cngs7vydi14ds7v5"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _ (invoke "pytest" "-v" "joblib"))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://joblib.readthedocs.io/")
    (synopsis "Using Python functions as pipeline jobs")
    (description
     "Joblib is a set of tools to provide lightweight pipelining in Python.
In particular, joblib offers: transparent disk-caching of the output values
and lazy re-evaluation (memoize pattern), easy simple parallel computing
logging and tracing of the execution.")
    (license license:bsd-3)))

(define-public python2-joblib
  (package-with-python2 python-joblib))

(define-public python-daemon
  (package
    (name "python-daemon")
    (version "2.2.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "python-daemon" version))
       (sha256
        (base32
         "09fcjdjzk9ywmpnrj62iyxqgcygzdafsz41qlrk2dknzbagcmzmg"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'disable-tests
           (lambda _
             ;; FIXME: Determine why test fails
             (substitute* "test/test_daemon.py"
               (("test_detaches_process_context")
                "skip_test_detaches_process_context"))
             #t)))))
    (propagated-inputs
     `(("python-lockfile" ,python-lockfile)))
    (native-inputs
     `(("python-unittest2" ,python-unittest2)
       ("python-testtools" ,python-testtools)
       ("python-testscenarios" ,python-testscenarios)
       ("python-mock" ,python-mock)
       ("python-docutils" ,python-docutils)))
    (home-page "https://pagure.io/python-daemon/")
    (synopsis "Python library for making a Unix daemon process")
    (description "Python-daemon is a library that assists a Python program to
turn itself into a well-behaved Unix daemon process, as specified in PEP 3143.

This library provides a @code{DaemonContext} class that manages the following
important tasks for becoming a daemon process:
@enumerate
@item Detach the process into its own process group.
@item Set process environment appropriate for running inside a chroot.
@item Renounce suid and sgid privileges.
@item Close all open file descriptors.
@item Change the working directory, uid, gid, and umask.
@item Set appropriate signal handlers.
@item Open new file descriptors for stdin, stdout, and stderr.
@item Manage a specified PID lock file.
@item Register cleanup functions for at-exit processing.
@end enumerate")
    ;; Only setup.py is gpl3+, everything else is apache 2.0 licensed.
    (license (list license:asl2.0 license:gpl3+))))

(define-public python-docutils
  (package
    (name "python-docutils")
    (version "0.14")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "docutils" version))
       (sha256
        (base32
         "0x22fs3pdmr42kvz6c654756wja305qv6cx1zbhwlagvxgr4xrji"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; no setup.py test command
    (home-page "http://docutils.sourceforge.net/")
    (synopsis "Python Documentation Utilities")
    (description
     "Docutils is a modular system for processing documentation into useful
formats, such as HTML, XML, and LaTeX.  For input Docutils supports
reStructuredText.")
    ;; Most of the source code is public domain, but some source files are
    ;; licensed under the PFSL, BSD 2-clause, and GPLv3+ licenses.
    (license (list license:public-domain license:psfl license:bsd-2 license:gpl3+))))

(define-public python2-docutils
  (package-with-python2 python-docutils))

(define-public python-pygments
  (package
    (name "python-pygments")
    (version "2.4.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Pygments" version))
       (sha256
        (base32
         "15v2sqm5g12bqa0c7wikfh9ck2nl97ayizy1hpqhmws5gqalq748"))))
    (build-system python-build-system)
    (arguments
     ;; FIXME: Tests require sphinx, which depends on this.
     '(#:tests? #f))
    (home-page "http://pygments.org/")
    (synopsis "Syntax highlighting")
    (description
     "Pygments is a syntax highlighting package written in Python.")
    (license license:bsd-2)))

(define-public python2-pygments
  (package-with-python2 python-pygments))

(define-public python-bumpversion
  (package
    (name "python-bumpversion")
    (version "0.5.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "bumpversion" version))
       (sha256
        (base32
         "0zn7694yfipxg35ikkfh7kvgl2fissha3dnqad2c5bvsvmrwhi37"))))
    (build-system python-build-system)
    (home-page "https://github.com/peritus/bumpversion")
    (synopsis "Tool to bump software version")
    (description "This tool provides a command-line interface (CLI) to bump a
software version simply.")
    (license license:expat)))

(define-public python-deprecated
  (package
    (name "python-deprecated")
    (version "1.2.5")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/tantale/deprecated.git")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32
         "14909glxxwwc4b9qpz2b9jdriwzi5n65ichw85xqppap5f79wcwz"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      (invoke "pytest"))))))
    (propagated-inputs
     `(("python-wrapt" ,python-wrapt)))
    (native-inputs
     `(("python-bumpversion" ,python-bumpversion)
       ("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-sphinx" ,python-sphinx)
       ("python-tox" ,python-tox)))
    (home-page "https://github.com/tantale/deprecated")
    (synopsis "Python decorator to deprecate classes, functions or methods")
    (description "The @code{deprecated} decorator provides a convenient way to deprecate
to deprecate classes, functions or methods.")
    (license license:expat)))

(define-public python-pygithub
  (package
    (name "python-pygithub")
    (version "1.43.7")
    (source
     ;; We fetch from the Git repo because there are no tests in the PyPI
     ;; archive.
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/PyGithub/PyGithub.git")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32
         "0ww92zz0ja9w6rw83vphmn8rwmcn6abg16j4q7zxjc0rrg2cfj9i"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  ;; Some tests rely on the network.
                  (add-after 'unpack 'disable-failing-tests
                    (lambda _
                      (substitute* "tests/Issue142.py"
                        (("testDecodeJson") "disabled_testDecodeJson"))
                      #t))
                  (add-before 'check 'prepare-for-tests
                    (lambda _
                      (for-each (lambda (f)
                                  (chmod f #o666))
                                (find-files "./tests"))
                      (system* "python" "-m" "lib2to3" "-w" "-n" "tests")
                      (setenv "PYTHONPATH"
                              (string-append "./tests:" (getenv "PYTHONPATH")))
                      #t)))))
    (propagated-inputs
     `(("python-deprecated" ,python-deprecated)
       ("python-pyjwt" ,python-pyjwt)
       ("python-requests" ,python-requests)))
    (native-inputs `(("python-httpretty" ,python-httpretty)))
    (home-page "https://pygithub.readthedocs.io/en/latest/")
    (synopsis "Python library for the GitHub API")
    (description "This library allows managing GitHub resources such as
repositories, user profiles, and organizations in your Python applications,
using version 3 of the GitHub application programming interface (API).")
    (license license:lgpl3+)))

(define-public python-rellu
  (package
    (name "python-rellu")
    (version "0.7")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "rellu" version))
       (sha256
        (base32
         "1w0arpj1sm7vh29nrbnca4pnp8sx42l07r17inwqcjjf9bhng66x"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-invoke" ,python-invoke)
       ("python-pygithub" ,python-pygithub)))
    (home-page "https://github.com/robotframework/rellu")
    (synopsis "Utilities to create PyPI releases")
    (description "This collection of utilities contains tooling and templates
to assist in creating releases on GitHub and publishing them on PyPI.  It is
designed to be used by Robot Framework and tools and libraries in its
ecosystem, but can naturally be used also by other projects.")
    (license license:asl2.0)))

(define-public python-robotframework
  (package
    (name "python-robotframework")
    (version "3.1.2")
    ;; There are no tests in the PyPI archive.
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/robotframework/robotframework.git")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32 "16gnxy0qinh8fhs0qvhff5z2xh49c3cqgm0d7bfjw120df6x7fym"))
       (patches (search-patches
                 "python-robotframework-honor-source-date-epoch.patch"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (add-before 'build 'build-and-install-doc
                    (lambda* (#:key outputs #:allow-other-keys)
                      (let* ((doc-output (assoc-ref outputs "doc"))
                             (doc (string-append doc-output "/share/"
                                                 ,name "-" ,version "/")))
                        (invoke "invoke" "library-docs" "all")
                        (mkdir-p doc)
                        (copy-recursively "doc/libraries"
                                          (string-append doc "/libraries"))
                        #t)))
                  (replace 'check
                    (lambda _
                      (invoke "python" "utest/run.py"))))))
    (native-inputs
     `(("python-invoke" ,python-invoke)
       ("python-rellu" ,python-rellu)
       ("python:tk" ,python "tk")))     ;used when building the HTML doc
    (outputs '("out" "doc"))
    (home-page "https://robotframework.org")
    (synopsis "Generic automation framework")
    (description "Robot Framework is a generic automation framework for
acceptance testing, acceptance test driven development (ATDD), and robotic
process automation (RPA).")
    (license license:asl2.0)))

(define-public python-robotframework-lint
  ;; There is no properly tagged release; the commit below seems to correspond
  ;; to the 0.9 stable release available from PyPI.  The tests are not
  ;; included in the PyPI archive, so we fetch the sources from the upstream
  ;; Git repo.
  (let ((commit "e851879bab1f63e4e53b34a4dc8a67ed95102830")
        (revision "1"))
    (package
      (name "python-robotframework-lint")
      (version (git-version "0.9.0" revision commit))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "https://github.com/boakley/robotframework-lint.git")
               (commit commit)))
         (file-name (git-file-name name version))
         (sha256
          (base32
           "1p6fknqg5sb9qz5857ji4a877657vgfjm5v3zn45994parx6ml1m"))))
      (build-system python-build-system)
      (arguments
       `(#:phases
         (modify-phases %standard-phases
           (replace 'check
             (lambda _
               (invoke "python" "-m" "robot" "-A"
                       "tests/conf/default.args" "tests"))))))
      (propagated-inputs
       `(("python-robotframework" ,python-robotframework)))
      (home-page "https://github.com/boakley/robotframework-lint/")
      (synopsis "Static analysis tool (linter) for Robot Framework")
      (description "This package provides the @code{rflint} command-line
utility, a static analysis tool (linter) for Robot Framework source files.")
      (license license:asl2.0))))

(define-public python-robotframework-sshlibrary
  (package
    (name "python-robotframework-sshlibrary")
    (version "3.3.0")
    ;; There are no tests in the PyPI archive.
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/robotframework/SSHLibrary.git")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32
         "1mk6dz2jqqndbx4yji09012q6rmadnqdywi7czvj62b0s07dr3r2"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'build 'build-and-install-doc
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((doc-output (assoc-ref outputs "doc"))
                    (doc (string-append doc-output "/share/"
                                        ,name "-" ,version "/")))
               (invoke "chmod" "-R" "+w" "docs")
               (invoke "invoke" "kw-docs" "project-docs")
               (mkdir-p doc)
               (for-each delete-file (find-files "docs" "\\.rst"))
               (copy-recursively "docs" doc)
               #t)))
         (replace 'check
           (lambda _
             ;; Some tests require an SSH server; we remove them.
             (delete-file "utest/test_client_api.py")
             (delete-file "utest/test_scp.py")
             (invoke "python" "utest/run.py"))))))
    (propagated-inputs
     `(("python-robotframework" ,python-robotframework)
       ("python-paramiko" ,python-paramiko)
       ("python-scp" ,python-scp)))
    (native-inputs
     `(("openssh" ,openssh)
       ("which" ,which)
       ;; To generate the documentation
       ("python-docutils" ,python-docutils)
       ("python-invoke" ,python-invoke)
       ("python-pygments" ,python-pygments)
       ("python-rellu" ,python-rellu)))
    (outputs '("out" "doc"))
    (home-page "https://github.com/robotframework/SSHLibrary")
    (synopsis "Robot Framework library for SSH and SFTP")
    (description "SSHLibrary is a Robot Framework library providing support
for SSH and SFTP.  It has the following main usages:
@itemize @bullet
@item Executing commands on the remote machine, either blocking or non-blocking.
@item Writing and reading in an interactive shell.
@item Transferring files and directories over SFTP.
@item Ensuring that files and directories exist on the remote machine.
@end itemize")
    (license license:asl2.0)))

(define-public python-scp
  (package
    (name "python-scp")
    (version "0.13.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "scp" version))
       (sha256
        (base32
         "1crlpw9lnn58fs1c1rmh7s7s9y5gkgpgjsqlvg9qa51kq1knx7gg"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f))                     ;tests require an SSH server
    (propagated-inputs
     `(("python-paramiko" ,python-paramiko)))
    (home-page "https://github.com/jbardin/scp.py")
    (synopsis "SCP protocol module for Python and Paramiko")
    (description "The scp module extends the Paramiko library to send and
receive files via the SCP1 protocol, as implemented by the OpenSSH
@command{scp} program.")
    (license license:gpl2+)))

(define-public python-rst.linker
  (package
    (name "python-rst.linker")
    (version "1.10")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "rst.linker" version))
       (sha256
        (base32
         "0iqaacp7pj1s8avs4kc0qg0r7dscywaq37y6l9j14glqdikk0wdj"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-dateutil" ,python-dateutil)
       ("python-six" ,python-six)))
    (native-inputs
     `(("python-setuptools-scm" ,python-setuptools-scm)))
    ;; Test would require path.py, which would introduce a cyclic dependence.
    (arguments `(#:tests? #f))
    ;; Note: As of version 1.7 the documentation is not worth building.
    (home-page "https://github.com/jaraco/rst.linker")
    (synopsis "Sphinx plugin to add links and timestamps")
    (description "rst.linker allows to automatically replace text by a
reStructuredText external reference or timestamps.  It's primary purpose is to
augment the changelog, but it can be used for other documents, too.")
    (license license:expat)))

(define-public python2-rst.linker
  (package-with-python2 python-rst.linker))

(define-public python-feedgenerator
  (package
    (name "python-feedgenerator")
    (version "1.9")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "feedgenerator" version))
       (sha256
        (base32
         "01mirwkm7xfx539hmvj7g9da1j51gw5lsx74dr0glizskjm5vq2s"))
       (modules '((guix build utils)))
       (snippet
        '(begin
           ;; Remove pre-compiled .pyc files from source.
           (for-each delete-file-recursively
                     (find-files "." "__pycache__" #:directories? #t))
           (for-each delete-file (find-files "." "\\.pyc$"))
           #t))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pytz" ,python-pytz)
       ("python-six" ,python-six)))
    (home-page "https://github.com/getpelican/feedgenerator")
    (synopsis
     "Standalone version of Django's Atom/RSS feed generator")
    (description
     "Feedgenerator-py3k is a standalone version of Django's feedgenerator,
which can produce feeds in RSS 2.0, RSS 0.91, and Atom formats.")
    (license license:bsd-3)))

(define-public python2-feedgenerator
  (package-with-python2 python-feedgenerator))

(define-public python-toml
  (package
    (name "python-toml")
    (version "0.9.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "toml" version))
       (sha256
        (base32
         "0bdbpbip67wdm6c7xwc6mmbmskyradj4cdxn1iibj4fcx1nbv1lf"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))                     ;no tests suite in release
    (home-page "https://github.com/uiri/toml")
    (synopsis "Library for TOML")
    (description
     "@code{toml} is a library for parsing and creating Tom's Obvious, Minimal
Language (TOML) configuration files.")
    (license license:expat)))

(define-public python-jsonrpc-server
  (package
    (name "python-jsonrpc-server")
    (version "0.1.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "python-jsonrpc-server" version))
       (sha256
        (base32
         "0m4ykpcdy52x37n1ikysp07j7p8ialcdvvvsrjp3545sn7iiid09"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-future" ,python-future)
       ("python-mock" ,python-mock)
       ("python-pytest" ,python-pytest)))
    (home-page
     "https://github.com/palantir/python-jsonrpc-server")
    (synopsis "JSON RPC 2.0 server library")
    (description
     "This package provides a JSON RPC 2.0 server library for Python.")
    (license license:expat)))

(define-public python-pydocstyle
  (package
    (name "python-pydocstyle")
    (version "3.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pydocstyle" version))
       (sha256
        (base32
         "1m1xv9clkg9lgzyza6dnj359z04vh5g0h49nhzghv7lg81gchhap"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-snowballstemmer" ,python-snowballstemmer)))
    (home-page
     "https://github.com/PyCQA/pydocstyle/")
    (synopsis "Python docstring style checker")
    (description
     "This package provides a style checker for the Python Language
Server (PLS).")
    (license license:expat)))

(define-public python-language-server
  (package
    (name "python-language-server")
    (version "0.26.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "python-language-server" version))
       (sha256
        (base32
         "1vs9ckfmm534n1hq3m871916wsjvi5h4gyj6wlzg13ck6506lx0s"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pluggy" ,python-pluggy)
       ("python-jsonrpc-server" ,python-jsonrpc-server)
       ("python-jedi" ,python-jedi)
       ("python-yapf" ,python-yapf)
       ("python-pyflakes" ,python-pyflakes)
       ("python-pydocstyle" ,python-pydocstyle)
       ("python-pycodestyle" ,python-pycodestyle)
       ("python-mccabe" ,python-mccabe)
       ("python-rope" ,python-rope)
       ("python-autopep8" ,python-autopep8)
       ("python-pylint" ,python-pylint)))
    (home-page "https://github.com/palantir/python-language-server")
    (synopsis "Python implementation of the Language Server Protocol")
    (description
     "The Python Language Server (pyls) is an implementation of the Python 3
language specification for the Language Server Protocol (LSP).  This tool is
used in text editing environments to provide a complete and integrated
feature-set for programming Python effectively.")
    (license license:expat)))

(define-public python-black
  (package
    (name "python-black")
    (version "18.6b4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "black" version))
       (sha256
        (base32
         "0i4sfqgz6w15vd50kbhi7g7rifgqlf8yfr8y78rypd56q64qn592"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'patch-source-shebangs 'patch-extra-shebangs
           (lambda _
             (let ((python3 (which "python3")))
               (substitute* '("tests/data/fmtonoff.py"
                              "tests/data/string_prefixes.py"
                              "tests/data/function.py")
                 (("#!/usr/bin/env python3(\\.[0-9]+)?" _ minor-version)
                  (string-append "#!" python3 (if (string? minor-version)
                                                  minor-version
                                                  ""))))))))))
    (propagated-inputs
     `(("python-click" ,python-click)
       ("python-attrs" ,python-attrs)
       ("python-appdirs" ,python-appdirs)
       ("python-toml" ,python-toml)))
    (home-page "https://github.com/ambv/black")
    (synopsis "The uncompromising code formatter")
    (description "Black is the uncompromising Python code formatter.")
    (license license:expat)))

(define-public python-blinker
  (package
    (name "python-blinker")
    (version "1.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "blinker" version))
       (sha256
        (base32
         "1dpq0vb01p36jjwbhhd08ylvrnyvcc82yxx3mwjx6awrycjyw6j7"))))
    (build-system python-build-system)
    (home-page "http://pythonhosted.org/blinker/")
    (synopsis "Fast, simple object-to-object and broadcast signaling")
    (description
     "Blinker provides a fast dispatching system that allows any number of
interested parties to subscribe to events, or \"signals\".")
    (license license:expat)))

(define-public python2-blinker
  (package-with-python2 python-blinker))

(define-public pelican
  (package
    (name "pelican")
    (version "4.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pelican" version))
       (sha256
        (base32
         "05yda7n6r0ll18fpdjzkzyr0ls8hbb86fnjyb33k9jvv5avah2lr"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-feedgenerator" ,python-feedgenerator)
       ("python-jinja2" ,python-jinja2)
       ("python-pygments" ,python-pygments)
       ("python-docutils" ,python-docutils)
       ("python-pytz" ,python-pytz)
       ("python-blinker" ,python-blinker)
       ("python-unidecode" ,python-unidecode)
       ("python-six" ,python-six)
       ("python-dateutil" ,python-dateutil)
       ("python-markdown" ,python-markdown)))
    (home-page "https://getpelican.com/")
    (arguments
     `(;; XXX Requires a lot more packages to do unit tests :P
       #:tests? #f
       #:phases (modify-phases %standard-phases
                  (add-before
                   'install 'adjust-requires
                   ;; Since feedgenerator is installed from git, it doesn't
                   ;; conform to the version requirements.
                   ;;
                   ;; We *do have* "feedgenerator >= 1.6", but strip off the
                   ;; version requirement so setuptools doesn't get confused.
                   (lambda _
                     (substitute* "setup.py"
                       (("['\"]feedgenerator.*?['\"]")
                        "'feedgenerator'")))))))
    (synopsis "Python-based static site publishing system")
    (description
     "Pelican is a tool to generate a static blog from reStructuredText,
Markdown input files, and more.  Pelican uses Jinja2 for templating
and is very extensible.")
    (license license:agpl3+)))

(define-public mallard-ducktype
  (package
    (name "mallard-ducktype")
    (version "1.0.2")
    (source
     (origin
       (method git-fetch)
       ;; git-reference because tests are not included in pypi source tarball
       ;; https://issues.guix.gnu.org/issue/36755#2
       (uri (git-reference
             (url "https://github.com/projectmallard/mallard-ducktype.git")
             (commit version)))
       (file-name (git-file-name name version))
       (sha256
        (base32
         "1jk9bfz7g04ip78s03b0xak6d54rj4h9zpgadkziy1ji216g6y4c"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (with-directory-excursion "tests"
               (invoke "sh" "runtests")))))))
    (home-page "http://projectmallard.org")
    (synopsis "Convert Ducktype to Mallard documentation markup")
    (description
     "Ducktype is a lightweight syntax that can represent all the semantics
of the Mallard XML documentation system.  Ducktype files can be converted to
Mallard using the @command{ducktype} tool.  The yelp-tools package
provides additional functionality on the produced Mallard documents.")
    (license license:expat)))

(define-public python-scikit-image
  (package
    (name "python-scikit-image")
    (version "0.14.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "scikit-image" version))
       (sha256
        (base32 "07qchljkyxvg5nrm12fvszi7pmjk4m01qp0w0z8syxzxxs20pz8s"))))
    (build-system python-build-system)
    (arguments
     ;; TODO: Some tests require running X11 server. Disable them?
     '(#:tests? #f))
    ;; See DEPENDS.txt for the list of build and run time requiremnts
    (propagated-inputs
     `(("python-cloudpickle" ,python-cloudpickle)
       ("python-dask" ,python-dask)
       ("python-matplotlib" ,python-matplotlib)
       ("python-networkx" ,python-networkx)
       ("python-numpy" ,python-numpy)
       ("python-pillow" ,python-pillow)
       ("python-pywavelets" ,python-pywavelets)
       ("python-scipy" ,python-scipy)
       ("python-six" ,python-six)))
    (native-inputs
     `(("python-cython" ,python-cython)))
    (home-page "http://scikit-image.org/")
    (synopsis "Image processing in Python")
    (description
     "Scikit-image is a collection of algorithms for image processing.")
    (license license:bsd-3)))

(define-public python2-scikit-image
  (package-with-python2 python-scikit-image))

(define-public python-cython
  (package
    (name "python-cython")
    (version "0.29.13")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Cython" version))
       (sha256
        (base32
         "13k37lrcgagwwnzr5bzririsscb793vndj234d475x1h9ad0d7f2"))))
    (build-system python-build-system)
    ;; we need the full python package and not just the python-wrapper
    ;; because we need libpython3.3m.so
    (inputs
     `(("python" ,python)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'set-HOME
           ;; some tests require access to "$HOME/.cython"
           (lambda _ (setenv "HOME" "/tmp") #t))

         ;; FIXME: These tests started failing on armhf after the 0.28 update
         ;; (commit c69d11c5930), both with an error such as this:
         ;;  compiling (cpp) and running dictcomp ...
         ;;  === C/C++ compiler error output: ===
         ;;  â€˜
         ;;  dictcomp.cpp:5221: confused by earlier errors, bailing out
         ;; See <https://hydra.gnu.org/build/2948724> for logs.
         ,@(if (target-arm32?)
               `((add-before 'check 'disable-failing-tests
                  (lambda _
                    (let ((disabled-tests (open-file "tests/bugs.txt" "a")))
                      (for-each (lambda (test)
                                  (format disabled-tests "~a\n" test))
                                '("memslice" "dictcomp"))
                      (close-port disabled-tests)))))
               '())

         (replace 'check
           (lambda _
             ;; Disable compiler optimizations to greatly reduce the running
             ;; time of the test suite.
             (setenv "CFLAGS" "-O0")

             (invoke "python" "runtests.py" "-vv"
                     "-j" (number->string (parallel-job-count))))))))
    (home-page "https://cython.org/")
    (synopsis "C extensions for Python")
    (description "Cython is an optimising static compiler for both the Python
programming language and the extended Cython programming language.  It makes
writing C extensions for Python as easy as Python itself.")
    (license license:asl2.0)
    (properties `((python2-variant . ,(delay python2-cython))))))

(define-public python2-cython
  (package (inherit (package-with-python2
                     (strip-python2-variant python-cython)))
    (name "python2-cython")
    (inputs
     `(("python-2" ,python-2))))) ; this is not automatically changed

;; The RPython toolchain currently does not support Python 3.
(define-public python2-rpython
  (package
    (name "python2-rpython")
    (version "0.2.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "rpython" version))
       (sha256
        (base32
         "02z9cvxf0y41dcvwnvf2zn0albhhw1drvjjbq27m6i1piw1k6fc0"))))
    (build-system python-build-system)
    (arguments `(#:python ,python-2))
    (native-inputs
     `(("python2-pytest" ,python2-pytest))) ; needed for running tests
    (home-page "https://rpython.readthedocs.org")
    (synopsis "Framework for implementing interpreters and virtual machines")
    (description "RPython is a translation and support framework for
producing implementations of dynamic languages, emphasizing a clean separation
between language specification and implementation aspects.")
    (license license:expat)))

;; NOTE: when upgrading numpy please make sure that python-pandas and
;; python-scipy still build, as these three packages are often used together.
(define-public python-numpy
  (package
    (name "python-numpy")
    (version "1.15.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/numpy/numpy/releases/download/v"
             version "/numpy-" version ".tar.gz"))
       (sha256
        (base32
         "102vcl2qq4pjbm7a3d67vkkvn4466ngia1d8wi5avqwqh8j0jvkn"))))
    (build-system python-build-system)
    (inputs
     `(("openblas" ,openblas)
       ("lapack" ,lapack)))
    (native-inputs
     `(("python-cython" ,python-cython)
       ("python-pytest" ,python-pytest)
       ("gfortran" ,gfortran)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'build 'configure-blas-lapack
           (lambda* (#:key inputs #:allow-other-keys)
             (call-with-output-file "site.cfg"
               (lambda (port)
                 (format port
                         "[openblas]
libraries = openblas
library_dirs = ~a/lib
include_dirs = ~a/include

# backslash-n to make emacs happy
\n[lapack]
lapack_libs = lapack
library_dirs = ~a/lib
include_dirs = ~a/include
"
                         (assoc-ref inputs "openblas")
                         (assoc-ref inputs "openblas")
                         (assoc-ref inputs "lapack")
                         (assoc-ref inputs "lapack"))))
             #t))
         (add-before 'build 'fix-executable-paths
           (lambda* (#:key inputs #:allow-other-keys)
             ;; Make /gnu/store/...-bash-.../bin/sh the default shell,
             ;; instead of /bin/sh.
             (substitute* "numpy/distutils/exec_command.py"
               (("(os.environ.get\\('SHELL', ')(/bin/sh'\\))" match match-start match-end)
                (string-append match-start (assoc-ref inputs "bash") match-end)))
             ;; Use "gcc" executable, not "cc".
             (substitute* "numpy/distutils/system_info.py"
               (("c = distutils\\.ccompiler\\.new_compiler\\(\\)")
                "c = distutils.ccompiler.new_compiler(); c.set_executables(compiler='gcc',compiler_so='gcc',linker_exe='gcc',linker_so='gcc -shared')"))
             #t))
         ;; Tests can only be run after the library has been installed and not
         ;; within the source directory.
         (delete 'check)
         (add-after 'install 'check
           (lambda* (#:key outputs inputs #:allow-other-keys)
             ;; Make installed package available for running the tests
             (add-installed-pythonpath inputs outputs)
             ;; Make sure "f2py" etc is found.
             (setenv "PATH" (string-append (assoc-ref outputs "out") "/bin"
                                           ":" (getenv "PATH")))
             (with-directory-excursion "/tmp"
               (invoke "python" "-c"
                       "import numpy; numpy.test(verbose=2)")))))))
    (home-page "http://www.numpy.org/")
    (synopsis "Fundamental package for scientific computing with Python")
    (description "NumPy is the fundamental package for scientific computing
with Python.  It contains among other things: a powerful N-dimensional array
object, sophisticated (broadcasting) functions, tools for integrating C/C++
and Fortran code, useful linear algebra, Fourier transform, and random number
capabilities.")
    (license license:bsd-3)))

(define-public python2-numpy
  (package-with-python2 python-numpy))

;; NOTE: NumPy 1.8 is packaged only for Python 2 because it is of
;; interest only for legacy code going back to NumPy's predecessor
;; Numeric.
(define-public python2-numpy-1.8
  (package (inherit python2-numpy)
    (version "1.8.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/numpy/numpy/archive/v" version ".tar.gz"))
       (file-name (string-append "python2-numpy-" version ".tar.gz"))
       (sha256
        (base32
         "0sc20gz1b17xnyrkp5frca3ql5qfalpv916hfg2kqxpwr6jg0f1g"))))
    (arguments
     (substitute-keyword-arguments (package-arguments python2-numpy)
       ((#:phases phases)
        `(modify-phases ,phases
           (replace 'configure-blas-lapack
             (lambda* (#:key inputs #:allow-other-keys)
               (call-with-output-file "site.cfg"
                 (lambda (port)
                   (format port
                           "[openblas]
libraries = openblas,lapack
library_dirs = ~a/lib:~a/lib
include_dirs = ~a/include:~a/include
"
                           (assoc-ref inputs "openblas")
                           (assoc-ref inputs "lapack")
                           (assoc-ref inputs "openblas")
                           (assoc-ref inputs "lapack"))))
               #t))))))
    (native-inputs
     `(("python2-nose" ,python2-nose)))
    (description "NumPy is the fundamental package for scientific computing
with Python.  It contains among other things: a powerful N-dimensional array
object, sophisticated (broadcasting) functions, tools for integrating C/C++
and Fortran code, useful linear algebra, Fourier transform, and random number
capabilities.  Version 1.8 is the last one to contain the numpy.oldnumeric API
that includes the compatibility layer numpy.oldnumeric with NumPy's predecessor
Numeric.")
    (license license:bsd-3)))

(define-public python-munch
  (package
    (name "python-munch")
    (version "2.0.4")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "munch" version))
        (sha256
         (base32
          "1cmqg91xnqx8gvnh4pmp0bfl1dfcm65d5p9mg73zz8pkjhx6h80l"))))
    (build-system python-build-system)
    (home-page "https://github.com/Infinidat/munch")
    (synopsis "Dot-accessible dictionary")
    (description "Munch is a dot-accessible dictionary similar to JavaScript
objects.")
    (license license:expat)))

(define-public python2-munch
  (package-with-python2 python-munch))

(define-public python-colormath
  (package
    (name "python-colormath")
    (version "3.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "colormath" version))
       (sha256
        (base32
         "05qjycgxp3p2f9n6lmic68sxmsyvgnnlyl4z9w7dl9s56jphaiix"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-networkx" ,python-networkx)
       ("python-numpy" ,python-numpy)))
    (home-page "https://github.com/gtaylor/python-colormath")
    (synopsis "Color math and conversion library")
    (description
     "This is a Python library for color math and conversions.")
    (license license:bsd-3)))

(define-public python2-colormath
  (package-with-python2 python-colormath))

(define-public python-spectra
  (package
    (name "python-spectra")
    (version "0.0.11")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "spectra" version))
       (sha256
        (base32
         "1f322x914bhkg6r5gv1vmnir3iy0k5kih0fd2gp3rdkw32jn5cwf"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _ (invoke "nosetests" "-v"))))))
    (propagated-inputs
     `(("python-colormath" ,python-colormath)))
    (native-inputs
     `(("python-nose" ,python-nose)))
    (home-page "https://github.com/jsvine/spectra")
    (synopsis "Color scales and color conversion")
    (description
     "This package provides a Python library intended to make color math,
color scales, and color space conversion easy.  It has support for:

@enumerate
@item Color scales
@item Color ranges
@item Color blending
@item Brightening/darkening colors
@item Saturating/desaturating colors
@item Conversion to/from multiple color spaces.
@end enumerate\n")
    (license license:expat)))

(define-public python2-spectra
  (package-with-python2 python-spectra))

(define-public python-numpy-documentation
  (package
    (name "python-numpy-documentation")
    (version (package-version python-numpy))
    (source (package-source python-numpy))
    (build-system python-build-system)
    (native-inputs
     `(("python-matplotlib" ,python-matplotlib)
       ("python-numpy" ,python-numpy)
       ("pkg-config" ,pkg-config)
       ("python-sphinx" ,python-sphinx)
       ("python-numpydoc" ,python-numpydoc)
       ("texlive" ,(texlive-union (list texlive-fonts-cm-super
                                        texlive-fonts-ec
                                        texlive-generic-ifxetex
                                        texlive-generic-pdftex
                                        texlive-amsfonts
                                        texlive-latex-capt-of
                                        texlive-latex-cmap
                                        texlive-latex-environ
                                        texlive-latex-eqparbox
                                        texlive-latex-etoolbox
                                        texlive-latex-expdlist
                                        texlive-latex-fancyhdr
                                        texlive-latex-fancyvrb
                                        texlive-latex-fncychap
                                        texlive-latex-float
                                        texlive-latex-framed
                                        texlive-latex-geometry
                                        texlive-latex-graphics
                                        texlive-latex-hyperref
                                        texlive-latex-mdwtools
                                        texlive-latex-multirow
                                        texlive-latex-needspace
                                        texlive-latex-oberdiek
                                        texlive-latex-parskip
                                        texlive-latex-preview
                                        texlive-latex-tabulary
                                        texlive-latex-threeparttable
                                        texlive-latex-titlesec
                                        texlive-latex-trimspaces
                                        texlive-latex-ucs
                                        texlive-latex-upquote
                                        texlive-latex-url
                                        texlive-latex-varwidth
                                        texlive-latex-wrapfig)))
       ("texinfo" ,texinfo)
       ("perl" ,perl)
       ("scipy-sphinx-theme"
        ,(origin ; The build script expects scipy-sphinx-theme as a git submodule
           (method git-fetch)
           (uri (git-reference
                 (url "https://github.com/scipy/scipy-sphinx-theme.git")
                 (commit "c466764e2231ba132c09826b5b138fffa1cfcec3")))
           (sha256
            (base32
             "0q2y87clwlsgc7wvlsn9pzyssybcq10plwhq2w1ydykfsyyqbmkl"))))
       ,@(package-native-inputs python-numpy)))
    (arguments
     `(#:tests? #f ; we're only generating the documentation
       #:phases
       (modify-phases %standard-phases
         (delete 'build)
         (replace 'install
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((data (string-append (assoc-ref outputs "out") "/share"))
                    (doc (string-append
                          data "/doc/" ,name "-"
                          ,(package-version python-numpy)))
                    (info-reader (string-append data "/info"))
                    (html (string-append doc "/html"))
                    (scipy-sphinx-theme "scipy-sphinx-theme")
                    (sphinx-theme-checkout (assoc-ref inputs scipy-sphinx-theme))
                    (pyver ,(string-append "PYVER=")))

               ;; FIXME: this is needed to for texlive-union to generate
               ;; fonts, which are not found.
               (setenv "HOME" "/tmp")

               (with-directory-excursion "doc"
                 (copy-recursively sphinx-theme-checkout scipy-sphinx-theme)
                 (mkdir-p html)
                 (invoke "make" "html" pyver)
                 (invoke "make" "latex" "PAPER=a4" pyver)
                 (invoke "make" "-C" "build/latex"
                          "all-pdf" "PAPER=a4" pyver)
                 ;; FIXME: Generation of the info file fails.
                 ;; (invoke "make" "info" pyver)
                 ;; (mkdir-p info)
                 ;; (copy-file "build/texinfo/numpy.info"
                 ;;            (string-append info "/numpy.info"))
                 (for-each (lambda (file)
                             (copy-file (string-append "build/latex" file)
                                        (string-append doc file)))
                           '("/numpy-ref.pdf" "/numpy-user.pdf"))
                 (with-directory-excursion "build/html"
                   (for-each (lambda (file)
                               (let* ((dir (dirname file))
                                      (tgt-dir (string-append html "/" dir)))
                                 (unless (equal? "." dir)
                                   (mkdir-p tgt-dir))
                                 (install-file file html)))
                             (find-files "." ".*")))))
             #t)))))
    (home-page (package-home-page python-numpy))
    (synopsis "Documentation for the python-numpy package")
    (description (package-description python-numpy))
    (license (package-license python-numpy))))

(define-public python2-numpy-documentation
  (let ((numpy-documentation (package-with-python2 python-numpy-documentation)))
    (package
      (inherit numpy-documentation)
      (native-inputs `(("python2-functools32" ,python2-functools32)
                       ,@(package-native-inputs numpy-documentation))))))

(define-public python-pygit2
  (package
    (name "python-pygit2")
    (version "0.28.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pygit2" version))
       (sha256
        (base32 "11kzj5mjkspvplnpdb6bj8dcj6rgmkk986k8hjcklyg5yaxkz32d"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f))            ; tests don't run correctly in our environment
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-cffi" ,python-cffi)
       ("libgit2" ,libgit2)
       ("python-tox" ,python-tox)))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/libgit2/pygit2")
    (synopsis "Python bindings for libgit2")
    (description "Pygit2 is a set of Python bindings to the libgit2 shared
library, libgit2 implements Git plumbing.")
    ;; GPL2.0 only, with linking exception.
    (license license:gpl2)))

(define-public python2-pygit2
  (package-with-python2 python-pygit2))

(define-public python-pyparsing
  (package
    (name "python-pyparsing")
    (version "2.3.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyparsing" version))
       (sha256
        (base32 "0yk6xl885b91dmlhlsap7x78hk2rdr879fln9anbq6k4ca42djb6"))))
    (build-system python-build-system)
    (outputs '("out" "doc"))
    (arguments
     `(#:tests? #f ; no test target
       #:phases
       (modify-phases %standard-phases
         (add-after 'install 'install-doc
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((doc (string-append (assoc-ref outputs "doc")
                                        "/share/doc/" ,name "-" ,version))
                    (html-doc (string-append doc "/html"))
                    (examples (string-append doc "/examples")))
               (mkdir-p html-doc)
               (mkdir-p examples)
               (for-each
                (lambda (dir tgt)
                  (map (lambda (file)
                         (install-file file tgt))
                       (find-files dir ".*")))
                (list "docs" "htmldoc" "examples")
                (list doc html-doc examples))
               #t))))))
    (home-page "https://github.com/pyparsing/pyparsing")
    (synopsis "Python parsing class library")
    (description
     "The pyparsing module is an alternative approach to creating and
executing simple grammars, vs. the traditional lex/yacc approach, or the use
of regular expressions.  The pyparsing module provides a library of classes
that client code uses to construct the grammar directly in Python code.")
    (license license:expat)))

(define-public python2-pyparsing
  (package-with-python2 python-pyparsing))

(define-public python-numpydoc
  (package
    (name "python-numpydoc")
    (version "0.8.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "numpydoc" version))
       (sha256
        (base32
         "1zazxg3m8j4fksv3f7v7vpf4bj9qb1vj3r326am0vdip141vzx31"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-sphinx" ,python-sphinx)))
    (native-inputs
     `(("python-nose" ,python-nose)))
    (home-page "https://pypi.python.org/pypi/numpydoc")
    (synopsis
     "Numpy's Sphinx extensions")
    (description
     "Sphinx extension to support docstrings in Numpy format.")
    (license license:bsd-2)))

(define-public python2-numpydoc
  (package-with-python2 python-numpydoc))

(define-public python-numexpr
  (package
    (name "python-numexpr")
    (version "2.6.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "numexpr" version))
       (sha256
        (base32
         "1frnbcwmsi312154x274xl28xazr1k8vjby83fwyla2n10a81bgq"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f))          ; no tests included
    (propagated-inputs
     `(("python-numpy" ,python-numpy)))
    (home-page "https://github.com/pydata/numexpr")
    (synopsis "Fast numerical expression evaluator for NumPy")
    (description
     "Numexpr is a fast numerical expression evaluator for NumPy.  With it,
expressions that operate on arrays are accelerated and use less memory than
doing the same calculation in Python.  In addition, its multi-threaded
capabilities can make use of all your cores, which may accelerate
computations, most specially if they are not memory-bounded (e.g. those using
transcendental functions).")
    (license license:expat)))

(define-public python2-numexpr
  (package-with-python2 python-numexpr))

(define-public python-cycler
  (package
    (name "python-cycler")
    (version "0.10.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "cycler" version))
              (sha256
               (base32
                "1n69n23fak1gjxlrbhqisi2b9pv3ckrfj98llx3p53953082syyd"))))
    (build-system python-build-system)
    (arguments
     ;; XXX: The current version requires 'coveralls' which we don't have.
     ;; Enable this for the next release which uses 'python-pytest'.
     '(#:tests? #f))
    (propagated-inputs
     `(("python-six" ,python-six)))
    (home-page "http://matplotlib.org/cycler/")
    (synopsis "Composable keyword argument iterator")
    (description
     "When using @code{matplotlib} and plotting more than one line, it is
common to want to be able to want to be able to cycle over one or more artist
styles; but the plotting logic can quickly become involved.
To address this and enable easy cycling over arbitrary @code{kwargs}, the
@code{Cycler} class was developed.")
    (license license:bsd-3)))

(define-public python2-cycler
  (package-with-python2 python-cycler))

(define-public python-colorspacious
  (package
    (name "python-colorspacious")
    (version "1.1.0")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/njsmith/colorspacious.git")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32 "0g0lxqiscy5g5rq9421vv7abg0c90jzy0zmas2z3hya6k2dr5aid"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-numpy" ,python-numpy)))
    (native-inputs
     `(("python-nose" ,python-nose)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (invoke "nosetests" "--all-modules" "-v" "colorspacious"))))))
    (home-page "https://github.com/njsmith/colorspacious")
    (synopsis "Python library for colorspace conversions")
    (description "@code{colorspacious} is a Python library that lets you
convert between colorspaces like sRGB, XYZ, CIEL*a*b*, CIECAM02, CAM02-UCS, etc.")
    (license license:expat)))

(define-public python2-colorspacious
  (package-with-python2 python-colorspacious))

(define-public python-matplotlib
  (package
    (name "python-matplotlib")
    (version "2.2.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "matplotlib" version))
       (sha256
        (base32
         "1rcc7x9ig3hpchkc4cwdvym3y451w74275fxr455zkfagrsvymbk"))))
    (build-system python-build-system)
    (propagated-inputs ; the following packages are all needed at run time
     `(("python-cycler" ,python-cycler)
       ("python-kiwisolver" ,python-kiwisolver)
       ("python-pyparsing" ,python-pyparsing)
       ("python-pygobject" ,python-pygobject)
       ("gobject-introspection" ,gobject-introspection)
       ("python-tkinter" ,python "tk")
       ("python-dateutil" ,python-dateutil)
       ("python-numpy" ,python-numpy)
       ("python-pillow" ,python-pillow)
       ("python-pytz" ,python-pytz)
       ("python-six" ,python-six)
       ;; From version 1.4.0 'matplotlib' makes use of 'cairocffi' instead of
       ;; 'pycairo'. However, 'pygobject' makes use of a 'pycairo' 'context'
       ;; object. For this reason we need to import both libraries.
       ;; https://pythonhosted.org/cairocffi/cffi_api.html#converting-pycairo
       ("python-pycairo" ,python-pycairo)
       ("python-cairocffi" ,python-cairocffi)))
    (inputs
     `(("libpng" ,libpng)
       ("imagemagick" ,imagemagick)
       ("freetype" ,freetype)
       ("cairo" ,cairo)
       ("glib" ,glib)
       ;; FIXME: Add backends when available.
       ;("python-wxpython" ,python-wxpython)
       ("tcl" ,tcl)
       ("tk" ,tk)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-nose" ,python-nose)
       ("python-mock" ,python-mock)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'build 'configure-environment
           (lambda* (#:key outputs inputs #:allow-other-keys)
             (let ((cairo (assoc-ref inputs "cairo")))
               ;; Setting this directory in the 'basedirlist' of 'setup.cfg'
               ;; has not effect.
               (setenv "LD_LIBRARY_PATH" (string-append cairo "/lib"))
               (setenv "HOME" (getcwd))
               (call-with-output-file "setup.cfg"
                 (lambda (port)
                   (format port "[directories]~%
basedirlist = ~a,~a~%
 [rc_options]~%
backend = TkAgg~%"
                        (assoc-ref inputs "tcl")
                        (assoc-ref inputs "tk")))))
             #t)))))
    (home-page "http://matplotlib.org")
    (synopsis "2D plotting library for Python")
    (description
     "Matplotlib is a Python 2D plotting library which produces publication
quality figures in a variety of hardcopy formats and interactive environments
across platforms.  Matplotlib can be used in Python scripts, the python and
ipython shell, web application servers, and six graphical user interface
toolkits.")
    (license license:psfl)
    (properties `((python2-variant . ,(delay python2-matplotlib))))))

(define-public python2-matplotlib
  (let ((matplotlib (package-with-python2
                     (strip-python2-variant python-matplotlib))))
    (package (inherit matplotlib)
      ;; Make sure to use special packages for Python 2 instead
      ;; of those automatically rewritten by package-with-python2.
      (propagated-inputs
       `(("python2-pycairo" ,python2-pycairo)
         ("python2-backports-functools-lru-cache"
          ,python2-backports-functools-lru-cache)
         ("python2-functools32" ,python2-functools32)
         ("python2-pygobject-2" ,python2-pygobject-2)
         ("python2-subprocess32" ,python2-subprocess32)
         ("python2-tkinter" ,python-2 "tk")
         ,@(fold alist-delete (package-propagated-inputs matplotlib)
                 '("python-pycairo" "python-pygobject" "python-tkinter")))))))

(define-public python-matplotlib-documentation
  (package
    (name "python-matplotlib-documentation")
    (version (package-version python-matplotlib))
    (source (package-source python-matplotlib))
    (build-system python-build-system)
    (native-inputs
     `(("python-matplotlib" ,python-matplotlib)
       ("python-colorspacious" ,python-colorspacious)
       ("python-sphinx" ,python-sphinx)
       ("python-sphinx-gallery" ,python-sphinx-gallery)
       ("python-numpydoc" ,python-numpydoc)
       ("python-ipython" ,python-ipython)
       ("python-ipykernel" ,python-ipykernel)
       ("python-mock" ,python-mock)
       ("graphviz" ,graphviz)
       ("texlive" ,(texlive-union (list texlive-amsfonts
                                        texlive-latex-amsmath
                                        texlive-latex-enumitem
                                        texlive-latex-expdlist
                                        texlive-latex-geometry
                                        texlive-latex-preview
                                        texlive-latex-type1cm
                                        texlive-latex-ucs

                                        texlive-generic-pdftex

                                        texlive-fonts-ec
                                        texlive-fonts-adobe-times
                                        texlive-fonts-txfonts)))
       ("texinfo" ,texinfo)
       ,@(package-native-inputs python-matplotlib)))
    (arguments
     `(#:tests? #f ; we're only generating documentation
       #:phases
       (modify-phases %standard-phases
         (replace 'build
           (lambda _
             (chdir "doc")
             (setenv "PYTHONPATH"
                     (string-append (getenv "PYTHONPATH")
                                    ":" (getcwd) "/../examples/units"))
             (substitute* "conf.py"
               ;; Don't use git.
               (("^SHA = check_output.*")
                (string-append "SHA = \"" ,version "\"\n"))
               ;; Don't fetch intersphinx files from the Internet
               (("^explicit_order_folders" m)
                (string-append "intersphinx_mapping = {}\n" m))
               (("'sphinx.ext.intersphinx',") "")
               ;; Disable URL embedding which requires internet access.
               (("'https://docs.scipy.org/doc/numpy'") "None")
               (("'https://docs.scipy.org/doc/scipy/reference'") "None"))
             (invoke "make"
                     "SPHINXBUILD=sphinx-build"
                     "SPHINXOPTS=" ; don't abort on warnings
                     "html" "texinfo")))
         (replace 'install
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((data (string-append (assoc-ref outputs "out") "/share"))
                    (doc (string-append data "/doc/python-matplotlib-" ,version))
                    (info (string-append data "/info"))
                    (html (string-append doc "/html")))
               (mkdir-p html)
               (mkdir-p info)
               (copy-recursively "build/html" html)
               (symlink (string-append html "/_images")
                        (string-append info "/matplotlib-figures"))
               (with-directory-excursion "build/texinfo"
                 (substitute* "matplotlib.texi"
                   (("@image\\{([^,]*)" all file)
                    (string-append "@image{matplotlib-figures/" file)))
                 (symlink (string-append html "/_images")
                          "./matplotlib-figures")
                 (invoke "makeinfo" "--no-split"
                         "-o" "matplotlib.info" "matplotlib.texi"))
               (install-file "build/texinfo/matplotlib.info" info))
             #t)))))
    (home-page (package-home-page python-matplotlib))
    (synopsis "Documentation for the python-matplotlib package")
    (description (package-description python-matplotlib))
    (license (package-license python-matplotlib))))

(define-public python2-matplotlib-documentation
  (package-with-python2 python-matplotlib-documentation))

(define-public python-matplotlib-venn
  (package
    (name "python-matplotlib-venn")
    (version "0.11.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "matplotlib-venn" version ".zip"))
       (sha256
        (base32
         "13w3i1wih0mij08hrgppzg0g9z50y54rc28l6gdi1r5w45l7l0dy"))))
    (build-system python-build-system)
    (arguments '(#:tests? #f)) ; tests are not included
    (propagated-inputs
     `(("python-matplotlib" ,python-matplotlib)
       ("python-numpy" ,python-numpy)
       ("python-scipy" ,python-scipy)))
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page "https://github.com/konstantint/matplotlib-venn")
    (synopsis "Plot area-proportional Venn diagrams")
    (description
     "This package provides tools for plotting area-proportional two- and
three-way Venn diagrams in @code{matplotlib}.")
    (license license:expat)))

(define-public python2-pysnptools
  (package
    (name "python2-pysnptools")
    (version "0.3.13")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pysnptools" version))
       (sha256
        (base32
         "0lnis5xsl7bi0hz4f7gbicahzi5zlxkc21nk3g374xv8fb5hb3qm"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2 ; only Python 2.7 is supported
       #:tests? #f))      ; test files (e.g. examples/toydata.bim) not included
    (propagated-inputs
     `(("python2-numpy" ,python2-numpy)
       ("python2-scipy" ,python2-scipy)
       ("python2-pandas" ,python2-pandas)))
    (native-inputs
     `(("python2-cython" ,python2-cython)))
    (home-page "http://microsoftgenomics.github.io/PySnpTools/")
    (synopsis "Library for reading and manipulating genetic data")
    (description
     "PySnpTools is a library for reading and manipulating genetic data.  It
can, for example, efficiently read whole PLINK *.bed/bim/fam files or parts of
those files.  It can also efficiently manipulate ranges of integers using set
operators such as union, intersection, and difference.")
    (license license:asl2.0)))

(define-public python-scipy
  (package
    (name "python-scipy")
    (version "1.2.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "scipy" version))
       (sha256
        (base32
         "1cgvgin8fvckv96hjh3ikmwkra5rif51bdb75ifzf7xbil5iwcx4"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-matplotlib" ,python-matplotlib)
       ("python-pyparsing" ,python-pyparsing)))
    (inputs
     `(("lapack" ,lapack)
       ("openblas" ,openblas)))
    (native-inputs
     `(("python-cython" ,python-cython)
       ("python-pytest" ,python-pytest)
       ("python-sphinx" ,python-sphinx)
       ("python-numpydoc" ,python-numpydoc)
       ("gfortran" ,gfortran)
       ("perl" ,perl)
       ("which" ,which)))
    (outputs '("out" "doc"))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'disable-broken-tests
           (lambda _
             (substitute* "scipy/sparse/linalg/dsolve/tests/test_linsolve.py"
               (("^( +)def test_threads_parallel\\(self\\):" m indent)
                (string-append indent
                               "@pytest.mark.skip(reason=\"Disabled by Guix\")\n"
                               m)))
             (substitute* "scipy/sparse/linalg/eigen/arpack/tests/test_arpack.py"
               (("^def test_parallel_threads\\(\\):" m)
                (string-append "@pytest.mark.skip(reason=\"Disabled by Guix\")\n"
                               m)))
             #t))
         (add-before 'build 'configure-openblas
           (lambda* (#:key inputs #:allow-other-keys)
             (call-with-output-file "site.cfg"
               (lambda (port)
                 (format port
                         "[blas]
libraries = openblas
library_dirs = ~a/lib
include_dirs = ~a/include

# backslash-n to make emacs happy
\n[atlas]
library_dirs = ~a/lib
atlas_libs = openblas
"
                         (assoc-ref inputs "openblas")
                         (assoc-ref inputs "openblas")
                         (assoc-ref inputs "openblas"))))
             #t))
         (add-after 'install 'install-doc
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                    (doc (string-append data "/doc/" ,name "-" ,version))
                    (html (string-append doc "/html"))
                    (pyver ,(string-append "PYVER=" (version-major+minor
                                                     (package-version python))))
                    ;; By default it tries to run sphinx-build through the Python
                    ;; interpreter which won't work with our shell wrapper.
                    (sphinxbuild "SPHINXBUILD=LANG=C sphinx-build"))
               ;; Make installed package available for building the
               ;; documentation
               (add-installed-pythonpath inputs outputs)
               (with-directory-excursion "doc"
                 ;; Fix generation of images for mathematical expressions.
                 (substitute* (find-files "source" "conf\\.py")
                   (("pngmath_use_preview = True")
                    "pngmath_use_preview = False"))
                 (mkdir-p html)
                 (invoke "make" "html" pyver sphinxbuild)
                 (with-directory-excursion "build/html"
                   (for-each (lambda (file)
                               (let* ((dir (dirname file))
                                      (tgt-dir (string-append html "/" dir)))
                                 (install-file file html)))
                             (find-files "." ".*")))))
             #t))
         ;; Tests can only be run after the library has been installed and not
         ;; within the source directory.
         (delete 'check)
         (add-after 'install 'check
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (add-installed-pythonpath inputs outputs)
             (with-directory-excursion "/tmp"
               (invoke "python" "-c"
                       "import scipy; scipy.test(verbose=2)")))))))
    (home-page "https://www.scipy.org/")
    (synopsis "The Scipy library provides efficient numerical routines")
    (description "The SciPy library is one of the core packages that make up
the SciPy stack.  It provides many user-friendly and efficient numerical
routines such as routines for numerical integration and optimization.")
    (properties `((python2-variant . ,(delay python2-scipy))))
    (license license:bsd-3)))

(define-public python2-scipy
  (package-with-python2
   (strip-python2-variant python-scipy)))

(define-public python-socksipy-branch
  (package
    (name "python-socksipy-branch")
    (version "1.01")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "SocksiPy-branch" version))
       (sha256
        (base32
         "01l41v4g7fy9fzvinmjxy6zcbhgqaif8dhdqm4w90fwcw9h51a8p"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f)) ; There are no tests
    (home-page "https://code.google.com/archive/p/socksipy-branch/")
    (synopsis "Python SOCKS module")
    (description
     "SocksiPy - A Python SOCKS client module.  It provides a
socket-like interface that supports connections to any TCP
service through the use of a SOCKS4, SOCKS5 or HTTP proxy.
The original version was developed by Dan Haim, this is a
branch created by Mario Vilas to address some open issues,
as the original project seems to have been abandoned circa 2007.")
    (license license:bsd-3)))

(define-public python2-socksipy-branch
  (package-with-python2 python-socksipy-branch))

(define-public python-pycodestyle
  (package
    (name "python-pycodestyle")
    (version "2.4.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pycodestyle" version))
        (sha256
          (base32
            "0fhy4vnlgpjq4qd1wdnl6pvdw7rah0ypmn8c9mkhz8clsndskz6b"))))
    (build-system python-build-system)
    (home-page "https://pycodestyle.readthedocs.io/")
    (synopsis "Python style guide checker")
    (description "@code{pycodestyle} (formerly pep8) is a tool to check
Python code against some of the style conventions in
@url{http://www.python.org/dev/peps/pep-0008/,PEP 8}.")
    (license license:expat)))

(define-public python2-pycodestyle
  (package-with-python2 python-pycodestyle))

(define-public python-multidict
  (package
    (name "python-multidict")
    (version "4.2.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "multidict" version))
       (sha256
        (base32
         "1vf5bq8hn5a9rvhr5v4fwbmarfsp35hhr8gs74kqfijy34j2f194"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)))
    (home-page "https://github.com/aio-libs/multidict/")
    (synopsis "Multidict implementation")
    (description "Multidict is dict-like collection of key-value pairs
where key might be occurred more than once in the container.")
    (license license:asl2.0)))

(define-public python-orderedmultidict
  (package
    (name "python-orderedmultidict")
    (version "0.7.11")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "orderedmultidict" version))
        (sha256
          (base32
            "0dls862ibm7qbq4fnvwx0xn1v9hwyzywbff8xjjdr42dd75208yw"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-tests
           (lambda _
             ;; The package uses nosetest for running the tests.
             ;; Adding this initfile allows to run the test suite
             ;; without requiring nosetest.
             (with-output-to-file "tests/__init__.py" newline)
             #t)))))
    (propagated-inputs
     `(("python-six" ,python-six)))
    (native-inputs
     `(("python-pycodestyle" ,python-pycodestyle)))
    (home-page "https://github.com/gruns/orderedmultidict")
    (synopsis "Python Ordered Multivalue Dictionary - omdict")
    (description "This package contains a library for ordered multivalue
dictionaries.  A multivalue dictionary is a dictionary that can store
multiple values for the same key.  An ordered multivalue dictionary is a
multivalue dictionary that retains the order of insertions and deletions.")
    (license license:unlicense)))

(define-public python2-orderedmultidict
  (package-with-python2 python-orderedmultidict))

(define-public python-autopep8
  (package
    (name "python-autopep8")
    (version "1.3.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "autopep8" version))
       (sha256
        (base32
         "192bvhzi4d0claqxgzymvv7k3qnj627742bc8sgxpzjj42pd9112"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pycodestyle" ,python-pycodestyle)))
    (home-page "https://github.com/hhatto/autopep8")
    (synopsis "Format Python code according to the PEP 8 style guide")
    (description
     "@code{autopep8} automatically formats Python code to conform to
the PEP 8 style guide.  It uses the pycodestyle utility to determine
what parts of the code needs to be formatted.  @code{autopep8} is
capable of fixing most of the formatting issues that can be reported
by pycodestyle.")
    (license (license:non-copyleft
              "https://github.com/hhatto/autopep8/blob/master/LICENSE"))))

(define-public python2-autopep8
  (package-with-python2 python-autopep8))

(define-public python-distutils-extra
  (package
    (name "python-distutils-extra")
    (version "2.38")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://launchpad.net/python-distutils-extra/trunk/"
                          version "/+download/python-distutils-extra-"
                          version ".tar.gz"))
      (sha256
       (base32
        "0lx15kcbby9zisx33p2h5hgakgwh2bvh0ibag8z0px4j6ifhs41x"))))
    (build-system python-build-system)
    (home-page "https://launchpad.net/python-distutils-extra/")
    (synopsis "Enhancements to Python's distutils")
    (description
     "The python-distutils-extra module enables you to easily integrate
gettext support, themed icons, and scrollkeeper-based documentation into
Python's distutils.")
    (license license:gpl2)))

(define-public python2-distutils-extra
  (package-with-python2 python-distutils-extra))

(define-public python2-elib.intl
  (package
    (name "python2-elib.intl")
    (version "0.0.3")
    (source
     (origin
       ;; This project doesn't tag releases or publish tarballs, so we take
       ;; source from a (semi-arbitrary, i.e. latest as of now) git commit.
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/dieterv/elib.intl.git")
             (commit "d09997cfef")))
       (file-name (string-append name "-" version "-checkout"))
       (sha256
        (base32
         "0y7vzff9xgbnaay7m0va1arl6g68ncwrvbgwl7jqlclsahzzb09d"))))
    (build-system python-build-system)
    (arguments
     ;; incompatible with Python 3 (exception syntax)
     `(#:python ,python-2
       #:tests? #f))
    (home-page "https://github.com/dieterv/elib.intl")
    (synopsis "Enhanced internationalization for Python")
    (description
     "The elib.intl module provides enhanced internationalization (I18N)
services for your Python modules and applications.")
    (license license:lgpl3+)))

(define-public python-olefile
  (package
    (name "python-olefile")
    (version "0.46")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/decalage2/olefile/releases/"
                           "download/v" version "/olefile-" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1kjxh4gr651hpqkjfv89cfzr40hyvf3vjlda7mifiail83j7j07m"))))
    (build-system python-build-system)
    (home-page "https://www.decalage.info/python/olefileio")
    (synopsis "Read and write Microsoft OLE2 files.")
    (description
     "@code{olefile} can parse, read and write Microsoft OLE2 files (Structured
Storage or Compound Document, Microsoft Office).  It is an improved version of
the OleFileIO module from PIL, the Python Image Library.")
    (license license:bsd-3)))

(define-public python2-olefile
  (package-with-python2 python-olefile))

(define-public python-pillow
  (package
    (name "python-pillow")
    (version "5.4.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Pillow" version))
       (sha256
        (base32
         "17waygkhhzjd75kajlfw9v57mbb41lcpg6cvkdijqd7smm76ccsj"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (inputs
     `(("freetype" ,freetype)
       ("lcms"     ,lcms)
       ("zlib"     ,zlib)
       ("libjpeg"  ,libjpeg)
       ("openjpeg" ,openjpeg)
       ("libtiff"  ,libtiff)
       ("libwebp"  ,libwebp)))
    (propagated-inputs
     `(("python-olefile" ,python-olefile)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-ldconfig
           (lambda _
             (substitute* "setup.py"
               (("\\['/sbin/ldconfig', '-p'\\]") "['true']"))))
         (delete 'check) ; We must run checks after python-pillow is installed.
         (add-after 'install 'check-installed
           (lambda* (#:key outputs inputs #:allow-other-keys)
             (begin
               (setenv "HOME" (getcwd))
               ;; Make installed package available for running the tests.
               (add-installed-pythonpath inputs outputs)
               (invoke "python" "selftest.py" "--installed")
               (invoke "python" "-m" "pytest" "-vv")))))))
    (home-page "https://python-pillow.org")
    (synopsis "Fork of the Python Imaging Library")
    (description
     "The Python Imaging Library adds image processing capabilities to your
Python interpreter.  This library provides extensive file format support, an
efficient internal representation, and fairly powerful image processing
capabilities.  The core image library is designed for fast access to data
stored in a few basic pixel formats.  It should provide a solid foundation for
a general image processing tool.")
    (license (license:x11-style
              "http://www.pythonware.com/products/pil/license.htm"
              "The PIL Software License"))))

(define-public python2-pillow
  (package-with-python2 python-pillow))

(define-public python-pycparser
  (package
    (name "python-pycparser")
    (version "2.19")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "pycparser" version))
      (sha256
       (base32
        "1cr5dcj9628lkz1qlwq3fv97c25363qppkmcayqvd05dpy573259"))))
    (outputs '("out" "doc"))
    (build-system python-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (with-directory-excursion "tests"
               (invoke "python" "all_tests.py"))
             #t))
         (add-after 'install 'install-doc
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                    (doc (string-append data "/doc/" ,name "-" ,version))
                    (examples (string-append doc "/examples")))
               (mkdir-p examples)
               (for-each (lambda (file)
                           (copy-file (string-append "." file)
                                      (string-append doc file)))
                         '("/README.rst" "/CHANGES" "/LICENSE"))
               (copy-recursively "examples" examples)
               #t))))))
    (home-page "https://github.com/eliben/pycparser")
    (synopsis "C parser in Python")
    (description
     "Pycparser is a complete parser of the C language, written in pure Python
using the PLY parsing library.  It parses C code into an AST and can serve as
a front-end for C compilers or analysis tools.")
    (license license:bsd-3)))

(define-public python2-pycparser
  (package-with-python2 python-pycparser))

(define-public python-pywavelets
  (package
    (name "python-pywavelets")
    (version "1.0.1")
    (home-page "https://github.com/PyWavelets/pywt")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "PyWavelets" version))
              (sha256
               (base32
                "1p3qv2v66ghnqrb1f98wyyhp9dz71jwcd6kfpsax65sfdpiyqp1w"))))
    (build-system python-build-system)
    (arguments
     '(#:modules ((ice-9 ftw)
                  (srfi srfi-1)
                  (srfi srfi-26)
                  (guix build utils)
                  (guix build python-build-system))
       #:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      (let ((cwd (getcwd))
                            (libdir (find (cut string-prefix? "lib." <>)
                                          (scandir "build"))))
                      (with-directory-excursion (string-append cwd "/build/" libdir)
                        (invoke "nosetests" "-v" "."))))))))
    (native-inputs
     `(("python-matplotlib" ,python-matplotlib)          ;for tests
       ("python-nose" ,python-nose)))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)))
    (synopsis "Wavelet transforms in Python")
    (description
     "PyWavelets is a library for wavelet transforms in Python.  Wavelets are
mathematical basis functions that are localized in both time and frequency.
Wavelet transforms are time-frequency transforms employing wavelets.  They are
similar to Fourier transforms, the difference being that Fourier transforms are
localized only in frequency instead of in time and frequency.")
    (license license:expat)))

(define-public python2-pywavelets
  (package-with-python2 python-pywavelets))

(define-public python-xcffib
  (package
    (name "python-xcffib")
    (version "0.6.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "xcffib" version))
      (sha256
       (base32
        "04k91yxyb3pgc5lvxmivh8w71yjrap2g57yk3s73x4rm4nvjq51n"))))
    (build-system python-build-system)
    (inputs
     `(("libxcb" ,libxcb)))
    (propagated-inputs
     `(("python-cffi" ,python-cffi) ; used at run time
       ("python-six" ,python-six)))
    (arguments
     `(;; FIXME: Tests need more work. See ".travis.yml" in the repository.
       #:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-libxcb-path
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((libxcb (assoc-ref inputs "libxcb")))
               (substitute* '("xcffib/__init__.py")
                 (("^soname = \"") (string-append "soname = \"" libxcb "/lib/")))
               #t)))
         (add-after 'install 'install-doc
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((doc (string-append (assoc-ref outputs "out") "/share"
                                       "/doc/" ,name "-" ,version)))
               (mkdir-p doc)
               (copy-file "README.md"
                          (string-append doc "/README.md"))
               #t))))))
    (home-page "https://github.com/tych0/xcffib")
    (synopsis "XCB Python bindings")
    (description
     "Xcffib is a replacement for xpyb, an XCB Python bindings.  It adds
support for Python 3 and PyPy.  It is based on cffi.")
    (license license:expat)))

(define-public python2-xcffib
  (package-with-python2 python-xcffib))

(define-public python-cairocffi
  (package
    (name "python-cairocffi")
    (version "0.9.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "cairocffi" version))
      (sha256
       (base32
        "0dq3k4zhqd8cwsf3nyjqvjqm8wkvrjn1wjf44rl3v0h8kqx6qf0m"))
      (patches (search-patches "python-cairocffi-dlopen-path.patch"))))
    (build-system python-build-system)
    (outputs '("out" "doc"))
    (inputs
     `(("glib" ,glib)
       ("gtk+" ,gtk+)
       ("gdk-pixbuf" ,gdk-pixbuf)
       ("cairo" ,cairo)
       ("pango" ,pango)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-pytest-runner" ,python-pytest-runner)
       ("python-sphinx" ,python-sphinx)
       ("python-docutils" ,python-docutils)))
    (propagated-inputs
     `(("python-xcffib" ,python-xcffib))) ; used at run time
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-paths
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (substitute* (find-files "." "\\.py$")
              (("dlopen\\(ffi, 'cairo'")
               (string-append "dlopen(ffi, '" (assoc-ref inputs "cairo")
                              "/lib/libcairo.so.2'"))
              (("dlopen\\(ffi, 'gdk-3'")
               (string-append "dlopen(ffi, '" (assoc-ref inputs "gtk+")
                              "/lib/libgtk-3.so.0'"))
              (("dlopen\\(ffi, 'gdk_pixbuf-2.0'")
               (string-append "dlopen(ffi, '" (assoc-ref inputs "gdk-pixbuf")
                              "/lib/libgdk_pixbuf-2.0.so.0'"))
              (("dlopen\\(ffi, 'glib-2.0'")
               (string-append "dlopen(ffi, '" (assoc-ref inputs "glib")
                              "/lib/libglib-2.0.so.0'"))
              (("dlopen\\(ffi, 'gobject-2.0'")
               (string-append "dlopen(ffi, '" (assoc-ref inputs "glib")
                              "/lib/libgobject-2.0.so.0'"))
              (("dlopen\\(ffi, 'pangocairo-1.0'")
               (string-append "dlopen(ffi, '" (assoc-ref inputs "pango")
                              "/lib/libpangocairo-1.0.so.0'"))
              (("dlopen\\(ffi, 'pango-1.0'")
               (string-append "dlopen(ffi, '" (assoc-ref inputs "pango")
                              "/lib/libpango-1.0.so.0'")))
             #t))
         (add-after 'install 'install-doc
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                    (doc (string-append data "/doc/" ,name "-" ,version))
                    (html (string-append doc "/html")))
               (setenv "LD_LIBRARY_PATH"
                       (string-append (assoc-ref inputs "cairo") "/lib" ":"
                                      (assoc-ref inputs "gdk-pixbuf") "/lib"))
               (setenv "LANG" "en_US.UTF-8")
               (mkdir-p html)
               (for-each (lambda (file)
                           (copy-file (string-append "." file)
                                      (string-append doc file)))
                         '("/README.rst" "/CHANGES" "/LICENSE"))
               (system* "python" "setup.py" "build_sphinx")
               (copy-recursively "docs/_build/html" html)
               #t))))))
    (home-page "https://github.com/Kozea/cairocffi")
    (synopsis "Python bindings and object-oriented API for Cairo")
    (description
     "Cairocffi is a CFFI-based drop-in replacement for Pycairo, a set of
Python bindings and object-oriented API for cairo.  Cairo is a 2D vector
graphics library with support for multiple backends including image buffers,
PNG, PostScript, PDF, and SVG file output.")
    (license license:bsd-3)))

(define-public python2-cairocffi
  (package-with-python2 python-cairocffi))

(define-public python-decorator
  (package
    (name "python-decorator")
    (version "4.3.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "decorator" version))
       (sha256
        (base32 "0308djallnh00v112y5b7nadl657ysmkp6vc8xn51d6yzc9zm7n3"))))
    (build-system python-build-system)
    (home-page "https://pypi.python.org/pypi/decorator/")
    (synopsis "Python module to simplify usage of decorators")
    (description
      "The aim of the decorator module is to simplify the usage of decorators
for the average programmer, and to popularize decorators usage giving examples
of useful decorators, such as memoize, tracing, redirecting_stdout, locked,
etc.  The core of this module is a decorator factory.")
    (license license:expat)))

(define-public python2-decorator
  (package-with-python2 python-decorator))

(define-public python-drmaa
  (package
    (name "python-drmaa")
    (version "0.7.7")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "drmaa" version))
       (sha256
        (base32 "0xzqriqyvk5b8hszbavsyxd29wm3sxirm8zvvdm73rs2iq7w4hkx"))))
    (build-system python-build-system)
    ;; The test suite requires libdrmaa which is provided by the cluster
    ;; environment.  At runtime the environment variable DRMAA_LIBRARY_PATH
    ;; should be set to the path of the libdrmaa library.
    (arguments '(#:tests? #f))
    (native-inputs
     `(("python-nose" ,python-nose)))
    (home-page "https://pypi.python.org/pypi/drmaa")
    (synopsis "Python bindings for the DRMAA library")
    (description
      "A Python package for Distributed Resource Management (DRM) job
submission and control.  This package is an implementation of the DRMAA 1.0
Python language binding specification.")
    (license license:bsd-3)))

(define-public python2-drmaa
  (package-with-python2 python-drmaa))

(define-public python-grako
  (package
    (name "python-grako")
    (version "3.99.9")
    (source
     (origin
       (method url-fetch)
       (uri
        (pypi-uri "grako" version ".zip"))
       (sha256
        (base32
         "0r63i68wcnv63rfjkasq1ah81frz61a6mzbcnaxhrkdpx84p7hzw"))))
    (build-system python-build-system)
    (arguments '(#:tests? #f)) ; Test file 'grako.ebnf' is missing from archive.
    (native-inputs
     `(("unzip" ,unzip)
       ("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)))
    (home-page "https://bitbucket.org/neogeny/grako")
    (synopsis "EBNF parser generator")
    (description
     "Grako takes a grammar in a variation of EBNF as input, and outputs a
memoizing PEG/Packrat parser in Python.")
    (license license:bsd-3)))

(define-public python2-grako
  (package-with-python2 python-grako))

(define-public python-gridmap
  (package
    (name "python-gridmap")
    (version "0.13.0")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/pygridtools/gridmap.git")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32 "1478lbwsr1w24cii2x01m2910fvh8r43ghnb78nc972a96hqiknm"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; FIXME: Requires python-cherrypy.
    (propagated-inputs
     `(("python-psutil" ,python-psutil)
       ("python-drmaa" ,python-drmaa)
       ("python-pyzmq" ,python-pyzmq)))
    (home-page "https://github.com/pygridtools/gridmap")
    (synopsis "Create jobs on a cluster directly from Python")
    (description
      "Gridmap is a Python package to allow you to easily create jobs on the
cluster directly from Python.  You can directly map Python functions onto the
cluster without needing to write any wrapper code yourself.")
    (license license:gpl3+)))

(define-public python2-gridmap
  (package-with-python2 python-gridmap))

(define-public python-honcho
  (package
    (name "python-honcho")
    (version "1.0.1")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/nickstenning/honcho.git")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32 "11bd87474qpif20xdcn0ra1idj5k16ka51i658wfpxwc6nzsn92b"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-mock" ,python-mock)
       ("python-tox" ,python-tox)
       ("which" ,which))) ;for tests
    (propagated-inputs
     `(("python-jinja2" ,python-jinja2)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (delete 'check)
         (add-after 'install 'check
           (lambda* (#:key outputs inputs #:allow-other-keys)
             ;; fix honcho path in testsuite
             (substitute* "tests/conftest.py"
               (("'honcho'") (string-append "'" (assoc-ref outputs "out")
                                            "/bin/honcho" "'")))
             ;; It's easier to run tests after install.
             ;; Make installed package available for running the tests
             (add-installed-pythonpath inputs outputs)
             (invoke "py.test" "-v"))))))
    (home-page "https://github.com/nickstenning/honcho")
    (synopsis "Manage Procfile-based applications")
    (description
      "A Procfile is a file which describes how to run an application
consisting of several processes. honcho starts all listed processes.
The output of all running processes is collected by honcho and
displayed.")
    (license license:expat)))

(define-public python2-honcho
  (package-with-python2 python-honcho))

(define-public python-pexpect
  (package
    (name "python-pexpect")
    (version "4.6.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pexpect" version))
       (sha256
        (base32 "1fla85g47iaxxpjhp9vkxdnv4pgc7rplfy6ja491smrrk0jqi3ia"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'prepare-tests
           (lambda _
             (substitute* (find-files "tests")
               (("/bin/ls") (which "ls"))
               (("/bin/echo") (which "echo"))
               (("/bin/which") (which "which"))
               ;; Many tests try to use the /bin directory which
               ;; is not present in the build environment.
               ;; Use one that's non-empty and unlikely to change.
               (("/bin'") "/dev'"))
             ;; XXX: Socket connection test gets "Connection reset by peer".
             ;; Why does it not work? Delete for now.
             (delete-file "tests/test_socket.py")
             #t))
         (replace 'check (lambda _ (invoke "nosetests" "-v"))))))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-pytest" ,python-pytest)
       ("man-db" ,man-db)
       ("which" ,which)
       ("bash-full" ,bash)))                 ;full Bash for 'test_replwrap.py'
    (propagated-inputs
     `(("python-ptyprocess" ,python-ptyprocess)))
    (home-page "http://pexpect.readthedocs.org/")
    (synopsis "Controlling interactive console applications")
    (description
     "Pexpect is a pure Python module for spawning child applications;
controlling them; and responding to expected patterns in their output.
Pexpect works like Don Libes’ Expect.  Pexpect allows your script to spawn a
child application and control it as if a human were typing commands.")
    (license license:isc)))

(define-public python2-pexpect
  (package-with-python2 python-pexpect))

(define-public python-setuptools-scm
  (package
    (name "python-setuptools-scm")
    (version "3.1.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "setuptools_scm" version))
              (sha256
               (base32
                "0h4bglwfz8b9prqljv8z3w9rgydfyxzaj05bm1y6zs5m6shz548i"))))
    (build-system python-build-system)
    (home-page "https://github.com/pypa/setuptools_scm/")
    (synopsis "Manage Python package versions in SCM metadata")
    (description
     "Setuptools_scm handles managing your Python package versions in
@dfn{software configuration management} (SCM) metadata instead of declaring
them as the version argument or in a SCM managed file.")
    (license license:expat)))

(define-public python2-setuptools-scm
  (package-with-python2 python-setuptools-scm))

(define-public python-pathlib2
  (package
    (name "python-pathlib2")
    (version "2.3.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pathlib2" version))
       (sha256
        (base32
         "0hpp92vqqgcd8h92msm9slv161b1q160igjwnkf2ag6cx0c96695"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-scandir" ,python-scandir)
       ("python-six" ,python-six)))
    (home-page "https://pypi.python.org/pypi/pathlib2/")
    (synopsis "Object-oriented file system paths")
    (description "The goal of pathlib2 is to provide a backport of the
standard @code{pathlib} module which tracks the standard library module, so
all the newest features of the standard @code{pathlib} can be used also on
older Python versions.")
    (license license:expat)))

(define-public python-importlib-metadata
  (package
    (name "python-importlib-metadata")
    (version "0.18")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "importlib_metadata" version))
       (sha256
        (base32
         "1nqj6vj2z4byi8flzf2lbldhqgicsz9mkpv4k69kjd8p8qxy4vnb"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-configparser" ,python-configparser)
       ("python-contextlib2" ,python-contextlib2)
       ("python-docutils" ,python-docutils)
       ("python-pathlib2" ,python-pathlib2)
       ("python-rst.linker" ,python-rst.linker)
       ("python-zipp" ,python-zipp)))
    (native-inputs
     `(("python-setuptools-scm" ,python-setuptools-scm)
       ("python-sphinx" ,python-sphinx)))
    (home-page "https://importlib-metadata.readthedocs.io/")
    (synopsis "Read metadata from Python packages")
    (description
     "@code{importlib_metadata} is a library which provides an API for
accessing an installed Python package's metadata, such as its entry points or
its top-level name.  This functionality intends to replace most uses of
@code{pkg_resources} entry point API and metadata API.  Along with
@code{importlib.resources} in Python 3.7 and newer, this can eliminate the
need to use the older and less efficient @code{pkg_resources} package.")
    (license license:asl2.0)))

(define-public python-jaraco-packaging
  (package
    (name "python-jaraco-packaging")
    (version "6.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "jaraco.packaging" version))
        (sha256
          (base32
            "0zimrnkh33b9g8ffw11mjh6kvs54cy5gcjw1h5cl1r7dc833dmkm"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pytest" ,python-pytest)
       ("python-pytest-checkdocs" ,python-pytest-checkdocs)
       ("python-pytest-flake8" ,python-pytest-flake8)
       ("python-rst.linker" ,python-rst.linker)
       ("python-setuptools" ,python-setuptools)
       ("python-setuptools-scm" ,python-setuptools-scm)
       ("python-six" ,python-six)
       ("python-sphinx" ,python-sphinx)))
    (home-page "https://github.com/jaraco/jaraco.packaging")
    (synopsis "Tools to supplement packaging Python releases")
    (description
     "This package provides various tools to supplement packaging Python
releases.")
    (license license:expat)))

(define-public python-pathpy
  (package
    (name "python-pathpy")
    (version "11.5.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "path.py" version))
       (sha256
        (base32 "1jxkf91syzxlpiwgm83fjfz1m5xh3jrvv4iyl5wjsnkk599pls5n"))))
    (outputs '("out" "doc"))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-appdirs" ,python-appdirs)))
    (native-inputs
     `(("python-setuptools-scm" ,python-setuptools-scm)
       ("python-sphinx" ,python-sphinx)
       ("python-rst.linker" ,python-rst.linker)
       ("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)
       ("python-jaraco-packaging" ,python-jaraco-packaging)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'build 'build-doc
           (lambda _
             (setenv "LANG" "en_US.UTF-8")
             (invoke "python" "setup.py" "build_sphinx")))
         (add-after 'install 'install-doc
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                    (doc (string-append data "/doc/" ,name "-" ,version))
                    (html (string-append doc "/html")))
               (mkdir-p html)
               (for-each (lambda (file)
                           (copy-file file (string-append doc "/" file)))
                         '("README.rst" "CHANGES.rst"))
               (copy-recursively "build/sphinx/html" html)
               #t)))
         (replace 'check
           (lambda _
             ;; The import time test aborts if an import takes longer than
             ;; 100ms.  It may very well take a little longer than that.
             (invoke "pytest" "-v" "-k" "not test_import_time"))))))
    (home-page "https://github.com/jaraco/path.py")
    (synopsis "Python module wrapper for built-in os.path")
    (description
     "@code{path.py} implements path objects as first-class entities, allowing
common operations on files to be invoked on those path objects directly.")
    (license license:expat)))

(define-public python2-pathpy
  (package-with-python2 python-pathpy))

(define-public python-simplegeneric
  (package
    (name "python-simplegeneric")
    (version "0.8.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "simplegeneric" version ".zip"))
       (sha256
        (base32 "0wwi1c6md4vkbcsfsf8dklf3vr4mcdj4mpxkanwgb6jb1432x5yw"))))
    (build-system python-build-system)
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page "http://cheeseshop.python.org/pypi/simplegeneric")
    (synopsis "Python module for simple generic functions")
    (description
     "The simplegeneric module lets you define simple single-dispatch generic
functions, akin to Python’s built-in generic functions like @code{len()},
@code{iter()} and so on.  However, instead of using specially-named methods,
these generic functions use simple lookup tables, akin to those used by
e.g. @code{pickle.dump()} and other generic functions found in the Python
standard library.")
    (license license:zpl2.1)))

(define-public python2-simplegeneric
  (package-with-python2 python-simplegeneric))

(define-public python-ipython-genutils
  ;; TODO: This package is retired, check if can be removed, see description.
  (package
    (name "python-ipython-genutils")
    (version "0.1.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "ipython_genutils" version))
      (sha256
       (base32 "19l2pp1c64ansr89l3cqh19jdi2ixhssdzx0vz4n6r52a6i281is"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f)) ; no tests
    (home-page "https://ipython.org")
    (synopsis "Vestigial utilities from IPython")
    (description
     "This package provides retired utilities from IPython.  No packages
outside IPython/Jupyter should depend on it.

This package shouldn't exist.  It contains some common utilities shared by
Jupyter and IPython projects during The Big Split.  As soon as possible, those
packages will remove their dependency on this, and this package will go
away.")
    (license license:bsd-3)))

(define-public python2-ipython-genutils
  (package-with-python2 python-ipython-genutils))

(define-public python-traitlets
  (package
    (name "python-traitlets")
    (version "4.3.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "traitlets" version))
       (sha256
        (base32
         "0dbq7sx26xqz5ixs711k5nc88p8a0nqyz6162pwks5dpcz9d4jww"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check (lambda _ (invoke "pytest" "-vv" "traitlets"))))))
    (propagated-inputs
     `(("python-ipython-genutils" ,python-ipython-genutils)
       ("python-decorator" ,python-decorator)))    ;not needed for >4.3.2
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (properties `((python2-variant . ,(delay python2-traitlets))))
    (home-page "https://ipython.org")
    (synopsis "Configuration system for Python applications")
    (description
     "Traitlets is a framework that lets Python classes have attributes with
type checking, dynamically calculated default values, and ‘on change’
callbacks.  The package also includes a mechanism to use traitlets for
configuration, loading values from files or from command line arguments.  This
is a distinct layer on top of traitlets, so you can use traitlets in your code
without using the configuration machinery.")
    (license license:bsd-3)))

(define-public python2-traitlets
  (let ((traitlets (package-with-python2 (strip-python2-variant python-traitlets))))
    (package
      (inherit traitlets)
      (propagated-inputs
       `(("python2-enum34" ,python2-enum34)
         ,@(package-propagated-inputs traitlets))))))

(define-public python-jupyter-core
  (package
    (name "python-jupyter-core")
    (version "4.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append (pypi-uri "jupyter_core" version)))
       (sha256
        (base32
         "1dy083rarba8prn9f9srxq3c7n7vyql02ycrqq306c40lr57aw5s"))))
    (build-system python-build-system)
    ;; FIXME: not sure how to run the tests
    (arguments `(#:tests? #f))
    (propagated-inputs
     `(("python-traitlets" ,python-traitlets)))
    (home-page "http://jupyter.org/")
    (synopsis "Jupyter base package")
    (description
     "Jupyter core is the base package on which Jupyter projects rely.")
    (license license:bsd-3)))

(define-public python2-jupyter-core
  (package-with-python2 python-jupyter-core))

(define-public python-jupyter-client
  (package
    (name "python-jupyter-client")
    (version "5.2.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "jupyter_client" version))
       (sha256
        (base32
         "0l9mh7ccrpl3lppym3dnky8n1nk7xarzzdcxf4q2s7aw203cpydm"))))
    (build-system python-build-system)
    ;; Tests fail because of missing native python kernel which I assume is
    ;; provided by the ipython package, which we cannot use because it would
    ;; cause a dependency cycle.
    (arguments
     `(#:tests? #f

       #:phases (modify-phases %standard-phases
                  (add-after 'unpack 'set-tool-file-names
                    (lambda* (#:key inputs #:allow-other-keys)
                      (let ((iproute (assoc-ref inputs "iproute")))
                        (substitute* "jupyter_client/localinterfaces.py"
                          (("'ip'")
                           (string-append "'" iproute "/sbin/ip'")))
                        #t))))))
    (inputs
     `(("iproute" ,iproute)))
    (propagated-inputs
     `(("python-pyzmq" ,python-pyzmq)
       ("python-traitlets" ,python-traitlets)
       ("python-jupyter-core" ,python-jupyter-core)))
    (home-page "http://jupyter.org/")
    (synopsis "Jupyter protocol implementation and client libraries")
    (description
     "The @code{jupyter_client} package contains the reference implementation
of the Jupyter protocol.  It also provides client and kernel management APIs
for working with kernels, and the @code{jupyter kernelspec} entrypoint for
installing @code{kernelspec}s for use with Jupyter frontends.")
    (license license:bsd-3)))

(define-public python2-jupyter-client
  (package-with-python2 python-jupyter-client))

(define-public python-ipykernel
  (package
    (name "python-ipykernel")
    (version "5.1.1")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "ipykernel" version))
      (sha256
       (base32 "173nm29g85w8cac3fg40b27qaq26g41wgg6qn79ql1hq4w2n5sgh"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (setenv "HOME" "/tmp")
             (invoke "pytest" "-v")
             #t))
         (add-after 'install 'set-python-file-name
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Record the absolute file name of the 'python' executable in
             ;; 'kernel.json'.
             (let ((out (assoc-ref outputs "out")))
               (substitute* (string-append out "/share/jupyter"
                                           "/kernels/python3/kernel.json")
                 (("\"python\"")
                  (string-append "\"" (which "python") "\"")))
               #t))))))
    (propagated-inputs
     `(("python-ipython" ,python-ipython)
       ;; imported at runtime during connect
       ("python-jupyter-client" ,python-jupyter-client)))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-nose" ,python-nose)))
    (home-page "https://ipython.org")
    (synopsis "IPython Kernel for Jupyter")
    (description
     "This package provides the IPython kernel for Jupyter.")
    (license license:bsd-3)))

;; Version 5.1.1 and above no longer support Python 2.
(define-public python2-ipykernel
  (package
    (name "python2-ipykernel")
    (version "5.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ipykernel" version))
       (sha256
        (base32 "0br95qhrd5k65g10djngiy27hs0642301hlf2q142i8djabvzh0g"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (setenv "HOME" "/tmp")
             (invoke "pytest" "-v")
             #t)))))
    (propagated-inputs
     `(("python2-ipython" ,python2-ipython)
       ;; imported at runtime during connect
       ("python2-jupyter-client" ,python2-jupyter-client)))
    (native-inputs
     `(("python2-pytest" ,python2-pytest)
       ("python2-nose" ,python2-nose)))
    (home-page "https://ipython.org")
    (synopsis "IPython Kernel for Jupyter")
    (description
     "This package provides the IPython kernel for Jupyter.")
    (license license:bsd-3)))

(define-public python-pari-jupyter
  (package
    (name "python-pari-jupyter")
    (version "1.3.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pari_jupyter" version))
       (sha256
        (base32
         "1yash0p422nnin7z58b99d0p23nx79f5m0mainc9hsjg72jhdhr6"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-ipykernel" ,python-ipykernel)))
    (inputs
     `(("pari-gp" ,pari-gp)
       ("readline" ,readline)))
    (arguments
     `(#:tests? #f)) ; no test suite
    (home-page
     "https://github.com/jdemeyer/pari_jupyter")
    (synopsis "A Jupyter kernel for PARI/GP")
    (description "The package provides a PARI/GP kernel for Jupyter.")
    (license license:gpl3+)))

(define-public python-backcall
  (package
    (name "python-backcall")
    (version "0.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "backcall" version))
       (sha256
        (base32
         "1r01dqch3f8fdj3n6fviw8hxqrs6w5v0qw4izmvqzry1w9dxiv1q"))))
    (build-system python-build-system)
    (home-page "https://github.com/takluyver/backcall/")
    (synopsis "Specifications for callback functions passed in to an API")
    (description
     "If your code lets other people supply callback functions, it's important
to specify the function signature you expect, and check that functions support
that.  Adding extra parameters later would break other peoples code unless
you're careful.  The @code{backcall} package provides a way of specifying the
callback signature using a prototype function.")
    (license license:bsd-3)))

;; This is the latest release of the LTS version of ipython with support for
;; Python 2.7 and Python 3.x.  Later non-LTS versions starting from 6.0 have
;; dropped support for Python 2.7.
(define-public python2-ipython
  (package
    (name "python2-ipython")
    (version "5.8.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ipython" version ".tar.gz"))
       (sha256
        (base32 "01l93i4hspf0lvhmycvc8j378bslm9rw30mwfspsl6v1ayc69b2b"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python2-backports-shutil-get-terminal-size"
        ,python2-backports-shutil-get-terminal-size)
       ("python2-pathlib2" ,python2-pathlib2)
       ("python2-pyzmq" ,python2-pyzmq)
       ("python2-prompt-toolkit" ,python2-prompt-toolkit-1)
       ("python2-terminado" ,python2-terminado)
       ("python2-matplotlib" ,python2-matplotlib)
       ("python2-numpy" ,python2-numpy)
       ("python2-numpydoc" ,python2-numpydoc)
       ("python2-jinja2" ,python2-jinja2)
       ("python2-mistune" ,python2-mistune)
       ("python2-pexpect" ,python2-pexpect)
       ("python2-pickleshare" ,python2-pickleshare)
       ("python2-simplegeneric" ,python2-simplegeneric)
       ("python2-jsonschema" ,python2-jsonschema)
       ("python2-traitlets" ,python2-traitlets)
       ("python2-nbformat" ,python2-nbformat)
       ("python2-pygments" ,python2-pygments)))
    (inputs
     `(("readline" ,readline)
       ("which" ,which)))
    (native-inputs
     `(("graphviz" ,graphviz)
       ("pkg-config" ,pkg-config)
       ("python2-requests" ,python2-requests) ;; for tests
       ("python2-testpath" ,python2-testpath)
       ("python2-mock" ,python2-mock)
       ("python2-nose" ,python2-nose)))
    (arguments
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         (add-before 'check 'delete-broken-tests
           (lambda* (#:key inputs #:allow-other-keys)
             ;; These tests throw errors for unknown reasons.
             (delete-file "IPython/core/tests/test_profile.py")
             (delete-file "IPython/core/tests/test_interactiveshell.py")
             (delete-file "IPython/core/tests/test_magic.py")
             #t)))))
    (home-page "https://ipython.org")
    (synopsis "IPython is a tool for interactive computing in Python")
    (description
     "IPython provides a rich architecture for interactive computing with:
Powerful interactive shells, a browser-based notebook, support for interactive
data visualization, embeddable interpreters and tools for parallel
computing.")
    (license license:bsd-3)))

(define-public python-ipython
  (package
    (name "python-ipython")
    (version "7.5.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ipython" version ".tar.gz"))
       (sha256
        (base32 "09mbxq37mfn88xjnib7qfzaq9krr7gf1jxwy1p6mcjr254082h78"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-backcall" ,python-backcall)
       ("python-pyzmq" ,python-pyzmq)
       ("python-prompt-toolkit" ,python-prompt-toolkit)
       ("python-terminado" ,python-terminado)
       ("python-matplotlib" ,python-matplotlib)
       ("python-numpy" ,python-numpy)
       ("python-numpydoc" ,python-numpydoc)
       ("python-jedi" ,python-jedi)
       ("python-jinja2" ,python-jinja2)
       ("python-mistune" ,python-mistune)
       ("python-pexpect" ,python-pexpect)
       ("python-pickleshare" ,python-pickleshare)
       ("python-simplegeneric" ,python-simplegeneric)
       ("python-jsonschema" ,python-jsonschema)
       ("python-traitlets" ,python-traitlets)
       ("python-nbformat" ,python-nbformat)
       ("python-pygments" ,python-pygments)))
    (inputs
     `(("readline" ,readline)
       ("which" ,which)))
    (native-inputs
     `(("graphviz" ,graphviz)
       ("pkg-config" ,pkg-config)
       ("python-requests" ,python-requests) ;; for tests
       ("python-testpath" ,python-testpath)
       ("python-nose" ,python-nose)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; Tests can only be run after the library has been installed and not
         ;; within the source directory.
         (delete 'check)
         (add-after 'install 'check
           (lambda* (#:key inputs outputs tests? #:allow-other-keys)
             (if tests?
                 (begin
                   ;; Make installed package available for running the tests
                   (add-installed-pythonpath inputs outputs)
                   (setenv "HOME" "/tmp/") ;; required by a test
                   ;; We only test the core because one of the other tests
                   ;; tries to import ipykernel.
                   (invoke "python" "IPython/testing/iptest.py"
                           "-v" "IPython/core/tests"))
                 #t)))
         (add-before 'check 'fix-tests
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "./IPython/utils/_process_posix.py"
               (("/usr/bin/env', 'which") (which "which")))
             (substitute* "./IPython/core/tests/test_inputtransformer.py"
               (("#!/usr/bin/env python")
                (string-append "#!" (which "python"))))
             ;; This test introduces a circular dependency on ipykernel
             ;; (which depends on ipython).
             (delete-file "IPython/core/tests/test_display.py")
             ;; AttributeError: module 'IPython.core' has no attribute 'formatters'
             (delete-file "IPython/core/tests/test_interactiveshell.py")
             #t)))))
    (home-page "https://ipython.org")
    (synopsis "IPython is a tool for interactive computing in Python")
    (description
     "IPython provides a rich architecture for interactive computing with:
Powerful interactive shells, a browser-based notebook, support for interactive
data visualization, embeddable interpreters and tools for parallel
computing.")
    (license license:bsd-3)))

(define-public python-ipython-documentation
  (package
    (inherit python-ipython)
    (name "python-ipython-documentation")
    (version (package-version python-ipython))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (delete 'build)
         (delete 'check)
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((data (string-append (assoc-ref outputs "out") "/share"))
                    (doc (string-append data "/doc/" ,name "-" ,version))
                    (html (string-append doc "/html"))
                    (man1 (string-append data "/man/man1"))
                    (info (string-append data "/info"))
                    (examples (string-append doc "/examples"))
                    (python-arg (string-append "PYTHON=" (which "python"))))
               (setenv "LANG" "en_US.utf8")
               (with-directory-excursion "docs"
                 ;; FIXME: pdf fails to build
                 ;;(system* "make" "pdf" "PAPER=a4")
                 (system* "make" python-arg "html")
                 ;; FIXME: the generated texi file contains ^@^@, which trips
                 ;; up the parser.
                 ;; (system* "make" python-arg "info")
                 )
               (copy-recursively "docs/man" man1)
               (copy-recursively "examples" examples)
               (copy-recursively "docs/build/html" html)
               ;; (copy-file "docs/build/latex/ipython.pdf"
               ;;            (string-append doc "/ipython.pdf"))
               (mkdir-p info)
               ;; (copy-file "docs/build/texinfo/ipython.info"
               ;;            (string-append info "/ipython.info"))
               (copy-file "COPYING.rst" (string-append doc "/COPYING.rst")))
             #t)))))
    (inputs
     `(("python-ipython" ,python-ipython)
       ("python-ipykernel" ,python-ipykernel)))
    (native-inputs
     `(("python-sphinx" ,python-sphinx)
       ("python-sphinx-rtd-theme" ,python-sphinx-rtd-theme)
       ;; FIXME: It's possible that a smaller union would work just as well.
       ("texlive" ,(texlive-union (list texlive-amsfonts
                                        texlive-fonts-ec
                                        texlive-generic-ifxetex
                                        texlive-generic-pdftex
                                        texlive-latex-capt-of
                                        texlive-latex-cmap
                                        texlive-latex-environ
                                        texlive-latex-eqparbox
                                        texlive-latex-etoolbox
                                        texlive-latex-expdlist
                                        texlive-latex-fancyhdr
                                        texlive-latex-fancyvrb
                                        texlive-latex-fncychap
                                        texlive-latex-float
                                        texlive-latex-framed
                                        texlive-latex-geometry
                                        texlive-latex-graphics
                                        texlive-latex-hyperref
                                        texlive-latex-mdwtools
                                        texlive-latex-multirow
                                        texlive-latex-needspace
                                        texlive-latex-oberdiek
                                        texlive-latex-parskip
                                        texlive-latex-preview
                                        texlive-latex-tabulary
                                        texlive-latex-threeparttable
                                        texlive-latex-titlesec
                                        texlive-latex-trimspaces
                                        texlive-latex-ucs
                                        texlive-latex-upquote
                                        texlive-latex-url
                                        texlive-latex-varwidth
                                        texlive-latex-wrapfig)))
       ("texinfo" ,texinfo)))))

(define-public python-urwid
  (package
    (name "python-urwid")
    (version "2.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "urwid" version))
       (sha256
        (base32
         "1g6cpicybvbananpjikmjk8npmjk4xvak1wjzji62wc600wkwkb4"))))
    (build-system python-build-system)
    (home-page "http://urwid.org")
    (synopsis "Console user interface library for Python")
    (description
     "Urwid is a curses-based UI/widget library for Python.  It includes many
features useful for text console applications.")
    (license license:lgpl2.1+)))

(define-public python2-urwid
  (package-with-python2 python-urwid))

(define-public python-urwidtrees
  (package
    (name "python-urwidtrees")
    (version "1.0.2")
    (source
      (origin
        (method url-fetch)
        ;; package author intends on distributing via github rather than pypi:
        ;; https://github.com/pazz/alot/issues/877#issuecomment-230173331
        (uri (string-append "https://github.com/pazz/urwidtrees/archive/"
                            version ".tar.gz"))
        (file-name (string-append name "-" version ".tar.gz"))
        (sha256
          (base32
            "0d30lyd3s2a97rhqfax5w9ssqds2z6aydqx3c6j2c2lk3cb4ngvh"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; no tests
    (propagated-inputs `(("python-urwid" ,python-urwid)))
    (home-page "https://github.com/pazz/urwidtrees")
    (synopsis "Tree widgets for urwid")
    (description "Urwidtrees is a Widget Container API for the @code{urwid}
toolkit.  Use it to build trees of widgets.")
    (license license:gpl3+)))

(define-public python2-urwidtrees
  (package-with-python2 python-urwidtrees))

(define-public python-ua-parser
  (package
    (name "python-ua-parser")
    (version "0.8.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ua-parser" version))
       (sha256
        (base32
         "1jwdf58rhchjzzrad405pviv0iq24xa2xmmmdgcm2c8s6b4wzfwp"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))                    ;no test suite in release
    (native-inputs
     `(("python-pyyaml" ,python-pyyaml)))
    (home-page "https://github.com/ua-parser/uap-python")
    (synopsis "User agent parser")
    (description
     "@code{ua-parser} is a Python port of Browserscope's user agent parser.")
    (license license:asl2.0)))

(define-public python2-ua-parser
  (package-with-python2 python-ua-parser))

(define-public python-user-agents
  (package
    (name "python-user-agents")
    (version "1.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "user-agents" version))
       (sha256
        (base32
         "0fc00cd3j8dahq1zzn8pkgfgd7lq37bp2scmdma2n1c049vicgb4"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))                  ;missing devices.json test file in release
    (propagated-inputs
     `(("python-ua-parser" ,python-ua-parser)))
    (home-page "https://github.com/selwin/python-user-agents")
    (synopsis "User Agent strings parsing library")
  (description
   "A library to identify devices (phones, tablets) and their capabilities by
parsing (browser/HTTP) user agent strings.")
  (license license:expat)))

(define-public python2-user-agents
  (package-with-python2 python-user-agents))

(define-public python-dbus
  (package
    (name "python-dbus")
    (version "1.2.8")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://dbus.freedesktop.org/releases/dbus-python/"
                           "dbus-python-" version ".tar.gz"))
       (sha256
        (base32
         "0vvvjmiwnc9cjlks3gcdk43ap7llhlpz7cm1wbw0nc2yfsxjpwdb"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-before
          'check 'pre-check
          (lambda _
            ;; XXX: For the missing '/etc/machine-id'.
            (substitute* "test/run-test.sh"
              (("DBUS_FATAL_WARNINGS=1")
               "DBUS_FATAL_WARNINGS=0"))
            #t)))))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("python" ,python-wrapper)
       ("dbus-glib" ,dbus-glib)))
    (synopsis "Python bindings for D-bus")
    (description "python-dbus provides bindings for libdbus, the reference
implementation of D-Bus.")
    (home-page "https://www.freedesktop.org/wiki/Software/DBusBindings/")
    (license license:expat)))

(define-public python2-dbus
  (package (inherit python-dbus)
    (name "python2-dbus")
    (inputs `(("python" ,python-2)
              ,@(alist-delete "python"
                              (package-inputs python-dbus)
                              equal?)))
    ;; FIXME: on Python 2, the test_utf8 fails with:
    ;; "ValueError: unichr() arg not in range(0x10000) (narrow Python build)"
    (arguments `(#:tests? #f))))

(define-public python-notify2
  (package
    (name "python-notify2")
    (version "0.3.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "notify2" version))
       (sha256
        (base32
         "0z8rrv9rsg1r2qgh2dxj3dfj5xnki98kgi3w839kqby4a26i1yik"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f))                    ; tests depend on system state
    (native-inputs
     `(("python-dbus" ,python-dbus)))
    (home-page "https://bitbucket.org/takluyver/pynotify2")
    (synopsis "Python interface to D-Bus notifications")
    (description
     "Pynotify2 provides a Python interface for sending D-Bus notifications.
It is a reimplementation of pynotify in pure Python, and an alternative to
the GObject Introspection bindings to libnotify for non-GTK applications.")
    (license (list license:bsd-2
                   license:lgpl2.1+))))

(define-public python2-notify2
  (package-with-python2 python-notify2))

(define-public python-lxml
  (package
    (name "python-lxml")
    (version "4.2.5")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "lxml" version))
        (sha256
         (base32
          "0zw0y9hs0nflxhl9cs6ipwwh53szi3w2x06wl0k9cylyqac0cwin"))))
    (build-system python-build-system)
    (inputs
      `(("libxml2" ,libxml2)
        ("libxslt" ,libxslt)))
    (home-page "http://lxml.de/")
    (synopsis
      "Python XML processing library")
    (description
      "The lxml XML toolkit is a Pythonic binding for the C libraries
libxml2 and libxslt.")
    (license license:bsd-3))) ; and a few more, see LICENSES.txt

(define-public python2-lxml
  (package-with-python2 python-lxml))

;; beautifulsoup4 has a totally different namespace than 3.x,
;; and pypi seems to put it under its own name, so I guess we should too
(define-public python-beautifulsoup4
  (package
    (name "python-beautifulsoup4")
    (version "4.7.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "beautifulsoup4" version))
       (sha256
        (base32
         "0j2kycz2dxgx68xzjm7rxg5xn6v61gq5ifvxyg99slmqkybnal4l"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; The Python 2 source is the definitive source of beautifulsoup4. We
         ;; must use this conversion script when building with Python 3. The
         ;; conversion script also runs the tests.
         ;; For more information, see the file 'convert-py3k' in the source
         ;; distribution.
         (replace 'check
           (lambda _ (invoke "./convert-py3k"))))))
    (propagated-inputs
     `(("python-soupsieve" ,python-soupsieve)))
    (home-page
     "https://www.crummy.com/software/BeautifulSoup/bs4/")
    (synopsis
     "Python screen-scraping library")
    (description
     "Beautiful Soup is a Python library designed for rapidly setting up
screen-scraping projects.  It offers Pythonic idioms for navigating,
searching, and modifying a parse tree, providing a toolkit for
dissecting a document and extracting what you need.  It automatically
converts incoming documents to Unicode and outgoing documents to UTF-8.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-beautifulsoup4))))))

(define-public python2-beautifulsoup4
  (package
    (inherit (package-with-python2
              (strip-python2-variant python-beautifulsoup4)))
    (arguments `(#:python ,python-2))))

(define-public python-soupsieve
  (package
    (name "python-soupsieve")
    (version "1.9.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "soupsieve" version))
       (sha256
        (base32
         "0in9rc9q3h8w5b4qf7kvl3qxcvw6vrz35ckblchgf70hm6pg3dbj"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f))
    ;;XXX: 2 tests fail currently despite claming they were to be
    ;;skipped. Also, beautifulsoup4 may depend on this in the future, so we
    ;;don't want to create a circular dependency.
    (home-page "https://github.com/facelessuser/soupsieve")
    (synopsis "CSS selector library")
    (description
     "Soup Sieve is a CSS selector library designed to be used with Beautiful
Soup 4.  It aims to provide selecting, matching, and filtering using modern
CSS selectors.  Soup Sieve currently provides selectors from the CSS level 1
specifications up through the latest CSS level 4 drafts and beyond (though
some are not yet implemented).")
    (properties `((python2-variant . ,(delay python2-soupsieve))))
    (license license:expat)))

(define-public python2-soupsieve
  (let ((base (package-with-python2 (strip-python2-variant python-soupsieve))))
    (package
      (inherit base)
      (propagated-inputs
       `(("python2-backports-functools-lru-cache"
          ,python2-backports-functools-lru-cache)
         ,@(package-propagated-inputs base))))))

(define-public python-netifaces
  (package
    (name "python-netifaces")
    (version "0.10.7")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "netifaces" version))
        (sha256
          (base32
            "1gccklrcplbbqh81g1mdgpa5y8na7kkf29cq2ka3f5a2fp5hyndx"))))
    (build-system python-build-system)
    (home-page "https://github.com/al45tair/netifaces")
    (synopsis
      "Python module for portable network interface information")
    (description
      "Netifaces is a Python module providing information on network
interfaces in an easy and portable manner.")
    (license license:expat)))

(define-public python2-netifaces
  (package-with-python2 python-netifaces))

(define-public python-networkx
  (package
    (name "python-networkx")
    (version "2.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "networkx" version ".zip"))
       (sha256
        (base32 "12swxb15299v9vqjsq4z8rgh5sdhvpx497xwnhpnb0gynrx6zra5"))))
    (build-system python-build-system)
    ;; python-decorator is needed at runtime.
    (propagated-inputs
     `(("python-decorator" ,python-decorator)))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("unzip" ,unzip)))
    (home-page "https://networkx.github.io/")
    (synopsis "Python module for creating and manipulating graphs and networks")
    (description
      "NetworkX is a Python package for the creation, manipulation, and study
of the structure, dynamics, and functions of complex networks.")
    (license license:bsd-3)))

(define-public python2-networkx
  (package-with-python2 python-networkx))

(define-public python-datrie
  (package
    (name "python-datrie")
    (version "0.7.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "datrie" version))
       (sha256
        (base32
         "08r0if7dry2q7p34gf7ffyrlnf4bdvnprxgydlfxgfnvq8f3f4bs"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (add-before 'build 'cythonize
                    (lambda _
                      ;; Regenerate Cython classes to solve ABI issues with Python
                      ;; 3.7.0.  See <https://github.com/pytries/datrie/issues/52>.
                      (invoke "cython" "src/datrie.pyx" "src/cdatrie.pxd"
                              "src/stdio_ext.pxd" "-a"))))))
    (native-inputs
     `(("python-cython" ,python-cython)
       ("python-hypothesis" ,python-hypothesis)
       ("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)))
    (home-page "https://github.com/kmike/datrie")
    (synopsis "Fast, efficiently stored trie for Python")
    (description
     "This package provides a fast, efficiently stored trie implementation for
Python.")
    (license license:lgpl2.1+)))

(define-public snakemake
  (package
    (name "snakemake")
    (version "5.2.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "snakemake" version))
       (sha256
        (base32 "0gj0xxgiq3mp9qyyrbfzldiaq1giliqw0in64nqiz7vx49myqj7z"))))
    (build-system python-build-system)
    (arguments
     ;; TODO: Package missing test dependencies.
     '(#:tests? #f
       #:phases
       (modify-phases %standard-phases
         ;; For cluster execution Snakemake will call Python.  Since there is
         ;; no suitable PYTHONPATH set, cluster execution will fail.  We fix
         ;; this by calling the snakemake wrapper instead.
         (add-after 'unpack 'call-wrapper-not-wrapped-snakemake
           (lambda* (#:key outputs #:allow-other-keys)
             (substitute* "snakemake/executors.py"
               (("\\{sys.executable\\} -m snakemake")
                (string-append (assoc-ref outputs "out")
                               "/bin/snakemake")))
             #t)))))
    (propagated-inputs
     `(("python-gitpython" ,python-gitpython)
       ("python-wrapt" ,python-wrapt)
       ("python-requests" ,python-requests)
       ("python-appdirs" ,python-appdirs)
       ("python-configargparse" ,python-configargparse)
       ("python-datrie" ,python-datrie)
       ("python-docutils" ,python-docutils)
       ("python-jinja2" ,python-jinja2)
       ("python-jsonschema" ,python-jsonschema)
       ("python-networkx" ,python-networkx)
       ("python-pyyaml" ,python-pyyaml)
       ("python-ratelimiter" ,python-ratelimiter)))
    (home-page "https://snakemake.readthedocs.io")
    (synopsis "Python-based execution environment for make-like workflows")
    (description
      "Snakemake aims to reduce the complexity of creating workflows by
providing a clean and modern domain specific specification language (DSL) in
Python style, together with a fast and comfortable execution environment.")
    (license license:expat)))

;; This is currently needed for the pigx-* packages.
(define-public snakemake-4
  (package (inherit snakemake)
    (version "4.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "snakemake" version))
       (sha256
        (base32 "0g0paia4z7w3srnqdmavq3hrb2x7qnpf81jx50njl0p7y4y0j8jv"))))
    (propagated-inputs
     `(("python-wrapt" ,python-wrapt)
       ("python-requests" ,python-requests)
       ("python-appdirs" ,python-appdirs)
       ("python-configargparse" ,python-configargparse)
       ("python-pyyaml" ,python-pyyaml)
       ("python-ratelimiter" ,python-ratelimiter)))))

(define-public python-pyqrcode
  (package
    (name "python-pyqrcode")
    (version "1.2.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "PyQRCode" version))
       (sha256
        (base32
         "1m9ln8k9v7dfbh1i81225hx5mdsh8mpf9g7r4wpbfmiyfcs7dgzx"))))
    (build-system python-build-system)
    (home-page
     "https://github.com/mnooner256/pyqrcode")
    (synopsis "QR code generator")
    (description
     "Pyqrcode is a QR code generator written purely in Python with
SVG, EPS, PNG and terminal output.")
    (license license:bsd-3)))

(define-public python-seaborn
  (package
    (name "python-seaborn")
    (version "0.9.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "seaborn" version))
       (sha256
        (base32 "0bqysi3fxfjl1866m5jq8z7mynhqbqnikim74dmzn8539iwkzj3n"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'start-xserver
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((xorg-server (assoc-ref inputs "xorg-server")))
               ;; There must be a running X server and make check doesn't
               ;; start one.  Therefore we must do it.
               (system (format #f "~a/bin/Xvfb :1 &" xorg-server))
               (setenv "DISPLAY" ":1")
               #t)))
         (replace 'check (lambda _ (invoke "pytest" "seaborn") #t)))))
    (propagated-inputs
     `(("python-pandas" ,python-pandas)
       ("python-matplotlib" ,python-matplotlib)
       ("python-numpy" ,python-numpy)
       ("python-scipy" ,python-scipy)))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("xorg-server" ,xorg-server)))
    (home-page "http://stanford.edu/~mwaskom/software/seaborn/")
    (synopsis "Statistical data visualization")
    (description
     "Seaborn is a library for making attractive and informative statistical
graphics in Python.  It is built on top of matplotlib and tightly integrated
with the PyData stack, including support for numpy and pandas data structures
and statistical routines from scipy and statsmodels.")
    (license license:bsd-3)))

(define-public python2-seaborn
  (package-with-python2 python-seaborn))

(define-public python-mpmath
  (package
  (name "python-mpmath")
  (version "0.19")
  (source (origin
            (method url-fetch)
            (uri (string-append "http://mpmath.org/files/mpmath-"
                                version ".tar.gz"))
            (sha256
             (base32
              "08ijsr4ifrqv3cjc26mkw0dbvyygsa99in376hr4b96ddm1gdpb8"))))
  (build-system python-build-system)
  (arguments
   '(#:phases
     (modify-phases %standard-phases
       (replace 'check
         (lambda _
           (invoke "python" "mpmath/tests/runtests.py" "-local"))))))
  (home-page "http://mpmath.org")
  (synopsis "Arbitrary-precision floating-point arithmetic in python")
  (description
    "@code{mpmath} can be used as an arbitrary-precision substitute for
Python's float/complex types and math/cmath modules, but also does much
more advanced mathematics.")
  (license license:bsd-3)))

(define-public python2-mpmath
  (package-with-python2 python-mpmath))

(define-public python-bigfloat
  (package
    (name "python-bigfloat")
    (version "0.3.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "bigfloat" version))
       (sha256
        (base32 "0xd7q4l7v0f463diznjv4k9wlaks80pn9drdqmfifi7zx8qvybi6"))))
    (build-system python-build-system)
    (inputs
     `(("mpfr" ,mpfr)))
    (home-page "https://github.com/mdickinson/bigfloat")
    (synopsis "Arbitrary precision floating-point arithmetic for Python")
    (description
     "This package provides a Python interface to the MPFR library for
multiprecision arithmetic.")
    (license license:lgpl3+)))

(define-public python2-bigfloat
  (package-with-python2 python-bigfloat))

(define-public python-sympy
  (package
    (name "python-sympy")
    (version "1.1.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/sympy/sympy/releases/download/sympy-"
             version "/sympy-" version ".tar.gz"))
       (sha256
        (base32 "190n29sppw7g8ihilc5451y7jlfcaw56crqiqbf1jff43dlmfnxc"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; Run the core tests after installation.  By default it would run
         ;; *all* tests, which take a very long time to complete and are known
         ;; to be flaky.
         (delete 'check)
         (add-after 'install 'check
           (lambda* (#:key outputs #:allow-other-keys)
             (invoke "python3" "-c" "import sympy; sympy.test(\"/core\")")
             #t)))))
    (propagated-inputs
     `(("python-mpmath" ,python-mpmath)))
    (home-page "http://www.sympy.org/")
    (synopsis "Python library for symbolic mathematics")
    (description
     "SymPy is a Python library for symbolic mathematics.  It aims to become a
full-featured computer algebra system (CAS) while keeping the code as simple
as possible in order to be comprehensible and easily extensible.")
    (license license:bsd-3)))

(define-public python2-sympy
  (package
    (inherit (package-with-python2 python-sympy))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; Run the core tests after installation.  By default it would run
         ;; *all* tests, which take a very long time to complete and are known
         ;; to be flaky.
         (delete 'check)
         (add-after 'install 'check
           (lambda* (#:key outputs #:allow-other-keys)
             (invoke "python" "-c" "import sympy; sympy.test(\"/core\")")
             #t)))))))

(define-public python-q
  (package
    (name "python-q")
    (version "2.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "q" version))
       (sha256
        (base32
         "1mgfazh8fkizh6walra2zv885f3lcgr3nb02v1frfm4p8ddcy3yy"))))
    (build-system python-build-system)
    (home-page "https://github.com/zestyping/q")
    (synopsis "Quick-and-dirty debugging output for tired programmers")
    (description
     "q is a Python module for \"print\" style of debugging Python code.  It
provides convenient short API for print out of values, tracebacks, and
falling into the Python interpreter.")
    (license license:asl2.0)))

(define-public python2-q
  (package-with-python2 python-q))

(define-public python2-xlib
  (package
    (name "python2-xlib")
    (version "0.14")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/python-xlib/python-xlib"
                                  "/" version "/"
                                  "python-xlib-" version ".tar.gz"))
              (sha256
               (base32
                "1sv0447j0rx8cgs3jhjl695p5pv13ihglcjlrrz1kq05lsvb0wa7"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2                         ;Python 2 only
       #:tests? #f))                              ;no tests
    (home-page "http://python-xlib.sourceforge.net/")
    (synopsis "Python X11 client library")
    (description
     "The Python X Library is intended to be a fully functional X client
library for Python programs.  It is useful to implement low-level X clients.
It is written entirely in Python.")
    (license license:gpl2+)))

(define-public python-singledispatch
  (package
    (name "python-singledispatch")
    (version "3.4.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "singledispatch" version))
       (sha256
        (base32
         "171b7ip0hsq5qm83np40h3phlr36ym18w0lay0a8v08kvy3sy1jv"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-six" ,python-six))) ; required for conversion, not at run-time
    (home-page
     "http://docs.python.org/3/library/functools.html#functools.singledispatch")
    (synopsis "Backport of singledispatch feature from Python 3.4")
    (description
     "This library brings functools.singledispatch from Python 3.4 to Python
2.6-3.3.")
    (license license:expat)))

(define-public python2-singledispatch
  (package-with-python2 python-singledispatch))

;; the python- version can be removed with python-3.5
(define-public python-backports-abc
  (package
    (name "python-backports-abc")
      (version "0.5")
      (source
        (origin
          (method url-fetch)
          (uri (pypi-uri "backports_abc" version))
          (sha256
           (base32
            "1pkv8d1zxj5f9i227dxbjczncbv7ks7ywnjwyxfjagm02i2yafq3"))))
    (build-system python-build-system)
    (home-page "https://github.com/cython/backports_abc")
    (synopsis "Backport of additions to the 'collections.abc' module")
    (description
     "Python-backports-abc provides a backport of additions to the
@code{collections.abc} module in Python-3.5.")
    (license license:psfl)))

(define-public python2-backports-abc
  (package-with-python2 python-backports-abc))

(define-public python-backports-csv
  (package
    (name "python-backports-csv")
    (version "1.0.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "backports.csv" version))
       (sha256
        (base32
         "1imzbrradkfn8s2m1qcimyn74dn1mz2p3j381jljn166rf2i6hlc"))))
    (build-system python-build-system)
    (home-page "https://github.com/ryanhiebert/backports.csv")
    (synopsis "Backport of Python 3's csv module for Python 2")
    (description
     "Provides a  backport of Python 3's @code{csv} module for parsing
comma separated values.  The API of the @code{csv} module in Python 2
is drastically different from the @code{csv} module in Python 3.
This is due, for the most part, to the difference between str in
Python 2 and Python 3.")
    (license license:psfl)))

(define-public python2-backports-csv
  (package-with-python2 python-backports-csv))

(define-public python2-backports-shutil-get-terminal-size
  (package
    (name "python2-backports-shutil-get-terminal-size")
    (version "1.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "backports.shutil_get_terminal_size" version))
       (sha256
        (base32
         "107cmn7g3jnbkp826zlj8rrj19fam301qvaqf0f3905f5217lgki"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (invoke "py.test" "-v"))))))
    (native-inputs
     `(("python2-pytest" ,python2-pytest)))
    (home-page "https://github.com/chrippa/backports.shutil_get_terminal_size")
    (synopsis "Backport of Python 3.3's @code{shutil.get_terminal_size}")
    (description
     "This package provides a backport of the @code{get_terminal_size
function} from Python 3.3's @code{shutil}.
Unlike the original version it is written in pure Python rather than C,
so it might be a tiny bit slower.")
    (license license:expat)))

(define-public python-waf
  (package
    (name "python-waf")
    (version "2.0.11")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://waf.io/"
                                  "waf-" version ".tar.bz2"))
              (sha256
               (base32
                "13zrniwkmfqgsgzi9v5m1367fppp9yzrz6z2ny6hy8dmpb8mj4z4"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'build
           (lambda _
             (invoke "python" "waf-light" "configure" "build")))
         (replace 'check
           (lambda _
             (invoke "python" "waf" "--version")))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (install-file "waf" (string-append out "/bin")))
             #t))
         ;; waf breaks when it is wrapped.
         (delete 'wrap))))
    (home-page "https://waf.io/")
    (synopsis "Python-based build system")
    (description
     "Waf is a Python-based framework for configuring, compiling and installing
applications.")
    (license license:bsd-3)))

(define-public python2-waf
  (package-with-python2 python-waf))

(define-public python-pyzmq
  (package
    (name "python-pyzmq")
    (version "17.1.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyzmq" version))
       (sha256
        (base32 "1pyxxrz60f88ffm0y6vpbx3q8jcr9ybz8fcilihwzwhh36n84ax7"))))
    (build-system python-build-system)
    (arguments
     `(#:configure-flags
       (list (string-append "--zmq=" (assoc-ref %build-inputs "zeromq")))
       ;; FIXME: You must build pyzmq with 'python setup.py build_ext
       ;; --inplace' for 'python setup.py test' to work.
       #:tests? #f))
    (inputs
     `(("zeromq" ,zeromq)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-nose" ,python-nose)))
    (home-page "https://github.com/zeromq/pyzmq")
    (synopsis "Python bindings for 0MQ")
    (description
     "PyZMQ is the official Python binding for the ZeroMQ messaging library.")
    (license license:bsd-4)))

(define-public python2-pyzmq
  (package-with-python2 python-pyzmq))

(define-public python-pep8
  ;; This package has been renamed to ‘pycodestyle’ and is no longer updated.
  ;; Its last release (1.7.1) adds only a scary warning to this effect, breaking
  ;; some dependents' test suites, and nothing more.
  (package
    (name "python-pep8")
    (version "1.7.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pep8" version))
        (sha256
          (base32
            "002rkl4lsn6x2mxmf8ar00l0m8i3mzrc6pnzz77blyksmpsxa4x1"))))
    (build-system python-build-system)
    (home-page "https://pep8.readthedocs.org/")
    (synopsis "Python style guide checker")
    (description
     "This tools checks Python code against some of the style conventions in
PEP 8.")
    (license license:expat)))

(define-public python2-pep8
  (package-with-python2 python-pep8))

(define-public python-pyflakes
  (package
    (name "python-pyflakes")
    (version "2.0.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pyflakes" version))
        (sha256
          (base32
            "0jba28czyvimdc72llms3f17swp3i8jdcabf5w0j00adfbn64xls"))))
    (build-system python-build-system)
    (home-page
      "https://github.com/pyflakes/pyflakes")
    (synopsis "Passive checker of Python programs")
    (description
      "Pyflakes statically checks Python source code for common errors.")
    (license license:expat)))

(define-public python2-pyflakes
  (package-with-python2 python-pyflakes))

(define-public python-mccabe
  (package
    (name "python-mccabe")
    (version "0.6.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "mccabe" version))
        (sha256
          (base32
            "07w3p1qm44hgxf3vvwz84kswpsx6s7kvaibzrsx5dzm0hli1i3fx"))))
    (build-system python-build-system)
    (native-inputs
      `(("python-pytest" ,python-pytest-bootstrap)
        ("python-pytest-runner" ,python-pytest-runner)))
    (home-page "https://github.com/flintwork/mccabe")
    (synopsis "McCabe checker, plugin for flake8")
    (description
      "This package provides a Flake8 plug-in to compute the McCabe cyclomatic
complexity of Python source code.")
    (license license:expat)))

(define-public python2-mccabe
  (package-with-python2 python-mccabe))

(define-public python-mccabe-0.2.1
  (package (inherit python-mccabe)
    (version "0.2.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "mccabe" version))
        (sha256
          (base32
            "0fi4a81kr5bcv5p4xgibqr595hyj5dafkqgsmfk96mfy8w71fajs"))))))

(define-public python2-mccabe-0.2.1
  (package-with-python2 python-mccabe-0.2.1))

;; Flake8 2.4.1 requires an older version of pep8.
;; This should be removed ASAP.
(define-public python-pep8-1.5.7
  (package (inherit python-pep8)
    (version "1.5.7")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pep8" version))
       (sha256
        (base32
         "12b9bbdbwnspxgak14xg58c130x2n0blxzlms5jn2dszn8qj3d0m"))))
    (arguments
     ;; XXX Tests not compatible with Python 3.5.
     '(#:tests? #f))))

(define-public python2-pep8-1.5.7
  (package-with-python2 python-pep8-1.5.7))

;; Flake8 2.4.1 requires an older version of pyflakes.
;; This should be removed ASAP.
(define-public python-pyflakes-0.8.1
  (package (inherit python-pyflakes)
    (version "0.8.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyflakes" version))
       (sha256
        (base32
         "0sbpq6pqm1i9wqi41mlfrsc5rk92jv4mskvlyxmnhlbdnc80ma1z"))))
    (arguments
     ;; XXX Tests not compatible with Python 3.5.
     '(#:tests? #f))))

(define-public python2-pyflakes-0.8.1
  (package-with-python2 python-pyflakes-0.8.1))

;; This package is used by hypothesis which has thousands of dependent packages.
;; FIXME: Consolidate this with "python-flake8" below in the next rebuild cycle.
(define-public python-flake8-3.5
  (package
    (name "python-flake8")
    (version "3.5.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "flake8" version))
        (sha256
          (base32
            "184b33grvvjmiwlv9kyd7yng9qv5ld24154j70z332xxg9gjclvj"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; Two errors don't seem to have assigned codes.
         (add-after 'unpack 'delete-broken-test
           (lambda _ (delete-file "tests/unit/test_pyflakes_codes.py") #t))
         (add-after 'unpack 'fix-problem-with-pycodestyle
           (lambda _
             ;; See https://gitlab.com/pycqa/flake8/merge_requests/230
             ;; This should no longer be needed with the next release.
             (substitute* "setup.py"
               (("PEP8_PLUGIN\\('break_around_binary_operator'\\),")
                "PEP8_PLUGIN('break_after_binary_operator'),\
PEP8_PLUGIN('break_before_binary_operator'),"))
             #t))
         (delete 'check)
         (add-after 'install 'check
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (add-installed-pythonpath inputs outputs)
             (invoke "pytest" "-v")
             #t)))))
    (propagated-inputs
     `(("python-pycodestyle" ,python-pycodestyle)
       ("python-pyflakes" ,python-pyflakes)
       ("python-mccabe" ,python-mccabe)))
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-pytest" ,python-pytest-bootstrap)
       ("python-pytest-runner" ,python-pytest-runner)))
    (home-page "https://gitlab.com/pycqa/flake8")
    (synopsis
      "The modular source code checker: pep8, pyflakes and co")
    (description
      "Flake8 is a wrapper around PyFlakes, pep8 and python-mccabe.")
    (properties `((python2-variant . ,(delay python2-flake8-3.5))))
    (license license:expat)))

(define-public python2-flake8-3.5
  (let ((base (package-with-python2 (strip-python2-variant python-flake8-3.5))))
    (package (inherit base)
      (propagated-inputs
       `(("python2-configparser" ,python2-configparser)
         ("python2-enum34" ,python2-enum34)
          ,@(package-propagated-inputs base))))))

;; Version 3.5.0 has compatibility issues with Pyflakes 2.0, so we need
;; this newer version.  Keep it as a separate variable for now to avoid
;; rebuilding "python-hypothesis"; this should be removed in the next
;; rebuild cycle.
(define-public python-flake8
  (package
    (inherit python-flake8-3.5)
    (version "3.6.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "flake8" version))
              (sha256
               (base32
                "0w0nprx22rbvrrkbfx9v5jc5gskbm08g219l7r8wai8zfswgadba"))))
    (arguments
     (substitute-keyword-arguments (package-arguments python-flake8-3.5)
       ((#:phases phases)
        `(modify-phases ,phases
           (delete 'delete-broken-test)
           (delete 'fix-problem-with-pycodestyle)))))
    (properties `((python2-variant . ,(delay python2-flake8))))))

(define-public python2-flake8
  (let ((base (package-with-python2 (strip-python2-variant python-flake8))))
    (package (inherit base)
             (propagated-inputs
              (package-propagated-inputs python2-flake8-3.5)))))

;; python-hacking requires flake8 <2.6.0.
(define-public python-flake8-2.5
  (package
    (inherit python-flake8)
    (version "2.5.5")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "flake8" version))
              (sha256
               (base32
                "1snylqwbmrylbx3r1wpz8ggk98f6bcag4441ag8mm2l7wyn58sij"))))
    (propagated-inputs
     `(("python-pep8" ,python-pep8)
       ,@(package-propagated-inputs python-flake8)))
    (properties `((python2-variant . ,(delay python2-flake8-2.5))))))

(define-public python2-flake8-2.5
  (package
    (inherit python2-flake8)
    (version (package-version python-flake8-2.5))
    (source (origin
              (inherit (package-source python-flake8-2.5))))
    (propagated-inputs
     `(("python2-pep8" ,python2-pep8)
       ,@(package-propagated-inputs python2-flake8)))))

(define-public python-flake8-polyfill
  (package
    (name "python-flake8-polyfill")
    (version "1.0.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "flake8-polyfill" version))
       (sha256
        (base32
         "1nlf1mkqw856vi6782qcglqhaacb23khk9wkcgn55npnjxshhjz4"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (setenv "PYTHONPATH"
                     (string-append (getcwd) "/build/lib:"
                                    (getenv "PYTHONPATH")))
             (invoke "py.test" "-v"))))))
    (native-inputs
     `(("python-flake8" ,python-flake8)
       ("python-mock" ,python-mock)
       ("python-pep8" ,python-pep8)
       ("python-pycodestyle" ,python-pycodestyle)
       ("python-pytest" ,python-pytest)))
    (home-page "https://gitlab.com/pycqa/flake8-polyfill")
    (synopsis "Polyfill package for Flake8 plugins")
    (description
     "This package that provides some compatibility helpers for Flake8
plugins that intend to support Flake8 2.x and 3.x simultaneously.")
    (license license:expat)))

(define-public python2-flake8-polyfill
  (package-with-python2 python-flake8-polyfill))

(define-public python-mistune
  (package
    (name "python-mistune")
    (version "0.8.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "mistune" version))
       (sha256
        (base32
         "0vkmsh0x480rni51lhyvigfdf06b9247z868pk3bal1wnnfl58sr"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-cython" ,python-cython)))
    (home-page "https://github.com/lepture/mistune")
    (synopsis "Markdown parser in pure Python")
    (description "This package provides a fast markdown parser in pure
Python.")
    (license license:bsd-3)))

(define-public python2-mistune
  (package-with-python2 python-mistune))

(define-public python-markdown
  (package
    (name "python-markdown")
    (version "3.1.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Markdown" version))
       (sha256
        (base32
         "0yhylk4ffqqs7x086fav4pnfsl1021v7lghznzkififprmmqfl1f"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-pyyaml" ,python-pyyaml)))
    (home-page "https://python-markdown.github.io/")
    (synopsis "Python implementation of Markdown")
    (description
     "This package provides a Python implementation of John Gruber's
Markdown.  The library features international input, various Markdown
extensions, and several HTML output formats.  A command line wrapper
markdown_py is also provided to convert Markdown files to HTML.")
    (license license:bsd-3)))

(define-public python2-markdown
  (package-with-python2 python-markdown))

(define-public python-ptyprocess
  (package
    (name "python-ptyprocess")
    (version "0.5.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ptyprocess" version))
       (sha256
        (base32
         "0ra31k10v3629xq0kdn8lwmfbi97anmk48r03yvh7mks0kq96hg6"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _ (invoke "nosetests"))))))
    (home-page "https://github.com/pexpect/ptyprocess")
    (synopsis "Run a subprocess in a pseudo terminal")
    (description
     "This package provides a Python library used to launch a subprocess in a
pseudo terminal (pty), and interact with both the process and its pty.")
    (license license:isc)))

(define-public python2-ptyprocess
  (package-with-python2 python-ptyprocess))

(define-public python-cram
  (package
    (name "python-cram")
    (version "0.7")
    (home-page "https://bitheap.org/cram/")
    (source (origin
              (method url-fetch)
              (uri (list (string-append home-page "cram-"
                                        version ".tar.gz")
                         (pypi-uri "cram" version)))
              (sha256
               (base32
                "0bvz6fwdi55rkrz3f50zsy35gvvwhlppki2yml5bj5ffy9d499vx"))))
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-source
           (lambda _
             (substitute* (find-files "cram" ".*\\.py$")
               ;; Replace default shell path.
               (("/bin/sh") (which "sh")))
             (substitute* (find-files "tests" ".*\\.t$")
               (("md5") "md5sum")
               (("/bin/bash") (which "bash"))
               (("/bin/sh") (which "sh")))
             (substitute* "cram/_test.py"
               ;; This hack works around a bug triggered by substituting
               ;; the /bin/sh paths. "tests/usage.t" compares the output of
               ;; "cram -h", which breaks the output at 80 characters. This
               ;; causes the line showing the default shell to break into two
               ;; lines, but the test expects a single line...
               (("env\\['COLUMNS'\\] = '80'")
                "env['COLUMNS'] = '160'"))
             #t))
         (delete 'check)
         (add-after 'install 'check
           ;; The test phase uses the built library and executable.
           ;; It's easier to run it after install since the build
           ;; directory contains version-specific PATH.
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (add-installed-pythonpath inputs outputs)
             (setenv "PATH" (string-append (getenv "PATH") ":"
                                           (assoc-ref outputs "out") "/bin"))
             (invoke "make" "test"))))))
    (build-system python-build-system)
    (native-inputs
     `(("python-coverage" ,python-coverage)
       ("which" ,which)))
    (synopsis "Simple testing framework for command line applications")
    (description
     "Cram is a functional testing framework for command line applications.
Cram tests look like snippets of interactive shell sessions.  Cram runs each
command and compares the command output in the test with the command’s actual
output.")
    (license license:gpl2+)))

(define-public python2-cram
  (package-with-python2 python-cram))

(define-public python-straight-plugin
  (package
    (name "python-straight-plugin")
    (version "1.4.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "straight.plugin" version))
       (sha256
        (base32
         "069pjll4383p4kkgvcc40hgyvf79j2wdbpgwz77yigzxksh1gj62"))))
    (build-system python-build-system)
    (home-page "https://github.com/ironfroggy/straight.plugin")
    (synopsis "Simple namespaced plugin facility")
    (description "Straight Plugin provides a type of plugin you can create from
almost any existing Python modules, and an easy way for outside developers to
add functionality and customization to your projects with their own plugins.")
    (license license:expat)))

(define-public python2-straight-plugin
  (package-with-python2 python-straight-plugin))

(define-public python-fonttools
  (package
    (name "python-fonttools")
    (version "3.28.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "fonttools" version ".zip"))
              (sha256
               (base32
                "0vsvjhidpb5kywpjgz1j3fywzkddxkb0afqai18qa3h6lqjyxwpb"))))
    (build-system python-build-system)
    (native-inputs
     `(("unzip" ,unzip)
       ("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)))
    (home-page "https://github.com/behdad/fonttools")
    (synopsis "Tools to manipulate font files")
    (description
     "FontTools/TTX is a library to manipulate font files from Python.  It
supports reading and writing of TrueType/OpenType fonts, reading and writing
of AFM files, reading (and partially writing) of PS Type 1 fonts.  The package
also contains a tool called “TTX” which converts TrueType/OpenType fonts to and
from an XML-based format.")
    (license license:expat)))

(define-public python2-fonttools
  (package-with-python2 python-fonttools))

(define-public python-ly
  (package
    (name "python-ly")
    (version "0.9.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri name version))
       (sha256
        (base32
         "0x98dv7p8mg26p4816yy8hz4f34zf6hpnnfmr56msgh9jnsm2qfl"))))
    (build-system python-build-system)
    (arguments
     ;; FIXME: Some tests need network access.
     '(#:tests? #f))
    (synopsis "Tool and library for manipulating LilyPond files")
    (description "This package provides a Python library to parse, manipulate
or create documents in LilyPond format.  A command line program ly is also
provided that can be used to do various manipulations with LilyPond files.")
    (home-page "https://pypi.python.org/pypi/python-ly")
    (license license:gpl2+)))

(define-public python-appdirs
  (package
    (name "python-appdirs")
    (version "1.4.3")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "appdirs" version))
        (sha256
          (base32
            "14id6wxi12lgyw0mg3bcfnf888ad07jz9yj46gfzhn186z8rcn4y"))))
    (build-system python-build-system)
    (home-page "https://github.com/ActiveState/appdirs")
    (synopsis
      "Determine platform-specific dirs, e.g. a \"user data dir\"")
    (description
      "This module provides a portable way of finding out where user data
should be stored on various operating systems.")
    (license license:expat)))

(define-public python2-appdirs
  (package-with-python2 python-appdirs))

(define-public python-gorilla
  (package
    (name "python-gorilla")
    (version "0.3.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "gorilla" version))
              (sha256
               (base32
                "0b40blcp6fih4nvqbilra4qw1dfccv1ahjmr41ac4d9rjadqkcpy"))))
    (build-system python-build-system)
    (home-page "https://github.com/christophercrouzet/gorilla")
    (synopsis "Convenient monkey patching with Python")
    (description
     "Gorilla is a Python library that provides a convenient approach to
monkey patching.  Monkey patching is the process of modifying module and
class attributes at runtime with the purpose of replacing or extending
third-party code.")
    (license license:expat)))

(define-public python-llfuse
  (package
    (name "python-llfuse")
    (version "1.3.5")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "llfuse" version ".tar.bz2"))
              (sha256
               (base32
                "1n7a90jww3ly49fm7x27m3xw3la3qfrnykcakga654g6kcyjlhbf"))))
    (build-system python-build-system)
    (inputs
     `(("fuse" ,fuse)
       ("attr" ,attr)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (synopsis "Python bindings for FUSE")
    (description
     "Python-LLFUSE is a set of Python bindings for the low level FUSE API.")
    (home-page "https://bitbucket.org/nikratio/python-llfuse/")
    (license license:lgpl2.0+)
    (properties `((python2-variant . ,(delay python2-llfuse))))))

(define-public python2-llfuse
  (package (inherit (package-with-python2
                 (strip-python2-variant python-llfuse)))
    (propagated-inputs `(("python2-contextlib2" ,python2-contextlib2)))))

;; For attic-0.16
(define-public python-llfuse-0.41
  (package (inherit python-llfuse)
    (version "0.41.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://bitbucket.org/nikratio/python-llfuse/downloads/"
                    "llfuse-" version ".tar.bz2"))
              (sha256
               (base32
                "1imlqw9b73086y97izr036f58pgc5akv4ihc2rrf8j5h75jbrlaa"))))
    ;; Python-LLFUSE < 0.42 includes underscore.js, which is MIT (expat)
    ;; licensed.  The rest of the package is licensed under LGPL2.0 or later.
    (license (list license:expat license:lgpl2.0+))))

(define-public python-msgpack
  (package
    (name "python-msgpack")
    (version "0.5.6")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "msgpack" version))
              (sha256
               (base32
                "1hz2dba1nvvn52afg34liijsm7kn65cmn06dl0xbwld6bb4cis0f"))))
    (build-system python-build-system)
    (arguments
     `(#:modules ((guix build utils)
                  (guix build python-build-system)
                  (ice-9 ftw)
                  (srfi srfi-1)
                  (srfi srfi-26))
       #:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (let ((cwd (getcwd)))
               (setenv "PYTHONPATH"
                       (string-append cwd "/build/"
                                      (find (cut string-prefix? "lib" <>)
                                            (scandir (string-append cwd "/build")))
                                      ":"
                                      (getenv "PYTHONPATH")))
             (invoke "pytest" "-v" "test")))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (synopsis "MessagePack (de)serializer")
    (description "MessagePack is a fast, compact binary serialization format,
suitable for similar data to JSON.  This package provides CPython bindings for
reading and writing MessagePack data.")
    (home-page "https://pypi.python.org/pypi/msgpack/")
    (license license:asl2.0)))

;; This msgpack library's name changed from "python-msgpack" to "msgpack" with
;; release 0.5. Some packages like borg still call it by the old name for now.
;; <https://bugs.gnu.org/30662>
(define-public python-msgpack-transitional
  (package
    (inherit python-msgpack)
    (name "python-msgpack-transitional")
    (arguments
     (substitute-keyword-arguments (package-arguments python-msgpack)
       ((#:phases phases)
        `(modify-phases ,phases
           (add-after 'unpack 'configure-transitional
             (lambda _
               ;; Keep using the old name.
               (substitute* "setup.py"
                 (("TRANSITIONAL = False")
                   "TRANSITIONAL = 1"))
               #t))))))))

(define-public python2-msgpack
  (package-with-python2 python-msgpack))

(define-public python-netaddr
  (package
    (name "python-netaddr")
    (version "0.7.19")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "netaddr" version))
       (sha256
         (base32
          "1zdfadvpq4lmcqzr383gywxn4xyn355kj1n3lk9q2l03vmyfrbiq"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f)) ;; No tests.
    (home-page "https://github.com/drkjam/netaddr/")
    (synopsis "Pythonic manipulation of  network addresses")
    (description
      "A Python library for representing and manipulating IPv4, IPv6, CIDR, EUI
and MAC network addresses.")
    (license license:bsd-3)))

(define-public python2-netaddr
  (package-with-python2 python-netaddr))

(define-public python2-pyroute2
  (package
    (name "python2-pyroute2")
    (version "0.5.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyroute2" version))
       (sha256
        (base32
         "1gmz4r1w0yzj6fjjypnalmfyy0lnfznydyn62gi3wk50j5hhxbny"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2))                       ;Python 3.x is not supported
    (home-page "https://github.com/svinota/pyroute2")
    (synopsis "Python netlink library")
    (description
     "Pyroute2 is a pure Python netlink library with minimal dependencies.
Supported netlink families and protocols include:
@itemize
@item rtnl, network settings - addresses, routes, traffic controls
@item nfnetlink - netfilter API: ipset, nftables, ...
@item ipq - simplest userspace packet filtering, iptables QUEUE target
@item devlink - manage and monitor devlink-enabled hardware
@item generic - generic netlink families
  @itemize
  @item nl80211 - wireless functions API (basic support)
  @item taskstats - extended process statistics
  @item acpi_events - ACPI events monitoring
  @item thermal_events - thermal events monitoring
  @item VFS_DQUOT - disk quota events monitoring
  @end itemize
@end itemize")
    (license license:gpl2+)))

(define-public python-wrapt
  (package
    (name "python-wrapt")
    (version "1.11.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "wrapt" version))
        (sha256
          (base32
            "0cqmysny1pz01jw26q48q5zasvns6507rwhgm6wcw743f0r01sja"))))
    (build-system python-build-system)
    (arguments
     ;; Tests are not included in the tarball, they are only available in the
     ;; git repository.
     `(#:tests? #f))
    (home-page "https://github.com/GrahamDumpleton/wrapt")
    (synopsis "Module for decorators, wrappers and monkey patching")
    (description
      "The aim of the wrapt module is to provide a transparent object proxy for
  Python, which can be used as the basis for the construction of function
  wrappers and decorator functions.")
    (license license:bsd-2)))

(define-public python2-wrapt
  (package-with-python2 python-wrapt))

(define-public python-xlrd
  (package
    (name "python-xlrd")
    (version "1.0.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "xlrd" version))
              (sha256
               (base32
                "0s8hjiz01vbhy85xalrz0qlsmd9ypf36zjqrf97hh984spapvy0g"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; Current test in setup.py does not work as of 1.0.0, so use nose to
         ;; run tests instead for now.
         (replace 'check (lambda _ (invoke "nosetests"))))))
    (native-inputs `(("python-nose"       ,python-nose)))
    (home-page "http://www.python-excel.org/")
    (synopsis "Library for extracting data from Excel files")
    (description "This package provides a library to extract data from
spreadsheets using Microsoft Excel proprietary file formats @samp{.xls} and
@samp{.xlsx} (versions 2.0 onwards).  It has support for Excel dates and is
Unicode-aware.  It is not intended as an end-user tool.")
    (license license:bsd-3)))

(define-public python2-xlrd
  (package-with-python2 python-xlrd))

(define-public python-prettytable
  (package
    (name "python-prettytable")
    (version "0.7.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "prettytable" version ".tar.bz2"))
       (sha256
        (base32
         "0diwsicwmiq2cpzpxri7cyl5fmsvicafw6nfqf6p6p322dji2g45"))))
    (build-system python-build-system)
    (home-page "http://code.google.com/p/prettytable/")
    (synopsis "Display tabular data in an ASCII table format")
    (description
      "A library designed to represent tabular data in visually appealing ASCII
tables.  PrettyTable allows for selection of which columns are to be printed,
independent alignment of columns (left or right justified or centred) and
printing of sub-tables by specifying a row range.")
    (license license:bsd-3)))

(define-public python2-prettytable
  (package-with-python2 python-prettytable))

(define-public python-tables
  (package
    (name "python-tables")
    (version "3.4.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "tables" version))
       (sha256
        (base32
         "0affz7k8babh8wdmsgrz5jxrd569by2w8ffimcxs9wiaf5rw1idx"))
       (modules '((guix build utils)))
       (snippet
        '(begin
           ;; Remove pre-compiled .pyc files from source.
           (for-each delete-file-recursively
                     (find-files "." "__pycache__" #:directories? #t))
           (for-each delete-file (find-files "." "\\.pyc$"))
           #t))))
    (build-system python-build-system)
    (arguments
     `(;; FIXME: python-build-system does not pass configure-flags to "build"
       ;; or "check", so we must override the build and check phases.
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'use-gcc
           (lambda _
             (substitute* "setup.py"
               (("compiler = new_compiler\\(\\)" line)
                (string-append line
                               "\ncompiler.set_executables(compiler='gcc',"
                               "compiler_so='gcc',"
                               "linker_exe='gcc',"
                               "linker_so='gcc -shared')")))
             #t))
         (replace 'build
           (lambda* (#:key inputs #:allow-other-keys)
             (invoke "python" "setup.py" "build"
                     (string-append "--hdf5="
                                    (assoc-ref inputs "hdf5")))))
         (replace 'check
           (lambda* (#:key inputs #:allow-other-keys)
             (invoke "python" "setup.py" "check"
                     (string-append "--hdf5="
                                    (assoc-ref inputs "hdf5"))))))))
    (propagated-inputs
     `(("python-numexpr" ,python-numexpr)
       ("python-numpy" ,python-numpy)))
    (native-inputs
     `(("python-cython" ,python-cython)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("hdf5" ,hdf5)
       ("bzip2" ,bzip2)
       ("zlib" ,zlib)))
    (home-page "http://www.pytables.org/")
    (synopsis "Hierarchical datasets for Python")
    (description "PyTables is a package for managing hierarchical datasets and
designed to efficiently cope with extremely large amounts of data.")
    (license license:bsd-3)))

(define-public python2-tables
  (package-with-python2 python-tables))

(define-public python-pyasn1
  (package
    (name "python-pyasn1")
    (version "0.4.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyasn1" version))
       (sha256
        (base32
         "1z5h38anjzzrxpraa9iq9llffyx2zs8gx0q6dc1g029miwnn50gv"))))
    (build-system python-build-system)
    (home-page "http://pyasn1.sourceforge.net/")
    (synopsis "ASN.1 types and codecs")
    (description
     "This is an implementation of ASN.1 types and codecs in Python.  It is
suitable for a wide range of protocols based on the ASN.1 specification.")
    (license license:bsd-2)))

(define-public python2-pyasn1
  (package-with-python2 python-pyasn1))

(define-public python-pyasn1-modules
  (package
    (name "python-pyasn1-modules")
    (version "0.2.2")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pyasn1-modules" version))
        (sha256
         (base32
          "0ivm850yi7ajjbi8j115qpsj95bgxdsx48nbjzg0zip788c3xkx0"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pyasn1" ,python-pyasn1)))
    (home-page "https://sourceforge.net/projects/pyasn1/")
    (synopsis "ASN.1 codec implementations")
    (description
     "Pyasn1-modules is a collection of Python modules providing ASN.1 types and
implementations of ASN.1-based codecs and protocols.")
    (license license:bsd-3)))

(define-public python2-pyasn1-modules
  (package-with-python2 python-pyasn1-modules))

(define-public python-querystring-parser
  (package
    (name "python-querystring-parser")
    (version "1.2.4")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "querystring_parser" version))
              (sha256
               (base32
                "0qlar8a0wa003hm2z6wcpb625r6vjj0a70rsni9h8lz0zwfcwkv4"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      ;; XXX FIXME: This test is broken with Python 3.7.
                      (substitute* "querystring_parser/tests.py"
                        (("self\\.assertEqual\\(self\\.knownValuesNormalized, result\\)")
                         "True"))
                      (invoke "python" "querystring_parser/tests.py"))))))
    (propagated-inputs
     `(("python-six" ,python-six)))
    (home-page "https://github.com/bernii/querystring-parser")
    (synopsis "QueryString parser that correctly handles nested dictionaries")
    (description
     "This package provides a query string parser for Python and Django
projects that correcly creates nested dictionaries from sent form/querystring
data.")
    (license license:expat)))

(define-public python-ipaddress
  (package
    (name "python-ipaddress")
    (version "1.0.22")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "ipaddress" version))
              (sha256
               (base32
                "0b570bm6xqpjwqis15pvdy6lyvvzfndjvkynilcddjj5x98wfimi"))))
    (build-system python-build-system)
    (home-page "https://github.com/phihag/ipaddress")
    (synopsis "IP address manipulation library")
    (description
      "This package provides a fast, lightweight IPv4/IPv6 manipulation library
 in Python.  This library is used to create, poke at, and manipulate IPv4 and
 IPv6 addresses and networks.  This is a port of the Python 3.3 ipaddress
 module to older versions of Python.")
    (license license:psfl)))

(define-public python2-ipaddress
  (package-with-python2 python-ipaddress))

(define-public python2-ipaddr
  (package
    (name "python2-ipaddr")
    (version "2.1.11")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ipaddr" version))
       (sha256
        (base32 "1dwq3ngsapjc93fw61rp17fvzggmab5x1drjzvd4y4q0i255nm8v"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2                         ;version 2 only
       #:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _ (invoke "python" "ipaddr_test.py"))))))
    (home-page "https://github.com/google/ipaddr-py")
    (synopsis "IP address manipulation library")
    (description
     "Ipaddr is a Python@tie{}2 library for creating and manupilating IPv4 and
IPv6 addresses and networks.

For new implementations you may prefer to use the standard module
@code{ipaddress}, which was introduced in Python 3.3 and backported to older
versions of Python.")
    (license license:asl2.0)))

(define-public python-idna
  (package
    (name "python-idna")
    (version "2.8")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "idna" version))
       (sha256
        (base32
         "01rlkigdxg17sf9yar1jl8n18ls59367wqh59hnawlyg53vb6my3"))))
    (build-system python-build-system)
    (home-page "https://github.com/kjd/idna")
    (synopsis "Internationalized domain names in applications")
    (description
     "This is a library to support the Internationalised Domain Names in
Applications (IDNA) protocol as specified in RFC 5891.  This version of the
protocol is often referred to as “IDNA2008” and can produce different results
from the earlier standard from 2003.  The library is also intended to act as a
suitable drop-in replacement for the “encodings.idna” module that comes with
the Python standard library but currently only supports the older 2003
specification.")
    (license license:bsd-4)))

(define-public python-idna-2.7
  (package (inherit python-idna)
           (version "2.7")
           (source (origin
                     (method url-fetch)
                     (uri (pypi-uri "idna" version))
                     (sha256
                      (base32
                       "05jam7d31767dr12x0rbvvs8lxnpb1mhdb2zdlfxgh83z6k3hjk8"))))))


(define-public python2-idna
  (package-with-python2 python-idna))

(define-public python-idna-ssl
  (package
    (name "python-idna-ssl")
    (version "1.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "idna-ssl" version))
       (sha256
        (base32
         "0ydrc8hpg9mdr5hqq1lqfsfbn6sjq69slwpfrnlrm3k0phqg14qj"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))          ;circular dependency with python-aiohttp
    (home-page "https://github.com/aio-libs/idna-ssl")
    (synopsis "Patch @code{ssl.match_hostname} for Unicode(idna) domains support")
    (description "Patch @code{ssl.match_hostname} for Unicode(idna)
domains support.")
    (license license:expat)))

(define-public python-pretend
  (package
    (name "python-pretend")
    (version "1.0.9")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pretend" version))
       (sha256
        (base32
         "040vm94lcbscg5p81g1icmwwwa2jm7wrd1ybmxnv1sz8rl8bh3n9"))))
    (build-system python-build-system)
    (home-page "https://github.com/alex/pretend")
    (synopsis "Library for stubbing in Python")
    (description
     "Pretend is a library to make stubbing with Python easier.  Stubbing is a
technique for writing tests.  You may hear the term mixed up with mocks,
fakes, or doubles.  Basically, a stub is an object that returns pre-canned
responses, rather than doing any computation.")
    (license license:bsd-3)))

(define-public python2-pretend
  (package-with-python2 python-pretend))

(define-public python-pip
  (package
    (name "python-pip")
    (version "18.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pip" version))
       (sha256
        (base32
         "188fclay154s520n43s7cxxlhdaiysvxf19zk8vr1xbyjyyr58n0"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f))          ; there are no tests in the pypi archive.
    (home-page "https://pip.pypa.io/")
    (synopsis "Package manager for Python software")
    (description
     "Pip is a package manager for Python software, that finds packages on the
Python Package Index (PyPI).")
    (license license:expat)))

(define-public python2-pip
  (package-with-python2 python-pip))

(define-public python-tlsh
  (package
    (name "python-tlsh")
    (version "3.4.5")
    (home-page "https://github.com/trendmicro/tlsh")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/trendmicro/tlsh.git")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32 "1ydliir308xn4ywy705mmsh7863ldlixdvpqwdhbipzq9vfpmvll"))))
    (build-system cmake-build-system)
    (arguments
     '(#:out-of-source? #f
       #:phases (modify-phases %standard-phases
                  (replace
                   'install
                   (lambda* (#:key outputs #:allow-other-keys)
                     ;; Build and install the Python bindings.  The underlying
                     ;; C++ library is apparently not meant to be installed.
                     (let ((out (assoc-ref outputs "out")))
                       (with-directory-excursion "py_ext"
                         (and (system* "python" "setup.py" "build")
                              (system* "python" "setup.py" "install"
                                       (string-append "--prefix=" out))))))))))
    (inputs `(("python" ,python-wrapper)))        ;for the bindings
    (synopsis "Fuzzy matching library for Python")
    (description
     "Trend Micro Locality Sensitive Hash (TLSH) is a fuzzy matching library.
Given a byte stream with a minimum length of 256 bytes, TLSH generates a hash
value which can be used for similarity comparisons.  Similar objects have
similar hash values, which allows for the detection of similar objects by
comparing their hash values.  The byte stream should have a sufficient amount
of complexity; for example, a byte stream of identical bytes will not generate
a hash value.")
    (license license:asl2.0)))

(define-public python2-tlsh
  (package
    (inherit python-tlsh)
    (name "python2-tlsh")
    (inputs `(("python" ,python-2)))))

(define-public python-termcolor
  (package
    (name "python-termcolor")
    (version "1.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "termcolor" version))
       (sha256
        (base32
         "0fv1vq14rpqwgazxg4981904lfyp84mnammw7y046491cv76jv8x"))))
    (build-system python-build-system)
    (arguments
     ;; There are no tests.
     `(#:tests? #f))
    (home-page "https://pypi.python.org/pypi/termcolor")
    (synopsis "ANSII Color formatting for terminal output")
    (description
     "This package provides ANSII Color formatting for output in terminals.")
    (license license:expat)))

(define-public python2-termcolor
  (package-with-python2 python-termcolor))

(define-public python-libarchive-c
  (package
    (name "python-libarchive-c")
    (version "2.8")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "libarchive-c" version))
              (sha256
               (base32
                "0qg0v1s9c1xdk9philhnv8k6c6nicvnvfwlc0j9srg90jmdlvm06"))))
    (build-system python-build-system)
    (arguments
     '(#:phases (modify-phases %standard-phases
                  (add-before
                   'build 'reference-libarchive
                   (lambda* (#:key inputs #:allow-other-keys)
                     ;; Retain the absolute file name of libarchive.so.
                     (let ((libarchive (assoc-ref inputs "libarchive")))
                       (substitute* "libarchive/ffi.py"
                         (("find_library\\('archive'\\)")
                          (string-append "'" libarchive
                                         "/lib/libarchive.so'"))))))
                  (replace 'check
                    (lambda _ (invoke "pytest" "-vv"))))))
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-pytest" ,python-pytest)))
    (inputs
     `(("libarchive" ,libarchive)))
    (home-page "https://github.com/Changaco/python-libarchive-c")
    (synopsis "Python interface to libarchive")
    (description
     "This package provides Python bindings to libarchive, a C library to
access possibly compressed archives in many different formats.  It uses
Python's @code{ctypes} foreign function interface (FFI).")
    (license license:lgpl2.0+)))

(define-public python2-libarchive-c
  (package-with-python2 python-libarchive-c))

(define-public python-file
  (package
    (inherit file)
    (name "python-file")
    (build-system python-build-system)
    (arguments
     '(#:tests? #f                                ;no tests
       #:configure-flags '("--single-version-externally-managed" "--root=/")
       #:phases (modify-phases %standard-phases
                  (add-before 'build 'change-directory
                    (lambda _
                      (chdir "python")
                      #t))
                  (add-before 'build 'set-library-file-name
                    (lambda* (#:key inputs #:allow-other-keys)
                      (let ((file (assoc-ref inputs "file")))
                        (substitute* "magic.py"
                          (("find_library\\('magic'\\)")
                           (string-append "'" file "/lib/libmagic.so'")))
                        #t))))))
    (inputs `(("file" ,file)))
    (native-inputs (if (%current-target-system)
                       `(("self" ,this-package))
                       '()))
    (synopsis "Python bindings to the libmagic file type guesser.  Note that
this module and the python-magic module both provide a \"magic.py\" file;
these two modules, which are different and were developed separately, both
serve the same purpose: provide Python bindings for libmagic.")))

(define-public python2-file
  (package-with-python2 python-file))

(define-public python-debian
  (package
    (name "python-debian")
    (home-page "https://salsa.debian.org/python-debian-team/python-debian")
    (version "0.1.28")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri name version))
       (sha256
        (base32
         "0i15f0xzx679sd0ldq2sls9pnnps9fv6vhqvnv9dzf4qhma42i0y"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)))
    (synopsis "Debian package related modules")
    (description
     ;; XXX: Use @enumerate instead of @itemize to work around
     ;; <http://bugs.gnu.org/21772>.
     "This package provides Python modules that abstract many formats of
Debian-related files, such as:

@enumerate
@item Debtags information;
@item @file{debian/changelog} files;
@item packages files, pdiffs;
@item control files of single or multiple RFC822-style paragraphs---e.g.
   @file{debian/control}, @file{.changes}, @file{.dsc};
@item Raw @file{.deb} and @file{.ar} files, with (read-only) access to
   contained files and meta-information.
@end enumerate\n")

    ;; Modules are either GPLv2+ or GPLv3+.
    (license license:gpl3+)))

(define-public python2-debian
  (package-with-python2 python-debian))

(define-public python-nbformat
  (package
    (name "python-nbformat")
    (version "4.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "nbformat" version))
       (sha256
        (base32
         "00nlf08h8yc4q73nphfvfhxrcnilaqanb8z0mdy6nxk0vzq4wjgp"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f)) ; no test target
    (propagated-inputs
     `(("python-ipython-genutils" ,python-ipython-genutils)
       ("python-jsonschema" ,python-jsonschema)
       ("python-jupyter-core" ,python-jupyter-core)
       ("python-traitlets" ,python-traitlets)))
    (home-page "http://jupyter.org")
    (synopsis "Jupyter Notebook format")
    (description "This package provides the reference implementation of the
Jupyter Notebook format and Python APIs for working with notebooks.")
    (license license:bsd-3)))

(define-public python2-nbformat
  (package-with-python2 python-nbformat))

(define-public python-bleach
  (package
    (name "python-bleach")
    (version "1.4.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "bleach" version))
       (sha256
        (base32
         "0jvg3jxrvnx7xmm9gj262v60ib452xlnwlb0navyp7jsvcd0d4qj"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-html5lib" ,python-html5lib-0.9)
       ("python-six" ,python-six)))
    (native-inputs
     `(("python-nose" ,python-nose)))
    (home-page "https://github.com/jsocol/bleach")
    (synopsis "Whitelist-based HTML-sanitizing tool")
    (description "Bleach is an easy whitelist-based HTML-sanitizing tool.")
    (license license:asl2.0)))

(define-public python2-bleach
  (package-with-python2 python-bleach))

(define-public python-entrypoints
  (package
    (name "python-entrypoints")
    (version "0.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "entrypoints" version))
       (sha256
        (base32
         "0lc4si3xb7hza424414rdqdc3vng3kcrph8jbvjqb32spqddf3f7"))))
    (build-system python-build-system)
    ;; The package does not come with a setup.py file, so we have to generate
    ;; one ourselves.
    (arguments
     `(#:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'create-setup.py
           (lambda _
             (call-with-output-file "setup.py"
               (lambda (port)
                 (format port "\
from setuptools import setup
setup(name='entrypoints', version='~a', py_modules=['entrypoints'])
" ,version))))))))
    (home-page "https://github.com/takluyver/entrypoints")
    (synopsis "Discover and load entry points from installed Python packages")
    (description "Entry points are a way for Python packages to advertise
objects with some common interface.  The most common examples are
@code{console_scripts} entry points, which define shell commands by
identifying a Python function to run.  The @code{entrypoints} module contains
functions to find and load entry points.")
    (license license:expat)))

(define-public python2-entrypoints
  (package-with-python2 python-entrypoints))

(define-public python-nbconvert
  (package
    (name "python-nbconvert")
    (version "5.0.0b1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "nbconvert" version))
       (sha256
        (base32
         "0brclbb18l4nmd5qy3dl9wn05rjdh1fz4rmzdlfqacj12rcdvdgp"))))
    (build-system python-build-system)
    (arguments
     `(;; The "bdist_egg" target is disabled by default, causing the installation
       ;; to fail.
       #:configure-flags (list "bdist_egg")
       ;; FIXME: 5 failures, 40 errors.
       #:tests? #f))
       ;; #:phases
       ;; (modify-phases %standard-phases
       ;;   (replace 'check
       ;;     (lambda _
       ;;       (zero? (system* "py.test" "-v")))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (propagated-inputs
     `(("python-bleach" ,python-bleach)
       ("python-entrypoints" ,python-entrypoints)
       ("python-jinja2" ,python-jinja2)
       ("python-jupyter-core" ,python-jupyter-core)
       ("python-mistune" ,python-mistune)
       ("python-nbformat" ,python-nbformat)
       ("python-pygments" ,python-pygments)
       ("python-traitlets" ,python-traitlets)))
    (home-page "http://jupyter.org")
    (synopsis "Converting Jupyter Notebooks")
    (description "The @code{nbconvert} tool, @{jupyter nbconvert}, converts
notebooks to various other formats via Jinja templates.  It allows you to
convert an @code{.ipynb} notebook file into various static formats including:

@enumerate
@item HTML
@item LaTeX
@item PDF
@item Reveal JS
@item Markdown (md)
@item ReStructured Text (rst)
@item executable script
@end enumerate\n")
    (license license:bsd-3)))

(define-public python2-nbconvert
  (package-with-python2 python-nbconvert))

(define-public python-notebook
  (package
    (name "python-notebook")
    (version "5.7.4")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "notebook" version))
              (sha256
               (base32
                "0jm7324mbxljmn9hgapj66q7swyz5ai92blmr0jpcy0h80x6f26r"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             ;; These tests require a browser
             (delete-file-recursively "notebook/tests/selenium")
             ;; Some tests need HOME
             (setenv "HOME" "/tmp")
             ;; This file contains "warningfilters", which are not supported
             ;; by this version of nose.
             (delete-file "setup.cfg")
             (with-directory-excursion "/tmp"
               (invoke "nosetests" "-v"))
             #t)))))
    (propagated-inputs
     `(("python-jupyter-core" ,python-jupyter-core)
       ("python-nbformat" ,python-nbformat)
       ("python-nbconvert" ,python-nbconvert)
       ("python-prometheus-client" ,python-prometheus-client)
       ("python-send2trash" ,python-send2trash)
       ("python-terminado" ,python-terminado)))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-sphinx" ,python-sphinx)
       ("python-requests" ,python-requests)))
    (home-page "http://jupyter.org/")
    (synopsis "Web-based notebook environment for interactive computing")
    (description
     "The Jupyter HTML notebook is a web-based notebook environment for
interactive computing.")
    (properties `((python2-variant . ,(delay python2-notebook))))
    (license license:bsd-3)))

(define-public python2-notebook
  (let ((base (package-with-python2
                (strip-python2-variant python-notebook))))
    (package (inherit base)
      (native-inputs
       `(("python2-mock" ,python2-mock)
         ,@(package-native-inputs base)))
      (arguments
       (substitute-keyword-arguments (package-arguments base)
         ((#:phases phases)
          `(modify-phases ,phases
             (add-before 'check 'disable-test-case
              ;; The test requires network access to localhost. Curiously it
              ;; fails with Python 2 only. Simply make the test-case return
              ;; immediately.
              (lambda _
                (substitute*
                    "notebook/services/nbconvert/tests/test_nbconvert_api.py"
                  (("formats = self.nbconvert_api") "return #")))))))))))

(define-public python-widgetsnbextension
  (package
    (name "python-widgetsnbextension")
    (version "3.4.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "widgetsnbextension" version))
       (sha256
        (base32
         "0rc2nivdy7k4m3vljx7wdh2jh11djapcgwhvzlbs0isl8gl8nqgs"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-ipykernel" ,python-ipykernel)
       ("python-notebook" ,python-notebook)))
    (native-inputs
     `(("python-certifi" ,python-certifi)
       ("python-nose" ,python-nose)))
    (home-page "https://ipython.org")
    (synopsis "IPython HTML widgets for Jupyter")
    (description "This package provides interactive HTML widgets for Jupyter
notebooks.")
    (license license:bsd-3)))

(define-public python2-widgetsnbextension
  (package-with-python2 python-widgetsnbextension))

(define-public python-ipywidgets
  (package
    (name "python-ipywidgets")
    (version "5.2.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ipywidgets" version))
       (sha256
        (base32
         "1lk0qrr5l9a0z7qkkn30hv5832whxwxymf1l576fmmad0n7hkxms"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-ipython" ,python-ipython)
       ("python-traitlets" ,python-traitlets)
       ("python-widgetsnbextension" ,python-widgetsnbextension)))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-pytest" ,python-pytest)))
    (home-page "https://ipython.org")
    (synopsis "IPython HTML widgets for Jupyter")
    (description "Ipywidgets are interactive HTML widgets for Jupyter
notebooks and the IPython kernel.  Notebooks come alive when interactive
widgets are used.  Users gain control of their data and can visualize changes
in the data.")
    (license license:bsd-3)))

(define-public python2-ipywidgets
  (package-with-python2 python-ipywidgets))

(define-public python-jupyter-console
  (package
    (name "python-jupyter-console")
    (version "6.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "jupyter_console" version))
       (sha256
        (base32
         "1xdjw11cppf1fxvwkw2bk13ckkwas3bdah8baingn9296mvfi31h"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-ipykernel" ,python-ipykernel)
       ("python-jupyter-client" ,python-jupyter-client)
       ("python-prompt-toolkit" ,python-prompt-toolkit)
       ("python-pygments" ,python-pygments)))
    (native-inputs
     `(("python-nose" ,python-nose)))
    (home-page "https://jupyter.org")
    (synopsis "Jupyter terminal console")
    (description "This package provides a terminal-based console frontend for
Jupyter kernels.  It also allows for console-based interaction with non-Python
Jupyter kernels such as IJulia and IRKernel.")
    (license license:bsd-3)))

(define-public python2-jupyter-console
  (package
    (name "python2-jupyter-console")
    (version "5.2.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "jupyter_console" version))
       (sha256
        (base32
         "1kam1qzgwr7srhm5r6aj90di5sws4bq0jmiw15452ddamb9yspal"))))
    (build-system python-build-system)
    ;; Tests only run in an TTY.
    (arguments `(#:tests? #f))
    (propagated-inputs
     `(("python2-ipykernel" ,python2-ipykernel)
       ("python2-jupyter-client" ,python2-jupyter-client)
       ("python2-prompt-toolkit" ,python2-prompt-toolkit-1)
       ("python2-pygments" ,python2-pygments)))
    (native-inputs
     `(("python2-nose" ,python2-nose)))
    (home-page "https://jupyter.org")
    (synopsis "Jupyter terminal console")
    (description "This package provides a terminal-based console frontend for
Jupyter kernels.  It also allows for console-based interaction with non-Python
Jupyter kernels such as IJulia and IRKernel.")
    (license license:bsd-3)))

;; The python-ipython and python-jupyter-console require each other. To get
;; the functionality in both packages working, strip down the
;; python-jupyter-console package when using it as an input to python-ipython.
(define python-jupyter-console-minimal
  (package
    (inherit python-jupyter-console)
    (name "python-jupyter-console-minimal")
    (arguments
     (substitute-keyword-arguments
         (package-arguments python-jupyter-console)
       ((#:phases phases)
        `(modify-phases ,phases
           (add-after 'install 'delete-bin
             (lambda* (#:key outputs #:allow-other-keys)
               ;; Delete the bin files, to avoid conflicts in profiles
               ;; where python-ipython and python-jupyter-console are
               ;; both present.
               (delete-file-recursively
                (string-append
                 (assoc-ref outputs "out") "/bin"))))))))
    ;; Remove the python-ipython propagated input, to avoid the cycle
    (propagated-inputs
     (alist-delete
      "python-ipython"
      (package-propagated-inputs python-jupyter-console)))))

(define-public python-qtconsole
  (package
    (name "python-qtconsole")
    (version "4.4.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "qtconsole" version))
       (sha256
        (base32
         "1b03n1ixzscm0jw97l4dq5iy4fslnqxq5bb8287xb7n2a1gs26xw"))))
    (build-system python-build-system)
    (arguments
     ;; XXX: Tests are disabled, because this package needs python-ipython 7,
     ;; but we only have the LTS version 5.x.  This means that there might be
     ;; runtime errors, but since this is a dependency of the Jupyter package,
     ;; and Jupyter can be used without the qtconsole we can overlook this for
     ;; now.
     `(#:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-before 'check 'pre-check
           (lambda _
             (setenv "QT_QPA_PLATFORM" "offscreen")
             #t)))))
    (propagated-inputs
     `(("python-ipykernel" ,python-ipykernel)
       ("python-ipython" ,python-ipython)))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "http://jupyter.org")
    (synopsis "Jupyter Qt console")
    (description "This package provides a Qt-based console for Jupyter with
support for rich media output.")
    (license license:bsd-3)))

(define-public jupyter
  (package
    (name "jupyter")
    (version "1.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "jupyter" version))
       (sha256
        (base32
         "0pwf3pminkzyzgx5kcplvvbvwrrzd3baa7lmh96f647k30rlpp6r"))))
    (build-system python-build-system)
    (arguments '(#:tests? #f)) ; there are none.
    (propagated-inputs
     `(("python-ipykernel" ,python-ipykernel)
       ("python-ipywidgets" ,python-ipywidgets)
       ("python-jupyter-console" ,python-jupyter-console)
       ("python-nbconvert" ,python-nbconvert)
       ("python-notebook" ,python-notebook)
       ("python-qtconsole" ,python-qtconsole)))
    (native-search-paths
     (list (search-path-specification
            (variable "JUPYTER_PATH")
            (files '("share/jupyter")))))
    (home-page "https://jupyter.org")
    (synopsis "Web application for interactive documents")
    (description
     "The Jupyter Notebook is a web application that allows you to create and
share documents that contain live code, equations, visualizations and
explanatory text.  Uses include: data cleaning and transformation, numerical
simulation, statistical modeling, machine learning and much more.")
    (license license:bsd-3)))

(define-public python-chardet
  (package
    (name "python-chardet")
    (version "3.0.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "chardet" version))
       (sha256
        (base32
         "1bpalpia6r5x1kknbk11p1fzph56fmmnp405ds8icksd3knr5aw4"))))
    (native-inputs
     `(("python-hypothesis" ,python-hypothesis)
       ("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)))
    (build-system python-build-system)
    (home-page "https://github.com/chardet/chardet")
    (synopsis "Universal encoding detector for Python 2 and 3")
    (description
     "This package provides @code{chardet}, a Python module that can
automatically detect a wide range of file encodings.")
    (license license:lgpl2.1+)))

(define-public python2-chardet
  (package-with-python2 python-chardet))

(define-public python-docopt
  (package
    (name "python-docopt")
    (version "0.6.2")
    (source
     (origin
       (method url-fetch)
       ;; The release on PyPI does not include tests.
       (uri (string-append
             "https://github.com/docopt/docopt/archive/"
             version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "16bf890xbdz3m30rsv2qacklh2rdn1zrfspfnwzx9g7vwz8yw4r1"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _ (invoke "py.test"))))))
    (home-page "http://docopt.org")
    (synopsis "Command-line interface description language for Python")
    (description "This library allows the user to define a command-line
interface from a program's help message rather than specifying it
programmatically with command-line parsers like @code{getopt} and
@code{argparse}.")
    (license license:expat)))

(define-public python2-docopt
  (package-with-python2 python-docopt))

(define-public python-pythondialog
  (package
    (name "python-pythondialog")
    (version "3.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pythondialog" version))
       (sha256
        (base32
         "1728ghsran47jczn9bhlnkvk5bvqmmbihabgif5h705b84r1272c"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-path
           (lambda* (#:key inputs #:allow-other-keys)
             (let* ((dialog (assoc-ref inputs "dialog")))
               ;; Since this library really wants to grovel the search path, we
               ;; must hardcode dialog's store path into it.
               (substitute* "dialog.py"
                 (("os.getenv\\(\"PATH\", \":/bin:/usr/bin\"\\)")
                  (string-append "os.getenv(\"PATH\")  + \":" dialog "/bin\"")))
               #t))))
       #:tests? #f)) ; no test suite
    (propagated-inputs
     `(("dialog" ,dialog)))
    (home-page "http://pythondialog.sourceforge.net/")
    (synopsis "Python interface to the UNIX dialog utility")
    (description "A Python wrapper for the dialog utility.  Its purpose is to
provide an easy to use, pythonic and comprehensive Python interface to dialog.
This allows one to make simple text-mode user interfaces on Unix-like systems")
    (license license:lgpl2.1)
    (properties `((python2-variant . ,(delay python2-pythondialog))))))

(define-public python2-pythondialog
  (let ((base (package-with-python2 (strip-python2-variant python-pythondialog))))
    (package
      (inherit base)
      (version (package-version python-pythondialog))
      (source (origin
                (method url-fetch)
                (uri (pypi-uri "python2-pythondialog" version))
                (sha256
                 (base32
                  "0d8k7lxk50imdyx85lv8j98i4c93a71iwpapnl1506rpkbm9qvd9")))))))

(define-public python-configobj
  (package
    (name "python-configobj")
    (version "5.0.6")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "configobj" version))
              (sha256
               (base32
                "00h9rcmws03xvdlfni11yb60bz3kxfvsj6dg6nrpzj71f03nbxd2"))
              ;; Patch setup.py so it looks for python-setuptools, which is
              ;; required to parse the keyword 'install_requires' in setup.py.
              (patches (search-patches "python-configobj-setuptools.patch"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)))
    (synopsis "Config file reading, writing and validation")
    (description "ConfigObj is a simple but powerful config file reader and
writer: an ini file round tripper.  Its main feature is that it is very easy to
use, with a straightforward programmer’s interface and a simple syntax for
config files.")
    (home-page "https://github.com/DiffSK/configobj")
    (license license:bsd-3)))

(define-public python2-configobj
  (package-with-python2 python-configobj))

(define-public python-configargparse
  (package
    (name "python-configargparse")
    (version "0.14.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "ConfigArgParse" version))
              (sha256
               (base32
                "149fy4zya0rsnlkvxbbq43cyr8lscb5k4pj1m6n7f1grwcmzwbif"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pyyaml" ,python-pyyaml)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             ;; Bypass setuptools-shim because one test relies on "setup.py"
             ;; being the first argument passed to the python call.
             ;;
             ;; NOTE: Many tests do not run because they rely on Python's
             ;; built-in test.test_argparse, but we remove the unit tests from
             ;; our Python installation.
             (invoke "python" "setup.py" "test"))))))
    (synopsis "Replacement for argparse")
    (description "A drop-in replacement for argparse that allows options to also
be set via config files and/or environment variables.")
    (home-page "https://github.com/bw2/ConfigArgParse")
    (license license:expat)))

(define-public python2-configargparse
  (package-with-python2 python-configargparse))

(define-public python-argparse-manpage
  (package
    (name "python-argparse-manpage")
    (version "1.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "argparse-manpage" version))
       (sha256
        (base32
         "0blh31zns68anina9lba5wh81d1414s97p60zw5l0d0shhh0wj5p"))))
    (build-system python-build-system)
    (home-page "https://github.com/praiskup/argparse-manpage")
    (synopsis "Build manual page from Python's ArgumentParser object")
    (description
     "This package provides tools to build manual pages from Python's
@code{ArgumentParser} object.")
    (license license:asl2.0)))

(define-public python-contextlib2
  (package
    (name "python-contextlib2")
    (version "0.5.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "contextlib2" version))
       (sha256
        (base32
         "0j6ad6lwwyc9kv71skj098v5l7x5biyj2hs4lc5x1kcixqcr97sh"))))
    (build-system python-build-system)
    (home-page "http://contextlib2.readthedocs.org/")
    (synopsis "Tools for decorators and context managers")
    (description "This module is primarily a backport of the Python
3.2 contextlib to earlier Python versions.  Like contextlib, it
provides utilities for common tasks involving decorators and context
managers.  It also contains additional features that are not part of
the standard library.")
    (license license:psfl)))

(define-public python2-contextlib2
  (package
    (name "python2-contextlib2")
    (version "0.5.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "contextlib2" version))
       (sha256
        (base32
         "0j6ad6lwwyc9kv71skj098v5l7x5biyj2hs4lc5x1kcixqcr97sh"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _ (invoke "python" "test_contextlib2.py" "-v"))))))
    (native-inputs
     `(("python2-unittest2" ,python2-unittest2)))
    (home-page "http://contextlib2.readthedocs.org/")
    (synopsis "Tools for decorators and context managers")
    (description "This module is primarily a backport of the Python
3.2 contextlib to earlier Python versions.  Like contextlib, it
provides utilities for common tasks involving decorators and context
managers.  It also contains additional features that are not part of
the standard library.")
    (license license:psfl)))

(define-public python-texttable
  (package
    (name "python-texttable")
    (version "0.9.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "texttable" version))
       (sha256
        (base32
         "0yawv64c0zbawwv6zz84whb32fnb2n9jylwjcfsrcdgh7xvl340i"))))
    (build-system python-build-system)
    (arguments '(#:tests? #f)) ; no tests
    (home-page "https://github.com/foutaise/texttable/")
    (synopsis "Python module for creating simple ASCII tables")
    (description "Texttable is a Python module for creating simple ASCII
tables.")
    (license license:lgpl2.1+)))

(define-public python2-texttable
  (package-with-python2 python-texttable))

(define-public python-atomicwrites
  (package
    (name "python-atomicwrites")
    (version "1.1.5")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "atomicwrites" version))
             (sha256
              (base32
               "11bm90fwm2avvf4f3ib8g925w7jr4m11vcsinn1bi6ns4bm32214"))))
    (build-system python-build-system)
    (synopsis "Atomic file writes in Python")
    (description "Library for atomic file writes using platform dependent tools
for atomic file system operations.")
    (home-page "https://github.com/untitaker/python-atomicwrites")
    (license license:expat)))

(define-public python2-atomicwrites
  (package-with-python2 python-atomicwrites))

(define-public python-click-threading
  (package
    (name "python-click-threading")
    (version "0.4.4")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "click-threading" version))
             (sha256
              (base32
               "1rsxc2fbkxlhwhlmxsdjzq3spn284l6rvjfcz9mbb17ibgdgmc5j"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-click" ,python-click)))
    (synopsis "Utilities for multithreading in Click")
    (description "This package provides utilities for multithreading in Click
applications.")
    (home-page "https://github.com/click-contrib/click-threading")
    (license license:expat)))

(define-public python-click-log
  (package
    (name "python-click-log")
    (version "0.3.2")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "click-log" version))
             (sha256
              (base32
               "091i03bhxyzsdbc6kilxhivfda2f8ymz3b33xa6cj5kbzjiirz8n"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-click" ,python-click)))
    (synopsis "Logging for click applications")
    (description "This package provides a Python library for logging Click
applications.")
    (home-page "https://github.com/click-contrib/click-log")
    (license license:expat)))

(define-public python-apipkg
  (package
    (name "python-apipkg")
    (version "1.4")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "apipkg" version))
             (sha256
              (base32
               "1iks5701qnp3dlr3q1d9qm68y2plp2m029irhpz92a44psfkjf1f"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (synopsis "Namespace control and lazy-import mechanism")
    (description "With apipkg you can control the exported namespace of a Python
package and greatly reduce the number of imports for your users.  It is a small
pure Python module that works on virtually all Python versions.")
    (home-page "https://github.com/pytest-dev/apipkg")
    (license license:expat)))

(define-public python2-apipkg
  (package-with-python2 python-apipkg))

(define-public python-execnet
  (package
    (name "python-execnet")
    (version "1.4.1")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "execnet" version))
             (sha256
              (base32
               "1rpk1vyclhg911p3hql0m0nrpq7q7mysxnaaw6vs29cpa6kx8vgn"))))
    (build-system python-build-system)
    (arguments
     `(;; 2 failed, 275 passed, 670 skipped, 4 xfailed
       ;; The two test failures are caused by the lack of an `ssh` executable.
       ;; The test suite can be run with pytest after the 'install' phase.
       #:tests? #f))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-setuptools-scm" ,python-setuptools-scm)))
    (propagated-inputs
     `(("python-apipkg" ,python-apipkg)))
    (synopsis "Rapid multi-Python deployment")
    (description "Execnet provides a share-nothing model with
channel-send/receive communication for distributing execution across many
Python interpreters across version, platform and network barriers.  It has a
minimal and fast API targeting the following uses:
@enumerate
@item distribute tasks to (many) local or remote CPUs
@item write and deploy hybrid multi-process applications
@item write scripts to administer multiple environments
@end enumerate")
    (home-page "http://codespeak.net/execnet/")
    (license license:expat)))

(define-public python2-execnet
  (package-with-python2 python-execnet))

(define-public python-icalendar
  (package
    (name "python-icalendar")
    (version "4.0.3")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "icalendar" version))
             (sha256
              (base32
               "0mk3dk1dxkcm46jy48v27j2w2349iv4sbimqj1yb5js43mx49hh7"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-dateutil" ,python-dateutil)
       ("python-pytz" ,python-pytz)))
    (synopsis "Python library for parsing iCalendar files")
    (description "The icalendar package is a parser/generator of iCalendar
files for use with Python.")
    (home-page "https://github.com/collective/icalendar")
    (license license:bsd-2)))

(define-public python-args
  (package
    (name "python-args")
    (version "0.1.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "args" version))
              (sha256
               (base32
                "057qzi46h5dmxdqknsbrssn78lmqjlnm624iqdhrnpk26zcbi1d7"))))
    (build-system python-build-system)
    (home-page "https://github.com/kennethreitz/args")
    (synopsis "Command-line argument parser")
    (description
     "This library provides a Python module to parse command-line arguments.")
    (license license:bsd-3)))

(define-public python2-args
  (package-with-python2 python-args))

(define-public python-clint
  (package
    (name "python-clint")
    (version "0.5.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "clint" version))
              (sha256
               (base32
                "1an5lkkqk1zha47198p42ji3m94xmzx1a03dn7866m87n4r4q8h5"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _ (invoke "py.test" "-v"))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (propagated-inputs
     `(("python-args" ,python-args)))
    (home-page "https://github.com/kennethreitz/clint")
    (synopsis "Command-line interface tools")
    (description
     "Clint is a Python module filled with a set of tools for developing
command-line applications, including tools for colored and indented
output, progress bar display, and pipes.")
    (license license:isc)))

(define-public python2-clint
  (package-with-python2 python-clint))

(define-public python-rply
  (package
    (name "python-rply")
    (version "0.7.5")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "rply" version))
              (sha256
               (base32
                "0lv428895zxsz43968qx0q9bimwqnfykndz4dpjbq515w2gvzhjh"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-appdirs" ,python-appdirs)))
    (home-page "https://github.com/alex/rply")
    (synopsis "Parser generator for Python")
    (description
     "This package provides a pure Python based parser generator, that also
works with RPython.  It is a more-or-less direct port of David Bazzley's PLY,
with a new public API, and RPython support.")
    (license license:bsd-3)))

(define-public python2-rply
  (package-with-python2 python-rply))

(define-public python-hy
  (package
    (name "python-hy")
    (version "0.13.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "hy" version))
              (sha256
               (base32
                "19sfymaksx9jhksfnb15ahid46mzrhdfzz6yy2craz2qnzvpmky8"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             ;; Tests require write access to HOME.
             (setenv "HOME" "/tmp")
             (invoke "nosetests"))))))
    (native-inputs
     `(("python-coverage" ,python-coverage)
       ("python-nose" ,python-nose)))
    (propagated-inputs
     `(("python-astor" ,python-astor)
       ("python-clint" ,python-clint)
       ("python-rply" ,python-rply)))
    (home-page "http://hylang.org/")
    (synopsis "Lisp frontend to Python")
    (description
     "Hy is a dialect of Lisp that's embedded in Python.  Since Hy transforms
its Lisp code into the Python Abstract Syntax Tree, you have the whole world of
Python at your fingertips, in Lisp form.")
    (license license:expat)))

(define-public python2-hy
  (package-with-python2 python-hy))

(define-public python2-functools32
  (package
    (name "python2-functools32")
    (version "3.2.3-2")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "functools32" version))
        (sha256
         (base32
          "0v8ya0b58x47wp216n1zamimv4iw57cxz3xxhzix52jkw3xks9gn"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:tests? #f)) ; no test target
    (home-page "https://github.com/MiCHiLU/python-functools32")
    (synopsis
     "Backport of the functools module from Python 3.2.3")
    (description
     "This package is a backport of the @code{functools} module from Python
3.2.3 for use with older versions of Python and PyPy.")
    (license license:expat)))

(define-public python2-subprocess32
  (package
    (name "python2-subprocess32")
    (version "3.2.7")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "subprocess32" version))
              (sha256
               (base32
                "14350dhhlhyz5gqzi3lihn9m6lvskx5mcb20srx1kgsk9i50li8y"))
              (patches
               (search-patches "python2-subprocess32-disable-input-test.patch"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       ;; The test suite fails with Python > 2.7.13:
       ;;     import test.support
       ;; ImportError: No module named support
       #:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-/bin/sh
           (lambda _
             (substitute* '("subprocess32.py"
                            "test_subprocess32.py")
               (("/bin/sh") (which "sh")))
             #t)))))
    (home-page "https://github.com/google/python-subprocess32")
    (synopsis "Backport of the subprocess module from Python 3.2")
    (description
     "This is a backport of the @code{subprocess} standard library module
from Python 3.2 and 3.3 for use on Python 2.  It includes bugfixes and some
new features.  On POSIX systems it is guaranteed to be reliable when used
in threaded applications.  It includes timeout support from Python 3.3 but
otherwise matches 3.2’s API.")
    (license license:psfl)))

(define-public python2-futures
  (package
    (name "python2-futures")
    (version "3.2.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "futures" version))
        (sha256
         (base32
          "0rdjmmsab550kxsssdq49jcniz77zlkpw4pvi9hvib3lsskjmh4y"))))
    (build-system python-build-system)
    (arguments `(#:python ,python-2
                 ;; FIXME: Python 2.7.14 moved the test.support library,
                 ;; but our package has not yet been adjusted.  Enable
                 ;; tests when the python2 package has been fixed.
                 #:tests? #f))
    (home-page "https://github.com/agronholm/pythonfutures")
    (synopsis
     "Backport of the concurrent.futures package from Python 3.2")
    (description
     "The concurrent.futures module provides a high-level interface for
asynchronously executing callables.  This package backports the
concurrent.futures package from Python 3.2")
    (license license:bsd-3)))

(define-public python-promise
  (package
    (name "python-promise")
    (version "0.4.2")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "promise" version))
        (sha256
         (base32
          "1k19ms8l3d5jzjh557rgkxb5sg4mqgfc315rn4hx1z3n8qq6lr3h"))))
    (build-system python-build-system)
    ;; Tests wants python-futures, which is a python2 only program, and
    ;; can't be found by python-promise at test time.
    (arguments `(#:tests? #f))
    (home-page "https://github.com/syrusakbary/promise")
    (synopsis "Promises/A+ implementation for Python")
    (description
     "Promises/A+ implementation for Python")
    (properties `((python2-variant . ,(delay python2-promise))))
    (license license:expat)))

(define-public python2-promise
  (let ((promise (package-with-python2
                   (strip-python2-variant python-promise))))
    (package (inherit promise)
      (arguments (substitute-keyword-arguments (package-arguments promise)
                   ((#:tests? _) #t)))
      (native-inputs
       `(("python2-futures" ,python2-futures)
         ("python2-pytest" ,python2-pytest)
         ,@(package-native-inputs promise))))))

(define-public python-progressbar33
  (package
    (name "python-progressbar33")
    (version "2.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "progressbar33" version))
       (sha256
        (base32
         "1zvf6zs5hzrc03p9nfs4p16vhilqikycvv1yk0pxn8s07fdhvzji"))))
    (build-system python-build-system)
    (home-page "http://github.com/germangh/python-progressbar")
    (synopsis "Text progress bar library for Python")
    (description
     "This package provides a text progress bar library for Python.  This
version only differs from the original @code{progressbar} package in that it
uses relative package imports instead of absolute imports, which is necessary
for the module to work under Python 3.3.")
    ;; Either or both of these licenses may be selected.
    (license (list license:lgpl2.1+ license:bsd-3))))

(define-public python-colorama
  (package
   (name "python-colorama")
   (version "0.3.9")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "colorama" version))
     (sha256
      (base32
       "1wd1szk0z3073ghx26ynw43gnc140ibln1safgsis6s6z3s25ss8"))))
   (build-system python-build-system)
   (synopsis "Colored terminal text rendering for Python")
   (description "Colorama is a Python library for rendering colored terminal
text.")
   (home-page "https://pypi.python.org/pypi/colorama")
   (license license:bsd-3)))

(define-public python2-colorama
  (package-with-python2 python-colorama))

(define-public python-rsa
  (package
   (name "python-rsa")
   (version "3.4.2")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "rsa" version))
     (sha256
      (base32
       "1dcxvszbikgzh99ybdc7jq0zb9wspy2ds8z9mjsqiyv3q884xpr5"))))
   (build-system python-build-system)
   (propagated-inputs
    `(("python-pyasn1" ,python-pyasn1)))
   (synopsis "Pure-Python RSA implementation")
   (description "Python-RSA is a pure-Python RSA implementation.  It supports
encryption and decryption, signing and verifying signatures, and key
generation according to PKCS#1 version 1.5.  It can be used as a Python
library as well as on the command line.")
   (home-page "https://stuvel.eu/rsa")
   (license license:asl2.0)))

(define-public python2-rsa
  (package-with-python2 python-rsa))

(define-public python-pluggy
  (package
   (name "python-pluggy")
   (version "0.7.1")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "pluggy" version))
     (sha256
      (base32
       "1qbn70mksmr03hac6jgp6fiqc4l7859z8dchx2x950vhlij87swm"))))
   (build-system python-build-system)
   (native-inputs
    `(("python-setuptools-scm" ,python-setuptools-scm)))
   (synopsis "Plugin and hook calling mechanism for Python")
   (description "Pluggy is an extraction of the plugin manager as used by
Pytest but stripped of Pytest specific details.")
   (home-page "https://pypi.python.org/pypi/pluggy")
   (license license:expat)))

(define-public python2-pluggy
  (package-with-python2 python-pluggy))

(define-public python-tox
  (package
   (name "python-tox")
   (version "2.8.1")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "tox" version))
     (sha256
      (base32
       "1drp6mwm8wdypjym15ia8lwjxbhcksb9vzxg4ay5dh4ji57by2ny"))))
   (build-system python-build-system)
   (arguments
    ;; FIXME: Tests require pytest-timeout, which itself requires
    ;; pytest>=2.8.0 for installation.
    '(#:tests? #f))
   (propagated-inputs
    `(("python-pluggy" ,python-pluggy) ; >=0.3.0,<0.4.0
      ("python-py" ,python-py)
      ("python-virtualenv" ,python-virtualenv)))
   (native-inputs
    `(; FIXME: Missing: ("python-pytest-timeout" ,python-pytest-timeout)
      ("python-pytest" ,python-pytest)  ; >= 2.3.5
      ("python-setuptools-scm" ,python-setuptools-scm)))
   (home-page "http://tox.testrun.org/")
   (synopsis "Virtualenv-based automation of test activities")
   (description "Tox is a generic virtualenv management and test command line
tool.  It can be used to check that a package installs correctly with
different Python versions and interpreters, or run tests in each type of
supported environment, or act as a frontend to continuous integration
servers.")
   (license license:expat)))

(define-public python2-tox
  (package-with-python2 python-tox))

(define-public python-jmespath
  (package
   (name "python-jmespath")
   (version "0.9.3")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "jmespath" version))
     (sha256
      (base32
       "0r7wc7fsxmlwzxx9j1j7rms06c6xs6d4sysirdhz1jk2mb4x90ba"))))
   (build-system python-build-system)
   (native-inputs
    `(("python-nose" ,python-nose)))
   (synopsis "JSON Matching Expressions")
   (description "JMESPath (pronounced “james path”) is a Python library that
allows one to declaratively specify how to extract elements from a JSON
document.")
   (home-page "https://github.com/jmespath/jmespath.py")
   (license license:expat)))

(define-public python2-jmespath
  (package-with-python2 python-jmespath))

(define-public python-botocore
  (package
    (name "python-botocore")
    (version "1.12.149")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "botocore" version))
       (sha256
        (base32
         "12597f74khp3ngwr282cb949w0gcqj20rkfc3x275dijavyy5cmf"))))
    (build-system python-build-system)
    (arguments
     ;; FIXME: Many tests are failing.
     '(#:tests? #f))
    (propagated-inputs
     `(("python-dateutil" ,python-dateutil)
       ("python-docutils" ,python-docutils)
       ("python-jmespath" ,python-jmespath)))
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-nose" ,python-nose)
       ("behave" ,behave)
       ("python-tox" ,python-tox)
       ("python-urllib3" ,python-urllib3)
       ("python-wheel" ,python-wheel)))
    (home-page "https://github.com/boto/botocore")
    (synopsis "Low-level interface to AWS")
    (description "Botocore is a Python library that provides a low-level
interface to the Amazon Web Services (AWS) API.")
    (license license:asl2.0)))

(define-public python2-botocore
  (package-with-python2 python-botocore))

(define-public python-xdo
  (package
    (name "python-xdo")
    (version "0.3")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://http.debian.net/debian/pool/main/p/python-xdo/"
                    "python-xdo_" version ".orig.tar.gz"))
              (sha256
               (base32
                "1vqh1n5yy5dhnq312kwrl90fnck4v26is3lq3lxdvcn60vv19da0"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-before 'install 'patch-libxdo-path
           ;; Hardcode the path of dynamically loaded libxdo library.
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((libxdo (string-append
                            (assoc-ref inputs "xdotool")
                            "/lib/libxdo.so")))
               (substitute* "xdo/_xdo.py"
                 (("find_library\\(\"xdo\"\\)")
                  (simple-format #f "\"~a\"" libxdo)))
               #t))))
       #:tests? #f))  ; no tests provided
    (propagated-inputs
     `(("python-six" ,python-six)))
    (inputs
     `(("xdotool" ,xdotool)
       ("libX11" ,libx11)))
    (home-page "https://tracker.debian.org/pkg/python-xdo")
    (synopsis "Python library for simulating X11 keyboard/mouse input")
    (description "Provides bindings to libxdo for manipulating X11 via simulated
input.  (Note that this is mostly a legacy library; you may wish to look at
python-xdo for newer bindings.)")
    (license license:bsd-3)))

(define-public python2-xdo
  (package-with-python2 python-xdo))

(define-public python-mako
  (package
    (name "python-mako")
    (version "1.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Mako" version))
       (sha256
        (base32
         "0jqa3qfpykyn4fmkn0kh6043sfls7br8i2bsdbccazcvk9cijsd3"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      (invoke "pytest" "-vv"))))))
    (propagated-inputs
     `(("python-markupsafe" ,python-markupsafe)))
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-pytest" ,python-pytest)))
    (home-page "https://www.makotemplates.org/")
    (synopsis "Templating language for Python")
    (description "Mako is a templating language for Python that compiles
templates into Python modules.")
    (license license:expat)))

(define-public python2-mako
  (package-with-python2 python-mako))

(define-public python-waitress
  (package
    (name "python-waitress")
    (version "1.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "waitress" version))
       (patches (search-patches "python-waitress-fix-tests.patch"))
       (sha256
        (base32
         "1a85gyji0kajc3p0s1pwwfm06w4wfxjkvvl4rnrz3h164kbd6g6k"))))
    (build-system python-build-system)
    (home-page "https://github.com/Pylons/waitress")
    (synopsis "Waitress WSGI server")
    (description "Waitress is meant to be a production-quality pure-Python WSGI
server with very acceptable performance.")
    (license license:zpl2.1)))

(define-public python2-waitress
  (package-with-python2 python-waitress))

(define-public python-pyquery
  (package
    (name "python-pyquery")
    (version "1.2.17")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyquery" version))
       (sha256
        (base32
         "1xia20wm0vx5dk85kcwgh13bylz8qh47ffjxssd2586r60xi783a"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-webob" ,python-webob)
       ("python-webtest" ,python-webtest)))
    (propagated-inputs
     `(("python-lxml" ,python-lxml)
       ("python-cssselect" ,python-cssselect)))
    (home-page "https://github.com/gawel/pyquery")
    (synopsis "Make jQuery-like queries on xml documents")
    (description "pyquery allows you to make jQuery queries on xml documents.
The API is as much as possible the similar to jQuery.  pyquery uses lxml for
fast xml and html manipulation.")
    (license license:bsd-3)))

(define-public python-anyjson
  (package
    (name "python-anyjson")
    (version "0.3.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "anyjson" version))
       (sha256
        (base32
         "1fjph4alvcscsl5d4b6qpv1yh31jy05jxi1l0xff7lws7j32v09p"))))
    (build-system python-build-system)
    (arguments
     `(;; We could possibly get tests working, but on Python 3 it's not so easy.
       ;; Very strangely, 2to3 is run *during setup.py install* (or bdist, or
       ;; whatever) so this transformation needs to be done before the tests
       ;; can be run.  Maybe we could add a build step to transform beforehand
       ;; but it could be annoying/difficult.
       ;; We can enable tests for the Python 2 version, though, and do below.
       #:tests? #f))
    (home-page "https://bitbucket.org/runeh/anyjson/")
    (synopsis
     "Wraps best available JSON implementation in a common interface")
    (description
     "Anyjson loads whichever is the fastest JSON module installed
and provides a uniform API regardless of which JSON implementation is used.")
    (license license:bsd-3)
    (properties `((python2-variant . ,(delay python2-anyjson))))))

(define-public python2-anyjson
  (let ((anyjson (package-with-python2
                  (strip-python2-variant python-anyjson))))
    (package
      (inherit anyjson)
      (arguments `(;; Unlike the python 3 variant, we do run tests.  See above!
                   #:tests? #t
                   ,@(package-arguments anyjson)))
      (native-inputs `(("python2-nose" ,python2-nose))))))

(define-public python-amqp
  (package
    (name "python-amqp")
    (version "2.3.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "amqp" version))
       (sha256
        (base32
         "1sv600dgqwpimr6i1g59y9hpn50mc236gdqkr7zin13kvlpx0g87"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-case" ,python-case)
       ("python-pytest-sugar" ,python-pytest-sugar)
       ("python-mock" ,python-mock)))
    (propagated-inputs
     `(("python-vine" ,python-vine)))
    (home-page "https://github.com/celery/py-amqp")
    (synopsis
     "Low-level AMQP client for Python (fork of amqplib)")
    (description
     "This is a fork of amqplib which was originally written by Barry Pederson.
It is maintained by the Celery project, and used by kombu as a pure python
alternative when librabbitmq is not available.")
    (license license:lgpl2.1+)
    (properties `((python2-variant . ,(delay python2-amqp))))))

(define-public python2-amqp
  (let ((amqp (package-with-python2
               (strip-python2-variant python-amqp))))
    (package
      (inherit amqp)
      (arguments `(;; Tries to run coverage tests with nose-cover3, which seems
                   ;; unmaintained.  Weirdly, does not do this on the python 3
                   ;; version?
                   #:tests? #f
                   ,@(package-arguments amqp))))))

(define-public python-txamqp
  (package
    (name "python-txamqp")
    (version "0.8.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "txAMQP" version))
       (sha256
        (base32
         "0jd9864k3csc06kipiwzjlk9mq4054s8kzk5q1cfnxj8572s4iv4"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-twisted" ,python-twisted)))
    (home-page "https://github.com/txamqp/txamqp")
    (synopsis "Communicate with AMQP peers and brokers using Twisted")
    (description
     "This package provides a Python library for communicating with AMQP peers
and brokers using the asynchronous networking framework Twisted.  It contains
all the necessary code to connect, send and receive messages to/from an
AMQP-compliant peer or broker (Qpid, OpenAMQ, RabbitMQ) using Twisted.  It
also includes support for using Thrift RPC over AMQP in Twisted
applications.")
    (license license:asl2.0)))

(define-public python2-txamqp
  (package-with-python2 python-txamqp))

(define-public python-kombu
  (package
    (name "python-kombu")
    (version "4.2.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "kombu" version))
       (sha256
        (base32
         "15k8f7mzqr049sg9vi48m19vjykviafk3f0p5xzgw9by0x0kyxjj"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-case" ,python-case)
       ("python-pyro4" ,python-pyro4)
       ("python-pytest-sugar" ,python-pytest-sugar)
       ("python-pytz" ,python-pytz)))
    (propagated-inputs
     `(("python-anyjson" ,python-anyjson)
       ("python-amqp" ,python-amqp)
       ("python-redis" ,python-redis)))
    (home-page "https://kombu.readthedocs.io")
    (synopsis "Message passing library for Python")
    (description "The aim of Kombu is to make messaging in Python as easy as
possible by providing an idiomatic high-level interface for the AMQ protocol,
and also provide proven and tested solutions to common messaging problems.
AMQP is the Advanced Message Queuing Protocol, an open standard protocol for
message orientation, queuing, routing, reliability and security, for which the
RabbitMQ messaging server is the most popular implementation.")
    (license license:bsd-3)
    (properties `((python2-variant . ,(delay python2-kombu))))))

(define-public python2-kombu
  (let ((kombu (package-with-python2
                (strip-python2-variant python-kombu))))
    (package
      (inherit kombu)
      (arguments `(;; FIXME: 'TestTransport.test_del_sync' fails on python2.
                   ;; It works fine on the python3 variant.
                   #:tests? #f
                   ,@(package-arguments kombu)))
      (native-inputs `(("python2-unittest2" ,python2-unittest2)
                ,@(package-native-inputs kombu))))))

(define-public python-billiard
  (package
    (name "python-billiard")
    (version "3.5.0.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "billiard" version))
       (sha256
        (base32
         "03msmapj3s5zgqk87d646mafz7a01h5bm2wijalgpi0s80ks5na2"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-case" ,python-case)
       ("python-pytest" ,python-pytest)))
    (home-page "https://github.com/celery/billiard")
    (synopsis
     "Python multiprocessing fork with improvements and bugfixes")
    (description
     "Billiard is a fork of the Python 2.7 multiprocessing package.  The
multiprocessing package itself is a renamed and updated version of R Oudkerk's
pyprocessing package.  This standalone variant is intended to be compatible with
Python 2.4 and 2.5, and will draw its fixes/improvements from python-trunk.")
    (license license:bsd-3)
    (properties `((python2-variant . ,(delay python2-billiard))))))

(define-public python2-billiard
  (let ((billiard (package-with-python2
                   (strip-python2-variant python-billiard))))
    (package
      (inherit billiard)
      (native-inputs `(("python2-unittest2" ,python2-unittest2)
                       ("python2-mock" ,python2-mock)
                       ,@(package-native-inputs billiard))))))

(define-public python-celery
  (package
    (name "python-celery")
    (version "4.2.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "celery" version))
       (sha256
        (base32
         "0y66rz7z8dfcgs3s0qxmdddlaq57bzbgxgfz896nbp14grkv9nkp"))))
    (build-system python-build-system)
    (arguments
     '(;; TODO The tests fail with Python 3.7
       ;; https://github.com/celery/celery/issues/4849
       #:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-requirements
           (lambda _
             (substitute* "requirements/test.txt"
               (("pytest>=3\\.0,<3\\.3")
                "pytest>=3.0"))
             #t)))))
    (native-inputs
     `(("python-case" ,python-case)
       ("python-pytest" ,python-pytest)))
    (propagated-inputs
     `(("python-pytz" ,python-pytz)
       ("python-billiard" ,python-billiard)
       ("python-kombu" ,python-kombu)))
    (home-page "https://celeryproject.org")
    (synopsis "Distributed Task Queue")
    (description "Celery is an asynchronous task queue/job queue based on
distributed message passing.  It is focused on real-time operation, but
supports scheduling as well.  The execution units, called tasks, are executed
concurrently on a single or more worker servers using multiprocessing,
Eventlet, or gevent.  Tasks can execute asynchronously (in the background) or
synchronously (wait until ready).")
    (license license:bsd-3)
    (properties `((python2-variant . ,(delay python2-celery))))))

(define-public python2-celery
  (let ((celery (package-with-python2
                 (strip-python2-variant python-celery))))
    (package
      (inherit celery)
      (native-inputs `(("python2-unittest2" ,python2-unittest2)
                       ("python2-mock" ,python2-mock)
                       ,@(package-native-inputs celery))))))

(define-public python-translitcodec
  (package
    (name "python-translitcodec")
    (version "0.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "translitcodec" version))
       (sha256
        (base32
         "10x6pvblkzky1zhjs8nmx64nb9jdzxad4bxhq4iwv0j4z2aqjnki"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))  ; no tests provided
    (home-page
     "https://github.com/claudep/translitcodec")
    (synopsis
     "Unicode to 8-bit charset transliteration codec")
    (description
     "This package contains codecs for transliterating ISO 10646 texts into
best-effort representations using smaller coded character sets (ASCII,
ISO 8859, etc.).")
    (license license:expat)))

(define-public python2-translitcodec
  (package-with-python2 python-translitcodec))

(define-public python-editor
  (package
  (name "python-editor")
  (version "0.5")
  (source
    (origin
      (method url-fetch)
      (uri (pypi-uri "python-editor" version))
      (sha256
        (base32
          "1ypnpgvzpkbwsg4rdvy4sy51j28b5xq9v8pnkwxncn07vqz06p7n"))))
  (build-system python-build-system)
  (home-page
    "https://github.com/fmoo/python-editor")
  (synopsis
    "Programmatically open an editor, capture the result")
  (description
    "python-editor is a library that provides the editor module for
programmatically interfacing with your system's $EDITOR.")
  (license license:asl2.0)))

(define-public python2-editor
  (package-with-python2 python-editor))

(define-public python-vobject
  (package
    (name "python-vobject")
    (version "0.9.5")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "vobject" version))
              (sha256
               (base32
                "0hqjgf3ay1m5w1c0k00g5yfpdz1zni5qnr5rh9b8fg9hjvhwlmhg"))))
    (build-system python-build-system)
    (arguments
     '(;; The test suite relies on some non-portable Windows interfaces.
       #:tests? #f))
    (propagated-inputs
     `(("python-dateutil" ,python-dateutil)
       ("python-pyicu" ,python-pyicu)))
    (synopsis "Parse and generate vCard and vCalendar files")
    (description "Vobject is intended to be a full featured Python package for
parsing and generating vCard and vCalendar files.  Currently, iCalendar files
are supported and well tested. vCard 3.0 files are supported, and all data
should be imported, but only a few components are understood in a sophisticated
way.")
    (home-page "http://eventable.github.io/vobject/")
    (license license:asl2.0)))

(define-public python2-vobject
  (package-with-python2 python-vobject))

(define-public python-munkres
  (package
    (name "python-munkres")
    (version "1.0.8")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "munkres" version))
              (sha256
               (base32
                "0mbspx4zv8id4x6pim6ybsa1xh96qwpbqj7skbqz4c9c9nf1lpqq"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; no test suite
    (home-page "http://software.clapper.org/munkres/")
    (synopsis "Implementation of the Munkres algorithm")
    (description "The Munkres module provides an implementation of the Munkres
algorithm (also called the Hungarian algorithm or the Kuhn-Munkres algorithm),
useful for solving the Assignment Problem.")
    (license license:bsd-3)))

(define-public python2-munkres
  (package-with-python2 python-munkres))

(define-public python-whoosh
  (package
    (name "python-whoosh")
    (version "2.7.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Whoosh" version))
       (sha256
        (base32
         "10qsqdjpbc85fykc1vgcs8xwbgn4l2l52c8d83xf1q59pwyn79bw"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://bitbucket.org/mchaput/whoosh")
    (synopsis "Full text indexing, search, and spell checking library")
    (description
     "Whoosh is a fast, pure-Python full text indexing, search, and spell
checking library.")
    (license license:bsd-2)))

(define-public python2-whoosh
  (let ((whoosh (package-with-python2 (strip-python2-variant python-whoosh))))
    (package (inherit whoosh)
      (propagated-inputs
       `(("python2-backport-ssl-match-hostname"
          ,python2-backport-ssl-match-hostname)
          ,@(package-propagated-inputs whoosh))))))

(define-public python-pathlib
  (package
    (name "python-pathlib")
    (version "1.0.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pathlib" version))
              (sha256
               (base32
                "17zajiw4mjbkkv6ahp3xf025qglkj0805m9s41c45zryzj6p2h39"))))
    (build-system python-build-system)
    ;; The tests depend on the internal "test" module, which does not provide
    ;; a stable interface.
    (arguments `(#:tests? #f))
    (home-page "https://pathlib.readthedocs.org/")
    (synopsis "Object-oriented file system paths")
    (description "Pathlib offers a set of classes to handle file system paths.
It offers the following advantages over using string objects:

@enumerate
@item No more cumbersome use of os and os.path functions.  Everything can
be done easily through operators, attribute accesses, and method calls.
@item Embodies the semantics of different path types.  For example,
comparing Windows paths ignores casing.
@item Well-defined semantics, eliminating any inconsistencies or
ambiguities (forward vs. backward slashes, etc.).
@end enumerate

Note: In Python 3.4, pathlib is now part of the standard library.  For other
Python versions please consider python-pathlib2 instead, which tracks the
standard library module.  This module (python-pathlib) isn't maintained
anymore.")
    (license license:expat)))

(define-public python2-pathlib
  (package-with-python2 python-pathlib))

(define-public python2-pathlib2
  (package
    (name "python2-pathlib2")
    (version "2.3.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pathlib2" version))
              (sha256
               (base32
                "10yb0iv5x2hs631rcppkhbddx799d3h8pcwmkbh2a66ns3w71ccf"))))
    (build-system python-build-system)
    ;; We only need the the Python 2 variant, since for Python 3 our minimum
    ;; version is 3.4 which already includes this package as part of the
    ;; standard library.
    (arguments
     `(#:python ,python-2))
    (propagated-inputs
     `(("python2-scandir" ,python2-scandir)
       ("python2-six" ,python2-six)))
    (home-page "https://pypi.python.org/pypi/pathlib2/")
    (synopsis "Object-oriented file system paths - backport of standard
pathlib module")
    (description "The goal of pathlib2 is to provide a backport of standard
pathlib module which tracks the standard library module, so all the newest
features of the standard pathlib can be used also on older Python versions.

Pathlib offers a set of classes to handle file system paths.  It offers the
following advantages over using string objects:

@enumerate
@item No more cumbersome use of os and os.path functions.  Everything can
be done easily through operators, attribute accesses, and method calls.
@item Embodies the semantics of different path types.  For example,
comparing Windows paths ignores casing.
@item Well-defined semantics, eliminating any inconsistencies or
ambiguities (forward vs. backward slashes, etc.).
@end enumerate")
    (license license:expat)))

(define-public python2-pathlib2-bootstrap
  (hidden-package
   (package
     (inherit python2-pathlib2)
     (name "python2-pathlib2-bootstrap")
     (propagated-inputs
      `(("python2-scandir" ,python2-scandir)
        ("python2-six" ,python2-six-bootstrap))))))

(define-public python-jellyfish
  (package
    (name "python-jellyfish")
    (version "0.5.6")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "jellyfish" version))
              (sha256
               (base32
                "1j9rplb16ba2prjj6mip46z0w9pnhnqpwgiwi0x93vnas14rlyl8"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/jamesturk/jellyfish")
    (synopsis "Approximate and phonetic matching of strings")
    (description "Jellyfish uses a variety of string comparison and phonetic
encoding algorithms to do fuzzy string matching.")
    (license license:bsd-2)
    (properties `((python2-variant . ,(delay python2-jellyfish))))))

(define-public python2-jellyfish
  (let ((jellyfish (package-with-python2
                     (strip-python2-variant python-jellyfish))))
    (package (inherit jellyfish)
      (native-inputs `(("python2-unicodecsv" ,python2-unicodecsv)
                       ,@(package-native-inputs jellyfish))))))

(define-public python2-unicodecsv
  (package
    (name "python2-unicodecsv")
    (version "0.14.1")
    (source (origin
             (method url-fetch)
             ;; The test suite is not included in the PyPi release.
             ;; https://github.com/jdunck/python-unicodecsv/issues/19
             (uri (string-append "https://github.com/jdunck/python-unicodecsv/"
                                 "archive/" version ".tar.gz"))
             (file-name (string-append name "-" version ".tar.gz"))
             (sha256
              (base32
               "087nqanfcyp6mlfbbr5lva5f3w6iz1bybls9xlrb8icmc474wh4w"))))
    (build-system python-build-system)
    (arguments
     `(;; It supports Python 3, but Python 3 can already do Unicode CSV.
       #:python ,python-2))
    (native-inputs
     `(("python2-unittest2" ,python2-unittest2)))
    (home-page "https://github.com/jdunck/python-unicodecsv")
    (synopsis "Unicode CSV module for Python 2")
    (description "Unicodecsv is a drop-in replacement for Python 2.7's CSV
module, adding support for Unicode strings.")
    (license license:bsd-2)))

(define-public python-rarfile
  (package
    (name "python-rarfile")
    (version "2.8")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "rarfile" version))
              (sha256
               (base32
                "0qfad483kcbga0bn4qmcz953xjk16r52fahiy46zzn56v80y89ra"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           ;; Many tests fail, but the installation proceeds.
           (lambda _ (invoke "make" "-C" "test" "test"))))))
    (native-inputs
     `(("which" ,which))) ; required for tests
    (propagated-inputs
     `(("libarchive" ,libarchive)))
    (home-page "https://github.com/markokr/rarfile")
    (synopsis "RAR archive reader for Python")
    (description "This is Python module for RAR archive reading.  The interface
is made as zipfile like as possible.")
    (license license:isc)))

(define-public python2-rarfile
  (package-with-python2 python-rarfile))

(define-public python-magic
  (package
    (name "python-magic")
    (version "0.4.15")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "python-magic" version))
       (sha256
        (base32
         "1mgwig9pnzgkf86q9ji9pnc99bngms15lfszq5rgqb9db07mqxpk"))
       (file-name (string-append name "-" version "-checkout"))))
    (build-system python-build-system)
    (arguments
     ;; The tests are unreliable, so don't run them.  The tests fail
     ;; under Python3 because they were written for Python2 and
     ;; contain import statements that do not work in Python3.  One of
     ;; the tests fails under Python2 because its assertions are
     ;; overly stringent; it relies on comparing output strings which
     ;; are brittle and can change depending on the version of
     ;; libmagic being used and the system on which the test is
     ;; running.  In my case, under GuixSD 0.10.0, only one test
     ;; failed, and it seems to have failed only because the version
     ;; of libmagic that is packaged in Guix outputs a slightly
     ;; different (but not wrong) string than the one that the test
     ;; expected.
     '(#:tests? #f
       #:phases (modify-phases %standard-phases
                  ;; Replace a specific method call with a hard-coded
                  ;; path to the necessary libmagic.so file in the
                  ;; store.  If we don't do this, then the method call
                  ;; will fail to find the libmagic.so file, which in
                  ;; turn will cause any application using
                  ;; python-magic to fail.
                  (add-before 'build 'hard-code-path-to-libmagic
                    (lambda* (#:key inputs #:allow-other-keys)
                      (let ((file (assoc-ref inputs "file")))
                        (substitute* "magic.py"
                          (("ctypes.util.find_library\\('magic'\\)")
                           (string-append "'" file "/lib/libmagic.so'")))
                        #t)))
                  (add-before 'install 'disable-egg-compression
                    (lambda _
                      (let ((port (open-file "setup.cfg" "a")))
                        (display "\n[easy_install]\nzip_ok = 0\n"
                                 port)
                        (close-port port)
                        #t))))))
    (inputs
     ;; python-magic needs to be able to find libmagic.so.
     `(("file" ,file)))
    (home-page
     "https://github.com/ahupp/python-magic")
    (synopsis
     "File type identification using libmagic")
    (description
     "This module uses ctypes to access the libmagic file type
identification library.  It makes use of the local magic database and
supports both textual and MIME-type output.  Note that this module and
the python-file module both provide a \"magic.py\" file; these two
modules, which are different and were developed separately, both serve
the same purpose: to provide Python bindings for libmagic.")
    (license license:expat)))

(define-public python2-magic
  (package-with-python2 python-magic))

(define-public python2-s3cmd
  (package
    (name "python2-s3cmd")
    (version "1.6.1")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "mirror://sourceforge/s3tools/s3cmd/" version "/"
                            "s3cmd-" version ".tar.gz"))
        (sha256
          (base32
            "0ki1rzhm5icvi9ry5jswi4b22yqwyj0d2wsqsgilwx6qhi7pjxa6"))))
    (build-system python-build-system)
    (arguments
     ;; s3cmd is written for python2 only and contains no tests.
     `(#:python ,python-2
       #:tests? #f))
    (propagated-inputs
     `(("python2-dateutil" ,python2-dateutil)
       ;; The python-file package also provides a magic.py module.
       ;; This is an unfortunate state of affairs; however, s3cmd
       ;; fails to install if it cannot find specifically the
       ;; python-magic package.  Thus we include it, instead of using
       ;; python-file.  Ironically, s3cmd sometimes works better
       ;; without libmagic bindings at all:
       ;; https://github.com/s3tools/s3cmd/issues/198
       ("python2-magic" ,python2-magic)))
    (home-page "http://s3tools.org/s3cmd")
    (synopsis "Command line tool for S3-compatible storage services")
    (description
     "S3cmd is a command line tool for uploading, retrieving and managing data
in storage services that are compatible with the Amazon Simple Storage
Service (S3) protocol, including S3 itself.  It supports rsync-like backup,
GnuPG encryption, and more.  It also supports management of Amazon's
CloudFront content delivery network.")
    (license license:gpl2+)))

(define-public python-pkgconfig
  (package
    (name "python-pkgconfig")
    (version "1.3.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pkgconfig" version))
        (sha256
          (base32
            "107x2wmchlch8saixb488cgjz9n6inl38wi7nxkb942rbaapxiqb"))))
    (build-system python-build-system)
    (native-inputs
      `(("python-nose" ,python-nose)))
    (inputs
      `(("pkg-config" ,pkg-config)))
    (arguments
      `(#:phases
        (modify-phases %standard-phases
          (add-before 'build 'patch
            ;; Hard-code the path to pkg-config.
            (lambda _
              (substitute* "pkgconfig/pkgconfig.py"
                (("cmd = 'pkg-config")
                 (string-append "cmd = '" (which "pkg-config"))))
              #t))
          (replace 'check
            (lambda _
              (invoke "nosetests" "test.py"))))))
    (home-page "https://github.com/matze/pkgconfig")
    (synopsis "Python interface for pkg-config")
    (description "This module provides a Python interface to pkg-config.  It
can be used to find all pkg-config packages, check if a package exists,
check if a package meets certain version requirements, query CFLAGS and
LDFLAGS and parse the output to build extensions with setup.py.")
    (license license:expat)))

(define-public python2-pkgconfig
  (package-with-python2 python-pkgconfig))

(define-public python-bz2file
  (package
    (name "python-bz2file")
    (version "0.98")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "bz2file" version))
       (sha256
        (base32
         "126s53fkpx04f33a829yqqk8fj4png3qwg4m66cvlmhmwc8zihb4"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f)) ; Tests use deprecated python modules.
    (home-page "https://github.com/nvawda/bz2file")
    (synopsis "Read and write bzip2-compressed files")
    (description
     "Bz2file is a Python library for reading and writing bzip2-compressed
files.  It contains a drop-in replacement for the I/O interface in the
standard library's @code{bz2} module, including features from the latest
development version of CPython that are not available in older releases.")
    (license license:asl2.0)))

(define-public python2-bz2file
  (package-with-python2 python-bz2file))

(define-public python-future
  (package
    (name "python-future")
    (version "0.17.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "future" version))
       (sha256
        (base32
         "1f2rlqn9rh7adgir52dlbqz69gsab44x0mlm8gf1cs7xvhv54137"))))
    (build-system python-build-system)
    ;; Many tests connect to the network or are otherwise flawed.
    ;; https://github.com/PythonCharmers/python-future/issues/210
    (arguments
     `(#:tests? #f))
    (home-page "http://python-future.org")
    (synopsis "Single-source support for Python 3 and 2")
    (description
     "@code{python-future} is the missing compatibility layer between Python 2 and
Python 3.  It allows you to use a single, clean Python 3.x-compatible codebase
to support both Python 2 and Python 3 with minimal overhead.")
    (license license:expat)))

(define-public python2-future
  (package-with-python2 python-future))

(define-public python-cysignals
  (package
    (name "python-cysignals")
    (version "1.9.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "cysignals" version))
        (sha256
          (base32
            "15ix8crpad26cfl1skyg7qajqqfdrm8q5ahhmlfmqi1aw0jqj2g2"))))
    (build-system python-build-system)
    (native-inputs
      `(("python-cython" ,python-cython)
        ("python-sphinx" ,python-sphinx)))
    (inputs
      `(("pari-gp" ,pari-gp)))
    (arguments
     `(#:modules ((guix build python-build-system)
                  ((guix build gnu-build-system) #:prefix gnu:)
                  (guix build utils))
       ;; FIXME: Tests are executed after installation and currently fail
       ;; when not installing into standard locations; the author is working
       ;; on a fix.
       #:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-before
          'build 'configure
          (assoc-ref gnu:%standard-phases 'configure)))))
    (home-page
      "https://github.com/sagemath/cysignals")
    (synopsis
      "Handling of interrupts and signals for Cython")
    (description
      "The cysignals package provides mechanisms to handle interrupts (and
other signals and errors) in Cython code, using two related approaches,
for mixed Cython/Python code or external C libraries and pure Cython code,
respectively.")
    (license license:lgpl3+)))

(define-public python2-cysignals
  (package-with-python2 python-cysignals))

(define-public python2-shedskin
 (package
  (name "python2-shedskin")
  (version "0.9.4")
  (source
    (origin
      (method url-fetch)
      (uri (string-append "https://github.com/shedskin/shedskin/"
                          "releases/download/v" version
                          "/shedskin-" version ".tgz"))
      (sha256
        (base32
          "0nzwrzgw1ga8rw6f0ryq7zr9kkiavd1cqz5hzxkcbicl1dk7kz41"))))
  (build-system python-build-system)
  (arguments
   `(#:python ,python-2
     #:phases (modify-phases %standard-phases
               (add-after 'unpack 'fix-resulting-include-libs
                (lambda* (#:key inputs #:allow-other-keys)
                 (let ((libgc (assoc-ref inputs "libgc"))
                       (pcre (assoc-ref inputs "pcre")))
                  (substitute* "shedskin/makefile.py"
                   (("variable == 'CCFLAGS':[ ]*")
                    (string-append "variable == 'CCFLAGS':\n"
                                   "            line += ' -I " pcre "/include"
                                   " -I " libgc "/include'"))
                   (("variable == 'LFLAGS':[ ]*")
                    (string-append "variable == 'LFLAGS':\n"
                                   "            line += ' -L" pcre "/lib"
                                   " -L " libgc "/lib'")))
                  #t))))))
  (inputs `(("pcre" ,pcre)
            ("libgc" ,libgc)))
  (home-page "https://shedskin.github.io/")
  (synopsis "Experimental Python-2 to C++ Compiler")
  (description (string-append "This is an experimental compiler for a subset of
Python.  It generates C++ code and a Makefile."))
  (license (list license:gpl3 license:bsd-3 license:expat))))

(define-public python2-rope
  (package
    (name "python2-rope")
    (version "0.11.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "rope" version))
      (sha256
        (base32
         "1cppm0pa9aqgsbkq130lskrzmrvjs5vpiavjjbhpz2fdw52w8251"))))
    (arguments
     ;; Rope has only partial python3 support, see `python-rope'
     `(#:python ,python-2))
    (build-system python-build-system)
    (native-inputs
     `(("python2-unittest2" ,python2-unittest2)))
    (home-page "https://github.com/python-rope/rope")
    (synopsis "Refactoring library for Python")
    (description "Rope is a refactoring library for Python.  It facilitates
the renaming, moving and extracting of attributes, functions, modules, fields
and parameters in Python 2 source code.  These refactorings can also be applied
to occurrences in strings and comments.")
    (license license:gpl2)))

(define-public python-rope
  (package
    (inherit python2-rope)
    (name "python-rope")
    (arguments `(#:python ,python-wrapper
                 ;; XXX: Only partial python3 support, results in some failing
                 ;; tests: <https://github.com/python-rope/rope/issues/247>.
                 #:tests? #f))
    (properties `((python2-variant . ,(delay python2-rope))))))

(define-public python-py3status
  (package
    (name "python-py3status")
    (version "3.16")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "py3status" version))
       (sha256
        (base32
         "1xrfph277bgjln3jbpzpgkhxad04fjvj7s3xfil42q1sxi4s3q3g"))))
    (build-system python-build-system)
    (inputs
     `(("file" ,file)))
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         ;; 'file' is used for detection of configuration file encoding
         ;; let's make link the dependency to particular input
         (add-before 'build 'patch-file-path
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((file-path (assoc-ref inputs "file")))
               (substitute* "py3status/parse_config.py"
                 (("\\['file', '-b'")
                  (string-append "['" file-path "/bin/file', '-b'")))
               #t))))
       #:tests? #f)) ; TODO: Requires many libraries not in Guix.
    (home-page "https://github.com/ultrabug/py3status")
    (synopsis "Extensible i3status wrapper written in Python")
    (description "py3status is an i3status wrapper which extends i3status
functionality in a modular way, allowing you to extend your panel with your
own code, responding to click events and updating clock every second.")
    (license license:bsd-3)))

(define-public python-tblib
  (package
    (name "python-tblib")
    (version "1.3.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "tblib" version))
              (sha256 (base32
                       "1rsg8h069kqgncyv8fgzyj6qflk6j10cb78pa5jk34ixwq044vj3"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'adjust-tests
           (lambda _
             (when (which "python3")
               ;; Adjust the example output to match that of Python 3.7:
               ;; <https://github.com/ionelmc/python-tblib/issues/36>.
               (substitute* "README.rst"
                 (("Exception\\('fail',") "Exception('fail'"))
               #t)))
         (replace 'check
           (lambda _
             ;; Upstream runs tests after installation and the package itself
             ;; resides in a subdirectory. Extend PYTHONPATH so it will be
             ;; found.
             (setenv "PYTHONPATH"
                     (string-append (getcwd) "/build/lib:"
                                    (getenv "PYTHONPATH")))
             (invoke "py.test" "-vv" "tests" "README.rst"))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-six" ,python-six)))
    (home-page "https://github.com/ionelmc/python-tblib")
    (synopsis "Traceback serialization library")
    (description
     "Traceback serialization allows you to:

@enumerate
@item Pickle tracebacks and raise exceptions with pickled tracebacks in
different processes.  This allows better error handling when running code over
multiple processes (imagine multiprocessing, billiard, futures, celery etc).

@item Parse traceback strings and raise with the parsed tracebacks.
@end enumerate\n")
    (license license:bsd-3)))

(define-public python2-tblib
  (package-with-python2 python-tblib))

(define-public python-greenlet
  (package
    (name "python-greenlet")
    (version "0.4.15")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "greenlet" version))
              (sha256
               (base32
                "1g4g1wwc472ds89zmqlpyan3fbnzpa8qm48z3z1y6mlk44z485ll"))))
    (build-system python-build-system)
    (home-page "https://greenlet.readthedocs.io/")
    (synopsis "Lightweight in-process concurrent programming")
    (description
     "Greenlet package is a spin-off of Stackless, a version of CPython
that supports micro-threads called \"tasklets\".  Tasklets run
pseudo-concurrently (typically in a single or a few OS-level threads) and
are synchronized with data exchanges on \"channels\".")
    (license (list license:psfl license:expat))))

(define-public python2-greenlet
  (package-with-python2 python-greenlet))

(define-public python-objgraph
  (package
    (name "python-objgraph")
    (version "3.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "objgraph" version))
       (sha256
        (base32
         "184m09am5gpbqfaiy7l0hwh476mczbrly1dffs0rw2p1d1i2q32a"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-graphviz" ,python-graphviz)))
    (native-inputs
     `(("python-mock" ,python-mock)
       ("graphviz" ,graphviz)))
    (home-page "https://mg.pov.lt/objgraph/")
    (synopsis "Draw Python object reference graphs with graphviz")
    (description
     "This package provides tools to draw Python object reference graphs with
graphviz.")
    (license license:expat)))

(define-public python-gevent
  (package
    (name "python-gevent")
    (version "1.3.7")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "gevent" version))
              (sha256
               (base32
                "0b0fr04qdk1p4sniv87fh8z5psac60x01pv054kpgi94520g81iz"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  ;; unbunding libev and c-ares
                  (delete-file-recursively "deps")
                  #t))))
    (build-system python-build-system)
    (arguments
     `(#:modules ((ice-9 ftw)
                  (ice-9 match)
                  (srfi srfi-26)
                  (guix build utils)
                  (guix build python-build-system))
       #:phases (modify-phases %standard-phases
                  (add-after 'unpack 'unpack-libev
                    (lambda* (#:key inputs #:allow-other-keys)
                      (mkdir-p "deps/libev")
                      ;; FIXME: gevent requires building libev, even though
                      ;; it only links against the proper one.
                      (invoke "tar" "-xf" (assoc-ref inputs "libev-source")
                              "--strip-components=1" "-C" "deps/libev")))
                  (add-before 'patch-source-shebangs 'patch-hard-coded-paths
                    (lambda _
                      (substitute* "src/gevent/subprocess.py"
                        (("/bin/sh") (which "sh")))
                      (for-each (lambda (file)
                                  (substitute* file
                                    (("/bin/sh") (which "sh"))
                                    (("/bin/true") (which "true"))))
                                (find-files "src/greentest" "\\.py$"))
                      #t))
                  (add-before 'build 'do-not-use-bundled-sources
                    (lambda* (#:key inputs #:allow-other-keys)
                      (setenv "CONFIG_SHELL" (which "bash"))
                      (setenv "LIBEV_EMBED" "false")
                      (setenv "CARES_EMBED" "false")
                      (setenv "EMBED" "false")

                      (let ((greenlet (string-append
                                       (assoc-ref inputs "python-greenlet")
                                       "/include")))
                        (match (scandir greenlet
                                        (lambda (item)
                                          (string-prefix? "python" item)))
                          ((python)
                           (setenv "CPATH"
                                   (string-append greenlet "/" python)))))
                      #t))
                  (add-before 'check 'skip-timer-test
                    (lambda _
                      ;; XXX: Skip 'TestTimerResolution', which appears to be
                      ;; unreliable.
                      (substitute* "src/greentest/test__core_timer.py"
                                   (("not greentest.RUNNING_ON_CI") "False"))
                      #t))
                  (replace 'check
                    (lambda _
                      ;; Make sure the build directory is on PYTHONPATH.
                      (setenv "PYTHONPATH"
                              (string-append
                               (getenv "PYTHONPATH") ":"
                               (getcwd) "/build/"
                               (car (scandir "build" (cut string-prefix? "lib." <>)))))
                      (with-directory-excursion "src/greentest"
                        ;; XXX: Many tests require network access.  Instead we only
                        ;; run known-good tests.  Unfortunately we cannot use
                        ;; recursion here since this directory also contains
                        ;; Python-version-specific subfolders.
                        (apply invoke "python" "testrunner.py" "--config"
                               "known_failures.py"
                               (scandir "." (cut regexp-exec
                                                 (make-regexp "test_+(subprocess|core)")
                                                 <>)))))))))
    (propagated-inputs
     `(("python-greenlet" ,python-greenlet)
       ("python-objgraph" ,python-objgraph)))
    (native-inputs
     `(("libev-source" ,(package-source libev))
       ("python-six" ,python-six)))
    (inputs
     `(("c-ares" ,c-ares)
       ("libev" ,libev)))
    (home-page "http://www.gevent.org/")
    (synopsis "Coroutine-based network library")
    (description
     "gevent is a coroutine-based Python networking library that uses greenlet
to provide a high-level synchronous API on top of the libev event loop.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-gevent))))))

(define-public python2-gevent
  (let ((base (package-with-python2
               (strip-python2-variant python-gevent))))
    (package
      (inherit base)
      (native-inputs `(,@(package-native-inputs python-gevent)
                       ("python-mock" ,python2-mock))))))

(define-public python-fastimport
  (package
    (name "python-fastimport")
    (version "0.9.6")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "fastimport" version))
        (sha256
          (base32 "1aqjsin4rmqm7ln4j0p73fzxifws6c6ikgyhav7r137m2ixsxl43"))))
    (build-system python-build-system)
    (home-page "https://github.com/jelmer/python-fastimport")
    (synopsis "VCS fastimport parser and generator in Python")
    (description "This package provides a parser for and generator of the Git
@url{https://www.kernel.org/pub/software/scm/git/docs/git-fast-import.html,fastimport}
format.")
    (license license:gpl2+)))

(define-public python2-fastimport
  (package-with-python2 python-fastimport))

(define-public python-twisted
  (package
    (name "python-twisted")
    (version "19.2.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "Twisted" version ".tar.bz2"))
              (sha256
               (base32
                "0liymyd4pzphizjlpwkncxjpm9akyr3lkfkm77yfg6wasv108b7s"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f))                    ; FIXME: some tests fail
    (propagated-inputs
     `(("python-zope-interface" ,python-zope-interface)
       ("python-pyhamcrest" ,python-pyhamcrest)
       ("python-incremental" ,python-incremental)
       ("python-hyperlink" ,python-hyperlink)
       ("python-constantly" ,python-constantly)
       ("python-automat" ,python-automat)))
    (home-page "https://twistedmatrix.com/")
    (synopsis "Asynchronous networking framework written in Python")
    (description
     "Twisted is an extensible framework for Python programming, with special
focus on event-based network programming and multiprotocol integration.")
    (license license:expat)))

(define-public python2-twisted
  (package-with-python2 python-twisted))

(define-public python-pika
  (package
    (name "python-pika")
    (version "0.12.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pika" version))
        (sha256
         (base32
          "0ld7akgm93s8pfa4dsx9qlzlhj76zspbr5m9ms0ns09yd2w4aq9h"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pyev" ,python-pyev)
       ("python-tornado" ,python-tornado)
       ("python-twisted" ,python-twisted)))
    (home-page "https://pika.readthedocs.org")
    (synopsis "Pure Python AMQP Client Library")
    (description
     "Pika is a pure-Python implementation of the AMQP (Advanced Message Queuing
Protocol) 0-9-1 protocol that tries to stay fairly independent of the underlying
network support library.")
    (license license:bsd-3)))

(define-public python2-pika
  (package-with-python2 python-pika))

(define-public python-ply
  (package
    (name "python-ply")
    (version "3.10")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "ply" version))
        (sha256
          (base32
            "1jxsr1d2f732r6ljhvm827113dckwl6qwakfvpbdhcbhvpvlmscn"))))
    (build-system python-build-system)
    (home-page "http://www.dabeaz.com/ply/")
    (synopsis "Python Lex & Yacc")
    (description "PLY is a @code{lex}/@code{yacc} implemented purely in Python.
It uses LR parsing and does extensive error checking.")
    (license license:bsd-3)))

(define-public python2-ply
  (package-with-python2 python-ply))

(define-public python-tabulate
  (package
    (name "python-tabulate")
    (version "0.7.7")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "tabulate" version))
             (sha256
              (base32
               "1inqhspd4frxnp08c32yndr0lc4px1xfkqah184i5w09gkhvi843"))))
    (build-system python-build-system)
    (arguments
     ;; FIXME: The pypi release tarball is missing a 'test/common.py'
     ;; and the latest release is not tagged in the upstream repository.
     '(#:tests? #f))
    (home-page "https://bitbucket.org/astanin/python-tabulate")
    (synopsis "Pretty-print tabular data")
    (description
     "Tabulate is a library and command-line utility to pretty-print tabular
data in Python.")
    (license license:expat)))

(define-public python2-tabulate
  (package-with-python2 python-tabulate))

(define-public python-kazoo
  (package
    (name "python-kazoo")
    (version "2.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "kazoo" version))
       (sha256
        (base32
         "16y213k7r8shyn2zw1k6lkzjgcrvm441pqv8scvcjixhvpbx3hm7"))))
    (build-system python-build-system)
    (arguments '(#:tests? #f)) ; XXX: needs zookeeper
    (propagated-inputs
     `(("python-six" ,python-six)))
    (home-page "https://kazoo.readthedocs.org")
    (synopsis "High-level Zookeeper client library")
    (description
     "Kazoo is a Python client library for the Apache Zookeeper distributed
application service.  It is designed to be easy to use and to avoid common
programming errors.")
    (license license:asl2.0)))

(define-public python2-kazoo
  (package-with-python2 python-kazoo))

(define-public python-pykafka
  (package
    (name "python-pykafka")
    (version "2.4.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pykafka" version))
              (sha256
               (base32
                "1id6sr159p6aa13bxcqyr9gln8sqg1l0ddzns5iws8kk5q1p5cfv"))))
    (build-system python-build-system)
    (arguments '(#:tests? #f)) ; XXX: needs zookeeper, kafka, etc.
    (propagated-inputs
     `(("python-gevent" ,python-gevent)
       ("python-kazoo" ,python-kazoo)
       ("python-tabulate" ,python-tabulate)))
    (inputs
     `(("librdkafka" ,librdkafka)))
    (home-page "https://pykafka.readthedocs.io/")
    (synopsis "Apache Kafka client for Python")
    (description
     "PyKafka is a client for the Apache Kafka distributed messaging system.
It includes Python implementations of Kafka producers and consumers, which
are optionally backed by a C extension built on librdkafka.")
    (license license:asl2.0)))

(define-public python2-pykafka
  (package-with-python2 python-pykafka))

(define-public python-wcwidth
 (package
  (name "python-wcwidth")
  (version "0.1.7")
  (source
    (origin
      (method url-fetch)
      (uri (pypi-uri "wcwidth" version))
      (sha256
        (base32
          "0pn6dflzm609m4r3i8ik5ni9ijjbb5fa3vg1n7hn6vkd49r77wrx"))))
  (build-system python-build-system)
  (home-page "https://github.com/jquast/wcwidth")
  (synopsis "Measure number of terminal column cells of wide-character codes")
  (description "Wcwidth measures the number of terminal column cells of
wide-character codes.  It is useful for those implementing a terminal emulator,
or programs that carefully produce output to be interpreted by one.  It is a
Python implementation of the @code{wcwidth} and @code{wcswidth} C functions
specified in POSIX.1-2001 and POSIX.1-2008.")
  (license license:expat)))

(define-public python2-wcwidth
  (package-with-python2 python-wcwidth))

(define-public python2-jsonrpclib
  (package
    (name "python2-jsonrpclib")
    (version "0.1.7")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "jsonrpclib" version))
              (sha256
               (base32
                "02vgirw2bcgvpcxhv5hf3yvvb4h5wzd1lpjx8na5psdmaffj6l3z"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f
       #:python ,python-2))
    (home-page "https://github.com/joshmarshall/jsonrpclib/")
    (synopsis "Implementation of JSON-RPC specification for Python")
    (description
     "This library is an implementation of the JSON-RPC specification.
It supports both the original 1.0 specification, as well as the
new (proposed) 2.0 spec, which includes batch submission, keyword arguments,
etc.")
    (license license:asl2.0)))

(define-public python-chai
  (package
    (name "python-chai")
    (version "1.1.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "chai" version))
              (sha256
               (base32
                "1k6n6zbgrrs83crp6mr3yqj9zlv40b8rpisyrliwsq7naml2p3gz"))))
    (build-system python-build-system)
    (home-page "https://github.com/agoragames/chai")
    (synopsis "Mocking framework for Python")
    (description
     "Chai provides an api for mocking, stubbing and spying your python
objects, patterned after the Mocha library for Ruby.")
    (license license:bsd-3)))

(define-public python2-chai
  (package-with-python2 python-chai))

(define-public python-inflection
  (package
    (name "python-inflection")
    (version "0.3.1")
    (source
     (origin (method url-fetch)
             (uri (pypi-uri "inflection" version))
             (sha256
              (base32
               "1jhnxgnw8y3mbzjssixh6qkc7a3afc4fygajhqrqalnilyvpzshq"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/jpvanhal/inflection")
    (synopsis "Python string transformation library")
    (description
     "Inflection is a string transformation library.  It singularizes
and pluralizes English words, and transforms strings from CamelCase to
underscored string.")
    (license license:expat)))

(define-public python2-inflection
  (package-with-python2 python-inflection))

(define-public python-pylev
  (package
    (name "python-pylev")
    (version "1.3.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pylev" version))
              (sha256
               (base32
                "1hz1x9blsbxya1y9nnhnwwdnqmakxi9mc0jkwj0rn6b1h44i0f86"))))
    (build-system python-build-system)
    (home-page "https://github.com/toastdriven/pylev")
    (synopsis "Levenshtein distance implementation in Python")
    (description "Pure Python Levenshtein implementation, based off the
Wikipedia code samples at
@url{http://en.wikipedia.org/wiki/Levenshtein_distance}.")
    (license license:bsd-3)))

(define-public python2-pylev
  (package-with-python2 python-pylev))

(define-public python-cleo
  (package
    (name "python-cleo")
    (version "0.6.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "cleo" version))
              (sha256
               (base32
                "0q1cf0szr0d54am4pypzwdnm74zpladdsinad94c2fz5i06fdpf7"))))
    (build-system python-build-system)
    (native-inputs
     `(;; For testing
       ("python-mock" ,python-mock)
       ("python-pytest-mock" ,python-pytest-mock)
       ("python-pytest" ,python-pytest)))
    (propagated-inputs
     `(("python-backpack" ,python-backpack)
       ("python-pastel" ,python-pastel)
       ("python-pylev" ,python-pylev)))
    (home-page "https://github.com/sdispater/cleo")
    (synopsis "Command-line arguments library for Python")
    (description
     "Cleo allows you to create command-line commands with signature in
docstring and colored output.")
    (license license:expat)))

(define-public python2-cleo
  (package-with-python2 python-cleo))

(define-public python-lazy-object-proxy
  (package
    (name "python-lazy-object-proxy")
    (version "1.3.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "lazy-object-proxy" version))
              (sha256
               (base32
                "0yha7q9bhw857fwaby785d63mffhngl9npwzlk9i0pwlkwvbx4gb"))))
    (build-system python-build-system)
    (home-page "https://github.com/ionelmc/python-lazy-object-proxy")
    (synopsis "Lazy object proxy for python")
    (description
     "Lazy object proxy is an object that wraps a callable but defers the call
until the object is actually required, and caches the result of said call.")
    (license license:bsd-2)))

(define-public python2-lazy-object-proxy
  (package-with-python2 python-lazy-object-proxy))

(define-public python-dnspython
  (package
  (name "python-dnspython")
  (version "1.15.0")
  (source (origin
            (method url-fetch)
            (uri (string-append "http://www.dnspython.org/kits/"
                                version "/dnspython-" version ".tar.gz"))
            (sha256
             (base32
              "0jr4v2pd90i6l1xxbss2m05psbjaxvyvvvpq44wycijpfgjqln8i"))))
  (build-system python-build-system)
  (arguments '(#:tests? #f)) ; XXX: requires internet access
  (home-page "http://www.dnspython.org")
  (synopsis "DNS toolkit for Python")
  (description
   "dnspython is a DNS toolkit for Python.  It supports almost all record
types.  It can be used for queries, zone transfers, and dynamic updates.
It supports TSIG authenticated messages and EDNS0.")
  (license license:expat)))

(define-public python2-dnspython
  (package-with-python2 python-dnspython))

(define-public python-email-validator
  (package
    (name "python-email-validator")
    (version "1.0.2")
    (source
     (origin (method url-fetch)
             (uri (pypi-uri "email_validator" version))
             (sha256
              (base32
               "1ja9149l9ck5n45a72h3is7v476hjny5ybxbcamx1nw6iplsm7k6"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-before 'build 'use-dnspython
           (lambda _
             (substitute* "setup.py"
               (("dnspython3") "dnspython"))
             #t)))))
    (propagated-inputs
     `(("python-dnspython" ,python-dnspython)
       ("python-idna" ,python-idna)))
    (home-page "https://github.com/JoshData/python-email-validator")
    (synopsis "Email address validation library for Python")
    (description
     "This library validates email address syntax and deliverability.")
    (license license:cc0)))

(define-public python2-email-validator
  (package-with-python2 python-email-validator))

(define-public python-ukpostcodeparser
  (package
    (name "python-ukpostcodeparser")
    (version "1.0.3")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "UkPostcodeParser" version))
              (sha256
               (base32
                "1jwg9z4rz51mcka1821rwgycsd0mcicyp1kiwjfa2kvg8bm9p2qd"))))
    (build-system python-build-system)
    (home-page "https://github.com/hamstah/ukpostcodeparser")
    (synopsis "UK Postcode parser for Python")
    (description
     "This library provides the @code{parse_uk_postcode} function for
parsing UK postcodes.")
    (license license:expat)))

(define-public python2-ukpostcodeparser
  (package-with-python2 python-ukpostcodeparser))

(define-public python-faker
  (package
  (name "python-faker")
  (version "0.7.9")
  (source (origin
            (method url-fetch)
            (uri (pypi-uri "Faker" version))
            (sha256
             (base32
              "1fh2p2yz0fsdr4fqwxgddwbvfb6qn6vp8yx0qwqzra27yq5d1wsm"))
            (patches
             (search-patches "python-faker-fix-build-32bit.patch"))
            (modules '((guix build utils)))
            (snippet
             '(begin
                (for-each delete-file (find-files "." "\\.pyc$"))
                #t))))
  (build-system python-build-system)
  (arguments
   '(#:phases
     (modify-phases %standard-phases
       (replace 'check
         (lambda _ (invoke "python" "-m" "unittest" "-v" "tests"))))))
  (native-inputs
   `(;; For testing
     ("python-email-validator" ,python-email-validator)
     ("python-mock" ,python-mock)
     ("python-ukpostcodeparser" ,python-ukpostcodeparser)))
  (propagated-inputs
   `(("python-dateutil" ,python-dateutil)
     ("python-six" ,python-six)))
  (home-page "https://github.com/joke2k/faker")
  (synopsis "Python package that generates fake data")
  (description
   "Faker is a Python package that generates fake data such as names,
addresses, and phone numbers.")
  (license license:expat)
  (properties `((python2-variant . ,(delay python2-faker))))))

(define-public python2-faker
  (let ((base (package-with-python2 (strip-python2-variant
                                     python-faker))))
    (package
      (inherit base)
      (propagated-inputs
       `(("python2-ipaddress" ,python2-ipaddress)
         ,@(package-propagated-inputs base))))))

(define-public python-pyaml
  (package
    (name "python-pyaml")
    (version "18.11.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pyaml" version))
              (sha256
               (base32
                "0fi604ix8lbpj1266q7js6szm771saprdzzcdwmj43wy83694qmr"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-unidecode" ,python-unidecode)))
    (propagated-inputs
     `(("python-pyyaml" ,python-pyyaml)))
    (home-page "https://github.com/mk-fg/pretty-yaml")
    (synopsis "YAML pretty-print library for Python")
    (description
     "pyaml is a PyYAML based python module to produce pretty and readable
YAML-serialized data.")
    (license license:wtfpl2)))

(define-public python2-pyaml
  (package-with-python2 python-pyaml))

(define-public python-backpack
  (package
    (name "python-backpack")
    (version "0.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "backpack" version))
       (sha256
        (base32
         "14rq1mvm0jda90lcx9gyyby9dvq4x3js2cmxvd6vl4686ixwyqh1"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-nose" ,python-nose)))
    (propagated-inputs
     `(("python-simplejson" ,python-simplejson)))
    (home-page "https://github.com/sdispater/backpack")
    (synopsis "Utilities for working with Python collections")
    (description "Backpack provides some useful utilities for working with
collections of data.")
    (license license:expat)))

(define-public python2-backpack
  (package-with-python2 python-backpack))

(define-public python-prompt-toolkit
  (package
    (name "python-prompt-toolkit")
    (version "2.0.7")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "prompt_toolkit" version ".tar.gz"))
       (sha256
        (base32
         "0fgacqk73w7s932vy46pan2yp8rvjmlkag20xvaydh9mhf6h85zx"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (delete 'check)
         (add-after 'install 'post-install-check
           (lambda* (#:key inputs outputs #:allow-other-keys)
             ;; HOME is needed for the test
             ;; "test_pathcompleter_can_expanduser".
             (setenv "HOME" "/tmp")
             (add-installed-pythonpath inputs outputs)
             (invoke "py.test"))))))
    (propagated-inputs
     `(("python-wcwidth" ,python-wcwidth)
       ("python-six" ,python-six)
       ("python-pygments" ,python-pygments)))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/jonathanslenders/python-prompt-toolkit")
    (synopsis "Library for building command line interfaces in Python")
    (description
     "Prompt-Toolkit is a library for building interactive command line
interfaces in Python.  It's like GNU Readline but it also features syntax
highlighting while typing, out-of-the-box multi-line input editing, advanced
code completion, incremental search, support for Chinese double-width
characters, mouse support, and auto suggestions.")
    (license license:bsd-3)))

(define-public python2-prompt-toolkit
  (package-with-python2 python-prompt-toolkit))

(define-public python-prompt-toolkit-1
  (package (inherit python-prompt-toolkit)
    (version "1.0.15")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "prompt_toolkit" version ".tar.gz"))
       (sha256
        (base32
         "05v9h5nydljwpj5nm8n804ms0glajwfy1zagrzqrg91wk3qqi1c5"))))))

(define-public python2-prompt-toolkit-1
  (package-with-python2 python-prompt-toolkit-1))

(define-public python-jedi
  (package
    (name "python-jedi")
    (version "0.13.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "jedi" version))
       (sha256
        (base32
         "0nsrjlb57njqppxmi8wjsb1dkad7qa7svx67jbkhixq66lz61c1b"))))
    (build-system python-build-system)
    (arguments
     `( ;; Many tests are failing with Python 3.7.x as of version 0.13.3 (see:
        ;; https://github.com/davidhalter/jedi/issues/1263)
       #:tests? #f
       #:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda* (#:key tests? #:allow-other-keys)
             (when tests?
               (invoke "py.test" "-vv")))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-docopt" ,python-docopt)))
    (propagated-inputs
     `(("python-parso" ,python-parso)))
    (home-page "https://github.com/davidhalter/jedi")
    (synopsis "Autocompletion and static analysis library for Python")
    (description
     "Jedi is a static analysis tool for Python that can be used in Integrated
Development Environments (@dfn{IDE}s) and text editors.  It understands Python
on a deeper level than many other static analysis frameworks for Python.

Jedi understands docstrings and you can use Jedi autocompletion in your REPL as
well.")
    (license license:expat)))

(define-public python2-jedi
  (let ((base (package-with-python2 (strip-python2-variant python-jedi))))
    (package
      (inherit base)
      (arguments (substitute-keyword-arguments (package-arguments base)
                   ((#:tests? _) #t))))))

(define-public ptpython
  (package
    (name "ptpython")
    (version "0.34")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "ptpython" version))
              (sha256
               (base32
                "1mmbiyzf0n8hm7z2a562x7w5cbl6jc0zsk6vp40q1z4cyblv1k13"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; FIXME: No tests in pypi tarball.
    (propagated-inputs
     `(("python-docopt" ,python-docopt)
       ("python-jedi" ,python-jedi)
       ("python-prompt-toolkit" ,python-prompt-toolkit)
       ("python-pygments" ,python-pygments)))
    (home-page "https://github.com/jonathanslenders/ptpython")
    (synopsis "Python Read-Eval-Print-Loop with nice IDE-like features")
    (description
     "ptpython is a Python read-eval-print loop with IDE-like features.
It supports syntax highlighting, multiline editing, autocompletion, mouse,
color schemes, bracketed paste, Vi and Emacs keybindings, Chinese characters
etc.")
    (license license:bsd-3)
    (properties `((python2-variant . ,(delay ptpython-2))))))

(define-public ptpython-2
  (let ((base (package-with-python2 (strip-python2-variant ptpython))))
    (package
      (inherit base)
      (name "ptpython2"))))

(define-public python-stem
  (package
    (name "python-stem")
    (version "1.7.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "stem" version))
       (sha256
        (base32
         "18lc95pmc7i089nlsb06dsxyjl5wbhxfqgdxbjcia35ndh8z7sn9"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (invoke "./run_tests.py" "--unit")
             #t)))))
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-pycodestyle" ,python-pycodestyle)
       ("python-pyflakes" ,python-pyflakes)))
    (home-page "https://stem.torproject.org/")
    (synopsis
     "Python controller library that allows applications to interact with Tor")
    (description
     "Stem is a Python controller library for Tor.  With it you can use Tor's
control protocol to script against the Tor process and read descriptor data
relays publish about themselves.")
    (license license:lgpl3)))

(define-public python2-stem
  (package-with-python2 python-stem))

(define-public python-pyserial
  (package
    (name "python-pyserial")
    (version "3.1.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pyserial" version))
        (sha256
          (base32
            "0k1nfdrxxkdlv4zgaqsdv8li0pj3gbh2pyxw8q2bsg6f9490amyn"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; FIXME: 3/49 tests are failing.
       ;; #:phases
       ;; (modify-phases %standard-phases
       ;;   (replace 'check
       ;;     (lambda _
       ;;       (zero? (system* "python" "test/run_all_tests.py" "loop://")))))))
    (home-page
      "https://github.com/pyserial/pyserial")
    (synopsis "Python Serial Port Bindings")
    (description "@code{pyserial} provide serial port bindings for Python.  It
supports different byte sizes, stop bits, parity and flow control with RTS/CTS
and/or Xon/Xoff.  The port is accessed in RAW mode.")
    (license license:bsd-3)))

(define-public python2-pyserial
  (package-with-python2 python-pyserial))

(define-public python-kivy
  (package
    (name "python-kivy")
    (version "1.10.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Kivy" version))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1zzxjdp78hfjjiklzr82l4zwibwcq4j6kgicspqs6iyyfn5yisbw"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f              ; Tests require many optional packages
       #:phases
       (modify-phases %standard-phases
         (add-after 'patch-generated-file-shebangs 'set-sdl-paths
           (lambda* (#:key inputs #:allow-other-keys)
             (setenv "KIVY_SDL2_PATH"
                     (string-append (assoc-ref inputs "sdl-union")
                                    "/include/SDL2"))
             #t)))))
    (native-inputs
     `(("git" ,git)
       ("pkg-config" ,pkg-config)
       ("python-cython" ,python-cython)))
    (inputs
     `(("gstreamer" ,gstreamer)
       ("mesa" ,mesa)
       ("sdl-union"
        ,(sdl-union (list sdl2 sdl2-image sdl2-mixer sdl2-ttf)))))
    (home-page "http://kivy.org")
    (synopsis
     "Multitouch application framework")
    (description
     "A software library for rapid development of
hardware-accelerated multitouch applications.")
    (license license:expat)))

(define-public python2-kivy
  (package-with-python2 python-kivy))

(define-public python-kivy-next
  (deprecated-package "python-kivy-next" python-kivy))

(define-public python2-kivy-next
  (deprecated-package "python2-kivy-next" python2-kivy))

(define-public python-binaryornot
  (package
    (name "python-binaryornot")
    (version "0.4.4")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "binaryornot" version))
              (sha256
               (base32
                "0qc006986rb6bcbmiymwgcl1mns2jphr1j7sr7nk41nlr7gh359m"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-chardet" ,python-chardet)
       ("python-hypothesis" ,python-hypothesis)))
    (home-page "https://github.com/audreyr/binaryornot")
    (synopsis "Package to check if a file is binary or text")
    (description "Ultra-lightweight pure Python package to check if a file is
binary or text.")
    (license license:bsd-3)
    (properties `((python2-variant . ,(delay python2-binaryornot))))))

(define-public python2-binaryornot
  (let ((base (package-with-python2 (strip-python2-variant python-binaryornot))))
    (package (inherit base)
      (propagated-inputs
       `(("python2-enum34" ,python2-enum34)
         ,@(package-propagated-inputs base))))))

(define-public python-nltk
  (package
    (name "python-nltk")
    (version "3.2.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "nltk" version))
              (sha256
               (base32
                "0skxbhnymwlspjkzga0f7x1hg3y50fwpfghs8g8k7fh6f4nknlym"))))
    (build-system python-build-system)
    (arguments
     '(;; The tests require some extra resources to be downloaded.
       ;; TODO Try packaging these resources.
       #:tests? #f))
    (home-page "http://nltk.org/")
    (synopsis "Natural Language Toolkit")
    (description "It provides interfaces to over 50 corpora and lexical
resources such as WordNet, along with a suite of text processing libraries
for classification, tokenization, stemming, tagging, parsing, and semantic
reasoning, wrappers for natural language processing libraries.")
    (license license:asl2.0)))

(define-public python2-nltk
  (package-with-python2 python-nltk))

(define-public python-pymongo
  (package
    (name "python-pymongo")
    (version "3.7.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pymongo" version))
              (sha256
               (base32
                "0zis4707r9hdg5qgkhp3wss9camr9h56ixyfc8n9dxwlnnly4x4c"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-certifi" ,python-certifi)))
    (home-page "https://github.com/mongodb/mongo-python-driver")
    (synopsis "Python driver for MongoDB")
    (description "Python driver for MongoDB.")
    (license license:asl2.0)))

(define-public python2-pymongo
  (package-with-python2 python-pymongo))

(define-public python-consul
  (package
    (name "python-consul")
    (version "0.6.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "python-consul" version))
        (sha256
         (base32
          "0rfyxcy4cr3x848vhx876ifalxd5ghq6l5x813m49h4vq2d4jiq8"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; The tests are not distributed
    (propagated-inputs
     `(("python-requests" ,python-requests)
       ("python-six" ,python-six)))
    (home-page "https://github.com/cablehead/python-consul")
    (synopsis "Python client for Consul")
    (description
     "Python client for @url{http://www.consul.io/,Consul}, a tool for service
discovery, monitoring and configuration.")
    (license license:expat)))

(define-public python2-consul
  (package-with-python2 python-consul))

(define-public python-schematics
  (package
    (name "python-schematics")
    (version "1.1.1")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/schematics/schematics.git")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32 "0xdqskycznqc7mfp60bhw1zq8wx7yx1dvmbq3brnm1dx3xnqa0zd"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)))
    (arguments
     ;; The tests require a bunch of not very nice packages with fixed
     ;; version requirements (e.g. python-coveralls).
     `(#:tests? #f))
    (home-page "https://github.com/schematics/schematics")
    (synopsis "Python Data Structures for Humans")
    (description "Python Data Structures for Humans.")
    (license license:bsd-3)))

(define-public python2-schematics
  (package-with-python2 python-schematics))

(define-public python-odfpy
  (package
    (name "python-odfpy")
    (version "1.3.3")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "odfpy" version))
              (sha256
               (base32
                "1a6ms0w9zfhhkqhvrnynwwbxrivw6hgjc0s5k7j06npc7rq0blxw"))))
    (arguments
     `(#:modules ((srfi srfi-1)
                  (guix build python-build-system)
                  (guix build utils))
       #:phases
       (modify-phases %standard-phases
         (replace 'check
           ;; The test runner invokes python2 and python3 for test*.py.
           ;; To avoid having both in inputs, we replicate it here.
           (lambda _
             (for-each (lambda (test-file) (invoke "python" test-file))
                       (find-files "tests" "^test.*\\.py$"))
             #t)))))
    (build-system python-build-system)
    (home-page "https://github.com/eea/odfpy")
    (synopsis "Python API and tools to manipulate OpenDocument files")
    (description "Collection of libraries and utility programs written in
Python to manipulate OpenDocument 1.2 files.")
    (license
     ;; The software is mainly dual GPL2+ and ASL2.0, but includes a
     ;; number of files with other licenses.
     (list license:gpl2+ license:asl2.0 license:lgpl2.1+ license:cc-by-sa3.0))))

(define-public python2-odfpy
  (package-with-python2 python-odfpy))

(define-public python-natsort
  (package
    (name "python-natsort")
    (version "5.4.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "natsort" version))
              (sha256
               (base32
                "0i732amg6yzkx4g4c9j09jmqq39q377x9cl2nbkm5hax2c2v0wxf"))))
    (build-system python-build-system)
    (arguments
     `(#:modules ((guix build utils)
                  (guix build python-build-system)
                  (srfi srfi-1)
                  (srfi srfi-26)
                  (ice-9 ftw))
       #:phases
       (modify-phases %standard-phases
         (add-before 'check 'set-cachedir
           ;; Tests require write access to $HOME by default
           (lambda _ (setenv "PYTHON_EGG_CACHE" "/tmp") #t))
         (replace 'check
           (lambda _
             (let ((cwd (getcwd)))
               (setenv "PYTHONPATH"
                       (string-append
                        cwd "/build/"
                        (find (cut string-prefix? "lib" <>)
                              (scandir (string-append cwd "/build")))
                        ":"
                        (getenv "PYTHONPATH")))
               (invoke "pytest" "-v")))))))
    (native-inputs
     `(("python-hypothesis" ,python-hypothesis)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-pytest-mock" ,python-pytest-mock)
       ("python-pytest" ,python-pytest)))
    (propagated-inputs ; TODO: Add python-fastnumbers.
     `(("python-pyicu" ,python-pyicu)))
    (home-page "https://github.com/SethMMorton/natsort")
    (synopsis "Natural sorting for python and shell")
    (description
     "Natsort lets you apply natural sorting on lists instead of
lexicographical.  If you use the built-in @code{sorted} method in python
on a list such as @code{[@code{a20}, @code{a9}, @code{a1}, @code{a4},
@code{a10}]}, it would be returned as @code{[@code{a1}, @code{a10}, @code{a20},
@code{a4}, @code{a9}]}.  Natsort provides a function @code{natsorted} that
identifies numbers and sorts them separately from strings.  It can also sort
version numbers, real numbers, mixed types and more, and comes with a shell
command @command{natsort} that exposes this functionality in the command line.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-natsort))))))

(define-public python2-natsort
  (let ((base (package-with-python2 (strip-python2-variant python-natsort))))
    (package (inherit base)
             (native-inputs
              `(("python2-pathlib" ,python2-pathlib)
                ,@(package-native-inputs base))))))

(define-public python-glances
  (package
  (name "python-glances")
  (version "3.1.1")
  (source
    (origin
      (method url-fetch)
      (uri (pypi-uri "Glances" version))
      (sha256
        (base32
          "07j1ggzsqiskyz1i4mrnyr9i95v0dqi0i0hibnv1l188km8shmi8"))
      (modules '((guix build utils)))
      (snippet
       '(begin
          ;; Glances phones PyPI for weekly update checks by default.
          ;; Disable these.  The user can re-enable them if desired.
          (substitute* "glances/outdated.py"
            (("^(.*)self\\.load_config\\(config\\)\n" line indentation)
             (string-append indentation
                            "self.args.disable_check_update = True\n"
                            line)))
          #t))))
  (build-system python-build-system)
  (propagated-inputs
   `(("python-future" ,python-future)
     ("python-psutil" ,python-psutil)))
  (home-page
    "https://github.com/nicolargo/glances")
  (synopsis "Cross-platform curses-based monitoring tool")
  (description
    "Glances is a curses-based monitoring tool for a wide variety of platforms.
Glances uses the PsUtil library to get information from your system.  It
monitors CPU, load, memory, network bandwidth, disk I/O, disk use, and more.")
  (license license:lgpl3+)))

(define-public python2-glances
  (package-with-python2 python-glances))

(define-public python-graphql-core
  (package
    (name "python-graphql-core")
    (version "0.5.3")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "graphql-core" version))
        (sha256
         (base32
          "0rsaarx2sj4xnw9966rhh4haiqaapm4lm2mfqm48ywd51j5vh1a0"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f ; Tests require the unpackaged pytest-benchmark.
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-hardcoded-version
           (lambda _ (substitute*
                       "setup.py"
                       (("'gevent==1.1rc1'") "'gevent'"))
             #t)))))
    (native-inputs
     `(("python-gevent" ,python-gevent)
       ("python-mock" ,python-mock)
       ("python-pytest-mock" ,python-pytest-mock)))
    (propagated-inputs
     `(("python-promise" ,python-promise)
       ("python-six" ,python-six)))
    (home-page "https://github.com/graphql-python/graphql-core")
    (synopsis "GraphQL implementation for Python")
    (description
     "GraphQL implementation for Python.  GraphQL is a data query language and
runtime designed and used to request and deliver data to mobile and web apps.
This library is a port of @url{https://github.com/graphql/graphql-js,graphql-js}
to Python.")
    (license license:expat)))

(define-public python2-graphql-core
  (package-with-python2 python-graphql-core))

(define-public python-graphql-relay
  (package
    (name "python-graphql-relay")
    (version "0.4.5")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "graphql-relay" version))
        (sha256
         (base32
          "1nv5dxcj59zv31qvl8bd142njmxcmymny2dz3br1l2cpbljbf5i7"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; The tests are not distributed
    (propagated-inputs
     `(("python-graphql-core" ,python-graphql-core)
       ("python-promise" ,python-promise)
       ("python-six" ,python-six)))
    (home-page "https://github.com/graphql-python/graphql-relay-py")
    (synopsis "Relay implementation for Python")
    (description
     "This is a library to allow the easy creation of Relay-compliant servers
using the GraphQL Python reference implementation of a GraphQL server.  It
should be noted that the code is a exact port of the original
@url{https://github.com/graphql/graphql-relay-js,graphql-relay js implementation}
from Facebook.")
    (license license:expat)))

(define-public python2-graphql-relay
  (package-with-python2 python-graphql-relay))

(define-public python-graphene
  (package
    (name "python-graphene")
    (version "0.10.2")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "graphene" version))
        (sha256
         (base32
          "09zhac7igh9ixdz0ay6csy35b40l1jwbf2wrbxmgxwfhy51iy06q"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-graphql-core" ,python-graphql-core)
       ("python-graphql-relay" ,python-graphql-relay)
       ("python-iso8601" ,python-iso8601)
       ("python-promise" ,python-promise)
       ("python-six" ,python-six)))
    (arguments
     `(#:tests? #f))                    ; no tests/ in the PyPI tarball
    (home-page "http://graphene-python.org/")
    (synopsis "GraphQL Framework for Python")
    (description
     "Graphene is a Python library for building GraphQL schemas/types.
A GraphQL schema describes your data model, and provides a GraphQL server
with an associated set of resolve methods that know how to fetch data.")
    (properties `((python2-variant . ,(delay python2-graphene))))
    (license license:expat)))

(define-public python2-graphene
  (let ((base (package-with-python2
                (strip-python2-variant python-graphene))))
    (package (inherit base)
      (native-inputs
       `(("python2-sqlalchemy" ,python2-sqlalchemy)
         ,@(package-native-inputs base))))))

(define-public python-nautilus
  (package
    (name "python-nautilus")
    (version "0.4.9")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "nautilus" version))
        (sha256
         (base32
          "01hwzjc1zshk4vvxrcghm398fpy4jls66dyz06g07mrwqif8878p"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f)) ; fails to import test modules
    (propagated-inputs
     `(("python-bcrypt" ,python-bcrypt)
       ("python-click" ,python-click)
       ("python-consul" ,python-consul)
       ("python-graphene" ,python-graphene)
       ("python-jinja2" ,python-jinja2)
       ("python-peewee" ,python-peewee)
       ("python-pika" ,python-pika)
       ("python-tornado" ,python-tornado)
       ("python-wtforms" ,python-wtforms)))
    (native-inputs
     `(("python-nose2" ,python-nose2)))
    (home-page "https://github.com/AlecAivazis/nautilus")
    (synopsis "Library for creating microservice applications")
    (description
     "Nautilus is a framework for flux based microservices that looks to
provide extendible implementations of common aspects of a cloud so that you can
focus on building massively scalable web applications.")
    (license license:expat)))

(define-public python-snowballstemmer
  (package
    (name "python-snowballstemmer")
    (version "1.2.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "snowballstemmer" version))
              (sha256
               (base32
                "0a0idq4y5frv7qsg2x62jd7rd272749xk4x99misf5rcifk2d7wi"))))
    (build-system python-build-system)
    (arguments
     `(;; No tests exist
       #:tests? #f))
    (home-page "https://github.com/shibukawa/snowball_py")
    (synopsis "Snowball stemming library collection for Python")
    (description "This package provides 16 word stemmer algorithms generated
from Snowball algorithms.  It includes the 15 original ones plus the Poerter
English stemmer.")
    (license license:bsd-3)))

(define-public python2-snowballstemmer
  (package-with-python2 python-snowballstemmer))

(define-public python-setproctitle
(package
  (name "python-setproctitle")
  (version "1.1.10")
  (source
    (origin
      (method url-fetch)
      (uri (pypi-uri "setproctitle" version))
      (sha256
        (base32
          "163kplw9dcrw0lffq1bvli5yws3rngpnvrxrzdw89pbphjjvg0v2"))))
  (build-system python-build-system)
  (arguments
   '(#:phases
     (modify-phases %standard-phases
        (add-before 'check 'patch-Makefile
           ;; Stricly this is only required for the python2 variant.
           ;; But adding a phase in an inherited package seems to be
           ;; cumbersum. So we patch even for python3.
           (lambda _
             (let ((nose (assoc-ref %build-inputs "python2-nose")))
               (when nose
                 (substitute* "Makefile"
                   (("\\$\\(PYTHON\\) [^ ]which nosetests[^ ] ")
                    (string-append nose "/bin/nosetests "))))
               #t)))
        (replace 'check
           (lambda _
             (setenv "PYTHON" (or (which "python3") (which "python")))
             (setenv "PYCONFIG" (or (which "python3-config")
                                    (which "python-config")))
             (setenv "CC" "gcc")
             ;; No need to extend PYTHONPATH to find the built package, since
             ;; the Makefile will build anyway
             (invoke "make" "check"))))))
  (native-inputs
   `(("procps" ,procps))) ; required for tests
  (home-page
    "https://github.com/dvarrazzo/py-setproctitle")
  (synopsis
   "Setproctitle implementation for Python to customize the process title")
  (description "The library allows a process to change its title (as displayed
by system tools such as ps and top).

Changing the title is mostly useful in multi-process systems, for
example when a master process is forked: changing the children's title
allows to identify the task each process is busy with.  The technique
is used by PostgreSQL and the OpenSSH Server for example.")
  (license license:bsd-3)
  (properties `((python2-variant . ,(delay python2-setproctitle))))))

(define-public python2-setproctitle
  (let ((base (package-with-python2
               (strip-python2-variant python-setproctitle))))
    (package
      (inherit base)
      (native-inputs `(("python2-nose" ,python2-nose)
                       ,@(package-native-inputs base))))))

(define-public python-validictory
  (package
    (name "python-validictory")
    (version "1.0.1")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "validictory" version))
      (sha256
       (base32
        "1zf1g9sw47xzp5f80bd94pb42j9yqv82lcrgcvdwr6nkaphfi37q"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'bootstrap
           ;; Move the tests out of the package directory to avoid
           ;; packaging them.
           (lambda* _
             (rename-file "validictory/tests" "tests")
             (delete-file "tests/__init__.py")))
         (replace 'check
           (lambda _
             ;; Extend PYTHONPATH so the built package will be found.
             (setenv "PYTHONPATH"
                     (string-append (getcwd) "/build/lib:"
                                    (getenv "PYTHONPATH")))
             (invoke "py.test" "-vv" ))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page
     "https://github.com/jamesturk/validictory")
    (synopsis "General purpose Python data validator")
    (description "It allows validation of arbitrary Python data structures.

The schema format is based on the JSON Schema
proposal (http://json-schema.org), so combined with json the library is also
useful as a validator for JSON data.")
  (license license:expat)))

(define-public python2-validictory
  (package-with-python2 python-validictory))

(define-public python-pyelftools
  (package
    (name "python-pyelftools")
    (version "0.25")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyelftools" version))
       (sha256
        (base32
         "090vdksbz341f7ljvr0zswblw4lspa8qaiikzyjkf318arpxmil9"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'set-pythonpath
           (lambda _
             (setenv "PYTHONPATH"
                     (string-append
                      (getcwd) "/test/"
                      ":" (getenv "PYTHONPATH")))
             #t)))))
    (home-page
     "https://github.com/eliben/pyelftools")
    (synopsis
     "Analyze binary and library file information")
    (description "This Python library provides interfaces for parsing and
analyzing two binary and library file formats; the Executable and Linking
Format (ELF), and debugging information in the Debugging With Attributed
Record Format (DWARF).")
    (license license:public-domain)))

(define-public python-pyev
  (package
    (name "python-pyev")
    (version "0.9.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pyev" version))
        (sha256
         (base32
          "0rf603lc0s6zpa1nb25vhd8g4y337wg2wyz56i0agsdh7jchl0sx"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f ; no test suite
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((libev (string-append (assoc-ref inputs "libev")
                                         "/lib/libev.so.4")))
               (substitute* "setup.py"
                 (("libev_dll_name = find_library\\(\\\"ev\\\"\\)")
                  (string-append "libev_dll_name = \"" libev "\"")))))))))
    (inputs
     `(("libev" ,libev)))
    (home-page "http://pythonhosted.org/pyev/")
    (synopsis "Python libev interface")
    (description "Pyev provides a Python interface to libev.")
    (license license:gpl3)))

(define-public python2-pyev
  (package-with-python2 python-pyev))

(define-public python-imagesize
  (package
    (name "python-imagesize")
    (version "1.1.0")
    (source
      (origin
      (method url-fetch)
      (uri (pypi-uri "imagesize" version))
      (sha256
       (base32
        "1dg3wn7qpwmhgqc0r9na2ding1wif9q5spz3j9zn2riwphc2k0zk"))))
    (build-system python-build-system)
    (home-page "https://github.com/shibukawa/imagesize_py")
    (synopsis "Gets image size of files in various formats in Python")
    (description
      "This package allows determination of image size from
PNG, JPEG, JPEG2000 and GIF files in pure Python.")
    (license license:expat)))

(define-public python2-imagesize
 (package-with-python2 python-imagesize))

(define-public python-termstyle
  (package
    (name "python-termstyle")
    (version "0.1.11")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "termstyle" version))
        (sha256
          (base32
            "17wzkkcqy5zc0g68xlad3kcv66iw14d2pwqc0h9420gak0vbhx7g"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (invoke "python" "test3.py"))))))
    (home-page "https://github.com/gfxmonk/termstyle")
    (synopsis "Console text coloring for Python")
    (description "This package provides console text coloring for Python.")
    (license license:bsd-3)))

(define-public python-argcomplete
  (package
    (name "python-argcomplete")
    (version "1.7.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "argcomplete" version))
        (sha256
          (base32
            "11bwiw6j0nilgz81xnw6f1npyga3prp8asjqrm87cdr3ria5l03x"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pexpect" ,python-pexpect)
       ("tcsh" ,tcsh)
       ("bash-full" ,bash)))             ;full Bash for 'test_file_completion'
    (home-page "https://github.com/kislyuk/argcomplete")
    (synopsis "Shell tab completion for Python argparse")
    (description "argcomplete provides extensible command line tab completion
of arguments and options for Python scripts using @code{argparse}.  It's
particularly useful for programs with many options or sub-parsers that can
dynamically suggest completions; for example, when browsing resources over the
network.")
    (license license:asl2.0)))

(define-public python2-argcomplete
  (package-with-python2 python-argcomplete))

(define-public python-xopen
  (package
    (name "python-xopen")
    (version "0.5.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "xopen" version))
        (sha256
          (base32
           "17xbrgi23l87yg6h0qcknssp2q812miiy33qw6v45v5gx0jwv5xh"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-setuptools-scm" ,python-setuptools-scm)))
    (home-page "https://github.com/marcelm/xopen/")
    (synopsis "Open compressed files transparently")
    (description "This module provides an @code{xopen} function that works like
Python's built-in @code{open} function, but can also deal with compressed files.
Supported compression formats are gzip, bzip2 and, xz, and are automatically
recognized by their file extensions.  The focus is on being as efficient as
possible on all supported Python versions.")
    (license license:expat)))

(define-public python2-xopen
  (let ((base (package-with-python2
               (strip-python2-variant python-xopen))))
    (package
      (inherit base)
      (propagated-inputs `(("python2-bz2file" ,python2-bz2file)
                           ,@(package-propagated-inputs base))))))

(define-public python-cheetah
  (package
    (name "python-cheetah")
    (version "3.1.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "Cheetah3" version))
        (sha256
          (base32
           "1ihag9cxll6b86fc8v5lkhmr3brdbi4yiz16zpgw79yylmv8fgr9"))))
    (build-system python-build-system)
    (arguments
     `(#:modules ((guix build utils)
                  (guix build python-build-system)
                  (ice-9 ftw)
                  (srfi srfi-1)
                  (srfi srfi-26))
       #:phases (modify-phases %standard-phases
                  (add-after 'unpack 'use-absolute-python
                    (lambda _
                      (substitute* "Cheetah/CheetahWrapper.py"
                        (("#!/usr/bin/env python")
                         (string-append "#!" (which "python"))))
                      #t))
                  (replace 'check
                    (lambda _
                      (let ((cwd (getcwd)))
                        (setenv "PYTHONPATH"
                                (string-append
                                 cwd "/build/"
                                 (find (cut string-prefix? "lib" <>)
                                       (scandir (string-append cwd "/build")))
                                 ":" (getenv "PYTHONPATH")))
                        (setenv "PATH"
                                (string-append (getenv "PATH")
                                               ":" cwd "/bin"))
                        (setenv "TMPDIR" "/tmp")

                        (substitute* "Cheetah/Tests/Test.py"
                          (("unittest.TextTestRunner\\(\\)")
                           "unittest.TextTestRunner(verbosity=2)"))

                        (invoke "python" "Cheetah/Tests/Test.py")))))))
    (propagated-inputs
     `(("python-markdown" ,python-markdown)))    ;optional
    (home-page "http://cheetahtemplate.org/")
    (synopsis "Template engine")
    (description "Cheetah is a text-based template engine and Python code
generator.

Cheetah can be used as a standalone templating utility or referenced as
a library from other Python applications.  It has many potential uses,
but web developers looking for a viable alternative to ASP, JSP, PHP and
PSP are expected to be its principle user group.

Features:
@enumerate
@item Generates HTML, SGML, XML, SQL, Postscript, form email, LaTeX, or any other
   text-based format.
@item Cleanly separates content, graphic design, and program code.
@item Blends the power and flexibility of Python with a simple template language
   that non-programmers can understand.
@item Gives template writers full access to any Python data structure, module,
   function, object, or method in their templates.
@item Makes code reuse easy by providing an object-orientated interface to
   templates that is accessible from Python code or other Cheetah templates.
   One template can subclass another and selectively reimplement sections of it.
@item Provides a simple, yet powerful, caching mechanism that can dramatically
   improve the performance of a dynamic website.
@item Compiles templates into optimized, yet readable, Python code.
@end enumerate")
    (license (license:x11-style "file://LICENSE"))))

(define-public python2-cheetah
  (package-with-python2 python-cheetah))

(define-public python-dulwich
  (package
    (name "python-dulwich")
    (version "0.18.6")
    (source
      (origin
        (method url-fetch)
        (uri (list (string-append "https://www.dulwich.io/releases/"
                            "dulwich-" version ".tar.gz")
                   (pypi-uri "dulwich" version)))
        (sha256
          (base32
           "1aa1xfrxkc3j9s4xi0llhf5gndyi9ryprcxsqfa5fcb8ph34981q"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'fix-tests
           (lambda* (#:key inputs #:allow-other-keys)
             ;; The tests use Popen with a custom environment which doesn't
             ;; include PATH.
             (substitute* "dulwich/tests/compat/utils.py"
               (("'git'") (string-append "'"
                                         (which "git")
                                         "'")))
             (substitute* '("dulwich/tests/test_repository.py"
                            "dulwich/tests/test_hooks.py")
               (("#!/bin/sh") (string-append "#!" (which "sh"))))
             (setenv "TEST_RUNNER" "unittest")
             (setenv "PYTHONHASHSEED" "random")
             #t)))))
    (propagated-inputs
     `(("python-fastimport" ,python-fastimport)))
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-geventhttpclient" ,python-geventhttpclient)
       ("git" ,git)))
    (home-page "https://www.dulwich.io/")
    (synopsis "Git implementation in Python")
    (description "Dulwich is an implementation of the Git file formats and
protocols written in pure Python.")
    ;; Can be used with either license.
    (license (list license:asl2.0 license:gpl2+))))

(define-public python2-dulwich
  (package-with-python2 python-dulwich))

(define-public python-pbkdf2
  (package
    (name "python-pbkdf2")
    (version "1.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pbkdf2" version))
       (sha256
        (base32
         "0yb99rl2mbsaamj571s1mf6vgniqh23v98k4632150hjkwv9fqxc"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (setenv "PYTHONPATH"
                     (string-append (getcwd) "/build/lib:"
                                    (getenv "PYTHONPATH")))
             (invoke "python" "test/test_pbkdf2.py"))))))
    (propagated-inputs
     `(("python-pycrypto" ,python-pycrypto)))  ; optional
    (home-page "https://www.dlitz.net/software/python-pbkdf2/")
    (synopsis "Password-based key derivation")
    (description "This module implements the password-based key derivation
function, PBKDF2, specified in RSA PKCS#5 v2.0.

PKCS#5 v2.0 Password-Based Key Derivation is a key derivation function which
is part of the RSA Public Key Cryptography Standards series.  The provided
implementation takes a password or a passphrase and a salt value (and
optionally a iteration count, a digest module, and a MAC module) and provides
a file-like object from which an arbitrarly-sized key can be read.")
    (license license:expat)))

(define-public python2-pbkdf2
  (package-with-python2 python-pbkdf2))

(define-public python-qrcode
  (package
    (name "python-qrcode")
    (version "6.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "qrcode" version))
       (sha256
        (base32 "0sa3n298b9jpz6zn0birnjii3mg9sihjq28n9nzjlzv09y2m6ljh"))))
    (build-system python-build-system)
    (arguments
     ;; FIXME: Tests require packaging 'pymaging'.
     '(#:tests? #f))
    (propagated-inputs
     `(("python-lxml" ,python-lxml)     ; for SVG output
       ("python-pillow" ,python-pillow) ; for PNG output
       ("python-six" ,python-six)))
    (home-page "https://github.com/lincolnloop/python-qrcode")
    (synopsis "QR Code image generator")
    (description "This package provides a pure Python QR Code generator
module.  It uses the Python Imaging Library (PIL) to allow for the generation
of QR Codes.

In addition this package provides a command line tool to generate QR codes and
either write these QR codes to a file or do the output as ascii art at the
console.")
    (license license:bsd-3)))

(define-public python2-qrcode
  (package-with-python2 python-qrcode))

(define-public python-rst2ansi
  (package
    (name "python-rst2ansi")
    (version "0.1.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "rst2ansi" version))
       (sha256
        (base32
         "0vzy6gd60l79ff750scl0sz48r1laalkl6md6dwzah4dcadgn5qv"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-docutils" ,python-docutils)))
    (home-page "https://github.com/Snaipe/python-rst-to-ansi")
    (synopsis "Convert RST to ANSI-decorated console output")
    (description
     "Python module dedicated to rendering RST (reStructuredText) documents
to ansi-escaped strings suitable for display in a terminal.")
    (license license:expat)))

(define-public python-ansi2html
  (package
    (name "python-ansi2html")
    (version "1.2.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ansi2html" version))
       (sha256
        (base32
         "1wa00zffprb78w1mqq90dk47czz1knanys2a40zbw2vyapd5lp9y"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-nose" ,python-nose)))
    (propagated-inputs
     `(("python-six" ,python-six)))
    (home-page "https://github.com/ralphbean/ansi2html")
    (synopsis "Convert ANSI-decorated console output to HTML")
    (description
     "@command{ansi2html} is a Python library and command line utility for
convering text with ANSI color codes to HTML or LaTeX.")
    (license license:gpl3+)))

(define-public python2-ansi2html
  (package-with-python2 python-ansi2html))

(define-public python-ddt
  (package
    (name "python-ddt")
    (version "1.1.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ddt" version))
       (sha256
        (base32
         "1lw17420iimhghkgzgax85nn8d1an2d6k2cfvb7j5kwn2dqlr1vk"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-nose" ,python-nose)))
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-pyyaml" ,python-pyyaml)))
    (home-page "https://github.com/txels/ddt")
    (synopsis "Data-Driven Tests")
    (description
     "Data-Driven Tests (@dfn{DDT}) allow you to multiply one test case by
running it with different test data, and make it appear as multiple test
cases.")
    (license license:expat)))

(define-public python2-ddt
  (package-with-python2 python-ddt))

(define-public python-pycountry
  (package
    (name "python-pycountry")
    (version "18.5.26")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pycountry" version))
       (sha256
        (base32
         "15q9j047s3yc9cfcxq1ch8b71f81na44cr6dydd5gxk0ki9a4akz"))))
    (build-system python-build-system)
    (home-page "https://bitbucket.org/flyingcircus/pycountry")
    (synopsis "ISO databases for languages, countries, currencies, etc.")
    (description
     "@code{pycountry} provides the ISO databases for the standards:
@enumerate
@item 639-3 (Languages)
@item 3166 (Countries)
@item 3166-3 (Deleted Countries)
@item 3166-2 (Subdivisions of countries)
@item 4217 (Currencies)
@item 15924 (Scripts)
@end enumerate
It includes a copy from Debian’s pkg-isocodes and makes the data accessible
through a Python API.")
    (license license:lgpl2.1+)))

(define-public python2-pycountry
  (package-with-python2 python-pycountry))

(define-public python-pycosat
  (package
    (name "python-pycosat")
    (version "0.6.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pycosat" version))
       (sha256
        (base32
         "1kl3wh1f47rc712n4bmwplbx3fqz3x9i1b587jrbpmvdva4c8f6l"))))
    ;; TODO: Unundle picosat. http://fmv.jku.at/picosat/
    (build-system python-build-system)
    (home-page "https://github.com/ContinuumIO/pycosat")
    (synopsis "Bindings to picosat (a SAT solver)")
    (description
     "This package provides efficient Python bindings to @code{picosat} on
the C level.  When importing pycosat, the @code{picosat} solver becomes part
of the Python process itself.  @code{picosat} is a @dfn{Boolean Satisfiability
Problem} (SAT) solver.")
    (license license:expat)))

(define-public python2-pycosat
  (package-with-python2 python-pycosat))

(define-public python2-ruamel.ordereddict
  (package
    (name "python2-ruamel.ordereddict")
    (version "0.4.9")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ruamel.ordereddict" version))
       (sha256
        (base32
         "1xmkl8v9l9inm2pyxgc1fm5005yxm7fkd5gv74q7lj1iy5qc8n3h"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         (delete 'check)
         (add-after 'install 'check
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (add-installed-pythonpath inputs outputs)
             (invoke "python" "test/testordereddict.py"))))))
    (home-page "https://bitbucket.org/ruamel/ordereddict")
    (synopsis "Version of dict that keeps keys in insertion order")
    (description
     "This is an implementation of an ordered dictionary with @dfn{Key
Insertion Order} (KIO: updates of values do not affect the position of the
key), @dfn{Key Value Insertion Order} (KVIO, an existing key's position is
removed and put at the back).  The standard library module @code{OrderedDict},
implemented later, implements a subset of @code{ordereddict} functionality.
Sorted dictionaries are also provided.  Currently only with @dfn{Key Sorted
Order} (KSO, no sorting function can be specified, but a transform can be
specified to apply on the key before comparison (e.g. @code{string.lower})).")
    (license license:expat)))

(define-public python-pypeg2
  (package
    (name "python-pypeg2")
    (version "2.15.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyPEG2" version))
       (sha256
        (base32
         "0v8ziaam2r637v94ra4dbjw6jzxz99gs5x4i585kgag1v204yb9b"))))
    (build-system python-build-system)
    (propagated-inputs `(("python-lxml" ,python-lxml)))
    (arguments
     ;;https://bitbucket.org/fdik/pypeg/issues/36/test-failures-on-py35
     '(#:tests? #f))
    (home-page "https://fdik.org/pyPEG/")
    (synopsis "Parsering Expression Grammars in Python")
    (description "PyPEG is an intrinsic parser interpreter framework for
Python.  It is based on Parsing Expression Grammars, PEG.  With pyPEG you can
parse many formal languages.")
    (license license:gpl2)))

(define-public python-incremental
  (package
    (name "python-incremental")
    (version "17.5.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "incremental" version))
       (sha256
        (base32
         "1cylxdz1cnkm5g3pklna3h2n0i0rks95ir1pnpxfnvpkmab1cxbv"))))
    (build-system python-build-system)
    (home-page "https://github.com/hawkowl/incremental")
    (synopsis "Library for versioning Python projects")
    (description "Incremental is a small library that versions your Python
projects.")
    (license license:expat)))

(define-public python2-incremental
  (package-with-python2 python-incremental))

(define-public python-invoke
  (package
    (name "python-invoke")
    (home-page "http://www.pyinvoke.org/")
    (version "1.1.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "invoke" version))
              (sha256
               (base32
                "0aiy1xvk1f91246zxd1zqrm679vdvd10h843a2na41cqr3cflpi6"))))
    (build-system python-build-system)
    (arguments
     ;; XXX: Requires many dependencies that are not yet in Guix.
     `(#:tests? #f))
    (synopsis "Pythonic task execution")
    (description
     "Invoke is a Python task execution tool and library, drawing inspiration
from various sources to arrive at a powerful and clean feature set.  It is
evolved from the Fabric project, but focuses on local and abstract concerns
instead of servers and network commands.")
    (license license:bsd-3)))

(define-public python2-invoke
  (package-with-python2 python-invoke))

(define-public python-automat
  (package
    (name "python-automat")
    (version "0.7.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "Automat" version))
              (sha256
               (base32
                "03ivg70n3b1cbcd2zvjhk8y4kmqxcvhmili39lmgx09dza1qpmyb"))))
    (build-system python-build-system)
    ;; We disable the tests because they require python-twisted, while
    ;; python-twisted depends on python-automat.  Twisted is optional, but the
    ;; tests fail if it is not available.  Also see
    ;; <https://github.com/glyph/automat/issues/71>.
    (arguments '(#:tests? #f))
    (native-inputs
     `(("python-m2r" ,python-m2r)
       ("python-setuptools-scm" ,python-setuptools-scm)
       ("python-graphviz" ,python-graphviz)))
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-attrs" ,python-attrs)))
    (home-page "https://github.com/glyph/Automat")
    (synopsis "Self-service finite-state machines")
    (description "Automat is a library for concise, idiomatic Python
expression of finite-state automata (particularly deterministic finite-state
transducers).")
    (license license:expat)))

(define-public python2-automat
  (package-with-python2 python-automat))

(define-public python-m2r
  (package
    (name "python-m2r")
    (version "0.2.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "m2r" version))
              (sha256
               (base32
                "16gdm8i06jjmlpvckpfmlkr4693dh0vs192vgsqn84fsdkbbm45z"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-docutils" ,python-docutils)
       ("python-mistune" ,python-mistune)))
    (native-inputs
     `(("python-pygments" ,python-pygments)
       ("python-mock" ,python-mock)))
    (home-page "https://github.com/miyakogi/m2r")
    (synopsis "Markdown to reStructuredText converter")
    (description "M2R converts a markdown file including reST markups to valid
reST format.")
    (license license:expat)))

(define-public python2-m2r
  (package-with-python2 python-m2r))

(define-public python-constantly
  (package
    (name "python-constantly")
    (version "15.1.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "constantly" version))
              (sha256
               (base32
                "0dgwdla5kfpqz83hfril716inm41hgn9skxskvi77605jbmp4qsq"))))
    (build-system python-build-system)
    (home-page "https://github.com/twisted/constantly")
    (synopsis "Symbolic constants in Python")
    (description "Constantly is a Python library that provides symbolic
constant support.  It includes collections and constants with text, numeric,
and bit flag values.")
    (license license:expat)))

(define-public python2-constantly
  (package-with-python2 python-constantly))

(define-public python-attrs
  (package
    (name "python-attrs")
    (version "19.1.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "attrs" version))
              (sha256
               (base32
                "16g33zr5f449lqc5wgvzpknxryfzrfsxcr6kpgxwn7l5fkv71f7h"))))
    (build-system python-build-system)
    (arguments
     `(#:modules ((guix build utils)
                  (guix build python-build-system)
                  (ice-9 ftw)
                  (srfi srfi-1)
                  (srfi srfi-26))
       #:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      (let ((cwd (getcwd)))
                        (setenv "PYTHONPATH"
                                (string-append
                                 cwd "/build/"
                                 (find (cut string-prefix? "lib" <>)
                                       (scandir (string-append cwd "/build")))
                                 ":"
                                 (getenv "PYTHONPATH")))
                        (invoke "python" "-m" "pytest")))))))
    (native-inputs
     `(("python-coverage" ,python-coverage)
       ("python-hypothesis" ,python-hypothesis)
       ("python-pympler" ,python-pympler)
       ("python-pytest" ,python-pytest)
       ("python-six" ,python-six)
       ("python-sphinx" ,python-sphinx)
       ("python-zope-interface" ,python-zope-interface)))
    (home-page "https://github.com/python-attrs/attrs/")
    (synopsis "Attributes without boilerplate")
    (description "@code{attrs} is a Python package with class decorators that
ease the chores of implementing the most common attribute-related object
protocols.")
    (license license:expat)))

(define-public python2-attrs
  (package-with-python2 python-attrs))

(define-public python-attrs-bootstrap
  (package
    (inherit python-attrs)
    (name "python-attrs-bootstrap")
    ;; Keep this on a fixed version so python-attrs can be updated without
    ;; triggering a mass-rebuild.  FIXME: Update this in the next rebuild cycle.
    (version "17.4.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "attrs" version))
              (sha256
               (base32
                "1jafnn1kzd6qhxgprhx6y6ik1r5m2rilx25syzcmq03azp660y8w"))))
    (native-inputs `())
    (arguments `(#:tests? #f))))

(define-public python2-attrs-bootstrap
  (package-with-python2 python-attrs-bootstrap))

(define-public python2-cliapp
  (package
    (name "python2-cliapp")
    (version "1.20180812.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "http://git.liw.fi/cgi-bin/cgit/cgit.cgi/cliapp/snapshot/cliapp-"
             version ".tar.gz"))
       (sha256
        (base32
         "1c1jlblbns8qhiaqjpg4xi6lip8xwfc5w643p43rg543havaj45x"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         ;; check phase needs to be run before the build phase. If not,
         ;; coverage-test-runner looks for tests for the built source files,
         ;; and fails.
         (delete 'check)
         (add-before 'build 'check
           (lambda _
             ;; Disable python3 tests
             (substitute* "check"
               (("python3") "# python3"))
             (invoke "./check"))))))
    (native-inputs
     `(("python2-coverage-test-runner" ,python2-coverage-test-runner)
       ("python2-pep8" ,python2-pep8)))
    (propagated-inputs
     `(("python2-pyaml" ,python2-pyaml)))
    (home-page "https://liw.fi/cliapp/")
    (synopsis "Python framework for command line programs")
    (description "@code{python2-cliapp} is a python framework for
command line programs.  It contains the typical stuff such programs
need to do, such as parsing the command line for options, and
iterating over input files.")
    (license license:gpl2+)))

(define-public python2-ttystatus
  (package
    (name "python2-ttystatus")
    (version "0.36")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "http://git.liw.fi/cgi-bin/cgit/cgit.cgi/ttystatus/snapshot/ttystatus-"
             version ".tar.gz"))
       (sha256
        (base32
         "06mdk4d19zw2j3is54gndhzl396g3xc8k52m7i86z69s9hcz71by"))))
    (build-system python-build-system)
    (native-inputs
     `(("python2-coverage-test-runner" ,python2-coverage-test-runner)
       ("python2-pep8" ,python2-pep8)))
    (arguments
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         ;; check phase needs to be run before the build phase. If not,
         ;; coverage-test-runner looks for tests for the built source files,
         ;; and fails.
         (delete 'check)
         (add-before 'build 'check
           (lambda _ (invoke "make" "check"))))))
    (home-page "https://liw.fi/ttystatus/")
    (synopsis "Python library for showing progress reporting and
status updates on terminals")
    (description "@code{python2-ttystatus} is a python library for
showing progress reporting and status updates on terminals, for
command line programs.  Output is automatically adapted to the width
of the terminal: truncated if it does not fit, and resized if the
terminal size changes.")
    (license license:gpl3+)))

(define-public python2-tracing
  (package
    (name "python2-tracing")
    (version "0.10")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "http://git.liw.fi/cgi-bin/cgit/cgit.cgi/python-tracing/snapshot/tracing-"
             version ".tar.gz"))
       (sha256
        (base32
         "06cw4zg42fsvqy372vi2whj26w56vzg5axhzwdjc2bgwf03garbw"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2))
    (home-page "https://liw.fi/tracing/")
    (synopsis "Python debug logging helper")
    (description "@code{python2-tracing} is a python library for
logging debug messages.  It provides a way to turn debugging messages
on and off, based on the filename they occur in.  It is much faster
than using @code{logging.Filter} to accomplish the same thing, which
matters when code is run in production mode.  The actual logging still
happens using the @code{logging} library.")
    (license license:gpl3+)))

(define-public python2-larch
  (package
    (name "python2-larch")
    (version "1.20151025")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "http://git.liw.fi/cgi-bin/cgit/cgit.cgi/larch/snapshot/larch-"
             version ".tar.gz"))
       (patches (search-patches
                 "python2-larch-coverage-4.0a6-compatibility.patch"))
       (sha256
        (base32
         "1p4knkkavlqymgciz2wbcnfrdgdbafhg14maplnk4vbw0q8xs663"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         ;; check phase needs to be run before the build phase. If not,
         ;; coverage-test-runner looks for tests for the built source files,
         ;; and fails.
         (delete 'check)
         (add-before 'build 'check
           (lambda _ (invoke "make" "check"))))))
    (native-inputs
     `(("cmdtest" ,cmdtest)
       ("python2-coverage-test-runner" ,python2-coverage-test-runner)))
    (propagated-inputs
     `(("python2-tracing" ,python2-tracing)))
    (home-page "https://liw.fi/larch/")
    (synopsis "Python copy-on-write B-tree library")
    (description "@code{python2-larch} is an implementation of
particular kind of B-tree, based on research by Ohad Rodeh.  See
@url{http://liw.fi/larch/ohad-btrees-shadowing-clones.pdf} for details
on the data structure.

The distinctive feature of this B-tree is that a node is never
(conceptually) modified.  Instead, all updates are done by
copy-on-write.  This makes it easy to clone a tree, and modify only the
clone, while other processes access the original tree.")
    (license license:gpl3+)))

(define-public python-astroid
  (package
    (name "python-astroid")
    (version "2.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "astroid" version))
       (sha256
        (base32
         "08hz675knh4294bancdapql392fmbjyimhbyrmfkz1ka7l035c1m"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-lazy-object-proxy" ,python-lazy-object-proxy)
       ("python-six" ,python-six)
       ("python-wrapt" ,python-wrapt)))
    (native-inputs
     `(("python-dateutil" ,python-dateutil)
       ("python-nose" ,python-nose)
       ("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'remove-spurious-test
           (lambda _
             ;; This can be removed after upgrading from python-3.7
             ;; https://github.com/PyCQA/astroid/issues/593
             ;; https://bugs.python.org/issue34056
             (delete-file "astroid/tests/unittest_modutils.py")
             #t))
         (replace 'check
           (lambda _
             (invoke "pytest" "astroid"))))))
    (home-page "https://github.com/PyCQA/astroid")
    (synopsis "Common base representation of python source code for pylint and
other projects")
    (description "@code{python-astroid} provides a common base representation
of python source code for projects such as pychecker, pyreverse, pylint, etc.

It provides a compatible representation which comes from the _ast module.  It
rebuilds the tree generated by the builtin _ast module by recursively walking
down the AST and building an extended ast.  The new node classes have
additional methods and attributes for different usages.  They include some
support for static inference and local name scopes.  Furthermore, astroid
builds partial trees by inspecting living objects.")
    (license license:lgpl2.1+)
    (properties `((python2-variant . ,(delay python2-astroid))))))

(define-public python2-astroid
  (let ((base (package-with-python2
               (strip-python2-variant python-astroid))))
    (package (inherit base)
    ;; Version 2.x removes python2 support.
    (version "1.6.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "astroid" version))
       (sha256
        (base32
         "0fir4b67sm7shcacah9n61pvq313m523jb4q80sycrh3p8nmi6zw"))))
    (arguments
      (substitute-keyword-arguments (package-arguments base)
        ((#:phases phases)
         `(modify-phases ,phases
            (add-after 'unpack 'remove-spurious-test
              (lambda _
                ;; https://github.com/PyCQA/astroid/issues/276
                (delete-file "astroid/tests/unittest_brain.py")
                #t))
            (replace 'check
              (lambda _
                (invoke"python" "-m" "unittest" "discover"
                                "-p" "unittest*.py")))))))
    (native-inputs `())
    (propagated-inputs
      `(("python2-backports-functools-lru-cache"
         ,python2-backports-functools-lru-cache)
        ("python2-enum34" ,python2-enum34)
        ("python2-singledispatch" ,python2-singledispatch)
        ,@(package-propagated-inputs base))))))

(define-public python-isort
  (package
    (name "python-isort")
    (version "4.3.4")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
              ;; Tests pass only from the Github sources
              (url "https://github.com/timothycrosley/isort")
              (commit version)))
       (file-name (git-file-name name version))
       (sha256
        (base32
         "1q0mlrpki5vjbgwxag5rghljjcfg7mvb0pbkwid80p0sqrxlm2p6"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-pytest" ,python-pytest)))
    (home-page "https://github.com/timothycrosley/isort")
    (synopsis "Python utility/library to sort python imports")
    (description "@code{python-isort} is a python utility/library to sort
imports alphabetically, and automatically separated into sections.  It
provides a command line utility, a python library and plugins for various
editors.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-isort))))))

(define-public python2-isort
  (let ((base (package-with-python2
               (strip-python2-variant python-isort))))
    (package (inherit base)
      (native-inputs
       `(("python2-futures" ,python2-futures)
         ,@(package-native-inputs base))))))

(define-public python2-backports-functools-lru-cache
  (package
    (name "python2-backports-functools-lru-cache")
    (version "1.5")
    (source
     (origin
       (method url-fetch)
       ;; only the pypi tarballs contain the necessary metadata
       (uri (pypi-uri "backports.functools_lru_cache" version))
       (sha256
        (base32
         "06jgv8gib4fhky0p5cmxdghvsgjyzcdgk48k8pxb1ccf11znk64x"))))
    (build-system python-build-system)
    (native-inputs
     `(("python2-setuptools-scm" ,python2-setuptools-scm)))
    (arguments
     `(#:python ,python-2))
    (home-page "https://github.com/jaraco/backports.functools_lru_cache")
    (synopsis "Backport of functools.lru_cache from Python 3.3")
    (description "@code{python2-backports-functools-lru-cache} is a backport
of @code{functools.lru_cache} from python 3.3.")
    (license license:expat)))

(define-public python-configparser
  (package
    (name "python-configparser")
    (version "3.5.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://bitbucket.org/ambv/configparser/get/"
             version ".tar.bz2"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0waq40as14abwzbb321hfz4vr1fi363nscy32ga14qvfygrg96wa"))))
    (build-system python-build-system)
    (home-page "https://github.com/jaraco/configparser/")
    (synopsis "Backport of configparser from python 3.5")
    (description "@code{python-configparser} is a backport of
@code{configparser} from Python 3.5 so that it can be used directly
in other versions.")
    (license license:expat)))

(define-public python2-configparser
  (package-with-python2 python-configparser))

(define-public python-mando
  (package
    (name "python-mando")
    (version "0.6.4")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "mando" version))
              (sha256
               (base32
                "0q6rl085q1hw1wic52pqfndr0x3nirbxnhqj9akdm5zhq2fv3zkr"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-rst2ansi" ,python-rst2ansi)
       ("python-six" ,python-six)))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://mando.readthedocs.org/")
    (synopsis
     "Wrapper around argparse, allowing creation of complete CLI applications")
    (description
     "This package is a wrapper around argparse, allowing you to write complete CLI
applications in seconds while maintaining all the flexibility.")
    (license license:expat)))

(define-public python2-mando
  (package-with-python2 python-mando))

(define-public python2-argparse
  (package
    (name "python2-argparse")
    (version "1.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "argparse" version))
       (sha256
        (base32
         "1r6nznp64j68ih1k537wms7h57nvppq0szmwsaf99n71bfjqkc32"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2))
    (home-page "https://github.com/ThomasWaldmann/argparse/")
    (synopsis "Python command-line parsing library")
    (description
     "This package is mostly for people who want to have @code{argparse} on
older Pythons because it was not part of the standard library back then.")
    (license license:psfl)))

(define-public python-fudge
  (package
    (name "python-fudge")
    ;; 0.9.6 is the latest version suitable for testing the "fabric" Python 2
    ;; package, which is currently the only use of this package.
    (version "0.9.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "fudge" version))
       (sha256
        (base32
         "185ia3vr3qk4f2s1a9hdxb8ci4qc0x0xidrad96pywg8j930qs9l"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))     ;XXX: Tests require the NoseJS Python package.
    (home-page "https://github.com/fudge-py/fudge")
    (synopsis "Replace real objects with fakes/mocks/stubs while testing")
    (description
     "Fudge is a Python module for using fake objects (mocks and stubs) to
test real ones.

In readable Python code, you declare the methods available on your fake object
and how they should be called.  Then you inject that into your application and
start testing.  This declarative approach means you don’t have to record and
playback actions and you don’t have to inspect your fakes after running code.
If the fake object was used incorrectly then you’ll see an informative
exception message with a traceback that points to the culprit.")
    (license license:expat)))

(define-public python2-fudge
  (package-with-python2 python-fudge))

(define-public python-mwclient
  (package
    (name "python-mwclient")
    (version "0.8.4")
    (source
     (origin
       (method url-fetch)
       ;; The PyPI version wouldn't contain tests.
       (uri (string-append "https://github.com/mwclient/mwclient/archive/"
                           "v" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1jj0yhilkjir00719fc7w133x7hdyhkxhk6xblla4asig45klsfv"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-requests" ,python-requests)
       ("python-requests-oauthlib"
        ,python-requests-oauthlib)
       ("python-six" ,python-six)))
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-pytest" ,python-pytest)
       ("python-pytest-pep8" ,python-pytest-pep8)
       ("python-pytest-cache" ,python-pytest-cache)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-responses" ,python-responses)))
    (home-page "https://github.com/btongminh/mwclient")
    (synopsis "MediaWiki API client")
    (description "This package provides a MediaWiki API client.")
    (license license:expat)))

(define-public python2-mwclient
  (package-with-python2 python-mwclient))

(define-public python-utils
  (package
    (name "python-utils")
    (version "2.1.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "python-utils" version))
              (sha256
               (base32
                "1mcsy6q5am4ya72rgkpb6kax6vv7c93cfkkas89xnpa4sj9zf28p"))))
    (build-system python-build-system)
    (native-inputs
     `(("pytest-runner" ,python-pytest-runner)
       ("pytest" ,python-pytest)
       ("six" ,python-six)))
    (home-page "https://github.com/WoLpH/python-utils")
    (synopsis "Convenient utilities not included with the standard Python install")
    (description
      "Python Utils is a collection of small Python functions and classes which
make common patterns shorter and easier.")
    (license license:bsd-2)))

(define-public python2-utils
  (package-with-python2 python-utils))

(define-public python-diff-match-patch
  (package
    (name "python-diff-match-patch")
    (version "20121119")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "diff-match-patch" version))
        (sha256
         (base32
          "0k1f3v8nbidcmmrk65m7h8v41jqi37653za9fcs96y7jzc8mdflx"))))
    (build-system python-build-system)
    (home-page "https://code.google.com/p/google-diff-match-patch")
    (synopsis "Synchronize plain text")
    (description "Diff Match and Patch libraries offer robust algorithms to
perform the operations required for synchronizing plain text.")
    (license license:asl2.0)))

(define-public python2-diff-match-patch
  (package-with-python2 python-diff-match-patch))

(define-public python-dirsync
  (package
    (name "python-dirsync")
    (version "2.2.3")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "dirsync" version))
        (sha256
         (base32
          "1r40fkanksagcszf1ag85mdr8w7rgc7196n6s1qlsk2abw6i7v0z"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("six" ,python-six)))
    (home-page "https://bitbucket.org/tkhyn/dirsync")
    (synopsis "Advanced directory tree synchronisation tool")
    (description "Advanced directory tree synchronisation tool.")
    (license license:expat)))

(define-public python2-dirsync
  (package-with-python2 python-dirsync))

(define-public python-levenshtein
  (package
    (name "python-levenshtein")
    (version "0.12.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "python-Levenshtein" version))
      (sha256
       (base32
        "1c9ybqcja31nghfcc8xxbbz9h60s9qi12b9hr4jyl69xbvg12fh3"))))
    (build-system python-build-system)
    (home-page "https://github.com/ztane/python-Levenshtein")
    (synopsis "Fast computation of Levenshtein distance and string similarity")
    (description
     "The Levenshtein Python C extension module contains functions for fast computation of
@enumerate
@item Levenshtein (edit) distance, and edit operations
@item string similarity
@item approximate median strings, and generally string averaging
@item string sequence and set similarity
@end enumerate
It supports both normal and Unicode strings.")
    (license license:gpl2+)))

(define-public python2-levenshtein
  (package-with-python2 python-levenshtein))

(define-public python-scandir
  (package
    (name "python-scandir")
    (version "1.9.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "scandir" version))
       (sha256
        (base32 "0r3hvf1a9jm1rkqgx40gxkmccknkaiqjavs8lccgq9s8khh5x5s4"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      (invoke "python" "test/run_tests.py"))))))
    (home-page "https://github.com/benhoyt/scandir")
    (synopsis "Directory iteration function")
    (description
     "Directory iteration function like os.listdir(), except that instead of
returning a list of bare filenames, it yields DirEntry objects that include
file type and stat information along with the name.  Using scandir() increases
the speed of os.walk() by 2-20 times (depending on the platform and file
system) by avoiding unnecessary calls to os.stat() in most cases.

This package is part of the Python standard library since version 3.5.")
    (license license:bsd-3)))

(define-public python2-scandir
  (package-with-python2 python-scandir))

(define-public python2-stemming
  (package
    (name "python2-stemming")
    (version "1.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "stemming" version))
       (sha256
        (base32 "0ldwa24gnnxhniv0fhygkpc2mwgd93q10ag8rvzayv6hw418frsr"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2))
    (home-page "https://bitbucket.org/mchaput/stemming/overview")
    (synopsis "Python implementations of various stemming algorithms")
    (description
     "Python implementations of the Porter, Porter2, Paice-Husk, and Lovins
stemming algorithms for English.  These implementations are straightforward and
efficient, unlike some Python versions of the same algorithms available on the
Web.  This package is an extraction of the stemming code included in the Whoosh
search engine.")
    (license license:public-domain)))

(define-public python-factory-boy
  (package
    (name "python-factory-boy")
    (version "2.8.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "factory_boy" version))
       (sha256
        (base32 "1fvin6san5xsjh2c4y18caj2lnmwxlylyqm8mh1yc6rp38wlwr56"))))
    (build-system python-build-system)
    (arguments
     ;; Tests are not included in the tarball.
     `(#:tests? #f))
    (propagated-inputs
     `(("faker" ,python-faker)))
    (home-page "https://github.com/benhoyt/scandir")
    (synopsis "Versatile test fixtures replacement")
    (description
     "Factory_boy is a fixtures replacement based on thoughtbot’s factory_girl.

As a fixtures replacement tool, it aims to replace static, hard to maintain
fixtures with easy-to-use factories for complex object.

Instead of building an exhaustive test setup with every possible combination
of corner cases, factory_boy allows you to use objects customized for the
current test, while only declaring the test-specific fields")
    (license license:expat)))

(define-public python2-factory-boy
  (package-with-python2 python-factory-boy))

(define-public python-translate-toolkit
  (package
    (name "python-translate-toolkit")
    (version "2.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "translate-toolkit" version ".tar.bz2"))
       (sha256
        (base32 "1vlkwrg83vb17jc36pmwh2b7jphwf390lz0jw8hakcg16qhwypvq"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-sphinx" ,python-sphinx)))
    (propagated-inputs
     `(("python-babel" ,python-babel)
       ("python-beautifulsoup4" ,python-beautifulsoup4)
       ("python-chardet" ,python-chardet)
       ("python-diff-match-patch" ,python-diff-match-patch)
       ("python-levenshtein" ,python-levenshtein)
       ("python-lxml" ,python-lxml)
       ("python-six" ,python-six)
       ("python-vobject" ,python-vobject)
       ("python-pyyaml" ,python-pyyaml)))
    (arguments
     ;; TODO: tests are not run, because they end with
     ;; TypeError: parse() missing 2 required positional arguments: 'tree' and
     ;; 'parse_funcs'
     ;; during test setup.
     `(#:tests? #f))
    (home-page "https://toolkit.translatehouse.org")
    (synopsis "Tools and API for translation and localization engineering")
    (description
     "Tools and API for translation and localization engineering.  It contains
several utilities, as well as an API for building localization tools.")
    (license license:gpl2+)))

(define-public python2-translate-toolkit
  (package-with-python2 python-translate-toolkit))

(define-public python-packaging
  (package
    (name "python-packaging")
    (version "19.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "packaging" version))
        (sha256
         (base32
          "1brjhygq9dz6x1kdljivkjfldi3qf5rbkqgck1bpgv9qpv8ab60c"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _ (invoke "py.test" "-vv"))))))
    (native-inputs
     `(("python-pretend" ,python-pretend)
       ("python-pytest" ,python-pytest)))
    (propagated-inputs
     `(("python-pyparsing" ,python-pyparsing)
       ("python-six" ,python-six)))
    (home-page "https://github.com/pypa/packaging")
    (synopsis "Core utilities for Python packages")
    (description "Packaging is a Python module for dealing with Python packages.
It offers an interface for working with package versions, names, and dependency
information.")
    ;; From 'LICENSE': This software is made available under the terms of
    ;; *either* of the licenses found in LICENSE.APACHE or LICENSE.BSD.
    ;; Contributions to this software is made under the terms of *both* these
    ;; licenses.
    (license (list license:asl2.0 license:bsd-2))))

(define-public python2-packaging
  (package-with-python2 python-packaging))

(define-public python-relatorio
  (package
    (name "python-relatorio")
    (version "0.8.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "relatorio" version))
       (sha256
        (base32
         "1na6hlhz1awi1hbjg1gyclq0khz42iz90wvdjw7mmj655788bpxx"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-lxml" ,python-lxml)
       ("python-genshi" ,python-genshi)))
    (native-inputs
     `(("python-magic" ,python-magic)))
    (home-page "https://relatorio.tryton.org/")
    (synopsis "Templating library able to output ODT and PDF files")
    (description "Relatorio is a templating library which provides a way to
easily output ODT, ODS, PNG, SVG and several other kinds of files.  Support
for more filetypes can be easily added by creating plugins for them.")
    (license license:gpl3+)))

(define-public python2-relatorio
  (package-with-python2 python-relatorio))

(define-public python-radon
  (package
    (name "python-radon")
    (version "2.2.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "radon" version))
       (sha256
        (base32
         "07gq5hq4nrffxnlnksws9hrx7fd001gam63j62i82gyfr23gvdym"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      (invoke "python" "radon/tests/run.py"))))))
    (propagated-inputs
     `(("python-colorama" ,python-colorama)
       ("python-flake8-polyfill" ,python-flake8-polyfill)
       ("python-mando" ,python-mando)))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-pytest-mock" ,python-pytest-mock)))
    (home-page "https://radon.readthedocs.org/")
    (synopsis "Code Metrics in Python")
    (description "Radon is a Python tool which computes various code metrics.
Supported metrics are:
@itemize @bullet
@item raw metrics: SLOC, comment lines, blank lines, &c.
@item Cyclomatic Complexity (i.e.  McCabe’s Complexity)
@item Halstead metrics (all of them)
@item the Maintainability Index (a Visual Studio metric)
@end itemize")
    (license license:expat)))

(define-public python2-radon
  (package-with-python2 python-radon))

(define-public python-sure
  (package
    (name "python-sure")
    (version "1.4.11")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "sure" version))
       (sha256
        (base32
         "1and0drq8w9iplsic22n2h7hkpyq03a1mbqk4sgcdqhqzdqm539w"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-mock" ,python-mock)
       ("python-six" ,python-six)))
    (native-inputs
     `(("python-nose" ,python-nose)))
    (home-page "https://github.com/gabrielfalcao/sure")
    (synopsis "Automated testing library in python for python")
    (description
     "Sure is a python library that leverages a DSL for writing assertions.
Sure is heavily inspired by @code{RSpec Expectations} and @code{should.js}.")
    (license license:gpl3+)))

(define-public python2-sure
  (package-with-python2 python-sure))

(define-public python2-couleur
  ;; This package does not seem to support python3 at all, hence,
  ;; only the python2 variant definition is provided.
  (package
    (name "python2-couleur")
    (version "0.6.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "couleur" version))
       (sha256
        (base32
         "1qqaxyqz74wvid0cr119dhcwz0h0if5b5by44zl49pd5z65v58k1"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2))
    (home-page "https://github.com/gabrielfalcao/couleur")
    (synopsis
     "ANSI terminal tool for python, colored shell and other handy fancy features")
    (description
     "@code{Couleur} provides python programs a way to use the ANSI features in a unix
terminal such as coloured output in the shell, overwriting output, indentation, etc.")
    ;; README.md says ASL2.0, but all source code headers are LGPL3+.
    ;; https://github.com/gabrielfalcao/couleur/issues/11
    (license license:lgpl3+)))

(define-public python-misaka
  (package
    (name "python-misaka")
    (version "2.1.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "misaka" version))
       (sha256
        (base32
         "1mzc29wwyhyardclj1vg2xsfdibg2lzb7f1azjcxi580ama55wv2"))))
    (build-system python-build-system)
    (arguments
     `(;; Line 37 of setup.py calls self.run_command('develop')
       ;; in the 'check' phase. This command seems to be trying
       ;; to write to
       ;; /gnu/store/...-python-<version>/lib/python<version>/site-packages/
       ;; for which it does not have the permission to write.
       #:tests? #f))
    (propagated-inputs
     `(("python-cffi" ,python-cffi)))
    (home-page "https://github.com/FSX/misaka")
    (synopsis "Python binding for Hoedown")
    (description
     "@code{Misaka} is a CFFI-based binding for @code{Hoedown}, a fast markdown processing
library written in C.  It features a fast HTML renderer and functionality to make custom
renderers (e.g. man pages or LaTeX).")
    (license license:expat)))

(define-public python2-misaka
  (package-with-python2 python-misaka))

(define-public python2-steadymark
  ;; This is forced into being a python2 only variant
  ;; due to its dependence on couleur that has no support
  ;; for python3
  (package
    (name "python2-steadymark")
    (version "0.7.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "steadymark" version))
       (sha256
        (base32
         "1640i9g8dycql3cc8j0bky0jkzj0q39blfbp4lsgpkprkfgcdk8v"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-couleur" ,python2-couleur)
       ("python-sure" ,python2-sure)
       ("python-misaka" ,python2-misaka)))
    (arguments
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         (add-before 'build 'patch-setup-py
           (lambda _
             ;; Update requirements from dependency==version
             ;; to dependency>=version
             (substitute* "setup.py"
               (("==") ">="))
             #t)))))
    (home-page "https://github.com/gabrielfalcao/steadymark")
    (synopsis "Markdown-based test runner for python")
    (description
     "@code{Steadymark} allows documentation to be written in github-flavoured
markdown.  The documentation may contain snippets of code surrounded by python
code blocks and @code{Steadymark} will find these snippets and run them, making
sure that there are no old malfunctional examples in the documentation examples.")
    (license license:expat)))

(define-public python-jsonpointer
  (package
    (name "python-jsonpointer")
    (version "1.10")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "jsonpointer" version))
       (sha256
        (base32
         "1cg0gvgqjysydv6p45v4jywg1jb3v48c7m3cbpi57zgf6nndr9cz"))))
  (build-system python-build-system)
  (home-page "https://github.com/stefankoegl/python-json-pointer")
  (synopsis "Identify specific nodes in a JSON document")
  (description "@code{jsonpointer} allows you to access specific nodes
by path in a JSON document (see RFC 6901).")
  (license license:bsd-3)))

(define-public python2-jsonpointer
  (package-with-python2 python-jsonpointer))

(define-public python-jsonpatch
  (package
    (name "python-jsonpatch")
    (version "1.16")
    (source
     (origin
       (method url-fetch)
       ;; pypi version lacks tests.js
       (uri (string-append "https://github.com/stefankoegl/python-json-patch/"
                           "archive/v" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "085ykisl8v7mv9h7hvhdy3l2fjzs4214gx32r5k6nx4f76hbv6y5"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-jsonpointer" ,python-jsonpointer)))
    (home-page "https://github.com/stefankoegl/python-json-patch")
    (synopsis "Applying JSON Patches in Python 2.6+ and 3.x")
    (description "@code{jsonpatch} is a library and program that allows
applying JSON Patches according to RFC 6902.")
    (license license:bsd-3)))

(define-public python2-jsonpatch
  (package-with-python2 python-jsonpatch))

(define-public python-jsonpatch-0.4
  (package (inherit python-jsonpatch)
    (name "python-jsonpatch")
    (version "0.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/stefankoegl/python-json-patch/"
                           "archive/v" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0j0cd9z9zyp8kppp464jxrfgrnbgkzl1yi10i5gsv8yz6d95929d"))))))

(define-public python2-jsonpatch-0.4
  (package-with-python2 python-jsonpatch-0.4))

(define-public python-rfc3986
  (package
    (name "python-rfc3986")
    (version "1.1.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "rfc3986" version))
              (sha256
               (base32
                "06wlmysw83f75ff84zr1yr6n0shvc2xn1n1sb4iwzqap9hf5fn44"))))
    (build-system python-build-system)
    (arguments
     `(#:modules ((guix build utils)
                  (guix build python-build-system)
                  (ice-9 ftw)
                  (srfi srfi-1)
                  (srfi srfi-26))
       #:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (let ((cwd (getcwd)))
               (setenv "PYTHONPATH"
                       (string-append cwd "/build/"
                                      (find (cut string-prefix? "lib" <>)
                                            (scandir (string-append cwd "/build")))
                                      ":"
                                      (getenv "PYTHONPATH")))
             (invoke "pytest" "-v")))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://rfc3986.readthedocs.io/")
    (synopsis "Parse and validate URI references")
    (description
     "@code{rfc3986} is a Python implementation of RFC@tie{}3986 including
validation and authority parsing.  This module also supports RFC@tie{}6874
which adds support for zone identifiers to IPv6 addresses.")
    (license license:asl2.0)))

(define-public python2-rfc3986
  (package-with-python2 python-rfc3986))

(define-public python-rfc3987
  (package
    (name "python-rfc3987")
    (version "1.3.7")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "rfc3987" version))
      (sha256
       (base32
        "192pclzs2y0yaywqkrlvd0x73740q310kvqvm6jldhi619mq59wi"))))
    (build-system python-build-system)
    (home-page "https://pypi.python.org/pypi/rfc3987")
    (synopsis "Parsing and validation of URIs (RFC 3986) and IRIs (RFC 3987)")
    (description "@code{rfc3987} provides routines for parsing and
validation of URIs (see RFC 3986) and IRIs (see RFC 3987).")
    (license license:gpl3+)))

(define-public python2-rfc3987
  (package-with-python2 python-rfc3987))

(define-public python-validate-email
  (package
    (name "python-validate-email")
    (version "1.3")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "validate_email" version))
      (sha256
       (base32
        "1bxffaf5yz2cph8ki55vdvdypbwkvn2xr1firlcy62vqbzf1jivq"))))
    (build-system python-build-system)
    (home-page "https://github.com/syrusakbary/validate_email")
    (synopsis "Verifies if an email address is valid and really exists")
    (description "@code{validate_email} can be used to verify if an email
address is valid and really exists.")
    (license license:lgpl3+)))

(define-public python2-validate-email
  (package-with-python2 python-validate-email))

(define-public python-flex
  (package
    (name "python-flex")
    (version "6.10.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "flex" version))
      (sha256
       (base32
        "00pamnwla3khk8nyla7y28dq9jnh69swd7f4jfsl7sn1izs8n8zk"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-click" ,python-click)
       ("python-iso8601" ,python-iso8601)
       ("python-jsonpointer" ,python-jsonpointer)
       ("python-pyyaml" ,python-pyyaml)
       ("python-requests" ,python-requests)
       ("python-rfc3987" ,python-rfc3987)
       ("python-six" ,python-six)
       ("python-validate-email" ,python-validate-email)))
    (home-page "https://github.com/pipermerriam/flex")
    (synopsis "Validates Swagger schemata")
    (description "@code{flex} can be used to validate Swagger schemata.")
    (license license:bsd-3)))

(define-public python2-flex
  (package-with-python2 python-flex))

(define-public python-marshmallow
  (package
    (name "python-marshmallow")
    (version "3.0.0b14")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "marshmallow" version))
      (sha256
       (base32
        "1digk3f5cfk7wmlka65mc7bzsd96pbsgcsvp6pimd5b4ff9zb5p3"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-dateutil" ,python-dateutil)
       ("python-simplejson" ,python-simplejson)))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-pytz" ,python-pytz)))
    (home-page "https://github.com/marshmallow-code/marshmallow")
    (synopsis "Convert complex datatypes to and from native
Python datatypes.")
    (description "@code{marshmallow} provides a library for converting
complex datatypes to and from native Python datatypes.")
    (license license:expat)))

(define-public python2-marshmallow
  (package-with-python2 python-marshmallow))

(define-public python-apispec
  (package
    (name "python-apispec")
    (version "0.25.3")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "apispec" version))
      (sha256
        (base32
          "0kxa8723zbisx10363yh4mmmn4higxrspymbjfz5zq8f644zagm9"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pyyaml" ,python-pyyaml)))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-flask" ,python-flask)
       ("python-marshmallow" ,python-marshmallow)
       ("python-tornado" ,python-tornado)
       ("python-bottle" ,python-bottle)
       ("python-mock" ,python-mock)))
    (home-page "https://github.com/marshmallow-code/apispec")
    (synopsis "Swagger 2.0 API specification generator")
    (description "@code{python-apispec} is a pluggable API specification
generator. Currently supports the OpenAPI specification (f.k.a.
Swagger 2.0).")
    (license license:expat)))

(define-public python2-apispec
  (package-with-python2 python-apispec))

(define-public python-flasgger
  (package
    (name "python-flasgger")
    (version "0.6.3")
    (source
      (origin
        (method git-fetch)
        (uri (git-reference
              (url "https://github.com/rochacbruno/flasgger.git")
              (commit version)))
        (file-name (git-file-name name version))
        (sha256
          (base32 "0yydxsyjnc0clbrjqb1n7587l6cdqvwdagwxk5hkx01qwdfbkvpn"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (substitute* "Makefile"
               (("flake8 flasgger --ignore=F403")
                "flake8 flasgger --ignore=E731,F403"))
             (setenv "PYTHONPATH" (string-append (getcwd)
                                                 ":"
                                                 (getenv "PYTHONPATH")))
             (invoke "py.test"))))))
    (propagated-inputs
     `(("python-flask" ,python-flask)
       ("python-pyyaml" ,python-pyyaml)
       ("python-jsonschema" ,python-jsonschema)
       ("python-mistune" ,python-mistune)
       ("python-six" ,python-six)))
    (native-inputs
     `(("python-decorator" ,python-decorator)
       ("python-flake8" ,python-flake8)
       ("python-flask-restful" ,python-flask-restful)
       ("python-flex" ,python-flex)
       ("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-marshmallow" ,python-marshmallow)
       ("python-apispec" ,python-apispec)))
    (home-page "https://github.com/rochacbruno/flasgger/")
    (synopsis "Extract Swagger specs from your Flask project")
    (description "@code{python-flasgger} allows extracting Swagger specs
from your Flask project.  It is a fork of Flask-Swagger.")
    (license license:expat)))

(define-public python2-flasgger
  (package-with-python2 python-flasgger))

(define-public python-swagger-spec-validator
  (package
    (name "python-swagger-spec-validator")
    (version "2.4.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "swagger-spec-validator" version))
       (sha256
        (base32
         "11g627icrsqwazsncwi0sdvprcj6hwaayw5xk3xsj8d97bmrzqjp"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-jsonschema" ,python-jsonschema)
       ("python-pyyaml" ,python-pyyaml)
       ("python-six" ,python-six)))
    (home-page
     "https://github.com/Yelp/swagger_spec_validator")
    (synopsis "Validation of Swagger specifications")
    (description "@code{swagger_spec_validator} provides a library for
validating Swagger API specifications.")
    (license license:asl2.0)))

(define-public python2-swagger-spec-validator
  (package-with-python2 python-swagger-spec-validator))

(define-public python-apache-libcloud
  (package
    (name "python-apache-libcloud")
    (version "2.4.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "apache-libcloud" version))
        (sha256
         (base32
          "0daj3mkzw79v5zin2r1s2wkrz1hplfc16bwj4ss68i5qjq4l2p0j"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-ssh
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "libcloud/compute/ssh.py"
               (("'ssh'") (string-append "'" (assoc-ref inputs "openssh")
                                         "/bin/ssh" "'")))
             #t))
         (add-after 'unpack 'patch-tests
           (lambda _
             (substitute* "./libcloud/test/test_file_fixtures.py"
               ;; See <https://issues.apache.org/jira/browse/LIBCLOUD-923>.
               (("def _ascii") "def _raw_data(self, method, url, body, headers):
        return (httplib.OK,
                \"1234abcd\",
                {\"test\": \"value\"},
                httplib.responses[httplib.OK])
    def _ascii"))
             (substitute* "libcloud/test/compute/test_ssh_client.py"
               (("class ShellOutSSHClientTests")
                "@unittest.skip(\"Guix container doesn't have ssh service\")
class ShellOutSSHClientTests")
               ;; See <https://issues.apache.org/jira/browse/LIBCLOUD-924>.
               (("'.xf0.x90.x8d.x88'") "b'\\xF0\\x90\\x8D\\x88'")
               (("'.xF0', '.x90', '.x8D', '.x88'")
                "b'\\xF0', b'\\x90', b'\\x8D', b'\\x88'"))
             #t))
         (add-before 'check 'copy-secret
           (lambda _
             (copy-file "libcloud/test/secrets.py-dist"
                        "libcloud/test/secrets.py")
             #t)))))
    (inputs
     `(("openssh" ,openssh)))
    (propagated-inputs
     `(("python-paramiko" ,python-paramiko)
       ("python-requests" ,python-requests)))
    (native-inputs
     `(("python-lockfile" ,python-lockfile)
       ("python-mock" ,python-mock)
       ("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)
       ("python-requests-mock" ,python-requests-mock)))
    (home-page "https://libcloud.apache.org/")
    (synopsis "Unified Cloud API")
    (description "@code{libcloud} is a Python library for interacting with
many of the popular cloud service providers using a unified API.")
    (license license:asl2.0)))

(define-public python2-apache-libcloud
  (package-with-python2 python-apache-libcloud))

(define-public python-smmap2
  (package
    (name "python-smmap2")
    (version "2.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "smmap2" version))
       (sha256
        (base32
         "1hvn28p3zvxa98sbi9lrqvv2ps4q284j4jq9a619zw0m7yv0sly7"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nosexcover" ,python-nosexcover)))
    (home-page "https://github.com/Byron/smmap")
    (synopsis "Python sliding window memory map manager")
    (description "@code{smmap2} is a pure Python implementation of a sliding
window memory map manager.")
    (license license:bsd-3)))

(define-public python2-smmap2
  (package-with-python2 python-smmap2))

(define-public python-regex
  (package
    (name "python-regex")
    (version "2019.04.14")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "regex" version))
              (sha256
               (base32
                "1a6hhfs6l6snr1z654ay6wzbmwdkmv282fzfkd5hk2d1n73y8v6m"))))
    ;; TODO: Fix and enable regex_test.py tests that complain about the
    ;; test.support module not existing.
    (build-system python-build-system)
    (home-page "https://bitbucket.org/mrabarnett/mrab-regex")
    (synopsis "Alternative regular expression module")
    (description "This regular expression implementation is backwards-
compatible with the standard @code{re} module, but offers additional
functionality like full case-folding for case-insensitive matches in Unicode.")
    (license license:psfl)))

(define-public python2-regex
  (package-with-python2 python-regex))

(define-public python2-pyopengl
  (package
   (name "python2-pyopengl")
   (version "3.1.0")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "PyOpenGL" version))
     (sha256
      (base32
       "1byxjj6a8rwzhxhjqlc588zdad2qwxdd7vlam2653ylll31waiwv"))))
   (arguments
     `(#:python ,python-2))
   (build-system python-build-system)
   (home-page "http://pyopengl.sourceforge.net")
   (synopsis "Standard OpenGL bindings for Python")
   (description
    "PyOpenGL is the most common cross platform Python binding to OpenGL and
related APIs.  The binding is created using the standard @code{ctypes}
library.")
   (license license:bsd-3)))

(define-public python2-pyopengl-accelerate
  (package
    (inherit python2-pyopengl)
    (name "python2-pyopengl-accelerate")
    (version "3.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "PyOpenGL-accelerate" version))
       (sha256
        (base32
         "0464c1ifzk0k92lyndikmvzjgnx1y25r7bkkc8pnxm4kp1q4czwj"))))
    (synopsis "Acceleration code for PyOpenGL")
    (description
     "This is the Cython-coded accelerator module for PyOpenGL.")))

(define-public python-rencode
  (package
   (name "python-rencode")
   (version "1.0.5")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "rencode" version))
     (sha256
      (base32
       "0mzwdq1is7kyyr32i5k4iz6g5xxdvmiyc132jnc60p9m6lnwjrpv"))))
   (build-system python-build-system)
   (arguments
    `(#:phases
      (modify-phases %standard-phases
        (add-before 'check 'delete-bogus-test
          ;; This test requires /home/aresch/Downloads, which is not provided by
          ;; the build environment.
          (lambda _
            (delete-file "rencode/t.py")
            #t)))))
   (native-inputs `(("pkg-config" ,pkg-config)
                    ("python-cython" ,python-cython)))
   (home-page "https://github.com/aresch/rencode")
   (synopsis "Serialization of heterogeneous data structures")
   (description
    "The @code{rencode} module is a data structure serialization library,
similar to @code{bencode} from the BitTorrent project.  For complex,
heterogeneous data structures with many small elements, r-encoding stake up
significantly less space than b-encodings.  This version of rencode is a
complete rewrite in Cython to attempt to increase the performance over the
pure Python module.")
   (license license:bsd-3)))

(define-public python2-rencode
  (package-with-python2 python-rencode))

(define-public python-xenon
  (package
    (name "python-xenon")
    (version "0.5.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "xenon" version))
       (sha256
        (base32
         "029cbhysg2vr5n4jz8gpg2793f8wkwnqpr1qgv6c1dn685vy31mc"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pyyaml" ,python-pyyaml)
       ("python-radon" ,python-radon)
       ("python-requests" ,python-requests)
       ("python-flake8" ,python-flake8)
       ("python-tox" ,python-tox)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'build 'patch-test-requirements
           (lambda _
             ;; Remove httpretty dependency for tests.
             (substitute* "setup.py"
               (("httpretty") ""))
             #t)))))
    (home-page "https://xenon.readthedocs.org/")
    (synopsis "Monitor code metrics for Python on your CI server")
    (description
     "Xenon is a monitoring tool based on Radon.  It monitors code complexity.
Ideally, @code{xenon} is run every time code is committed.  Through command
line options, various thresholds can be set for the complexity of code.  It
will fail (i.e.  it will exit with a non-zero exit code) when any of these
requirements is not met.")
    (license license:expat)))

(define-public python2-xenon
  (package-with-python2 python-xenon))

(define-public python-pysocks
  (package
    (name "python-pysocks")
    (version "1.7.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "PySocks" version))
       (sha256
        (base32
         "0z4p31bpqm893cf87qqgb30k7nwd8kqfjwwjm5cvxb6zbyj1w0yr"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f))
    (home-page "https://github.com/Anorov/PySocks")
    (synopsis "SOCKS client module")
    (description "@code{pysocks} is an updated and semi-actively maintained
version of @code{SocksiPy} with bug fixes and extra features.")
    (license license:bsd-3)))

(define-public python2-pysocks
  (package-with-python2 python-pysocks))

(define-public python-pydiff
  (package
    (name "python-pydiff")
    (version "0.2")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pydiff" version))
        (sha256
          (base32
            "1als83h9w0gab24ipyna6khm390qmpnpkc5jksmdbs2xc8hp2z44"))))
    (build-system python-build-system)
    (home-page "https://github.com/myint/pydiff")
    (synopsis "Library to diff two Python files at the bytecode level")
    (description
      "@code{pydiff} makes it easy to look for actual code changes while
ignoring formatting changes.")
    (license license:expat)))

(define-public python2-pydiff
  (package-with-python2 python-pydiff))

(define-public python-tqdm
  (package
    (name "python-tqdm")
    (version "4.19.6")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "tqdm" version))
         (sha256
           (base32
             "1pw0ngm0zn9papdmkwipi3yih5c3di6d0w849bdmrraq4d2d9h2y"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-flake8" ,python-flake8)
       ("python-nose" ,python-nose)
       ("python-coverage" ,python-coverage)))
    (home-page "https://github.com/tqdm/tqdm")
    (synopsis "Fast, extensible progress meter")
    (description
      "Make loops show a progress bar on the console by just wrapping any
iterable with @code{|tqdm(iterable)|}.  Offers many options to define
design and layout.")
    (license (list license:mpl2.0 license:expat))))

(define-public python2-tqdm
  (package-with-python2 python-tqdm))

(define-public python-pkginfo
  (package
    (name "python-pkginfo")
    (version "1.4.2")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pkginfo" version))
        (sha256
          (base32
            "0x6lm17p1ks031mj6pajyp4rkq74vpqq8qwjb7ikgwmkli1day2q"))))
    (build-system python-build-system)
    (arguments
     ;; The tests are broken upstream.
     '(#:tests? #f))
    (home-page
      "https://code.launchpad.net/~tseaver/pkginfo/trunk")
    (synopsis
      "Query metadatdata from sdists, bdists, and installed packages")
    (description
      "API to query the distutils metadata written in @file{PKG-INFO} inside a
source distriubtion (an sdist) or a binary distribution (e.g., created by
running bdist_egg).  It can also query the EGG-INFO directory of an installed
distribution, and the *.egg-info stored in a \"development checkout\" (e.g,
created by running @code{python setup.py develop}).")
    (license license:expat)))

(define-public python2-pkginfo
  (package-with-python2 python-pkginfo))

(define-public python-twine
  (package
    (name "python-twine")
    (version "1.9.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "twine" version))
        (sha256
          (base32
            "1ay1b6kdq6k4bfbjsvf6ymj41wrgpvinhxndb09355pwhxwmp96a"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-tqdm" ,python-tqdm)
       ("python-pkginfo" ,python-pkginfo)
       ("python-requests" ,python-requests)
       ("python-requests-toolbelt" ,python-requests-toolbelt)))
    (home-page "https://github.com/pypa/twine")
    (synopsis "Collection of utilities for interacting with PyPI")
    (description
      "@code{twine} currently supports registering projects and uploading
distributions.  It authenticates the user over HTTPS, allows them to pre-sign
their files and supports any packaging format (including wheels).")
    (license license:asl2.0)))

(define-public python2-twine
  (package-with-python2 python-twine))

(define-public python-linecache2
  (package
    (name "python-linecache2")
    (version "1.0.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "linecache2" version))
        (sha256
          (base32
            "0z79g3ds5wk2lvnqw0y2jpakjf32h95bd9zmnvp7dnqhf57gy9jb"))))
    (build-system python-build-system)
    (arguments
     `(;; The tests depend on unittest2, and our version is a bit too old.
       #:tests? #f))
    (native-inputs
     `(("python-pbr" ,python-pbr-minimal)))
    (home-page
      "https://github.com/testing-cabal/linecache2")
    (synopsis "Backports of the linecache module")
    (description
      "The linecache module allows one to get any line from any file, while
attempting to optimize internally, using a cache, the common case where many
lines are read from a single file.")
    (license license:psfl)))

(define-public python2-linecache2
  (package-with-python2 python-linecache2))

(define-public python-traceback2
  (package
    (name "python-traceback2")
    (version "1.4.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "traceback2" version))
        (sha256
          (base32
            "0c1h3jas1jp1fdbn9z2mrgn3jj0hw1x3yhnkxp7jw34q15xcdb05"))))
    (build-system python-build-system)
    (arguments
     `(;; python-traceback2 and python-unittest2 depend on one another.
       #:tests? #f))
    (native-inputs
     `(("python-pbr" ,python-pbr-minimal)))
    (propagated-inputs
      `(("python-linecache2" ,python-linecache2)))
    (home-page
      "https://github.com/testing-cabal/traceback2")
    (synopsis "Backports of the traceback module")
    (description
      "This module provides a standard interface to extract, format and print
stack traces of Python programs.  It exactly mimics the behavior of the Python
interpreter when it prints a stack trace.")
    (license license:psfl)))

(define-public python2-traceback2
  (package-with-python2 python-traceback2))

(define-public python-ratelimiter
  (package
    (name "python-ratelimiter")
    (version "1.2.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ratelimiter" version))
       (sha256
        (base32
         "1dhz85mj5bqd2mij84ncs6pz32hgidr79hay4aqfmzaa4rbb497p"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f))          ; There are no tests in the pypi archive.
    (home-page "https://github.com/RazerM/ratelimiter")
    (synopsis "Simple rate limiting object")
    (description
     "The @code{ratelimiter} module ensures that an operation will not be
executed more than a given number of times during a given period.")
    (license license:asl2.0)))

(define-public python2-ratelimiter
  (package-with-python2 python-ratelimiter))

(define-public python-dukpy
  (package
    (name "python-dukpy")
    (version "0.3")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/kovidgoyal/dukpy.git")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32 "13h21nqzasv4zj32xs61brmc106pr2cx243672crcmwxxnjgaxls"))))
    (build-system python-build-system)
    (home-page "https://github.com/kovidgoyal/dukpy")
    (synopsis "Run JavaScript in python")
    (description
     "dukpy is a JavaScript runtime environment for Python using the duktape
embeddable JavaScript engine.")
    ;; Dukpy is licensed under MIT like the embedded duktape library,
    ;; with 'errors.c' as GPL3.
    (license (list license:expat license:gpl3))))

(define-public python2-dukpy
  (package-with-python2 python-dukpy))

(define-public python-jsonrpclib-pelix
  (package
    (name "python-jsonrpclib-pelix")
    (version "0.3.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "jsonrpclib-pelix" version))
       (sha256
        (base32
         "0f83z5zi7w32vprhk1dyc94ir1bh4hdd57bjdbwkq9ykng8qilhl"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))                    ; no tests in PyPI tarball
    (home-page "https://github.com/tcalmant/jsonrpclib/")
    (synopsis "JSON-RPC 2.0 client library for Python")
    (description
     "This library implements the JSON-RPC v2.0
specification (backwards-compatible) as a client library for Python.  This
version is a fork of jsonrpclib by Josh Marshall, usable with Pelix remote
services.")
    (license license:asl2.0)))

(define-public python2-jsonrpclib-pelix
  (package-with-python2 python-jsonrpclib-pelix))

(define-public python-setuptools-scm-git-archive
  (package
    (name "python-setuptools-scm-git-archive")
    (version "1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "setuptools_scm_git_archive" version))
       (sha256
        (base32
         "1nii1sz5jq75ilf18bjnr11l9rz1lvdmyk66bxl7q90qan85yhjj"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (propagated-inputs
     `(("python-setuptools-scm" ,python-setuptools-scm)))
    (home-page "https://github.com/Changaco/setuptools_scm_git_archive/")
    (synopsis "Setuptools_scm plugin for git archives")
    (description
     "The setuptools_scm_git_archive package is a plugin to
setuptools_scm, which supports obtaining versions from git archives that
belong to tagged versions.")
    (license license:expat)))

(define-public python2-setuptools-scm-git-archive
  (package-with-python2 python-setuptools-scm-git-archive))

(define-public python-setuptools-git
  (package
    (name "python-setuptools-git")
    (version "1.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "setuptools-git" version))
       (sha256
        (base32
         "0i84qjwp5m0l9qagdjww2frdh63r37km1c48mrvbmaqsl1ni6r7z"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; This is needed for tests.
         (add-after 'unpack 'configure-git
           (lambda _
             (setenv "HOME" "/tmp")
             (invoke "git" "config" "--global" "user.email" "guix")
             (invoke "git" "config" "--global" "user.name" "guix")
             #t)))))
    (native-inputs
     `(("git" ,git-minimal)))
    (home-page "https://github.com/msabramo/setuptools-git")
    (synopsis "Setuptools revision control system plugin for Git")
    (description
     "This package provides a plugin for Setuptools for revision control with
Git.")
    (license license:bsd-3)))

(define-public python-pyclipper
  (package
    (name "python-pyclipper")
    (version "1.1.0.post1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyclipper" version ".zip"))
       (sha256
        (base32
         "0ldbkbnx94an4zzrwb1sxmg6k0jgk4cwmvcdyy8y5k1zslc612wa"))
      (modules '((guix build utils)))
      (snippet
       '(begin
          ;; This file is generated by Cython.
          (delete-file "pyclipper/pyclipper.cpp") #t))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'build 'cythonize-sources
           (lambda _
             (with-directory-excursion "pyclipper"
               (invoke "cython" "--cplus" "pyclipper.pyx")))))))
    (propagated-inputs
     `(("python-setuptools-scm-git-archive" ,python-setuptools-scm-git-archive)))
    (native-inputs
     `(("python-cython" ,python-cython)
       ("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)
       ("python-unittest2" ,python-unittest2)
       ("unzip" ,unzip)))
    (home-page "https://github.com/greginvm/pyclipper")
    (synopsis "Wrapper for Angus Johnson's Clipper library")
    (description
     "Pyclipper is a Cython wrapper for the C++ translation of the
Angus Johnson's polygon clipping Clipper library (ver. 6.4.2).")
    (license license:expat)))

(define-public python2-pyclipper
  (package-with-python2 python-pyclipper))

(define-public python2-booleanoperations
  (package
    (name "python2-booleanoperations")
    (version "0.7.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "booleanOperations" version ".zip"))
       (sha256
        (base32
         "1hw42fazdpvsn77glx96hwsj9l17mvx37sc5707s08y5w6fx16mn"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2))
    (native-inputs
     `(("unzip" ,unzip)
       ("python2-pytest" ,python2-pytest)
       ("python2-pytest-runner" ,python2-pytest-runner)))
    (propagated-inputs
     `(("python-fonttools" ,python2-fonttools)
       ("python-pyclipper" ,python2-pyclipper)
       ("python-ufolib" ,python2-ufolib)))
    (home-page "https://github.com/typemytype/booleanOperations")
    (synopsis "Boolean operations on paths")
    (description
     "BooleanOperations provides a Python library that enables
boolean operations on paths.")
    (license license:expat)))

(define-public python-tempdir
  (package
    (name "python-tempdir")
    (version "0.7.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "tempdir" version))
       (sha256
        (base32
         "13msyyxqbicr111a294x7fsqbkl6a31fyrqflx3q7k547gnq15k8"))))
    (build-system python-build-system)
    (home-page "https://pypi.org/project/tempdir/")
    (arguments
     ;; the package has no tests
     '(#:tests? #f))
    (synopsis "Python library for managing temporary directories")
    (description
     "This library manages temporary directories that are automatically
deleted with all their contents when they are no longer needed.  It is
particularly convenient for use in tests.")
    (license license:expat)))

(define-public python2-tempdir
  (package-with-python2 python-tempdir))

(define-public python-activepapers
  (package
    (name "python-activepapers")
    (version "0.2.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ActivePapers.Py" version))
       (sha256
        (base32
         "12wkhjh90ffipjzv10swndp2xv9hd7xrxvg6v0n4n3i411pj4xb8"))))
    (build-system python-build-system)
    (arguments
     `(#:modules ((ice-9 ftw)
                  (srfi srfi-1)
                  (guix build utils)
                  (guix build python-build-system))

       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'delete-python2-code
           (lambda _
             (for-each delete-file
                       '("lib/activepapers/builtins2.py"
                         "lib/activepapers/standardlib2.py"
                         "lib/activepapers/utility2.py"))))
         (replace 'check
           (lambda _
             ;; Deactivate the test cases that download files
             (setenv "NO_NETWORK_ACCESS" "1")
             ;; For some strange reason, some tests fail if nosetests runs all
             ;; test modules in a single execution. They pass if each test
             ;; module is run individually.
             (for-each (lambda (filename)
                         (invoke "nosetests"
                                 (string-append "tests/" filename)))
                       (scandir "tests"
                                (lambda (filename)
                                  (string-suffix? ".py" filename)))))))))
    (native-inputs
     `(("python-tempdir" ,python-tempdir)
       ("python-nose" ,python-nose)))
    (propagated-inputs
     `(("python-h5py" ,python-h5py)))
    (home-page "http://www.activepapers.org/")
    (synopsis "Executable papers for scientific computing")
    (description
     "ActivePapers is a tool for working with executable papers, which
combine data, code, and documentation in single-file packages,
suitable for publication as supplementary material or on repositories
such as figshare or Zenodo.")
    (properties `((python2-variant . ,(delay python2-activepapers))))
    (license license:bsd-3)))

(define-public python2-activepapers
  (let ((base (package-with-python2
               (strip-python2-variant python-activepapers))))
    (package
      (inherit base)
      (arguments
       (substitute-keyword-arguments (package-arguments base)
         ((#:phases phases)
          `(modify-phases ,phases
             (delete 'delete-python2-code)
             (add-after 'unpack 'delete-python3-code
               (lambda _
                 (for-each delete-file
                           '("lib/activepapers/builtins3.py"
                             "lib/activepapers/standardlib3.py"
                             "lib/activepapers/utility3.py")))))))))))

(define-public python-semver
  (package
    (name "python-semver")
    (version "2.7.9")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "semver" version))
        (sha256
          (base32
            "0hhgqppchv59rqj0yzi1prdg2nfsywqmjsqy2rycyxm0hvxmbyqz"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-test-requirements
           (lambda _
             (substitute* "setup.py"
               ;; Our Python is new enough.
               (("'virtualenv<14\\.0\\.0'") "'virtualenv'"))
             #t)))))
    (native-inputs
     `(("python-tox" ,python-tox)
       ("python-virtualenv" ,python-virtualenv)))
    (home-page "https://github.com/k-bx/python-semver")
    (synopsis "Python helper for Semantic Versioning")
    (description "This package provides a Python library for
@url{Semantic Versioning, http://semver.org/}.")
    (license license:bsd-3)))

(define-public python2-semver
  (package-with-python2 python-semver))

(define-public python-pyro4
  (package
    (name "python-pyro4")
    (version "4.75")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Pyro4" version))
       (sha256
        (base32 "1dfpp36imddx19yv0kd28gk1l71ckhpqy6jd590wpm2680jw15rq"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-serpent" ,python-serpent)))
    (home-page "https://pyro4.readthedocs.io")
    (synopsis "Distributed object middleware for Python")
    (description
     "Pyro enables you to build applications in which objects can talk to each
other over the network.  You can just use normal Python method calls to call
objects on other machines, also known as remote procedure calls (RPC).")
    (license license:expat)))

(define-public python2-pyro
  (package
    (name "python2-pyro")
    (version "3.16")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Pyro" version))
       (file-name (string-append "Pyro-" version ".tar.gz"))
       (sha256
        (base32
         "0y75wzdqbjy565rpxaxscav4j8xg060sa90lnmb7aypgaf251v8v"))))
    (build-system python-build-system)
    (arguments
     ;; Pyro is not compatible with Python 3
     `(#:python ,python-2
       ;; Pyro has no test cases for automatic execution
       #:tests? #f))
    (home-page "http://pythonhosted.org/Pyro/")
    (synopsis "Distributed object manager for Python")
    (description "Pyro is a Distributed Object Technology system
written in Python that is designed to be easy to use.  It resembles
Java's Remote Method Invocation (RMI).  It has less similarity to CORBA,
which is a system and language independent Distributed Object Technology
and has much more to offer than Pyro or RMI.  Pyro 3.x is no
longer maintained.  New projects should use Pyro4 instead, which
is the new Pyro version that is actively developed.")
    (license license:expat)))

(define-public python2-scientific
  (package
    (name "python2-scientific")
    (version "2.9.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://bitbucket.org/khinsen/"
                           "scientificpython/downloads/ScientificPython-"
                           version ".tar.gz"))
       (file-name (string-append "ScientificPython-" version ".tar.gz"))
       (sha256
        (base32
         "0fc69zhlsn9d2jvbzyjl9ah53vj598h84nkq230c83ahfvgzx5y3"))))
    (build-system python-build-system)
    (inputs
     `(("netcdf" ,netcdf)))
    (propagated-inputs
     `(("python-numpy" ,python2-numpy-1.8)
       ("python-pyro" ,python2-pyro)))
    (arguments
     ;; ScientificPython is not compatible with Python 3
     `(#:python ,python-2
       #:tests? #f ; No test suite
       #:phases
       (modify-phases %standard-phases
         (replace 'build
           (lambda* (#:key inputs #:allow-other-keys)
             (invoke "python" "setup.py" "build"
                     (string-append "--netcdf_prefix="
                                    (assoc-ref inputs "netcdf"))))))))
    (home-page "https://bitbucket.org/khinsen/scientificpython")
    (synopsis "Python modules for scientific computing")
    (description "ScientificPython is a collection of Python modules that are
useful for scientific computing.  Most modules are rather general (Geometry,
physical units, automatic derivatives, ...) whereas others are more
domain-specific (e.g. netCDF and PDB support).  The library is currently
not actively maintained and works only with Python 2 and NumPy < 1.9.")
    (license license:cecill-c)))

(define-public python2-mmtk
  (package
    (name "python2-mmtk")
    (version "2.7.11")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://bitbucket.org/khinsen/"
                           "mmtk/downloads/MMTK-" version ".tar.gz"))
       (file-name (string-append "MMTK-" version ".tar.gz"))
       (sha256
        (base32
         "1d0nnjx4lwsvh8f99vv1r6gi50d93yba0adkz8b4zgv4za4c5862"))))
    (build-system python-build-system)
    (native-inputs
     `(("netcdf" ,netcdf)))
    (propagated-inputs
     `(("python-scientific" ,python2-scientific)
       ("python-tkinter" ,python-2 "tk")))
    (arguments
     `(#:python ,python-2
       #:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-before 'build 'includes-from-scientific
           (lambda* (#:key inputs #:allow-other-keys)
             (mkdir-p "Include/Scientific")
             (copy-recursively
                     (string-append
                      (assoc-ref inputs "python-scientific")
                      "/include/python2.7/Scientific")
                     "Include/Scientific"))))))
    (home-page "http://dirac.cnrs-orleans.fr/MMTK")
    (synopsis "Python library for molecular simulation")
    (description "MMTK is a library for molecular simulations with an emphasis
on biomolecules.  It provides widely used methods such as Molecular Dynamics
and normal mode analysis, but also basic routines for implementing new methods
for simulation and analysis.  The library is currently not actively maintained
and works only with Python 2 and NumPy < 1.9.")
    (license license:cecill-c)))

(define-public python-phonenumbers
  (package
    (name "python-phonenumbers")
    (version "8.9.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "phonenumbers" version))
       (sha256
        (base32
         "03fmrgb4r8x3ykmddjs9i3zhs703in8smikj3a6447blqpimwyh1"))))
    (build-system python-build-system)
    (home-page
     "https://github.com/daviddrysdale/python-phonenumbers")
    (synopsis
     "Python library for dealing with international phone numbers")
    (description
     "This package provides a Python port of Google's libphonenumber library.")
    (license license:asl2.0)))

(define-public python2-phonenumbers
  (package-with-python2 python-phonenumbers))

(define-public python-send2trash
  (package
    (name "python-send2trash")
    (version "1.5.0")
    (source
     (origin (method git-fetch)
             ;; Source tarball on PyPI doesn't include tests.
             (uri (git-reference
                   (url "https://github.com/hsoft/send2trash.git")
                   (commit version)))
             (file-name (git-file-name name version))
             (sha256
              (base32
               "1c76zldhw2ay7q7r00nnzcampjz9lkqfcbzqpm0iqp5i6bmmv30v"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'pre-check
           (lambda _
             (mkdir-p "/tmp/foo")
             (setenv "HOME" "/tmp/foo")
             #t)))))
    (home-page "https://github.com/hsoft/send2trash")
    (synopsis "Send files to the user's @file{~/Trash} directory")
    (description "This package provides a Python library to send files to the
user's @file{~/Trash} directory.")
    (properties `((python2-variant . ,(delay python2-send2trash))))
    (license license:bsd-3)))

(define-public python2-send2trash
  (package
    (inherit (package-with-python2 (strip-python2-variant python-send2trash)))
    (arguments
     (substitute-keyword-arguments (package-arguments python-send2trash)
       ((#:phases phases)
        `(modify-phases ,phases
           (add-before 'check 'setenv
             (lambda _
               (setenv "PYTHONPATH"
                       (string-append (getcwd) ":" (getenv "PYTHONPATH")))
               #t))))))))

(define-public python-yapf
  (package
    (name "python-yapf")
    (version "0.24.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "yapf" version))
       (sha256
        (base32
         "0anwby0ydmyzcsgjc5dn1ryddwvii4dq61vck447q0n96npnzfyf"))))
    (build-system python-build-system)
    (home-page "https://github.com/google/yapf")
    (synopsis "Formatter for Python code")
    (description "YAPF is a formatter for Python code.  It's based off of
@dfn{clang-format}, developed by Daniel Jasper.  In essence, the algorithm
takes the code and reformats it to the best formatting that conforms to the
style guide, even if the original code didn't violate the style guide.")
    (license license:asl2.0)))

(define-public python2-yapf
  (package-with-python2 python-yapf))

(define-public python-gyp
  (let ((commit "5e2b3ddde7cda5eb6bc09a5546a76b00e49d888f")
        (revision "0"))
    (package
      (name "python-gyp")
      ;; Google does not release versions,
      ;; based on second most recent commit date.
      (version (git-version "0.0.0" revision commit))
      (source
       (origin
         ;; Google does not release tarballs,
         ;; git checkout is needed.
         (method git-fetch)
         (uri (git-reference
               (url "https://chromium.googlesource.com/external/gyp")
               (commit commit)))
         (file-name (git-file-name name version))
         (sha256
          (base32
           "0fr7nxcrk292djmxzpcjaphnsd123k31gp8jnd91vwknhq6snmv9"))))
      (build-system python-build-system)
      (home-page "https://gyp.gsrc.io/")
      (synopsis "GYP is a Meta-Build system")
      (description
       "GYP builds build systems for large, cross platform applications.
It can be used to generate XCode projects, Visual Studio projects, Ninja build
files, and Makefiles.")
      (license license:bsd-3))))

(define-public python2-gyp
  (package-with-python2 python-gyp))

(define-public python-whatever
  (package
    (name "python-whatever")
    (version "0.5")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/Suor/whatever/archive/" version
                           ".tar.gz"))
       (sha256
        (base32
         "1iqvnaf0zpc6b4rvbqq4xy45mszcscyzpzknv8wg6j84pbp22sap"))
       (file-name (string-append name "-" version ".tar.gz"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
        (replace 'check
          (lambda _
            (invoke "py.test"))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "http://github.com/Suor/whatever")
    (synopsis "Make anonymous functions by partial application of operators")
    (description "@code{whatever} provides an easy way to make anonymous
functions by partial application of operators.")
    (license license:bsd-3)))

(define-public python2-whatever
  (package-with-python2 python-whatever))

(define-public python-funcy
  (package
    (name "python-funcy")
    (version "1.11")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/Suor/funcy.git")
             (commit version)))
       (sha256
        (base32 "1s98vkjnq3zq71737hn8xa15kssvmy1sfzsll3vrlv53902418mw"))
       (file-name (git-file-name name version))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (invoke "py.test"))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-whatever" ,python-whatever)))
    (home-page "http://github.com/Suor/funcy")
    (synopsis "Functional tools")
    (description "@code{funcy} is a library that provides functional tools.
Examples are:
@enumerate
@item merge - Merges collections of the same type
@item walk - Type-preserving map
@item select - Selects a part of a collection
@item take - Takes the first n items of a collection
@item first - Takes the first item of a collection
@item remove - Predicated-removes items of a collection
@item concat - Concatenates two collections
@item flatten - Flattens a collection with subcollections
@item distinct - Returns only distinct items
@item split - Predicated-splits a collection
@item split_at - Splits a collection at a given item
@item group_by - Groups items by group
@item pairwise - Pairs off adjacent items
@item partial - Partially-applies a function
@item curry - Curries a function
@item compose - Composes functions
@item complement - Complements a predicate
@item all_fn - \"all\" with predicate
@end enumerate")
    (license license:bsd-3)))

(define-public python2-funcy
  (package-with-python2 python-funcy))

(define-public python-isoweek
  (package
    (name "python-isoweek")
    (version "1.3.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "isoweek" version))
       (sha256
        (base32
         "1s7zsf0pab0l9gn6456qadnz5i5h90hafcjwnhx5mq23qjxggwvk"))))
    (build-system python-build-system)
    (home-page "https://github.com/gisle/isoweek")
    (synopsis "Objects representing a week")
    (description "The @code{isoweek} module provide the class Week that
implements the week definition of ISO 8601.  This standard also defines
a notation for identifying weeks; yyyyWww (where the W is a literal).
Week instances stringify to this form.")
    (license license:bsd-3)))

(define-public python2-isoweek
  (package-with-python2 python-isoweek))

(define-public python-tokenize-rt
  (package
    (name "python-tokenize-rt")
    (version "2.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "tokenize-rt" version))
       (sha256
        (base32
         "1yjvbz7rvrz31zjyax1cgy3xhf4wb3j18jwnj4bnl77ca4gliyiw"))))
    (build-system python-build-system)
    (home-page "https://github.com/asottile/tokenize-rt")
    (synopsis "Wrapper around the stdlib tokenize which roundtrips.")
    (description
     "This Python library is a wrapper around @code{tokenize} from the Python
standard library.  It provides two additional tokens @code{ESCAPED_NL} and
@code{UNIMPORTANT_WS}, and a @code{Token} data type.  Use @code{src_to_tokens}
and @code{tokens_to_src} to roundtrip.")
    (license license:expat)))

(define-public python-future-fstrings
  (package
    (name "python-future-fstrings")
    (version "0.4.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "future_fstrings" version))
       (sha256
        (base32
         "0ydxqz2dvns44g55p8ix2x18qkfk3aaz0m0dc70f3g6n8js35h47"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-tokenize-rt" ,python-tokenize-rt)))
    (home-page "https://github.com/asottile/future-fstrings")
    (synopsis "Backport of fstrings to Python < 3.6")
    (description
     "This package provides a UTF-8 compatible encoding
@code{future_fstrings}, which performs source manipulation.  It decodes the
source bytes using the UTF-8 encoding and then rewrites Python 3.6 style
@code{f} strings.")
    (license license:expat)))

(define-public python-typed-ast
  (package
    (name "python-typed-ast")
    (version "1.3.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "typed-ast" version))
       (sha256
        (base32
         "1m7pr6qpana3cvqwiw7mlvrgvmw27ch5mx1592572xhlki8g85ak"))))
    (build-system python-build-system)
    (arguments
     `(#:modules ((guix build utils)
                  (guix build python-build-system)
                  (ice-9 ftw)
                  (srfi srfi-1)
                  (srfi srfi-26))
       #:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (let ((cwd (getcwd)))
               (setenv "PYTHONPATH"
                       (string-append cwd "/build/"
                                      (find (cut string-prefix? "lib" <>)
                                            (scandir (string-append cwd "/build")))
                                      ":"
                                      (getenv "PYTHONPATH"))))
             (invoke "pytest")
             #t)))))
    (native-inputs `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/python/typed_ast")
    (synopsis "Fork of Python @code{ast} modules with type comment support")
    (description "This package provides a parser similar to the standard
@code{ast} library.  Unlike @code{ast}, the parsers in @code{typed_ast}
include PEP 484 type comments and are independent of the version of Python
under which they are run.  The @code{typed_ast} parsers produce the standard
Python AST (plus type comments), and are both fast and correct, as they are
based on the CPython 2.7 and 3.7 parsers.")
    ;; See the file "LICENSE" for the details.
    (license (list license:psfl
                   license:asl2.0
                   license:expat))))    ;ast27/Parser/spark.py

(define-public python-typing
  (package
    (name "python-typing")
    (version "3.6.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "typing" version))
       (sha256
        (base32
         "0ba9acs4awx15bf9v3nrs781msbd2nx826906nj6fqks2bvca9s0"))))
    (build-system python-build-system)
    (home-page "https://docs.python.org/3/library/typing.html")
    (synopsis "Type hints for Python")
    (description "This is a backport of the standard library @code{typing}
module to Python versions older than 3.5.  Typing defines a standard notation
for Python function and variable type annotations.  The notation can be used
for documenting code in a concise, standard format, and it has been designed
to also be used by static and runtime type checkers, static analyzers, IDEs
and other tools.")
    (license license:psfl)))

(define-public python2-typing
  (package-with-python2 python-typing))

(define-public python-typing-extensions
  (package
    (name "python-typing-extensions")
    (version "3.7.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "typing_extensions" version))
       (sha256
        (base32
         "0wfsv71pvkyf2na938l579jh0v3kzl6g744ijgnahcwd4d9x0b7v"))))
    (build-system python-build-system)
    (home-page
     "https://github.com/python/typing/blob/master/typing_extensions/README.rst")
    (synopsis "Experimental type hints for Python")
    (description
     "The typing_extensions module contains additional @code{typing} hints not
yet present in the of the @code{typing} standard library.
Included are implementations of:
@enumerate
@item ClassVar
@item ContextManager
@item Counter
@item DefaultDict
@item Deque
@item NewType
@item NoReturn
@item overload
@item Protocol
@item runtime
@item Text
@item Type
@item TYPE_CHECKING
@item AsyncGenerator
@end enumerate\n")
    (license license:psfl)))

(define-public bpython
  (package
    (name "bpython")
    (version "0.17.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "bpython" version))
       (sha256
        (base32
         "0bxhxi5zxdkrf8b4gwn0d363kdz3qnypjwhm1aydki53ph8ca1w9"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'remove-failing-test
           (lambda _
             ;; Remove failing test. FIXME: make it pass
             (delete-file "bpython/test/test_args.py")
             #t))
         (add-after 'wrap 'add-aliases
           ;; for symmetry to bpython2, add symlinks bypthon3, bpdb3, etc.
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (for-each
                (lambda (old new)
                  (symlink old (string-append out "/bin/" new)))
                '("bpython" "bpython-curses" "bpython-urwid" "bpdb")
                '("bpython3" "bpython3-curses" "bpython3-urwid" "bpdb3")))
             #t)))))
    (propagated-inputs
     `(("python-pygments" ,python-pygments)
       ("python-requests" ,python-requests)
       ("python-babel" ,python-babel) ; optional, for internationalization
       ("python-curtsies" ,python-curtsies) ; >= 0.1.18
       ("python-greenlet" ,python-greenlet)
       ("python-urwid" ,python-urwid) ; for bpython-urwid only
       ("python-six" ,python-six)))
    (native-inputs
     `(("python-sphinx" ,python-sphinx)
       ("python-mock" ,python-mock)))
    (home-page "https://bpython-interpreter.org/")
    (synopsis "Fancy interface to the Python interpreter")
    (description "Bpython is a fancy interface to the Python
interpreter. bpython's main features are

@enumerate
@item in-line syntax highlighting,
@item readline-like autocomplete with suggestions displayed as you type,
@item expected parameter list for any Python function,
@item \"rewind\" function to pop the last line of code from memory and
      re-evaluate,
@item send the code you've entered off to a pastebin,
@item save the code you've entered to a file, and
@item auto-indentation.
@end enumerate")
    (license license:expat)))

(define-public bpython2
  (let ((base (package-with-python2
               (strip-python2-variant bpython))))
    (package (inherit base)
      (name "bpython2")
      (arguments
       `(#:python ,python-2
         #:phases
         (modify-phases %standard-phases
         (add-after 'unpack 'remove-failing-test
           (lambda _
             ;; Remove failing test. FIXME: make it pass
             (delete-file "bpython/test/test_args.py")
             ;; Disable failing test-cases (renaming inhibits they are
             ;; discovered)
             (substitute* "bpython/test/test_curtsies_repl.py"
               (("^(\\s*def )(test_get_last_word_with_prev_line\\W)" _ a b)
                (string-append a "xxx_off_" b))
               (("^(\\s*def )(test_complex\\W)" _ a b)
                (string-append a "xxx_off_" b)))
             #t))
           (add-before 'build 'rename-scripts
             ;; rename the scripts to bypthon2, bpdb2, etc.
             (lambda _
               (substitute* "setup.py"
                 (("^(\\s+'bpdb)(\\s+=.*',?)\\s*?$" _ name rest)
                  (string-append name "2" rest "\n"))
                 (("^(\\s+'bpython)(-\\S+)?(\\s+=.*',?)\\s*?$" _ name sub rest)
                  (string-append name "2" (or sub "") rest "\n")))
               #t))))))))

(define-public python-pyinotify
  (package
    (name "python-pyinotify")
    (version "0.9.6")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pyinotify" version))
              (sha256
               (base32
                "1x3i9wmzw33fpkis203alygfnrkcmq9w1aydcm887jh6frfqm6cw"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f))          ;no tests
    (home-page "https://github.com/seb-m/pyinotify")
    (synopsis "Python library for monitoring inotify events")
    (description
     "@code{pyinotify} provides a Python interface for monitoring
file system events on Linux.")
    (license license:expat)))

(define-public python2-pyinotify
  (package-with-python2 python-pyinotify))

;; Ada parser uses this version.
(define-public python2-quex-0.67.3
  (package
    (name "python2-quex")
    (version "0.67.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/quex/HISTORY/"
                           (version-major+minor version)
                           "/quex-" version ".zip"))
       (sha256
        (base32
         "14gv8ll3ipqv4kyc2xiy891nrmjl4ic823zfyx8hassagyclyppw"))))
    (build-system python-build-system)
    (native-inputs
     `(("unzip" ,unzip)))
    (arguments
     `(#:python ,python-2
       #:tests? #f
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (delete 'build)
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (share/quex (string-append out "/share/quex"))
                    (bin (string-append out "/bin")))
               (copy-recursively "." share/quex)
               (mkdir-p bin)
               (symlink (string-append share/quex "/quex-exe.py")
                        (string-append bin "/quex"))
               #t))))))
    (native-search-paths
     (list (search-path-specification
            (variable "QUEX_PATH")
            (files '("share/quex")))))
    (home-page "http://quex.sourceforge.net/")
    (synopsis "Lexical analyzer generator in Python")
    (description "@code{quex} is a lexical analyzer generator in Python.")
    (license license:lgpl2.1+)))        ; Non-military

(define-public python2-quex
  (package (inherit python2-quex-0.67.3)
    (name "python2-quex")
    (version "0.68.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/quex/DOWNLOAD/quex-" version ".tar.gz"))
       (sha256
        (base32
         "0svc9nla3b9145d6b7fb9dizx412l3difzqw0ilh9lz52nsixw8j"))
       (file-name (string-append name "-" version ".tar.gz"))))))

(define-public python-more-itertools
  (package
    (name "python-more-itertools")
    (version "4.3.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "more-itertools" version))
       (sha256
        (base32
         "17h3na0rdh8xq30w4b9pizgkdxmm51896bxw600x84jflg9vaxn4"))))
    (build-system python-build-system)
    (arguments
     `(,@(if (any (cute string-prefix? <> (or (%current-system)
                                              (%current-target-system)))
                  '("armhf" "i686"))
        '(#:phases
          (modify-phases %standard-phases
          ;; This is required for 32-bit hardware.
          ;; TODO: Try to remove this when upgrading.
          (add-after 'unpack 'patch-test
            (lambda _
              (substitute* "more_itertools/tests/test_more.py"
                (("10 \\*\\* 10") "9 ** 9"))
              #t))))
        '())))
    (propagated-inputs
     `(("python-six" ,python-six-bootstrap)))
    (home-page "https://github.com/erikrose/more-itertools")
    (synopsis "More routines for operating on iterables, beyond itertools")
    (description "Python's built-in @code{itertools} module implements a
number of iterator building blocks inspired by constructs from APL, Haskell,
and SML.  @code{more-itertools} includes additional building blocks for
working with iterables.")
    (license license:expat)))

(define-public python2-more-itertools
  (package-with-python2 python-more-itertools))

(define-public python-latexcodec
  (package
    (name "python-latexcodec")
    (version "1.0.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "latexcodec" version))
       (sha256
        (base32 "0s4wdbg0w2l8pj3i0y4510i0s04p8nhxcsa2z41bjsv0k66npb81"))))
    (build-system python-build-system)
    (inputs
     `(("python-six" ,python-six)))
    (home-page "https://readthedocs.org/projects/latexcodec/")
    (synopsis "Work with LaTeX code in Python")
    (description "Lexer and codec to work with LaTeX code in Python.")
    (license license:expat)))

(define-public python-pybtex
  (package
    (name "python-pybtex")
    (version "0.21")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pybtex" version))
       (sha256
        (base32
         "00300j8dn5pxq4ndxmfmbmycg2znawkqs49val2x6jlmfiy6r2mg"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)))
    (inputs
     `(("python-latexcodec" ,python-latexcodec)
       ("python-pyyaml" ,python-pyyaml)
       ("python-six" ,python-six)))
    (arguments
     `(#:test-target "nosetests"))
    (home-page "https://pybtex.org/")
    (synopsis "BibTeX-compatible bibliography processor")
    (description "Pybtex is a BibTeX-compatible bibliography processor written
in Python.  You can simply type pybtex instead of bibtex.")
    (license license:expat)))

(define-public python-onetimepass
  (package
    (name "python-onetimepass")
    (version "1.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "onetimepass" version))
       (sha256
        (base32 "09vagxgbq78wvq4xbikmn2hpqqsa2i96kqsmphf7dqynfv0dlsd5"))))
    (build-system python-build-system)
    (propagated-inputs `(("python-six" ,python-six)))
    (home-page "https://github.com/tadeck/onetimepass/")
    (synopsis "One-time password library")
    (description "Python one-time password library for HMAC-based (HOTP) and
time-based (TOTP) passwords.")
    (license license:expat)))

(define-public python-parso
  (package
    (name "python-parso")
    (version "0.3.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "parso" version))
       (sha256
        (base32
         "18p89iwcm8mnf380f92g9w0bhx5km8wxp392vvjcq4y1ld1llw1m"))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (build-system python-build-system)
    (home-page "https://github.com/davidhalter/parso")
    (synopsis "Python Parser")
    (description "Parso is a Python parser that supports error recovery and
round-trip parsing for different Python versions (in multiple Python versions).
Parso is also able to list multiple syntax errors in your Python file.")
    (license license:expat)))

(define-public python2-parso
  (package-with-python2 python-parso))

(define-public python-async-generator
  (package
    (name "python-async-generator")
    (version "1.10")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "async_generator" version))
       (sha256
        (base32
         "0i11f6z6lix8ixi3vsk6s76zvvpmgrw6zjrcwjm0m4hjdh83vfvf"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/python-trio/async_generator")
    (synopsis "Async generators and context managers for Python 3.5+")
    (description "@code{async_generator} back-ports Python 3.6's native async
generators and Python 3.7's context managers into Python 3.5.")
    ;; Dual licensed.
    (license (list license:expat license:asl2.0))))

(define-public python-async-timeout
  (package
    (name "python-async-timeout")
    (version "3.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "async-timeout" version))
       (sha256
        (base32
         "0pscbyr840m7fyfc3r8zv9kgkwdcn9f78p7zsrczciwd09m82g0c"))))
    (build-system python-build-system)
    (home-page "https://github.com/aio-libs/async_timeout/")
    (synopsis "Timeout context manager for asyncio programs")
    (description "@code{async-timeout} provides a timeout timeout context
manager compatible with @code{asyncio}.")
    (license license:asl2.0)))

(define-public python-glob2
  (package
    (name "python-glob2")
    (version "0.6")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/miracle2k/python-glob2.git")
             (commit version)))
       (file-name (git-file-name name version))
       (sha256
        (base32 "1lm1xz3k3l0k1c5bcp9hlzmi3gp5j8dl1k3xhpiq5mnm0xq6n163"))))
    (build-system python-build-system)
    (home-page "https://github.com/miracle2k/python-glob2/")
    (synopsis "Extended Version of the python buildin glob module")
    (description "This is an extended version of the Python
@url{http://docs.python.org/library/glob.html, built-in glob module} which
adds:

@itemize
@item The ability to capture the text matched by glob patterns, and return
those matches alongside the file names.
@item A recursive @code{**} globbing syntax, akin for example to the
@code{globstar} option of Bash.
@item The ability to replace the file system functions used, in order to glob
on virtual file systems.
@item Compatible with Python 2 and Python 3 (tested with 3.3).
@end itemize

Glob2 currently based on the glob code from Python 3.3.1.")
    (license license:bsd-2)))

(define-public python2-glob2
  (package-with-python2 python-glob2))

(define-public python-gipc
  (package
    (name "python-gipc")
    (version "0.6.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "gipc" version ".zip"))
       (sha256
        (base32
         "0pd9by719qh882hqs6xpby61sn1x5h98hms5p2p8yqnycrf1s0h2"))))
    (build-system python-build-system)
    (native-inputs
     `(("unzip" ,unzip)))
    (propagated-inputs
     `(("python-gevent" ,python-gevent)))
    (home-page "http://gehrcke.de/gipc")
    (synopsis "Child process management in the context of gevent")
    (description "Usage of Python's multiprocessing package in a
gevent-powered application may raise problems.  With @code{gipc},
process-based child processes can safely be created anywhere within a
gevent-powered application.")
    (license license:expat)))

(define-public python2-gipc
  (package-with-python2 python-gipc))

(define-public python-fusepy
  (package
    (name "python-fusepy")
    (version "2.0.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "fusepy" version))
       (sha256
        (base32
         "0v5grm4zyf58hsplwsxfbihddw95lz9w8cy3rpzbyha287swgx8h"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'build 'set-library-file-name
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((fuse (assoc-ref inputs "fuse")))
               (substitute* "fuse.py"
                 (("find_library\\('fuse'\\)")
                  (string-append "'" fuse "/lib/libfuse.so'")))
               #t))))))
    (propagated-inputs
     `(("fuse" ,fuse)))
    (home-page "https://github.com/fusepy/fusepy")
    (synopsis "Simple ctypes bindings for FUSE")
    (description "Python module that provides a simple interface to FUSE and
MacFUSE.  The binding is created using the standard @code{ctypes} library.")
    (license license:isc)))

(define-public python2-fusepy
  (package-with-python2 python-fusepy))

(define-public python2-gdrivefs
  (package
    (name "python2-gdrivefs")
    (version "0.14.9")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "gdrivefs" version))
       (sha256
        (base32
         "0v9sp2cfg4ki3wagkwf3rnfpjhvgf845anz3757il9z95yvvcvb7"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         (add-before 'build 'patch-setup-py
           (lambda _
             ;; Update requirements from dependency==version
             ;; to dependency>=version
             (substitute* "gdrivefs/resources/requirements.txt"
               (("==") ">="))
             #t)))))
    (native-inputs
     `(("python2-gipc" ,python2-gipc)
       ("python2-gevent" ,python2-gevent)
       ("python2-greenlet" ,python2-greenlet)
       ("python2-httplib2" ,python2-httplib2)
       ("python2-uritemplate" ,python2-uritemplate)
       ("python2-oauth2client" ,python2-oauth2client)
       ("python2-six" ,python2-six)))
    (propagated-inputs
     `(("python2-dateutil" ,python2-dateutil)
       ("python2-fusepy" ,python2-fusepy)
       ("python2-google-api-client" ,python2-google-api-client)))
    (home-page "https://github.com/dsoprea/GDriveFS")
    (synopsis "Mount Google Drive as a local file system")
    (description "@code{gdrivefs} provides a FUSE wrapper for Google Drive
under Python 2.7.")
    (license license:gpl2)))

(define-public pybind11
  (package
    (name "pybind11")
    (version "2.2.4")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "https://github.com/pybind/pybind11.git")
                    (commit (string-append "v" version))))
              (sha256
               (base32
                "0pa79ymcasv8br5ifbx7878id5py2jpjac3i20cqxr6gs9l6ivlv"))
              (file-name (git-file-name name version))))
    (build-system cmake-build-system)
    (native-inputs
     `(("python" ,python)
       ("python-pytest" ,python-pytest)))
    (arguments
     `(#:test-target "check"))
    (home-page "https://github.com/pybind/pybind11/")
    (synopsis "Seamless operability between C++11 and Python")
    (description "pybind11 is a lightweight header-only library that exposes
C++ types in Python and vice versa, mainly to create Python bindings of
existing C++ code.  Its goals and syntax are similar to the excellent
Boost.Python library by David Abrahams: to minimize boilerplate code in
traditional extension modules by inferring type information using compile-time
introspection.")
    (license license:expat)))

(define-public python-fasteners
  (package
    (name "python-fasteners")
    (version "0.14.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "fasteners" version))
       (sha256
        (base32
         "063y20kx01ihbz2mziapmjxi2cd0dq48jzg587xdsdp07xvpcz22"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-monotonic" ,python-monotonic)
       ("python-six" ,python-six)
       ("python-testtools" ,python-testtools)))
    (home-page "https://github.com/harlowja/fasteners")
    (synopsis "Python package that provides useful locks")
    (description
     "This package provides a Python program that provides following locks:

@itemize
@item Locking decorator
@item Reader-writer locks
@item Inter-process locks
@item Generic helpers
@end itemize\n")
    (properties `((python2-variant . ,(delay python2-fasteners))))
    (license license:asl2.0)))

(define-public python2-fasteners
  (let ((base (package-with-python2 (strip-python2-variant python-fasteners))))
    (package
      (inherit base)
      (propagated-inputs
       `(("python2-futures" ,python2-futures)
         ,@(package-propagated-inputs base))))))

(define-public python-requests-file
  (package
    (name "python-requests-file")
    (version "1.4.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "requests-file" version))
       (sha256
        (base32
         "1yp2jaxg3v86pia0q512dg3hz6s9y5vzdivsgrba1kds05ial14g"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-requests" ,python-requests)
       ("python-six" ,python-six)))
    (home-page
     "https://github.com/dashea/requests-file")
    (synopsis "File transport adapter for Requests")
    (description
     "Requests-File is a transport adapter for use with the Requests Python
library to allow local file system access via @code{file://} URLs.")
    (license license:asl2.0)))

(define-public python2-requests-file
  (package-with-python2 python-requests-file))

(define-public python-tldextract
  (package
    (name "python-tldextract")
    (version "2.2.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "tldextract" version))
       (sha256
        (base32
         "1d5s8v6kpsgazyahflhji1cfdcf89rv7l7z55v774bhzvcjp2y99"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-responses" ,python-responses)))
    (propagated-inputs
     `(("python-idna" ,python-idna)
       ("python-requests" ,python-requests)
       ("python-requests-file" ,python-requests-file)))
    (home-page
     "https://github.com/john-kurkowski/tldextract")
    (synopsis
     "Separate the TLD from the registered domain and subdomains of a URL")
    (description
     "TLDExtract accurately separates the TLD from the registered domain and
subdomains of a URL, using the Public Suffix List.  By default, this includes
the public ICANN TLDs and their exceptions.  It can optionally support the
Public Suffix List's private domains as well.")
    (license license:bsd-3)))

(define-public python2-tldextract
  (package-with-python2 python-tldextract))

(define-public python-pynamecheap
  (package
    (name "python-pynamecheap")
    (version "0.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "PyNamecheap" version))
       (sha256
        (base32
         "0wkbwz208j8nfrsmzmclvxg22ymknn0mlz76wbdza9k2bx2zja6l"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-requests" ,python-requests)))
    (home-page
     "https://github.com/Bemmu/PyNamecheap")
    (synopsis
     "Namecheap API client in Python")
    (description
     "PyNamecheap is a Namecheap API client in Python.")
    (license license:expat)))

(define-public python2-pynamecheap
  (package-with-python2 python-pynamecheap))

(define-public python-dns-lexicon
  (package
    (name "python-dns-lexicon")
    (version "2.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "dns-lexicon" version))
       (sha256
        (base32
         "0jdn3ns71bsybr7njgsqr9xlxsqh7zh6phn4ld0liazqdn2l5f6m"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))                    ;requires internet access
    (propagated-inputs
     `(("python-future" ,python-future)
       ("python-pynamecheap" ,python-pynamecheap)
       ("python-requests" ,python-requests)
       ("python-tldextract" ,python-tldextract)
       ("python-urllib3" ,python-urllib3)))
    (home-page "https://github.com/AnalogJ/lexicon")
    (synopsis
     "Manipulate DNS records on various DNS providers")
    (description
     "Lexicon provides a way to manipulate DNS records on multiple DNS
providers in a standardized way.  It has a CLI but it can also be used as a
Python library.  It was designed to be used in automation, specifically with
Let's Encrypt.")
    (license license:expat)))

(define-public python2-dns-lexicon
  (package-with-python2 python-dns-lexicon))

(define-public python-commandlines
  (package
    (name "python-commandlines")
    (version "0.4.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "commandlines" version))
       (sha256
        (base32
         "0r7xcr0knv02p4mswa2bng61nn8nbhhrs6kvdnb9bb3hhjvm1dl6"))))
    (build-system python-build-system)
    (home-page "https://github.com/chrissimpkins/commandlines")
    (synopsis "Command line argument to object parsing library")
    (description
     "@code{Commandlines} is a Python library for command line application
development that supports command line argument parsing, command string
validation testing and application logic.")
    (license license:expat)))

;; Make sure to upgrade python-llvmlite in (gnu packages llvm) together with
;; python-numba.  They have a very unflexible relationship.
(define-public python-numba
  (package
    (name "python-numba")
    (version "0.42.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "numba" version))
       (sha256
        (base32
         "03rqdfx0512lcri2bcpngx5k3jwfbqnanqj3n19c7d6h6hqxvq9x"))))
    (build-system python-build-system)
    (arguments
     `(#:modules ((guix build utils)
                  (guix build python-build-system)
                  (ice-9 ftw)
                  (srfi srfi-1)
                  (srfi srfi-26))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'disable-proprietary-features
           (lambda _
             (setenv "NUMBA_DISABLE_HSA" "1")
             (setenv "NUMBA_DISABLE_CUDA" "1")
             #t))
         (add-after 'unpack 'remove-failing-tests
           (lambda _
             ;; FIXME: these tests fail for unknown reasons:
             ;; test_non_writable_pycache, test_non_creatable_pycache, and
             ;; test_frozen (all in numba.tests.test_dispatcher.TestCache).
             (substitute* "numba/tests/test_dispatcher.py"
               (("def test(_non_writable_pycache)" _ m)
                (string-append "def guix_skip" m))
               (("def test(_non_creatable_pycache)" _ m)
                (string-append "def guix_skip" m))
               (("def test(_frozen)" _ m)
                (string-append "def guix_skip" m)))

             ;; These tests fail because we don't run the tests from the build
             ;; directory: test_setup_py_distutils, test_setup_py_setuptools
             ;; They ar in numba.tests.test_pycc.TestDistutilsSupport.
             (substitute* "numba/tests/test_pycc.py"
               (("def test(_setup_py_distutils|_setup_py_setuptools)" _ m)
                (string-append "def guix_skip" m)))
             #t))
         (replace 'check
           (lambda _
             (let ((cwd (getcwd)))
               (setenv "PYTHONPATH"
                       (string-append cwd "/build/"
                                      (find (cut string-prefix? "lib" <>)
                                            (scandir (string-append cwd "/build")))
                                      ":"
                                      (getenv "PYTHONPATH")))
               ;; Something is wrong with the PYTHONPATH when running the
               ;; tests from the build directory, as it complains about not being
               ;; able to import certain modules.
               (with-directory-excursion "/tmp"
                 (invoke "python3" "-m" "numba.runtests" "-v" "-m")))
             #t)))))
    (propagated-inputs
     `(("python-llvmlite" ,python-llvmlite)
       ("python-numpy" ,python-numpy)
       ("python-singledispatch" ,python-singledispatch)))
    ;; Needed for tests.
    (inputs
     `(("python-jinja2" ,python-jinja2)
       ("python-pygments" ,python-pygments)))
    (home-page "https://numba.pydata.org")
    (synopsis "Compile Python code using LLVM")
    (description "Numba gives you the power to speed up your applications with
high performance functions written directly in Python.  With a few
annotations, array-oriented and math-heavy Python code can be just-in-time
compiled to native machine instructions, similar in performance to C, C++ and
Fortran, without having to switch languages or Python interpreters.

Numba works by generating optimized machine code using the LLVM compiler
infrastructure at import time, runtime, or statically (using the included pycc
tool).")
    (license license:bsd-3)))

(define-public python-anndata
  (package
    (name "python-anndata")
    (version "0.6.18")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "anndata" version))
       (sha256
        (base32
         "03x83yjaccbqszj7x4fwwmpil0ai59yx64d1zmf2691za3j03w73"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-h5py" ,python-h5py)
       ("python-natsort" ,python-natsort)
       ("python-pandas" ,python-pandas)
       ("python-scipy" ,python-scipy)))
    (home-page "https://github.com/theislab/anndata")
    (synopsis "Annotated data for data analysis pipelines")
    (description "Anndata is a package for simple (functional) high-level APIs
for data analysis pipelines.  In this context, it provides an efficient,
scalable way of keeping track of data together with learned annotations and
reduces the code overhead typically encountered when using a mostly
object-oriented library such as @code{scikit-learn}.")
    (license license:bsd-3)))

(define-public python-dill
  (package
    (name "python-dill")
    (version "0.2.9")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "dill" version))
       (sha256
        (base32 "0vwqyi6hyz2r29zydc78dqymkbc5y7gia16xcdh215cikxph9mpn"))))
    (build-system python-build-system)
    ;; FIXME: The check phase fails with "don't know how to make test from: …".
    (arguments '(#:tests? #f))
    (home-page "https://pypi.org/project/dill")
    (synopsis "Serialize all of Python")
    (description "Dill extends Python's @code{pickle} module for serializing
and de-serializing Python objects to the majority of the built-in Python
types.  Dill provides the user the same interface as the @code{pickle} module,
and also includes some additional features.  In addition to pickling Python
objects, @code{dill} provides the ability to save the state of an interpreter
session in a single command.  Hence, it would be feasible to save a
interpreter session, close the interpreter, ship the pickled file to another
computer, open a new interpreter, unpickle the session and thus continue from
the saved state of the original interpreter session.")
    (license license:bsd-3)))

(define-public python-multiprocess
  (package
    (name "python-multiprocess")
    (version "0.70.6.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "multiprocess" version))
       (sha256
        (base32
         "1ip5caz67b3q0553mr8gm8xwsb8x500jn8ml0gihgyfy52m2ypcq"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-dill" ,python-dill)))
    (home-page "https://pypi.org/project/multiprocess")
    (synopsis "Multiprocessing and multithreading in Python")
    (description
     "This package is a fork of the multiprocessing Python package, a package
which supports the spawning of processes using the API of the standard
library's @code{threading} module.")
    (license license:bsd-3)))

(define-public python-toolz
  (package
    (name "python-toolz")
    (version "0.9.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "toolz" version))
       (sha256
        (base32
         "1j9i7fdjnx9dz35fdj5gvgxx6585ja9sxgaiv65if77nlxz0m7wj"))))
    (build-system python-build-system)
    ;; FIXME: tests cannot be computed: "Can't perform this operation for
    ;; unregistered loader type"
    (arguments '(#:tests? #f))
    (home-page "https://github.com/pytoolz/toolz/")
    (synopsis "List processing tools and functional utilities")
    (description
     "This package provides a set of utility functions for iterators,
functions, and dictionaries.")
    (license license:bsd-3)))

(define-public python2-toolz
  (package-with-python2 python-toolz))

(define-public python-cytoolz
  (package
    (name "python-cytoolz")
    (version "0.9.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "cytoolz" version))
       (sha256
        (base32
         "1r80p88hm3f3r4zpixzr047y5hw4bzy41m4xywnhycda83x0dk44"))))
    (build-system python-build-system)
    ;; FIXME: tests fail with "module 'cytoolz.curried' has no attribute
    ;; 'exceptions'"
    (arguments '(#:tests? #f))
    (propagated-inputs
     `(("python-toolz" ,python-toolz)))
    (native-inputs
     `(("python-cython" ,python-cython)))
    (home-page "https://github.com/pytoolz/cytoolz")
    (synopsis "High performance functional utilities")
    (description
     "The cytoolz package implements the same API as provided by toolz.  The
main differences are that @code{cytoolz} is faster and cytoolz offers a C API
that is accessible to other projects developed in Cython.")
    (license license:bsd-3)))

(define-public python-sortedcontainers
  (package
    (name "python-sortedcontainers")
    (version "2.0.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "sortedcontainers" version))
       (sha256
        (base32
         "10hrk2k0hbf9x78vd3f0lj277m1yzfhzzxr0hja718liwb398wk0"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-tox" ,python-tox)))
    (home-page "http://www.grantjenks.com/docs/sortedcontainers/")
    (synopsis "Sorted List, Sorted Dict, Sorted Set")
    (description
     "This package provides a sorted collections library, written in
pure-Python.")
    (license license:asl2.0)))

(define-public python-cloudpickle
  (package
    (name "python-cloudpickle")
    (version "0.6.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "cloudpickle" version))
       (sha256
        (base32
         "1wdw89mlm7fqa3fm3ymskx05jrys66n8m1z1a8s0mss0799ahsgi"))))
    (build-system python-build-system)
    ;; FIXME: there are 5 errors in 122 tests:
    ;; ERROR: test_function_pickle_compat_0_4_0 (tests.cloudpickle_test.CloudPickleTest)
    ;; ERROR: test_function_pickle_compat_0_4_1 (tests.cloudpickle_test.CloudPickleTest)
    ;; ERROR: test_function_pickle_compat_0_4_0 (tests.cloudpickle_test.Protocol2CloudPickleTest)
    ;; ERROR: test_function_pickle_compat_0_4_1 (tests.cloudpickle_test.Protocol2CloudPickleTest)
    ;; ERROR: test_temp_file (tests.cloudpickle_file_test.CloudPickleFileTests)
    ;; TypeError: cannot serialize '_io.BufferedRandom' object
    (arguments '(#:tests? #f))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-mock" ,python-mock)
       ("python-tornado" ,python-tornado)))
    (home-page "https://github.com/cloudpipe/cloudpickle")
    (synopsis "Extended pickling support for Python objects")
    (description
     "Cloudpickle makes it possible to serialize Python constructs not
supported by the default pickle module from the Python standard library.  It
is especially useful for cluster computing where Python expressions are
shipped over the network to execute on remote hosts, possibly close to the
data.")
    (license license:bsd-3)))

(define-public python2-cloudpickle
  (package-with-python2 python-cloudpickle))

(define-public python-locket
  (package
    (name "python-locket")
    (version "0.2.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "locket" version))
       (sha256
        (base32
         "1d4z2zngrpqkrfhnd4yhysh66kjn4mblys2l06sh5dix2p0n7vhz"))))
    (build-system python-build-system)
    (home-page "https://github.com/mwilliamson/locket.py")
    (synopsis "File-based locks for Python")
    (description
     "Locket implements a lock that can be used by multiple processes provided
they use the same path.")
    (license license:bsd-2)))

(define-public python2-locket
  (package-with-python2 python-locket))

(define-public python-blosc
  (package
    (name "python-blosc")
    (version "1.5.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "blosc" version))
       (sha256
        (base32
         "1cm91c6r431yla2mbs4895bgiianjf30dfz14vvv99dslygd65jw"))))
    (build-system python-build-system)
    ;; FIXME: all tests pass, but then this error is printed:
    ;; TypeError: calling <function run at 0x7ffff2568d90> returned None, not a test
    (arguments '(#:tests? #f))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)))
    (home-page "https://github.com/blosc/python-blosc")
    (synopsis "Python wrapper for the Blosc data compressor library")
    (description "Blosc is a high performance compressor optimized for binary
data.  It has been designed to transmit data to the processor cache faster
than the traditional, non-compressed, direct memory fetch approach via a
@code{memcpy()} system call.

Blosc works well for compressing numerical arrays that contains data with
relatively low entropy, like sparse data, time series, grids with
regular-spaced values, etc.

This Python package wraps the Blosc library.")
    (license license:bsd-3)))

(define-public python2-blosc
  (package-with-python2 python-blosc))

(define-public python-partd
  (package
    (name "python-partd")
    (version "0.3.9")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "partd" version))
       (sha256
        (base32
         "0sz6rwlnl4fqq220pyz863cnv0gjdxl4m7lscl71ishl5z0xkmhz"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-blosc" ,python-blosc)
       ("python-locket" ,python-locket)
       ("python-numpy" ,python-numpy)
       ("python-pandas" ,python-pandas)
       ("python-pyzmq" ,python-pyzmq)
       ("python-toolz" ,python-toolz)))
    (home-page "https://github.com/dask/partd/")
    (synopsis "Appendable key-value storage")
    (description "Partd stores key-value pairs.  Values are raw bytes.  We
append on old values.  Partd excels at shuffling operations.")
    (license license:bsd-3)))

(define-public python2-partd
  (package-with-python2 python-partd))

(define-public python-dask
  (package
    (name "python-dask")
    (version "1.2.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "dask" version))
       (sha256
        (base32 "0b29gvf96gmp20wicly3v3mhyc93zbm3mdv935fka6x0wax7cy2y"))))
    (build-system python-build-system)
    ;; A single test out of 5000+ fails.  This test is marked as xfail when
    ;; pytest-xdist is used.
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'disable-broken-test
           (lambda _
             (substitute* "dask/tests/test_threaded.py"
               (("def test_interrupt\\(\\)" m)
                (string-append "@pytest.mark.skip(reason=\"Disabled by Guix\")\n"
                               m)))
             (when (which "python2")
               ;; This test fails with recent Pandas:
               ;; <https://github.com/dask/dask/issues/3794>.
               (substitute* "dask/dataframe/tests/test_dataframe.py"
                 (("def test_info\\(\\)" m)
                  (string-append "@pytest.mark.skip(reason=\"Disabled by Guix\")\n"
                                 m))))
             #t))
         (replace 'check
           (lambda _ (invoke "pytest" "-vv"))))))
    (propagated-inputs
     `(("python-cloudpickle" ,python-cloudpickle)
       ("python-numpy" ,python-numpy)
       ("python-pandas" ,python-pandas)
       ("python-partd" ,python-partd)
       ("python-toolz" ,python-toolz)
       ("python-pyyaml" ,python-pyyaml)))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)))
    (home-page "https://github.com/dask/dask/")
    (synopsis "Parallel computing with task scheduling")
    (description
     "Dask is a flexible parallel computing library for analytics.  It
consists of two components: dynamic task scheduling optimized for computation,
and large data collections like parallel arrays, dataframes, and lists that
extend common interfaces like NumPy, Pandas, or Python iterators to
larger-than-memory or distributed environments.  These parallel collections
run on top of the dynamic task schedulers. ")
    (license license:bsd-3)))

(define-public python2-dask
  (package-with-python2 python-dask))

(define-public python-ilinkedlist
  (package
    (name "python-ilinkedlist")
    (version "0.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ilinkedlist" version))
       (sha256
        (base32
         "0nrw4sr3afldrp7073hvc0rgdz282s0l819jdmj1i6nn05v33h0l"))))
    (build-system python-build-system)
    (native-inputs `(("python-pytest" ,python-pytest)))
    (inputs `(("python" ,python)))
    (home-page "https://github.com/luther9/ilinkedlist-py")
    (synopsis "Immutable linked list library")
    (description
     "This is a implementation of immutable linked lists for Python.  It
contains @code{nil} (the empty linked list) and a @code{Pair} class for nodes.
Since a linked list is treated as immutable, it is hashable, and its length
can be retrieved in constant time.  Some of the terminology is inspired by
LISP.  It is possible to create an improper list by creating a @code{Pair}
with a non-list @code{cdr}.")
    (license license:gpl3+)))

(define-public python-readlike
  (package
    (name "python-readlike")
    (version "0.1.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "readlike" version))
       (sha256
        (base32 "027w8fvi50ksl57q0a7kb5zvmq8jxaawnviib1jdqw0p3igvm1j4"))))
    (build-system python-build-system)
    (home-page "https://github.com/jangler/readlike")
    (synopsis "GNU Readline-like line editing module")
    (description
     "This Python module provides line editing functions similar to the default
Emacs-style ones of GNU Readline.  Unlike the Python standard library's
@code{readline} package, this one allows access to those capabilties in settings
outside of a standard command-line interface.  It is especially well-suited to
interfacing with Urwid, due to a shared syntax for describing key inputs.

Currently, all stateless Readline commands are implemented.  Yanking and history
are not supported.")
    (license license:expat)))

(define-public python2-readlike
  (package-with-python2 python-readlike))

(define-public python-reparser
  (package
    (name "python-reparser")
    (version "1.4.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ReParser" version))
       (sha256
        (base32 "0nniqb69xr0fv7ydlmrr877wyyjb61nlayka7xr08vlxl9caz776"))))
    (build-system python-build-system)
    (home-page "https://github.com/xmikos/reparser")
    (synopsis "Simple lexer/parser for inline markup based on regular expressions")
    (description
     "This Python library provides a simple lexer/parser for inline markup based
on regular expressions.")
    (license license:expat)))

(define-public python2-reparser
  (let ((reparser (package-with-python2
                   (strip-python2-variant python-reparser))))
    (package (inherit reparser)
             (propagated-inputs
              `(("python2-enum34" ,python2-enum34)
                ,@(package-propagated-inputs reparser))))))

(define-public python-precis-i18n
  (package
    (name "python-precis-i18n")
    (version "1.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "precis_i18n" version))
       (sha256
        (base32
         "0gjhvwd8aifx94rl1ag08vlmndyx2q3fkyqb0c4i46x3p2bc2yi2"))))
    (build-system python-build-system)
    (home-page "https://github.com/byllyfish/precis_i18n")
    (synopsis "Implementation of the PRECIS framework")
    (description
     "This module implements the PRECIS Framework as described in RFC 8264,
RFC 8265 and RFC 8266.")
    (license license:expat)))

(define-public python-absl-py
  (package
    (name "python-absl-py")
    (version "0.6.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "absl-py" version))
       (sha256
        (base32
         "1mp9lk0b2qa37b7y6ak4lvf6ifw2ylyy6bkf9ik77md3j4xrwlc7"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)))
    (home-page "https://github.com/abseil/abseil-py")
    (synopsis "Abseil Python common libraries")
    (description
     "This package provides the Abseil Python Common Libraries, a collection
of Python libraries for building Python applications.")
    (license license:asl2.0)))

(define-public python-astor
  (package
    (name "python-astor")
    (version "0.7.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "astor" version))
       (sha256
        (base32
         "13gv6f2xz9i564byp21gcpc0l3w4cs23k1wbcam8kky2ls3hvhwm"))))
    (build-system python-build-system)
    ;; FIXME: There are two errors and two test failures.
    (arguments `(#:tests? #f))
    (home-page "https://github.com/berkerpeksag/astor")
    (synopsis "Read and write Python ASTs")
    (description "Astor is designed to allow easy manipulation of Python
source via the Abstract Syntax Tree.")
    (license license:bsd-3)))

(define-public python2-astor
  (package-with-python2 python-astor))

(define-public python-grpcio
  (package
    (name "python-grpcio")
    (version "1.17.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "grpcio" version))
       (sha256
        (base32
         "0qb9y6j83nxa6d4kc60i8yfgdm7a8ms7b54kncjzf5y7nsxp8rzx"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)))
    (home-page "https://grpc.io")
    (synopsis "HTTP/2-based RPC framework")
    (description "This package provides a Python library for communicating
with the HTTP/2-based RPC framework gRPC.")
    (license license:asl2.0)))

(define-public python-astunparse
  (package
    (name "python-astunparse")
    (version "1.6.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "astunparse" version))
       (sha256
        (base32 "0rzbc44xcvzjhhiy7wac96mgal5mcjz1mfq8rmvgswskf4kf9cys"))))
    (build-system python-build-system)
    (arguments '(#:tests? #f))          ; there are none
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-wheel" ,python-wheel)))
    (home-page "https://github.com/simonpercivall/astunparse")
    (synopsis "AST unparser for Python")
    (description "This package provides an AST unparser for Python.  It is a
factored out version of @code{unparse} found in the Python source
distribution.")
    (license license:bsd-3)))

(define-public python-gast
  (package
    (name "python-gast")
    (version "0.2.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "gast" version))
       (sha256
        (base32 "1w5dzdb3gpcfmd2s0b93d8gff40a1s41rv31458z14inb3s9v4zy"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-astunparse" ,python-astunparse)))
    (home-page "https://pypi.org/project/gast/")
    (synopsis "Generic Python AST that abstracts the underlying Python version")
    (description
     "GAST provides a compatibility layer between the AST of various Python
versions, as produced by @code{ast.parse} from the standard @code{ast}
module.")
    (license license:bsd-3)))

(define-public python-wikidata
  (package
    (name "python-wikidata")
    (version "0.6.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Wikidata" version))
       (sha256
        (base32
         "08nlnydddfp1jj0cdmshvld1irzngbp3dij928wqsg9ziklm6mw9"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-babel" ,python-babel)))
    (home-page "https://github.com/dahlia/wikidata")
    (synopsis "Wikidata client library")
    (description
     "This package provides a Python interface to
@url{https://www.wikidata.org/, Wikidata}.")
    (properties '((upstream-name . "Wikidata")))
    (license license:gpl3+)))

(define-public python-doctest-ignore-unicode
  (package
    (name "python-doctest-ignore-unicode")
    (version "0.1.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "doctest-ignore-unicode" version))
       (sha256
        (base32
         "1m9aa4qnyj21lbq4sbvmv1vcz7zksss4rz37ddf2hxv4hk8b547w"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)))
    (home-page "https://github.com/gnublade/doctest-ignore-unicode")
    (synopsis "Ignore Unicode literal prefixes in doctests")
    (description
     "This package adds support for a flag to ignore Unicode literal prefixes
in doctests.")
    (license license:asl2.0)))

(define-public python-attr
  (package
    (name "python-attr")
    (version "0.3.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "attr" version))
       (sha256
        (base32
         "0pbpskvxp5hzdvcaf766ljwpckshir8sf7z6jqji6zyib20594ch"))))
    (build-system python-build-system)
    (home-page "https://github.com/denis-ryzhkov/attr")
    (synopsis "Decorator for attributes of target function or class")
    (description "Simple decorator to set attributes of target function or
class in a @acronym{DRY, Don't Repeat Yourself} way.")
    (license license:expat)))

(define-public python-construct
  (package
    (name "python-construct")
    (version "2.9.45")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "construct" version))
       (sha256
        (base32
         "130iy05awzigm2xah2yvlmb08mac5bi4gzr5m3g7k1krs3ps0w92"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f)) ; No tests exist.
    (propagated-inputs
     `(("python-extras" ,python-extras)
       ("python-arrow" ,python-arrow)
       ("python-numpy" ,python-numpy)
       ("python-ruamel.yaml" ,python-ruamel.yaml)))
    (home-page "http://construct.readthedocs.io")
    (synopsis "Declarative and symmetrical parser and builder for binary data")
    (description
     "This package provides both simple, atomic constructs (such as
integers of various sizes), as well as composite ones which allow you
form hierarchical and sequential structures of increasing complexity.
It features bit and byte granularity, easy debugging and testing, an
easy-to-extend subclass system, and lots of primitive constructs to
make your work easier.")
    (license license:expat)))

(define-public python-humanize
  (package
    (name "python-humanize")
    (version "0.5.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "humanize" version))
        (sha256
         (base32
          "06dvhm3k8lf2rayn1gxbd46y0fy1db26m3h9vrq7rb1ib08mfgx4"))))
    (arguments
     '(#:tests? #f)) ; tests not in pypi archive
    (build-system python-build-system)
    (home-page "https://github.com/jmoiron/humanize")
    (synopsis "Print numerical information in a human-readable form")
    (description "This package provides a Python module that displays numbers
and dates in \"human readable\" forms.  For example, it would display
\"12345591313\" as \"12.3 billion\".")
    (license license:expat)))

(define-public python-txaio
  (package
    (name "python-txaio")
    (version "18.8.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "txaio" version))
        (sha256
         (base32
          "1zmpdph6zddgrnkkcykh6qk5s46l7s5mzfqrh82m4b5iffn61qv7"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-twisted" ,python-twisted)
       ("python-six" ,python-six)))
    (home-page "https://github.com/crossbario/txaio")
    (synopsis "Compatibility layer between Python asyncio and Twisted")
    (description "Txaio provides a compatibility layer between the Python
@code{asyncio} module and @code{Twisted}.")
    (license license:expat)))

(define-public python-toolshed
  (package
    (name "python-toolshed")
    (version "0.4.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "toolshed" version))
       (sha256
        (base32
         "14zvz51gzf9i1i3d1sj363ba4rksl6lcf4lz1arl8hpqgcbir8r3"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)))
    (home-page "https://github.com/brentp/toolshed/")
    (synopsis "Collection of modules and functions for working with data")
    (description "This is a collection of well-tested, simple modules and
functions that aim to reduce boilerplate when working with data.")
    (license license:bsd-2)))

(define-public python-annoy
  (package
    (name "python-annoy")
    (version "1.15.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "annoy" version))
       (sha256
        (base32
         "1rxn6snn0r32r07g45hdjhh8aa1xzx6fjrm8g62d8vzp46z7rzrp"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)))
    (home-page "https://github.com/spotify/annoy/")
    (synopsis "Approximate nearest neighbors library")
    (description
     "Annoy is a C++ library with Python bindings to search for points in
space that are close to a given query point.  It also creates large read-only
file-based data structures that are @code{mmap}ped into memory so that many
processes may share the same data.")
    (license license:asl2.0)))

(define-public python-pylzma
  (package
    (name "python-pylzma")
    (version "0.5.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pylzma" version))
        (sha256
          (base32
            "074anvhyjgsv2iby2ql1ixfvjgmhnvcwjbdz8gk70xzkzcm1fx5q"))))
    (build-system python-build-system)
    (home-page "http://www.joachim-bauch.de/projects/pylzma/")
    (synopsis "Python bindings for the LZMA library by Igor Pavlov.")
    (description "This package provides Python bindings for the LZMA library
by Igor Pavlov.")
    (license license:lgpl2.1+)))

(define-public python2-pylzma
  (package-with-python2 python-pylzma))

(define-public python2-zeroconf
  (package
    (name "python2-zeroconf")

    ;; This is the last version that supports Python 2.x.
    (version "0.19.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "zeroconf" version))
       (sha256
        (base32
         "0ykzg730n915qbrq9bn5pn06bv6rb5zawal4sqjyfnjjm66snkj3"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-requires
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "setup.py"
               (("enum-compat")
                "enum34"))
             #t)))))
    (native-inputs
     `(("python2-six" ,python2-six)
       ("python2-enum32" ,python2-enum34)
       ("python2-netifaces" ,python2-netifaces)
       ("python2-typing" ,python2-typing)))
    (home-page "https://github.com/jstasiak/python-zeroconf")
    (synopsis "Pure Python mDNS service discovery")
    (description
     "Pure Python multicast DNS (mDNS) service discovery library (Bonjour/Avahi
compatible).")
    (license license:lgpl2.1+)))

(define-public python-bsddb3
  (package
    (name "python-bsddb3")
    (version "6.2.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "bsddb3" version))
       (sha256
        (base32
         "019db2y6bfmiqbrgg9x9f6h72qjmqh05czdn2v5sy9bl0gs23mj2"))))
    (build-system python-build-system)
    (inputs
     `(("bdb" ,bdb)))
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'configure-locations
           (lambda* (#:key inputs #:allow-other-keys)
             (setenv "BERKELEYDB_DIR" (assoc-ref inputs "bdb"))
             (setenv "YES_I_HAVE_THE_RIGHT_TO_USE_THIS_BERKELEY_DB_VERSION" "1")
             #t))
         (replace 'check
           (lambda _
             (invoke "python3" "test3.py" "-v"))))))
    (home-page "https://www.jcea.es/programacion/pybsddb.htm")
    (synopsis "Python bindings for Oracle Berkeley DB")
    (description
     "This module provides a nearly complete wrapping of the Oracle/Sleepycat
C API for the Database Environment, Database, Cursor, Log Cursor, Sequence and
Transaction objects, and each of these is exposed as a Python type in the
bsddb3.db module.  The database objects can use various access methods: btree,
hash, recno, and queue.  Complete support of Berkeley DB distributed
transactions.  Complete support for Berkeley DB Replication Manager.
Complete support for Berkeley DB Base Replication.  Support for RPC.")
    (license license:bsd-3)))

(define-public python-dbfread
  (package
    (name "python-dbfread")
    (version "2.0.7")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "dbfread" version))
              (sha256
               (base32
                "0gdpwdzf1fngsi6jrdyj4qdf6cr7gnnr3zp80dpkzbgz0spskj07"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://dbfread.readthedocs.io")
    (synopsis "Read DBF Files with Python")
    (description
     "This library reads DBF files and returns the data as native Python data
types for further processing.  It is primarily intended for batch jobs and
one-off scripts.")
    (license license:expat)))

(define-public python-cached-property
  (package
    (name "python-cached-property")
    (version "1.5.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "cached-property" version))
       (sha256
        (base32
         "010m1bl380l2r3vwq24r5v14l6gwvgm9v0mqqjkjss552jgsa5wj"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; https://github.com/pydanny/cached-property/issues/131
         ;; recent versions of freezegun break one test
         (add-after 'unpack 'disable-broken-test
           (lambda _
             (substitute* "tests/test_cached_property.py"
               (("def test_threads_ttl_expiry\\(self\\)" m)
                (string-append "@unittest.skip(\"Disabled by Guix\")\n"
                               "    " m)))
             #t)))))
    (native-inputs
     `(("python-freezegun" ,python-freezegun)))
    (home-page
     "https://github.com/pydanny/cached-property")
    (synopsis
     "Decorator for caching properties in classes")
    (description
     "This package provides a decorator which makes caching
time-or-computationally-expensive properties quick and easy and works in Python
2 or 3.")
    (license license:bsd-3)))
