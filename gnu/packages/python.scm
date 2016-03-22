;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013, 2014, 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2014, 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2014, 2015 Federico Beffa <beffa@fbengineering.ch>
;;; Copyright © 2015 Omar Radwan <toxemicsquire4@gmail.com>
;;; Copyright © 2015 Pierre-Antoine Rault <par@rigelk.eu>
;;; Copyright © 2015 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015, 2016 Christopher Allan Webber <cwebber@dustycloud.org>
;;; Copyright © 2015 Eric Dvorsak <eric@dvorsak.fr>
;;; Copyright © 2015, 2016 David Thompson <davet@gnu.org>
;;; Copyright © 2015, 2016 Leo Famulari <leo@famulari.name>
;;; Copyright © 2015 Ben Woodcroft <donttrustben@gmail.com>
;;; Copyright © 2015, 2016 Erik Edrosa <erik.edrosa@gmail.com>
;;; Copyright © 2015, 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2015 Kyle Meyer <kyle@kyleam.com>
;;; Copyright © 2015, 2016 Chris Marusich <cmmarusich@gmail.com>
;;; Copyright © 2016 Danny Milosavljevic <dannym+a@scratchpost.org>
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

(define-module (gnu packages python)
  #:use-module ((guix licenses)
                #:select (asl2.0 bsd-4 bsd-3 bsd-2 non-copyleft cc0 x11 x11-style
                          gpl2 gpl2+ gpl3+ lgpl2.0+ lgpl2.1 lgpl2.1+ lgpl3+ agpl3+
                          isc mpl2.0 psfl public-domain repoze unlicense x11-style
                          zpl2.1))
  #:use-module ((guix licenses) #:select (expat zlib) #:prefix license:)
  #:use-module (gnu packages)
  #:use-module (gnu packages attr)
  #:use-module (gnu packages backup)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages file)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages image)
  #:use-module (gnu packages imagemagick)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages networking)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages statistics)
  #:use-module (gnu packages texlive)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages web)
  #:use-module (gnu packages base)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages zip)
  #:use-module (gnu packages tcl)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system python)
  #:use-module (guix build-system trivial)
  #:use-module (srfi srfi-1))

(define-public python-2
  (package
    (name "python")
    (version "2.7.10")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://www.python.org/ftp/python/"
                          version "/Python-" version ".tar.xz"))
      (sha256
       (base32
        "1h7zbrf9pkj29hlm18b10548ch9757f75m64l47sy75rh43p7lqw"))
      (patches (map search-patch
                    '("python-2.7-search-paths.patch"
                      "python-2-deterministic-build-info.patch"
                      "python-2.7-source-date-epoch.patch")))))
    (outputs '("out"
               "tk"))                     ;tkinter; adds 50 MiB to the closure
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f
       ;; 268 tests OK.
       ;; 103 tests failed:
       ;;     test_distutils test_shutil test_signal test_site test_slice
       ;;     test_smtplib test_smtpnet test_socket test_socketserver
       ;;     test_softspace test_sort test_spwd test_sqlite test_ssl
       ;;     test_startfile test_stat test_str test_strftime test_string
       ;;     test_stringprep test_strop test_strptime test_strtod test_struct
       ;;     test_structmembers test_structseq test_subprocess test_sunau
       ;;     test_sunaudiodev test_sundry test_symtable test_syntax test_sys
       ;;     test_sys_setprofile test_sys_settrace test_sysconfig test_tarfile
       ;;     test_tcl test_telnetlib test_tempfile test_textwrap test_thread
       ;;     test_threaded_import test_threadedtempfile test_threading
       ;;     test_threading_local test_threadsignals test_time test_timeit
       ;;     test_timeout test_tk test_tokenize test_tools test_trace
       ;;     test_traceback test_transformer test_ttk_guionly test_ttk_textonly
       ;;     test_tuple test_typechecks test_ucn test_unary
       ;;     test_undocumented_details test_unicode test_unicode_file
       ;;     test_unicodedata test_univnewlines test_univnewlines2k test_unpack
       ;;     test_urllib test_urllib2 test_urllib2_localnet test_urllib2net
       ;;     test_urllibnet test_urlparse test_userdict test_userlist
       ;;     test_userstring test_uu test_uuid test_wait3 test_wait4
       ;;     test_warnings test_wave test_weakref test_weakset test_whichdb
       ;;     test_winreg test_winsound test_with test_wsgiref test_xdrlib
       ;;     test_xml_etree test_xml_etree_c test_xmllib test_xmlrpc
       ;;     test_xpickle test_xrange test_zipfile test_zipfile64
       ;;     test_zipimport test_zipimport_support test_zlib
       ;; 30 tests skipped:
       ;;     test_aepack test_al test_applesingle test_bsddb test_bsddb185
       ;;     test_bsddb3 test_cd test_cl test_codecmaps_cn test_codecmaps_hk
       ;;     test_codecmaps_jp test_codecmaps_kr test_codecmaps_tw test_crypt
       ;;     test_curses test_dl test_gdb test_gl test_idle test_imageop
       ;;     test_imgfile test_ioctl test_kqueue test_linuxaudiodev test_macos
       ;;     test_macostools test_msilib test_nis test_ossaudiodev
       ;;     test_scriptpackages
       ;; 6 skips unexpected on linux2:
       ;;     test_bsddb test_bsddb3 test_crypt test_gdb test_idle test_ioctl
       ;; One of the typical errors:
       ;; test_unicode
       ;; test test_unicode crashed -- <type 'exceptions.OSError'>: [Errno 2] No
       ;; such file or directory
       #:test-target "test"
       #:configure-flags
       (list "--enable-shared"                    ;allow embedding
             "--with-system-ffi"                  ;build ctypes
             (string-append "LDFLAGS=-Wl,-rpath="
                            (assoc-ref %outputs "out") "/lib"))

        #:modules ((ice-9 ftw) (ice-9 match)
                   (guix build utils) (guix build gnu-build-system))
        #:phases
        (modify-phases %standard-phases
          (add-before
           'configure 'patch-lib-shells
           (lambda _
             ;; Filter for existing files, since some may not exist in all
             ;; versions of python that are built with this recipe.
             (substitute* (filter file-exists?
                                  '("Lib/subprocess.py"
                                    "Lib/popen2.py"
                                    "Lib/distutils/tests/test_spawn.py"
                                    "Lib/test/test_subprocess.py"))
               (("/bin/sh") (which "sh")))

             ;; Use zero as the timestamp in .pyc files so that builds are
             ;; deterministic.  TODO: Remove it when this variable is set in
             ;; gnu-build-system.scm.
             (setenv "SOURCE_DATE_EPOCH" "1")
             #t))
          (add-before 'configure 'do-not-record-configure-flags
            (lambda* (#:key configure-flags #:allow-other-keys)
              ;; Remove configure flags from the installed '_sysconfigdata.py'
              ;; and 'Makefile' so we don't end up keeping references to the
              ;; build tools.
              ;;
              ;; Preserve at least '--with-system-ffi' since otherwise the
              ;; thing tries to build libffi, fails, and we end up with a
              ;; Python that lacks ctypes.
              (substitute* "configure"
                (("^CONFIG_ARGS=.*$")
                 (format #f "CONFIG_ARGS='~a'\n"
                         (if (member "--with-system-ffi" configure-flags)
                             "--with-system-ffi"
                             ""))))
              #t))
          (add-before
           'check 'pre-check
           (lambda _
             ;; 'Lib/test/test_site.py' needs a valid $HOME
             (setenv "HOME" (getcwd))
             #t))
          (add-after
           'unpack 'set-source-file-times-to-1980
           ;; XXX One of the tests uses a ZIP library to pack up some of the
           ;; source tree, and fails with "ZIP does not support timestamps
           ;; before 1980".  Work around this by setting the file times in the
           ;; source tree to sometime in early 1980.
           (lambda _
             (let ((circa-1980 (* 10 366 24 60 60)))
               (ftw "." (lambda (file stat flag)
                          (utime file circa-1980 circa-1980)
                          #t))
               #t)))
          (add-after 'install 'move-tk-inter
            (lambda* (#:key outputs #:allow-other-keys)
              ;; When Tkinter support is built move it to a separate output so
              ;; that the main output doesn't contain a reference to Tcl/Tk.
              (let ((out (assoc-ref outputs "out"))
                    (tk  (assoc-ref outputs "tk")))
                (when tk
                  (match (find-files out "tkinter.*\\.so")
                    ((tkinter.so)
                     ;; The .so is in OUT/lib/pythonX.Y/lib-dynload, but we
                     ;; want it under TK/lib/pythonX.Y/site-packages.
                     (let* ((len    (string-length out))
                            (target (string-append
                                     tk "/"
                                     (string-drop
                                      (dirname (dirname tkinter.so))
                                      len)
                                     "/site-packages")))
                       (install-file tkinter.so target)
                       (delete-file tkinter.so)))))
                #t))))))
    (inputs
     `(("bzip2" ,bzip2)
       ("gdbm" ,gdbm)
       ("libffi" ,libffi)                         ; for ctypes
       ("sqlite" ,sqlite)                         ; for sqlite extension
       ("openssl" ,openssl)
       ("readline" ,readline)
       ("zlib" ,zlib)
       ("tcl" ,tcl)
       ("tk" ,tk)))                               ; for tkinter
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (native-search-paths
     (list (search-path-specification
            (variable "PYTHONPATH")
            (files '("lib/python2.7/site-packages")))))
    (home-page "http://python.org")
    (synopsis "High-level, dynamically-typed programming language")
    (description
     "Python is a remarkably powerful dynamic programming language that
is used in a wide variety of application domains.  Some of its key
distinguishing features include: clear, readable syntax; strong
introspection capabilities; intuitive object orientation; natural
expression of procedural code; full modularity, supporting hierarchical
packages; exception-based error handling; and very high level dynamic
data types.")
    (license psfl)))

(define-public python
  (package (inherit python-2)
    (version "3.4.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://www.python.org/ftp/python/"
                                  version "/Python-" version ".tar.xz"))
              (patches (map search-patch
                            '("python-fix-tests.patch"
                              ;; XXX Try removing this patch for python > 3.4.3
                              "python-disable-ssl-test.patch"
                              "python-3-deterministic-build-info.patch"
                              "python-3-search-paths.patch")))
              (patch-flags '("-p0"))
              (sha256
               (base32
                "1f4nm4z08sy0kqwisvv95l02crv6dyysdmx44p1mz3bn6csrdcxm"))))
    (arguments (substitute-keyword-arguments (package-arguments python-2)
                 ((#:tests? _) #t)))
    (native-search-paths
     (list (search-path-specification
            (variable "PYTHONPATH")
            (files (list (string-append "lib/python"
                                        (version-major+minor version)
                                        "/site-packages"))))))))

;; Minimal variants of Python, mostly used to break the cycle between Tk and
;; Python (Tk -> libxcb -> Python.)

(define-public python2-minimal
  (package (inherit python-2)
    (name "python-minimal")
    (outputs '("out"))
    (arguments
     (substitute-keyword-arguments (package-arguments python-2)
       ((#:configure-flags cf)
        `(append ,cf '("--without-system-ffi")))))
    (inputs '())))                          ;none of the optional dependencies

(define-public python-minimal
  (package (inherit python)
    (name "python-minimal")
    (outputs '("out"))
    (arguments
     (substitute-keyword-arguments (package-arguments python)
       ((#:configure-flags cf)
        `(append ,cf '("--without-system-ffi")))))

    ;; OpenSSL is a mandatory dependency of Python 3.x, for urllib;
    ;; zlib is required by 'zipimport', used by pip.
    (inputs `(("openssl" ,openssl)
              ("zlib" ,zlib)))))

(define* (wrap-python3 python
                       #:optional
                       (name (string-append (package-name python) "-wrapper")))
  (package (inherit python)
    (name name)
    (source #f)
    (build-system trivial-build-system)
    (outputs '("out"))
    (propagated-inputs `(("python" ,python)))
    (arguments
     `(#:modules ((guix build utils))
       #:builder
         (begin
           (use-modules (guix build utils))
           (let ((bin (string-append (assoc-ref %outputs "out") "/bin"))
                 (python (string-append (assoc-ref %build-inputs "python") "/bin/")))
                (mkdir-p bin)
                (for-each
                  (lambda (old new)
                    (symlink (string-append python old)
                             (string-append bin "/" new)))
                  `("python3" ,"pydoc3" ,"idle3")
                  `("python"  ,"pydoc"  ,"idle"))))))
    (synopsis "Wrapper for the Python 3 commands")
    (description
     "This package provides wrappers for the commands of Python@tie{}3.x such
that they can be invoked under their usual name---e.g., @command{python}
instead of @command{python3}.")))

(define-public python-wrapper (wrap-python3 python))
(define-public python-minimal-wrapper (wrap-python3 python-minimal))

(define-public python-psutil
  (package
    (name "python-psutil")
    (version "3.3.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "psutil" version))
       (sha256
        (base32
         "11bd1555vf2ibjnmqf64im5cp55vcqfq45ccinm9ll3bs68na6s2"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://pypi.python.org/pypi/psutil/")
    (synopsis "Library for retrieving information on running processes")
    (description
     "psutil (Python system and process utilities) is a library for retrieving
information on running processes and system utilization (CPU, memory, disks,
network) in Python.  It is useful mainly for system monitoring, profiling and
limiting process resources and management of running processes.  It implements
many functionalities offered by command line tools such as: ps, top, lsof,
netstat, ifconfig, who, df, kill, free, nice, ionice, iostat, iotop, uptime,
pidof, tty, taskset, pmap.")
    (license bsd-3)))

(define-public python2-psutil
  (package-with-python2 python-psutil))

(define-public python-passlib
  (package
    (name "python-passlib")
    (version "1.6.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "passlib" version))
       (sha256
        (base32
         "1z27wdxs5rj5xhhqfzvzn3yg682irkxw6dcs5jj7mcf97psk8gd8"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-setuptools" ,python-setuptools)))
    (inputs
     `(("python-py-bcrypt" ,python-py-bcrypt)))
    (arguments
     `(#:phases
       (alist-cons-before
        'check 'set-PYTHON_EGG_CACHE
        ;; some tests require access to "$HOME/.cython"
        (lambda* _ (setenv "PYTHON_EGG_CACHE" "/tmp"))
         %standard-phases)))
    (home-page "https://bitbucket.org/ecollins/passlib")
    (synopsis
     "Comprehensive password hashing framework")
    (description
     "Passlib is a password hashing library for Python 2 & 3, which provides
cross-platform implementations of over 30 password hashing algorithms, as well
as a framework for managing existing password hashes.  It's designed to be
useful for a wide range of tasks, from verifying a hash found in /etc/shadow,
to providing full-strength password hashing for multi-user application.")
    (license bsd-3)))

(define-public python2-passlib
  (package-with-python2 python-passlib))

(define-public python-py-bcrypt
  (package
    (name "python-py-bcrypt")
    (version "0.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/p/py-bcrypt/py-bcrypt-"
             version
             ".tar.gz"))
       (sha256
        (base32
         "0y6smdggwi5s72v6p1nn53dg6w05hna3d264cq6kas0lap73p8az"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://code.google.com/p/py-bcrypt")
    (synopsis
     "Bcrypt password hashing and key derivation")
    (description
     "A python wrapper of OpenBSD's Blowfish password hashing code.  This
system hashes passwords using a version of Bruce Schneier's Blowfish block
cipher with modifications designed to raise the cost of off-line password
cracking and frustrate fast hardware implementation.  The computation cost of
the algorithm is parametised, so it can be increased as computers get faster.
The intent is to make a compromise of a password database less likely to
result in an attacker gaining knowledge of the plaintext passwords (e.g. using
John the Ripper).")
    ;; "sha2.c" is under BSD-3;
    ;; "blowfish.c" and "bcrypt.c" are under BSD-4;
    ;; the rest is under ISC.
    (license (list isc bsd-3 bsd-4))))

(define-public python2-py-bcrypt
  (package-with-python2 python-py-bcrypt))


(define-public python-paramiko
  (package
    (name "python-paramiko")
    (version "1.15.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/p/paramiko/paramiko-"
             version
             ".tar.gz"))
       (sha256
        (base32
         "0mbfzm9zlrz6mla9xakrm8wkll3x035f9rj3c5pbgjzfldqscmjg"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (propagated-inputs
     `(("python-pycrypto" ,python-pycrypto)))
    (inputs
     `(("python-ecdsa" ,python-ecdsa)))
    (home-page "http://www.paramiko.org/")
    (synopsis "SSHv2 protocol library")
    (description "Paramiko is a python implementation of the SSHv2 protocol,
providing both client and server functionality.  While it leverages a Python C
extension for low level cryptography (PyCrypto), Paramiko itself is a pure
Python interface around SSH networking concepts.")
    (license lgpl2.1+)))

(define-public python2-paramiko
  (package-with-python2 python-paramiko))


(define-public python-httplib2
  (package
    (name "python-httplib2")
    (version "0.9.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/h/httplib2/httplib2-"
             version
             ".tar.gz"))
       (sha256
        (base32
         "1xc3clbrf77r0600kja71j7hk1218sjiq0gfmb8vjdajka8kjqxw"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page
     "https://github.com/jcgregorio/httplib2")
    (synopsis "Comprehensive HTTP client library")
    (description
     "A comprehensive HTTP client library supporting many features left out of
other HTTP libraries.")
    (license license:expat)))

(define-public python2-httplib2
  (package-with-python2 python-httplib2))

(define-public python-ecdsa
  (package
    (name "python-ecdsa")
    (version "0.13")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/e/ecdsa/ecdsa-"
             version
             ".tar.gz"))
       (sha256
        (base32
         "1yj31j0asmrx4an9xvsaj2icdmzy6pw0glfpqrrkrphwdpi1xkv4"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (inputs
     `(("openssl" ,openssl)))
    (home-page
     "http://github.com/warner/python-ecdsa")
    (synopsis
     "ECDSA cryptographic signature library (pure python)")
    (description
     "This is an easy-to-use implementation of ECDSA cryptography (Elliptic
Curve Digital Signature Algorithm), implemented purely in Python.  With this
library, you can quickly create keypairs (signing key and verifying key), sign
messages, and verify the signatures.  The keys and signatures are very short,
making them easy to handle and incorporate into other protocols.")
    (license license:expat)))

(define-public python2-ecdsa
  (package-with-python2 python-ecdsa))

(define-public python-ccm
  (package
    (name "python-ccm")
    (version "2.0.4.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/c/ccm/ccm-"
             version
             ".tar.gz"))
       (sha256
        (base32
         "199jw221albs2iv6xczczq88fxnh0aw8hzmys8qkbzkd99dssng9"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (inputs
     `(("python-pyyaml" ,python-pyyaml)
       ("python-six" ,python-six)))
    (home-page "https://github.com/pcmanus/ccm")
    (synopsis "Cassandra Cluster Manager")
    (description "A script/library to create, launch and remove an Apache
Cassandra cluster on localhost.")
    (license asl2.0)))

(define-public python2-ccm
  (package-with-python2 python-ccm))

(define-public python-pytz
  (package
    (name "python-pytz")
    (version "2015.7")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "pytz" version))
      (sha256
       (base32
        "1spgdfp1ssya7v3kww7zp71xpj437skpqazcvqr3kr1p1brnw9lr"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f)) ; no test target
    (home-page "http://pythonhosted.org/pytz")
    (synopsis "Python timezone library")
    (description
     "This library allows accurate and cross platform timezone calculations
using Python 2.4 or higher and provides access to the Olson timezone database.")
    (license license:expat)))

(define-public python2-pytz
  (package-with-python2 python-pytz))


(define-public python-babel
  (package
    (name "python-babel")
    (version "2.1.1")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "Babel" version))
      (sha256
       (base32
        "0j2jgfzj1a2m39pm2qc36fzr7a6p5ybwndi0xdzhi2p8zw7dbdkz"))))
    (build-system python-build-system)
    (inputs
     `(("python-pytz" ,python-pytz)
       ("python-setuptools" ,python-setuptools)))
    (arguments `(#:tests? #f)) ; no test target
    (home-page "http://babel.pocoo.org/")
    (synopsis
     "Tools for internationalizing Python applications")
    (description
     "Babel is composed of two major parts:
- tools to build and work with gettext message catalogs
- a Python interface to the CLDR (Common Locale Data Repository), providing
access to various locale display names, localized number and date formatting,
etc. ")
    (license bsd-3)))

(define-public python2-babel
  (package-with-python2 python-babel))

(define-public python2-backport-ssl-match-hostname
  (package
    (name "python2-backport-ssl-match-hostname")
    (version "3.5.0.1")
    (source
     (origin
      (method url-fetch)
      (uri (string-append
            "https://pypi.python.org/packages/source/b/"
            "backports.ssl_match_hostname/backports.ssl_match_hostname-"
            version ".tar.gz"))
      (sha256
       (base32
        "1wndipik52cyqy0677zdgp90i435pmvwd89cz98lm7ri0y3xjajh"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:tests? #f)) ; no test target
    (inputs
     `(("python2-setuptools" ,python2-setuptools)))
    (home-page "https://bitbucket.org/brandon/backports.ssl_match_hostname")
    (synopsis "Backport of ssl.match_hostname() function from Python 3.5")
    (description
     "This backport brings the ssl.match_hostname() function to users of
earlier versions of Python.  The function checks the hostname in the
certificate returned by the server to which a connection has been established,
and verifies that it matches the intended target hostname.")
    (license psfl)))

(define-public python-h5py
  (package
    (name "python-h5py")
    (version "2.4.0")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/h/h5py/h5py-"
                          version ".tar.gz"))
      (sha256
       (base32
        "0q4f9l8grf6pwp64xbv8bmyxx416s7h4522nnxac056ap3savbps"))))
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
     `(("python-numpy" ,python-numpy)))
    (inputs
     `(("hdf5" ,hdf5)))
    (native-inputs
     `(("python-cython" ,python-cython)))
    (home-page "http://www.h5py.org/")
    (synopsis "Read and write HDF5 files from Python")
    (description
     "The h5py package provides both a high- and low-level interface to the
HDF5 library from Python.  The low-level interface is intended to be a
complete wrapping of the HDF5 API, while the high-level component supports
access to HDF5 files, datasets and groups using established Python and NumPy
concepts.")
    (license bsd-3)))

(define-public python2-h5py
  (let ((h5py (package-with-python2 python-h5py)))
    (package (inherit h5py)
      (propagated-inputs
       `(("python2-numpy" ,python2-numpy)
         ,@(alist-delete
            "python-numpy"
            (package-propagated-inputs h5py)))))))

(define-public python-lockfile
  (package
    (name "python-lockfile")
    (version "0.9.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/l/lockfile/"
                           "lockfile-" version ".tar.gz"))
       (sha256
        (base32
         "0iwif7i84gwpvrnpv4brshdk8j6l77smvknm8k3bg77mj6f5ini3"))))
    (build-system python-build-system)
    (arguments '(#:test-target "check"))
    (home-page "http://code.google.com/p/pylockfile/")
    (synopsis "Platform-independent file locking module")
    (description
     "The lockfile package exports a LockFile class which provides a simple
API for locking files.")
    (license license:expat)))

(define-public python2-lockfile
  (package-with-python2 python-lockfile))

(define-public python-mock
  (package
    (name "python-mock")
    (version "1.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/m/mock/"
                           "mock-" version ".tar.gz"))
       (sha256
        (base32
         "0kzlsbki6q0awf89rc287f3aj8x431lrajf160a70z0ikhnxsfdq"))))
    (build-system python-build-system)
    (arguments '(#:test-target "check"))
    (home-page "http://code.google.com/p/mock/")
    (synopsis "Python mocking and patching library for testing")
    (description
     "Mock is a library for testing in Python.  It allows you to replace parts
of your system under test with mock objects and make assertions about how they
have been used.")
    (license license:expat)))

(define-public python2-mock
  (package-with-python2 python-mock))


(define-public python-setuptools
  (package
    (name "python-setuptools")
    (version "18.3.1")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/s/setuptools/setuptools-"
                          version ".tar.gz"))
      (sha256
       (base32
        "0kc7rbav00ks6iaw14p38y81q12fx0lpkhgf5m97xc04f5r318ig"))))
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
    (license psfl)))

(define-public python2-setuptools
  (package-with-python2 python-setuptools))


(define-public python-pycrypto
  (package
    (name "python-pycrypto")
    (version "2.6.1")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/p/"
                          "pycrypto/pycrypto-" version ".tar.gz"))
      (sha256
       (base32
        "0g0ayql5b9mkjam8hym6zyg6bv77lbh66rv1fyvgqb17kfc1xkpj"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (inputs
     `(("python" ,python)
       ("gmp" ,gmp)))
    (arguments
     `(#:phases
       (alist-cons-before
        'build 'set-build-env
        ;; pycrypto runs an autoconf configure script behind the scenes
        (lambda _
          (setenv "CONFIG_SHELL" (which "bash")))
        %standard-phases)))
    (home-page "http://www.pycrypto.org/")
    (synopsis "Cryptographic modules for Python")
    (description
     "Pycrypto is a collection of both secure hash functions (such as SHA256
and RIPEMD160), and various encryption algorithms (AES, DES, RSA, ElGamal,
etc.).  The package is structured to make adding new modules easy.")
    (license public-domain)))

(define-public python2-pycrypto
  (let ((pycrypto (package-with-python2 python-pycrypto)))
    (package (inherit pycrypto)
      (inputs
       `(("python" ,python-2)
         ,@(alist-delete
            "python"
            (package-inputs pycrypto)))))))

(define-public python-keyring
  (package
    (name "python-keyring")
    (version "5.7.1")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "keyring" version))
      (sha256
       (base32
        "1h7a1r9ick7wdd0xb5p63413nvjadna2xawrsvmklsl5ddhm5wrx"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-setuptools-scm" ,python-setuptools-scm)
       ("python-mock" ,python-mock)))
    (inputs
     `(("python-pycrypto" ,python-pycrypto)))
    (arguments
     `(#:tests? #f))                      ;TODO: tests require pytest
    (home-page "http://bitbucket.org/kang/python-keyring-lib")
    (synopsis "Store and access your passwords safely")
    (description
     "The Python keyring lib provides a easy way to access the system keyring
service from python.  It can be used in any application that needs safe
password storage.")
    ;; "MIT" and PSF dual license
    (license x11)))

(define-public python2-keyring
  (let ((keyring (package-with-python2 python-keyring)))
    (package (inherit keyring)
      (inputs
       `(("python2-pycrypto" ,python2-pycrypto))))))

(define-public python-six
  (package
    (name "python-six")
    (version "1.10.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "six" version))
      (sha256
       (base32
        "0snmb8xffb3vsma0z67i0h0w2g2dy0p3gsgh9gi4i0kgc5l8spqh"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://pypi.python.org/pypi/six/")
    (synopsis "Python 2 and 3 compatibility utilities")
    (description
     "Six is a Python 2 and 3 compatibility library.  It provides utility
functions for smoothing over the differences between the Python versions with
the goal of writing Python code that is compatible on both Python versions.
Six supports every Python version since 2.5.  It is contained in only one
Python file, so it can be easily copied into your project.")
    (license x11)))

(define-public python2-six
  (package-with-python2 python-six))

(define-public python-dateutil-2
  (package
    (name "python-dateutil")
    (version "2.4.2")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/p/"
                          name "/" name "-" version ".tar.gz"))
      (sha256
       (base32
        "0ggbm2z72p0nwjqgvpw8s5bqzwayqiqv2iws0x2a605m3mf4959y"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-six" ,python-six)))
    (home-page "http://labix.org/python-dateutil")
    (synopsis "Extensions to the standard datetime module")
    (description
     "The dateutil module provides powerful extensions to the standard
datetime module, available in Python 2.3+.")
    (license bsd-3)))

(define-public python2-dateutil-2
  (package-with-python2 python-dateutil-2))

(define-public python-dateutil
  (package
    (name "python-dateutil")
    (version "1.5") ; last version for python < 3
    (source
     (origin
      (method url-fetch)
      (uri (string-append "http://labix.org/download/python-dateutil/"
                          "python-dateutil-" version ".tar.gz"))
      (sha256
       (base32
        "0fqfglhy5khbvsipr3x7m6bcaqljh8xl5cw33vbfxy7qhmywm2n0"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://labix.org/python-dateutil")
    (synopsis "Extensions to the standard datetime module")
    (description
     "The dateutil module provides powerful extensions to the standard
datetime module, available in Python 2.3+.")
    (license psfl)))

(define-public python2-dateutil
  (package-with-python2 python-dateutil))

(define-public python-parsedatetime
  (package
    (name "python-parsedatetime")
    (version "1.5")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/p/"
                          "parsedatetime/parsedatetime-" version ".tar.gz"))
      (sha256
       (base32
        "1as0mm4ql3z0324nc9bys2s1ngh507i317p16b79rx86wlmvx9ix"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://github.com/bear/parsedatetime/")
    (synopsis
     "Parse human-readable date/time text")
    (description
     "Parse human-readable date/time text.")
    (license asl2.0)))

(define-public python2-parsedatetime
  (package-with-python2 python-parsedatetime))

(define-public python-pandas
  (package
    (name "python-pandas")
    (version "0.16.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pandas" version))
       (sha256
        (base32 "10agmrkps8bi5948vwpipfxds5kj1d076m9i0nhaxwqiw7gm6670"))))
    (build-system python-build-system)
    (arguments
     `(;; Three tests fail:
       ;; - test_read_google
       ;; - test_read_yahoo
       ;; - test_month_range_union_tz_dateutil
       #:tests? #f))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-pytz" ,python-pytz)
       ("python-dateutil" ,python-dateutil-2)))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-setuptools" ,python-setuptools)))
    (home-page "http://pandas.pydata.org")
    (synopsis "Data structures for data analysis, time series, and statistics")
    (description
     "Pandas is a Python package providing fast, flexible, and expressive data
structures designed to make working with structured (tabular,
multidimensional, potentially heterogeneous) and time series data both easy
and intuitive.  It aims to be the fundamental high-level building block for
doing practical, real world data analysis in Python.")
    (license bsd-3)))

(define-public python2-pandas
  (let ((pandas (package-with-python2 python-pandas)))
    (package (inherit pandas)
             (propagated-inputs
              `(("python2-numpy" ,python2-numpy)
                ,@(alist-delete "python-numpy"
                                (package-propagated-inputs pandas)))))))

(define-public python-tzlocal
  (package
    (name "python-tzlocal")
    (version "1.2")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "tzlocal" version))
      (sha256
       (base32
        "12wsw2fl3adrqrwghasld57bhqdrzn0crblqrci1p5acd0ni53s3"))))
    (build-system python-build-system)
    (propagated-inputs `(("python-pytz" ,python-pytz)))
    (home-page "https://github.com/regebro/tzlocal")
    (synopsis
     "Local timezone information for Python")
    (description
     "Tzlocal returns a tzinfo object with the local timezone information.
This module attempts to fix a glaring hole in pytz, that there is no way to
get the local timezone information, unless you know the zoneinfo name, and
under several distributions that's hard or impossible to figure out.")
    (license cc0)))

(define-public python2-pysqlite
  (package
    (name "python2-pysqlite")
    (version "2.8.1")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "pysqlite" version))
      (sha256
       (base32
        "0rm0zqyb363y6wljhfmbxs16jjv7p8nk1d8zgq9sdwj6js7y3jkm"))))
    (build-system python-build-system)
    (inputs
     `(("sqlite" ,sqlite)))
    (arguments
     `(#:python ,python-2 ; incompatible with Python 3
       #:tests? #f)) ; no test target
    (home-page "http://github.com/ghaering/pysqlite")
    (synopsis "SQLite bindings for Python")
    (description
     "Pysqlite provides SQLite bindings for Python that comply to the
Database API 2.0T.")
    (license license:zlib)))


(define-public python2-mechanize
  (package
    (name "python2-mechanize")
    (version "0.2.5")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/m/mechanize/mechanize-"
                          version ".tar.gz"))
      (sha256
       (base32
        "0rj7r166i1dyrq0ihm5rijfmvhs8a04im28lv05c0c3v206v4rrf"))))
    (build-system python-build-system)
    (inputs
     `(("python2-setuptools" ,python2-setuptools)))
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
    (license (non-copyleft "file://COPYING"
                           "See COPYING in the distribution."))))


(define-public python-simplejson
  (package
    (name "python-simplejson")
    (version "3.3.0")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/s/simplejson/simplejson-"
                          version ".tar.gz"))
      (sha256
       (base32
        "07wsry5j44l5zzm74l4j2bvasiq8n5m32f31n2p7c68i5vc6p2ks"))))
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
    (license x11)))

(define-public python2-simplejson
  (package-with-python2 python-simplejson))


(define-public python-pyicu
  (package
    (name "python-pyicu")
    (version "1.9.2")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/P/PyICU/PyICU-"
                          version ".tar.gz"))
      (sha256
       (base32
        "1diba0g8md614fvm9yf50paiwdkhj6rd7xwf1rg9mc0pxc0hhn4v"))))
    (build-system python-build-system)
    (inputs
     `(("icu4c" ,icu4c)))
    (home-page "http://pyicu.osafoundation.org/")
    (synopsis "Python extension wrapping the ICU C++ API")
    (description
     "PyICU is a python extension wrapping the ICU C++ API.")
    (license x11)
    (properties `((python2-variant . ,(delay python2-pyicu))))))

(define-public python2-pyicu
  (package
    (inherit (package-with-python2
              (strip-python2-variant python-pyicu)))
    (native-inputs `(("python2-setuptools" ,python2-setuptools)))))

(define-public python2-dogtail
  ;; Python 2 only, as it leads to "TabError: inconsistent use of tabs and
  ;; spaces in indentation" with Python 3.
  (package
    (name "python2-dogtail")
    (version "0.8.2")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "https://fedorahosted.org/released/dogtail/dogtail-"
                   version ".tar.gz"))
             (sha256
              (base32
               "1yc4cg7ip87z15gyd4wy2vzbywrjc52a3m8r8gqy2b50d65llcg1"))))
    (build-system python-build-system)
    (arguments `(#:python ,python-2
                 #:tests? #f))                    ; invalid command "test"
    (home-page "https://fedorahosted.org/dogtail/")
    (synopsis "GUI test tool and automation framework written in ​Python")
    (description
     "Dogtail is a GUI test tool and automation framework written in Python.
It uses Accessibility (a11y) technologies to communicate with desktop
applications. dogtail scripts are written in Python and executed like any
other Python program.")
    (license gpl2+)))

(define-public python2-empy
  (package
    (name "python2-empy")
    (version "3.3")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://www.alcyone.com/software/empy/empy-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "01g8mmkfnvjdmlhsihwyx56lrg7r5m5d2fg6mnxsvy6g0dnl69f6"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:phases (alist-replace
                 'check
                 (lambda _
                   (zero? (system* "./test.sh")))
                 %standard-phases)))
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
    (license lgpl2.1+)))

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
    (license (x11-style "http://docs.python.org/2/license.html"
                        "Like \"CWI LICENSE AGREEMENT FOR PYTHON \
0.9.0 THROUGH 1.2\"."))))

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
              (patches (map search-patch
                            (list "pybugz-stty.patch"
                                  "pybugz-encode-error.patch")))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2                         ; SyntaxError with Python 3
       #:tests? #f))                              ; no 'test' sub-command
    (inputs `(("element-tree" ,python2-element-tree)))
    (synopsis "Python and command-line interface to Bugzilla")
    (description
     "PyBugz is a Python library and command-line tool to query the Bugzilla
bug tracking system.  It is meant as an aid to speed up interaction with the
bug tracker.")
    (home-page "http://www.liquidx.net/pybugz/")
    (license gpl2)))

(define-public python-enum34
  (package
    (name "python-enum34")
    (version "1.1.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "enum34" version))
      (sha256
       (base32
        "0yx1m4564wxgbm4glb3457hi16xihd9w63rv13y2przkdir9dfgp"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (alist-replace
        'check
        (lambda _ (zero? (system* "python" "enum/test_enum.py")))
        %standard-phases)))
    (home-page "https://pypi.python.org/pypi/enum34")
    (synopsis "Backported Python 3.4 Enum")
    (description
     "Enum34 is the new Python stdlib enum module available in Python 3.4
backported for previous versions of Python from 2.4 to 3.3.")
    (license bsd-3)))

(define-public python2-enum34
  (package-with-python2 python-enum34))

(define-public python-parse-type
  (package
    (name "python-parse-type")
    (version "0.3.4")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/p/"
                          "parse_type/parse_type-" version ".tar.gz"))
      (sha256
       (base32
        "0iv1c34npr4iynwpgv1vkjx9rjd18a85ir8c01gc5f7wp8iv7l1x"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-six" ,python-six)
       ("python-parse" ,python-parse)))
    (arguments '(#:tests? #f))            ;TODO: tests require pytest
    (home-page "https://github.com/jenisys/parse_type")
    (synopsis "Extended parse module")
    (description
     "Parse_type extends the python parse module.")
    (license bsd-3)))

(define-public python-parse
  (package
    (name "python-parse")
    (version "1.6.4")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/p/"
                          "parse/parse-" version ".tar.gz"))
      (sha256
       (base32
        "0m30q64l6szl7s9mhvqy64w2fdhdn8lb91fmacjiwbv3479cmk57"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (alist-replace
        'check
        (lambda _ (zero? (system* "python" "test_parse.py")))
        %standard-phases)))
    (home-page "https://github.com/r1chardj0n3s/parse")
    (synopsis "Parse strings")
    (description
     "Parse strings using a specification based on the Python format()
syntax.")
    (license x11)))


(define-public scons
  (package
    (name "scons")
    (version "2.3.4")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://sourceforge/scons/scons-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "0hdlci43wjz8maryj83mz04ir6rwcdrrzpd7cpzvdlzycqhdfmsb"))))
    (build-system python-build-system)
    (arguments
     ;; With Python 3.x, fails to build with a syntax error.
     `(#:python ,python-2
       #:tests? #f))                       ; no 'python setup.py test' command
    (home-page "http://scons.org/")
    (synopsis "Software construction tool written in Python")
    (description
     "SCons is a software construction tool.  Think of SCons as an improved,
cross-platform substitute for the classic Make utility with integrated
functionality similar to autoconf/automake and compiler caches such as ccache.
In short, SCons is an easier, more reliable and faster way to build
software.")
    (license x11)))

(define-public python-extras
  (package
    (name "python-extras")
    (version "0.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/e/extras/extras-"
             version ".tar.gz"))
       (sha256
        (base32
         "1h7zx4dfyclalg0fqnfjijpn0f793a9mx8sy3b27gd31nr6dhq3s"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (arguments
     ;; error in setup.cfg: command 'test' has no such option 'buffer'
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
    (version "0.1.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/p/python-mimeparse/python-mimeparse-"
             version ".tar.gz"))
       (sha256
        (base32
         "1hyxg09kaj02ri0rmwjqi86wk4nd1akvv7n0dx77azz76wga4s9w"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (arguments
     '(#:tests? #f)) ; no setup.py test command
    (home-page
     "https://github.com/dbtsai/python-mimeparse")
    (synopsis "Python library for parsing MIME types")
    (description
     "Mimeparse provides basic functions for parsing MIME type names and
matching them against a list of media-ranges.")
    (license license:expat)))

(define-public python2-mimeparse
  (package-with-python2 python-mimeparse))

(define-public python-nose
  (package
    (name "python-nose")
    (version "1.3.7")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "nose" version))
        (sha256
          (base32
            "164a43k7k2wsqqk1s6vavcdamvss4mz0vd6pwzv2h9n8rgwzxgzi"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (arguments
     '(#:tests? #f)) ; FIXME: test suite fails
    (home-page "http://readthedocs.org/docs/nose/")
    (synopsis "Python testing library")
    (description
     "Nose extends the unittest library to make testing easier.")
    (license lgpl2.0+)))

(define-public python2-nose
  (package-with-python2 python-nose))

(define-public python-unittest2
  (package
    (name "python-unittest2")
    (version "0.5.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/u/unittest2py3k/unittest2py3k-"
             version ".tar.gz"))
       (sha256
        (base32
         "00yl6lskygcrddx5zspkhr0ibgvpknl4678kkm6s626539grq93q"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://pypi.python.org/pypi/unittest2")
    (synopsis "Python unit testing library")
    (description
     "Unittest2 is a replacement for the unittest module in the Python
standard library.")
    (license psfl)))

(define-public python2-unittest2
  (package (inherit python-unittest2)
    (name "python2-unittest2")
    (version "0.5.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/u/unittest2/unittest2-"
             version ".tar.gz"))
       (sha256
        (base32
         "0wbs4i4x3x7klr3v35ss6p9mcqz883i1xgcpkhvl7n2lyv6yhpda"))))
    (inputs
     `(("python2-setuptools" ,python2-setuptools)))
    (arguments
     `(#:python ,python-2
       #:tests? #f)))) ; no setup.py test command

(define-public python-py
  (package
    (name "python-py")
    (version "1.4.31")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "py" version))
       (sha256
        (base32
         "0561gz2w3i825gyl42mcq14y3dcgkapfiv5zv9a2bz15qxiijl56"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://pylib.readthedocs.org/")
    (synopsis "Python library for parsing, I/O, instrospection, and logging")
    (description
     "Py is a Python library for file name parsing, .ini file parsing, I/O,
code introspection, and logging.")
    (license license:expat)))

(define-public python2-py
  (package-with-python2 python-py))

(define-public python-pytest
  (package
    (name "python-pytest")
    (version "2.7.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/p/pytest/pytest-"
             version ".tar.gz"))
       (sha256
        (base32
         "1z4yi986f9n0p8qmzmn21m21m8j1x78hk3505f89baqm6pdw7afm"))
       (modules '((guix build utils)))
       (snippet
        ;; One of the tests involves the /usr directory, so it fails.
        '(substitute* "testing/test_argcomplete.py"
           (("def test_remove_dir_prefix\\(self\\):")
            "@pytest.mark.xfail\n    def test_remove_dir_prefix(self):")))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-py" ,python-py)
       ("python-nose" ,python-nose)
       ("python-mock" ,python-mock)))
    (home-page "http://pytest.org")
    (synopsis "Python testing library")
    (description
     "Pytest is a testing tool that provides auto-discovery of test modules
and functions, detailed info on failing assert statements, modular fixtures,
and many external plugins.")
    (license license:expat)))

(define-public python2-pytest
  (package-with-python2 python-pytest))

(define-public python-pytest-cov
  (package
    (name "python-pytest-cov")
    (version "2.2.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pytest-cov" version))
        (sha256
          (base32
           "1lf9jsmhqk5nc4w3kzwglmdzjvmi7ajvrsnwv826j3bn0wzx8c92"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-coverage" ,python-coverage)
       ("python-pytest" ,python-pytest)))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/pytest-dev/pytest-cov")
    (synopsis "Pytest plugin for measuring coverage")
    (description
     "Pytest-cov produces coverage reports.  It supports centralised testing and
distributed testing in both @code{load} and @code{each} modes.  It also
supports coverage of subprocesses.")
  (license license:expat)))

(define-public python2-pytest-cov
  (package-with-python2 python-pytest-cov))

(define-public python-pytest-runner
  (package
    (name "python-pytest-runner")
    (version "2.6.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/p/"
                           "pytest-runner/pytest-runner-"
                           version ".tar.gz"))
       (sha256
        (base32
         "1nwcqx0l3fv52kv8526wy8ypzghbq96c96di318d98d3wh7a8xg7"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; The fancy way of setting the version with setuptools_scm does not
         ;; seem to work here.
         (add-after 'unpack 'set-version
          (lambda _
            (substitute* "docs/conf.py"
              (("version = setuptools_scm\\.get_version\\(root='\\.\\.')")
               (string-append "version = \"" ,version "\"")))
            #t)))))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-setuptools" ,python-setuptools)
       ("python-setuptools-scm" ,python-setuptools-scm)))
    (home-page "https://bitbucket.org/pytest-dev/pytest-runner")
    (synopsis "Invoke py.test as a distutils command")
    (description
     "This package provides a @command{pytest-runner} command that
@file{setup.py} files can use to run tests.")
    (license license:expat)))

(define-public python2-pytest-runner
  (package-with-python2 python-pytest-runner))

(define-public python-pytest-xdist
  (package
    (name "python-pytest-xdist")
    (version "1.14")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pytest-xdist" version ".zip"))
       (sha256
        (base32
         "08rn2l39ds60xshs4js787l84pfckksqklfq2wq9x8ig2aci2pja"))))
    (build-system python-build-system)
    (native-inputs
     `(("unzip" ,unzip)
       ("python-setuptools" ,python-setuptools)
       ("python-setuptools-scm" ,python-setuptools-scm)))
    (propagated-inputs
     `(("python-execnet" ,python-execnet)
       ("python-pytest" ,python-pytest)
       ("python-py" ,python-py)))
    (home-page
     "https://github.com/pytest-dev/pytest-xdist")
    (synopsis
     "Plugin for py.test with distributed testing and loop-on-failing modes")
    (description
     "The pytest-xdist plugin extends py.test with some unique test execution
modes: parallelization, running tests in boxed subprocesses, the ability
to run tests repeatedly when failed, and the ability to run tests on multiple
Python interpreters or platforms.  It uses rsync to copy the existing
program code to a remote location, executes there, and then syncs the
result back.")
    (license license:expat)))

(define-public python2-pytest-xdist
  (package-with-python2 python-pytest-xdist))

(define-public python-scripttest
  (package
    (name "python-scripttest")
    (version "1.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/s/scripttest/scripttest-"
             version ".tar.gz"))
       (sha256
        (base32
         "0f4w84k8ck82syys7yg9maz93mqzc8p5ymis941x034v44jzq74m"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-pytest" ,python-pytest)))
    (home-page "http://pythonpaste.org/scripttest/")
    (synopsis "Python library to test command-line scripts")
    (description "Scripttest is a Python helper library for testing
interactive command-line applications.  With it you can run a script in a
subprocess and see the output as well as any file modifications.")
    (license license:expat)))

(define-public python2-scripttest
  (package-with-python2 python-scripttest))

(define-public python-testtools
  (package
    (name "python-testtools")
    (version "1.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/t/testtools/testtools-"
             version ".tar.gz"))
       (sha256
        (base32
         "1dyml28ykpl5jb9khdmcdvhy1cxqingys6qvj2k04fzlaj6z3bbx"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-mimeparse" ,python-mimeparse)))
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-extras" ,python-extras)))
    (home-page "https://github.com/testing-cabal/testtools")
    (synopsis
     "Extensions to the Python standard library unit testing framework")
    (description
     "Testtools extends the Python standard library unit testing framework to
provide matchers, more debugging information, and cross-Python
compatibility.")
    (license psfl)))

(define-public python2-testtools
  (package-with-python2 python-testtools))

(define-public python-testscenarios
  (package
    (name "python-testscenarios")
    (version "0.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/t/testscenarios/testscenarios-"
             version ".tar.gz"))
       (sha256
        (base32
         "1671jvrvqlmbnc42j7pc5y6vc37q44aiwrq0zic652pxyy2fxvjg"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-testtools" ,python-testtools)
       ("python-mimeparse" ,python-mimeparse)))
    (home-page "https://launchpad.net/testscenarios")
    (synopsis "Pyunit extension for dependency injection")
    (description
     "Testscenarios provides clean dependency injection for Python unittest
style tests.")
    (license (list bsd-3 asl2.0)))) ; at the user's option

(define-public python2-testscenarios
  (package-with-python2 python-testscenarios))

(define-public python-testresources
  (package
    (name "python-testresources")
    (version "0.2.7")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/t/testresources/testresources-"
             version ".tar.gz"))
       (sha256
        (base32
         "0cbj3plbllyz42c4b5xxgwaa7mml54lakslrn4kkhinxhdri22md"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://launchpad.net/testresources")
    (synopsis
     "Pyunit extension for managing test resources")
    (description
     "Testresources is an extension to Python's unittest to allow declarative
use of resources by test cases.")
    (license (list bsd-3 asl2.0)))) ; at the user's option

(define-public python2-testresources
  (package-with-python2 python-testresources))

(define-public python-subunit
  (package
    (name "python-subunit")
    (version "0.0.21")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/p/python-subunit/python-subunit-"
             version ".tar.gz"))
       (sha256
        (base32
         "1nkw9wfbvizmpajbj3in8ns07g7lwkiv8hip14jjlwk3cacls6jv"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-testtools" ,python-testtools)
       ("python-mimeparse" ,python-mimeparse)
       ("python-testscenarios" ,python-testscenarios)))
    (home-page "http://launchpad.net/subunit")
    (synopsis "Python implementation of the subunit protocol")
    (description
     "Python-subunit is a Python implementation of the subunit test streaming
protocol.")
    (license (list bsd-3 asl2.0)))) ; at the user's option

(define-public python2-subunit
  (package-with-python2 python-subunit))

;; Recent versions of python-fixtures need a recent version of python-pbr,
;; which needs a recent version of python-fixtures. To fix this circular
;; dependency, we keep old versions of python-fixtures and python-pbr to
;; bootstrap the whole thing:
;; - python-fixtures-0.3.16 is used to build python-pbr-0.11
;; - python-pbr-0.11 is used to build python-fixtures
;; - python-fixtures is used to build python-pbr
(define-public python-fixtures-0.3.16
  (package
    (name "python-fixtures")
    (version "0.3.16")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/f/fixtures/fixtures-"
             version ".tar.gz"))
       (sha256
        (base32
         "0x9r2gwilcig5g54k60bxzg96zabizq1855lrprlb4zckalp9asc"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (arguments
     '(#:tests? #f)) ; no setup.py test command
    (home-page "https://launchpad.net/python-fixtures")
    (synopsis "Python test fixture library")
    (description
     "Fixtures provides a way to create reusable state, useful when writing
Python tests.")
    (license (list bsd-3 asl2.0)))) ; at user's option

(define-public python2-fixtures-0.3.16
  (package-with-python2 python-fixtures-0.3.16))

(define-public python-pbr-0.11
  (package
    (name "python-pbr")
    (version "0.11.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/p/pbr/pbr-"
             version ".tar.gz"))
       (sha256
        (base32
         "0v9gb7gyqf7q9s99l0nnjj9ww9b0jvyqlwm4d56pcyinxydddw6p"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f)) ;; Most tests seem to use the Internet.
    (inputs
      `(("python-fixtures-0.3.16" ,python-fixtures-0.3.16)
        ("python-pip" ,python-pip)
        ("python-setuptools" ,python-setuptools)))
    (home-page "https://launchpad.net/pbr")
    (synopsis "Change the default behavior of Python’s setuptools")
    (description
      "Python Build Reasonableness (PBR) is a library that injects some useful
and sensible default behaviors into your setuptools run.")
    (license asl2.0)))

(define-public python2-pbr-0.11
  (package-with-python2 python-pbr-0.11))

(define-public python-fixtures
  (package
    (name "python-fixtures")
    (version "1.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "fixtures" version))
       (sha256
        (base32
         "0djxvdwm8s60dbfn7bhf40x6g818p3b3mlwijm1c3bqg7msn271y"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-pbr-0.11" ,python-pbr-0.11)))
    (inputs
     `(("python-pip" ,python-pip)
       ("python-setuptools" ,python-setuptools)
       ;; Tests
       ("python-testtools" ,python-testtools)))
    (arguments
     '(#:tests? #f)) ; no setup.py test command
    (home-page "https://launchpad.net/python-fixtures")
    (synopsis "Python test fixture library")
    (description
     "Fixtures provides a way to create reusable state, useful when writing
Python tests.")
    (license (list bsd-3 asl2.0)))) ; at user's option

(define-public python2-fixtures
  (package-with-python2 python-fixtures))

(define-public python-testrepository
  (package
    (name "python-testrepository")
    (version "0.0.20")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/t/testrepository/testrepository-"
             version ".tar.gz"))
       (sha256
        (base32
         "1ssqb07c277010i6gzzkbdd46gd9mrj0bi0i8vn560n2k2y4j93m"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-fixtures-0.3.16" ,python-fixtures-0.3.16)
       ("python-testtools" ,python-testtools)))
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-subunit" ,python-subunit)
       ("python-mimeparse" ,python-mimeparse)))
    (home-page "https://launchpad.net/testrepository")
    (synopsis "Database for Python test results")
    (description "Testrepository provides a database of test results which can
be used as part of a developer's workflow to check things such as what tests
have failed since the last commit or what tests are currently failing.")
    (license (list bsd-3 asl2.0)))) ; at user's option

(define-public python2-testrepository
  (package-with-python2 python-testrepository))

(define-public python-coverage
  (package
    (name "python-coverage")
    (version "4.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "coverage" version))
       (sha256
        (base32
         "0qjlja8ny4gcfp8abqfwdrvr8qw9kr69lkja0b4cqqbsdmdjgcc5"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://nedbatchelder.com/code/coverage")
    (synopsis "Code coverage measurement for Python")
    (description
     "Coverage measures code coverage, typically during test execution.  It
uses the code analysis tools and tracing hooks provided in the Python standard
library to determine which lines are executable, and which have been
executed.")
    (license bsd-3)))

(define-public python2-coverage
  (package-with-python2 python-coverage))

(define-public python-discover
  (package
    (name "python-discover")
    (version "0.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/d/discover/discover-"
             version ".tar.gz"))
       (sha256
        (base32
         "0y8d0zwiqar51kxj8lzmkvwc3b8kazb04gk5zcb4nzg5k68zmhq5"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://pypi.python.org/pypi/discover/")
    (synopsis
     "Python test discovery for unittest")
    (description
     "Discover provides test discovery for unittest, a feature that has been
backported from Python 2.7 for Python 2.4+.")
    (license bsd-3)))

(define-public python2-discover
  (package-with-python2 python-discover))

(define-public behave
  (package
    (name "behave")
    (version "1.2.4")
    (source (origin
             (method url-fetch)
             (uri (string-append "https://pypi.python.org/packages/source/b/"
                                 name "/" name "-" version ".tar.gz"))
             (sha256
              (base32
               "1v2rfy8xnf0rk7cj4cgr7lam4015d458i7bg0xqs9czfv6njlm14"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-six" ,python-six)
       ("python-parse" ,python-parse)
       ("python-parse-type" ,python-parse-type)))
    (arguments `(#:tests? #f))          ;TODO: tests require nose>=1.3 and
                                        ;PyHamcrest>=1.8
    (home-page "http://github.com/behave/behave")
    (synopsis "Python behavior-driven development")
    (description
     "Behave is a tool for behavior-driven development in python.
Behavior-driven development (or BDD) is an agile software development
technique that encourages collaboration between developers, QA and
non-technical or business participants in a software project.  Behave uses
tests written in a natural language style, backed up by Python code.")
    (license x11)))

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
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (arguments `(#:tests? #f)) ; no tests
    (home-page "https://github.com/ianare/exif-py")
    (synopsis "Python library to extract EXIF data from image files")
    (description
     "ExifRead is a Python library to extract EXIF data from tiff and jpeg
files.")
    (license bsd-3)))

(define-public python2-exif-read
  (package-with-python2 python-exif-read))

(define-public python-pyld
  (package
    (name "python-pyld")
    (version "0.6.8")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "PyLD" version))
              (sha256
               (base32
                "0k881ffazpf8q1z8862g4bb3pzwpnz9whrci2mf311mvn1qbyqad"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (arguments `(#:tests? #f)) ; no tests
    (home-page "http://github.com/digitalbazaar/pyld")
    (synopsis "Python implementation of the JSON-LD specification")
    (description
     "PyLD is an implementation of the JSON-LD specification.")
    (license bsd-3)))

(define-public python2-pyld
  (package-with-python2 python-pyld))

(define-public python-certifi
  (package
    (name "python-certifi")
    (version "2015.11.20.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "certifi" version))
              (sha256
               (base32
                "05lgwf9rz1kn465azy2bpb3zmpnsn9gkypbhnjlclchv98ssgc1h"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (arguments `(#:tests? #f)) ; no tests
    (home-page "http://python-requests.org/")
    (synopsis "Python CA certificate bundle")
    (description
     "Certifi is a Python library that contains a CA certificate bundle, which
is used by the Requests library to verify HTTPS requests.")
    (license asl2.0)))

(define-public python2-certifi
  (package-with-python2 python-certifi))

(define-public python-click
  (package
    (name "python-click")
    (version "6.2")
    (source
     (origin
       (method url-fetch)
         (uri (pypi-uri "click" version))
       (sha256
        (base32 "10kavbisnk9m93jl2wi34pw7ryr2qbxshh2cysxwxd7bymqgz87v"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://click.pocoo.org")
    (synopsis "Command line library for Python")
    (description
     "Click is a Python package for creating command line interfaces in a
composable way with as little code as necessary.  Its name stands for
\"Command Line Interface Creation Kit\".  It's highly configurable but comes
with sensible defaults out of the box.")
    (license bsd-3)))

(define-public python2-click
  (package-with-python2 python-click))

(define-public python-wheel
  (package
    (name "python-wheel")
    (version "0.29.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "wheel" version))
        (sha256
         (base32
          "0j0n38hg1jvrmyy68f9ikvzq1gs9g0sx4ws7maf8wi3bwbbqmfqy"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-jsonschema" ,python-jsonschema)
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


(define-public python-requests
  (package
    (name "python-requests")
    (version "2.9.1")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "requests" version))
             (sha256
              (base32
               "0zsqrzlybf25xscgi7ja4s48y2abf9wvjkn47wh984qgs1fq2xy5"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (propagated-inputs
     `(("python-py" ,python-py)
       ("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-wheel" ,python-wheel)))
    (home-page "http://python-requests.org/")
    (synopsis "Python HTTP library")
    (description
     "Requests is a Python HTTP client library.  It aims to be easier to use
than Python’s urllib2 library.")
    (license asl2.0)))

;; Some software requires an older version of Requests, notably Docker
;; Compose.
(define-public python-requests-2.7
  (package (inherit python-requests)
    (version "2.7.0")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "requests" version))
             (sha256
              (base32
               "0gdr9dxm24amxpbyqpbh3lbwxc2i42hnqv50sigx568qssv3v2ir"))))))

(define-public python2-requests
  (package-with-python2 python-requests))

(define-public python-vcversioner
  (package
    (name "python-vcversioner")
    (version "2.14.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "vcversioner" version))
       (sha256
        (base32
         "11ivq1bm7v0yb4nsfbv9m7g7lyjn112gbvpjnjz8nv1fx633dm5c"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (synopsis "Python library for version number discovery")
    (description "Vcversioner is a Python library that inspects tagging
information in a variety of version control systems in order to discover
version numbers.")
    (home-page "https://github.com/habnabit/vcversioner")
    (license isc)))

(define-public python2-vcversioner
  (package-with-python2 python-vcversioner))

(define-public python-jsonschema
  (package
    (name "python-jsonschema")
    (version "2.5.1")
    (source (origin
             (method url-fetch)
             (uri
              (string-append
               "https://pypi.python.org/packages/source/j/jsonschema/jsonschema-"
               version ".tar.gz"))
             (sha256
              (base32
               "0hddbqjm4jq63y8jf44nswina1crjs16l9snb6m3vvgyg31klrrn"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-vcversioner" ,python-vcversioner)))
    (home-page "http://github.com/Julian/jsonschema")
    (synopsis "Implementation of JSON Schema for Python")
    (description
     "Jsonschema is an implementation of JSON Schema for Python.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-jsonschema))))))

(define-public python2-jsonschema
  (let ((jsonschema (package-with-python2
                     (strip-python2-variant python-jsonschema))))
    (package (inherit jsonschema)
      (inputs
       `(("python2-functools32" ,python2-functools32)
         ,@(package-inputs jsonschema))))))

(define-public python-unidecode
  (package
    (name "python-unidecode")
    (version "0.04.18")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "Unidecode" version))
             (sha256
              (base32
               "12hhblqy1ajvidm38im4171x4arg83pfmziyn53nizp29p3m14gi"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://pypi.python.org/pypi/Unidecode")
    (synopsis "ASCII transliterations of Unicode text")
    (description
     "Unidecode provides ASCII transliterations of Unicode text.  Unidecode is
useful when integrating with legacy code that doesn't support Unicode, or for
ease of entry of non-Roman names on a US keyboard, or when constructing ASCII
machine identifiers from human-readable Unicode strings that should still be
somewhat intelligeble.")
    (license gpl2+)))

(define-public python2-unidecode
  (package-with-python2 python-unidecode))

(define-public python-pyjwt
  (package
    (name "python-pyjwt")
    (version "1.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "PyJWT" version))
       (sha256
        (base32
         "1556v2jppd8mjkkj66pxb5rcazm35jq81r233mdl8hfmz9n3icp1"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-pytest-runner" ,python-pytest-runner)))
    (arguments
     '(#:tests? #f)) ; test suite doesn't work
    (home-page "http://github.com/progrium/pyjwt")
    (synopsis "JSON Web Token implementation in Python")
    (description
     "PyJWT is a JSON Web Token implementation written in Python.")
    (license license:expat)))

(define-public python2-pyjwt
  (package-with-python2 python-pyjwt))

(define-public python-oauthlib
  (package
    (name "python-oauthlib")
    (version "1.0.3")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "oauthlib" version))
              (sha256
               (base32
                "1bfrj70vdjxjw74khbyh6f0dksv7p5rh2346jnlrffyacd3gwjzg"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-coverage" ,python-coverage)
       ("python-nose" ,python-nose)
       ("python-mock" ,python-mock)))
    (inputs
     `(("python-blinker" ,python-blinker)
       ("python-cryptography" ,python-cryptography)
       ("python-pyjwt" ,python-pyjwt)))
    (home-page "https://github.com/idan/oauthlib")
    (synopsis "OAuth implementation for Python")
    (description
     "Oauthlib is a generic, spec-compliant, thorough implementation of the
OAuth request-signing logic.")
    (license bsd-3)))

(define-public python2-oauthlib
  (let ((base (package-with-python2 python-oauthlib)))
    (package
      (inherit base)
      (inputs
       `(("python2-unittest2" ,python2-unittest2)
         ("python2-cryptography" ,python2-cryptography)
         ,@(alist-delete "python-cryptography"
	                 (package-inputs base)))))))

(define-public python-itsdangerous
  (package
    (name "python-itsdangerous")
    (version "0.24")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/i/itsdangerous/itsdangerous-"
             version ".tar.gz"))
       (sha256
        (base32
         "06856q6x675ly542ig0plbqcyab6ksfzijlyf1hzhgg3sgwgrcyb"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://github.com/mitsuhiko/itsdangerous")
    (synopsis "Python library for passing data to/from untrusted environments")
    (description
     "Itsdangerous provides various helpers to pass trusted data to untrusted
environments and back.")
    (license bsd-3)))

(define-public python2-itsdangerous
  (package-with-python2 python-itsdangerous))

(define-public python-pyyaml
  (package
    (name "python-pyyaml")
    (version "3.11")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/P/PyYAML/PyYAML-"
             version ".tar.gz"))
       (sha256
        (base32
         "1s26125vfnskng58ym37xhwv8v0mm95b2cwbjfag8prfhy596v63"))))
    (build-system python-build-system)
    (inputs
     `(("libyaml" ,libyaml)))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
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

(define-public python-virtualenv
  (package
    (name "python-virtualenv")
    (version "13.1.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "virtualenv" version))
       (sha256
        (base32
         "1p732accxwqfjbdna39k8w8lp9gyw91vr4kzkhm8mgfxikqqxg5a"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
        (replace 'check
         (lambda _ (zero? (system* "py.test")))))))
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-mock" ,python-mock)
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
    (version "0.23")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/M/MarkupSafe/MarkupSafe-"
             version ".tar.gz"))
       (sha256
        (base32
         "1hvip33wva3fnmvfp9x5klqri7hpl1hkgqmjbss18nmrb7zimv54"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://github.com/mitsuhiko/markupsafe")
    (synopsis "XML/HTML/XHTML markup safe string implementation for Python")
    (description
     "Markupsafe provides an XML/HTML/XHTML markup safe string implementation
for Python.")
    (license bsd-3)))

(define-public python2-markupsafe
  (package-with-python2 python-markupsafe))

(define-public python-jinja2
  (package
    (name "python-jinja2")
    (version "2.8")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Jinja2" version))
       (sha256
        (base32
         "1x0v41lp5m1pjix3l46zx02b7lqp2hflgpnxwkywxynvi3zz47xw"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-markupsafe" ,python-markupsafe)))
    (home-page "http://jinja.pocoo.org/")
    (synopsis "Python template engine")
    (description
     "Jinja2 is a small but fast and easy to use stand-alone template engine
written in pure Python.")
    (license bsd-3)))

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
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://defunkt.io/pystache/")
    (synopsis "Python logic-less template engine")
    (description
     "Pystache is a Python implementation of the framework agnostic,
logic-free templating system Mustache.")
    (license license:expat)))

(define-public python2-pystache
  (package-with-python2 python-pystache))

(define-public python-joblib
  (package
    (name "python-joblib")
    (version "0.9.0b4")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://pypi.python.org/packages/source/"
                                  "j/joblib/joblib-" version ".tar.gz"))
              (sha256
               (base32
                "1dvw3f8jgj6h0fxkghbgyclvdzc7l0ig7n0vis70awb5kczb9bs3"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-nose"       ,python-nose)))
    (home-page "http://pythonhosted.org/joblib/")
    (synopsis "Using Python functions as pipeline jobs")
    (description
     "Joblib is a set of tools to provide lightweight pipelining in Python.
In particular, joblib offers: transparent disk-caching of the output values
and lazy re-evaluation (memoize pattern), easy simple parallel computing
logging and tracing of the execution.")
    (license bsd-3)))

(define-public python2-joblib
  (package-with-python2 python-joblib))

(define-public python-docutils
  (package
    (name "python-docutils")
    (version "0.12")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/d/docutils/docutils-"
             version ".tar.gz"))
       (sha256
        (base32
         "1ylnjnw1x4b2y7blr6x35ncdzn69k253kw4cdkv6asdb21w73ny7"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
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
    (license (list public-domain psfl bsd-2 gpl3+))))

(define-public python2-docutils
  (package-with-python2 python-docutils))

(define-public python-pygments
  (package
    (name "python-pygments")
    (version "2.0.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Pygments" version))
       (sha256
        (base32
         "0lagrwifsgn0s8bzqahpr87p7gd38xja8f06akscinp6hj89283k"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://pygments.org/")
    (synopsis "Syntax highlighting")
    (description
     "Pygments is a syntax highlighting package written in Python.")
    (license bsd-2)))

(define-public python2-pygments
  (package-with-python2 python-pygments))

(define-public python-sphinx
  (package
    (name "python-sphinx")
    (version "1.2.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/S/Sphinx/Sphinx-"
             version ".tar.gz"))
       (sha256
        (base32
         "011xizm3jnmf4cvs5i6kgf6c5nn046h79i8j0vd0f27yw9j3p4wl"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-jinja2" ,python-jinja2)
       ("python-docutils" ,python-docutils)
       ("python-pygments" ,python-pygments)))
    (home-page "http://sphinx-doc.org/")
    (synopsis "Python documentation generator")
    (description "Sphinx is a tool that makes it easy to create documentation
for Python projects or other documents consisting of multiple reStructuredText
sources.")
    (license bsd-3)))

(define-public python2-sphinx
  (package-with-python2 python-sphinx))

(define-public python-sphinx-rtd-theme
  (package
    (name "python-sphinx-rtd-theme")
    (version "0.1.6")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/s/"
                           "sphinx_rtd_theme/sphinx_rtd_theme-"
                           version ".tar.gz"))
       (sha256
        (base32
         "19nw3rn7awplcdrz63kg1njqwkbymfg9lwn7l2grhdyhyr2gaa8g"))))
    (build-system python-build-system)
    (arguments
     `(;; With standard flags, the install phase attempts to create a zip'd
       ;; egg file, and fails with an error: 'ZIP does not support timestamps
       ;; before 1980'
       #:configure-flags '("--single-version-externally-managed"
                           "--record=sphinx-rtd-theme.txt")))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (inputs
     `(("python-docutils" ,python-docutils)
       ("python-sphinx" ,python-sphinx)))
    (home-page "https://github.com/snide/sphinx_rtd_theme/")
    (synopsis "ReadTheDocs.org theme for Sphinx")
    (description "A theme for Sphinx used by ReadTheDocs.org.")
    (license license:expat)))

(define-public python2-sphinx-rtd-theme
  (package-with-python2 python-sphinx-rtd-theme))

(define-public python-feedgenerator
  (package
    (name "python-feedgenerator")
    (version "20150710.97185b7")
    (source
     ;; Using the git checkout for now because license file not added till
     ;; https://github.com/dmdm/feedgenerator-py3k/commit/97185b7566c240c4bf5ed80db7d6c271204dab39
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/dmdm/feedgenerator-py3k.git")
             (commit "97185b7566c240c4bf5ed80db7d6c271204dab39")))
       (sha256
        (base32
         "0dbd6apij5j1923ib905x0srgcyls4wlabqlwp4dzkwmksvnrr2a"))))
    (arguments
     `(;; With standard flags, the install phase attempts to create a zip'd
       ;; egg file, and fails with an error: 'ZIP does not support timestamps
       ;; before 1980'
       #:configure-flags '("--single-version-externally-managed"
                           "--record=feedgenerator.txt")))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-pytz" ,python-pytz)
       ("python-six" ,python-six)))
    (home-page
     "https://github.com/dmdm/feedgenerator-py3k.git")
    (synopsis
     "Standalone version of Django's Atom/RSS feed generator")
    (description
     "Feedgenerator-py3k is a standalone version of Django's feedgenerator,
which can produce feeds in RSS 2.0, RSS 0.91, and Atom formats.")
    (license bsd-3)))

(define-public python2-feedgenerator
  (package-with-python2 python-feedgenerator))

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
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    ;; No "test" command supplied to setuptools, so unless there's another way
    ;; to run tests, we're skipping them!
    (arguments '(#:tests? #f))
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
    (version "3.6.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pelican" version))
       (sha256
        (base32
         "1hn94rb4q3zmcq16in055xikal4dba5hfx3zznq7warllcgc9f8k"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (propagated-inputs
     `(("python-feedgenerator" ,python-feedgenerator)
       ("python-jinja2" ,python-jinja2)
       ("python-pygments" ,python-pygments)
       ("python-docutils" ,python-docutils)
       ("python-pytz" ,python-pytz)
       ("python-blinker" ,python-blinker)
       ("python-unidecode" ,python-unidecode)
       ("python-six" ,python-six)
       ("python-dateutil-2" ,python-dateutil-2)))
    (home-page "http://getpelican.com/")
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
    (license agpl3+)))

(define-public python-scikit-learn
  (package
    (name "python-scikit-learn")
    (version "0.16.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/scikit-learn/scikit-learn/archive/"
             version ".tar.gz"))
       (sha256
        (base32
         "140skabifgc7lvvj873pnzlwx0ni6q8qkrsyad2ccjb3h8rxzkih"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (alist-cons-before
        'check 'set-HOME
        ;; some tests require access to "$HOME"
        (lambda _ (setenv "HOME" "/tmp"))
        ;; Tests can only be run after the library has been installed and not
        ;; within the source directory.
        (alist-cons-after
         'install 'check
         (lambda _
           (with-directory-excursion "/tmp"
             ;; With Python 3 one test of 3334 fails
             ;; (sklearn.tests.test_common.test_transformers); see
             ;; https://github.com/scikit-learn/scikit-learn/issues/3693
             (system* "nosetests" "-v" "sklearn")))
         (alist-delete 'check %standard-phases)))))
    (inputs
     `(("openblas" ,openblas)
       ("python-nose" ,python-nose)))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-scipy" ,python-scipy)))
    (home-page "http://scikit-learn.org/")
    (synopsis "Machine Learning in Python")
    (description
     "Scikit-learn provides simple and efficient tools for data
mining and data analysis.")
    (license bsd-3)))

(define-public python2-scikit-learn
  (let ((scikit (package-with-python2 python-scikit-learn)))
    (package (inherit scikit)
      (propagated-inputs
       `(("python2-numpy" ,python2-numpy)
         ("python2-scipy" ,python2-scipy)
         ,@(alist-delete
            "python-numpy"
            (alist-delete
             "python-scipy" (package-propagated-inputs scikit))))))))

(define-public python-scikit-image
  (package
    (name "python-scikit-image")
    (version "0.11.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/s/scikit-image/scikit-image-"
             version ".tar.gz"))
       (sha256
        (base32 "0jz416fqvpahqyffw8plmszzfj669w8wvf3y9clnr5lr6a7md3kn"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-matplotlib" ,python-matplotlib)
       ("python-networkx" ,python-networkx)
       ("python-numpy" ,python-numpy)
       ("python-scipy" ,python-scipy)
       ("python-six" ,python-six)
       ("python-pillow" ,python-pillow)))
    (native-inputs
     `(("python-cython" ,python-cython)
       ("python-setuptools" ,python-setuptools)))
    (home-page "http://scikit-image.org/")
    (synopsis "Image processing in Python")
    (description
     "Scikit-image is a collection of algorithms for image processing.")
    (license bsd-3)))

(define-public python2-scikit-image
  (let ((scikit-image (package-with-python2 python-scikit-image)))
    (package (inherit scikit-image)
      (native-inputs
       `(("python2-mock" ,python2-mock)
         ,@(package-native-inputs scikit-image)))
      (propagated-inputs
       `(("python2-pytz" ,python2-pytz)
         ("python2-matplotlib" ,python2-matplotlib)
         ("python2-numpy" ,python2-numpy)
         ("python2-scipy" ,python2-scipy)
         ,@(fold alist-delete (package-propagated-inputs scikit-image)
                 '("python-matplotlib" "python-numpy" "python-scipy")))))))

(define-public python-redis
  (package
    (name "python-redis")
    (version "2.10.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/r/redis/redis-"
             version ".tar.gz"))
       (sha256
        (base32 "1701qjwn4n05q90fdg4bsg96s27xf5s4hsb4gxhv3xk052q3gyx4"))))
    (build-system python-build-system)
    ;; Tests require a running Redis server
    (arguments '(#:tests? #f))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-pytest" ,python-pytest)))
    (home-page "https://github.com/andymccurdy/redis-py")
    (synopsis "Redis Python client")
    (description
     "This package provides a Python interface to the Redis key-value store.")
    (license license:expat)))

(define-public python2-redis
  (package-with-python2 python-redis))

(define-public python-rq
  (package
    (name "python-rq")
    (version "0.5.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/r/rq/rq-"
             version ".tar.gz"))
       (sha256
        (base32 "0b0z5hn8wkfg300hx7816csgv3bcfamlr29fi3yzgqmpqxwj3fix"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-click" ,python-click)
       ("python-redis" ,python-redis)))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://python-rq.org/")
    (synopsis "Simple job queues for Python")
    (description
     "RQ (Redis Queue) is a simple Python library for queueing jobs and
processing them in the background with workers.  It is backed by Redis and it
is designed to have a low barrier to entry.")
    (license bsd-2)))

(define-public python2-rq
  (package-with-python2 python-rq))

(define-public python-cython
  (package
    (name "python-cython")
    (version "0.23.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Cython" version))
       (sha256
        (base32
         "13hdffhd37mx3gjby018xl179jaj957fy7kzi01crmimxvn2zi7y"))))
    (build-system python-build-system)
    ;; we need the full python package and not just the python-wrapper
    ;; because we need libpython3.3m.so
    (inputs
     `(("python" ,python)))
    (arguments
     `(#:phases
       (alist-cons-before
        'check 'set-HOME
        ;; some tests require access to "$HOME/.cython"
        (lambda* _ (setenv "HOME" "/tmp"))
        (alist-replace
         'check
         (lambda _ (zero? (system* "python" "runtests.py" "-vv")))
         %standard-phases))))
    (home-page "http://cython.org/")
    (synopsis "C extensions for Python")
    (description "Cython is an optimising static compiler for both the Python
programming language and the extended Cython programming language.  It makes
writing C extensions for Python as easy as Python itself.")
    (license asl2.0)
    (properties `((python2-variant . ,(delay python2-cython))))))

(define-public python2-cython
  (package (inherit (package-with-python2
                     (strip-python2-variant python-cython)))
    (name "python2-cython")
    (inputs
     `(("python-2" ,python-2))))) ; this is not automatically changed

;; This version of numpy is missing the documentation and is only used to
;; build matplotlib which is required to build numpy's documentation.
(define python-numpy-bootstrap
  (package
    (name "python-numpy-bootstrap")
    (version "1.10.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/numpy"
                           "/numpy-" version ".tar.gz"))
       (sha256
        (base32
         "1bjjhvncraka5s6i4lg644jrxij6bvycxy7an20gcz3a0m11iygp"))))
    (build-system python-build-system)
    (inputs
     `(("python-nose" ,python-nose)
       ("openblas" ,openblas)
       ("lapack" ,lapack)))
    (native-inputs
     `(("gfortran" ,gfortran)))
    (arguments
     `(#:phases
       (alist-cons-before
        'build 'set-environment-variables
        (lambda* (#:key inputs #:allow-other-keys)
          (call-with-output-file "site.cfg"
            (lambda (port)
              (format port
                      "[openblas]
libraries = openblas
library_dirs = ~a/lib
include_dirs = ~a/include

[lapack]
lapack_libs = lapack
library_dirs = ~a/lib
include_dirs = ~a/include
"
                      (assoc-ref inputs "openblas")
                      (assoc-ref inputs "openblas")
                      (assoc-ref inputs "lapack")
                      (assoc-ref inputs "lapack"))))
          ;; Use "gcc" executable, not "cc".
          (substitute* "numpy/distutils/system_info.py"
            (("c = distutils\\.ccompiler\\.new_compiler\\(\\)")
             "c = distutils.ccompiler.new_compiler(); c.set_executables(compiler='gcc',compiler_so='gcc',linker_exe='gcc',linker_so='gcc -shared')"))
          #t)
        ;; Tests can only be run after the library has been installed and not
        ;; within the source directory.
        (alist-cons-after
         'install 'check
         (lambda _
           (with-directory-excursion "/tmp"
             (zero? (system* "python" "-c"
                             "import numpy; numpy.test(verbose=2)"))))
         (alist-delete
          'check
          %standard-phases)))))
    (home-page "http://www.numpy.org/")
    (synopsis "Fundamental package for scientific computing with Python")
    (description "NumPy is the fundamental package for scientific computing
with Python.  It contains among other things: a powerful N-dimensional array
object, sophisticated (broadcasting) functions, tools for integrating C/C++
and Fortran code, useful linear algebra, Fourier transform, and random number
capabilities.")
    (license bsd-3)))

(define python2-numpy-bootstrap
  (package-with-python2 python-numpy-bootstrap))

(define-public python2-fastlmm
  (package
    (name "python2-fastlmm")
    (version "0.2.21")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "fastlmm" version ".zip"))
       (sha256
        (base32
         "1q8c34rpmwkfy3r4d5172pzdkpfryj561897z9r3x22gq7813x1m"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2)) ; only Python 2.7 is supported
    (propagated-inputs
     `(("python2-numpy" ,python2-numpy)
       ("python2-scipy" ,python2-scipy)
       ("python2-matplotlib" ,python2-matplotlib)
       ("python2-pandas" ,python2-pandas)
       ("python2-scikit-learn" ,python2-scikit-learn)
       ("python2-cython" ,python2-cython)
       ("python2-pysnptools" ,python2-pysnptools)))
    (native-inputs
     `(("unzip" ,unzip)
       ("python2-mock" ,python2-mock)
       ("python2-setuptools" ,python2-setuptools)))
    (home-page "http://research.microsoft.com/en-us/um/redmond/projects/mscompbio/fastlmm/")
    (synopsis "Perform genome-wide association studies on large data sets")
    (description
     "FaST-LMM, which stands for Factored Spectrally Transformed Linear Mixed
Models, is a program for performing both single-SNP and SNP-set genome-wide
association studies (GWAS) on extremely large data sets.")
    (license asl2.0)))

(define-public python-numpy
  (package (inherit python-numpy-bootstrap)
    (name "python-numpy")
    (outputs '("out" "doc"))
    (inputs
     `(("which" ,which)
       ("python-setuptools" ,python-setuptools)
       ("python-matplotlib" ,python-matplotlib)
       ("python-sphinx" ,python-sphinx)
       ("python-pyparsing" ,python-pyparsing)
       ("python-numpydoc" ,python-numpydoc)
       ,@(package-inputs python-numpy-bootstrap)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("texlive" ,texlive)
       ("texinfo" ,texinfo)
       ("perl" ,perl)
       ,@(package-native-inputs python-numpy-bootstrap)))
    (arguments
     `(,@(substitute-keyword-arguments
             (package-arguments python-numpy-bootstrap)
           ((#:phases phases)
            `(alist-cons-after
              'install 'install-doc
              (lambda* (#:key outputs #:allow-other-keys)
                (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                       (doc (string-append
                             data "/doc/" ,name "-"
                             ,(package-version python-numpy-bootstrap)))
                       (info (string-append data "/info"))
                       (html (string-append doc "/html"))
                       (pyver ,(string-append "PYVER=")))
                  (with-directory-excursion "doc"
                    (mkdir-p html)
                    (system* "make" "html" pyver)
                    (system* "make" "latex" "PAPER=a4" pyver)
                    (system* "make" "-C" "build/latex"
                             "all-pdf" "PAPER=a4" pyver)
                    ;; FIXME: Generation of the info file fails.
                    ;; (system* "make" "info" pyver)
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
                                (find-files "." ".*"))))))
              ,phases)))))))

(define-public python2-numpy
  (package-with-python2 python-numpy))

(define-public python-pyparsing
  (package
    (name "python-pyparsing")
    (version "2.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/pyparsing"
                           "/pyparsing-" version ".tar.gz"))
       (sha256
        (base32
         "0kw4py7gn45j93q8r7bzajfrjdc3xlsn2yzln41lf9zmrghjkrq6"))))
    (build-system python-build-system)
    (outputs '("out" "doc"))
    (arguments
     `(#:tests? #f ; no test target
       #:modules ((guix build python-build-system)
                  (guix build utils))
       #:phases
       (alist-cons-after
        'install 'install-doc
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
             (list doc html-doc examples))))
        %standard-phases)))
    (home-page "http://pyparsing.wikispaces.com")
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
    (version "0.5")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/n/numpydoc/numpydoc-"
             version ".tar.gz"))
       (sha256
        (base32
         "0d4dnifaxkll50jx6czj05y8cb4ny60njd2wz299sj2jxfy51w4k"))
       (modules '((guix build utils)))
       (snippet
        '(begin
           ;; Drop a test requiring matplotlib, which we cannot add as an
           ;; input since it would create a circular dependency: Extend the
           ;; test for Python 3, where it is already dropped, to Python 2.
           (substitute* "numpydoc/tests/test_plot_directive.py"
             (("3") "2"))))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-docutils" ,python-docutils)
       ("python-sphinx" ,python-sphinx)
       ("python-nose" ,python-nose)))
    (home-page "https://pypi.python.org/pypi/numpydoc")
    (synopsis
     "Numpy's Sphinx extensions")
    (description
     "Sphinx extension to support docstrings in Numpy format.")
    (license bsd-2)))

(define-public python2-numpydoc
  (package-with-python2 python-numpydoc))

(define-public python-numexpr
  (package
    (name "python-numexpr")
    (version "2.4.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/"
                           "n/numexpr/numexpr-" version ".tar.gz"))
       (sha256
        (base32
         "0nsnff5312fm38w6dm34bw7ghfqqy8vl9gig0al963h4mz8zm8nz"))))
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
  (let ((numexpr (package-with-python2 python-numexpr)))
    (package (inherit numexpr)
      ;; Make sure to use special packages for Python 2 instead
      ;; of those automatically rewritten by package-with-python2.
      (propagated-inputs
       `(("python2-numpy" ,python2-numpy)
         ,@(alist-delete "python-numpy"
                         (package-propagated-inputs numexpr)))))))

(define-public python-matplotlib
  (package
    (name "python-matplotlib")
    (version "1.4.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/matplotlib"
                           "/matplotlib-" version ".tar.gz"))
       (sha256
        (base32
         "1dn05cvd0g984lzhh72wa0z93psgwshbbg93fkab6slx5m3l95av"))
       (patches (list (search-patch "matplotlib-setupext-tk.patch")))))
    (build-system python-build-system)
    (outputs '("out" "doc"))
    (propagated-inputs ; the following packages are all needed at run time
     `(("python-pyparsing" ,python-pyparsing)
       ("python-pygobject" ,python-pygobject)
       ("gobject-introspection" ,gobject-introspection)
       ("python-tkinter" ,python "tk")
       ;; The 'gtk+' package (and 'gdk-pixbuf', 'atk' and 'pango' propagated
       ;; from 'gtk+') provides the required 'typelib' files used by
       ;; 'gobject-introspection'. The location of these files is set with the
       ;; help of the environment variable GI_TYPELIB_PATH. At build time this
       ;; is done automatically by a 'native-search-path' procedure. However,
       ;; at run-time the user must set this variable as follows:
       ;;
       ;; export GI_TYPELIB_PATH=~/.guix-profile/lib/girepository-1.0
       ("gtk+" ,gtk+)
       ;; From version 1.4.0 'matplotlib' makes use of 'cairocffi' instead of
       ;; 'pycairo'. However, 'pygobject' makes use of a 'pycairo' 'context'
       ;; object. For this reason we need to import both libraries.
       ;; https://pythonhosted.org/cairocffi/cffi_api.html#converting-pycairo
       ("python-pycairo" ,python-pycairo)
       ("python-cairocffi" ,python-cairocffi)))
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-dateutil" ,python-dateutil-2)
       ("python-six" ,python-six)
       ("python-pytz" ,python-pytz)
       ("python-numpy" ,python-numpy-bootstrap)
       ("python-sphinx" ,python-sphinx)
       ("python-numpydoc" ,python-numpydoc)
       ("python-nose" ,python-nose)
       ("python-mock" ,python-mock)
       ("libpng" ,libpng)
       ("imagemagick" ,imagemagick)
       ("freetype" ,freetype)
       ("cairo" ,cairo)
       ("glib" ,glib)
       ("python-pillow" ,python-pillow)
       ;; FIXME: Add backends when available.
       ;("python-wxpython" ,python-wxpython)
       ;("python-pyqt" ,python-pyqt)
       ("tcl" ,tcl)
       ("tk" ,tk)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("texlive" ,texlive)
       ("texinfo" ,texinfo)))
    (arguments
     `(#:phases
       (alist-cons-before
        'build 'configure-environment
        (lambda* (#:key outputs inputs #:allow-other-keys)
          (let ((cairo (assoc-ref inputs "cairo"))
                (gtk+ (assoc-ref inputs "gtk+")))
            ;; Setting these directories in the 'basedirlist' of 'setup.cfg'
            ;; has not effect.
            (setenv "LD_LIBRARY_PATH"
                    (string-append cairo "/lib:" gtk+ "/lib"))
            (setenv "HOME" (getcwd))
            (call-with-output-file "setup.cfg"
              (lambda (port)
                (format port "[directories]~%
basedirlist = ~a,~a~%
 [rc_options]~%
backend = TkAgg~%"
                        (assoc-ref inputs "tcl")
                        (assoc-ref inputs "tk"))))))
        (alist-cons-after
         'install 'install-doc
         (lambda* (#:key outputs #:allow-other-keys)
           (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                  (doc (string-append data "/doc/" ,name "-" ,version))
                  (info (string-append data "/info"))
                  (html (string-append doc "/html")))
             (with-directory-excursion "doc"
               ;; Produce pdf in 'A4' format.
               (substitute* (find-files "." "conf\\.py")
                 (("latex_paper_size = 'letter'")
                  "latex_paper_size = 'a4'"))
               (mkdir-p html)
               (mkdir-p info)
               ;; The doc recommends to run the 'html' target twice.
               (system* "python" "make.py" "html")
               (system* "python" "make.py" "html")
               (copy-recursively "build/html" html)
               (system* "python" "make.py" "latex")
               (system* "python" "make.py" "texinfo")
               (symlink (string-append html "/_images")
                        (string-append info "/matplotlib-figures"))
               (with-directory-excursion "build/texinfo"
                 (substitute* "matplotlib.texi"
                   (("@image\\{([^,]*)" all file)
                    (string-append "@image{matplotlib-figures/" file)))
                 (symlink (string-append html "/_images")
                          "./matplotlib-figures")
                 (system* "makeinfo" "--no-split"
                          "-o" "matplotlib.info" "matplotlib.texi"))
               (copy-file "build/texinfo/matplotlib.info"
                          (string-append info "/matplotlib.info"))
               (copy-file "build/latex/Matplotlib.pdf"
                          (string-append doc "/Matplotlib.pdf")))))
        %standard-phases))))
    (home-page "http://matplotlib.org")
    (synopsis "2D plotting library for Python")
    (description
     "Matplotlib is a Python 2D plotting library which produces publication
quality figures in a variety of hardcopy formats and interactive environments
across platforms.  Matplotlib can be used in Python scripts, the python and
ipython shell, web application servers, and six graphical user interface
toolkits.")
    (license psfl)
    (properties `((python2-variant . ,(delay python2-matplotlib))))))

(define-public python2-matplotlib
  (let ((matplotlib (package-with-python2
                     (strip-python2-variant python-matplotlib))))
    (package (inherit matplotlib)
      ;; Make sure to use special packages for Python 2 instead
      ;; of those automatically rewritten by package-with-python2.
      (propagated-inputs
       `(("python2-pycairo" ,python2-pycairo)
         ("python2-pygobject-2" ,python2-pygobject-2)
         ("python2-tkinter" ,python-2 "tk")
         ,@(fold alist-delete (package-propagated-inputs matplotlib)
                 '("python-pycairo" "python-pygobject" "python-tkinter")))))))

(define-public python2-pysnptools
  (package
    (name "python2-pysnptools")
    (version "0.3.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pysnptools" version ".zip"))
       (sha256
        (base32
         "15f4j4w5q603i7mlphb5r6mb1mn33pqg81595fpjp158140yqx7b"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2)) ; only Python 2.7 is supported
    (propagated-inputs
     `(("python2-numpy" ,python2-numpy)
       ("python2-scipy" ,python2-scipy)
       ("python2-pandas" ,python2-pandas)
       ("python2-cython" ,python2-cython)))
    (native-inputs
     `(("unzip" ,unzip)
       ("python2-setuptools" ,python2-setuptools)))
    (home-page "http://research.microsoft.com/en-us/um/redmond/projects/mscompbio/")
    (synopsis "Library for reading and manipulating genetic data")
    (description
     "PySnpTools is a library for reading and manipulating genetic data.  It
can, for example, efficiently read whole PLINK *.bed/bim/fam files or parts of
those files.  It can also efficiently manipulate ranges of integers using set
operators such as union, intersection, and difference.")
    (license asl2.0)))

(define-public python-rpy2
  (package
    (name "python-rpy2")
    (version "2.7.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "rpy2" version))
       (sha256
        (base32
         "0nhan2qvrw7b7gg5zddwa22kybdv3x1g26vkd7q8lvnkgzrs4dga"))))
    (build-system python-build-system)
    (inputs
     `(("python-six" ,python-six)
       ("readline" ,readline)
       ("icu4c" ,icu4c)
       ("pcre" ,pcre)
       ("r" ,r)))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ("zlib" ,zlib)))
    (home-page "http://rpy.sourceforge.net/")
    (synopsis "Python interface to the R language")
    (description "rpy2 is a redesign and rewrite of rpy.  It is providing a
low-level interface to R from Python, a proposed high-level interface,
including wrappers to graphical libraries, as well as R-like structures and
functions.")
    (license gpl3+)))

(define-public python2-rpy2
  (let ((rpy2 (package-with-python2 python-rpy2)))
    (package (inherit rpy2)
      (native-inputs
       `(("python2-singledispatch" ,python2-singledispatch)
         ,@(package-native-inputs rpy2))))))

(define-public python-scipy
  (package
    (name "python-scipy")
    (version "0.16.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/scipy"
                           "/scipy-" version ".tar.xz"))
       (sha256
        (base32
         "0wa0a4skpda3gx7lb12yn19nhbairlyxrvda2lz2bcawk3x5qzz2"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-matplotlib" ,python-matplotlib)
       ("python-pyparsing" ,python-pyparsing)))
    (inputs
     `(("lapack" ,lapack)
       ("openblas" ,openblas)))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-sphinx" ,python-sphinx)
       ("python-numpydoc" ,python-numpydoc)
       ("gfortran" ,gfortran)
       ("texlive" ,texlive)
       ("perl" ,perl)))
    (outputs '("out" "doc"))
    (arguments
     `(#:phases
       (alist-cons-before
        'build 'configure-openblas
        (lambda* (#:key inputs #:allow-other-keys)
          (call-with-output-file "site.cfg"
            (lambda (port)
              (format port
                      "[blas]
libraries = openblas
library_dirs = ~a/lib
include_dirs = ~a/include
[atlas]
library_dirs = ~a/lib
atlas_libs = openblas
"
                      (assoc-ref inputs "openblas")
                      (assoc-ref inputs "openblas")
                      (assoc-ref inputs "openblas"))))
          #t)
        (alist-cons-after
         'install 'install-doc
         (lambda* (#:key outputs #:allow-other-keys)
           (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                  (doc (string-append data "/doc/" ,name "-" ,version))
                  (html (string-append doc "/html"))
                  (pyver ,(string-append "PYVER=")))
             (with-directory-excursion "doc"
               ;; Fix generation of images for mathematical expressions.
               (substitute* (find-files "source" "conf\\.py")
                 (("pngmath_use_preview = True")
                  "pngmath_use_preview = False"))
               (mkdir-p html)
               (system* "make" "html" pyver)
               (system* "make" "latex" "PAPER=a4" pyver)
               (system* "make" "-C" "build/latex" "all-pdf" "PAPER=a4" pyver)
               (copy-file "build/latex/scipy-ref.pdf"
                          (string-append doc "/scipy-ref.pdf"))
               (with-directory-excursion "build/html"
                 (for-each (lambda (file)
                             (let* ((dir (dirname file))
                                    (tgt-dir (string-append html "/" dir)))
                               (install-file file html)))
                           (find-files "." ".*"))))))
         ;; Tests can only be run after the library has been installed and not
         ;; within the source directory.
         (alist-cons-after
          'install 'check
          (lambda _
            (with-directory-excursion "/tmp"
              (zero? (system* "python" "-c" "import scipy; scipy.test()"))))
          (alist-delete
           'check
           (alist-cons-after
            'unpack 'fix-tests
            (lambda _
              (substitute* "scipy/integrate/tests/test_quadpack.py"
                (("libm.so") "libm.so.6"))
              #t)
            %standard-phases)))))))
    (home-page "http://www.scipy.org/")
    (synopsis "The Scipy library provides efficient numerical routines")
    (description "The SciPy library is one of the core packages that make up
the SciPy stack.  It provides many user-friendly and efficient numerical
routines such as routines for numerical integration and optimization.")
    (license bsd-3)))

(define-public python2-scipy
  (package-with-python2 python-scipy))

(define-public python-sqlalchemy
  (package
    (name "python-sqlalchemy")
    (version "1.0.12")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/S/"
                          "SQLAlchemy/SQLAlchemy-" version ".tar.gz"))
      (sha256
       (base32
        "1l8qclhd0s90w3pvwhi5mjxdwr5j7gw7cjka2fx6f2vqmq7f4yb6"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-cython" ,python-cython) ;for c extensions
       ("python-pytest" ,python-pytest)
       ("python-mock"   ,python-mock))) ;for tests
    (arguments
     `(#:phases (alist-replace
                 'check
                 (lambda _ (zero? (system* "py.test")))
                 %standard-phases)))
    (home-page "http://www.sqlalchemy.org")
    (synopsis "Database abstraction library")
    (description
     "SQLAlchemy is the Python SQL toolkit and Object Relational Mapper that
gives application developers the full power and flexibility of SQL.  It
provides a full suite of well known enterprise-level persistence patterns,
designed for efficient and high-performing database access, adapted into a
simple and Pythonic domain language.")
    (license x11)))

(define-public python2-sqlalchemy
  (package-with-python2 python-sqlalchemy))

(define-public python-alembic
  (package
    (name "python-alembic")
    (version "0.8.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "alembic" version))
       (sha256
        (base32
         "0jk23a852l3ybv7gfz81xzslyrnqnpjds5x15zd234y9rh9gq1w5"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-pytest-cov" ,python-pytest-cov)))
    (propagated-inputs
     `(("python-sqlalchemy" ,python-sqlalchemy)
       ("python-mako" ,python-mako)
       ("python-editor" ,python-editor)))
    (home-page "http://bitbucket.org/zzzeek/alembic")
    (synopsis
     "Database migration tool for SQLAlchemy")
    (description
     "Alembic is a lightweight database migration tool for usage with the
SQLAlchemy Database Toolkit for Python.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-alembic))))))

(define-public python2-alembic
  (let ((alembic (package-with-python2
                  (strip-python2-variant python-alembic))))
    (package
      (inherit alembic)
      (native-inputs `(("python2-setuptools" ,python2-setuptools)
                       ,@(package-native-inputs alembic))))))

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
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://launchpad.net/python-distutils-extra/")
    (synopsis "Enhancements to Python's distutils")
    (description
     "The python-distutils-extra module enables you to easily integrate
gettext support, themed icons, and scrollkeeper-based documentation into
Python's distutils.")
    (license gpl2)))

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
       (sha256
        (base32
         "0y7vzff9xgbnaay7m0va1arl6g68ncwrvbgwl7jqlclsahzzb09d"))))
    (build-system python-build-system)
    (native-inputs
     `(("python2-setuptools" ,python2-setuptools)))
    (arguments
     ;; incompatible with Python 3 (exception syntax)
     `(#:python ,python-2
       #:tests? #f
       ;; With standard flags, the install phase attempts to create a zip'd
       ;; egg file, and fails with an error: 'ZIP does not support timestamps
       ;; before 1980'
       #:configure-flags '("--single-version-externally-managed"
                           "--record=elib.txt")))
    (home-page "https://github.com/dieterv/elib.intl")
    (synopsis "Enhanced internationalization for Python")
    (description
     "The elib.intl module provides enhanced internationalization (I18N)
services for your Python modules and applications.")
    (license lgpl3+)))

(define-public python-pillow
  (package
    (name "python-pillow")
    (version "3.1.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Pillow" version))
       (sha256
        (base32
         "1zwzakr5v0skdh0azp5cd6fwzbll5305dsk33k5jk570vv6lqvs8"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-nose"       ,python-nose)))
    (inputs
     `(("freetype" ,freetype)
       ("lcms"     ,lcms)
       ("zlib"     ,zlib)
       ("libjpeg"  ,libjpeg)
       ("openjpeg" ,openjpeg)
       ("libtiff"  ,libtiff)
       ("libwebp"  ,libwebp)))
    (propagated-inputs
     `(;; Used at runtime for pkg_resources
       ("python-setuptools" ,python-setuptools)))
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (add-before
                   'install 'disable-egg-compression
                   (lambda _
                     ;; Leave the .egg uncompressed since compressing it would
                     ;; prevent the GC from identifying run-time dependencies.
                     ;; See <http://bugs.gnu.org/20765>.
                     (let ((port (open-file "setup.cfg" "a")))
                       (display "\n[easy_install]\nzip_ok = 0\n"
                                port)
                       (close-port port)
                       #t)))
                  (add-after
                   'install 'check-installed
                   (lambda _
                     (begin
                       (setenv "HOME" (getcwd))
                       (and (zero? (system* "python" "selftest.py"
                                            "--installed"))
                            (zero? (system* "python" "test-installed.py"))))))
                 (delete 'check))))
    (home-page "https://pypi.python.org/pypi/Pillow")
    (synopsis "Fork of the Python Imaging Library")
    (description
     "The Python Imaging Library adds image processing capabilities to your
Python interpreter.  This library provides extensive file format support, an
efficient internal representation, and fairly powerful image processing
capabilities.  The core image library is designed for fast access to data
stored in a few basic pixel formats.  It should provide a solid foundation for
a general image processing tool.")
    (license (x11-style
              "http://www.pythonware.com/products/pil/license.htm"
              "The PIL Software License"))))

(define-public python2-pillow
  (package-with-python2 python-pillow))

(define-public python-pycparser
  (package
    (name "python-pycparser")
    (version "2.14")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "pycparser" version))
      (sha256
       (base32
        "0wvzyb6rxsfj3xcnpa4ynbh9qc7rrbk2277d5wqpphmx9akv8nbr"))))
    (outputs '("out" "doc"))
    (build-system python-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-setuptools" ,python-setuptools)))
    (arguments
     `(#:phases
       (alist-replace
        'check
        (lambda _
          (with-directory-excursion "tests"
            (zero? (system* "python" "all_tests.py"))))
        (alist-cons-after
         'install 'install-doc
         (lambda* (#:key outputs #:allow-other-keys)
           (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                  (doc (string-append data "/doc/" ,name "-" ,version))
                  (examples (string-append doc "/examples")))
             (mkdir-p examples)
             (for-each (lambda (file)
                         (copy-file (string-append "." file)
                                    (string-append doc file)))
                       '("/README.rst" "/CHANGES" "/LICENSE"))
             (copy-recursively "examples" examples)))
         %standard-phases))))
    (home-page "https://github.com/eliben/pycparser")
    (synopsis "C parser in Python")
    (description
     "Pycparser is a complete parser of the C language, written in pure Python
using the PLY parsing library.  It parses C code into an AST and can serve as
a front-end for C compilers or analysis tools.")
    (license bsd-3)))

(define-public python2-pycparser
  (package-with-python2 python-pycparser))

(define-public python-cffi
  (package
    (name "python-cffi")
    (version "1.4.2")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "cffi" version))
      (sha256
       (base32 "161rj52rzi3880lij17d6i9kvgkiwjilrqjs8405k8sf6ryif7cg"))))
    (build-system python-build-system)
    (outputs '("out" "doc"))
    (inputs
     `(("libffi" ,libffi)))
    (propagated-inputs ; required at run-time
     `(("python-pycparser" ,python-pycparser)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-sphinx" ,python-sphinx)
       ("python-pytest" ,python-pytest)
       ("python-setuptools" ,python-setuptools)))
    (arguments
     `(#:phases
       (alist-cons-after
        'install 'install-doc
        (lambda* (#:key outputs #:allow-other-keys)
          (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                 (doc (string-append data "/doc/" ,name "-" ,version))
                 (html (string-append doc "/html")))
            (with-directory-excursion "doc"
              (system* "make" "html")
              (mkdir-p html)
              (copy-recursively "build/html" html))
            (copy-file "LICENSE" (string-append doc "/LICENSE"))))
        %standard-phases)))
    (home-page "http://cffi.readthedocs.org")
    (synopsis "Foreign function interface for Python")
    (description
     "Foreign Function Interface for Python calling C code.")
    (license license:expat)))

(define-public python2-cffi
  (package-with-python2 python-cffi))

(define-public python-xcffib
  (package
    (name "python-xcffib")
    (version "0.1.9")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/x/"
                          "xcffib/xcffib-" version ".tar.gz"))
      (sha256
       (base32
        "0655hzxv57h1a9ja9kwp0ichbkhf3djw32k33d66xp0q37dq2y81"))))
    (build-system python-build-system)
    (inputs
     `(("libxcb" ,libxcb)
       ("python-six" ,python-six)))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (propagated-inputs
     `(("python-cffi" ,python-cffi))) ; used at run time
    (arguments
     `(#:phases
       (alist-cons-after
        'install 'install-doc
        (lambda* (#:key outputs #:allow-other-keys)
          (let ((doc (string-append (assoc-ref outputs "out") "/share"
                                    "/doc/" ,name "-" ,version)))
            (mkdir-p doc)
            (copy-file "README.md"
                       (string-append doc "/README.md"))))
        %standard-phases)))
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
    (version "0.6")
    (source
     (origin
      (method url-fetch)
      ;; The archive on pypi is missing the 'utils' directory!
      (uri (string-append "https://github.com/SimonSapin/cairocffi/archive/v"
                          version ".tar.gz"))
      (file-name (string-append name "-" version ".tar.gz"))
      (sha256
       (base32
        "03w5p62sp3nqiccx864sbq0jvh7946277jqx3rcc3dch5xwfvv51"))))
    (build-system python-build-system)
    (outputs '("out" "doc"))
    (inputs
     `(("gdk-pixbuf" ,gdk-pixbuf)
       ("cairo" ,cairo)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-sphinx" ,python-sphinx)
       ("python-docutils" ,python-docutils)
       ("python-setuptools" ,python-setuptools)))
    (propagated-inputs
     `(("python-xcffib" ,python-xcffib))) ; used at run time
    (arguments
     `(#:phases
       (alist-cons-after
        'install 'install-doc
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
            (copy-recursively "docs/_build/html" html)))
        %standard-phases)))
    (home-page "https://github.com/SimonSapin/cairocffi")
    (synopsis "Python bindings and object-oriented API for Cairo")
    (description
     "Cairocffi is a CFFI-based drop-in replacement for Pycairo, a set of
Python bindings and object-oriented API for cairo.  Cairo is a 2D vector
graphics library with support for multiple backends including image buffers,
PNG, PostScript, PDF, and SVG file output.")
    (license bsd-3)))

(define-public python2-cairocffi
  (package-with-python2 python-cairocffi))

(define-public python-decorator
  (package
    (name "python-decorator")
    (version "4.0.9")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "decorator" version))
       (sha256
        (base32 "1a5vwhflfd9sh3rfb40xlyipldgdzfff6brman57hqv3661jw0lh"))))
    (build-system python-build-system)
    (arguments '(#:tests? #f)) ; no test target
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
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
    (version "0.7.6")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/d/drmaa/drmaa-"
             version ".tar.gz"))
       (sha256
        (base32 "0bzl9f9g34dlhwf09i3fdv7dqqzf2iq0w7d6c2bafx1nlap8qfbh"))))
    (build-system python-build-system)
    ;; The test suite requires libdrmaa which is provided by the cluster
    ;; environment.  At runtime the environment variable DRMAA_LIBRARY_PATH
    ;; should be set to the path of the libdrmaa library.
    (arguments '(#:tests? #f))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-setuptools" ,python-setuptools)))
    (home-page "https://pypi.python.org/pypi/drmaa")
    (synopsis "Python bindings for the DRMAA library")
    (description
      "A Python package for Distributed Resource Management (DRM) job
submission and control.  This package is an implementation of the DRMAA 1.0
Python language binding specification.")
    (license bsd-3)))

(define-public python2-drmaa
  (package-with-python2 python-drmaa))

(define-public python-gridmap
  (package
    (name "python-gridmap")
    (version "0.13.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/pygridtools/gridmap/archive/v"
             version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32 "1gzjg2k6f14i1msm2b0ax8d9ds1hvk6qd5nlaivg8m4cxqp4cp1x"))))
    (build-system python-build-system)
    (inputs
     `(("python-psutil" ,python-psutil)
       ("python-drmaa" ,python-drmaa)
       ("python-pyzmq" ,python-pyzmq)))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/pygridtools/gridmap")
    (synopsis "Create jobs on a cluster directly from Python")
    (description
      "Gridmap is a Python package to allow you to easily create jobs on the
cluster directly from Python.  You can directly map Python functions onto the
cluster without needing to write any wrapper code yourself.")
    (license gpl3+)))

(define-public python2-gridmap
  (package-with-python2 python-gridmap))

(define-public python-pexpect
  (package
    (name "python-pexpect")
    (version "3.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/p/"
                           "pexpect/pexpect-" version ".tar.gz"))
       (sha256
        (base32 "1fp5gm976z7ghm8jw57463rj19cv06c8zw842prgyg788f6n3snz"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check (lambda _ (zero? (system* "nosetests")))))))
    (native-inputs
     `(("python-nose" ,python-nose)))
    (home-page "http://pexpect.readthedocs.org/")
    (synopsis "Controlling interactive console applications")
    (description
     "Pexpect is a pure Python module for spawning child applications;
controlling them; and responding to expected patterns in their output.
Pexpect works like Don Libes’ Expect.  Pexpect allows your script to spawn a
child application and control it as if a human were typing commands.")
    (license isc)))

(define-public python2-pexpect
  (package-with-python2 python-pexpect))

(define-public python-setuptools-scm
  (package
    (name "python-setuptools-scm")
    (version "1.9.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "setuptools_scm" version))
              (sha256
               (base32
                "0y24bl893zk6nrklbvdrlmpkalf214zjn6k1xrglljd29rrn4wxi"))))
    (build-system python-build-system)
    (native-inputs `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/pypa/setuptools_scm/")
    (synopsis "Manage Python package versions in SCM metadata")
    (description
     "Setuptools_scm handles managing your Python package versions in
@dfn{software configuration management} (SCM) metadata instead of declaring
them as the version argument or in a SCM managed file.")
    (license license:expat)))

(define-public python2-setuptools-scm
  (package-with-python2 python-setuptools-scm))

(define-public python-pathpy
  (package
    (name "python-pathpy")
    (version "8.1.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/p/"
                           "path.py/path.py-" version ".tar.gz"))
       (sha256
        (base32 "1p8s1l2vfkqhqxdhqlj0g1jjw4f1as2frr35sjcpjjpd5a89y41f"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-appdirs" ,python-appdirs)))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-setuptools-scm" ,python-setuptools-scm)
       ("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)))
    (home-page "http://github.com/jaraco/path.py")
    (synopsis "Python module wrapper for built-in os.path")
    (description
     "@code{path.py} implements path objects as first-class entities, allowing
common operations on files to be invoked on those path objects directly.")
    (license license:expat)))

(define-public python2-pathpy
  (package-with-python2 python-pathpy))

(define-public python-pickleshare
  (package
    (name "python-pickleshare")
    (version "0.5")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/p/"
                           "pickleshare/pickleshare-" version ".tar.gz"))
       (sha256
        (base32 "11ljr90j3p6qswdrbl7p4cjb2i93f6vn0vx9anzpshsx0d2mggn0"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pathpy" ,python-pathpy)))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/vivainio/pickleshare")
    (synopsis "Tiny key value database with concurrency support")
    (description
     "PickleShare is a small ‘shelve’-like datastore with concurrency support.
Like shelve, a PickleShareDB object acts like a normal dictionary.  Unlike
shelve, many processes can access the database simultaneously.  Changing a
value in database is immediately visible to other processes accessing the same
database.  Concurrency is possible because the values are stored in separate
files.  Hence the “database” is a directory where all files are governed by
PickleShare.")
    (license license:expat)))

(define-public python2-pickleshare
  (package-with-python2 python-pickleshare))

(define-public python-simplegeneric
  (package
    (name "python-simplegeneric")
    (version "0.8.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/s/"
                           "simplegeneric/simplegeneric-" version ".zip"))
       (sha256
        (base32 "0wwi1c6md4vkbcsfsf8dklf3vr4mcdj4mpxkanwgb6jb1432x5yw"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ("unzip" ,unzip)))
    (home-page "http://cheeseshop.python.org/pypi/simplegeneric")
    (synopsis "Python module for simple generic functions")
    (description
     "The simplegeneric module lets you define simple single-dispatch generic
functions, akin to Python’s built-in generic functions like @code{len()},
@code{iter()} and so on.  However, instead of using specially-named methods,
these generic functions use simple lookup tables, akin to those used by
e.g. @code{pickle.dump()} and other generic functions found in the Python
standard library.")
    (license zpl2.1)))

(define-public python2-simplegeneric
  (package-with-python2 python-simplegeneric))

(define-public python-ipython-genutils
  (package
    (name "python-ipython-genutils")
    (version "0.1.0")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://pypi.python.org/packages/source/i/"
                          "ipython_genutils/ipython_genutils-"
                          version ".tar.gz"))
      (sha256
       (base32 "19l2pp1c64ansr89l3cqh19jdi2ixhssdzx0vz4n6r52a6i281is"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f)) ; no tests
    (home-page "http://ipython.org")
    (synopsis "Vestigial utilities from IPython")
    (description
     "This package provides retired utilities from IPython.")
    (license bsd-3)))

(define-public python2-ipython-genutils
  (package-with-python2 python-ipython-genutils))

(define-public python-traitlets
  (package
    (name "python-traitlets")
    (version "4.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "traitlets" version))
       (sha256
        (base32
         "0nxgj8jxlm1kqf8cx2x7vjid05zdgbxpqhjbdl46r8njlpgkh3j4"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check (lambda _ (zero? (system* "nosetests")))))))
    (propagated-inputs
     `(("python-ipython-genutils" ,python-ipython-genutils)
       ("python-decorator" ,python-decorator)))
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-nose" ,python-nose)))
    (home-page "http://ipython.org")
    (synopsis "Configuration system for Python applications")
    (description
     "Traitlets is a framework that lets Python classes have attributes with
type checking, dynamically calculated default values, and ‘on change’
callbacks.  The package also includes a mechanism to use traitlets for
configuration, loading values from files or from command line arguments.  This
is a distinct layer on top of traitlets, so you can use traitlets in your code
without using the configuration machinery.")
    (license bsd-3)))

(define-public python2-traitlets
  (package-with-python2 python-traitlets))

(define-public python-ipython
  (package
    (name "python-ipython")
    (version "3.2.1")
    (source
     (origin
       (method url-fetch)
       (patches (list (search-patch "python-ipython-inputhook-ctype.patch")))
       (uri (string-append "https://pypi.python.org/packages/source/i/"
                           "ipython/ipython-" version ".tar.gz"))
       (sha256
        (base32 "0xwin0sa9n0cabx4cq1ibf5ldsiw5dyimibla82kicz5gbpas4y9"))))
    (build-system python-build-system)
    (outputs '("out" "doc"))
    (propagated-inputs
     `(("python-pyzmq" ,python-pyzmq)
       ("python-terminado" ,python-terminado)))
    (inputs
     `(("readline" ,readline)
       ("which" ,which)
       ("python-matplotlib" ,python-matplotlib)
       ("python-numpy" ,python-numpy)
       ("python-numpydoc" ,python-numpydoc)
       ("python-jinja2" ,python-jinja2)
       ("python-mistune" ,python-mistune)
       ("python-jsonschema" ,python-jsonschema)
       ("python-pygments" ,python-pygments)
       ("python-requests" ,python-requests) ;; for tests
       ("python-nose" ,python-nose)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-sphinx" ,python-sphinx)
       ("texlive" ,texlive)
       ("texinfo" ,texinfo)
       ("python-setuptools" ,python-setuptools)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after
          'install 'install-doc
          (lambda* (#:key inputs outputs #:allow-other-keys)
            (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                   (doc (string-append data "/doc/" ,name "-" ,version))
                   (html (string-append doc "/html"))
                   (man1 (string-append data "/man/man1"))
                   (info (string-append data "/info"))
                   (examples (string-append doc "/examples")))
              (setenv "LANG" "en_US.utf8")
              (with-directory-excursion "docs"
                ;; FIXME: html and pdf fail to build
                ;; (system* "make" "html")
                ;; (system* "make" "pdf" "PAPER=a4")
                (system* "make" "info"))
              (copy-recursively "docs/man" man1)
              (copy-recursively "examples" examples)
              ;; (copy-recursively "docs/build/html" html)
              ;; (copy-file "docs/build/latex/ipython.pdf"
              ;;            (string-append doc "/ipython.pdf"))
              (mkdir-p info)
              (copy-file "docs/build/texinfo/ipython.info"
                         (string-append info "/ipython.info"))
              (copy-file "COPYING.rst" (string-append doc "/COPYING.rst")))))
         ;; Tests can only be run after the library has been installed and not
         ;; within the source directory.
         (delete 'check)
         (add-after
          'install 'check
          (lambda* (#:key outputs tests? #:allow-other-keys)
            (if tests?
                (with-directory-excursion "/tmp"
                  (setenv "HOME" "/tmp/") ;; required by a test
                  (zero? (system* (string-append (assoc-ref outputs "out")
                                                 "/bin/iptest"))))
                #t)))
         (add-before
          'install 'fix-tests
          (lambda* (#:key inputs #:allow-other-keys)
            (substitute* "./IPython/utils/_process_posix.py"
              (("/usr/bin/env', 'which") (which "which")))
            (substitute* "./IPython/core/tests/test_inputtransformer.py"
              (("#!/usr/bin/env python")
               (string-append "#!" (which "python"))))
            ;; Disable 1 failing test
            (substitute* "./IPython/core/tests/test_magic.py"
              (("def test_dirops\\(\\):" all)
               (string-append "@dec.skipif(True)\n" all))))))))
    (home-page "http://ipython.org")
    (synopsis "IPython is a tool for interactive computing in Python")
    (description
     "IPython provides a rich architecture for interactive computing with:
Powerful interactive shells, a browser-based notebook, support for interactive
data visualization, embeddable interpreters and tools for parallel
computing.")
    (license bsd-3)))

(define-public python2-ipython
  (let ((ipython (package-with-python2 python-ipython)))
    (package
      (inherit ipython)
      ;; FIXME: some tests are failing
      (arguments
       `(#:tests? #f ,@(package-arguments ipython)))
      ;; Make sure we use custom python2-NAME packages.
      ;; FIXME: add pyreadline once available.
      (propagated-inputs
       `(("python2-terminado" ,python2-terminado)
         ,@(alist-delete "python-terminado"
                         (package-propagated-inputs ipython))))
      (inputs
       `(("python2-jsonschema" ,python2-jsonschema)
         ("python2-mock" ,python2-mock)
         ("python2-matplotlib" ,python2-matplotlib)
         ("python2-numpy" ,python2-numpy)
         ("python2-requests" ,python2-requests)
         ,@(fold alist-delete (package-inputs ipython)
                 '("python-jsonschema" "python-matplotlib" "python-numpy" "python-requests")))))))

(define-public python-isodate
  (package
    (name "python-isodate")
    (version "0.5.4")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "isodate" version))
        (sha256
          (base32
            "0cafaiwixgpxwh9dsd28qb0dbzsj6xpxjdkyk30ns91ps10mq422"))))
    (build-system python-build-system)
    (inputs
      `(("python-setuptools" ,python-setuptools)))
    (home-page
      "http://cheeseshop.python.org/pypi/isodate")
    (synopsis
      "Python date parser and formatter")
    (description
      "Python-isodate is a python module for parsing and formatting
ISO 8601 dates, time and duration.")
    (license bsd-3)))

(define-public python2-isodate
  (package-with-python2 python-isodate))

(define-public python-html5lib
  (package
    (name "python-html5lib")
    (version "1.0b8")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "html5lib" version))
        (sha256
          (base32
            "1lknq5j3nh11xrl268ks76zaj0gyzh34v94n5vbf6dk8llzxdx0q"))))
    (build-system python-build-system)
    (propagated-inputs
      `(("python-six" ,python-six))) ; required to "import html5lib"
    (inputs
      `(("python-setuptools" ,python-setuptools)))
    (arguments
     `(#:test-target "check"))
    (home-page
      "https://github.com/html5lib/html5lib-python")
    (synopsis
      "Python HTML parser based on the WHATWG HTML specifcation")
    (description
      "Html5lib is an HTML parser based on the WHATWG HTML specifcation
and written in Python.")
    (license license:expat)))

(define-public python2-html5lib
  (package-with-python2 python-html5lib))

(define-public python-urwid
  (package
    (name "python-urwid")
    (version "1.3.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "urwid" version))
       (sha256
        (base32
         "18mb0yy94sjc434rd61m2sfnw27sa0nyrszpj5a9r9zh7fnlzw19"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; Disable failing test. Bug filed upstream:
         ;; https://github.com/wardi/urwid/issues/164
         ;; TODO: check again for python-urwid > 1.3.0 or python > 3.4.3.
         (add-after 'unpack 'disable-failing-test
          (lambda _
            (substitute* "urwid/tests/test_event_loops.py"
              (("test_remove_watch_file")
                "disable_remove_watch_file")))))))
    (native-inputs `(("python-setuptools" ,python-setuptools)))
    (home-page "http://urwid.org")
    (synopsis "Console user interface library for Python")
    (description
     "Urwid is a curses-based UI/widget library for Python.  It includes many
features useful for text console applications.")
    (license lgpl2.1+)))

(define-public python2-urwid
  (package-with-python2 python-urwid))

(define-public python-dbus
  (package
    (name "python-dbus")
    (version "1.2.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://dbus.freedesktop.org/releases/dbus-python/dbus-python-"
             version ".tar.gz"))
       (sha256
        (base32 "1py62qir966lvdkngg0v8k1khsqxwk5m4s8nflpk1agk5f5nqb71"))))
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
     `(("python" ,python)
       ("dbus-glib" ,dbus-glib)))
    (synopsis "Python bindings for D-bus")
    (description "python-dbus provides bindings for libdbus, the reference
implementation of D-Bus.")
    (home-page "http://www.freedesktop.org/wiki/Software/DBusBindings/")
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

(define-public python-apsw
  (package
    (name "python-apsw")
    (version "3.9.2-r1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "apsw" version))
        (sha256
          (base32
           "0w4jb0wpx785qw42r3h4fh7gl5w2968q48i7gygybsfxck8nzffs"))))
    (build-system python-build-system)
    (inputs
      `(("python-setuptools" ,python-setuptools)
        ("sqlite" ,sqlite)))
    (arguments
     `(#:phases
        ;; swap check and install phases
        (alist-cons-after
         'install 'check
         (assoc-ref %standard-phases 'check)
         (alist-delete
          'check
          %standard-phases))))
    (home-page "https://github.com/rogerbinns/apsw/")
    (synopsis "Another Python SQLite Wrapper")
    (description "APSW is a Python wrapper for the SQLite
embedded relational database engine.  In contrast to other wrappers such as
pysqlite it focuses on being a minimal layer over SQLite attempting just to
translate the complete SQLite API into Python.")
    (license license:zlib)))

(define-public python2-apsw
  (package-with-python2 python-apsw))

(define-public python-lxml
  (package
    (name "python-lxml")
    (version "3.5.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "lxml" version))
        (sha256
          (base32
            "0y7m2s8ci6q642zl85y5axkj8z827l0vhjl532acb75hlkir77rl"))))
    (build-system python-build-system)
    (inputs
      `(("libxml2" ,libxml2)
        ("libxslt" ,libxslt)
        ("python-setuptools" ,python-setuptools)))
    (home-page "http://lxml.de/")
    (synopsis
      "Python XML processing library")
    (description
      "The lxml XML toolkit is a Pythonic binding for the C libraries
libxml2 and libxslt.")
    (license bsd-3))) ; and a few more, see LICENSES.txt

(define-public python2-lxml
  (package-with-python2 python-lxml))

;; beautifulsoup4 has a totally different namespace than 3.x,
;; and pypi seems to put it under its own name, so I guess we should too
(define-public python-beautifulsoup4
  (package
    (name "python-beautifulsoup4")
    (version "4.4.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "beautifulsoup4" version))
       (sha256
        (base32
         "1d36lc4pfkvl74fmzdib2nqnvknm0jddgf2n9yd7im150qyh3m47"))))
    (build-system python-build-system)
    (home-page
     "http://www.crummy.com/software/BeautifulSoup/bs4/")
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
    (native-inputs `(("python2-setuptools" ,python2-setuptools)))))

(define-public python2-cssutils
  (package
    (name "python2-cssutils")
    (version "1.0")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
              "https://pypi.python.org/packages/source/c/cssutils/cssutils-"
              version
              ".zip"))
        (sha256
          (base32
            "1bwim1353r4hqiir73sn4sc43y7ymh09qx0kly7vj048blppc125"))))
    (build-system python-build-system)
    (native-inputs
      `(("python2-mock" ,python2-mock) ; for the tests
        ("unzip" ,unzip))) ; for unpacking the source
    (inputs
      `(("python2-setuptools" ,python2-setuptools)))
    (arguments
     `(#:python ,python-2 ; Otherwise tests fail with a syntax error.
       #:tests? #f ; The tests apparently download an external URL.
       ))
    (home-page "http://cthedot.de/cssutils/")
    (synopsis
      "CSS Cascading Style Sheets library for Python")
    (description
      "Cssutils is a Python package for parsing and building CSS
Cascading Style Sheets.  Currently it provides a DOM only and no rendering
options.")
    (license lgpl3+)))

(define-public python-cssselect
  (package
    (name "python-cssselect")
    (version "0.9.1")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
              "https://pypi.python.org/packages/source/c/cssselect/cssselect-"
              version
              ".tar.gz"))
        (sha256
          (base32
            "10h623qnp6dp1191jri7lvgmnd4yfkl36k9smqklp1qlf3iafd85"))))
    (build-system python-build-system)
    (inputs
      `(("python-setuptools" ,python-setuptools)))
    (arguments
     ;; tests fail with message
     ;; AttributeError: 'module' object has no attribute 'tests'
     `(#:tests? #f))
    (home-page
      "https://pythonhosted.org/cssselect/")
    (synopsis
      "CSS3 selector parser and translator to XPath 1.0")
    (description
      "Cssselect ia a Python module that parses CSS3 Selectors and translates
them to XPath 1.0 expressions.  Such expressions can be used in lxml or
another XPath engine to find the matching elements in an XML or HTML document.")
    (license bsd-3)))

(define-public python2-cssselect
  (package-with-python2 python-cssselect))

(define-public python-netifaces
  (package
    (name "python-netifaces")
    (version "0.10.4")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
              "https://pypi.python.org/packages/source/n/netifaces/netifaces-"
              version
              ".tar.gz"))
        (sha256
          (base32
            "1plw237a4zib4z8s62g0mrs8gm3kjfrp5sxh6bbk9nl3rdls2mln"))))
    (build-system python-build-system)
    (inputs
      `(("python-setuptools" ,python-setuptools)))
    (home-page
      "https://bitbucket.org/al45tair/netifaces")
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
    (version "1.11")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "networkx" version))
       (sha256
        (base32 "1f74s56xb4ggixiq0vxyfxsfk8p20c7a099lpcf60izv1php03hd"))))
    (build-system python-build-system)
    ;; python-decorator is needed at runtime
    (propagated-inputs
     `(("python-decorator" ,python-decorator)))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-nose" ,python-nose)))
    (home-page "http://networkx.github.io/")
    (synopsis "Python module for creating and manipulating graphs and networks")
    (description
      "NetworkX is a Python package for the creation, manipulation, and study
of the structure, dynamics, and functions of complex networks.")
    (license bsd-3)))

(define-public python2-networkx
  (package-with-python2 python-networkx))

(define-public snakemake
  (package
    (name "snakemake")
    (version "3.2.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/s/snakemake/snakemake-"
             version ".tar.gz"))
       (sha256
        (base32 "0fi4b63sj60hvi7rfydvmz2icl4wj74djw5sn2gl8hxd02qw4b91"))))
    (build-system python-build-system)
    (inputs `(("python-setuptools" ,python-setuptools)))
    (home-page "https://bitbucket.org/johanneskoester/snakemake")
    (synopsis "Python-based execution environment for make-like workflows")
    (description
      "Snakemake aims to reduce the complexity of creating workflows by
providing a clean and modern domain specific specification language (DSL) in
Python style, together with a fast and comfortable execution environment.")
    (license license:expat)))

(define-public python-seaborn
  (package
    (name "python-seaborn")
    (version "0.5.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/s/seaborn/seaborn-"
             version ".tar.gz"))
       (sha256
        (base32 "1236abw18ijjglmv60q85ckqrvgf5qyy4zlq7nz5aqfg6q87z3wc"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pandas" ,python-pandas)
       ("python-matplotlib" ,python-matplotlib)
       ("python-scipy" ,python-scipy)))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://stanford.edu/~mwaskom/software/seaborn/")
    (synopsis "Statistical data visualization")
    (description
     "Seaborn is a library for making attractive and informative statistical
graphics in Python.  It is built on top of matplotlib and tightly integrated
with the PyData stack, including support for numpy and pandas data structures
and statistical routines from scipy and statsmodels.")
    (license bsd-3)))

(define-public python2-seaborn
  (let ((seaborn (package-with-python2 python-seaborn)))
    (package (inherit seaborn)
      (propagated-inputs
       `(("python2-pytz" ,python2-pytz)
         ("python2-pandas" ,python2-pandas)
         ("python2-matplotlib" ,python2-matplotlib)
         ("python2-scipy" ,python2-scipy))))))

(define-public python-sympy
  (package
    (name "python-sympy")
    (version "0.7.6")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/sympy/sympy/releases/download/sympy-"
             version "/sympy-" version ".tar.gz"))
       (sha256
        (base32 "19yp0gy4i7p4g6l3b8vaqkj9qj7yqb5kqy0qgbdagpzgkdz958yz"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://www.sympy.org/")
    (synopsis "Python library for symbolic mathematics")
    (description
     "SymPy is a Python library for symbolic mathematics.  It aims to become a
full-featured computer algebra system (CAS) while keeping the code as simple
as possible in order to be comprehensible and easily extensible.")
    (license bsd-3)))

(define-public python2-sympy
  (package-with-python2 python-sympy))

(define-public python-testlib
  (package
    (name "python-testlib")
    (version "0.6.5")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/t/testlib/testlib-"
             version ".zip"))
       (sha256
        (base32 "1mz26cxn4x8bbgv0rn0mvj2z05y31rkc8009nvdlb3lam5b4mj3y"))))
    (build-system python-build-system)
    (inputs
      `(("python-setuptools" ,python-setuptools)))
    (native-inputs
     `(("unzip" ,unzip)))
    (arguments
     `(#:phases
       (alist-replace
        'unpack
        (lambda* (#:key inputs outputs #:allow-other-keys)
          (let ((unzip (string-append (assoc-ref inputs "unzip")
                                      "/bin/unzip"))
                (source (assoc-ref inputs "source")))
            (and (zero? (system* unzip source))
                 (chdir (string-append "testlib-" ,version)))))
        %standard-phases)))
    (synopsis "Python micro test suite harness")
    (description "A micro unittest suite harness for Python.")
    (home-page "https://github.com/trentm/testlib")
    (license license:expat)))

(define-public python2-testlib
  (package-with-python2 python-testlib))

(define-public python2-xlib
  (package
    (name "python2-xlib")
    (version "0.14")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/python-xlib/"
                                  "python-xlib-" version ".tar.gz"))
              (sha256
               (base32
                "1sv0447j0rx8cgs3jhjl695p5pv13ihglcjlrrz1kq05lsvb0wa7"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2                         ;Python 2 only
       #:tests? #f))                              ;no tests
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://python-xlib.sourceforge.net/")
    (synopsis "Python X11 client library")
    (description
     "The Python X Library is intended to be a fully functional X client
library for Python programs.  It is useful to implement low-level X clients.
It is written entirely in Python.")
    (license gpl2+)))

(define-public python-singledispatch
  (package
    (name "python-singledispatch")
    (version "3.4.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/s/singledispatch/"
             "singledispatch-" version ".tar.gz"))
       (sha256
        (base32
         "171b7ip0hsq5qm83np40h3phlr36ym18w0lay0a8v08kvy3sy1jv"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (propagated-inputs
     `(("python-six" ,python-six)))
    (home-page
     "http://docs.python.org/3/library/functools.html#functools.singledispatch")
    (synopsis "Backport of singledispatch feature from Python 3.4")
    (description
     "This library brings functools.singledispatch from Python 3.4 to Python
2.6-3.3.")
    (license license:expat)))

(define-public python2-singledispatch
  (package-with-python2 python-singledispatch))

(define-public python-tornado
  (package
    (name "python-tornado")
    (version "4.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "tornado" version))
       (sha256
        (base32 "1gzgwayl6hmc9jfcl88bni4jcsk2jcca9dn1rvrfsvnijcjx7hn9"))))
    (build-system python-build-system)
    (inputs
     `(("python-certifi" ,python-certifi)))
    (native-inputs
     `(("python-backports-abc" ,python-backports-abc)
       ("python-setuptools" ,python-setuptools)))
    (home-page "http://www.tornadoweb.org/")
    (synopsis "Python web framework and asynchronous networking library")
    (description
     "Tornado is a Python web framework and asynchronous networking library,
originally developed at FriendFeed.  By using non-blocking network I/O,
Tornado can scale to tens of thousands of open connections, making it ideal
for long polling, WebSockets, and other applications that require a long-lived
connection to each user.")
    (license asl2.0)))

(define-public python2-tornado
  (let ((tornado (package-with-python2 python-tornado)))
    (package (inherit tornado)
      (inputs
       `(("python2-backport-ssl-match-hostname"
          ,python2-backport-ssl-match-hostname)
         ("python2-singledispatch", python2-singledispatch)
         ,@(package-inputs tornado))))))

;; the python- version can be removed with python-3.5
(define-public python-backports-abc
  (package
    (name "python-backports-abc")
      (version "0.4")
      (source
        (origin
          (method url-fetch)
          (uri (pypi-uri "backports_abc" version))
          (sha256
           (base32
            "19fh75lni9pb673n2fn505m1rckm0af0szcv5xx1qm1xpa940glb"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/cython/backports_abc")
    (synopsis "Backport of additions to the 'collections.abc' module.")
    (description
     "Python-backports-abc provides a backport of additions to the
'collections.abc' module in Python-3.5.")
    (license psfl)))

(define-public python2-backports-abc
  (package-with-python2 python-backports-abc))

(define-public python-waf
  (package
    (name "python-waf")
    (version "1.8.8")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://waf.io/"
                                  "waf-" version ".tar.bz2"))
              (sha256
               (base32
                "0b5q307fgn6a5d8yjia2d1l4bk1q3ilvc0w8k4isfrrx2gbcw8wn"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'build
                  (lambda _
                    (zero? (begin
                             (system* "python" "waf-light" "configure")
                             (system* "python" "waf-light" "build")))))
         (replace 'check
                  (lambda _
                    (zero? (system* "python" "waf" "--version"))))
         (replace 'install
                  (lambda _
                    (copy-file "waf" %output))))))
    (home-page "https://waf.io/")
    (synopsis "Python-based build system")
    (description
     "Waf is a Python-based framework for configuring, compiling and installing
applications.")
    (license bsd-3)))

(define-public python2-waf
  (package-with-python2 python-waf))

(define-public python-pyzmq
  (package
    (name "python-pyzmq")
    (version "15.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyzmq" version))
       (sha256
        (base32 "13fhwnlvsvxv72kfhqbpn6qi7msh8mc8377mpabv32skk2cjfnxx"))))
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
       ("python-nose" ,python-nose)
       ("python-setuptools" ,python-setuptools)))
    (home-page "http://github.com/zeromq/pyzmq")
    (synopsis "Python bindings for 0MQ")
    (description
     "PyZMQ is the official Python binding for the ZeroMQ messaging library.")
    (license bsd-4)))

(define-public python2-pyzmq
  (package-with-python2 python-pyzmq))

(define-public python-pep8
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
    (inputs
      `(("python-setuptools" ,python-setuptools)))
    (home-page "http://pep8.readthedocs.org/")
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
    (version "1.0.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pyflakes" version))
        (sha256
          (base32
            "0qs2sgqszq7wcplis8509wk2ygqcrwzbs1ghfj3svvivq2j377pk"))))
    (build-system python-build-system)
    (inputs
      `(("python-setuptools" ,python-setuptools)))
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
    (version "0.4.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "mccabe" version))
        (sha256
          (base32
            "0yr08a36h8lqlif10l4xcikbbig7q8f41gqywir7rrvnv3mi4aws"))))
    (build-system python-build-system)
    (inputs
      `(("python-pytest" ,python-pytest)
        ("python-pytest-runner" ,python-pytest-runner)
        ("python-setuptools" ,python-setuptools)))
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
            "0fi4a81kr5bcv5p4xgibqr595hyj5dafkqgsmfk96mfy8w71fajs"))))
    (inputs `(("python-setuptools" ,python-setuptools)))))

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
        (uri (string-append
               "https://pypi.python.org/packages/source/p/pep8/pep8-"
               version
               ".tar.gz"))
        (sha256
          (base32
            "12b9bbdbwnspxgak14xg58c130x2n0blxzlms5jn2dszn8qj3d0m"))))))

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
        (uri (string-append
               "https://pypi.python.org/packages/source/p/pyflakes/pyflakes-"
               version
               ".tar.gz"))
        (sha256
          (base32
            "0sbpq6pqm1i9wqi41mlfrsc5rk92jv4mskvlyxmnhlbdnc80ma1z"))))))

(define-public python2-pyflakes-0.8.1
  (package-with-python2 python-pyflakes-0.8.1))

(define-public python-flake8
  (package
    (name "python-flake8")
    (version "2.5.4")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "flake8" version))
        (sha256
          (base32
            "0bs9cz4fr99r2rwig1b8jwaadl1nan7kgpdzqwj0bwbckwbmh7nc"))))
    (build-system python-build-system)
    (inputs
      `(("python-setuptools" ,python-setuptools)
        ("python-pep8" ,python-pep8)
        ("python-pyflakes" ,python-pyflakes)
        ("python-mccabe" ,python-mccabe)
        ("python-mock" ,python-mock)
        ("python-nose" ,python-nose)))
    (home-page "https://gitlab.com/pycqa/flake8")
    (synopsis
      "The modular source code checker: pep8, pyflakes and co")
    (description
      "Flake8 is a wrapper around PyFlakes, pep8 and python-mccabe.")
    (license license:expat)))

(define-public python2-flake8
  (package-with-python2 python-flake8))

;; This will only be needed by the python-hacking package and will not be
;; necessary once python-hacking > 0.10.2 is released.
(define-public python-flake8-2.2.4
  (package (inherit python-flake8)
    (inputs
      `(("python-setuptools" ,python-setuptools)
        ("python-pep8" ,python-pep8-1.5.7)
        ("python-pyflakes" ,python-pyflakes-0.8.1)
        ("python-mccabe" ,python-mccabe-0.2.1)
        ("python-mock" ,python-mock)
        ("python-nose" ,python-nose)))
    (version "2.2.4")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "flake8" version))
        (sha256
          (base32
            "1r9wsry4va45h1rck5hxd3vzsg2q3y6lnl6pym1bxvz8ry19jwx8"))))))

(define-public python2-flake8-2.2.4
  (package-with-python2 python-flake8-2.2.4))

(define-public python-mistune
  (package
    (name "python-mistune")
    (version "0.7")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/m/mistune/mistune-"
             version
             ".tar.gz"))
       (sha256
        (base32
         "17zqjp9m4d1w3jf2rbbq5xshcw24q1vlcv24gkgfqqyyymajxahx"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-nose" ,python-nose)
       ("python-cython" ,python-cython)))
    (home-page "https://github.com/lepture/mistune")
    (synopsis "Markdown parser in pure Python")
    (description "This package provides a fast markdown parser in pure
Python.")
    (license bsd-3)))

(define-public python2-mistune
  (package-with-python2 python-mistune))

(define-public python-markdown
  (package
    (name "python-markdown")
    (version "2.6.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Markdown" version))
       (sha256
        (base32
         "0q758a3fiiawr20b3hhjfs677cwj6xi284yb7xspcvv0fdicz54d"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
                  (lambda _
                    (zero? (system* "python" "run-tests.py")))))))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-pyyaml" ,python-pyyaml)))
    (home-page "https://pythonhosted.org/Markdown/")
    (synopsis "Python implementation of Markdown")
    (description
     "This package provides a Python implementation of John Gruber's
Markdown.  The library features international input, various Markdown
extensions, and several HTML output formats.  A command line wrapper
markdown_py is also provided to convert Markdown files to HTML.")
    (license bsd-3)))

(define-public python2-markdown
  (package-with-python2 python-markdown))

(define-public python-ptyprocess
  (package
    (name "python-ptyprocess")
    (version "0.5")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/p/ptyprocess/ptyprocess-"
             version ".tar.gz"))
       (sha256
        (base32
         "0nggns5kikn32yyda2zrj1xdmh49pi3v0drggcdwljbv36r8zdyw"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-nose" ,python-nose)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
                  (lambda _
                    (zero? (system* "nosetests")))))))
    (home-page "https://github.com/pexpect/ptyprocess")
    (synopsis "Run a subprocess in a pseudo terminal")
    (description
     "This package provides a Python library used to launch a subprocess in a
pseudo terminal (pty), and interact with both the process and its pty.")
    (license isc)))

(define-public python2-ptyprocess
  (package-with-python2 python-ptyprocess))

(define-public python-terminado
  (package
    (name "python-terminado")
    (version "0.5")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/t/terminado/terminado-"
             version ".tar.gz"))
       (sha256
        (base32
         "1dkmp1n8dj5v1jl9mfrq8lwyc7dsfrvcmz2bgkpg315sy7pr7s33"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-tornado" ,python-tornado)
       ("python-ptyprocess" ,python-ptyprocess)))
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-nose" ,python-nose)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
                  (lambda _
                    (zero? (system* "nosetests")))))))
    (home-page "https://github.com/takluyver/terminado")
    (synopsis "Terminals served to term.js using Tornado websockets")
    (description "This package provides a Tornado websocket backend for the
term.js Javascript terminal emulator library.")
    (license bsd-2)))

(define-public python2-terminado
  (let ((terminado (package-with-python2 python-terminado)))
    (package (inherit terminado)
             (propagated-inputs
              `(("python2-tornado" ,python2-tornado)
                ("python2-backport-ssl-match-hostname"
                 ,python2-backport-ssl-match-hostname)
                ,@(alist-delete "python-tornado"
                                (package-propagated-inputs terminado)))))))

(define-public python-fonttools
  (package
    (name "python-fonttools")
    (version "2.5")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://pypi.python.org/packages/source/F/FontTools/"
                    "fonttools-" version ".tar.gz"))
              (sha256
               (base32
                "08ay3x4ijarwhl60gqx2i9jzq6pxs20p4snc2d1q5jagh4rn39lb"))))
    (build-system python-build-system)
    (arguments '(#:test-target "check"))
    (propagated-inputs
     ;; XXX: module not found if setuptools is not available.
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://github.com/behdad/fonttools")
    (synopsis "Tools to manipulate font files")
    (description
     "FontTools/TTX is a library to manipulate font files from Python.  It
supports reading and writinfg of TrueType/OpenType fonts, reading and writing
of AFM files, reading (and partially writing) of PS Type 1 fonts.  The package
also contains a tool called “TTX” which converts TrueType/OpenType fonts to and
from an XML-based format.")
    (license (non-copyleft "file://LICENSE.txt"
                           "See LICENSE.txt in the distribution."))))

(define-public python2-fonttools
  (package-with-python2 python-fonttools))

(define-public python-ly
  (package
    (name "python-ly")
    (version "0.9.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/p/python-ly/python-ly-"
             version ".tar.gz"))
       (sha256
        (base32
         "1y6ananq8fia4y4m5id6gvsrm68bzpzd1y46pfzvawic0wjg2l0l"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (synopsis "Tool and library for manipulating LilyPond files")
    (description "This package provides a Python library to parse, manipulate
or create documents in LilyPond format.  A command line program ly is also
provided that can be used to do various manipulations with LilyPond files.")
    (home-page "https://pypi.python.org/pypi/python-ly")
    (license gpl2+)))

(define-public python-appdirs
  (package
    (name "python-appdirs")
    (version "1.4.0")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
               "https://pypi.python.org/packages/source/a/appdirs/appdirs-"
               version
               ".tar.gz"))
        (sha256
          (base32
            "1iddva7v3fq0aqzsahkazxr7vpw28mqcrsy818z4wyiqnkplbhlg"))))
    (build-system python-build-system)
    (inputs
      `(("python-setuptools" ,python-setuptools)))
    (home-page "http://github.com/ActiveState/appdirs")
    (synopsis
      "Determine platform-specific dirs, e.g. a \"user data dir\"")
    (description
      "This module provides a portable way of finding out where user data
should be stored on various operating systems.")
    (license license:expat)))

(define-public python2-appdirs
  (package-with-python2 python-appdirs))

(define-public python-llfuse
  (package
    (name "python-llfuse")
    (version "1.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://bitbucket.org/nikratio/python-llfuse/downloads/"
                    "llfuse-" version ".tar.bz2"))
              (sha256
               (base32
                "1li7q04ljrvwharw4fblcbfhvk6s0l3lnv8yqb4c22lcgbkiqlps"))))
    (build-system python-build-system)
    (inputs
     `(("fuse" ,fuse)
       ("attr" ,attr)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-setuptools" ,python-setuptools)))
    (synopsis "Python bindings for FUSE")
    (description
     "Python-LLFUSE is a set of Python bindings for the low level FUSE API.")
    (home-page "https://bitbucket.org/nikratio/python-llfuse/")
    (license lgpl2.0+)
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
    (license (list license:expat lgpl2.0+))))

(define-public python-msgpack
  (package
    (name "python-msgpack")
    (version "0.4.7")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "msgpack-python" version))
              (sha256
               (base32
                "0syd7bs83qs9qmxw540jbgsildbqk4yb57fmrlns1021llli402y"))))
    (build-system python-build-system)
    (synopsis "MessagePack (de)serializer")
    (description "MessagePack is a fast, compact binary serialization format,
suitable for similar data to JSON.  This package provides CPython bindings for
reading and writing MessagePack data.")
    (home-page "https://pypi.python.org/pypi/msgpack-python/")
    (license asl2.0)
    (properties `((python2-variant . ,(delay python2-msgpack))))))

(define-public python2-msgpack
  (package (inherit (package-with-python2
                     (strip-python2-variant python-msgpack)))
    (native-inputs
     `(("python2-setuptools" ,python2-setuptools)))))

(define-public python2-msgpack
  (package-with-python2 python-msgpack))

(define-public python-netaddr
  (package
    (name "python-netaddr")
    (version "0.7.18")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/n/netaddr/netaddr-"
             version
             ".tar.gz"))
       (sha256
         (base32
          "06dxjlbcicq7q3vqy8agq11ra01kvvd47j4mk6dmghjsyzyckxd1"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f)) ;; No tests.
    (inputs
      `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/drkjam/netaddr/")
    (synopsis "Pythonic manipulation of  network addresses")
    (description
      "A Python library for representing and manipulating IPv4, IPv6, CIDR, EUI
and MAC network addresses.")
    (license bsd-3)))

(define-public python2-netaddr
  (package-with-python2 python-netaddr))

(define-public python-wrapt
  (package
    (name "python-wrapt")
    (version "1.10.5")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
               "https://pypi.python.org/packages/source/w/wrapt/wrapt-"
               version
               ".tar.gz"))
        (sha256
          (base32
            "0cq8rlpzkxzk48b50yrfhzn1d1hrq4gjcdqlrgq4v5palgiv9jwr"))))
    (build-system python-build-system)
    (arguments
     ;; Tests are not included in the tarball, they are only available in the
     ;; git repository.
     `(#:tests? #f))
    (inputs
      `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/GrahamDumpleton/wrapt")
    (synopsis "Module for decorators, wrappers and monkey patching")
    (description
      "The aim of the wrapt module is to provide a transparent object proxy for
  Python, which can be used as the basis for the construction of function
  wrappers and decorator functions.")
    (license bsd-2)))

(define-public python2-wrapt
  (package-with-python2 python-wrapt))

(define-public python-iso8601
  (package
  (name "python-iso8601")
  (version "0.1.10")
  (source
    (origin
      (method url-fetch)
      (uri (string-append
             "https://pypi.python.org/packages/source/i/iso8601/iso8601-"
             version
             ".tar.gz"))
      (sha256
        (base32
          "1qf01afxh7j4gja71vxv345if8avg6nnm0ry0zsk6j3030xgy4p7"))))
  (build-system python-build-system)
  (inputs
    `(("python-setuptools" ,python-setuptools)))
  (home-page "https://bitbucket.org/micktwomey/pyiso8601")
  (synopsis "Module to parse ISO 8601 dates")
  (description
    "This module parses the most common forms of ISO 8601 date strings (e.g.
@code{2007-01-14T20:34:22+00:00}) into @code{datetime} objects.")
  (license license:expat)))

(define-public python2-iso8601
  (package-with-python2 python-iso8601))

(define-public python-monotonic
  (package
    (name "python-monotonic")
    (version "0.3")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
               "https://pypi.python.org/packages/source/m/monotonic/monotonic-"
               version
               ".tar.gz"))
        (sha256
          (base32
            "0yz0bcbwx8r2c01czzfpbrxddynxyk9k95jj8h6sgcb7xmfvl998"))))
    (build-system python-build-system)
    (inputs
      `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/atdt/monotonic")
    (synopsis "Implementation of time.monotonic() for Python 2 & < 3.3")
    (description
      "This module provides a monotonic() function which returns the value (in
fractional seconds) of a clock which never goes backwards.")
    (license asl2.0)))

(define-public python2-monotonic
  (package-with-python2 python-monotonic))

(define-public python-webob
  (package
    (name "python-webob")
    (version "1.5.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "WebOb" version))
       (sha256
        (base32
         "02bhhzijfhv8hmi1i54d4b0v43liwhnywhflvxsv4x3zax9s3afq"))))
    (build-system python-build-system)
    (inputs
      `(("python-nose" ,python-nose)
        ("python-setuptools" ,python-setuptools)))
    (home-page "http://webob.org/")
    (synopsis "WSGI request and response object")
    (description
      "WebOb provides wrappers around the WSGI request environment, and an
object to help create WSGI responses.")
    (license license:expat)))

(define-public python2-webob
  (package-with-python2 python-webob))

(define-public python-xlrd
  (package
    (name "python-xlrd")
    (version "0.9.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://pypi.python.org/packages/source/x/"
                                  "xlrd/xlrd-" version ".tar.gz"))
              (sha256
               (base32
                "0wpa55nvidmm5m2qr622dsh3cj46akdk0h3zjgzschcmydck73cf"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; Current test in setup.py does not work as of 0.9.4, so use nose to
         ;; run tests instead for now.
         (replace 'check (lambda _ (zero? (system* "nosetests")))))))
    (native-inputs `(("python-nose"       ,python-nose)
                     ("python-setuptools" ,python-setuptools)))
    (home-page "http://www.python-excel.org/")
    (synopsis "Library for extracting data from Excel files")
    (description "This packages provides a library to extract data from
spreadsheets using Microsoft Excel® proprietary file formats @samp{.xls} and
@samp{.xlsx} (versions 2.0 onwards).  It has support for Excel dates and is
Unicode-aware.  It is not intended as an end-user tool.")
    (license bsd-3)))

(define-public python2-xlrd
  (package-with-python2 python-xlrd))

(define-public python-prettytable
  (package
    (name "python-prettytable")
    (version "0.7.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/P/PrettyTable/"
             "prettytable-" version ".tar.bz2"))
       (sha256
        (base32
         "0diwsicwmiq2cpzpxri7cyl5fmsvicafw6nfqf6p6p322dji2g45"))))
    (build-system python-build-system)
    (inputs
      `(("python-setuptools" ,python-setuptools)))
    (home-page "http://code.google.com/p/prettytable/")
    (synopsis "Display tabular data in an ASCII table format")
    (description
      "A library designed to represent tabular data in visually appealing ASCII
tables.  PrettyTable allows for selection of which columns are to be printed,
independent alignment of columns (left or right justified or centred) and
printing of sub-tables by specifying a row range.")
    (license bsd-3)))

(define-public python2-prettytable
  (package-with-python2 python-prettytable))

(define-public python-pyasn1
  (package
    (name "python-pyasn1")
    (version "0.1.8")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/p/"
                           "pyasn1/pyasn1-" version ".tar.gz"))
       (sha256
        (base32
         "0iw31d9l0zwx35szkzq72hiw002wnqrlrsi9dpbrfngcl1ybwcsx"))))
    (build-system python-build-system)
    (home-page "http://pyasn1.sourceforge.net/")
    (synopsis "ASN.1 types and codecs")
    (description
     "This is an implementation of ASN.1 types and codecs in Python.  It is
suitable for a wide range of protocols based on the ASN.1 specification.")
    (license bsd-2)))

(define-public python2-pyasn1
  (package-with-python2 python-pyasn1))

(define-public python-pyasn1-modules
  (package
    (name "python-pyasn1-modules")
    (version "0.0.8")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pyasn1-modules" version))
        (sha256
         (base32
          "0drqgw81xd3fxdlg89kgd79zzrabvfncvkbybi2wr6w2y4s1jmhh"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (propagated-inputs
     `(("python-pyasn1" ,python-pyasn1)))
    (home-page "http://sourceforge.net/projects/pyasn1/")
    (synopsis "ASN.1 codec implementations")
    (description
     "Pyasn1-modules is a collection of Python modules providing ASN.1 types and
implementations of ASN.1-based codecs and protocols.")
    (license bsd-3)))

(define-public python2-pyasn1-modules
  (package-with-python2 python-pyasn1-modules))

(define-public python2-ipaddress
  (package
    (name "python2-ipaddress")
    (version "1.0.14")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/i/"
                           "ipaddress/ipaddress-" version ".tar.gz"))
       (sha256
        (base32
         "0givid4963n57nsjibms2fc347zmcs188q1hw9al1dkc9kj4nvr2"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f  ; no tests
       #:python ,python-2))
    (home-page "https://github.com/phihag/ipaddress")
    (synopsis "IP address manipulation library")
    (description
     "This package provides a fast, lightweight IPv4/IPv6 manipulation library
in Python.  This library is used to create, poke at, and manipulate IPv4 and
IPv6 addresses and networks.  This is a port of the Python 3.3 ipaddress
module to older versions of Python.")
    (license psfl)))

(define-public python-idna
  (package
    (name "python-idna")
    (version "2.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/i/"
                           "idna/idna-" version ".tar.gz"))
       (sha256
        (base32
         "0frxgmgi234lr9hylg62j69j4ik5zhg0wz05w5dhyacbjfnrl68n"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
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
    (license bsd-4)))

(define-public python2-idna
  (package-with-python2 python-idna))

(define-public python-pretend
  (package
    (name "python-pretend")
    (version "1.0.8")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/p/"
                           "pretend/pretend-" version ".tar.gz"))
       (sha256
        (base32
         "0r5r7ygz9m6d2bklflbl84cqhjkc2q12xgis8268ygjh30g2q3wk"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/alex/pretend")
    (synopsis "Library for stubbing in Python")
    (description
     "Pretend is a library to make stubbing with Python easier.  Stubbing is a
technique for writing tests.  You may hear the term mixed up with mocks,
fakes, or doubles.  Basically, a stub is an object that returns pre-canned
responses, rather than doing any computation.")
    (license bsd-3)))

(define-public python2-pretend
  (package-with-python2 python-pretend))

(define-public python-cryptography-vectors
  (package
    (name "python-cryptography-vectors")
    (version "1.2.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/c/"
                           "cryptography-vectors/cryptography_vectors-"
                           version ".tar.gz"))
       (sha256
        (base32
         "0shawgpax79gvjrj0a313sll9gaqys7q1hxngn6j4k24lmz7bwki"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/pyca/cryptography")
    (synopsis "Test vectors for the cryptography package.")
    (description
      "This package contains test vectors for the cryptography package.")
    ;; Distributed under either BSD-3 or ASL2.0
    (license (list bsd-3 asl2.0))))

(define-public python2-cryptography-vectors
  (package-with-python2 python-cryptography-vectors))

(define-public python-cryptography
  (package
    (name "python-cryptography")
    (version "1.2.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "cryptography" version))
       (sha256
        (base32
         "0kj511z4g21fhcr649pyzpl0zzkkc7hsgxxjys6z8wwfvmvirccf"))))
    (build-system python-build-system)
    (inputs
     `(("openssl" ,openssl)))
    (propagated-inputs
     `(("python-cffi" ,python-cffi)
       ("python-six" ,python-six)
       ("python-pyasn1" ,python-pyasn1)
       ("python-idna" ,python-idna)
       ("python-iso8601" ,python-iso8601)))
    (native-inputs
     `(("python-cryptography-vectors" ,python-cryptography-vectors)
       ("python-hypothesis" ,python-hypothesis)
       ("python-setuptools" ,python-setuptools)
       ("python-pretend" ,python-pretend)
       ("python-pyasn1" ,python-pyasn1)
       ("python-pyasn1-modules" ,python-pyasn1-modules)
       ("python-pytest" ,python-pytest)))
    (home-page "https://github.com/pyca/cryptography")
    (synopsis "Cryptographic recipes and primitives for Python")
    (description
      "cryptography is a package which provides cryptographic recipes and
primitives to Python developers.  It aims to be the “cryptographic standard
library” for Python.  The package includes both high level recipes, and low
level interfaces to common cryptographic algorithms such as symmetric ciphers,
message digests and key derivation functions.")
    ;; Distributed under either BSD-3 or ASL2.0
    (license (list bsd-3 asl2.0))
    (properties `((python2-variant . ,(delay python2-cryptography))))))

(define-public python2-cryptography
  (let ((crypto (package-with-python2
                 (strip-python2-variant python-cryptography))))
    (package (inherit crypto)
      (propagated-inputs
       `(("python2-ipaddress" ,python2-ipaddress)
         ("python2-backport-ssl-match-hostname"
          ,python2-backport-ssl-match-hostname)
         ("python2-enum34" ,python2-enum34)
         ,@(package-propagated-inputs crypto))))))

(define-public python-pyopenssl
  (package
    (name "python-pyopenssl")
    (version "0.15.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/p/"
                           "pyOpenSSL/pyOpenSSL-" version ".tar.gz"))
       (sha256
        (base32
         "0wnnq15rhj7fhdcd8ycwiw6r6g3w9f9lcy6cigg8226vsrq618ph"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-tests
          (lambda* (#:key inputs #:allow-other-keys)
            (substitute* "OpenSSL/test/test_ssl.py"
              (("client\\.connect\\(\\('verisign\\.com', 443\\)\\)")
               "return True")
              ;; FIXME: disable broken test
              (("test_set_tmp_ecdh") "disabled__set_tmp_ecdh"))
            (substitute* "OpenSSL/test/test_crypto.py"
              (("command = b\"openssl \"")
               (string-append "command = b\""
                              (assoc-ref inputs "openssl")
                              "/bin/openssl" " \""))
              ;; FIXME: disable four broken tests
              (("test_der")             "disabled__der")
              (("test_digest")          "disabled__digest")
              (("test_get_extension")   "disabled__get_extension")
              (("test_extension_count") "disabled__extension_count"))
            #t)))))
    (propagated-inputs
     `(("python-cryptography" ,python-cryptography)
       ("python-six" ,python-six)))
    (inputs
     `(("openssl" ,openssl)))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/pyca/pyopenssl")
    (synopsis "Python wrapper module around the OpenSSL library")
    (description
      "PyOpenSSL is a high-level wrapper around a subset of the OpenSSL
library.")
    (license asl2.0)))

(define-public python2-pyopenssl
  (package-with-python2 python-pyopenssl))

(define-public python-pip
  (package
    (name "python-pip")
    (version "8.0.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pip" version))
       (sha256
        (base32
         "08cm8d4228fj0qnrysy3qv1a6022zr3dcs25amd14lgxil6vvx26"))))
    (build-system python-build-system)
    (inputs
      `(("python-setuptools" ,python-setuptools)
        ("python-virtualenv" ,python-virtualenv)
        ;; Tests
        ("python-mock" ,python-mock)
        ("python-pytest" ,python-pytest)
        ("python-scripttest" ,python-scripttest)))
    (home-page "https://pip.pypa.io/")
    (synopsis
      "Package manager for Python software")
    (description
      "Pip is a package manager for Python software, that finds packages on the
Python Package Index (PyPI).")
    (license license:expat)))

(define-public python2-pip
  (package-with-python2 python-pip))

(define-public python-tlsh
  (package
    (name "python-tlsh")
    (version "3.4.4")
    (home-page "https://github.com/trendmicro/tlsh")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/trendmicro/tlsh/archive/v"
                                  version ".tar.gz"))
              (sha256
               (base32
                "00bhzjqrlh7v538kbkbn8lgx976j1138al3sdhklaizqjvpwyk4r"))
              (file-name (string-append name "-" version ".tar.gz"))))
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
    (license asl2.0)))

(define-public python2-tlsh
  (package
    (inherit python-tlsh)
    (name "python2-tlsh")
    (inputs `(("python" ,python-2)))))

(define-public python-libarchive-c
  (package
    (name "python-libarchive-c")
    (version "2.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "libarchive-c" version))
              (sha256
               (base32
                "0z4r7v3dhd6b3120mav05ff08srih176r2rg5k8kn7mjd9pslm2x"))))
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
                                         "/lib/libarchive.so'"))))

                     ;; Do not make a compressed egg (see
                     ;; <http://bugs.gnu.org/20765>).
                     (let ((port (open-file "setup.cfg" "a")))
                       (display "\n[easy_install]\nzip_ok = 0\n"
                                port)
                       (close-port port)
                       #t))))))
    (inputs
     `(("python-setuptools" ,python-setuptools)
       ("libarchive" ,libarchive)))
    (home-page "https://github.com/Changaco/python-libarchive-c")
    (synopsis "Python interface to libarchive")
    (description
     "This package provides Python bindings to libarchive, a C library to
access possibly compressed archives in many different formats.  It uses
Python's @code{ctypes} foreign function interface (FFI).")
    (license lgpl2.0+)))

(define-public python2-libarchive-c
  (package-with-python2 python-libarchive-c))

(define-public python-file
  (package
    (inherit file)
    (name "python-file")
    (build-system python-build-system)
    (arguments
     '(#:tests? #f                                ;no tests
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
    (self-native-input? #f)
    (synopsis "Python bindings to the libmagic file type guesser.  Note that
this module and the python-magic module both provide a \"magic.py\" file;
these two modules, which are different and were developed separately, both
serve the same purpose: provide Python bindings for libmagic.")))

(define-public python2-file
  (package-with-python2 python-file))

(define-public python-debian
  (package
    (name "python-debian")
    (version "0.1.23")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/p/python-debian/python-debian-"
             version ".tar.gz"))
       (sha256
        (base32
         "193faznwnjc3n5991wyzim6h9gyq1zxifmfrnpm3avgkh7ahyynh"))))
    (build-system python-build-system)
    (inputs
     `(("python-six" ,python-six)))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://packages.debian.org/sid/python-debian")
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
    (license gpl3+)))

(define-public python2-debian
  (package-with-python2 python-debian))

(define-public python-chardet
  (package
    (name "python-chardet")
    (version "2.3.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/c/chardet/chardet-"
             version
             ".tar.gz"))
       (sha256
        (base32
         "1ak87ikcw34fivcgiz2xvi938dmclh078az65l9x3rmgljrkhgp5"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/chardet/chardet")
    (synopsis "Universal encoding detector for Python 2 and 3")
    (description
     "This package provides @code{chardet}, a Python module that can
automatically detect a wide range of file encodings.")
    (license lgpl2.1+)))

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
     `(("python-pytest" ,python-pytest)
       ("python-setuptools" ,python-setuptools)))
    (arguments
     `(#:phases (alist-replace
                 'check
                 (lambda _ (zero? (system* "py.test")))
                 %standard-phases)))
    (home-page "http://docopt.org")
    (synopsis "Command-line interface description language for Python")
    (description "This library allows the user to define a command-line
interface from a program's help message rather than specifying it
programatically with command-line parsers like @code{getopt} and
@code{argparse}.")
    (license license:expat)))

(define-public python2-docopt
  (package-with-python2 python-docopt))

(define-public python-zope-event
  (package
    (name "python-zope-event")
    (version "4.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/z"
                           "/zope.event/zope.event-" version ".tar.gz"))
       (sha256
        (base32
         "11p75zpfz3ffhz21nzx9wb23xs993ck5s6hkjcvhswwizni5jynw"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://pypi.python.org/pypi/zope.event")
    (synopsis "Event publishing system for Python")
    (description "Zope.event provides an event publishing API, intended for
use by applications which are unaware of any subscribers to their events.  It
is a simple event-dispatching system on which more sophisticated event
dispatching systems can be built.")
    (license zpl2.1)))

(define-public python2-zope-event
  (package-with-python2 python-zope-event))

(define-public python-zope-interface
  (package
    (name "python-zope-interface")
    (version "4.1.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/z"
                           "/zope.interface/zope.interface-" version ".tar.gz"))
       (sha256
        (base32
         "0ks8h73b2g4bkad821qbv0wzjppdrwys33i7ka45ik3wxjg1l8if"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-zope-event" ,python-zope-event)))
    (home-page "https://github.com/zopefoundation/zope.interface")
    (synopsis "Python implementation of the \"design by contract\"
methodology")
    (description "Zope.interface provides an implementation of \"object
interfaces\" for Python.  Interfaces are a mechanism for labeling objects as
conforming to a given API or contract.")
    (license zpl2.1)))

(define-public python2-zope-interface
  (package-with-python2 python-zope-interface))

(define-public python-zope-exceptions
  (package
    (name "python-zope-exceptions")
    (version "4.0.8")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/z"
                           "/zope.exceptions/zope.exceptions-"
                           version ".tar.gz"))
       (sha256
        (base32
         "0zwxaaa66sqxg5k7zcrvs0fbg9ym1njnxnr28dfmchzhwjvwnfzl"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; circular dependency with zope.testrunner
    (propagated-inputs
     `(("python-zope-interface" ,python-zope-interface)))
    (home-page "http://cheeseshop.python.org/pypi/zope.exceptions")
    (synopsis "Zope exceptions")
    (description "Zope.exceptions provides general-purpose exception types
that have uses outside of the Zope framework.")
    (license zpl2.1)))

(define-public python2-zope-exceptions
  (package-with-python2 python-zope-exceptions))

(define-public python-zope-testing
  (package
    (name "python-zope-testing")
    (version "4.5.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/z"
                           "/zope.testing/zope.testing-" version ".tar.gz"))
       (sha256
        (base32
         "1yvglxhzvhl45mndvn9gskx2ph30zz1bz7rrlyfs62fv2pvih90s"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-zope-exceptions" ,python-zope-exceptions)))
    (propagated-inputs
     `(("python-zope-interface" ,python-zope-interface)))
    (home-page "http://pypi.python.org/pypi/zope.testing")
    (synopsis "Zope testing helpers")
    (description "Zope.testing provides a number of testing utilities for HTML
forms, HTTP servers, regular expressions, and more.")
    (license zpl2.1)))

(define-public python2-zope-testing
  (package-with-python2 python-zope-testing))

(define-public python-zope-testrunner
  (package
    (name "python-zope-testrunner")
    (version "4.4.9")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/z"
                           "/zope.testrunner/zope.testrunner-"
                           version ".zip"))
       (sha256
        (base32
         "1r7iqknhh55y45f64mz5hghgvzx34h1i11k350s0avx6q8gznja1"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-six" ,python-six)
       ("python-zope-exceptions" ,python-zope-exceptions)
       ("python-zope-testing" ,python-zope-testing)
       ("unzip" ,unzip)))
    (propagated-inputs
     `(("python-zope-interface" ,python-zope-interface)))
    (home-page "http://pypi.python.org/pypi/zope.testrunner")
    (synopsis "Zope testrunner script")
    (description "Zope.testrunner provides a script for running Python
tests.")
    (license zpl2.1)))

(define-public python2-zope-testrunner
  (let ((base (package-with-python2 python-zope-testrunner)))
    (package
      (inherit base)
      (native-inputs
       (append (package-native-inputs base)
               `(("python2-subunit" ,python2-subunit)
                 ("python2-mimeparse" ,python2-mimeparse)))))))

(define-public python-zope-i18nmessageid
  (package
    (name "python-zope-i18nmessageid")
    (version "4.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/z"
             "/zope.i18nmessageid/zope.i18nmessageid-"
             version ".tar.gz"))
       (sha256
        (base32
         "1rslyph0klk58dmjjy4j0jxy21k03azksixc3x2xhqbkv97cmzml"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://pypi.python.org/pypi/zope.i18nmessageid")
    (synopsis "Message identifiers for internationalization")
    (description "Zope.i18nmessageid provides facilities for declaring
internationalized messages within program source text.")
    (license zpl2.1)))

(define-public python2-zope-i18nmessageid
  (package-with-python2 python-zope-i18nmessageid))

(define-public python-zope-schema
  (package
    (name "python-zope-schema")
    (version "4.4.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/z"
                           "/zope.schema/zope.schema-" version ".tar.gz"))
       (sha256
        (base32
         "1p943jdxb587dh7php4vx04qvn7b2877hr4qs5zyckvp5afhhank"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-zope-event" ,python-zope-event)
       ("python-zope-interface" ,python-zope-interface)))
    (native-inputs
     `(("python-zope-testing" ,python-zope-testing)))
    (home-page "http://pypi.python.org/pypi/zope.schema")
    (synopsis "Zope data schemas")
    (description "Zope.scheme provides extensions to zope.interface for
defining data schemas.")
    (license zpl2.1)))

(define-public python2-zope-schema
  (package-with-python2 python-zope-schema))

(define-public python-zope-configuration
  (package
    (name "python-zope-configuration")
    (version "4.0.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://pypi.python.org/packages/source/z"
                                  "/zope.configuration/zope.configuration-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1x9dfqypgympnlm25p9m43xh4qv3p7d75vksv9pzqibrb4cggw5n"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-zope-i18nmessageid" ,python-zope-i18nmessageid)
       ("python-zope-schema" ,python-zope-schema)))
    (home-page "http://pypi.python.org/pypi/zope.configuration")
    (synopsis "Zope Configuration Markup Language")
    (description "Zope.configuration implements ZCML, the Zope Configuration
Markup Language.")
    (license zpl2.1)))

(define-public python2-zope-configuration
  (package-with-python2 python-zope-configuration))

(define-public python-zope-proxy
  (package
    (name "python-zope-proxy")
    (version "4.1.6")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/z"
                           "/zope.proxy/zope.proxy-" version ".tar.gz"))
       (sha256
        (base32
         "0pqwwmvm1prhwv1ziv9lp8iirz7xkwb6n2kyj36p2h0ppyyhjnm4"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-zope-interface" ,python-zope-interface)))
    (home-page "http://pypi.python.org/pypi/zope.proxy")
    (synopsis "Generic, transparent proxies")
    (description "Zope.proxy provides generic, transparent proxies for Python.
Proxies are special objects which serve as mostly-transparent wrappers around
another object, intervening in the apparent behavior of the wrapped object
only when necessary to apply the policy (e.g., access checking, location
brokering, etc.) for which the proxy is responsible.")
    (license zpl2.1)))

(define-public python2-zope-proxy
  (package-with-python2 python-zope-proxy))

(define-public python-zope-location
  (package
    (name "python-zope-location")
    (version "4.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/z"
                           "/zope.location/zope.location-" version ".tar.gz"))
       (sha256
        (base32
         "1nj9da4ksiyv3h8n2vpzwd0pb03mdsh7zy87hfpx72b6p2zcwg74"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-zope-proxy" ,python-zope-proxy)
       ("python-zope-schema" ,python-zope-schema)))
    (home-page "http://pypi.python.org/pypi/zope.location/")
    (synopsis "Zope location library")
    (description "Zope.location implements the concept of \"locations\" in
Zope3, which are are special objects that have a structural location.")
    (license zpl2.1)))

(define-public python2-zope-location
  (package-with-python2 python-zope-location))

(define-public python-zope-security
  (package
    (name "python-zope-security")
    (version "4.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/z"
                           "/zope.security/zope.security-" version ".tar.gz"))
       (sha256
        (base32
         "14zmf684amc0x32kq05yxnhfqd1cmyhafkw05gn81rn90zjv6ssy"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-zope-i18nmessageid" ,python-zope-i18nmessageid)
       ("python-zope-component" ,python-zope-component)
       ("python-zope-location" ,python-zope-location)
       ("python-zope-proxy" ,python-zope-proxy)
       ("python-zope-schema" ,python-zope-schema)
       ("python-zope-testrunner" ,python-zope-testrunner)
       ("python-zope-testing" ,python-zope-testing)))
    (home-page "http://pypi.python.org/pypi/zope.security")
    (synopsis "Zope security framework")
    (description "Zope.security provides a generic mechanism to implement
security policies on Python objects.")
    (license zpl2.1)))

(define-public python2-zope-security
  (let ((zope-security (package-with-python2 python-zope-security)))
    (package (inherit zope-security)
      (propagated-inputs
       `(("python2-zope-testrunner" ,python2-zope-testrunner)
         ,@(alist-delete
            "python-zope-testrunner"
            (package-propagated-inputs zope-security)))))))

(define-public python-zope-component
  (package
    (name "python-zope-component")
    (version "4.2.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/z"
                           "/zope.component/zope.component-" version ".tar.gz"))
       (sha256
        (base32
         "06pqr8m5jv12xjyy5b59hh9anl61cxkzhw9mka33r3nxalmi2b18"))))
    (build-system python-build-system)
    (arguments
     ;; Skip tests due to circular dependency with python-zope-security.
     '(#:tests? #f))
    (native-inputs
     `(("python-zope-testing" ,python-zope-testing)))
    (propagated-inputs
     `(("python-zope-event" ,python-zope-event)
       ("python-zope-interface" ,python-zope-interface)
       ("python-zope-i18nmessageid" ,python-zope-i18nmessageid)
       ("python-zope-configuration" ,python-zope-configuration)))
    (home-page "https://github.com/zopefoundation/zope.component")
    (synopsis "Zope Component Architecture")
    (description "Zope.component represents the core of the Zope Component
Architecture.  Together with the zope.interface package, it provides
facilities for defining, registering and looking up components.")
    (license zpl2.1)))

(define-public python2-zope-component
  (package-with-python2 python-zope-component))

(define-public python2-pythondialog
  (package
    (name "python2-pythondialog")
    (version "3.3.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/p/"
                           "python2-pythondialog/python2-pythondialog-"
                           version ".tar.gz"))
       (sha256
        (base32
         "1yhkagsh99bfi592ymczf8rnw8rk6n9hdqy3dd98m3yrx8zmjvry"))))
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
       #:python ,python-2
       #:tests? #f)) ; no test suite
    (propagated-inputs
     `(("dialog" ,dialog)))
    (home-page "http://pythondialog.sourceforge.net/")
    (synopsis "Python interface to the UNIX dialog utility")
    (description "A Python wrapper for the dialog utility.  Its purpose is to
provide an easy to use, pythonic and comprehensive Python interface to dialog.
This allows one to make simple text-mode user interfaces on Unix-like systems")
    (license lgpl2.1)))

(define-public python-pyrfc3339
  (package
    (name "python-pyrfc3339")
    (version "1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyRFC3339" version))
       (sha256
        (base32
         "0dgm4l9y8jiax5cp6yxjd2i27cq8h33sh81n1wfbmnmqb32cdywd"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pytz" ,python-pytz)))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/kurtraschke/pyRFC3339")
    (synopsis "Python timestamp library")
    (description "Python library for generating and parsing RFC 3339-compliant
timestamps.")
    (license license:expat)))

(define-public python2-pyrfc3339
  (package-with-python2 python-pyrfc3339))

(define-public python-werkzeug
  (package
    (name "python-werkzeug")
    (version "0.11.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/W/Werkzeug"
                           "/Werkzeug-" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1gzwn1lkl90f3l1nzzxr7vjhm21qk8f837i8rvny5a209fcrhkzb"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "http://werkzeug.pocoo.org/")
    (synopsis "Utilities for WSGI applications")
    (description "One of the most advanced WSGI utility modules.  It includes a
powerful debugger, full-featured request and response objects, HTTP utilities to
handle entity tags, cache control headers, HTTP dates, cookie handling, file
uploads, a powerful URL routing system and a bunch of community-contributed
addon modules.")
    (license x11)))

(define-public python2-werkzeug
  (package-with-python2 python-werkzeug))

(define-public python-configobj
  (package
    (name "python-configobj")
    (version "5.0.6")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://pypi.python.org/packages/source/c/configobj/"
                    "configobj-" version ".tar.gz"))
              (sha256
               (base32
                "00h9rcmws03xvdlfni11yb60bz3kxfvsj6dg6nrpzj71f03nbxd2"))
              ;; Patch setup.py so it looks for python-setuptools, which is
              ;; required to parse the keyword 'install_requires' in setup.py.
              (patches (list (search-patch "python-configobj-setuptools.patch")))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ("python-six" ,python-six)))
    (synopsis "Config file reading, writing and validation")
    (description "ConfigObj is a simple but powerful config file reader and
writer: an ini file round tripper.  Its main feature is that it is very easy to
use, with a straightforward programmer’s interface and a simple syntax for
config files.")
    (home-page "https://github.com/DiffSK/configobj")
    (license bsd-3)))

(define-public python2-configobj
  (package-with-python2 python-configobj))

(define-public python-configargparse
  (package
    (name "python-configargparse")
    (version "0.10.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://pypi.python.org/packages/source/C/ConfigArgParse/"
                    "ConfigArgParse-" version ".tar.gz"))
              (sha256
               (base32
                "19wh919gbdbzxzpagg52q3lm62yicm95ddlcx77dyjc1slyshl1v"))))
    (build-system python-build-system)
    (arguments
     ;; FIXME: Bug in test suite filed upstream:
     ;; https://github.com/bw2/ConfigArgParse/issues/32
     '(#:tests? #f))
    (synopsis "Replacement for argparse")
    (description "A drop-in replacement for argparse that allows options to also
be set via config files and/or environment variables.")
    (home-page "https://github.com/bw2/ConfigArgParse")
    (license license:expat)))

(define-public python2-configargparse
  (package-with-python2 python-configargparse))

(define-public python-ndg-httpsclient
  (package
    (name "python-ndg-httpsclient")
    (version "0.4.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://pypi.python.org/packages/source/n/ndg-httpsclient/"
                    "ndg_httpsclient-" version ".tar.gz"))
              (sha256
                (base32
                  "0x32ibixm3vv5m9xfk83xsqm8xcqw4dd0khbh6qbri6rxgymbhg8"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pyopenssl" ,python-pyopenssl)))
    (synopsis "HTTPS support for Python's httplib and urllib2")
    (description "This is a HTTPS client implementation for httplib and urllib2
based on PyOpenSSL.  PyOpenSSL provides a more fully featured SSL implementation
over the default provided with Python and importantly enables full verification
of the SSL peer.")
    (home-page "https://github.com/cedadev/ndg_httpsclient/")
    (license bsd-3)))

;; python2-openssl requires special care, so package-with-python2 is
;; insufficient.
(define-public python2-ndg-httpsclient
  (package (inherit python-ndg-httpsclient)
    (name "python2-ndg-httpsclient")
    (arguments `(#:python ,python-2))
    (propagated-inputs
     `(("python2-pyopenssl" ,python2-pyopenssl)))))

(define-public python-contextlib2
  (package
    (name "python-contextlib2")
    (version "0.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "contextlib2" version))
       (sha256
        (base32
         "0cmp131dlh0d0zvw0aza1zd13glvngzk8lb4avks0hm7yxwdr9am"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _ (zero?
                      (system*
                       "python" "test_contextlib2.py" "-v")))))))
    (home-page "http://contextlib2.readthedocs.org/")
    (synopsis "Tools for decorators and context managers")
    (description "This module is primarily a backport of the Python
3.2 contextlib to earlier Python versions.  Like contextlib, it
provides utilities for common tasks involving decorators and context
managers.  It also contains additional features that are not part of
the standard library.")
    (license psfl)))

(define-public python2-contextlib2
  (package-with-python2 python-contextlib2))

(define-public python-texttable
  (package
    (name "python-texttable")
    (version "0.8.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "texttable" version))
       (sha256
        (base32
         "0bkhs4dx9s6g7fpb969hygq56hyz4ncfamlynw72s0n6nqfbd1w5"))))
    (build-system python-build-system)
    (arguments '(#:tests? #f)) ; no tests
    (home-page "https://github.com/foutaise/texttable/")
    (synopsis "Python module for creating simple ASCII tables")
    (description "Texttable is a Python module for creating simple ASCII
tables.")
    (license lgpl2.1+)))

(define-public python2-texttable
  (package-with-python2 python-texttable))

(define-public python-websocket-client
  (package
    (name "python-websocket-client")
    (version "0.34.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/w"
                           "/websocket-client/websocket_client-"
                           version ".tar.gz"))
       (sha256
        (base32
         "1prdx6d49f1cff17kzj15bnz09palfdgc1m5dkq9jd4mr90n4ak8"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-six" ,python-six))) ; for tests
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/liris/websocket-client")
    (synopsis "WebSocket client for Python")
    (description "The Websocket-client module provides the low level APIs for
WebSocket usage in Python programs.")
    (license lgpl2.1+)))

(define-public python2-websocket-client
  (package-with-python2 python-websocket-client))

(define-public python-atomicwrites
  (package
    (name "python-atomicwrites")
    (version "1.0.0")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "atomicwrites" version))
             (sha256
              (base32
               "019fa4771q7fb1167yfbh6msdzcqini6v7i59rmf72mzdjd7x5qv"))))
    (build-system python-build-system)
    (synopsis "Atomic file writes in Python")
    (description "Library for atomic file writes using platform dependent tools
for atomic filesystem operations.")
    (home-page "https://github.com/untitaker/python-atomicwrites")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-atomicwrites))))))

(define-public python2-atomicwrites
  (package (inherit (package-with-python2
                     (strip-python2-variant python-atomicwrites)))
    (native-inputs
     `(("python2-setuptools" ,python2-setuptools)))))

(define-public python-requests-toolbelt
  (package
    (name "python-requests-toolbelt")
    (version "0.6.0")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "requests-toolbelt" version))
             (sha256
              (base32
               "07slish560haspn0hpwgy2izhk2snqq06s6acp8xzmhhz079qknc"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-requests" ,python-requests)))
    (synopsis "Extensions to python-requests")
    (description "This is a toolbelt of useful classes and functions to be used
with python-requests.")
    (home-page "https://github.com/sigmavirus24/requests-toolbelt")
    (license asl2.0)))

(define-public python-click-threading
  (package
    (name "python-click-threading")
    (version "0.1.2")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "click-threading" version))
             (sha256
              (base32
               "0jmrv4334lfxa2ss53c06dafdwqbk1pb3ihd26izn5igw1bm8145"))))
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
    (version "0.1.3")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "click-log" version))
             (sha256
              (base32
               "0kdd1vminxpcfczxl2kkf285n0dr1gxh2cdbx1p6vkj7b7bci3gx"))))
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
    (propagated-inputs
     `(("python-pytest" ,python-pytest)))
    (synopsis "Namespace control and lazy-import mechanism")
    (description "With apipkg you can control the exported namespace of a Python
package and greatly reduce the number of imports for your users.  It is a small
pure Python module that works on virtually all Python versions.")
    (home-page "https://bitbucket.org/hpk42/apipkg")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-apipkg))))))

(define-public python2-apipkg
  (package
    (inherit (package-with-python2
              (strip-python2-variant python-apipkg)))
    (native-inputs
     `(("python2-setuptools" ,python2-setuptools)))))

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
    (native-inputs
     `(("python-setuptools-scm" ,python-setuptools-scm)))
    (propagated-inputs
     `(("python-apipkg" ,python-apipkg)))
    (synopsis "Rapid multi-Python deployment")
    (description "Execnet provides a share-nothing model with
channel-send/receive communication for distributing execution across many
Python interpreters across version, platform and network barriers.  It has a
minimal and fast API targetting the following uses:
@enumerate
@item distribute tasks to (many) local or remote CPUs
@item write and deploy hybrid multi-process applications
@item write scripts to administer multiple environments
@end enumerate")
    (home-page "http://codespeak.net/execnet/")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-execnet))))))

(define-public python2-execnet
  (let ((execnet (package-with-python2
                  (strip-python2-variant python-execnet))))
    (package
      (inherit execnet)
      (native-inputs
       `(("python2-setuptools" ,python2-setuptools)
         ,@(package-native-inputs execnet))))))

;;; The software provided by this package was integrated into pytest 2.8.
(define-public python-pytest-cache
  (package
    (name "python-pytest-cache")
    (version "1.0")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "pytest-cache" version))
             (sha256
              (base32
               "1a873fihw4rhshc722j4h6j7g3nj7xpgsna9hhg3zn6ksknnhx5y"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-execnet" ,python-execnet)))
    (synopsis "Py.test plugin with mechanisms for caching across test runs")
    (description "The pytest-cache plugin provides tools to rerun failures from
the last py.test invocation.")
    (home-page "https://bitbucket.org/hpk42/pytest-cache/")
    (license license:expat)))

(define-public python-pytest-localserver
  (package
    (name "python-pytest-localserver")
    (version "0.3.5")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "pytest-localserver" version))
             (sha256
              (base32
               "0dvqspjr6va55zwmnnc2mmpqc7mm65kxig9ya44x1z8aadzxpa4p"))))
    (build-system python-build-system)
    (arguments
      `(#:phases (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (zero? (system* "py.test" "--genscript=runtests.py"))
             (zero? (system* "py.test")))))))
    (native-inputs
     `(("unzip" ,unzip)))
    (propagated-inputs
     `(("python-pytest" ,python-pytest)
       ("python-requests" ,python-requests)
       ("python-six" ,python-six)
       ("python-werkzeug" ,python-werkzeug)))
    (synopsis "Py.test plugin to test server connections locally")
    (description "Pytest-localserver is a plugin for the pytest testing
framework which enables you to test server connections locally.")
    (home-page "https://pypi.python.org/pypi/pytest-localserver")
    (license license:expat)))

(define-public python-wsgi-intercept
  (package
    (name "python-wsgi-intercept")
    (version "1.1.2")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "wsgi_intercept" version))
             (sha256
              (base32
               "14ajy415ch5d0dnspg4b592p66wlgzah7ay218flp13517fp49zl"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-six" ,python-six)))
    (propagated-inputs
     `(("python-httplib2" ,python-httplib2)
       ("python-requests" ,python-requests)))
    (synopsis "Puts a WSGI application in place of a real URI for testing")
    (description "Wsgi_intercept installs a WSGI application in place of a real
URI for testing.  Testing a WSGI application normally involves starting a
server at a local host and port, then pointing your test code to that address.
Instead, this library lets you intercept calls to any specific host/port
combination and redirect them into a WSGI application importable by your test
program.  Thus, you can avoid spawning multiple processes or threads to test
your Web app.")
    (home-page "https://github.com/cdent/wsgi-intercept")
    (license license:expat)))

(define-public python-pytest-xprocess
  (package
    (name "python-pytest-xprocess")
    (version "0.9.1")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "pytest-xprocess" version))
             (sha256
              (base32
               "17zlql1xqw3ywcgwwbqmw633aly99lab12hm02asr8awvg5603pp"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pytest" ,python-pytest)
       ("python-pytest-cache" ,python-pytest-cache)
       ("python-psutil" ,python-psutil)))
    (synopsis "Pytest plugin to manage external processes across test runs")
    (description "Pytest-xprocess is an experimental py.test plugin for managing
processes across test runs.")
    (home-page "https://bitbucket.org/pytest-dev/pytest-xprocess")
    (license license:expat)))

(define-public python-icalendar
  (package
    (name "python-icalendar")
    (version "3.9.1")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "icalendar" version))
             (sha256
              (base32
               "0fhrczdj3jxy5bvswphp3vys7vwv5c9bpwg7asykqwa3z6253q6q"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-dateutil-2" ,python-dateutil-2)
       ("python-pytz" ,python-pytz)))
    (synopsis "Python library for parsing iCalendar files")
    (description "The icalendar package is a parser/generator of iCalendar
files for use with Python.")
    (home-page "https://github.com/collective/icalendar")
    (license bsd-2)))

(define-public python-sphinxcontrib-newsfeed
  (package
    (name "python-sphinxcontrib-newsfeed")
    (version "0.1.4")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "sphinxcontrib-newsfeed" version))
             (sha256
              (base32
               "1d7gam3mn8v4in4p16yn3v10vps7nnaz6ilw99j4klij39dqd37p"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-docutils" ,python-docutils)
       ("python-sphinx" ,python-sphinx)))
    (synopsis "News Feed extension for Sphinx")
    (description "Sphinxcontrib-newsfeed is an extension for adding a simple
Blog, News or Announcements section to a Sphinx website.")
    (home-page "https://bitbucket.org/prometheus/sphinxcontrib-newsfeed")
    (license bsd-2)))

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
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/kennethreitz/args")
    (synopsis "Command-line argument parser")
    (description
     "This library provides a Python module to parse command-line arguments.")
    (license bsd-3)))

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
    (inputs
     `(("python-args" ,python-args)
       ("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/kennethreitz/clint")
    (synopsis "Command-line interface tools")
    (description
     "Clint is a Python module filled with a set of tools for developing
command-line applications, including tools for colored and indented
output, progress bar display, and pipes.")
    (license isc)))

(define-public python2-clint
  (package-with-python2 python-clint))

(define-public python-astor
  (package
    (name "python-astor")
    (version "0.5")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "astor" version))
              (sha256
               (base32
                "1fdafq5hkis1fxqlmhw0sn44zp2ar46nxhbc22cvwg7hsd8z5gsa"))))
    (build-system python-build-system)
    (inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/berkerpeksag/astor")
    (synopsis "Read and write Python ASTs")
    (description
     "Astor is designed to allow easy manipulation of Python source via the
Abstract Syntax Tree.")
    (license bsd-3)))

(define-public python2-astor
  (package-with-python2 python-astor))

(define-public python-rply
  (package
    (name "python-rply")
    (version "0.7.4")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "rply" version))
              (sha256
               (base32
                "12rp1d9ba7nvd5rhaxi6xzx1rm67r1k1ylsrkzhpwnphqpb06cvj"))))
    (build-system python-build-system)
    (inputs
     `(("python-appdirs" ,python-appdirs)
       ("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/alex/rply")
    (synopsis "Parser generator for Python")
    (description
     "This package provides a pure Python based parser generator, that also
works with RPython.  It is a more-or-less direct port of David Bazzley's PLY,
with a new public API, and RPython support.")
    (license bsd-3)))

(define-public python2-rply
  (package-with-python2 python-rply))

(define-public python-hy
  (package
    (name "python-hy")
    (version "0.11.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "hy" version))
              (sha256
               (base32
                "1msqv747iz12r73mz4qvsmlwkddwjvrahlrk7ysrcz07h7dsscxs"))))
    (build-system python-build-system)
    (inputs
     `(("python-astor" ,python-astor)
       ("python-clint" ,python-clint)
       ("python-rply" ,python-rply)
       ("python-setuptools" ,python-setuptools)))
    (home-page "http://hylang.org/")
    (synopsis "Lisp frontend to Python")
    (description
     "Hy is a dialect of Lisp that's embedded in Python.  Since Hy transforms
its Lisp code into the Python Abstract Syntax Tree, you have the whole world of
Python at your fingertips, in Lisp form.")
    (license license:expat)))

(define-public python2-hy
  (package-with-python2 python-hy))

(define-public python-rauth
  (package
    (name "python-rauth")
    (version "0.7.2")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "rauth" version))
        (sha256
         (base32
          "00pq7zw429hhza9c0qzxiqp77m653jv09z92nralnmzwdf6pzicf"))))
    (build-system python-build-system)
    (arguments
     `(#:test-target "check"))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (propagated-inputs
     `(("python-requests" ,python-requests)))
    (home-page "https://github.com/litl/rauth")
    (synopsis "Python library for OAuth 1.0/a, 2.0, and Ofly")
    (description
     "Rauth is a Python library for OAuth 1.0/a, 2.0, and Ofly.  It also
provides service wrappers for convenient connection initialization and
authenticated session objects providing things like keep-alive.")
    (license license:expat)))

(define-public python2-rauth
  (let ((rauth (package-with-python2 python-rauth)))
    (package (inherit rauth)
      (propagated-inputs `(("python2-requests" ,python2-requests)))
      (native-inputs
       `(("python2-unittest2" ,python2-unittest2)
         ,@(package-native-inputs rauth))))))

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
    (native-inputs
     `(("python2-setuptools" ,python2-setuptools)))
    (home-page "https://github.com/MiCHiLU/python-functools32")
    (synopsis
     "Backport of the functools module from Python 3.2.3")
    (description
     "This package is a backport of the @code{functools} module from Python
3.2.3 for use with older versions of Python and PyPy.")
    (license license:expat)))

(define-public python-futures
  (package
    (name "python-futures")
    (version "3.0.3")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "futures" version))
        (sha256
         (base32
          "1vcb34dqhzkhbq1957vdjszhhm5y3j9ba88dgwhqx2zynhmk9qig"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (home-page "https://github.com/agronholm/pythonfutures")
    (synopsis
     "Backport of the concurrent.futures package from Python 3.2")
    (description
     "The concurrent.futures module provides a high-level interface for
asynchronously executing callables.  This package backports the
concurrent.futures package from Python 3.2")
    (license bsd-3)))

(define-public python2-futures
  (package-with-python2 python-futures))

(define-public python-urllib3
  (package
    (name "python-urllib3")
    (version "1.13.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "urllib3" version))
        (sha256
         (base32
          "10rrbr6c6k7j5dvfsyj4b2gsgxg9gggnn708qixf6ll57xqivfkf"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)
       ;; some packages for tests
       ("python-nose" ,python-nose)
       ("python-mock" ,python-mock)
       ("python-tornado" ,python-tornado)))
    (propagated-inputs
     `(;; packages for https security
       ("python-certifi" ,python-certifi)
       ("python-ndg-httpsclient" ,python-ndg-httpsclient)
       ("python-pyasn1" ,python-pyasn1)
       ("python-pyopenssl" ,python-pyopenssl)))
    (home-page "http://urllib3.readthedocs.org/")
    (synopsis "HTTP library with thread-safe connection pooling")
    (description
     "Urllib3 supports features left out of urllib and urllib2 libraries.  It
can reuse the same socket connection for multiple requests, it can POST files,
supports url redirection and retries, and also gzip and deflate decoding.")
    (license license:expat)))

(define-public python2-urllib3
  (package-with-python2 python-urllib3))

(define-public python-colorama
  (package
   (name "python-colorama")
   (version "0.3.3")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "colorama" version))
     (sha256
      (base32
       "1716z9pq1r5ys3nkg7wdrb3h2f9rmd0zdxpxzmx3bgwgf6xg48gb"))))
   (build-system python-build-system)
   (inputs
    `(("python-setuptools" ,python-setuptools)))
   (synopsis "colored terminal text rendering for Python")
   (description "Colorama is a Python library for rendering colored terminal
text.")
   (home-page "https://pypi.python.org/pypi/colorama")
   (license bsd-3)))

(define-public python2-colorama
  (package-with-python2 python-colorama))

(define-public python-rsa
  (package
   (name "python-rsa")
   (version "3.2")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "rsa" version))
     (sha256
      (base32
       "0xwp929g7lvb1sghxfpqlxvgg96qcwqdbhh27sjplx30n3xp3wrh"))))
   (build-system python-build-system)
   (inputs
    `(("python-pyasn1" ,python-pyasn1)
      ("python-setuptools" ,python-setuptools)))
   (synopsis "Pure-Python RSA implementation")
   (description "Python-RSA is a pure-Python RSA implementation.  It supports
encryption and decryption, signing and verifying signatures, and key
generation according to PKCS#1 version 1.5.  It can be used as a Python
library as well as on the command line.")
   (home-page "http://stuvel.eu/rsa")
   (license asl2.0)))

(define-public python2-rsa
  (package-with-python2 python-rsa))

(define-public python-pluggy
  (package
   (name "python-pluggy")
   (version "0.3.1")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "pluggy" version))
     (sha256
      (base32
       "18qfzfm40bgx672lkg8q9x5hdh76n7vax99aank7vh2nw21wg70m"))))
   (build-system python-build-system)
   (inputs
    `(("python-setuptools" ,python-setuptools)))
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
   (version "2.3.1")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "tox" version))
     (sha256
      (base32
       "1vj73ar4rimq3fwy5r2z3jv4g9qbh8rmpmncsc00g0k310acqzxz"))))
   (build-system python-build-system)
   (arguments
    ;; FIXME: Tests require a newer version of pytest, but upgrading our
    ;; pytest breaks other packages.
    '(#:tests? #f))
   (inputs
    `(("python-setuptools" ,python-setuptools)
      ("python-pluggy" ,python-pluggy)
      ("python-py" ,python-py)
      ("python-virtualenv" ,python-virtualenv)
      ("python-pytest" ,python-pytest)))
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
   (version "0.9.0")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "jmespath" version))
     (sha256
      (base32
       "0g9xvl69y7nr3w7ag4fsp6sm4fqf6vrqjw7504x2hzrrsh3ampq8"))))
   (build-system python-build-system)
   (inputs
    `(("python-setuptools" ,python-setuptools)))
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
   (version "1.3.17")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "botocore" version))
     (sha256
      (base32
       "08vpvdixx1c1lfv6vzjig68bpiir7wfyhzf49ysxgvhbprg5ra0w"))))
   (build-system python-build-system)
   (inputs
    `(("python-dateutil" ,python-dateutil-2)
      ("python-docutils" ,python-docutils)
      ("python-mock" ,python-mock)
      ("python-nose" ,python-nose)
      ("python-setuptools" ,python-setuptools)
      ("python-tox" ,python-tox)
      ("python-wheel" ,python-wheel)
      ("python-jmespath" ,python-jmespath)))
   (home-page "https://github.com/boto/botocore")
   (synopsis "Low-level interface to AWS")
   (description "Botocore is a Python library that provides a low-level
interface to the Amazon Web Services (AWS) API.")
   (license asl2.0)))

(define-public python2-botocore
  (package-with-python2 python-botocore))

(define-public awscli
  (package
   (name "awscli")
   (version "1.9.17")
   (source
    (origin
     (method url-fetch)
     (uri (string-append
           "https://pypi.python.org/packages/source/a/awscli/awscli-"
           version ".tar.gz"))
     (sha256
      (base32
       "1nj7jqvlpq57hfhby1njsbf8303gapa3njc4dramr6p3ffzvfi2i"))))
   (build-system python-build-system)
   (inputs
    `(("python-colorama" ,python-colorama)
      ("python-docutils" ,python-docutils)
      ("python-mock" ,python-mock)
      ("python-nose" ,python-nose)
      ("python-rsa" ,python-rsa)
      ("python-setuptools" ,python-setuptools)
      ("python-sphinx" ,python-sphinx)
      ("python-tox" ,python-tox)
      ("python-wheel" ,python-wheel)
      ("python-botocore" ,python-botocore)))
   (home-page "http://aws.amazon.com/cli/")
   (synopsis "Command line client for AWS")
   (description "AWS CLI provides a unified command line interface to the
Amazon Web Services (AWS) API.")
   (license asl2.0)))

(define-public python-hypothesis
  (package
    (name "python-hypothesis")
    (version "3.1.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "hypothesis" version))
              (sha256
               (base32
                "0qyqq9akm4vshhn8cngjc1qykcvsn7cz6dlm6njfsgpbraqrmbbw"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-flake8" ,python-flake8)
       ("python-pytest" ,python-pytest)))
    (synopsis "Library for property based testing")
    (description "Hypothesis is a library for testing your Python code against a
much larger range of examples than you would ever want to write by hand.  It’s
based on the Haskell library, Quickcheck, and is designed to integrate
seamlessly into your existing Python unit testing work flow.")
    (home-page "https://github.com/DRMacIver/hypothesis")
    (license mpl2.0)
    (properties `((python2-variant . ,(delay python2-hypothesis))))))

(define-public python2-hypothesis
  (let ((hypothesis (package-with-python2
                     (strip-python2-variant python-hypothesis))))
    (package (inherit hypothesis)
      (native-inputs
       `(("python2-enum34" ,python2-enum34)
         ("python2-setuptools" ,python2-setuptools))))))

(define-public python-pytest-subtesthack
  (package
    (name "python-pytest-subtesthack")
    (version "0.1.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pytest-subtesthack" version))
              (sha256
               (base32
                "15kzcr5pchf3id4ikdvlv752rc0j4d912n589l4rifp8qsj19l1x"))))
    (build-system python-build-system)
    (native-inputs
     `(;; setuptools required for python-2 variant
       ("python-setuptools" ,python-setuptools)))
    (propagated-inputs
     `(("python-pytest" ,python-pytest)))
    (synopsis "Set-up and tear-down fixtures for unit tests")
    (description "This plugin allows you to set up and tear down fixtures within
unit test functions that use @code{py.test}. This is useful for using
@command{hypothesis} inside py.test, as @command{hypothesis} will call the test
function multiple times, without setting up or tearing down fixture state as is
normally the case.")
    (home-page "https://github.com/untitaker/pytest-subtesthack/")
    (license unlicense)))

(define-public python2-pytest-subtesthack
  (package-with-python2 python-pytest-subtesthack))

(define-public python2-xdo
  (package
    (name "python2-xdo")
    (version "0.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://http.debian.net/debian/pool/main/p/python-xdo/"
                    "python-xdo_" version ".orig.tar.gz"))
              (sha256
               (base32
                "1kl5c1p0dyxf62plnk6fl77ycfb4whwjms16r14dxx8kn90hlqz4"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:tests? #f))  ; no tests provided
    (inputs
     `(("xdotool" ,xdotool)
       ("libX11" ,libx11)))
    (home-page "https://tracker.debian.org/pkg/python-xdo")
    (synopsis "Python library for simulating X11 keyboard/mouse input")
    (description "Provides bindings to libxdo for manipulating X11 via simulated
input.  (Note that this is mostly a legacy library; you may wish to look at
python-xdo for newer bindings.)")
    (license bsd-3)))

(define-public python-wtforms
  (package
    (name "python-wtforms")
    (version "2.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "WTForms" version ".zip"))
       (sha256
        (base32
         "0vyl26y9cg409cfyj8rhqxazsdnd0jipgjw06civhrd53yyi1pzz"))))
    (build-system python-build-system)
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page "http://wtforms.simplecodes.com/")
    (synopsis
     "Form validation and rendering library for Python web development")
    (description
     "WTForms is a flexible forms validation and rendering library
for Python web development.  It is very similar to the web form API
available in Django, but is a standalone package.")
    (license bsd-3)
    (properties `((python2-variant . ,(delay python2-wtforms))))))

(define-public python2-wtforms
  (package
    (inherit (package-with-python2
              (strip-python2-variant python-wtforms)))
    (inputs `(("python2-setuptools" ,python2-setuptools)))))

(define-public python-mako
  (package
    (name "python-mako")
    (version "1.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Mako" version))
       (sha256
        (base32
         "136kcjbs0s98qkx8a418b05dfblqp0kiiqyx8vhx4rarwc7bqi3n"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-markupsafe" ,python-markupsafe)
       ("python-mock" ,python-mock)
       ("python-nose" ,python-nose)))
    (home-page "http://www.makotemplates.org/")
    (synopsis "Templating language for Python")
    (description "Mako is a templating language for Python that compiles
templates into Python modules.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-mako))))))

(define-public python2-mako
  (let ((base (package-with-python2
               (strip-python2-variant python-mako))))
    (package
      (inherit base)
      (native-inputs
       (cons `("python2-setuptools" ,python2-setuptools)
             (package-native-inputs base))))))

(define-public python-waitress
  (package
    (name "python-waitress")
    (version "0.8.10")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "waitress" version))
       (sha256
        (base32
         "017n9ra6vvmq9d5sfhdzyzr1mg15x2hj2dhm4pdlw98c1ypw2h3w"))))
    (build-system python-build-system)
    (home-page "https://github.com/Pylons/waitress")
    (synopsis "Waitress WSGI server")
    (description "Waitress is meant to be a production-quality pure-Python WSGI
server with very acceptable performance.")
    (license zpl2.1)
    (properties `((python2-variant . ,(delay python2-waitress))))))

(define-public python2-waitress
  (package
    (inherit (package-with-python2
              (strip-python2-variant python-waitress)))
    (native-inputs `(("python2-setuptools" ,python2-setuptools)))))

(define-public python-wsgiproxy2
  (package
    (name "python-wsgiproxy2")
    (version "0.4.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "WSGIProxy2" version ".zip"))
       (sha256
        (base32
         "13kf9bdxrc95y9vriaz0viry3ah11nz4rlrykcfvb8nlqpx3dcm4"))))
    (build-system python-build-system)
    (native-inputs
     `(("unzip" ,unzip)
       ("python-nose" ,python-nose)
       ("python-coverage" ,python-coverage)))
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-webob" ,python-webob)))
    (home-page
     "https://github.com/gawel/WSGIProxy2/")
    (synopsis "WSGI Proxy with various http client backends")
    (description "WSGI turns HTTP requests into WSGI function calls.
WSGIProxy turns WSGI function calls into HTTP requests.
It also includes code to sign requests and pass private data,
and to spawn subprocesses to handle requests.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-wsgiproxy2))))))

(define-public python2-wsgiproxy2
  (let ((wsgiproxy2 (package-with-python2
                     (strip-python2-variant python-wsgiproxy2))))
    (package
      (inherit wsgiproxy2)
      (inputs `(("python2-setuptools" ,python2-setuptools)
                ,@(package-inputs wsgiproxy2))))))

(define-public python-pastedeploy
  (package
    (name "python-pastedeploy")
    (version "1.5.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "PasteDeploy" version))
       (sha256
        (base32
         "1jz3m4hq8v6hyhfjz9425nd3nvn52cvbfipdcd72krjmla4qz1fm"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)))
    (propagated-inputs
     ;; This package uses pkg_resources, part of setuptools, during runtime,
     ;; hence why not a native-input.
     `(("python-setuptools" ,python-setuptools)))
    (home-page "http://pythonpaste.org/deploy/")
    (synopsis
     "Load, configure, and compose WSGI applications and servers")
    (description
     "This tool provides code to load WSGI applications and servers from URIs;
these URIs can refer to Python Eggs for INI-style configuration files.  Paste
Script provides commands to serve applications based on this configuration
file.")
    (license license:expat)))

(define-public python2-pastedeploy
  (package-with-python2 python-pastedeploy))

(define-public python-paste
  (package
    (name "python-paste")
    (version "2.0.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Paste" version))
       (sha256
        (base32
         "16dsv9qi0r4qsrsb6dilpq2rx0fnglvh36flzywcdnm2jg43mb5d"))
       (patches (list (search-patch
                       "python-paste-remove-website-test.patch")
                      (search-patch
                       "python-paste-remove-timing-test.patch")))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)))
    (propagated-inputs
     `(;; Uses pkg_resources provided by setuptools internally.
       ("python-setuptools" ,python-setuptools)
       ("python-six" ,python-six)))
    (arguments
     '(;; Tests don't pass on Python 3, but work fine on Python 2.
       ;; (As of 2.0.2, Python 3 support in Paste is presently a bit broken,
       ;; but is usable enough for the minimal amount it's used in MediaGoblin
       ;; still... things should be better by the next Paste release.)
       #:tests? #f))
    (home-page "http://pythonpaste.org")
    (synopsis
     "Python web development tools, focusing on WSGI")
    (description
     "Paste provides a variety of web development tools and middleware which
can be nested together to build web applications.  Paste's design closely
follows ideas flowing from WSGI (Web Standard Gateway Interface).")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-paste))))))

(define-public python2-paste
  (let ((paste (package-with-python2
                (strip-python2-variant python-paste))))
    (package
      (inherit paste)
      (arguments
       ;; Tests are back for Python 2!
       `(#:tests? #t
         ,@(package-arguments paste))))))

(define-public python-pastescript
  (package
    (name "python-pastescript")
    (version "2.0.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "PasteScript" version))
       (sha256
        (base32
         "1h3nnhn45kf4pbcv669ik4faw04j58k8vbj1hwrc532k0nc28gy0"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)))
    (propagated-inputs
     `(;; Uses pkg_resources provided by setuptools internally.
       ("python-setuptools" ,python-setuptools)
       ("python-paste" ,python-paste)
       ("python-pastedeploy" ,python-pastedeploy)))
    (home-page "http://pythonpaste.org/script/")
    (arguments
     '(;; Unfortunately, this requires the latest unittest2,
       ;; but that requires traceback2 which requires linecache2 which requires
       ;; unittest2.  So we're skipping tests for now.
       ;; (Note: Apparently linetest2 only needs unittest2 for its tests,
       ;; so in theory we could get around this situation somehow.)
       #:tests? #f))
    (synopsis
     "Pluggable command line tool for serving web applications and more")
    (description
     "PasteScript is a plugin-friendly command line tool which provides a
variety of features, from launching web applications to bootstrapping project
layouts.")
    (license license:expat)))

(define-public python2-pastescript
  (package-with-python2 python-pastescript))

(define-public python-pyquery
  (package
    (name "python-pyquery")
    (version "1.2.11")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyquery" version))
       (sha256
        (base32
         "1ikz1387nsp0pp7mzzr6ip9n5gr67acpap24yn33987v7fkjp0sa"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-lxml" ,python-lxml)
       ("python-cssselect" ,python-cssselect)))
    (home-page "https://github.com/gawel/pyquery")
    (synopsis "Make jQuery-like queries on xml documents")
    (description "pyquery allows you to make jQuery queries on xml documents.
The API is as much as possible the similar to jQuery.  pyquery uses lxml for
fast xml and html manipulation.")
    (license bsd-3)
    (properties `((python2-variant . ,(delay python2-pyquery))))))

(define-public python2-pyquery
  (let ((pyquery (package-with-python2
                  (strip-python2-variant python-pyquery))))
    (package
      (inherit pyquery)
      (native-inputs `(("python2-setuptools" ,python2-setuptools))))))

(define-public python-webtest
  (package
    (name "python-webtest")
    (version "2.0.20")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "WebTest" version))
       (sha256
        (base32
         "0bv0qhdjakdsdgj4sk21gnpp8xp8bga4x03p6gjb83ihrsb7n4xv"))))
    (build-system python-build-system)
    (arguments
     `(;; Unfortunately we have to disable tests!
       ;; This release of WebTest is pinned to python-nose < 1.3,
       ;; but older versions of python-nose are plagued with the following
       ;; bug(s), which rears its ugly head during test execution:
       ;;   https://github.com/nose-devs/nose/issues/759
       ;;   https://github.com/nose-devs/nose/pull/811
       #:tests? #f))
    ;; Commented out code is no good, but in this case, once tests
    ;; are ready to be enabled again, we should put the following
    ;; in place:
    ;;  (native-inputs
    ;;   `(("python-nose" ,python-nose) ; technially < 1.3,
    ;;                                  ; but see above comment
    ;;     ("python-coverage" ,python-coverage)
    ;;     ("python-mock" ,python-mock)
    ;;     ("python-pastedeploy" ,python-pastedeploy)
    ;;     ("python-wsgiproxy2" ,python-wsgiproxy2)
    ;;     ("python-pyquery" ,python-pyquery)))
    (propagated-inputs
     `(("python-waitress" ,python-waitress)
       ("python-webob" ,python-webob)
       ("python-six" ,python-six)
       ("python-beautifulsoup4" ,python-beautifulsoup4)))
    (home-page "http://webtest.pythonpaste.org/")
    (synopsis "Helper to test WSGI applications")
    (description "Webtest allows you to test your Python web applications
without starting an HTTP server.  It supports anything that supports the
minimum of WSGI.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-webtest))))))

(define-public python2-webtest
  (let ((webtest (package-with-python2
                  (strip-python2-variant python-webtest))))
    (package
      (inherit webtest)
      (native-inputs `(("python2-setuptools" ,python2-setuptools)
                       ,@(package-native-inputs webtest))))))

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
    (home-page "http://bitbucket.org/runeh/anyjson/")
    (synopsis
     "Wraps best available JSON implementation in a common interface")
    (description
     "Anyjson loads whichever is the fastest JSON module installed
and provides a uniform API regardless of which JSON implementation is used.")
    (license bsd-3)
    (properties `((python2-variant . ,(delay python2-anyjson))))))

(define-public python2-anyjson
  (let ((anyjson (package-with-python2
                  (strip-python2-variant python-anyjson))))
    (package
      (inherit anyjson)
      (arguments `(;; Unlike the python 3 variant, we do run tests.  See above!
                   #:tests? #t
                   ,@(package-arguments anyjson)))
      (native-inputs `(("python2-setuptools" ,python2-setuptools)
                       ("python2-nose" ,python2-nose))))))

(define-public python-amqp
  (package
    (name "python-amqp")
    (version "1.4.9")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "amqp" version))
       (sha256
        (base32
         "06n6q0kxhjnbfz3vn8x9yz09lwmn1xi9d6wxp31h5jbks0b4vsid"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-mock" ,python-mock)))
    (home-page "http://github.com/celery/py-amqp")
    (synopsis
     "Low-level AMQP client for Python (fork of amqplib)")
    (description
     "This is a fork of amqplib which was originally written by Barry Pederson.
It is maintained by the Celery project, and used by kombu as a pure python
alternative when librabbitmq is not available.")
    (license lgpl2.1+)
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
                   ,@(package-arguments amqp)))
      (native-inputs `(("python2-setuptools" ,python2-setuptools)
                       ,@(package-native-inputs amqp))))))

(define-public python-kombu
  (package
    (name "python-kombu")
    (version "3.0.33")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "kombu" version))
       (sha256
        (base32
         "16brjx2lgwbj2a37d0pjbfb84nvld6irghmqrs3qfncajp51hgc5"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-nose" ,python-nose)))
    (propagated-inputs
     `(("python-anyjson" ,python-anyjson)
       ("python-amqp" ,python-amqp)))
    (home-page "http://kombu.readthedocs.org")
    (synopsis "Message passing library for Python")
    (description "The aim of Kombu is to make messaging in Python as easy as
possible by providing an idiomatic high-level interface for the AMQ protocol,
and also provide proven and tested solutions to common messaging problems.
AMQP is the Advanced Message Queuing Protocol, an open standard protocol for
message orientation, queuing, routing, reliability and security, for which the
RabbitMQ messaging server is the most popular implementation.")
    (license bsd-3)
    (properties `((python2-variant . ,(delay python2-kombu))))))

(define-public python2-kombu
  (let ((kombu (package-with-python2
                (strip-python2-variant python-kombu))))
    (package
      (inherit kombu)
      (inputs `(("python2-setuptools" ,python2-setuptools)
                ("python2-unittest2" ,python2-unittest2)
                ,@(package-inputs kombu))))))

(define-public python-billiard
  (package
    (name "python-billiard")
    (version "3.3.0.22")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "billiard" version))
       (sha256
        (base32
         "0zp7h6a58alrb3mwdw61jds07395j4j0mj6iqsb8czrihw9ih5nj"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)))
    (home-page "http://github.com/celery/billiard")
    (synopsis
     "Python multiprocessing fork with improvements and bugfixes")
    (description
     "Billiard is a fork of the Python 2.7 multiprocessing package.  The
multiprocessing package itself is a renamed and updated version of R Oudkerk's
pyprocessing package.  This standalone variant is intended to be compatible with
Python 2.4 and 2.5, and will draw its fixes/improvements from python-trunk.")
    (license bsd-3)
    (properties `((python2-variant . ,(delay python2-billiard))))))

(define-public python2-billiard
  (let ((billiard (package-with-python2
                   (strip-python2-variant python-billiard))))
    (package
      (inherit billiard)
      (native-inputs `(("python2-setuptools" ,python2-setuptools)
                       ("python2-unittest2" ,python2-unittest2)
                       ("python2-mock" ,python2-mock)
                       ,@(package-native-inputs billiard))))))

(define-public python-celery
  (package
    (name "python-celery")
    (version "3.1.20")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "celery" version))
       (sha256
        (base32
         "1md6ywg1s0946qyp8ndnsd677wm0yax933h2sb4m3a4j7lf1jbyh"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)))
    (propagated-inputs
     `(("python-pytz" ,python-pytz)
       ("python-billiard" ,python-billiard)
       ("python-kombu" ,python-kombu)))
    (home-page "http://celeryproject.org")
    (synopsis "Distributed Task Queue")
    (description "Celery is an asynchronous task queue/job queue based on
distributed message passing.  It is focused on real-time operation, but
supports scheduling as well.  The execution units, called tasks, are executed
concurrently on a single or more worker servers using multiprocessing,
Eventlet, or gevent.  Tasks can execute asynchronously (in the background) or
synchronously (wait until ready).")
    (license bsd-3)
    (properties `((python2-variant . ,(delay python2-celery))))))

(define-public python2-celery
  (let ((celery (package-with-python2
                 (strip-python2-variant python-celery))))
    (package
      (inherit celery)
      (native-inputs `(("python2-setuptools" ,python2-setuptools)
                       ("python2-unittest2" ,python2-unittest2)
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
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-translitcodec))))))

(define-public python2-translitcodec
  (package
    (inherit (package-with-python2
              (strip-python2-variant python-translitcodec)))
    (native-inputs `(("python2-setuptools" ,python2-setuptools)))))

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
  (license asl2.0)
  (properties `((python2-variant . ,(delay python2-editor))))))

(define-public python2-editor
  (package
    (inherit (package-with-python2
              (strip-python2-variant python-editor)))
    (inputs `(("python2-setuptools" ,python2-setuptools)))))

(define-public python-sphinxcontrib-programoutput
  (package
    (name "python-sphinxcontrib-programoutput")
    (version "0.8")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "sphinxcontrib-programoutput" version))
              (sha256
               (base32
                "098as6z1s0gb4dh5xcr1fd2vpm91zj93jzvgawspxf5s4hqs0xhp"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-docutils" ,python-docutils)
       ("python-sphinx" ,python-sphinx)))
    (synopsis "Sphinx extension to include program output")
    (description "A Sphinx extension to literally insert the output of arbitrary
commands into documents, helping you to keep your command examples up to date.")
    (home-page "https://github.com/lunaryorn/sphinxcontrib-programoutput")
    (license bsd-2)
    (properties `((python2-variant . ,(delay python2-sphinxcontrib-programoutput))))))

(define-public python2-sphinxcontrib-programoutput
  (package
    (inherit (package-with-python2
              (strip-python2-variant python-sphinxcontrib-programoutput)))
    (native-inputs `(("python2-setuptools" ,python2-setuptools)))))

(define-public python-sphinx-repoze-autointerface
  (package
    (name "python-sphinx-repoze-autointerface")
    (version "0.7.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "repoze.sphinx.autointerface" version))
              (sha256
               (base32
                "016mv3wbylw278wl7z33y2liyra8ljp08zq1g0anzadh1an5zvwp"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-docutils" ,python-docutils)
       ("python-sphinx" ,python-sphinx)
       ("python-zope-interface" ,python-zope-interface)))
    (synopsis "Auto-generate Sphinx API docs from Zope interfaces")
    (description "This package defines an extension for the Sphinx documentation
system.  The extension allows generation of API documentation by
introspection of @code{zope.interface} instances in code.")
    (home-page "https://github.com/repoze/repoze.sphinx.autointerface")
    (license repoze)))

(define-public python2-sphinx-repoze-autointerface
  (package-with-python2 python-sphinx-repoze-autointerface))

(define-public python-psycopg2
  (package
    (name "python-psycopg2")
    (version "2.6.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "psycopg2" version))
       (sha256
        (base32
         "0k4hshvrwsh8yagydyxgmd0pjm29lwdxkngcq9fzfzkmpsxrmkva"))))
    (build-system python-build-system)
    (arguments
     ;; Tests would require a postgresql database "psycopg2_test"
     ;; and a running postgresql database management service.
     `(#:tests? #f)) ; TODO re-enable after providing a test-db.
    (inputs
     `(("postgresql" ,postgresql))) ; libpq
    (home-page "http://initd.org/psycopg/")
    (synopsis "Python PostgreSQL adapter")
    (description
     "psycopg2 is a thread-safe PostgreSQL adapter that implements DB-API 2.0. ")
    (license lgpl3+)
    (properties `((python2-variant . ,(delay python2-psycopg2))))))

(define-public python2-psycopg2
  (package
    (inherit (package-with-python2
              (strip-python2-variant python-psycopg2)))
    (native-inputs `(("python2-setuptools" ,python2-setuptools)))))

(define-public python-vobject
  (package
    (name "python-vobject")
    (version "0.9.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "vobject" version))
              (sha256
               (base32
                "1cwzjnrdr9yg2x21wbf3kf59ibnchvj33mygd69yzi178a9gs9gz"))))
    (build-system python-build-system)
    (inputs
     `(("python-dateutil-2" ,python-dateutil-2)
       ("python-pyicu" ,python-pyicu)))
    (synopsis "Parse and generate vCard and vCalendar files")
    (description "Vobject is intended to be a full featured Python package for
parsing and generating vCard and vCalendar files.  Currently, iCalendar files
are supported and well tested. vCard 3.0 files are supported, and all data
should be imported, but only a few components are understood in a sophisticated
way.")
    (home-page "http://eventable.github.io/vobject/")
    (license asl2.0)
    (properties `((python2-variant . ,(delay python2-vobject))))))

(define-public python2-vobject
  (package
    (inherit (package-with-python2
              (strip-python2-variant python-vobject)))
    (native-inputs `(("python2-setuptools" ,python2-setuptools)))))

(define-public python-munkres
  (package
    (name "python-munkres")
    (version "1.0.7")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "munkres" version))
              (sha256
               (base32
                "1i6nf45i0kkzdx6k70giybsqxz4dxsjbrkrfqgjd7znfkf25sjik"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; no test suite
    (home-page "http://software.clapper.org/munkres/")
    (synopsis "Implementation of the Munkres algorithm")
    (description "The Munkres module provides an implementation of the Munkres
algorithm (also called the Hungarian algorithm or the Kuhn-Munkres algorithm),
useful for solving the Assignment Problem.")
    (license bsd-3)))

(define-public python2-munkres
  (package-with-python2 python-munkres))

(define-public python-flask
  (package
    (name "python-flask")
    (version "0.10.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "Flask" version))
              (sha256
               (base32
                "0wrkavjdjndknhp8ya8j850jq7a1cli4g5a93mg8nh1xz2gq50sc"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-itsdangerous" ,python-itsdangerous)
       ("python-jinja2" ,python-jinja2)
       ("python-werkzeug" ,python-werkzeug)))
    (home-page "https://github.com/mitsuhiko/flask/")
    (synopsis "Microframework based on Werkzeug, Jinja2 and good intentions")
    (description "Flask is a micro web framework based on the Werkzeug toolkit
and Jinja2 template engine.  It is called a micro framework because it does not
presume or force a developer to use a particular tool or library.")
    (license bsd-3)
    (properties `((python2-variant . ,(delay python2-flask))))))

(define-public python2-flask
  (package (inherit (package-with-python2
                     (strip-python2-variant python-flask)))
    (native-inputs `(("python2-setuptools" ,python2-setuptools)))))

(define-public python-cookies
  (package
    (name "python-cookies")
    (version "2.2.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "cookies" version))
              (sha256
               (base32
                "13pfndz8vbk4p2a44cfbjsypjarkrall71pgc97glk5fiiw9idnn"))))
    (build-system python-build-system)
    (arguments
     `(;; test are broken: https://gitlab.com/sashahart/cookies/issues/3
       #:tests? #f))
    (native-inputs
     `(("python-pytest" ,python2-pytest)))
    (synopsis "HTTP cookie parser and renderer")
    (description "A RFC 6265-compliant HTTP cookie parser and renderer in
Python.")
    (home-page "https://gitlab.com/sashahart/cookies")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-cookies))))))

(define-public python2-cookies
  (let ((cookies (package-with-python2
                  (strip-python2-variant python-cookies))))
    (package (inherit cookies)
      (native-inputs `(("python2-setuptools" ,python2-setuptools)
                       ,@(package-native-inputs cookies))))))

(define-public python-responses
  (package
    (name "python-responses")
    (version "0.5.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "responses" version))
              (sha256
               (base32
                "1spcfxixyk9k7pk82jm6zqkwk031s95lh8q0mz7539jrb7269bcc"))))
    (build-system python-build-system)
    (arguments
     `(;; Test suite is not distributed:
       ;; https://github.com/getsentry/responses/issues/38
       #:tests? #f))
    (native-inputs
     `(("python-cookies" ,python-cookies)
       ("python-mock" ,python-mock)))
    (propagated-inputs
     `(("python-requests" ,python-requests)
       ("python-six" ,python-six)))
    (home-page "https://github.com/getsentry/responses")
    (synopsis "Utility for mocking out the `requests` Python library")
    (description "A utility library for mocking out the `requests` Python
library.")
    (license asl2.0)
    (properties `((python2-variant . ,(delay python2-responses))))))

(define-public python2-responses
  (let ((responses (package-with-python2
                    (strip-python2-variant python-responses))))
    (package (inherit responses)
      (native-inputs `(("python2-setuptools" ,python2-setuptools)
                       ,@(package-native-inputs responses))))))

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
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _ (zero? (system* "python" "./test_pathlib.py")))))))
    (home-page "https://pathlib.readthedocs.org/")
    (synopsis "Object-oriented filesystem paths")
    (description "Pathlib offers a set of classes to handle filesystem paths.
It offers the following advantages over using string objects:

@enumerate
@item No more cumbersome use of os and os.path functions.  Everything can
be done easily through operators, attribute accesses, and method calls.
@item Embodies the semantics of different path types.  For example,
comparing Windows paths ignores casing.
@item Well-defined semantics, eliminating any inconsistencies or
ambiguities (forward vs. backward slashes, etc.).
@end enumerate\n")
    (license license:expat)))

(define-public python2-pathlib
  (package-with-python2 python-pathlib))

(define-public python-jellyfish
  (package
    (name "python-jellyfish")
    (version "0.5.3")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "jellyfish" version))
              (sha256
               (base32
                "12bxh8cy9xmvyrjz7aw159nd5pyvb645rkvw4r6bvm4xbvs8gd07"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/jamesturk/jellyfish")
    (synopsis "Approximate and phonetic matching of strings")
    (description "Jellyfish uses a variety of string comparison and phonetic
encoding algorithms to do fuzzy string matching.")
    (license bsd-2)
    (properties `((python2-variant . ,(delay python2-jellyfish))))))

(define-public python2-jellyfish
  (let ((jellyfish (package-with-python2
                     (strip-python2-variant python-jellyfish))))
    (package (inherit jellyfish)
      (native-inputs `(("python2-setuptools" ,python2-setuptools)
                       ("python2-unicodecsv" ,python2-unicodecsv)
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
     `(("python2-setuptools" ,python2-setuptools)
       ("python2-unittest2" ,python2-unittest2)))
    (home-page "https://github.com/jdunck/python-unicodecsv")
    (synopsis "Unicode CSV module for Python 2")
    (description "Unicodecsv is a drop-in replacement for Python 2.7's CSV
module, adding support for Unicode strings.")
    (license bsd-2)))

(define-public python-rarfile
  (package
    (name "python-rarfile")
    (version "2.7")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "rarfile" version))
              (sha256
               (base32
                "0d8n1dlpiz7av8dmbp0vclrwl9cnxizr4f2c9xvj1h5nvn480527"))
              ;; https://github.com/markokr/rarfile/pull/17/
              (patches (list (search-patch "python-rarfile-fix-tests.patch")))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           ;; Many tests fail, but the installation proceeds.
           (lambda _ (zero? (system* "make" "-C" "test" "test")))))))
    (native-inputs
     `(("which" ,which))) ; required for tests
    (propagated-inputs
     `(("libarchive" ,libarchive)))
    (home-page "https://github.com/markokr/rarfile")
    (synopsis "RAR archive reader for Python")
    (description "This is Python module for RAR archive reading.  The interface
is made as zipfile like as possible.")
    (license isc)))

(define-public python2-rarfile
  (package-with-python2 python-rarfile))

(define-public python-magic
  (package
    (name "python-magic")
    (version "0.4.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/ahupp/python-magic/archive/"
                           version ".tar.gz"))
       (sha256
        (base32
         "17bgy92i7sb021f2s4mw1dcvpm6p1mi9jihridwy1pyn8mzvpjgk"))
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
           #t))))))
    (native-inputs
     `(("python-setuptools" ,python-setuptools)))
    (inputs
     ;; python-magic needs to be able to find libmagic.so.
     `(("file" ,file)))
    (home-page "https://github.com/ahupp/python-magic")
    (synopsis "File type identification using libmagic")
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
        (uri (string-append "mirror://sourceforge/s3tools/"
                            "s3cmd-" version ".tar.gz"))
        (sha256
          (base32
            "0ki1rzhm5icvi9ry5jswi4b22yqwyj0d2wsqsgilwx6qhi7pjxa6"))))
    (build-system python-build-system)
    (arguments
     ;; s3cmd is written for python2 only and contains no tests.
     `(#:python ,python-2
       #:tests? #f))
    (native-inputs
     `(("python2-setuptools" ,python2-setuptools)))
    (inputs
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
    (license gpl2+)))
