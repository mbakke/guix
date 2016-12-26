;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013, 2014, 2015, 2016 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2014, 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2014, 2015 Federico Beffa <beffa@fbengineering.ch>
;;; Copyright © 2015 Omar Radwan <toxemicsquire4@gmail.com>
;;; Copyright © 2015 Pierre-Antoine Rault <par@rigelk.eu>
;;; Copyright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
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
;;; Copyright © 2016 Lukas Gradl <lgradl@openmailbox.org>
;;; Copyright © 2016 Hartmut Goebel <h.goebel@crazy-compilers.com>
;;; Copyright © 2016 Daniel Pimentel <d4n1@d4n1.org>
;;; Copyright © 2016 Sou Bunnbu <iyzsong@gmail.com>
;;; Copyright © 2016 Troy Sankey <sankeytms@gmail.com>
;;; Copyright © 2016 ng0 <ng0@we.make.ritual.n0.is>
;;; Copyright © 2016 Dylan Jeffers <sapientech@sapientech@openmailbox.org>
;;; Copyright © 2016 David Craven <david@craven.ch>
;;; Copyright © 2016 Marius Bakke <mbakke@fastmail.com>
;;; Copyright © 2016 Stefan Reichoer <stefan@xsteve.at>
;;; Copyright © 2016 Dylan Jeffers <sapientech@sapientech@openmailbox.org>
;;; Copyright © 2016 Alex Vong <alexvong1995@gmail.com>
;;; Copyright © 2016 Arun Isaac <arunisaac@systemreboot.net>
;;; Copyright © 2016 Julien Lepiller <julien@lepiller.eu>
;;; Copyright © 2016 Tobias Geerinckx-Rice <me@tobias.gr>
;;; Copyright © 2016 Thomas Danckaert <post@thomasdanckaert.be>
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
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages adns)
  #:use-module (gnu packages attr)
  #:use-module (gnu packages backup)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages django)
  #:use-module (gnu packages file)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gstreamer)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages image)
  #:use-module (gnu packages imagemagick)
  #:use-module (gnu packages libevent)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages networking)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages openstack)
  #:use-module (gnu packages password-utils)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages protobuf)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages sdl)
  #:use-module (gnu packages statistics)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages version-control)
  #:use-module (gnu packages video)
  #:use-module (gnu packages web)
  #:use-module (gnu packages base)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages zip)
  #:use-module (gnu packages tcl)
  #:use-module (gnu packages bdw-gc)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system python)
  #:use-module (guix build-system trivial)
  #:use-module (srfi srfi-1))

(define-public python-2.7
  (package
    (name "python")
    (version "2.7.12")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://www.python.org/ftp/python/"
                          version "/Python-" version ".tar.xz"))
      (sha256
       (base32
        "0y7rl603vmwlxm6ilkhc51rx2mfj14ckcz40xxgs0ljnvlhp30yp"))
      (patches (search-patches "python-2.7-search-paths.patch"
                               "python-2-deterministic-build-info.patch"
                               "python-2.7-site-prefixes.patch"
                               "python-2.7-source-date-epoch.patch"))
      (modules '((guix build utils)))
      ;; suboptimal to delete failing tests here, but if we delete them in the
      ;; arguments then we need to make sure to strip out that phase when it
      ;; gets inherited by python and python-minimal.
      (snippet
       '(begin
          (for-each delete-file
                    '("Lib/test/test_compileall.py"
                      "Lib/test/test_ctypes.py" ; fails on mips64el
                      "Lib/test/test_distutils.py"
                      "Lib/test/test_import.py"
                      "Lib/test/test_shutil.py"
                      "Lib/test/test_socket.py"
                      "Lib/test/test_subprocess.py"))
          #t))))
    (outputs '("out"
               "tk"))                     ;tkinter; adds 50 MiB to the closure
    (build-system gnu-build-system)
    (arguments
     `(;; 356 tests OK.
       ;; 6 tests failed:
       ;;     test_compileall test_distutils test_import test_shutil test_socket
       ;;     test_subprocess
       ;; 39 tests skipped:
       ;;     test_aepack test_al test_applesingle test_bsddb test_bsddb185
       ;;     test_bsddb3 test_cd test_cl test_codecmaps_cn test_codecmaps_hk
       ;;     test_codecmaps_jp test_codecmaps_kr test_codecmaps_tw test_curses
       ;;     test_dl test_gdb test_gl test_imageop test_imgfile test_ioctl
       ;;     test_kqueue test_linuxaudiodev test_macos test_macostools
       ;;     test_msilib test_ossaudiodev test_scriptpackages test_smtpnet
       ;;     test_socketserver test_startfile test_sunaudiodev test_timeout
       ;;     test_tk test_ttk_guionly test_urllib2net test_urllibnet
       ;;     test_winreg test_winsound test_zipfile64
       ;; 4 skips unexpected on linux2:
       ;;     test_bsddb test_bsddb3 test_gdb test_ioctl
       #:test-target "test"
       #:configure-flags
       (list "--enable-shared"                    ;allow embedding
             "--with-system-ffi"                  ;build ctypes
             "--with-ensurepip=install"           ;install pip and setuptools
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
          (add-after 'install 'remove-tests
            ;; Remove 25 MiB of unneeded unit tests.  Keep test_support.*
            ;; because these files are used by some libraries out there.
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (match (scandir (string-append out "/lib")
                                (lambda (name)
                                  (string-prefix? "python" name)))
                  ((pythonX.Y)
                   (let ((testdir (string-append out "/lib/" pythonX.Y
                                                 "/test")))
                     (with-directory-excursion testdir
                       (for-each delete-file-recursively
                                 (scandir testdir
                                          (match-lambda
                                            ((or "." "..") #f)
                                            (file
                                             (not
                                              (string-prefix? "test_support."
                                                              file))))))
                       (call-with-output-file "__init__.py" (const #t))
                       #t)))))))
          (add-before 'strip 'make-libraries-writable
            (lambda* (#:key outputs #:allow-other-keys)
              ;; Make .so files writable so they can be stripped.
              (let ((out (assoc-ref outputs "out")))
                (for-each (lambda (file)
                            (chmod file #o755))
                          (find-files (string-append out "/lib")
                                      "\\.so"))
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
    (home-page "https://www.python.org")
    (synopsis "High-level, dynamically-typed programming language")
    (description
     "Python is a remarkably powerful dynamic programming language that
is used in a wide variety of application domains.  Some of its key
distinguishing features include: clear, readable syntax; strong
introspection capabilities; intuitive object orientation; natural
expression of procedural code; full modularity, supporting hierarchical
packages; exception-based error handling; and very high level dynamic
data types.")
    (license license:psfl)))

;; Current 2.x version.
(define-public python-2 python-2.7)

(define-public python-3.5
  (package (inherit python-2)
    (version "3.5.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://www.python.org/ftp/python/"
                                  version "/Python-" version ".tar.xz"))
              (patches (search-patches
                        "python-fix-tests.patch"
                        "python-3.5-fix-tests.patch"
                        "python-3-deterministic-build-info.patch"
                        "python-3-search-paths.patch"))
              (patch-flags '("-p0"))
              (sha256
               (base32
                "0h6a5fr7ram2s483lh0pnmc4ncijb8llnpfdxdcl5dxr01hza400"))))
    (arguments (substitute-keyword-arguments (package-arguments python-2)
                 ((#:tests? _) #t)))
    (native-search-paths
     (list (search-path-specification
            (variable "PYTHONPATH")
            (files (list (string-append "lib/python"
                                        (version-major+minor version)
                                        "/site-packages"))))))))

(define-public python-3.4
  (package (inherit python-3.5)
    (version "3.4.5")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://www.python.org/ftp/python/"
                                  version "/Python-" version ".tar.xz"))
              (patches (search-patches
                        "python-fix-tests.patch"
                        "python-3.4-fix-tests.patch"
                        "python-3-deterministic-build-info.patch"
                        "python-3-search-paths.patch"))
              (patch-flags '("-p0"))
              (sha256
               (base32
                "12l9klp778wklxmckhghniy5hklss8r26995pyd00qbllk4b2r7f"))))))

;; Current 3.x version.
(define-public python-3 python-3.5)

;; Current major version.
(define-public python python-3)

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

    ;; Build fails due to missing ctypes without libffi.
    ;; OpenSSL is a mandatory dependency of Python 3.x, for urllib;
    ;; zlib is required by 'zipimport', used by pip.
    (inputs `(("libffi" ,libffi)
              ("openssl" ,openssl)
              ("zlib" ,zlib)))))

(define* (wrap-python3 python
                       #:optional
                       (name (string-append (package-name python) "-wrapper")))
  (package (inherit python)
    (name name)
    (source #f)
    (build-system trivial-build-system)
    (outputs '("out"))
    (inputs `(("bash" ,bash)))
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
                  `("python3" ,"pydoc3" ,"idle3" ,"pip3")
                  `("python"  ,"pydoc"  ,"idle"  ,"pip"))
                ;; python-config outputs search paths based upon its location,
                ;; use a bash wrapper to avoid changing its outputs.
                (let ((bash (string-append (assoc-ref %build-inputs "bash")
                                           "/bin/bash"))
                      (old  (string-append python "python3-config"))
                      (new  (string-append bin "/python-config")))
                  (with-output-to-file new
                    (lambda ()
                      (format #t "#!~a~%" bash)
                      (format #t "exec \"~a\" \"$@\"~%" old)
                      (chmod new #o755)
                      #t)))))))
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
    (version "4.3.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "psutil" version))
       (sha256
        (base32
         "1w4r09fvn6kd80m5mx4ws1wz100brkaq6hzzpwrns8cgjzjpl6c6"))))
    (build-system python-build-system)
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
    (license license:bsd-3)))

(define-public python2-psutil
  (package-with-python2 python-psutil))

(define-public python-passlib
  (package
    (name "python-passlib")
    (version "1.7.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "passlib" version))
       (sha256
        (base32
         "1vdbqsa1a31s98fxkinl052q8nnpvbxnb83qanxfpi2p6c2zdr0b"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)))
    (propagated-inputs
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
    (license license:bsd-3)))

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
    (license (list license:isc license:bsd-3 license:bsd-4))))

(define-public python2-py-bcrypt
  (package-with-python2 python-py-bcrypt))


(define-public python-paramiko
  (package
    (name "python-paramiko")
    (version "1.16.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "paramiko" version))
       (sha256
        (base32
         "14k8z7ndc3zk5xivnm4d8lncchx475ll5izpf8vmfbq7rp9yp5rj"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pycrypto" ,python-pycrypto)
       ("python-ecdsa" ,python-ecdsa)))
    (home-page "http://www.paramiko.org/")
    (synopsis "SSHv2 protocol library")
    (description "Paramiko is a python implementation of the SSHv2 protocol,
providing both client and server functionality.  While it leverages a Python C
extension for low level cryptography (PyCrypto), Paramiko itself is a pure
Python interface around SSH networking concepts.")
    (license license:lgpl2.1+)))

(define-public python2-paramiko
  (package-with-python2 python-paramiko))


(define-public python-httplib2
  (package
    (name "python-httplib2")
    (version "0.9.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "httplib2" version))
       (sha256
        (base32
         "126rsryvw9vhbf3qmsfw9lf4l4xm2srmgs439lgma4cpag4s3ay3"))))
    (build-system python-build-system)
    (home-page "https://github.com/jcgregorio/httplib2")
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
    (version "2.1.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ccm" version))
       (sha256
        (base32
         "177dfxsmk3k4cih6fh6v8d91bh4nqx7ns6pc07w7m7i3cvdx3c8n"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pyyaml" ,python-pyyaml)
       ;; Not listed in setup.py, but used in ccmlib/node.py for full
       ;; functionality
       ("python-psutil" ,python-psutil)
       ("python-six" ,python-six)))
    (home-page "https://github.com/pcmanus/ccm")
    (synopsis "Cassandra Cluster Manager for Apache Cassandra clusters on
localhost")
    (description "Cassandra Cluster Manager is a development tool for testing
local Cassandra clusters. It creates, launches and removes Cassandra clusters
on localhost.")
    (license license:asl2.0)))

(define-public python2-ccm
  (package-with-python2 python-ccm))

(define-public python-pytz
  (package
    (name "python-pytz")
    (version "2016.3")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "pytz" version ".tar.bz2"))
      (sha256
       (base32
        "1mjmrkk4vc5xzppw7fm0pli1nnbj57cvqv7jjv5whcmccyhxz4y1"))))
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
    (version "2.3.2")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "Babel" version))
      (sha256
       (base32
        "0k43pi0p1dwpds2w0km3fw92wixzxv2vw7p09capxmjz5cfh23lw"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pytz" ,python-pytz)))
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
    (license license:bsd-3)))

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
            (and (zero? (system* "./runexamples.sh"))
                 (zero? (system* "nosetests" "-v"))))))))
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
    (version "2.6.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "h5py" version))
      (sha256
       (base32
        "0df46dg7i7xfking9lp221bfm8dbl974yvlrbi1w7r6m61ac7bxj"))))
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

(define-public python-lockfile
  (package
    (name "python-lockfile")
    (version "0.12.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/l/lockfile/"
                           "lockfile-" version ".tar.gz"))
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

(define-public python-mock
  (package
    (name "python-mock")
    (version "1.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "mock" version))
       (sha256
        (base32
         "0kzlsbki6q0awf89rc287f3aj8x431lrajf160a70z0ikhnxsfdq"))))
    (build-system python-build-system)
    (arguments '(#:test-target "check"))
    (home-page "https://github.com/testing-cabal/mock")
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
    (version "31.0.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "setuptools" version))
      (sha256
       (base32
        "0ypybh4hx3bv4vhg2dc74xpj1g56ggnaffm87k4abhwjwq6wq608"))
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
    (license license:public-domain)))

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
    (version "8.7")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "keyring" version))
      (sha256
       (base32
        "0482rmi2x6p78wl2kz8qzyq21xz1sbbfwnv5x7dggar4vkwxhzfx"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-setuptools-scm" ,python-setuptools-scm)))
    (propagated-inputs
     `(("python-pycrypto" ,python-pycrypto)))
    (arguments
     `(#:tests? #f))                      ;TODO: tests require pytest
    (home-page "https://github.com/jaraco/keyring")
    (synopsis "Store and access your passwords safely")
    (description
     "The Python keyring lib provides a easy way to access the system keyring
service from python.  It can be used in any application that needs safe
password storage.")
    ;; "MIT" and PSF dual license
    (license license:x11)))

(define-public python2-keyring
  (package-with-python2 python-keyring))

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
    (home-page "http://pypi.python.org/pypi/six/")
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

(define-public python-dateutil-2
  (package
    (name "python-dateutil")
    (version "2.5.2")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "python-dateutil" version))
      (sha256
       (base32
        "0jrfpcgvgya6hs45dhrd9yiqgdgz9qp9aa07zsw8gqgn8zphff86"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)))
    (home-page "https://dateutil.readthedocs.io/en/stable/")
    (synopsis "Extensions to the standard datetime module")
    (description
     "The dateutil module provides powerful extensions to the standard
datetime module, available in Python 2.3+.")
    (license license:bsd-3)))

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
    (home-page "https://dateutil.readthedocs.io/en/stable/")
    (synopsis "Extensions to the standard datetime module")
    (description
     "The dateutil module provides powerful extensions to the standard
datetime module, available in Python 2.3+.")
    (license license:psfl)))

(define-public python2-dateutil
  (package-with-python2 python-dateutil))

(define-public python-parsedatetime
  (package
    (name "python-parsedatetime")
    (version "2.1")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "parsedatetime" version))
      (sha256
       (base32
        "0bdgyw6y3v7bcxlx0p50s8drxsh5bb5cy2afccqr3j90amvpii8p"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-pyicu" ,python-pyicu)))
    (home-page "http://github.com/bear/parsedatetime/")
    (synopsis
     "Parse human-readable date/time text")
    (description
     "Parse human-readable date/time text.")
    (license license:asl2.0)))

(define-public python2-parsedatetime
  (package-with-python2 python-parsedatetime))

(define-public python-pandas
  (package
    (name "python-pandas")
    (version "0.18.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
              "https://pypi.python.org/packages/11/09/"
              "e66eb844daba8680ddff26335d5b4fead77f60f957678243549a8dd4830d/"
              "pandas-" version ".tar.gz"))
       (sha256
        (base32 "1ckpxrvvjj6zxmn68icd9hib8qcpx9b35f6izxnr25br5ilq7r6j"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-pytz" ,python-pytz)
       ("python-dateutil" ,python-dateutil-2)))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-cython" ,python-cython)))
    (home-page "http://pandas.pydata.org")
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

(define-public python-tzlocal
  (package
    (name "python-tzlocal")
    (version "1.2.2")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "tzlocal" version))
      (sha256
       (base32
        "0paj7vlsb0np8b5sp4bv64wxv7qk2piyp7xg29pkhdjwsbls9fnb"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pytz" ,python-pytz)))
    (home-page "https://github.com/regebro/tzlocal")
    (synopsis
     "Local timezone information for Python")
    (description
     "Tzlocal returns a tzinfo object with the local timezone information.
This module attempts to fix a glaring hole in pytz, that there is no way to
get the local timezone information, unless you know the zoneinfo name, and
under several distributions that's hard or impossible to figure out.")
    (license license:cc0)))

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
    (version "3.10.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "simplejson" version))
      (sha256
       (base32
        "1qhwsykjlb85igb4cfl6v6gkprzbbg8gyqdd7zscc8w3x0ifcfwm"))))
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
    (license license:x11)))

(define-public python2-pyicu
  (package-with-python2 python-pyicu))

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
    (license license:gpl2+)))

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
    (license license:lgpl2.1+)))

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
    (license license:bsd-3)))

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
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-parse" ,python-parse)))
    (arguments '(#:tests? #f))            ;TODO: tests require pytest
    (home-page "https://github.com/jenisys/parse_type")
    (synopsis "Extended parse module")
    (description
     "Parse_type extends the python parse module.")
    (license license:bsd-3)))

(define-public python-parse
  (package
    (name "python-parse")
    (version "1.6.6")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "parse" version))
      (sha256
       (base32
        "0y31i3mwgv35qn0kzzjn9q8jqfdqmbi6sr6yfvn8rq4lqjm5lhvi"))
      (patches (search-patches "python-parse-too-many-fields.patch"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _ (zero? (system* "python" "test_parse.py")))))))
    (home-page "https://github.com/r1chardj0n3s/parse")
    (synopsis "Parse strings")
    (description
     "Parse strings using a specification based on the Python format()
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
    (version "2.3.4")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://sourceforge/scons/scons/" version
                                 "/scons-" version ".tar.gz"))
             (sha256
              (base32
               "0hdlci43wjz8maryj83mz04ir6rwcdrrzpd7cpzvdlzycqhdfmsb"))))
    (build-system python-build-system)
    (arguments
     ;; With Python 3.x, fails to build with a syntax error.
     `(#:python ,python-2
       #:use-setuptools? #f                ; still relies on distutils
       #:tests? #f))                       ; no 'python setup.py test' command
    (home-page "http://scons.org/")
    (synopsis "Software construction tool written in Python")
    (description
     "SCons is a software construction tool.  Think of SCons as an improved,
cross-platform substitute for the classic Make utility with integrated
functionality similar to autoconf/automake and compiler caches such as ccache.
In short, SCons is an easier, more reliable and faster way to build
software.")
    (license license:x11)))

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
    (arguments
     '(#:tests? #f)) ; FIXME: test suite fails
    (home-page "http://readthedocs.org/docs/nose/")
    (synopsis "Python testing library")
    (description
     "Nose extends the unittest library to make testing easier.")
    (license license:lgpl2.0+)))

(define-public python2-nose
  (package-with-python2 python-nose))

(define-public python-nose2
  (package
    (name "python-nose2")
    (version "0.6.5")
      (source
        (origin
          (method url-fetch)
          (uri (pypi-uri "nose2" version))
          (sha256
           (base32
            "1x4zjq1zlyrh8b9ba0cmafd3w94pxhid408kibyjd3s6h1lap6s7"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f)) ; 'module' object has no attribute 'collector'
    (propagated-inputs
     `(("python-cov-core" ,python-cov-core)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-six" ,python-six)))
    (home-page "https://github.com/nose-devs/nose2")
    (synopsis "Next generation of nicer testing for Python")
    (description
     "Nose2 is the next generation of nicer testing for Python, based on the
plugins branch of unittest2.  Nose2 aims to improve on nose by providing a
better plugin api, being easier for users to configure, and simplifying internal
interfaces and processes.")
    (license license:bsd-2)))

(define-public python2-nose2
  (package-with-python2 python-nose2))

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
    (home-page "http://pypi.python.org/pypi/unittest2")
    (synopsis "Python unit testing library")
    (description
     "Unittest2 is a replacement for the unittest module in the Python
standard library.")
    (license license:psfl)))

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
    (arguments
     `(#:python ,python-2
       #:tests? #f)))) ; no setup.py test command

(define-public python-pafy
  (package
    (name "python-pafy")
    (version "0.5.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pafy" version))
       (sha256
        (base32
         "1ckvrypyvb7jbqlgwdz0y337ajagjv7dgxyns326nqwypn1wpq0i"))))
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
    (propagated-inputs
     `(("python-py" ,python-py)))
    (native-inputs
     `(("python-nose" ,python-nose)
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

;; This package is used by Borg until we can upgrade all our Python packages to
;; use a more recent pytest.
(define-public python-pytest-2.9.2
  (package
    (inherit python-pytest)
    (name "python-pytest")
    (version "2.9.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pytest" version))
              (sha256
               (base32
                "1n6igbc1b138wx1q5gca4pqw1j6nsyicfxds5n0b5989kaxqmh8j"))))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'disable-invalid-test
           (lambda _
             (substitute* "testing/test_argcomplete.py"
               (("def test_remove_dir_prefix" line)
                (string-append "@pytest.mark.skip"
                               "(reason=\"Assumes that /usr exists.\")\n    "
                               line)))
             #t)))))))

(define-public python-pytest-cov
  (package
    (name "python-pytest-cov")
    (version "2.2.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pytest-cov" version))
        (sha256
         (base32
          "1yl4nbhzfgsxqlsyk4clafgp9x11zvgrkprm9i2p3fgkwx9jxcm8"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
          (lambda _
            ;; options taken from tox.ini
            ;; TODO: make "--restructuredtext" tests pass. They currently fail
            ;; with "Duplicate implicit target name"
            (zero? (system* "python" "./setup.py" "check"
                            "--strict" "--metadata")))))))
    (propagated-inputs
     `(("python-coverage" ,python-coverage)
       ("python-pytest" ,python-pytest)))
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
       (uri (pypi-uri "pytest-runner" version))
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
       ("python-setuptools-scm" ,python-setuptools-scm)))
    (home-page "https://github.com/pytest-dev/pytest-runner")
    (synopsis "Invoke py.test as a distutils command")
    (description
     "This package provides a @command{pytest-runner} command that
@file{setup.py} files can use to run tests.")
    (license license:expat)))

(define-public python2-pytest-runner
  (package-with-python2 python-pytest-runner))

(define-public python-pytest-mock
  (package
    (name "python-pytest-mock")
    (version "1.2")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pytest-mock" version ".zip"))
        (sha256
         (base32
          "03zxar5drzm7ksqyrwypjaza3cri6wqvpr6iam92djvg6znp32gp"))))
    (build-system python-build-system)
    (native-inputs
     `(("unzip" ,unzip)))
    (propagated-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/pytest-dev/pytest-mock/")
    (synopsis "Thin-wrapper around the mock package for easier use with py.test")
    (description
     "This plugin installs a @code{mocker} fixture which is a thin-wrapper
around the patching API provided by the @code{mock} package, but with the
benefit of not having to worry about undoing patches at the end of a test.
The mocker fixture has the same API as @code{mock.patch}, supporting the
same arguments.")
    (properties `((python2-variant . ,(delay python2-pytest-mock))))
    (license license:expat)))

(define-public python2-pytest-mock
  (let ((base (package-with-python2
                (strip-python2-variant python-pytest-mock))))
    (package (inherit base)
      (propagated-inputs
       `(("python2-mock" ,python2-mock)
         ,@(package-propagated-inputs base))))))

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
         "08rn2l39ds60xshs4js787l84pfckksqklfq2wq9x8ig2aci2pja"))
       (modules '((guix build utils)))
       (snippet
        '(begin
           ;; Remove pre-compiled .pyc files from source.
           (for-each delete-file-recursively
                     (find-files "." "__pycache__" #:directories? #t))
           (for-each delete-file (find-files "." "\\.pyc$"))
           #t))))
    (build-system python-build-system)
    (native-inputs
     `(("unzip" ,unzip)
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
    (native-inputs
     `(("python-pytest" ,python-pytest)))
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
     `(("python-mimeparse" ,python-mimeparse)
       ("python-extras" ,python-extras)))
    (home-page "https://github.com/testing-cabal/testtools")
    (synopsis
     "Extensions to the Python standard library unit testing framework")
    (description
     "Testtools extends the Python standard library unit testing framework to
provide matchers, more debugging information, and cross-Python
compatibility.")
    (license license:psfl)))

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
    (propagated-inputs
     `(("python-testtools" ,python-testtools)))
    (home-page "https://launchpad.net/testscenarios")
    (synopsis "Pyunit extension for dependency injection")
    (description
     "Testscenarios provides clean dependency injection for Python unittest
style tests.")
    (license (list license:bsd-3 license:asl2.0)))) ; at the user's option

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
    (home-page "https://launchpad.net/testresources")
    (synopsis
     "Pyunit extension for managing test resources")
    (description
     "Testresources is an extension to Python's unittest to allow declarative
use of resources by test cases.")
    (license (list license:bsd-3 license:asl2.0)))) ; at the user's option

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
    (propagated-inputs
     `(("python-extras" ,python-extras)
       ("python-mimeparse" ,python-mimeparse)))
    (native-inputs
     `(("python-testscenarios" ,python-testscenarios)))
    (home-page "http://launchpad.net/subunit")
    (synopsis "Python implementation of the subunit protocol")
    (description
     "Python-subunit is a Python implementation of the subunit test streaming
protocol.")
    (license (list license:bsd-3 license:asl2.0)))) ; at the user's option

(define-public python2-subunit
  (package-with-python2 python-subunit))

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
(define python-pbr-minimal
  (package
    (name "python-pbr-minimal")
    (version "1.8.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pbr" version))
       (sha256
        (base32
         "0jcny36cf3s8ar5r4a575npz080hndnrfs4np1fqhv0ym4k7c4p2"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f))
    (home-page "http://docs.openstack.org/developer/pbr/")
    (synopsis "Minimal build of python-pbr used for bootstrapping")
    (description
     "Used only for bootstrapping python2-pbr, you should not need this.")
    (license license:asl2.0)))

(define python2-pbr-minimal
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
      `(("python-fixtures" ,python-fixtures)
        ;; discover, coverage, hacking, subunit
        ("python-mock" ,python-mock)
        ("python-six" ,python-six)
        ("python-sphinx" ,python-sphinx)
        ("python-testrepository" ,python-testrepository)
        ("python-testresources" ,python-testresources)
        ("python-testscenarios" ,python-testscenarios)
        ("python-testtools" ,python-testtools)
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
     `(("python-six" ,python-six)))
    (native-inputs
     `(("python-pbr-minimal" ,python-pbr-minimal)
       ("python-testtools" ,python-testtools)))
    (home-page "https://launchpad.net/python-fixtures")
    (synopsis "Python test fixture library")
    (description
     "Fixtures provides a way to create reusable state, useful when writing
Python tests.")
    (license (list license:bsd-3 license:asl2.0)))) ; at user's option

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
     `(("python-fixtures" ,python-fixtures)
       ("python-subunit" ,python-subunit)
       ("python-testtools" ,python-testtools)))
    (native-inputs
     `(("python-pbr-minimal" ,python-pbr-minimal) ;; same as for building fixture
       ("python-mimeparse" ,python-mimeparse)))
    (home-page "https://launchpad.net/testrepository")
    (synopsis "Database for Python test results")
    (description "Testrepository provides a database of test results which can
be used as part of a developer's workflow to check things such as what tests
have failed since the last commit or what tests are currently failing.")
    (license (list license:bsd-3 license:asl2.0)))) ; at user's option

(define-public python2-testrepository
  (package-with-python2 python-testrepository))

(define-public python-coverage
  (package
    (name "python-coverage")
    (version "4.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "coverage" version))
       (sha256
        (base32
         "01rbr4br4lsk0lwn8fb96zwd2xr4f0mg1w7iq3j11i8f5ig2nqs1"))))
    (build-system python-build-system)
    (home-page "http://nedbatchelder.com/code/coverage")
    (synopsis "Code coverage measurement for Python")
    (description
     "Coverage measures code coverage, typically during test execution.  It
uses the code analysis tools and tracing hooks provided in the Python standard
library to determine which lines are executable, and which have been
executed.")
    (license license:bsd-3)))

(define-public python2-coverage
  (package-with-python2 python-coverage))

(define-public python-cov-core
  (package
    (name "python-cov-core")
    (version "1.15.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "cov-core" version))
        (sha256
         (base32
          "0k3np9ymh06yv1ib96sb6wfsxjkqhmik8qfsn119vnhga9ywc52a"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-coverage" ,python-coverage)))
    (home-page "https://github.com/schlamar/cov-core")
    (synopsis "plugin core for use by pytest-cov, nose-cov and nose2-cov")
    (description
     "This is a library package for use by pytest-cov, nose-cov and nose2-cov.
It is useful for developing coverage plugins for these testing frameworks.")
    (license license:expat)))

(define-public python2-cov-core
 (package-with-python2 python-cov-core))

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
    (home-page "http://pypi.python.org/pypi/discover/")
    (synopsis
     "Python test discovery for unittest")
    (description
     "Discover provides test discovery for unittest, a feature that has been
backported from Python 2.7 for Python 2.4+.")
    (license license:bsd-3)))

(define-public python2-discover
  (package-with-python2 python-discover))

(define-public behave
  (package
    (name "behave")
    (version "1.2.5")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "behave" version ".tar.bz2"))
             (sha256
              (base32
               "1iypp6z46r19n4xmgx6m1lwmlpfjh8vapq8izigrqlaarvp2y64c"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)
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
    (license license:x11)))

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
    (version "0.7.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "PyLD" version))
              (sha256
               (base32
                "1m0fs6897vxfkf7awah5i66i7b7smm5fnywf1w50fpzyfbfhr156"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f)) ; no tests
    (home-page "http://github.com/digitalbazaar/pyld")
    (synopsis "Python implementation of the JSON-LD specification")
    (description
     "PyLD is an implementation of the JSON-LD specification.")
    (license license:bsd-3)))

(define-public python2-pyld
  (package-with-python2 python-pyld))

(define-public python-certifi
  (package
    (name "python-certifi")
    (version "2016.8.31")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "certifi" version))
              (sha256
               (base32
                "06c9dcyv8ss050gkv5xjivbxhm6qm0s9vzy4r33wqabgv118lw7p"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f)) ; no tests
    (home-page "http://python-requests.org/")
    (synopsis "Python CA certificate bundle")
    (description
     "Certifi is a Python library that contains a CA certificate bundle, which
is used by the Requests library to verify HTTPS requests.")
    (license license:asl2.0)))

(define-public python2-certifi
  (package-with-python2 python-certifi))

(define-public python-click
  (package
    (name "python-click")
    (version "6.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "click" version))
       (sha256
        (base32
         "1sggipyz52crrybwbr9xvwxd4aqigvplf53k9w3ygxmzivd1jsnc"))))
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
             #t)))))
    (home-page "http://click.pocoo.org")
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
     `(("python-py" ,python-py)
       ("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-wheel" ,python-wheel)))
    (home-page "http://python-requests.org/")
    (synopsis "Python HTTP library")
    (description
     "Requests is a Python HTTP client library.  It aims to be easier to use
than Python’s urllib2 library.")
    (license license:asl2.0)))

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
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check (lambda _ (zero? (system* "nosetests")))))))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-vcversioner" ,python-vcversioner)))
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
             (native-inputs
              `(("python2-mock" ,python2-mock)
                ,@(package-native-inputs jsonschema)))
             (propagated-inputs
              `(("python2-functools32" ,python2-functools32))))))

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
    (home-page "https://pypi.python.org/pypi/Unidecode")
    (synopsis "ASCII transliterations of Unicode text")
    (description
     "Unidecode provides ASCII transliterations of Unicode text.  Unidecode is
useful when integrating with legacy code that doesn't support Unicode, or for
ease of entry of non-Roman names on a US keyboard, or when constructing ASCII
machine identifiers from human-readable Unicode strings that should still be
somewhat intelligeble.")
    (license license:gpl2+)))

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
     `(("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-pytest-runner" ,python-pytest-runner)))
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
     `(("python-nose" ,python-nose)
       ("python-cryptography" ,python-cryptography)
       ("python-pyjwt" ,python-pyjwt)
       ("python-blinker" ,python-blinker)))
    (home-page "https://github.com/idan/oauthlib")
    (synopsis "OAuth implementation for Python")
    (description
     "Oauthlib is a generic, spec-compliant, thorough implementation of the
OAuth request-signing logic.")
    (license license:bsd-3)
    (properties `((python2-variant . ,(delay python2-oauthlib))))))

(define-public python2-oauthlib
  (let ((base (package-with-python2 (strip-python2-variant python-oauthlib))))
    (package
      (inherit base)
      (native-inputs `(("python2-unittest2" ,python2-unittest2)
                       ("python2-mock" ,python2-mock)
                       ,@(package-native-inputs base))))))

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
    (home-page "http://github.com/mitsuhiko/itsdangerous")
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
    (version "15.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "virtualenv" version))
       (sha256
        (base32
         "07cbajzk8l05k5zhlw0b9wbf2is65bl9v6zrn2a0iyn57w6pd73d"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             ;; Disable failing test.  See upstream bug report
             ;; https://github.com/pypa/virtualenv/issues/957
             (substitute* "tests/test_virtualenv.py"
               (("skipif.*") "skipif(True, reason=\"Guix\")\n"))
             (zero? (system* "py.test")))))))
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
    (home-page "http://github.com/mitsuhiko/markupsafe")
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
    (version "2.8")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Jinja2" version))
       (sha256
        (base32
         "1x0v41lp5m1pjix3l46zx02b7lqp2hflgpnxwkywxynvi3zz47xw"))))
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
    (version "0.10.3")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "joblib" version))
              (sha256
               (base32
                "0787k919zlfmgymprz5bzv0v1df5bbirlf3awrghmjgvkrd9dci9"))
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
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'disable-failing-tests
           (lambda _
             ;; This numpydoc tests fails for unknown reasons
             (delete-file "doc/sphinxext/numpydoc/tests/test_docscrape.py")
             ;; This numpydoc test depends on matplotlib, which is not a
             ;; required input.
             (delete-file "doc/sphinxext/numpydoc/tests/test_plot_directive.py")
             ;; These tests fail to execute sys.executable
             (substitute* "joblib/test/test_parallel.py"
               (("import nose" line)
                (string-append "from nose.plugins.skip import SkipTest\n" line))
               (("def test_nested_parallel_warnings" line)
                (string-append "@SkipTest\n" line))
               (("def test_parallel_with_interactively_defined_functions" line)
                (string-append "@SkipTest\n" line)))
             #t)))))
    ;; Provide nose to enable tests command
    (native-inputs
     `(("python-nose"       ,python-nose)
       ("python-sphinx"     ,python-sphinx)
       ("python-docutils"   ,python-docutils)
       ("python-numpydoc"   ,python-numpydoc)))
    (home-page "http://pythonhosted.org/joblib/")
    (synopsis "Using Python functions as pipeline jobs")
    (description
     "Joblib is a set of tools to provide lightweight pipelining in Python.
In particular, joblib offers: transparent disk-caching of the output values
and lazy re-evaluation (memoize pattern), easy simple parallel computing
logging and tracing of the execution.")
    (license license:bsd-3)))

(define-public python2-joblib
  (package-with-python2 python-joblib))

(define-public python-docutils
  (package
    (name "python-docutils")
    (version "0.13.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "docutils" version))
       (sha256
        (base32
         "1gkma47i609jfs7dssxn4y9vsz06qi0l5q41nws0zgkpnrghz33i"))))
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
    (version "2.0.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Pygments" version))
       (sha256
        (base32
         "0lagrwifsgn0s8bzqahpr87p7gd38xja8f06akscinp6hj89283k"))))
    (build-system python-build-system)
    (home-page "http://pygments.org/")
    (synopsis "Syntax highlighting")
    (description
     "Pygments is a syntax highlighting package written in Python.")
    (license license:bsd-2)))

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
    (propagated-inputs
     `(("python-jinja2" ,python-jinja2)
       ("python-docutils" ,python-docutils)
       ("python-pygments" ,python-pygments)))
    (home-page "http://sphinx-doc.org/")
    (synopsis "Python documentation generator")
    (description "Sphinx is a tool that makes it easy to create documentation
for Python projects or other documents consisting of multiple reStructuredText
sources.")
    (license license:bsd-3)))

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
    (home-page "https://github.com/snide/sphinx_rtd_theme/")
    (synopsis "ReadTheDocs.org theme for Sphinx")
    (description "A theme for Sphinx used by ReadTheDocs.org.")
    (license license:expat)))

(define-public python2-sphinx-rtd-theme
  (package-with-python2 python-sphinx-rtd-theme))

(define-public python-rst.linker
  (package
    (name "python-rst.linker")
    (version "1.7")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "rst.linker" version))
       (sha256
        (base32
         "0bh4lnj2p1nh0wf5pgxgfbrp27xhb1rinahkb5j7s3qprq6qn0sr"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-dateutil" ,python-dateutil-2)
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
    (version "1.8")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "feedgenerator" version))
       (sha256
        (base32
         "0mkimp1fpdan4p3882vzcws4l594k71ich4g0wq97jbra7p602n0"))
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
    (version "3.6.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pelican" version))
       (sha256
        (base32
         "1hn94rb4q3zmcq16in055xikal4dba5hfx3zznq7warllcgc9f8k"))))
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
    (license license:agpl3+)))

(define-public python-scikit-learn
  (package
    (name "python-scikit-learn")
    (version "0.18.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/scikit-learn/scikit-learn/archive/"
             version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1hwswckdmd27f7k1jvwdc0m4mqrgxl2s245yq1scq34v124bjqgq"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (alist-cons-before
        'check 'set-HOME
        ;; some tests require access to "$HOME"
        (lambda _ (setenv "HOME" "/tmp"))
        %standard-phases)))
    (inputs
     `(("openblas" ,openblas)))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("python-cython" ,python-cython)))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-scipy" ,python-scipy)))
    (home-page "http://scikit-learn.org/")
    (synopsis "Machine Learning in Python")
    (description
     "Scikit-learn provides simple and efficient tools for data
mining and data analysis.")
    (license license:bsd-3)))

(define-public python2-scikit-learn
  (package-with-python2 python-scikit-learn))

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
    ;; See DEPENDS.txt for the list of build and run time requiremnts
    (propagated-inputs
     `(("python-matplotlib" ,python-matplotlib)
       ("python-networkx" ,python-networkx)
       ("python-scipy" ,python-scipy)
       ("python-pillow" ,python-pillow)))
    (native-inputs
     `(("python-numpy" ,python-numpy)
       ("python-cython" ,python-cython)
       ("python-six" ,python-six)))
    (home-page "http://scikit-image.org/")
    (synopsis "Image processing in Python")
    (description
     "Scikit-image is a collection of algorithms for image processing.")
    (license license:bsd-3)))

(define-public python2-scikit-image
  (package-with-python2 python-scikit-image))

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
    ;; As long as we are not running test, we do not need this input :-)
    ;;(native-inputs
    ;; `(("python-pytest" ,python-pytest)))
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
    (home-page "http://python-rq.org/")
    (synopsis "Simple job queues for Python")
    (description
     "RQ (Redis Queue) is a simple Python library for queueing jobs and
processing them in the background with workers.  It is backed by Redis and it
is designed to have a low barrier to entry.")
    (license license:bsd-2)))

(define-public python2-rq
  (package-with-python2 python-rq))

(define-public python-cython
  (package
    (name "python-cython")
    (version "0.24.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Cython" version))
       (sha256
        (base32
         "1fg7fmpvfcq9md4ncyqnnylyjy4z3ksdrshzis95g1sh03d8z044"))))
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
           (lambda _ (setenv "HOME" "/tmp")))
         (replace 'check
           (lambda _ (zero? (system* "python" "runtests.py" "-vv")))))))
    (home-page "http://cython.org/")
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
    (version "0.1.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "rpython" version))
       (sha256
        (base32
         "07pps06fq4c4wmi5ii0sgh9zgwniz5y7frqhm28g3a154l163fxc"))))
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

;; This version of numpy is missing the documentation and is only used to
;; build matplotlib which is required to build numpy's documentation.
(define python-numpy-bootstrap
  (package
    (name "python-numpy-bootstrap")
    (version "1.10.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/numpy/NumPy/" version
                           "/numpy-" version ".tar.gz"))
       (sha256
        (base32
         "1bjjhvncraka5s6i4lg644jrxij6bvycxy7an20gcz3a0m11iygp"))))
    (build-system python-build-system)
    (inputs
     `(("openblas" ,openblas)
       ("lapack" ,lapack)))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("gfortran" ,gfortran)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
        (add-before 'build 'set-environment-variables
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
           (with-directory-excursion "/tmp"
             (zero? (system* "python" "-c"
                             "import numpy; numpy.test(verbose=2)"))))))))
    (home-page "http://www.numpy.org/")
    (synopsis "Fundamental package for scientific computing with Python")
    (description "NumPy is the fundamental package for scientific computing
with Python.  It contains among other things: a powerful N-dimensional array
object, sophisticated (broadcasting) functions, tools for integrating C/C++
and Fortran code, useful linear algebra, Fourier transform, and random number
capabilities.")
    (license license:bsd-3)))

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
       ("python2-pysnptools" ,python2-pysnptools)))
    (native-inputs
     `(("unzip" ,unzip)
       ("python2-cython" ,python2-cython)
       ("python2-mock" ,python2-mock)))
    (home-page "http://research.microsoft.com/en-us/um/redmond/projects/mscompbio/fastlmm/")
    (synopsis "Perform genome-wide association studies on large data sets")
    (description
     "FaST-LMM, which stands for Factored Spectrally Transformed Linear Mixed
Models, is a program for performing both single-SNP and SNP-set genome-wide
association studies (GWAS) on extremely large data sets.")
    (license license:asl2.0)))

(define-public python-numpy
  (package (inherit python-numpy-bootstrap)
    (name "python-numpy")
    (outputs '("out" "doc"))
    (inputs
     `(("which" ,which)
       ,@(package-inputs python-numpy-bootstrap)))
    (propagated-inputs
     `(("python-matplotlib" ,python-matplotlib)
       ("python-pyparsing" ,python-pyparsing)
       ,@(package-propagated-inputs python-numpy-bootstrap)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-sphinx" ,python-sphinx)
       ("python-numpydoc" ,python-numpydoc)
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
              (lambda* (#:key inputs outputs #:allow-other-keys)
                ;; Make installed package available for building the
                ;; documentation
                (add-installed-pythonpath inputs outputs)
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
       (uri (string-append "mirror://sourceforge/pyparsing/pyparsing"
                           "/pyparsing-" version
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
    (version "2.6.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "numexpr" version))
       (sha256
        (base32
         "0i6iagl2hhbr8q4qzbbjd859v5806vqylq87fq7pi914ps6d6cag"))))
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

(define-public python-matplotlib
  (package
    (name "python-matplotlib")
    (version "1.4.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/matplotlib/matplotlib"
                           "/matplotlib-" version
                           "/matplotlib-" version ".tar.gz"))
       (sha256
        (base32
         "1dn05cvd0g984lzhh72wa0z93psgwshbbg93fkab6slx5m3l95av"))
       (patches (search-patches "matplotlib-setupext-tk.patch"))))
    (build-system python-build-system)
    (outputs '("out" "doc"))
    (propagated-inputs ; the following packages are all needed at run time
     `(("python-pyparsing" ,python-pyparsing)
       ("python-pygobject" ,python-pygobject)
       ("gobject-introspection" ,gobject-introspection)
       ("python-tkinter" ,python "tk")
       ("python-dateutil" ,python-dateutil-2)
       ("python-numpy" ,python-numpy-bootstrap)
       ("python-pillow" ,python-pillow)
       ("python-pytz" ,python-pytz)
       ("python-six" ,python-six)
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
     `(("libpng" ,libpng)
       ("imagemagick" ,imagemagick)
       ("freetype" ,freetype)
       ("cairo" ,cairo)
       ("glib" ,glib)
       ;; FIXME: Add backends when available.
       ;("python-wxpython" ,python-wxpython)
       ;("python-pyqt" ,python-pyqt)
       ("tcl" ,tcl)
       ("tk" ,tk)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-sphinx" ,python-sphinx)
       ("python-numpydoc" ,python-numpydoc)
       ("python-nose" ,python-nose)
       ("python-mock" ,python-mock)
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
         (lambda* (#:key inputs outputs #:allow-other-keys)
           (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                  (doc (string-append data "/doc/" ,name "-" ,version))
                  (info (string-append data "/info"))
                  (html (string-append doc "/html")))
             ;; Make installed package available for building the
             ;; documentation
             (add-installed-pythonpath inputs outputs)
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
         ("python2-pygobject-2" ,python2-pygobject-2)
         ("python2-tkinter" ,python-2 "tk")
         ,@(fold alist-delete (package-propagated-inputs matplotlib)
                 '("python-pycairo" "python-pygobject" "python-tkinter")))))))

(define-public python2-pysnptools
  (package
    (name "python2-pysnptools")
    (version "0.3.9")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pysnptools" version ".zip"))
       (sha256
        (base32
         "1wybggjzz8zw7aav4pjsg2h22xp17a1lghrprza1pxwlm7wf96y2"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2)) ; only Python 2.7 is supported
    (propagated-inputs
     `(("python2-numpy" ,python2-numpy)
       ("python2-scipy" ,python2-scipy)
       ("python2-pandas" ,python2-pandas)))
    (native-inputs
     `(("python2-cython" ,python2-cython)))
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page "http://research.microsoft.com/en-us/um/redmond/projects/mscompbio/")
    (synopsis "Library for reading and manipulating genetic data")
    (description
     "PySnpTools is a library for reading and manipulating genetic data.  It
can, for example, efficiently read whole PLINK *.bed/bim/fam files or parts of
those files.  It can also efficiently manipulate ranges of integers using set
operators such as union, intersection, and difference.")
    (license license:asl2.0)))

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
    (propagated-inputs
     `(("python-six" ,python-six)))
    (inputs
     `(("readline" ,readline)
       ("icu4c" ,icu4c)
       ("pcre" ,pcre)
       ("r" ,r)))
    (native-inputs
     `(("zlib" ,zlib)))
    (home-page "http://rpy.sourceforge.net/")
    (synopsis "Python interface to the R language")
    (description "rpy2 is a redesign and rewrite of rpy.  It is providing a
low-level interface to R from Python, a proposed high-level interface,
including wrappers to graphical libraries, as well as R-like structures and
functions.")
    (license license:gpl3+)))

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
; http://downloads.sourceforge.net/project/scipy/scipy/0.16.1/scipy-0.16.1.tar.gz
       (uri (string-append "mirror://sourceforge/scipy/scipy/" version
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

# backslash-n to make emacs happy
\n[atlas]
library_dirs = ~a/lib
atlas_libs = openblas
"
                      (assoc-ref inputs "openblas")
                      (assoc-ref inputs "openblas")
                      (assoc-ref inputs "openblas"))))
          #t)
        (alist-cons-after
         'install 'install-doc
         (lambda* (#:key inputs outputs #:allow-other-keys)
           (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                  (doc (string-append data "/doc/" ,name "-" ,version))
                  (html (string-append doc "/html"))
                  (pyver ,(string-append "PYVER=")))
             ;; Make installed package available for building the
             ;; documentation
             (add-installed-pythonpath inputs outputs)
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
    (license license:bsd-3)))

(define-public python2-scipy
  (package-with-python2 python-scipy))

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
    (license license:x11)))

(define-public python2-sqlalchemy
  (package-with-python2 python-sqlalchemy))

(define-public python-pycodestyle
  (package
    (name "python-pycodestyle")
    (version "2.0.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pycodestyle" version))
        (sha256
          (base32
            "1rz2v8506mdjdyxcnv9ygiw6v0d4dqx8z5sjyjm0w2v32h5l5w1p"))))
    (build-system python-build-system)
    (home-page "https://pycodestyle.readthedocs.io/")
    (synopsis "Python style guide checker")
    (description "@code{pycodestyle} (formerly pep8) is a tool to check
Python code against some of the style conventions in
@url{http://www.python.org/dev/peps/pep-0008/,PEP 8}.")
    (license license:expat)))

(define-public python2-pycodestyle
  (package-with-python2 python-pycodestyle))

(define-public python-orderedmultidict
  (package
    (name "python-orderedmultidict")
    (version "0.7.10")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "orderedmultidict" version))
        (sha256
          (base32
            "1gvqk0jd432wsn88kq4svad68xz3r012jfpnhh9in7bqrkyxidky"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-tests
           (lambda _
             ;; The package uses nosetest for running the tests.
             ;; Adding this initfile allows to run the test suite
             ;; without requiring nosetest.
             (zero? (system* "touch" "tests/__init__.py")))))))
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

(define-public python-furl
  (package
    (name "python-furl")
    (version "0.5.6")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "furl" version))
        (sha256
          (base32
            "0lzpfpm686hvz3sr1mcrnd1b3lgmnw8v59gb43wfi98r3b671pqc"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-orderedmultidict" ,python-orderedmultidict)))
    (native-inputs
     `(("python-pycodestyle" ,python-pycodestyle)))
    (home-page "https://github.com/gruns/furl")
    (synopsis "URL manipulation in Python")
    (description "Furl provides an easy-to-use alternative to the
@code{urllib} and @code{urlparse} modules for manipulating URLs.")
    (license license:unlicense)))

(define-public python2-furl
  (package-with-python2 python-furl))

(define-public python-flask-babel
  (package
    (name "python-flask-babel")
    (version "0.11.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "Flask-Babel" version))
        (sha256
          (base32
            "16b80cipdba9xj3jlaiaq6wgrgpjb70w3j01jjy9hbp4k71kd6yj"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-flask" ,python-flask)
       ("python-babel" ,python-babel)
       ("python-jinja2" ,python-jinja2)
       ("python-pytz" ,python-pytz)))
    (home-page "https://github.com/python-babel/flask-babel")
    (synopsis "Add i18n/l10n support to Flask applications")
    (description "This package implements internationalization and localization
support for Flask.  This is based on the Python babel module as well as pytz -
both of which are installed automatically if you install this library.")
    (license license:bsd-3)))

(define-public python2-flask-babel
  (package-with-python2 python-flask-babel))

(define-public python-sqlalchemy-utils
  (package
    (name "python-sqlalchemy-utils")
    (version "0.32.11")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "SQLAlchemy-Utils" version))
        (sha256
         (base32
          "1wghyvk73cmq3iqyg3fczw128fv2pan2v76m0xg1bw05h8fhvnk3"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-sqlalchemy" ,python-sqlalchemy)))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/kvesteri/sqlalchemy-utils")
    (synopsis "Various utility functions for SQLAlchemy")
    (description
     "SQLAlchemy-utils provides various utility functions and custom data types
for SQLAlchemy.  SQLAlchemy is an SQL database abstraction library for Python.

You might also want to install the following optional dependencies:
@enumerate
@item @code{python-passlib}
@item @code{python-babel}
@item @code{python-cryptography}
@item @code{python-pytz}
@item @code{python-psycopg2}
@item @code{python-furl}
@item @code{python-flask-babel}
@end enumerate
")
    (license license:bsd-3)))

(define-public python2-sqlalchemy-utils
  (package-with-python2 python-sqlalchemy-utils))

(define-public python-alembic
  (package
    (name "python-alembic")
    (version "0.8.7")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "alembic" version))
       (sha256
        (base32
         "0ias6fdzwr2s220fnjspkdgm9510bd0cnap0hx5y4zy4srba9f3z"))))
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
    (license license:expat)))

(define-public python2-alembic
  (package-with-python2 python-alembic))

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

(define-public python-pillow
  (package
    (name "python-pillow")
    (version "3.3.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Pillow" version))
       (sha256
        (base32
         "0xkv0p1d73gz0a1qaasf0ai4262g8f334j07vd60bjrxs2wr3nmj"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose"       ,python-nose)))
    (inputs
     `(("freetype" ,freetype)
       ("lcms"     ,lcms)
       ("zlib"     ,zlib)
       ("libjpeg"  ,libjpeg)
       ("openjpeg" ,openjpeg)
       ("libtiff"  ,libtiff)
       ("libwebp"  ,libwebp)))
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (add-after
                   'install 'check-installed
                   (lambda* (#:key outputs inputs #:allow-other-keys)
                     (begin
                       (setenv "HOME" (getcwd))
                       ;; Make installed package available for running the
                       ;; tests
                       (add-installed-pythonpath inputs outputs)
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
    (license (license:x11-style
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
     `(("pkg-config" ,pkg-config)))
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
    (license license:bsd-3)))

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
       ("python-pytest" ,python-pytest)))
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
     `(("libxcb" ,libxcb)))
    (propagated-inputs
     `(("python-cffi" ,python-cffi) ; used at run time
       ("python-six" ,python-six)))
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
       ("python-docutils" ,python-docutils)))
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
    (license license:bsd-3)))

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
    (license license:isc)))

(define-public python2-pexpect
  (package-with-python2 python-pexpect))

(define-public python-setuptools-scm
  (package
    (name "python-setuptools-scm")
    (version "1.11.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "setuptools_scm" version))
              (sha256
               (base32
                "1gqr73i150yzj3mz32854vj93x07yr52kn8fdckwa41ll8wgficc"))))
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
    (outputs '("out" "doc"))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-appdirs" ,python-appdirs)))
    (native-inputs
     `(("python-setuptools-scm" ,python-setuptools-scm)
       ("python-sphinx" ,python-sphinx)
       ("python-rst.linker" ,python-rst.linker)
       ("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'build 'build-doc
           (lambda _
             (setenv "LANG" "en_US.UTF-8")
             (zero? (system* "python" "setup.py" "build_sphinx"))))
         (add-after 'install 'install-doc
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((data (string-append (assoc-ref outputs "doc") "/share"))
                    (doc (string-append data "/doc/" ,name "-" ,version))
                    (html (string-append doc "/html")))
               (mkdir-p html)
               (for-each (lambda (file)
                           (copy-file file (string-append doc "/" file)))
                         '("README.rst" "CHANGES.rst"))
               (copy-recursively "build/sphinx/html" html)))))))
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
    (version "4.2.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "traitlets" version))
       (sha256
        (base32
         "1afy08sa5n9gnkvh3da49c16zkyv598vchv0p1hp7zzjy8895hz4"))))
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
    (license license:bsd-3)))

(define-public python2-traitlets
  (package-with-python2 python-traitlets))

(define-public python-jupyter-core
  (package
    (name "python-jupyter-core")
    (version "4.2.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append (pypi-uri "jupyter_core" version)))
       (sha256
        (base32
         "177d9csqldzhsh6xs1p4nf6lzvhzyg6gklqjf69lxgxyadx87v24"))))
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
    (version "4.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "jupyter_client" version))
       (sha256
        (base32
         "1vjjrpjw7k5sh982pbjnslv7byfbfazjw9g92jvs7dz5qbx556n9"))))
    (build-system python-build-system)
    ;; Tests fail because of missing native python kernel which I assume is
    ;; provided by the ipython package, which we cannot use because it would
    ;; cause a dependency cycle.
    (arguments `(#:tests? #f))
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
    (version "4.5.0")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "ipykernel" version))
      (sha256
       (base32 "15c2bp1x3i6s4xb7vz7742h3kmvdfdfn9n2haywm3mwgvf77jni4"))))
    (build-system python-build-system)
    ;; The tests load a submodule of IPython.  However, IPython itself depends
    ;; on ipykernel.
    (arguments `(#:tests? #f))
    (propagated-inputs
     ;; imported at runtime during connect
     `(("python-jupyter-client" ,python-jupyter-client)))
    (home-page "http://ipython.org")
    (synopsis "IPython Kernel for Jupyter")
    (description
     "This package provides the IPython kernel for Jupyter.")
    (license license:bsd-3)))

(define-public python2-ipykernel
  (package-with-python2 python-ipykernel))

(define-public python-testpath
  (package
    (name "python-testpath")
    (version "0.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/jupyter/testpath/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "04kh3fgvmqz6cfcw79q70qwjz7ib7lxm27cc548iy2rpr33qqf55"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f ; this package does not even have a setup.py
       #:phases
       (modify-phases %standard-phases
         (delete 'install)
         (replace 'build
                  (lambda* (#:key inputs outputs #:allow-other-keys)
                    (let ((dir (string-append
                                (assoc-ref outputs "out")
                                "/lib/python"
                                (string-take (string-take-right
                                              (assoc-ref inputs "python") 5) 3)
                                "/site-packages/testpath")))
                      (mkdir-p dir)
                      (copy-recursively "testpath" dir))
                    #t)))))
    (home-page "https://github.com/takluyver/testpath")
    (synopsis "Test utilities for code working with files and commands")
    (description
     "Testpath is a collection of utilities for Python code working with files
and commands.  It contains functions to check things on the filesystem, and
tools for mocking system commands and recording calls to those.")
    (license license:expat)))

(define-public python2-testpath
  (package-with-python2 python-testpath))

(define-public python-ipython
  (package
    (name "python-ipython")
    (version "4.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ipython" version ".tar.gz"))
       (sha256
        (base32 "1h2gp1p06sww9rzfkfzqy489bh47gj3910y2b1wdk3dcx1cqz4is"))))
    (build-system python-build-system)
    (outputs '("out" "doc"))
    (propagated-inputs
     `(("python-pyzmq" ,python-pyzmq)
       ("python-terminado" ,python-terminado)
       ("python-matplotlib" ,python-matplotlib)
       ("python-numpy" ,python-numpy)
       ("python-numpydoc" ,python-numpydoc)
       ("python-jinja2" ,python-jinja2)
       ("python-mistune" ,python-mistune)
       ("python-pexpect" ,python-pexpect)
       ("python-pickleshare" ,python-pickleshare)
       ("python-simplegeneric" ,python-simplegeneric)
       ("python-jsonschema" ,python-jsonschema)
       ("python-traitlets" ,python-traitlets)
       ("python-ipykernel" ,python-ipykernel)
       ("python-pygments" ,python-pygments)))
    (inputs
     `(("readline" ,readline)
       ("which" ,which)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-requests" ,python-requests) ;; for tests
       ("python-testpath" ,python-testpath)
       ("python-nose" ,python-nose)
       ("python-sphinx" ,python-sphinx)
       ("texlive" ,texlive)
       ("texinfo" ,texinfo)))
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
              ;; Make installed package available for running the tests
              (add-installed-pythonpath inputs outputs)
              (with-directory-excursion "docs"
                ;; FIXME: pdf fails to build
                ;;(system* "make" "pdf" "PAPER=a4")
                (system* "make" "html")
                (system* "make" "info"))
              (copy-recursively "docs/man" man1)
              (copy-recursively "examples" examples)
              (copy-recursively "docs/build/html" html)
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
          (lambda* (#:key inputs outputs tests? #:allow-other-keys)
            (if tests?
                (with-directory-excursion "/tmp"
                  ;; Make installed package available for running the tests
                  (add-installed-pythonpath inputs outputs)
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
    (license license:bsd-3)
    (properties `((python2-variant . ,(delay python2-ipython))))))

(define-public python2-ipython
  (let ((ipython (package-with-python2 (strip-python2-variant python-ipython))))
    (package
      (inherit ipython)
      ;; FIXME: some tests are failing
      (arguments
       `(#:tests? #f ,@(package-arguments ipython)))
      ;; FIXME: add pyreadline once available.
      (native-inputs
       `(("python2-mock" ,python2-mock)
         ,@(package-native-inputs ipython))))))

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
    (home-page
      "http://cheeseshop.python.org/pypi/isodate")
    (synopsis
      "Python date parser and formatter")
    (description
      "Python-isodate is a python module for parsing and formatting
ISO 8601 dates, time and duration.")
    (license license:bsd-3)))

(define-public python2-isodate
  (package-with-python2 python-isodate))

(define-public python-html5lib
  (package
    (name "python-html5lib")
    (version "1.0b10")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "html5lib" version))
        (sha256
          (base32
            "1yd068a5c00wd0ajq0hqimv7fd82lhrw0w3s01vbhy9bbd6xapqd"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-webencodings" ,python-webencodings)))
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

;; Needed for python-bleach, a dependency of python-notebook
(define-public python-html5lib-0.9
  (package
    (inherit python-html5lib)
    (version "0.999")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "html5lib" version))
       (sha256
        (base32
         "17n4zfsj6ynmbwdwviywmj8r6nzr3xvfx2zs0xhndmvm51z7z263"))))))

(define-public python2-html5lib-0.9
  (package-with-python2 python-html5lib-0.9))

(define-public python-webencodings
  (package
    (name "python-webencodings")
    (version "0.5")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "webencodings" version))
              (sha256
               (base32
                "015rw7662lkpb9aqiqah2hbizk6w531badqwjpz41rr47glmxid5"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (zero? (system* "py.test" "-v" "webencodings/tests.py")))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/SimonSapin/python-webencodings")
    (synopsis "Character encoding aliases for legacy web content")
    (description
     "In order to be compatible with legacy web content when interpreting
something like @code{Content-Type: text/html; charset=latin1}, tools need
to use a particular set of aliases for encoding labels as well as some
overriding rules.  For example, @code{US-ASCII} and @code{iso-8859-1} on
the web are actually aliases for @code{windows-1252}, and an @code{UTF-8}
or @code{UTF-16} BOM takes precedence over any other encoding declaration.
The WHATWG @url{https://encoding.spec.whatwg.org/,Encoding} standard
defines all such details so that implementations do not have to
reverse-engineer each other.

This module implements the Encoding standard and has encoding labels and
BOM detection, but the actual implementation for encoders and decoders
is Python’s.")
    (license license:bsd-3)))

(define-public python2-webencodings
  (package-with-python2 python-webencodings))

(define-public python-urwid
  (package
    (name "python-urwid")
    (version "1.3.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "urwid" version))
       (sha256
        (base32
         "18cnd1wdjcas08x5qwa5ayw6jsfcn33w4d9f7q3s29fy6qzc1kng"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; Disable failing test. Bug filed upstream:
         ;; https://github.com/wardi/urwid/issues/164
         ;; TODO: check again for python-urwid > 1.3.1 or python > 3.4.3.
         (add-after 'unpack 'disable-failing-test
          (lambda _
            (substitute* "urwid/tests/test_event_loops.py"
              (("test_remove_watch_file")
                "disable_remove_watch_file")))))))
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
      `(("sqlite" ,sqlite)))
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
    (version "3.6.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "lxml" version))
        (sha256
         (base32
          "1pvbmiy2m7jwv493kilbghhj2pkh8wy1na3ji350vhzhlwlclx4w"))))
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
    (version "4.5.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "beautifulsoup4" version))
       (sha256
        (base32
         "1qgmhw65ncsgccjhslgkkszif47q6gvxwqv4mim17agxd81p951w"))))
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
           (lambda _ (zero? (system* "./convert-py3k")))))))
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
    (license license:expat)))

(define-public python2-beautifulsoup4
  (package
    (inherit (package-with-python2
              (strip-python2-variant python-beautifulsoup4)))
    (arguments `(#:python ,python-2))))

(define-public python2-cssutils
  (package
    (name "python2-cssutils")
    (version "1.0.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "cssutils" version))
        (sha256
         (base32
          "0qwha9x1wml2qmipbcz03gndnlwhzrjdvw9i09si247a90l8p8fq"))))
    (build-system python-build-system)
    (native-inputs
      `(("python2-mock" ,python2-mock) ; for the tests
        ("unzip" ,unzip))) ; for unpacking the source
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
    (license license:lgpl3+)))

(define-public python-cssselect
  (package
    (name "python-cssselect")
    (version "0.9.2")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "cssselect" version))
        (sha256
         (base32
          "1xg6gbva1yswghiycmgincv6ab4bn7hpm720ndbj40h8xycmnfvi"))))
    (build-system python-build-system)
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
    (license license:bsd-3)))

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
     `(("python-nose" ,python-nose)))
    (home-page "http://networkx.github.io/")
    (synopsis "Python module for creating and manipulating graphs and networks")
    (description
      "NetworkX is a Python package for the creation, manipulation, and study
of the structure, dynamics, and functions of complex networks.")
    (license license:bsd-3)))

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
    (version "0.7.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "seaborn" version))
       (sha256
        (base32 "0ibi3xsfm2kysph61mnfy0pf8d5rkgxgrdb0z9nbizgcgdsb5a0m"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pandas" ,python-pandas)
       ("python-matplotlib" ,python-matplotlib)
       ("python-scipy" ,python-scipy)))
    (home-page "http://stanford.edu/~mwaskom/software/seaborn/")
    (synopsis "Statistical data visualization")
    (description
     "Seaborn is a library for making attractive and informative statistical
graphics in Python.  It is built on top of matplotlib and tightly integrated
with the PyData stack, including support for numpy and pandas data structures
and statistical routines from scipy and statsmodels.")
    (license license:bsd-3)
    (properties `((python2-variant . ,(delay python2-seaborn))))))

(define-public python2-seaborn
  (let ((base (package-with-python2 (strip-python2-variant python-seaborn))))
    (package
      (inherit base)
      (propagated-inputs `(("python2-pytz" ,python2-pytz)
                           ,@(package-propagated-inputs base))))))

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
    (home-page "http://www.sympy.org/")
    (synopsis "Python library for symbolic mathematics")
    (description
     "SymPy is a Python library for symbolic mathematics.  It aims to become a
full-featured computer algebra system (CAS) while keeping the code as simple
as possible in order to be comprehensible and easily extensible.")
    (license license:bsd-3)))

(define-public python2-sympy
  (package-with-python2 python-sympy))

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
    (native-inputs
     `(("unzip" ,unzip)))  ; for unpacking the source
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
    (native-inputs
     `(("python-certifi" ,python-certifi)))
    (propagated-inputs
     `(("python-backports-abc" ,python-backports-abc)))
    (home-page "http://www.tornadoweb.org/")
    (synopsis "Python web framework and asynchronous networking library")
    (description
     "Tornado is a Python web framework and asynchronous networking library,
originally developed at FriendFeed.  By using non-blocking network I/O,
Tornado can scale to tens of thousands of open connections, making it ideal
for long polling, WebSockets, and other applications that require a long-lived
connection to each user.")
    (license license:asl2.0)
    (properties `((python2-variant . ,(delay python2-tornado))))))

(define-public python2-tornado
  (let ((tornado (package-with-python2 (strip-python2-variant python-tornado))))
    (package (inherit tornado)
      (propagated-inputs
       `(("python2-backport-ssl-match-hostname"
          ,python2-backport-ssl-match-hostname)
         ("python2-singledispatch" ,python2-singledispatch)
          ,@(package-propagated-inputs tornado))))))

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
    (home-page "https://github.com/cython/backports_abc")
    (synopsis "Backport of additions to the 'collections.abc' module")
    (description
     "Python-backports-abc provides a backport of additions to the
'collections.abc' module in Python-3.5.")
    (license license:psfl)))

(define-public python2-backports-abc
  (package-with-python2 python-backports-abc))

(define-public python-waf
  (package
    (name "python-waf")
    (version "1.9.5")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://waf.io/"
                                  "waf-" version ".tar.bz2"))
              (sha256
               (base32
                "1sl3ipi2czds57rlzjnpdzqa0skx8asfvmh3qmibpvdwf15rpppg"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'build
           (lambda _
             (zero? (system* "python" "waf-light" "configure" "build"))))
         (replace 'check
           (lambda _
             (zero? (system* "python" "waf" "--version"))))
         (replace 'install
           (lambda _
             (copy-file "waf" %output))))))
    (home-page "http://waf.io/")
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
       ("python-nose" ,python-nose)))
    (home-page "http://github.com/zeromq/pyzmq")
    (synopsis "Python bindings for 0MQ")
    (description
     "PyZMQ is the official Python binding for the ZeroMQ messaging library.")
    (license license:bsd-4)))

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
    (native-inputs
      `(("python-pytest" ,python-pytest)
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
            "0bs9cz4fr99r2rwig1b8jwaadl1nan7kgpdzqwj0bwbckwbmh7nc"))
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
      `(("python-pep8" ,python-pep8)
        ("python-pyflakes" ,python-pyflakes)
        ("python-mccabe" ,python-mccabe)))
    (native-inputs
      `(("python-mock" ,python-mock) ; TODO: only required for < 3.3
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
    (propagated-inputs
      `(("python-pep8" ,python-pep8-1.5.7)
        ("python-pyflakes" ,python-pyflakes-0.8.1)
        ("python-mccabe" ,python-mccabe-0.2.1)))
    (native-inputs
      `(("python-mock" ,python-mock)
        ("python-nose" ,python-nose)))
    (version "2.2.4")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "flake8" version))
        (sha256
          (base32
            "1r9wsry4va45h1rck5hxd3vzsg2q3y6lnl6pym1bxvz8ry19jwx8"))
        (modules '((guix build utils)))
        (snippet
         '(begin
            ;; Remove pre-compiled .pyc files from source.
            (for-each delete-file-recursively
                      (find-files "." "__pycache__" #:directories? #t))
            (for-each delete-file (find-files "." "\\.pyc$"))
            #t))))))

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
    (license license:bsd-3)))

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
    (native-inputs
     `(("python-nose" ,python-nose)))
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
    (license license:isc)))

(define-public python2-ptyprocess
  (package-with-python2 python-ptyprocess))

(define-public python-terminado
  (package
    (name "python-terminado")
    (version "0.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "terminado" version))
       (sha256
        (base32
         "09h1kwi86g5mrk14s4pgbhshd602zry29lnpxamcqz864kva22rc"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-tornado" ,python-tornado)
       ("python-ptyprocess" ,python-ptyprocess)))
    (native-inputs
     `(("python-nose" ,python-nose)))
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
    (license license:bsd-2)
    (properties `((python2-variant . ,(delay python2-terminado))))))

(define-public python2-terminado
  (let ((terminado (package-with-python2 (strip-python2-variant python-terminado))))
    (package (inherit terminado)
      (propagated-inputs
       `(("python2-backport-ssl-match-hostname"
          ,python2-backport-ssl-match-hostname)
          ,@(package-propagated-inputs terminado))))))

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
    (arguments
     '(#:test-target "check"
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-setuppy
           ;; Remove the undocumented "extra_path" argument, which adds an
           ;; intervening directories between site-packages and the package
           ;; directory.
           (lambda _
             (substitute* "setup.py"
               (("^[ \t]*extra_path *= *'FontTools',") ""))
             #t)))))
    (home-page "http://github.com/behdad/fonttools")
    (synopsis "Tools to manipulate font files")
    (description
     "FontTools/TTX is a library to manipulate font files from Python.  It
supports reading and writing of TrueType/OpenType fonts, reading and writing
of AFM files, reading (and partially writing) of PS Type 1 fonts.  The package
also contains a tool called “TTX” which converts TrueType/OpenType fonts to and
from an XML-based format.")
    (license (license:non-copyleft
              "file://LICENSE.txt"
              "See LICENSE.txt in the distribution."))))

(define-public python2-fonttools
  (package-with-python2 python-fonttools))

(define-public python-ly
  (package
    (name "python-ly")
    (version "0.9.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/57/4f/"
                           "889579244947368f28eda66b782331b1e75f83fd72e63f9ece93cd7a18f9"
                           "/python-ly-" version ".tar.gz"))
       (sha256
        (base32
         "0g6n288l83sfwavxh1aryi0aqvsr3sp7v6f903mckwqa4scpky62"))))
    (build-system python-build-system)
    (synopsis "Tool and library for manipulating LilyPond files")
    (description "This package provides a Python library to parse, manipulate
or create documents in LilyPond format.  A command line program ly is also
provided that can be used to do various manipulations with LilyPond files.")
    (home-page "https://pypi.python.org/pypi/python-ly")
    (license license:gpl2+)))

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
    (version "1.1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://bitbucket.org/nikratio/python-llfuse/downloads/"
                    "llfuse-" version ".tar.bz2"))
              (sha256
               (base32
                "0v6vj9mb286njgd1szg9hz2qdh5f3vkhsvajripfcqg458av310v"))))
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
    (version "0.4.8")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "msgpack-python" version))
              (sha256
               (base32
                "11pqk5braa6wndpnr1dhg64js82vjgxnm0lzy73rwl831zgijaqs"))))
    (build-system python-build-system)
    (synopsis "MessagePack (de)serializer")
    (description "MessagePack is a fast, compact binary serialization format,
suitable for similar data to JSON.  This package provides CPython bindings for
reading and writing MessagePack data.")
    (home-page "https://pypi.python.org/pypi/msgpack-python/")
    (license license:asl2.0)))

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
    (home-page "https://github.com/drkjam/netaddr/")
    (synopsis "Pythonic manipulation of  network addresses")
    (description
      "A Python library for representing and manipulating IPv4, IPv6, CIDR, EUI
and MAC network addresses.")
    (license license:bsd-3)))

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
    (home-page "https://github.com/GrahamDumpleton/wrapt")
    (synopsis "Module for decorators, wrappers and monkey patching")
    (description
      "The aim of the wrapt module is to provide a transparent object proxy for
  Python, which can be used as the basis for the construction of function
  wrappers and decorator functions.")
    (license license:bsd-2)))

(define-public python2-wrapt
  (package-with-python2 python-wrapt))

(define-public python-iso8601
  (package
  (name "python-iso8601")
  (version "0.1.11")
  (source
    (origin
      (method url-fetch)
      (uri (pypi-uri "iso8601" version))
      (sha256
       (base32
        "0c7gh3lsdjds262h0v1sqc66l7hqgfwbakn96qrhdbl0i3vm5yz8"))))
  (build-system python-build-system)
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
    (home-page "https://github.com/atdt/monotonic")
    (synopsis "Implementation of time.monotonic() for Python 2 & < 3.3")
    (description
      "This module provides a monotonic() function which returns the value (in
fractional seconds) of a clock which never goes backwards.")
    (license license:asl2.0)))

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
    (native-inputs
      `(("python-nose" ,python-nose)))
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
         (replace 'check (lambda _ (zero? (system* "nosetests")))))))
    (native-inputs `(("python-nose"       ,python-nose)))
    (home-page "http://www.python-excel.org/")
    (synopsis "Library for extracting data from Excel files")
    (description "This packages provides a library to extract data from
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
       (uri (string-append
             "https://pypi.python.org/packages/source/P/PrettyTable/"
             "prettytable-" version ".tar.bz2"))
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
    (version "3.2.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "tables" version))
       (sha256
        (base32
         "117s6w7s3yxafpmf3zz3svana7xfrsviw01va1xp7h8ylx8v6r1m"))
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
             (zero? (system* "python" "setup.py" "build"
                             (string-append "--hdf5="
                                            (assoc-ref inputs "hdf5"))))))
         (replace 'check
           (lambda* (#:key inputs #:allow-other-keys)
             (zero? (system* "python" "setup.py" "check"
                             (string-append "--hdf5="
                                            (assoc-ref inputs "hdf5")))))))))
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
designed to efficently cope with extremely large amounts of data.")
    (license license:bsd-3)))

(define-public python2-tables
  (package-with-python2 python-tables))

(define-public python-pyasn1
  (package
    (name "python-pyasn1")
    (version "0.1.9")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyasn1" version))
       (sha256
        (base32
         "0zraxni14bqi20kr4bi6nwsh32aibz0fq0xaczfisw0zdpcsqg45"))))
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
    (version "0.0.8")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pyasn1-modules" version))
        (sha256
         (base32
          "0drqgw81xd3fxdlg89kgd79zzrabvfncvkbybi2wr6w2y4s1jmhh"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pyasn1" ,python-pyasn1)))
    (home-page "http://sourceforge.net/projects/pyasn1/")
    (synopsis "ASN.1 codec implementations")
    (description
     "Pyasn1-modules is a collection of Python modules providing ASN.1 types and
implementations of ASN.1-based codecs and protocols.")
    (license license:bsd-3)))

(define-public python2-pyasn1-modules
  (package-with-python2 python-pyasn1-modules))

(define-public python-ipaddress
  (package
    (name "python-ipaddress")
    (version "1.0.16")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "ipaddress" version))
              (sha256
               (base32
                "1c3imabdrw8nfksgjjflzg7h4ynjckqacb188rf541m74arq4cas"))))
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
           (lambda* _
             (zero? (system* "python" "ipaddr_test.py")))))))
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

(define-public python-cryptography-vectors
  (package
    (name "python-cryptography-vectors")
    (version "1.7.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "cryptography_vectors" version))
       (sha256
        (base32
         "1x2mz4wggja5ih45c6cw0kzyad4jr8avg327dawjr1gnpdq1psa7"))))
    (build-system python-build-system)
    (home-page "https://github.com/pyca/cryptography")
    (synopsis "Test vectors for the cryptography package")
    (description
      "This package contains test vectors for the cryptography package.")
    ;; Distributed under either BSD-3 or ASL2.0
    (license (list license:bsd-3 license:asl2.0))))

(define-public python2-cryptography-vectors
  (package-with-python2 python-cryptography-vectors))

(define-public python-cryptography
  (package
    (name "python-cryptography")
    (version "1.7.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "cryptography" version))
       (sha256
        (base32
         "0k6v7wq4h0yk9r0x0bl2x9fyrg4a6gj5qp4m9mgpk6m481yyygwm"))))
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
       ("python-pretend" ,python-pretend)
       ("python-pyasn1" ,python-pyasn1)
       ("python-pyasn1-modules" ,python-pyasn1-modules)
       ("python-pytz" ,python-pytz)
       ("python-pytest" ,python-pytest-2.9.2)))
    (home-page "https://github.com/pyca/cryptography")
    (synopsis "Cryptographic recipes and primitives for Python")
    (description
      "cryptography is a package which provides cryptographic recipes and
primitives to Python developers.  It aims to be the “cryptographic standard
library” for Python.  The package includes both high level recipes, and low
level interfaces to common cryptographic algorithms such as symmetric ciphers,
message digests and key derivation functions.")
    ;; Distributed under either BSD-3 or ASL2.0
    (license (list license:bsd-3 license:asl2.0))
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
    (version "16.2.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyOpenSSL" version))
       (sha256
        (base32
         "0vji4yrfshs15xpczbhzhasnjrwcarsqg87n98ixnyafnyxs6ybp"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-cryptography" ,python-cryptography)
       ("python-six" ,python-six)))
    (inputs
     `(("openssl" ,openssl)))
    (home-page "https://github.com/pyca/pyopenssl")
    (synopsis "Python wrapper module around the OpenSSL library")
    (description
      "PyOpenSSL is a high-level wrapper around a subset of the OpenSSL
library.")
    (license license:asl2.0)))

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
    (native-inputs
      `(;; Tests
        ("python-virtualenv" ,python-virtualenv)
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
       (uri (pypi-uri "python-termcolor" version))
       (sha256
        (base32
         "0fv1vq14rpqwgazxg4981904lfyp84mnammw7y046491cv76jv8x"))))
    (build-system python-build-system)
    (arguments
     ;; There are no tests.
     `(#:tests? #f))
    (home-page "http://pypi.python.org/pypi/termcolor")
    (synopsis "ANSII Color formatting for terminal output")
    (description
     "This package provides ANSII Color formatting for output in terminals.")
    (license license:expat)))

(define-public python2-termcolor
  (package-with-python2 python-termcolor))

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
                                         "/lib/libarchive.so'")))))))))
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
    (source (origin
              (inherit (package-source file))
              ;; This patch should not be applied to python2-file.
              (patches (search-patches "python-file-double-encoding-bug.patch"))))
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
    (propagated-inputs
     `(("python-six" ,python-six)))
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
    (license license:gpl3+)))

(define-public python2-debian
  (package-with-python2 python-debian))

(define-public python-nbformat
  (package
    (name "python-nbformat")
    (version "4.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "nbformat" version))
       (sha256
        (base32
         "0mq8iki3d4mnx7wy05phss7x98mds4fqydin8lcagidp1knw1xnv"))))
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
    (home-page "http://github.com/jsocol/bleach")
    (synopsis "Whitelist-based HTML-sanitizing tool")
    (description "Bleach is an easy whitelist-based HTML-sanitizing tool.")
    (license license:asl2.0)))

(define-public python2-bleach
  (package-with-python2 python-bleach))

(define-public python-entrypoints
  (package
    (name "python-entrypoints")
    (version "0.2.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/takluyver/entrypoints/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0azqlkh3j0za080lsf5crnhaxx3c93k9dpv5ihkhf5cppgw5sjz5"))))
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
    ;; The "bdist_egg" target is disabled by default, causing the installation
    ;; to fail.
    (arguments `(#:configure-flags (list "bdist_egg")))
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
    (version "4.2.3")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "notebook" version))
              (sha256
               (base32
                "0laq5c2f21frq6xcdckgq7raqhznbjb0qs0357g612z87wyn1a9r"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             ;; HOME must be set for tests
             (setenv "HOME" "/tmp")
             (zero? (system* "nosetests")))))))
    (propagated-inputs
     `(("python-jupyter-core" ,python-jupyter-core)
       ("python-nbformat" ,python-nbformat)
       ("python-nbconvert" ,python-nbconvert)
       ("python-ipython" ,python-ipython)))
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
    (version "1.2.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "widgetsnbextension" version))
       (sha256
        (base32
         "0lff2mrwrgsa1mxmwx3phl9xvy0jqfpg6khbmxy53jbq56rwy666"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-notebook" ,python-notebook)))
    (native-inputs
     `(("python-nose" ,python-nose)))
    (home-page "http://ipython.org")
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
    ;; FIXME: it's not clear how to run the tests.
    (arguments `(#:tests? #f))
    (propagated-inputs
     `(("python-ipykernel" ,python-ipykernel)
       ("python-ipython" ,python-ipython)
       ("python-traitlets" ,python-traitlets)
       ("python-widgetsnbextension" ,python-widgetsnbextension)))
    (home-page "http://ipython.org")
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
    (version "5.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "jupyter_console" version))
       (sha256
        (base32
         "04acmkwsi99rcg3vb54c6n492zv35s92h2ahabc0w6wj976cipvx"))))
    (build-system python-build-system)
    ;; FIXME: it's not clear how to run the tests.
    (arguments `(#:tests? #f))
    (propagated-inputs
     `(("python-ipykernel" ,python-ipykernel)
       ("python-ipython" ,python-ipython)
       ("python-jupyter-client" ,python-jupyter-client)
       ("python-prompt-toolkit" ,python-prompt-toolkit)
       ("python-pygments" ,python-pygments)))
    (home-page "https://jupyter.org")
    (synopsis "Jupyter terminal console")
    (description "This package provides a terminal-based console frontend for
Jupyter kernels.  It also allows for console-based interaction with non-Python
Jupyter kernels such as IJulia and IRKernel.")
    (license license:bsd-3)))

(define-public python2-jupyter-console
  (package-with-python2 python-jupyter-console))

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
    ;; FIXME: it's not clear how to run the tests.
    (arguments `(#:tests? #f))
    (propagated-inputs
     `(("python-ipykernel" ,python-ipykernel)
       ("python-ipywidgets" ,python-ipywidgets)
       ("python-jupyter-console" ,python-jupyter-console)
       ("python-nbconvert" ,python-nbconvert)
       ("python-notebook" ,python-notebook)))
    (home-page "http://jupyter.org")
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
    (home-page "http://pypi.python.org/pypi/zope.event")
    (synopsis "Event publishing system for Python")
    (description "Zope.event provides an event publishing API, intended for
use by applications which are unaware of any subscribers to their events.  It
is a simple event-dispatching system on which more sophisticated event
dispatching systems can be built.")
    (license license:zpl2.1)))

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
    (native-inputs
     `(("python-zope-event" ,python-zope-event)))
    (home-page "https://github.com/zopefoundation/zope.interface")
    (synopsis "Python implementation of the \"design by contract\"
methodology")
    (description "Zope.interface provides an implementation of \"object
interfaces\" for Python.  Interfaces are a mechanism for labeling objects as
conforming to a given API or contract.")
    (license license:zpl2.1)))

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
    (license license:zpl2.1)))

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
         "1yvglxhzvhl45mndvn9gskx2ph30zz1bz7rrlyfs62fv2pvih90s"))
       (modules '((guix build utils)))
       (snippet
        '(begin
           ;; Remove pre-compiled .pyc files backup files from source.
           (for-each delete-file (find-files "." "(\\.pyc|~)$"))
           #t))))
    (build-system python-build-system)
    (native-inputs
     `(("python-zope-exceptions" ,python-zope-exceptions)))
    (propagated-inputs
     `(("python-zope-interface" ,python-zope-interface)))
    (home-page "http://pypi.python.org/pypi/zope.testing")
    (synopsis "Zope testing helpers")
    (description "Zope.testing provides a number of testing utilities for HTML
forms, HTTP servers, regular expressions, and more.")
    (license license:zpl2.1)))

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
       ;("python-zope-interface" ,python-zope-interface)
       ("python-zope-exceptions" ,python-zope-exceptions)
       ("python-zope-testing" ,python-zope-testing)
       ("unzip" ,unzip)))
    (propagated-inputs
     `(("python-zope-interface" ,python-zope-interface)))
    (home-page "http://pypi.python.org/pypi/zope.testrunner")
    (synopsis "Zope testrunner script")
    (description "Zope.testrunner provides a script for running Python
tests.")
    (license license:zpl2.1)))

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
    (home-page "http://pypi.python.org/pypi/zope.i18nmessageid")
    (synopsis "Message identifiers for internationalization")
    (description "Zope.i18nmessageid provides facilities for declaring
internationalized messages within program source text.")
    (license license:zpl2.1)))

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
     `(("python-zope-testing" ,python-zope-testing)
       ("python-coverage" ,python-coverage)
       ("python-nose" ,python-nose)))
    (home-page "http://pypi.python.org/pypi/zope.schema")
    (synopsis "Zope data schemas")
    (description "Zope.scheme provides extensions to zope.interface for
defining data schemas.")
    (license license:zpl2.1)))

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
    (license license:zpl2.1)))

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
    (license license:zpl2.1)))

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
    (propagated-inputs
     `(("python-zope-proxy" ,python-zope-proxy)
       ("python-zope-schema" ,python-zope-schema)))
    (home-page "http://pypi.python.org/pypi/zope.location/")
    (synopsis "Zope location library")
    (description "Zope.location implements the concept of \"locations\" in
Zope3, which are are special objects that have a structural location.")
    (license license:zpl2.1)))

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
       ("python-zope-proxy" ,python-zope-proxy)
       ("python-zope-schema" ,python-zope-schema)))
     (native-inputs
     `(("python-zope-component" ,python-zope-component)
       ("python-zope-configuration" ,python-zope-configuration)
       ("python-zope-location" ,python-zope-location)
       ("python-zope-testrunner" ,python-zope-testrunner)
       ("python-zope-testing" ,python-zope-testing)))
    (home-page "http://pypi.python.org/pypi/zope.security")
    (synopsis "Zope security framework")
    (description "Zope.security provides a generic mechanism to implement
security policies on Python objects.")
    (license license:zpl2.1)))

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
    (license license:zpl2.1)))

(define-public python2-zope-component
  (package-with-python2 python-zope-component))

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
     `(("python-nose" ,python-nose)))
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
    (version "0.11.11")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Werkzeug" version))
       (sha256
        (base32
         "1rgpq8a2qv26d75v9j3b074inirlyy6y4b5x4rxblp202jy4cb77"))))
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
    (license license:x11)))

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
    (arguments
     '(;; The tests appear to require networking.
       #:tests? #f))
    (propagated-inputs
     `(("python-pyopenssl" ,python-pyopenssl)))
    (synopsis "HTTPS support for Python's httplib and urllib2")
    (description "This is a HTTPS client implementation for httplib and urllib2
based on PyOpenSSL.  PyOpenSSL provides a more fully featured SSL implementation
over the default provided with Python and importantly enables full verification
of the SSL peer.")
    (home-page "https://github.com/cedadev/ndg_httpsclient/")
    (license license:bsd-3)))

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
    (license license:psfl)))

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
    (license license:lgpl2.1+)))

(define-public python2-texttable
  (package-with-python2 python-texttable))

(define-public python-websocket-client
  (package
    (name "python-websocket-client")
    (version "0.37.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "websocket_client" version))
       (sha256
        (base32
         "0h9glp1jll3z76ly3kg08aqgxqk0a68p4zi9yn50353bh5nj92v7"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)))
    (home-page "https://github.com/liris/websocket-client")
    (synopsis "WebSocket client for Python")
    (description "The Websocket-client module provides the low level APIs for
WebSocket usage in Python programs.")
    (license license:lgpl2.1+)))

(define-public python2-websocket-client
  (package-with-python2 python-websocket-client))

(define-public python-atomicwrites
  (package
    (name "python-atomicwrites")
    (version "1.1.0")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "atomicwrites" version))
             (sha256
              (base32
               "1s01dci8arsl9d9vr5nz1fk9znldp1z3l4yl43f0c27z12b8yxl0"))))
    (build-system python-build-system)
    (synopsis "Atomic file writes in Python")
    (description "Library for atomic file writes using platform dependent tools
for atomic file system operations.")
    (home-page "https://github.com/untitaker/python-atomicwrites")
    (license license:expat)))

(define-public python2-atomicwrites
  (package-with-python2 python-atomicwrites))

(define-public python-requests-toolbelt
  (package
    (name "python-requests-toolbelt")
    (version "0.6.2")
    (source (origin
             (method url-fetch)
             (uri (string-append
                    "https://pypi.python.org/packages/"
                    "e1/a4/a94c037bc72ad70441aff1403d3243510d2542ddca7759faaeffeb11aefe/"
                    "requests-toolbelt-" version ".tar.gz"))
             (sha256
              (base32
               "15q9nrgp85nqlr4kdz1zvj8z2npafi2sr12y7fqgxbkq28j1aci6"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-betamax" ,python-betamax)
       ("python-mock" ,python-mock)
       ("python-pytest" ,python-pytest)))
    (propagated-inputs
     `(("python-requests" ,python-requests)))
    (synopsis "Extensions to python-requests")
    (description "This is a toolbelt of useful classes and functions to be used
with python-requests.")
    (home-page "https://github.com/sigmavirus24/requests-toolbelt")
    (license license:asl2.0)))

(define-public python-click-threading
  (package
    (name "python-click-threading")
    (version "0.2.0")
    (source (origin
             (method url-fetch)
             (uri (string-append
                    "https://pypi.python.org/packages/"
                    "fe/b7/e7f609d18a2a351cb71616adcf54df1acd82f83cb9b5936935a4d20e2c23/"
                    "click-threading-" version ".tar.gz"))
             (sha256
              (base32
               "18bcqikxwb3drb8rf60cclxkxw52521b38ax3byah6j8cn8y9p4j"))))
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
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (synopsis "Namespace control and lazy-import mechanism")
    (description "With apipkg you can control the exported namespace of a Python
package and greatly reduce the number of imports for your users.  It is a small
pure Python module that works on virtually all Python versions.")
    (home-page "https://bitbucket.org/hpk42/apipkg")
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
minimal and fast API targetting the following uses:
@enumerate
@item distribute tasks to (many) local or remote CPUs
@item write and deploy hybrid multi-process applications
@item write scripts to administer multiple environments
@end enumerate")
    (home-page "http://codespeak.net/execnet/")
    (license license:expat)))

(define-public python2-execnet
  (package-with-python2 python-execnet))

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
     `(("python-apipkg" ,python-apipkg)
       ("python-execnet" ,python-execnet)
       ("python-py" ,python-py)
       ("python-pytest" ,python-pytest)))
    (synopsis "Py.test plugin with mechanisms for caching across test runs")
    (description "The pytest-cache plugin provides tools to rerun failures from
the last py.test invocation.")
    (home-page "https://bitbucket.org/hpk42/pytest-cache/")
    (license license:expat)))

(define-public python2-pytest-cache
  (package-with-python2 python-pytest-cache))

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
     `(("python-pytest" ,python-pytest)
       ("python-requests" ,python-requests)
       ("python-six" ,python-six)))
    (propagated-inputs
     `(("python-werkzeug" ,python-werkzeug)))
    (synopsis "Py.test plugin to test server connections locally")
    (description "Pytest-localserver is a plugin for the pytest testing
framework which enables you to test server connections locally.")
    (home-page "https://pypi.python.org/pypi/pytest-localserver")
    (license license:expat)))

(define-public python-wsgi-intercept
  (package
    (name "python-wsgi-intercept")
    (version "1.2.2")
    (source (origin
             (method url-fetch)
             (uri (string-append
                    "https://pypi.python.org/packages/"
                    "38/76/ebcbc24d0cb77db34520a3ca6ed1bd43ace17d182bbd8dd7d976f1c176fb/"
                    "wsgi_intercept-" version ".tar.gz"))
             (sha256
              (base32
               "0kjj2v2dvmnpdd5h5gk9rzz0f54rhjb0yiz3zg65bmp65slfw65d"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-httplib2" ,python-httplib2)
       ("python-requests" ,python-requests)
       ("python-urllib3" ,python-urllib3)))
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
    (version "3.11")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "icalendar" version))
             (sha256
              (base32
               "01v2f3swd5s72x65cdihw83dx1z799b4i49a6ncg7vqmcm20wapd"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-dateutil-2" ,python-dateutil-2)
       ("python-pytz" ,python-pytz)))
    (synopsis "Python library for parsing iCalendar files")
    (description "The icalendar package is a parser/generator of iCalendar
files for use with Python.")
    (home-page "https://github.com/collective/icalendar")
    (license license:bsd-2)))

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
     `(("python-sphinx" ,python-sphinx)))
    (synopsis "News Feed extension for Sphinx")
    (description "Sphinxcontrib-newsfeed is an extension for adding a simple
Blog, News or Announcements section to a Sphinx website.")
    (home-page "https://bitbucket.org/prometheus/sphinxcontrib-newsfeed")
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
    (home-page "https://github.com/berkerpeksag/astor")
    (synopsis "Read and write Python ASTs")
    (description
     "Astor is designed to allow easy manipulation of Python source via the
Abstract Syntax Tree.")
    (license license:bsd-3)))

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
    (version "0.11.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "hy" version))
              (sha256
               (base32
                "1msqv747iz12r73mz4qvsmlwkddwjvrahlrk7ysrcz07h7dsscxs"))))
    (build-system python-build-system)
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
    (propagated-inputs
     `(("python-requests" ,python-requests)))
    (home-page "https://github.com/litl/rauth")
    (synopsis "Python library for OAuth 1.0/a, 2.0, and Ofly")
    (description
     "Rauth is a Python library for OAuth 1.0/a, 2.0, and Ofly.  It also
provides service wrappers for convenient connection initialization and
authenticated session objects providing things like keep-alive.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-rauth))))))

(define-public python2-rauth
  (let ((base (package-with-python2 (strip-python2-variant python-rauth))))
    (package
      (inherit base)
      (native-inputs `(("python2-unittest2" ,python2-unittest2)
                       ,@(package-native-inputs base))))))

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

(define-public python2-futures
  (package
    (name "python2-futures")
    (version "3.0.3")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "futures" version))
        (sha256
         (base32
          "1vcb34dqhzkhbq1957vdjszhhm5y3j9ba88dgwhqx2zynhmk9qig"))))
    (build-system python-build-system)
    (arguments `(#:python ,python-2))
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

(define-public python-urllib3
  (package
    (name "python-urllib3")
    (version "1.18.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "urllib3" version))
        (sha256
         (base32
          "1wb8aqnq53vzh2amrv8kc66f3h6fx217y0q62y6n30a64p2yqmam"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f))
    (native-inputs
     `(;; some packages for tests
       ("python-nose" ,python-nose)
       ("python-mock" ,python-mock)
       ("python-tornado" ,python-tornado)))
    (propagated-inputs
     `(;; extra packages for https security
       ("python-certifi" ,python-certifi)
       ("python-ndg-httpsclient" ,python-ndg-httpsclient)
       ("python-pyasn1" ,python-pyasn1)
       ("python-pyopenssl" ,python-pyopenssl)))
    (home-page "https://urllib3.readthedocs.org/")
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
   (synopsis "colored terminal text rendering for Python")
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
   (home-page "http://stuvel.eu/rsa")
   (license license:asl2.0)))

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
    ;; FIXME: Tests require pytest-timeout, which itself requires
    ;; pytest>=2.8.0 for installation.
    '(#:tests? #f))
   (propagated-inputs
    `(("python-pluggy" ,python-pluggy) ; >=0.3.0,<0.4.0
      ("python-py" ,python-py)
      ("python-virtualenv" ,python-virtualenv)))
   (native-inputs
    `(; FIXME: Missing: ("python-pytest-timeout" ,python-pytest-timeout)
      ("python-pytest" ,python-pytest)))  ; >= 2.3.5
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
   (version "1.4.62")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri "botocore" version))
     (sha256
      (base32
       "1zxczlwqy9bl27d9bc5x99mb5mcsxm350240lp5nx7014xb311lj"))))
   (build-system python-build-system)
   (propagated-inputs
    `(("python-dateutil" ,python-dateutil-2)
      ("python-docutils" ,python-docutils)
      ("python-jmespath" ,python-jmespath)))
   (native-inputs
    `(("python-mock" ,python-mock)
      ("python-nose" ,python-nose)
      ("behave" ,behave)
      ("python-tox" ,python-tox)
      ("python-wheel" ,python-wheel)))
   (home-page "https://github.com/boto/botocore")
   (synopsis "Low-level interface to AWS")
   (description "Botocore is a Python library that provides a low-level
interface to the Amazon Web Services (AWS) API.")
   (license license:asl2.0)))

(define-public python2-botocore
  (package-with-python2 python-botocore))

(define-public awscli
  (package
   (name "awscli")
   (version "1.11.5")
   (source
    (origin
     (method url-fetch)
     (uri (pypi-uri name version))
     (sha256
      (base32
       "0lclasm0wnayd3b8zl9l91i32nbgrhh0ncf9lksss4cv0myfwmfg"))))
   (build-system python-build-system)
   (propagated-inputs
    `(("python-colorama" ,python-colorama)
      ("python-botocore" ,python-botocore)
      ("python-s3transfer" ,python-s3transfer)
      ("python-docutils" ,python-docutils)
      ("python-rsa" ,python-rsa)))
   (native-inputs
    `(("python-mock" ,python-mock)
      ("python-nose" ,python-nose)
      ("python-sphinx" ,python-sphinx)
      ("python-tox" ,python-tox)
      ("python-wheel" ,python-wheel)))
   (home-page "http://aws.amazon.com/cli/")
   (synopsis "Command line client for AWS")
   (description "AWS CLI provides a unified command line interface to the
Amazon Web Services (AWS) API.")
   (license license:asl2.0)))

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
    (license license:mpl2.0)
    (properties `((python2-variant . ,(delay python2-hypothesis))))))

(define-public python2-hypothesis
  (let ((hypothesis (package-with-python2
                     (strip-python2-variant python-hypothesis))))
    (package (inherit hypothesis)
      (native-inputs
       `(("python2-enum34" ,python2-enum34))))))

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
    (propagated-inputs
     `(("python-pytest" ,python-pytest)))
    (synopsis "Set-up and tear-down fixtures for unit tests")
    (description "This plugin allows you to set up and tear down fixtures within
unit test functions that use @code{py.test}. This is useful for using
@command{hypothesis} inside py.test, as @command{hypothesis} will call the test
function multiple times, without setting up or tearing down fixture state as is
normally the case.")
    (home-page "https://github.com/untitaker/pytest-subtesthack/")
    (license license:unlicense)))

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
    (license license:bsd-3)))

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
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'remove-django-test
           ;; Don't fail the tests when the inputs for the optional tests cannot be found.
           (lambda _
             (substitute*
               "tests/runtests.py"
               (("'ext_django.tests', 'ext_sqlalchemy', 'ext_dateutil', 'locale_babel'") "")
               (("sys.stderr.write(\"### Disabled test '%s', dependency not found\n\" % name)") ""))
             #t)))))
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page "http://wtforms.simplecodes.com/")
    (synopsis
     "Form validation and rendering library for Python web development")
    (description
     "WTForms is a flexible forms validation and rendering library
for Python web development.  It is very similar to the web form API
available in Django, but is a standalone package.")
    (license license:bsd-3)))

(define-public python2-wtforms
  (package-with-python2 python-wtforms))

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
    (propagated-inputs
     `(("python-markupsafe" ,python-markupsafe)))
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-nose" ,python-nose)))
    (home-page "http://www.makotemplates.org/")
    (synopsis "Templating language for Python")
    (description "Mako is a templating language for Python that compiles
templates into Python modules.")
    (license license:expat)))

(define-public python2-mako
  (package-with-python2 python-mako))

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
    (license license:zpl2.1)))

(define-public python2-waitress
  (package-with-python2 python-waitress))

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
    (arguments
     '(;; Wsgiproxy2's test suite requires Restkit, which does not yet fully
       ;; support Python 3:
       ;; https://github.com/benoitc/restkit/issues/140
       #:tests? #f))
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
    (license license:expat)))

(define-public python2-wsgiproxy2
 (package-with-python2 python-wsgiproxy2))

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
       (patches (search-patches "python-paste-remove-website-test.patch"
                                "python-paste-remove-timing-test.patch"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-nose" ,python-nose)))
    (propagated-inputs
     `(("python-six" ,python-six)))
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
     `(("python-paste" ,python-paste)
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
    (version "1.2.13")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "pyquery" version))
       (sha256
        (base32
         "0j9fsisip21qv4xljsg5dmni1pgpvwrjyyhhql0glydc4bs5rjgv"))))
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

(define-public python2-pyquery
  (package-with-python2 python-pyquery))

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
    (license license:expat)))

(define-public python2-webtest
  (package-with-python2 python-webtest))

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

(define-public python-kombu
  (package
    (name "python-kombu")
    (version "3.0.37")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "kombu" version))
       (sha256
        (base32
         "0l16chb314gpq2v7fh94a22c30lcv6w3ylmhsa60bldlcq6a0r70"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-nose" ,python-nose)))
    (propagated-inputs
     `(("python-anyjson" ,python-anyjson)
       ("python-amqp" ,python-amqp)
       ("python-redis" ,python-redis)))
    (home-page "http://kombu.readthedocs.org")
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
      (native-inputs `(("python2-unittest2" ,python2-unittest2)
                ,@(package-native-inputs kombu))))))

(define-public python-billiard
  (package
    (name "python-billiard")
    (version "3.3.0.23")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "billiard" version))
       (sha256
        (base32
         "02wxsc6bhqvzh8j6w758kvgqbnj14l796mvmrcms8fgfamd2lak9"))))
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
    (version "3.1.24")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "celery" version))
       (sha256
        (base32
         "0yh2prhdnx2dgkb67a5drj12hh2zvzx5f611p7mqqg01ydghif4r"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; These tests break with Python 3.5:
         ;; https://github.com/celery/celery/issues/2897#issuecomment-253066295
         (replace 'check
           (lambda _
             (zero?
               (system* "nosetests" "--exclude=^test_safe_to_remove.*")))))))
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
     `(("python-sphinx" ,python-sphinx)))
    (synopsis "Sphinx extension to include program output")
    (description "A Sphinx extension to literally insert the output of arbitrary
commands into documents, helping you to keep your command examples up to date.")
    (home-page "https://github.com/lunaryorn/sphinxcontrib-programoutput")
    (license license:bsd-2)))

(define-public python2-sphinxcontrib-programoutput
  (package-with-python2 python-sphinxcontrib-programoutput))

(define-public python-sphinx-repoze-autointerface
  (package
    (name "python-sphinx-repoze-autointerface")
    (version "0.8")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "repoze.sphinx.autointerface" version))
              (sha256
               (base32
                "08ycivzf7bh4a1zcyp31hbyqs1b2c9r26raa3vxjwwmbfqr3iw4f"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-sphinx" ,python-sphinx)
       ("python-zope-interface" ,python-zope-interface)))
    (synopsis "Auto-generate Sphinx API docs from Zope interfaces")
    (description "This package defines an extension for the Sphinx documentation
system.  The extension allows generation of API documentation by
introspection of @code{zope.interface} instances in code.")
    (home-page "https://github.com/repoze/repoze.sphinx.autointerface")
    (license license:repoze)))

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
    (license license:lgpl3+)))

(define-public python2-psycopg2
  (package-with-python2 python-psycopg2))

(define-public python-vobject
  (package
    (name "python-vobject")
    (version "0.9.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "vobject" version))
              (sha256
               (base32
                "1qfnwlx8qwkgr6nf5wvl6ff1r3kll53dh3z6nyp173nmlhhhqccb"))))
    (build-system python-build-system)
    (arguments
     '(;; The test suite relies on some non-portable Windows interfaces.
       #:tests? #f))
    (propagated-inputs
     `(("python-dateutil-2" ,python-dateutil-2)
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

(define-public python-flask
  (package
    (name "python-flask")
    (version "0.11.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "Flask" version))
              (sha256
               (base32
                "03kbfll4sj3v5z7r31c7bhfpi11r1np076d4p1k2kg4yzcmkywdl"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-itsdangerous" ,python-itsdangerous)
       ("python-jinja2" ,python-jinja2)
       ("python-click" ,python-click)
       ("python-werkzeug" ,python-werkzeug)))
    (home-page "https://github.com/mitsuhiko/flask/")
    (synopsis "Microframework based on Werkzeug, Jinja2 and good intentions")
    (description "Flask is a micro web framework based on the Werkzeug toolkit
and Jinja2 template engine.  It is called a micro framework because it does not
presume or force a developer to use a particular tool or library.")
    (license license:bsd-3)))

(define-public python2-flask
  (package-with-python2 python-flask))

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
    (license license:expat)))

(define-public python2-cookies
  (package-with-python2 python-cookies))

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
     `(("python-mock" ,python-mock)))
    (propagated-inputs
     `(("python-requests" ,python-requests)
       ("python-cookies" ,python-cookies)
       ("python-six" ,python-six)))
    (home-page "https://github.com/getsentry/responses")
    (synopsis "Utility for mocking out the `requests` Python library")
    (description "A utility library for mocking out the `requests` Python
library.")
    (license license:asl2.0)))

(define-public python2-responses
  (package-with-python2 python-responses))

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
    (home-page "http://bitbucket.org/mchaput/whoosh")
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
    (version "2.1.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pathlib2" version))
              (sha256
               (base32
                "0p050msg5c8d0kadv702jnfshaxrb0il765cpkgnhn6mq5hakcyy"))))
    (build-system python-build-system)
    ;; We only need the the Python 2 variant, since for Python 3 our minimum
    ;; version is 3.4 which already includes this package as part of the
    ;; standard library.
    (arguments
     `(#:python ,python-2))
    (native-inputs
     `(("python2-six" ,python2-six)))
    (home-page "http://pypi.python.org/pypi/pathlib2/")
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
           (lambda _ (zero? (system* "make" "-C" "test" "test")))))))
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
    (version "1.1.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pkgconfig" version))
        (sha256
          (base32
            "1pw0kmvc57sjmaxi6c54fqsnihqj6hvhc9y1vaz36axafzqam7bh"))))
    (build-system python-build-system)
    (native-inputs
      `(("python-nose" ,python-nose)))
    (inputs
      `(("pkg-config" ,pkg-config)))
    (arguments
      `(;; Tests fail with "ValueError: _type_ 'v' not supported" on Python 3,
        ;; and on Python 2 they need the dl module deprecated since Python 2.6.
        #:tests? #f
        ;; Hard-code the path to pkg-config.
        #:phases
        (modify-phases %standard-phases
          (add-before
           'build 'patch
           (lambda _
             (substitute* "pkgconfig/pkgconfig.py"
               (("cmd = 'pkg-config")
                (string-append "cmd = '" (which "pkg-config"))))
             #t)))))
    (home-page "http://github.com/matze/pkgconfig")
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
    (license license:asl2.0)
    (properties `((python2-variant . ,(delay python2-bz2file))))))

(define-public python2-bz2file
  (let ((base (package-with-python2
               (strip-python2-variant python-bz2file))))
    (package
      (inherit base)
      (arguments
       `(#:python ,python-2
         #:phases
         (modify-phases %standard-phases
           ;; 'python setup.py test' does not work as of 0.98.
           ;; There is only the one test file, so we run it directly.
           (replace 'check
                    (lambda _ (zero? (system* "python"
                                              "test_bz2file.py"))))))))))

(define-public python-future
  (package
    (name "python-future")
    (version "0.15.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "future" version))
       (sha256
        (base32
         "15wvcfzssc68xqnqi1dq4fhd0848hwi9jn42hxyvlqna40zijfrx"))))
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
    (version "1.1.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "cysignals" version ".tar.bz2"))
        (sha256
          (base32
            "14cbyd9znlz6cxy1s3g6v6dv5jj45hn27pywkidd9b1zanaysqc6"))))
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
    (version "0.10.3")
    (source
     (origin
      (method url-fetch)
      (uri (pypi-uri "rope" version))
      (sha256
        (base32
         "18k5znhpwvrfck3yp0jmhd5j8r0f0s8bk1zh5yhs2cfgmfhbwigb"))))
    (arguments
     ;; Rope is currently python-2 only.
     ;; https://github.com/python-rope/rope/issues/57
     `(#:python ,python-2))
    (build-system python-build-system)
    (native-inputs
     `(("python2-unittest2" ,python2-unittest2)))
    (home-page "https://github.com/python-rope/rope")
    (synopsis "Refactoring library for Python")
    (description "Rope is a refactoring library for Python.  It facilitates
the renaming, moving and extracting of attributes, functions, modules, fields
and parameters in Python 2 source code.  These refactorings can also be applied
to occurences in strings and comments.")
    (license license:gpl2)))

(define-public python-py3status
  (package
    (name "python-py3status")
    (version "3.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "py3status" version))
       (sha256
        (base32
         "0i283z1pivmir61z8kbiycigc94l61v33ygzkhczf1ifq7cppyds"))))
    (build-system python-build-system)
    (home-page "https://github.com/ultrabug/py3status")
    (synopsis "Extensible i3status wrapper written in Python")
    (description "py3status is an i3status wrapper which extends i3status
functionality in a modular way, allowing you to extend your panel with your
own code, responding to click events and updating clock every second.")
    (license license:bsd-3)))

(define-public python-tblib
  (package
    (name "python-tblib")
    (version "1.3.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "tblib" version))
              (sha256 (base32
                       "02iahfkfa927hb4jq2bak36ldihwapzacfiq5lyxg8llwn98a1yi"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             ;; Upstream runs tests after installation and the package itself
             ;; resides in a subdirectory. Extend PYTHONPATH so it will be
             ;; found.
             (setenv "PYTHONPATH"
                     (string-append (getcwd) "/build/lib:"
                                    (getenv "PYTHONPATH")))
             (zero? (system* "py.test" "-vv" "tests" "README.rst")))))))
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
@end itemize")
    (license license:bsd-3)))

(define-public python2-tblib
  (package-with-python2 python-tblib))

(define-public python-sqlparse
  (package
    (name "python-sqlparse")
    (version "0.1.19")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "sqlparse" version))
              (sha256
               (base32
                "1s2fvaxgh9kqzrd6iwy5h7i61ckn05plx9np13zby93z3hdbx5nq"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda* _
             ;; setup.py-integrated 2to3 only affects the build files, but
             ;; py.test is using the source files. So we need to convert them
             ;; manually.
             (when (zero? (system* "python3"))
               (system* "2to3" "--no-diff" "-wn" "sqlparse" "tests"))
             (zero? (system* "py.test")))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://github.com/andialbrecht/sqlparse")
    (synopsis "Non-validating SQL parser")
    (description "Sqlparse is a non-validating SQL parser for Python.  It
provides support for parsing, splitting and formatting SQL statements.")
    (license license:bsd-3)))

(define-public python2-sqlparse
  (package-with-python2 python-sqlparse))

(define-public python-greenlet
  (package
    (name "python-greenlet")
    (version "0.4.9")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "greenlet" version))
              (sha256
               (base32
                "04h0m54dyqg49vyarq26mry6kbivnpl47rnmmrk9qn8wpfxviybr"))))
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

(define-public python-gevent
  (package
    (name "python-gevent")
    (version "1.1.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "gevent" version))
              (sha256
               (base32
                "1smf3kvidpdiyi2c81alal74p2zm0clrm6xbyy6y1k9a3f2vkrbf"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  ;; unbunding libev and c-ares
                  (for-each delete-file-recursively '("libev" "c-ares"))
                  ;; fixing testsuite
                  (call-with-output-file "greentest/__init__.py" noop)
                  (substitute* "greentest/testrunner.py"
                    (("import util") "from . import util")
                    (("from util import log") "from .util import log"))))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-greenlet" ,python-greenlet)))
    (native-inputs
     `(("python-six" ,python-six)))
    (inputs
     `(("c-ares" ,c-ares)
       ("libev" ,libev)))
    (home-page "http://www.gevent.org/")
    (synopsis "Coroutine-based network library")
    (description
     "gevent is a coroutine-based Python networking library that uses greenlet
to provide a high-level synchronous API on top of the libev event loop.")
    (license license:expat)))

(define-public python2-gevent
  (package-with-python2 python-gevent))

(define-public python-twisted
  (package
    (name "python-twisted")
    (version "16.2.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "Twisted" version ".tar.bz2"))
              (sha256
               (base32
                "0ydxrp9myw1mvsz3qfzx5579y5llmqa82pxvqchgp5syczffi450"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-zope-interface" ,python-zope-interface)))
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
    (version "0.10.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "pika" version))
        (sha256
         (base32
          "0nb4h08di432lv7dy2v9kpwgk0w92f24sqc2hw2s9vwr5b8v8xvj"))))
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
    (version "3.8")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
               "https://pypi.python.org/packages/"
               "96/e0/430fcdb6b3ef1ae534d231397bee7e9304be14a47a267e82ebcb3323d0b5"
               "/ply-" version ".tar.gz"))
        (sha256
          (base32
            "1f70ipynmiy09k6px2j7v4w5cdrc21za3xs2k6f1bsvb0bzvvlg7"))))
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
    (version "0.7.5")
    (source (origin
             (method url-fetch)
             (uri (pypi-uri "tabulate" version))
             (sha256
              (base32
               "03l1r7ddd1a0j2snv1yd0hlnghjad3fg1an1jr8936ksv75slwch"))
             ;; Fix tests
             (modules '((guix build utils)))
             (snippet '(substitute* '("test/test_cli.py"
                                      "test/test_input.py"
                                      "test/test_output.py"
                                      "test/test_regression.py")
                         (("from common") "from nose.tools")))))
    (build-system python-build-system)
    (native-inputs
     `(;; For testing
       ("python-nose" ,python-nose)))
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
    (version "2.2.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "kazoo" version))
       (sha256
        (base32
         "10pb864if9qi2pq9lfb9m8f7z7ss6rml80gf1d9h64lap5crjnjj"))))
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
              (uri (string-append
                     "https://pypi.python.org/packages/8b/3e/"
                     "384eeff406b06315738b62483fd2126c6e4f544167116b17cc04ea7d2a59/"
                     "pykafka-" version ".tar.gz"))
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
  (version "0.1.6")
  (source
    (origin
      (method url-fetch)
      (uri (string-append
             "https://pypi.python.org/packages/"
             "c2/d1/7689293086a8d5320025080cde0e3155b94ae0a7496fb89a3fbaa92c354a/"
             "wcwidth-" version ".tar.gz"))
      (sha256
        (base32
          "02wjrpf001gjdjsaxxbzcwfg19crlk2dbddayrfc2v06f53yrcyw"))))
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
              (uri (string-append
                    "https://pypi.python.org/packages/source/j/jsonrpclib/"
                    "jsonrpclib-" version ".tar.gz"))
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
    (version "1.1.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "chai" version))
              (sha256
               (base32
                "016kf3irrclpkpvcm7q0gmkfibq7jgy30a9v73pp42bq9h9a32bl"))))
    (build-system python-build-system)
    (home-page "https://github.com/agoragames/chai")
    (synopsis "Mocking framework for Python")
    (description
     "Chai provides an api for mocking, stubbing and spying your python
objects, patterned after the Mocha library for Ruby.")
    (license license:bsd-3)))

(define-public python2-chai
  (package-with-python2 python-chai))

(define-public python-arrow
  (package
    (name "python-arrow")
    (version "0.8.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "arrow" version))
              (sha256
               (base32
                "1bz7hkdgpqcjs866y58z8jywpy7al0f4rxdr00bh2l5qddyw245j"))))
    (build-system python-build-system)
    (native-inputs
     `(;; For testing
       ("python-chai" ,python-chai)
       ("python-simplejson" ,python-simplejson)))
    (propagated-inputs
     `(("python-dateutil" ,python-dateutil-2)))
    (home-page "https://github.com/crsmithdev/arrow/")
    (synopsis "Dates and times for Python")
    (description
     "Arrow is a Python library to creating, manipulating, formatting and
converting dates, times, and timestamps.  It implements and updates the
datetime type.")
    (license license:asl2.0)))

(define-public python2-arrow
  (package-with-python2 python-arrow))

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
    (home-page "http://github.com/jpvanhal/inflection")
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
    (home-page "http://github.com/toastdriven/pylev")
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
    (version "0.4.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "cleo" version))
              (sha256
               (base32
                "1k2dcl6mqpn5bljyl6w42rqyd9mb3y9kh2mg7m2x3kfjwvg0rpva"))))
    (build-system python-build-system)
    (native-inputs
     `(;; For testing
       ("python-mock" ,python-mock)
       ("python-pytest" ,python-pytest)))
    (propagated-inputs
     `(("python-psutil" ,python-psutil)
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
    (version "1.2.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "lazy-object-proxy" version))
              (sha256
               (base32
                "0s22aqqkdscyh8sjspyyax7qa1aiz8p4midrnyf39717fhfczm6x"))))
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
    (version "1.0.1")
    (source
     (origin (method url-fetch)
             (uri (pypi-uri "email_validator" version))
             (sha256
              (base32
               "0mn8jg5h8ifl8w6a6m0hq8kbk0mzw9vm054qfamkn89b3npz52qw"))))
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

(define-public python-fake-factory
  (package
  (name "python-fake-factory")
  (version "0.7.2")
  (source (origin
            (method url-fetch)
            (uri (pypi-uri "fake-factory" version))
            (sha256
             (base32
              "0vs0dkmg0dlaxf8w6q2i3k0i03gmp56ablldv7ci9x3nbadkn71g"))))
  (build-system python-build-system)
  (native-inputs
   `(;; For testing
     ("python-email-validator" ,python-email-validator)
     ("python-mock" ,python-mock)
     ("python-ukpostcodeparser" ,python-ukpostcodeparser)))
  (propagated-inputs
   `(("python-dateutil" ,python-dateutil-2)
     ("python-six" ,python-six)))
  (home-page "https://github.com/joke2k/faker")
  (synopsis "Python package that generates fake data")
  (description
   "Faker is a Python package that generates fake data such as names,
addresses, and phone numbers.")
  (license license:expat)
  (properties `((python2-variant . ,(delay python2-fake-factory))))))

(define-public python2-fake-factory
  (let ((base (package-with-python2 (strip-python2-variant
                                     python-fake-factory))))
    (package
      (inherit base)
      (propagated-inputs
       `(("python2-ipaddress" ,python2-ipaddress)
         ,@(package-propagated-inputs base))))))

(define-public python-pyaml
  (package
    (name "python-pyaml")
    (version "15.8.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pyaml" version))
              (sha256
               (base32
                "1f5m28vkh4ksq3d80d8mmd2z8wxvc3mgy2pmrv2751dm2xgznm4w"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-pyyaml" ,python-pyyaml)))
    (home-page "https://github.com/mk-fg/pretty-yaml")
    (synopsis "YAML pretty-print library for Python")
    (description
     "pyaml is a PyYAML based python module to produce pretty and readable
YAML-serialized data.")
    (license (license:non-copyleft "http://www.wtfpl.net/txt/copying/"))))

(define-public python2-pyaml
  (package-with-python2 python-pyaml))

(define-public python-flexmock
  (package
    (name "python-flexmock")
    (version "0.10.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "flexmock" version))
              (sha256
               (base32
                "0arc6njvs6i9v9hgvzk5m50296g7zy5m9d7pyb43vdsdgxrci5gy"))))
    (build-system python-build-system)
    (home-page "https://flexmock.readthedocs.org")
    (synopsis "Testing library for Python")
    (description
     "flexmock is a testing library for Python that makes it easy to create
mocks, stubs and fakes.")
    (license license:bsd-3)))

(define-public python2-flexmock
  (package-with-python2 python-flexmock))

(define-public python-orator
  (package
    (name "python-orator")
    (version "0.8.2")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "orator" version))
              (sha256
               (base32
                "1li49irsqha17nrda4nsb48biyy0rarp9pphf0jpqwm5zr8hv569"))))
    (build-system python-build-system)
    (arguments '(#:tests? #f)) ; no tests
    (propagated-inputs
     `(("python-arrow" ,python-arrow)
       ("python-blinker" ,python-blinker)
       ("python-cleo" ,python-cleo)
       ("python-fake-factory" ,python-fake-factory)
       ("python-inflection" ,python-inflection)
       ("python-lazy-object-proxy" ,python-lazy-object-proxy)
       ("python-pyaml" ,python-pyaml)
       ("python-simplejson" ,python-simplejson)
       ("python-wrapt" ,python-wrapt)))
    (home-page "https://orator-orm.com/")
    (synopsis "ActiveRecord ORM for Python")
    (description
     "Orator provides a simple ActiveRecord-like Object Relational Mapping
implementation for Python.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-orator))))))

(define-public python2-orator
  (let ((base (package-with-python2 (strip-python2-variant python-orator))))
    (package
      (inherit base)
      (propagated-inputs
       `(("python2-ipaddress" ,python2-ipaddress)
         ,@(package-propagated-inputs base))))))

(define-public python-prompt-toolkit
 (package
  (name "python-prompt-toolkit")
  (version "1.0.7")
  (source
    (origin
      (method url-fetch)
      (uri (pypi-uri "prompt_toolkit" version ".tar.gz"))
      (sha256
        (base32
          "1vyjd0b7wciv55i19l44zy0adx8q7ss79lhy2r9d1rwz2y4822zg"))))
  (build-system python-build-system)
  (arguments
   '(#:tests? #f)) ; The test suite uses some Windows-specific data types.
  (propagated-inputs
   `(("python-wcwidth" ,python-wcwidth)
     ("python-six" ,python-six)
     ("python-pygments" ,python-pygments)))
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

(define-public python-jedi
  (package
    (name "python-jedi")
    (version "0.9.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "jedi" version))
        (sha256
          (base32
            "0c8x962ynpx001fdvp07m2q5jk4igkxbj3rmnydavphvlgxijk1v"))))
    (build-system python-build-system)
    (home-page "https://github.com/davidhalter/jedi")
    (synopsis
      "Autocompletion for Python that can be used for text editors")
    (description
      "Jedi is an autocompletion tool for Python that can be used for text editors.")
    (license license:expat)))

(define-public python2-jedi
  (package-with-python2 python-jedi))

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

(define-public python-requests-oauthlib
  (package
    (name "python-requests-oauthlib")
    (version "0.6.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "requests-oauthlib" version))
       (sha256
        (base32
         "0ykff67sjcl227c23g0rxzfx34rr5bf21kwv0z3zmgk0lfmch7hn"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; removes tests that require network access
         (add-before 'check 'pre-check
           (lambda _
             (delete-file "tests/test_core.py")
             #t)))))
    (native-inputs
     `(("python-requests-mock" ,python-requests-mock)
       ("python-mock" ,python-mock)))
    (propagated-inputs
     `(("python-oauthlib" ,python-oauthlib)
       ("python-requests" ,python-requests)))
    (home-page
     "https://github.com/requests/requests-oauthlib")
    (synopsis
     "OAuthlib authentication support for Requests")
    (description
     "Requests-OAuthlib uses the Python Requests and OAuthlib libraries to
provide an easy-to-use Python interface for building OAuth1 and OAuth2 clients.")
    (license license:isc)))

(define-public python2-requests-oauthlib
  (package-with-python2 python-requests-oauthlib))

(define-public python-stem
  (package
    (name "python-stem")
    (version "1.4.1b")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "stem" version ".tar.bz2"))
       (sha256
        (base32
         "09a3amp1y351nwz088ckiibbp666qi2lxwkyknavswfm400s0ns7"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (zero? (system* "./run_tests.py" "--unit")))))))
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-pep8" ,python-pep8)
       ("python-pyflakes" ,python-pyflakes)))
    (propagated-inputs
     `(("python-pycrypto" ,python-pycrypto)))
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
    (version "1.9.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "kivy" version))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0zk3g1j1z0lzcm9d0k1lprrs95zr8n8k5pdg3p5qlsn26jz4bg19"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f              ; Tests require many optional packages
       #:phases
       (modify-phases %standard-phases
         (replace 'build (lambda _ (zero? (system* "make" "force"))))
         (add-after 'patch-generated-file-shebangs 'set-sdl-paths
           (lambda* (#:key inputs #:allow-other-keys)
             (setenv "KIVY_SDL2_PATH"
                     (string-append (assoc-ref inputs "sdl-union")
                                    "/include/SDL2"))
             #t)))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
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
  (let ((commit "a988c5e7a47da56263ff39514264a3de516ef2fe")
        (revision "1"))
    (package (inherit python-kivy)
      (name "python-kivy-next")
      (version (string-append "1.9.1-" revision "."
                              (string-take commit 7)))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "https://github.com/kivy/kivy")
               (commit commit)))
         (file-name (string-append name "-" version "-checkout"))
         (sha256
          (base32
           "0jk92b4a8l7blkvkgkjihk171s0dfnq582cckff5srwc8kal5m0p")))))))

(define-public python2-kivy-next
  (package-with-python2 python-kivy-next))

(define-public python-binaryornot
  (package
    (name "python-binaryornot")
    (version "0.4.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "binaryornot" version))
              (sha256
               (base32
                "1j4f51dxic39mdwf6alj7gd769wy6mhk916v031wjali51xkh3xb"))))
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
    (version "3.3.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pymongo" version))
              (sha256
               (base32
                "07mra6w86wjqy4lx5fvimidjhhfzd562gfjn8grsnbv2q8pk0i9x"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-certifi" ,python-certifi)))
    (home-page "http://github.com/mongodb/mongo-python-driver")
    (synopsis "Python driver for MongoDB")
    (description "Python driver for MongoDB.")
    (license license:asl2.0)))

(define-public python2-pymongo
  (package-with-python2 python-pymongo))

(define-public python-sh
  (package
    (name "python-sh")
    (version "1.11")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "sh" version))
              (sha256
               (base32
                "192r0mpv6dmkysjzhc43ddffiwb5g7c76bgr1mb1z2xz9awbj3sr"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f)) ; no tests
    (home-page "https://github.com/amoffat/sh")
    (synopsis "Python subprocess interface")
    (description "Abstracts process invocation by providing a function
interface for programs.")
    (license license:expat)))

(define-public python2-sh
  (package-with-python2 python-sh))

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
    (native-inputs
     `(("python-pytest" ,python-pytest)))
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
        (method url-fetch)
        (uri (string-append
               "https://github.com/schematics/schematics/archive/v" version ".tar.gz"))
        (file-name (string-append name "-" version ".tar.gz"))
        (sha256
         (base32
          "19v1i69bf3bzarfxmbv0v6ivpcn758x3shvbiy9l2hy0lvqwnp6l"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-six" ,python-six)))
    (arguments
     `(#:tests? #f)) ; requires a bunch of not very nice packages with fixed
                     ; version requirements (eg python-coveralls)
    (home-page "https://github.com/schematics/schematics")
    (synopsis "Python Data Structures for Humans")
    (description "Python Data Structures for Humans.")
    (license license:bsd-3)))

(define-public python2-schematics
  (package-with-python2 python-schematics))

(define-public python-publicsuffix
  (package
    (name "python-publicsuffix")
    (version "1.1.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "publicsuffix" version))
              (sha256
               (base32
                "1adx520249z2cy7ykwjr1k190mn2888wqn9jf8qm27ly4qymjxxf"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f)) ; tests use the internet
    (home-page "https://www.tablix.org/~avian/git/publicsuffix.git")
    (synopsis "Get suffix for a domain name")
    (description "Get a public suffix for a domain name using the Public Suffix
List.")
    (license license:expat)))

(define-public python2-publicsuffix
  (package-with-python2 python-publicsuffix))

(define-public python-publicsuffix2
  (package
    (name "python-publicsuffix2")
    (version "2.20160621")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "publicsuffix2" version ".tar.bz2"))
       (sha256
        (base32
         "06lx603gdwad5hc3hmn763ngq0rq9bzz1ni3ga72nzk5n872arkd"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f)) ; The test suite requires network access.
    (home-page "https://github.com/pombredanne/python-publicsuffix2")
    (synopsis "Get a public suffix for a domain name using the Public Suffix List")
    (description "Get a public suffix for a domain name using the Public Suffix
List.  Forked from and using the same API as the publicsuffix package.")
    (license (list license:expat license:mpl2.0))))

(define-public python2-publicsuffix2
  (package-with-python2 python-publicsuffix2))

(define-public python-url
  (package
    (name "python-url")
    (version "0.2.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "url" version))
              (sha256
               (base32
                "0v879yadcz9qxfl41ak6wkga1kimp9cflla9ddz03hjjvgkqy5ki"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-publicsuffix" ,python-publicsuffix)))
    (native-inputs
     `(("python-coverage" ,python-coverage)
       ("python-nose" ,python-nose)))
    (arguments
     `(#:tests? #f)) ; FIXME: tests fail with "ImportError: No module named 'tests'"
    (home-page "http://github.com/seomoz/url-py")
    (synopsis "URL Parsing")
    (description "Library for parsing urls.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-url))))))

(define-public python2-url
  (let ((base (package-with-python2 (strip-python2-variant python-url))))
    (package (inherit base)
      (propagated-inputs
       `(("python2-publicsuffix" ,python2-publicsuffix))))))

(define-public python-freezegun
  (package
    (name "python-freezegun")
    (version "0.3.7")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "freezegun" version))
        (sha256
          (base32
            "14l19x06v5jkq4rdwbmfyw4x9lrjb2300afrk21r1ash7y1y9a0w"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-mock" ,python-mock)
       ("python-nose" ,python-nose)
       ("python-coverage" ,python-coverage)))
    (propagated-inputs
     `(("python-six" ,python-six)
       ("python-dateutil-2" ,python-dateutil-2)))
    (arguments
     `(#:phases (modify-phases %standard-phases
        ;; The tests are normally executed via `make test`, but the PyPi
        ;; package does not include the Makefile.
        (replace 'check
          (lambda _
            (zero? (system* "nosetests" "./tests/")))))))
    (home-page "https://github.com/spulec/freezegun")
    (synopsis "Test utility for mocking the datetime module")
    (description
      "FreezeGun is a library that allows your python tests to travel through
time by mocking the datetime module.")
    (license license:asl2.0)))

(define-public python2-freezegun
  (package-with-python2 python-freezegun))


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
             (every (lambda (test-file)
                      (zero? (system* "python" test-file)))
                    (find-files "tests" "^test.*\\.py$")))))))
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

(define-public python-cachecontrol
  (package
    (name "python-cachecontrol")
    (version "0.11.6")
    (source
     (origin
       (method url-fetch)
       ;; Pypi does not have tests.
       (uri (string-append
             "https://github.com/ionrock/cachecontrol/archive/v"
             version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0yj60d0f69a2l8p7y86k4zhzzm6rnxpq74sfl240pry9l0lfw2vw"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             ;; Drop test that requires internet access.
             (delete-file "tests/test_regressions.py")
             (setenv "PYTHONPATH"
                     (string-append (getcwd) "/build/lib:"
                                    (getenv "PYTHONPATH")))
             (zero? (system* "py.test" "-vv")))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-redis" ,python-redis)
       ("python-webtest" ,python-webtest)
       ("python-mock" ,python-mock)))
    (propagated-inputs
     `(("python-requests" ,python-requests)
       ("python-lockfile" ,python-lockfile)))
    (home-page "https://github.com/ionrock/cachecontrol")
    (synopsis "The httplib2 caching algorithms for use with requests")
    (description "CacheControl is a port of the caching algorithms in
@code{httplib2} for use with @code{requests} session objects.")
    (license license:asl2.0)))

(define-public python2-cachecontrol
  (package-with-python2 python-cachecontrol))

(define-public python-lit
  (package
    (name "python-lit")
    (version "0.5.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "lit" version))
        (sha256
         (base32
          "135m2b9cwih85g66rjggavck328z7lj37srgpq3jxszbg0g2b91y"))))
    (build-system python-build-system)
    (home-page "http://llvm.org/")
    (synopsis "LLVM Software Testing Tool")
    (description "@code{lit} is a portable tool for executing LLVM and Clang
style test suites, summarizing their results, and providing indication of
failures.")
    (license license:ncsa)))

(define-public python2-lit
  (package-with-python2 python-lit))

(define-public python-pytest-pep8
  (package
    (name "python-pytest-pep8")
    (version "1.0.6")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pytest-pep8" version))
              (sha256
               (base32
                "06032agzhw1i9d9qlhfblnl3dw5hcyxhagn7b120zhrszbjzfbh3"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f)) ; Fails with recent pytest and pep8. See upstream issues #8 and #12.
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (propagated-inputs
     `(("python-pep8" ,python-pep8)))
    (home-page "https://bitbucket.org/pytest-dev/pytest-pep8")
    (synopsis "Py.test plugin to check PEP8 requirements")
    (description "Pytest plugin for checking PEP8 compliance.")
    (license license:expat)))

(define-public python2-pytest-pep8
  (package-with-python2 python-pytest-pep8))

(define-public python-pytest-flakes
  (package
    (name "python-pytest-flakes")
    (version "1.0.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pytest-flakes" version))
              (sha256
               (base32
                "0flag3n33kbhyjrhzmq990rvg4yb8hhhl0i48q9hw0ll89jp28lw"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (delete 'check)
         (add-after 'install 'check
           (lambda* (#:key outputs inputs #:allow-other-keys)
             ;; It's easier to run tests after install.
             ;; Make installed package available for running the tests
             (add-installed-pythonpath inputs outputs)
             (zero? (system* "py.test" "-vv")))))))
    (native-inputs
     `(("python-coverage" ,python-coverage)
       ("python-pytest" ,python-pytest)
       ("python-pytest-cache" ,python-pytest-cache)
       ("python-pytest-pep8" ,python-pytest-pep8)))
    (propagated-inputs
     `(("python-pyflakes" ,python-pyflakes)))
    (home-page "https://github.com/fschulze/pytest-flakes")
    (synopsis "Py.test plugin to check source code with pyflakes")
    (description "Pytest plugin for checking Python source code with pyflakes.")
    (license license:expat)))

(define-public python2-pytest-flakes
  (package-with-python2 python-pytest-flakes))

(define-public python-natsort
  (package
    (name "python-natsort")
    (version "5.0.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "natsort" version))
              (sha256
               (base32
                "1abld5p4a6n5zjnyw5mi2pv37gqalcybv2brjr2y6l9l2p8v9mja"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'set-cachedir
           ;; Tests require write access to $HOME by default
           (lambda _ (setenv "PYTHON_EGG_CACHE" "/tmp") #t)))))
    (native-inputs
     `(("python-hypothesis" ,python-hypothesis)
       ("python-pytest-cache" ,python-pytest-cache)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-pytest-flakes" ,python-pytest-flakes)
       ("python-pytest-pep8" ,python-pytest-pep8)))
    (propagated-inputs ; TODO: Add python-fastnumbers.
     `(("python-pyicu" ,python-pyicu)))
    (home-page "https://github.com/SethMMorton/natsort")
    (synopsis "Natural sorting for python and shell")
    (description
     "Natsort lets you apply natural sorting on lists instead of
lexicographical.  If you use the built-in @code{sorted} method in python
on a list such as @code{['a20', 'a9', 'a1', 'a4', 'a10']}, it would be
returned as @code{['a1', 'a10', 'a20', 'a4', 'a9']}.  Natsort provides a
function @code{natsorted} that identifies numbers and sorts them separately
from strings.  It can also sort version numbers, real numbers, mixed types
and more, and comes with a shell command @command{natsort} that exposes this
functionality in the command line.")
    (license license:expat)
    (properties `((python2-variant . ,(delay python2-natsort))))))

(define-public python2-natsort
  (let ((base (package-with-python2 (strip-python2-variant python-natsort))))
    (package (inherit base)
             (native-inputs
              `(("python2-pathlib" ,python2-pathlib)
                ("python2-mock" ,python2-mock)
                ("python2-enum34" ,python2-enum34)
                ,@(package-native-inputs base))))))

(define-public python-glances
  (package
  (name "python-glances")
  (version "2.7.1")
  (source
    (origin
      (method url-fetch)
      (uri (pypi-uri "Glances" version))
      (sha256
        (base32
          "11jbq40g8alsbirnd4kiagznqg270247i0m8qhi48ldf2i5xppxg"))))
  (build-system python-build-system)
  (propagated-inputs
   `(("python-psutil" ,python-psutil)))
  (home-page
    "https://github.com/nicolargo/glances")
  (synopsis
    "A cross-platform curses-based monitoring tool")
  (description
    "Glances is a curses-based monitoring tool for a wide variety of platforms.
Glances uses the PsUtil library to get information from your system. It monitors
CPU, load, memory, network bandwidth, disk I/O, disk use, and more.")
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
    (version "0.4.4")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "graphql-relay" version))
        (sha256
         (base32
          "04wr9ayshxjjdcg2v21c7ffbz36kif1wjl3604fqd3qignb3fbxi"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
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
    (native-inputs
     `(("python-django-filter" ,python-django-filter)
       ("python-mock" ,python-mock)
       ("python-psycopg2" ,python-psycopg2)
       ("python-pytest-django" ,python-pytest-django)
       ("python-sqlalchemy-utils" ,python-sqlalchemy-utils)))
    (propagated-inputs
     `(("python-graphql-core" ,python-graphql-core)
       ("python-graphql-relay" ,python-graphql-relay)
       ("python-iso8601" ,python-iso8601)
       ("python-promise" ,python-promise)
       ("python-six" ,python-six)))
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

(define-public python-betamax
  (package
    (name "python-betamax")
    (version "0.8.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "betamax" version))
        (sha256
         (base32
          "18f8v5gng3j773jlbbzx4rg1i4y2zw3m2l1zpmbvp8bh5a2q1i42"))))
    (build-system python-build-system)
    (arguments
     '(;; Many tests fail because they require networking.
       #:tests? #f))
    (propagated-inputs
     `(("python-requests" ,python-requests)))
    (home-page "https://github.com/sigmavirus24/betamax")
    (synopsis "Record HTTP interactions with python-requests")
    (description "Betamax will record your test suite's HTTP interactions and
replay them during future tests.  It is designed to work with python-requests.")
    (license license:expat)))

(define-public python2-betamax
  (package-with-python2 python-betamax))

(define-public python-s3transfer
  (package
    (name "python-s3transfer")
    (version "0.1.8")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "s3transfer" version))
              (sha256
               (base32
                "1jivjkp3xqif9gzr5fiq28jsskmh50vzzd7ldsb4rbyiw1iyv3hy"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             ;; 7 of the 'integration' tests require network access or login
             ;; credentials.
             (zero? (system* "nosetests" "--exclude=integration")))))))
    (native-inputs
     `(("python-docutils" ,python-docutils)
       ("python-mock" ,python-mock)
       ("python-nose" ,python-nose)))
    (propagated-inputs
     `(("python-botocore" ,python-botocore)))
    (synopsis "Amazon S3 Transfer Manager")
    (description "S3transfer is a Python library for managing Amazon S3
transfers.")
    (home-page "https://github.com/boto/s3transfer")
    (license license:asl2.0)
    (properties `((python2-variant . ,(delay python2-s3transfer))))))

(define-public python2-s3transfer
  (let ((base (package-with-python2 (strip-python2-variant python-s3transfer))))
    (package
      (inherit base)
      (native-inputs
       `(("python2-futures" ,python2-futures)
         ,@(package-native-inputs base))))))

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
             (zero? (system* "make" "check")))))))
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
             (zero? (system* "py.test" "-vv" )))))))
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

(define-public python-aniso8601
  (package
    (name "python-aniso8601")
    (version "1.1.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "aniso8601" version))
        (sha256
          (base32
            "1k5mjg9iqbjfslb5prrsfz7dhlvi6s35p1jxq8dm87w1b7dn5i2g"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-dateutil-2" ,python-dateutil-2)))
    (home-page
      "https://bitbucket.org/nielsenb/aniso8601")
    (synopsis
      "Python library for parsing ISO 8601 strings")
    (description
      "This package contains a library for parsing ISO 8601 datetime strings.")
    (license license:bsd-3)))

(define-public python-flask-restful
  (package
    (name "python-flask-restful")
    (version "0.3.5")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "Flask-RESTful" version))
        (sha256
          (base32
            "0hjcmdb56b7z4bkw848lxfkyrpnkwzmqn2dgnlv12mwvjpzsxr6c"))))
    (build-system python-build-system)
    (propagated-inputs
      `(("python-aniso8601" ,python-aniso8601)
        ("python-flask" ,python-flask)
        ("python-pycrypto" ,python-pycrypto)
        ("python-pytz" ,python-pytz)))
    (native-inputs
      `(;; Optional dependency of Flask. Tests need it.
        ("python-blinker" ,python-blinker)
        ("python-mock" ,python-mock) ; For tests
        ("python-nose" ,python-nose) ; For tests
        ("python-sphinx" ,python-sphinx)))
    (home-page
      "https://www.github.com/flask-restful/flask-restful/")
    (synopsis
      "Flask module for creating REST APIs")
    (description
      "This package contains a Flask module for creating REST APIs.")
    (license license:bsd-3)))

(define-public python-flask-basicauth
  (package
    (name "python-flask-basicauth")
    (version "0.2.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "Flask-BasicAuth" version))
        (sha256
          (base32
            "1zq1spkjr4sjdnalpp8wl242kdqyk6fhbnhr8hi4r4f0km4bspnz"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-flask" ,python-flask)))
    (home-page
      "https://github.com/jpvanhal/flask-basicauth")
    (synopsis
      "HTTP basic access authentication for Flask")
    (description
      "This package provides HTTP basic access authentication for Flask.")
    (license license:bsd-3)))

(define-public python-flask-sqlalchemy
  (package
    (name "python-flask-sqlalchemy")
    (version "2.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "Flask-SQLAlchemy" version))
        (sha256
          (base32
            "1i9ps5d5snih9xlqhrvmi3qfiygkmqzxh92n25kj4pf89kj4s965"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-flask" ,python-flask)
       ("python-sqlalchemy" ,python-sqlalchemy)))
    (home-page
      "http://github.com/mitsuhiko/flask-sqlalchemy")
    (synopsis
      "Module adding SQLAlchemy support to your Flask application")
    (description
      "This package adds SQLAlchemy support to your Flask application.")
    (license license:bsd-3)))

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
    (version "0.7.1")
    (source
      (origin
      (method url-fetch)
      (uri (pypi-uri "imagesize" version))
      (sha256
        (base32
          "0qk07k0z4241lkzzjji7z4da04pcvg7bfc4xz1934zlqhwmwdcha"))))
    (build-system python-build-system)
    (arguments
     '(;; Test files are not distributed on PyPi:
       ;; https://github.com/shibukawa/imagesize_py/issues/7
       #:tests? #f))
    (home-page "https://github.com/shibukawa/imagesize_py")
    (synopsis "Gets image size of files in variaous formats in Python")
    (description
      "This package allows determination of image size from
PNG, JPEG, JPEG2000 and GIF files in pure Python.")
    (license license:expat)))

(define-public python2-imagesize
 (package-with-python2 python-imagesize))

(define-public python-axolotl-curve25519
  (package
    (name "python-axolotl-curve25519")
    (version "0.1")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "git://github.com/tgalal/python-axolotl-curve25519")
             (commit "e4a9c4de0eae27223200579c58d1f8f6d20637e2")))
       (file-name (string-append name "-" version "-checkout"))
       (sha256
        (base32
         "0agap5q0hmvf6cwzjqc05kw53pjgf6942pcivpazksmg1vk400ra"))))
    (build-system python-build-system)
    (arguments
     `(;; Prevent creation of the egg. This works around
       ;; https://debbugs.gnu.org/cgi/bugreport.cgi?bug=20765
       #:configure-flags '("--root=/")))
    (home-page "https://github.com/tgalal/python-axolotl-curve25519")
    (synopsis "Python wrapper for curve25519 library")
    (description "This is a python wrapper for the curve25519 library
with ed25519 signatures.  The C code was pulled from
libaxolotl-android.  At the moment this wrapper is meant for use by
python-axolotl.")
    (license (list license:gpl3    ; Most files
                   license:bsd-3)))) ; curve/curve25519-donna.c

(define-public python2-axolotl-curve25519
  (package-with-python2 python-axolotl-curve25519))

(define-public python-axolotl
  (package
    (name "python-axolotl")
    (version "0.1.35")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/tgalal/python-axolotl/archive/"
             version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32 "1z8d89p7v40p4bwywjm9h4z28fdvra79ddw06azlkrfjbl7dxmz8"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; Don't install tests
         (add-before 'install 'remove-tests
           (lambda _
             (for-each delete-file-recursively
                       '("axolotl/tests" "build/lib/axolotl/tests"))
             #t)))
       ;; Prevent creation of the egg. This works around
       ;; https://debbugs.gnu.org/cgi/bugreport.cgi?bug=20765
       #:configure-flags '("--root=/")))
    (propagated-inputs
     `(("python-axolotl-curve25519" ,python-axolotl-curve25519)
       ("python-dateutil" ,python-dateutil)
       ("python-protobuf" ,python-protobuf)
       ("python-pycrypto" ,python-pycrypto)))
    (home-page "https://github.com/tgalal/python-axolotl")
    (synopsis "Python port of libaxolotl-android")
    (description "This is a python port of libaxolotl-android.  This
is a ratcheting forward secrecy protocol that works in synchronous and
asynchronous messaging environments.")
    (license license:gpl3)))

(define-public python2-axolotl
  (package-with-python2 python-axolotl))

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
    (home-page "http://github.com/gfxmonk/termstyle")
    (synopsis "Console text coloring for Python")
    (description "This package provides console text coloring for Python.")
    (license license:bsd-3)))

(define-public python-rednose
  (package
    (name "python-rednose")
    (version "1.2.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "rednose" version))
        (sha256
          (base32
            "0b0bsna217lr1nykyhl5fgjly15zhdvqd4prg4wy1zrgfv7al6m0"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-deps
           (lambda _
             ;; See <https://github.com/JBKahn/rednose/issues/12>
             (substitute* "setup.py"
               (("python-termstyle") "termstyle"))
             #t)))))
    (propagated-inputs
     `(("python-colorama" ,python-colorama)
       ("python-termstyle" ,python-termstyle)))
    (native-inputs
     `(("python-six" ,python-six)
       ("python-nose" ,python-nose)))
    (home-page "https://github.com/JBKahn/rednose")
    (synopsis "Colored output for Python nosetests")
    (description "This package provides colored output for the
@command{nosetests} command of the Python Nose unit test framework.")
    (license license:bsd-3)))

(define-public python-flask-restplus
  (package
    (name "python-flask-restplus")
    (version "0.9.2")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "flask-restplus" version))
        (sha256
          (base32
            "11his6ii5brpkhld0d5bwzjjw4q3vmplpd6fmgzjrvvklsbk0cf4"))))
    (build-system python-build-system)
    (propagated-inputs
      `(("python-aniso8601" ,python-aniso8601)
        ("python-flask" ,python-flask)
        ("python-jsonschema" ,python-jsonschema)
        ("python-pytz" ,python-pytz)
        ("python-six" ,python-six)))
    (native-inputs
     `(("python-tzlocal" ,python-tzlocal)
       ("python-blinker" ,python-blinker)
       ("python-nose" ,python-nose)
       ("python-rednose" ,python-rednose)))
    (home-page "https://github.com/noirbizarre/flask-restplus")
    (synopsis "Framework for documented API development with Flask")
    (description "This package provides a framework for API development with
the Flask web framework in Python.  It is similar to package
@code{python-flask-restful} but supports the @code{python-swagger}
documentation builder.")
    (license license:expat)))

(define-public python-sadisplay
  (package
    (name "python-sadisplay")
    (version "0.4.6")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "sadisplay" version))
      (sha256
        (base32
          "0zqad2fl7q26p090qmqgmxbm6iwgf9zij1w8da1g3wdgjj72ql05"))))
    (build-system python-build-system)
    (propagated-inputs
      `(("python-sqlalchemy" ,python-sqlalchemy)))
    (native-inputs
      `(("python-nose" ,python-nose)))
    (home-page "https://bitbucket.org/estin/sadisplay")
    (synopsis "SQLAlchemy schema displayer")
    (description "This package provides a program to build Entity
Relationship diagrams from a SQLAlchemy model (or directly from the
database).")
    (license license:bsd-3)))

(define-public python2-sadisplay
  (package-with-python2 python-sadisplay))

(define-public python-flask-restful-swagger
  (package
    (name "python-flask-restful-swagger")
    (version "0.19")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "flask-restful-swagger" version))
       (sha256
        (base32
         "16msl8hd5xjmj833bpy264v98cpl5hkw5bgl5gf5vgndxbv3rm6v"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-flask-restful" ,python-flask-restful)))
    (home-page "https://github.com/rantav/flask-restful-swagger")
    (synopsis "Extract Swagger specs from Flask-Restful projects")
    (description "This package lets you extract Swagger API documentation
specs from your Flask-Restful projects.")
    (license license:expat)))

(define-public python2-flask-restful-swagger
  (package-with-python2 python-flask-restful-swagger))

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
    (version "0.1.1")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "xopen" version))
        (sha256
          (base32
           "1wx6mylzcsyhjl19ycb83qq6iqpmr927lz62njfsar6ldsj0qcni"))
        (file-name (string-append name "-" version ".tar.gz"))))
    (build-system python-build-system)
    (home-page "https://github.com/marcelm/xopen/")
    (synopsis "Open compressed files transparently")
    (description "This module provides an @code{xopen} function that works like
Python's built-in @code{open} function, but can also deal with compressed files.
Supported compression formats are gzip, bzip2 and, xz, and are automatically
recognized by their file extensions.  The focus is on being as efficient as
possible on all supported Python versions.")
    (license license:expat)))

(define-public python2-xopen
  (package-with-python2 python-xopen))
