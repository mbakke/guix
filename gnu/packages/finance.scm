;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015, 2016 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Alex Griffin <a@ajgrf.com>
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

(define-module (gnu packages finance)
 #:use-module ((guix licenses) #:prefix license:)
 #:use-module (guix packages)
 #:use-module (guix download)
 #:use-module (guix build utils)
 #:use-module (guix build-system gnu)
 #:use-module (guix build-system cmake)
 #:use-module (gnu packages base)
 #:use-module (gnu packages boost)
 #:use-module (gnu packages databases)
 #:use-module (gnu packages emacs)
 #:use-module (gnu packages groff)
 #:use-module (gnu packages libedit)
 #:use-module (gnu packages libevent)
 #:use-module (gnu packages linux)
 #:use-module (gnu packages multiprecision)
 #:use-module (gnu packages pkg-config)
 #:use-module (gnu packages protobuf)
 #:use-module (gnu packages python)
 #:use-module (gnu packages qt)
 #:use-module (gnu packages texinfo)
 #:use-module (gnu packages textutils)
 #:use-module (gnu packages tls)
 #:use-module (gnu packages upnp))

(define-public bitcoin-core
  (package
    (name "bitcoin-core")
    (version "0.12.1")
    (source (origin
             (method url-fetch)
             (uri
              (string-append "https://bitcoin.org/bin/bitcoin-core-"
                             version "/bitcoin-" version ".tar.gz"))
             (sha256
              (base32
               "16g1cnasy24275kxrs0cg48nbx1dk54xvxm1pdsvk7y30mn3pz08"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python" ,python-2) ; for the tests
       ("util-linux" ,util-linux))) ; provides the hexdump command for tests
    (inputs
     `(("bdb" ,bdb-5.3) ; with 6.2.23, there is an error: ambiguous overload
       ("boost" ,boost)
       ("libevent" ,libevent)
       ("miniupnpc" ,miniupnpc)
       ("openssl" ,openssl)
       ("protobuf" ,protobuf)
       ("qt" ,qt)))
    (arguments
     `(#:configure-flags
        (list
          ;; We use a bdb version newer than 4.8.
          "--with-incompatible-bdb"
          ;; Boost is not found unless specified manually.
          (string-append "--with-boost="
                         (assoc-ref %build-inputs "boost")))
       #:phases
        (modify-phases %standard-phases
          (add-before 'check 'set-home
           (lambda _
            (setenv "HOME" (getenv "TMPDIR"))))))) ; Tests write to $HOME.
    (home-page "https://bitcoin.org/en/")
    (synopsis "Bitcoin peer-to-peer client")
    (description
     "Bitcoin is a digital currency that enables instant payments to anyone
anywhere in the world.  It uses peer-to-peer technology to operate without
central authority: managing transactions and issuing money are carried out
collectively by the network.  Bitcoin Core is the reference implementation
of the bitcoin protocol.  This package provides the Bitcoin Core command
line client and a client based on Qt.")
    (license license:expat)))

(define-public ledger
  (package
    (name "ledger")
    (version "3.1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/ledger/ledger/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "12jlv3gsjhrja25q9hrwh73cdacd2l3c2yyn8qnijav9mdhnbw4h"))))
    (build-system cmake-build-system)
    (arguments
     `(#:modules ((guix build cmake-build-system)
                  (guix build utils)
                  (guix build emacs-utils))
       #:imported-modules (,@%cmake-build-system-modules
                           (guix build emacs-utils))
       #:configure-flags
       `("-DBUILD_DOCS:BOOL=ON"
         "-DBUILD_WEB_DOCS:BOOL=ON"
         "-DBUILD_EMACSLISP:BOOL=ON"
         "-DUSE_PYTHON:BOOL=ON"
         "-DCMAKE_INSTALL_LIBDIR:PATH=lib"
         ,(string-append "-DUTFCPP_INCLUDE_DIR:PATH="
                         (assoc-ref %build-inputs "utfcpp")
                         "/include"))
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'install-examples
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((examples (string-append (assoc-ref outputs "out")
                                            "/share/doc/ledger/examples")))
               (install-file "test/input/sample.dat" examples)
               (install-file "test/input/demo.ledger" examples))
             #t))
         (add-after 'build 'build-doc
           (lambda _ (zero? (system* "make" "doc"))))
         (add-before 'check 'check-setup
           ;; One test fails if it can't set the timezone.
           (lambda* (#:key inputs #:allow-other-keys)
             (setenv "TZDIR"
                     (string-append (assoc-ref inputs "tzdata")
                                    "/share/zoneinfo"))
             #t))
         (add-after 'install 'relocate-elisp
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((site-dir (string-append (assoc-ref outputs "out")
                                             "/share/emacs/site-lisp"))
                    (guix-dir (string-append site-dir "/guix.d"))
                    (orig-dir (string-append site-dir "/ledger-mode"))
                    (dest-dir (string-append guix-dir "/ledger-mode")))
               (mkdir-p guix-dir)
               (rename-file orig-dir dest-dir)
               (emacs-generate-autoloads ,name dest-dir))
             #t)))))
    (inputs
     `(("boost" ,boost)
       ("gmp" ,gmp)
       ("libedit" ,libedit)
       ("mpfr" ,mpfr)
       ("python" ,python-2)
       ("tzdata" ,tzdata)
       ("utfcpp" ,utfcpp)))
    (native-inputs
     `(("emacs" ,emacs-minimal)
       ("groff" ,groff)
       ("texinfo" ,texinfo)))
    (home-page "http://ledger-cli.org/")
    (synopsis "Command-line double-entry accounting program")
    (description
     "Ledger is a powerful, double-entry accounting system that is
accessed from the UNIX command-line.  This may put off some users, since
there is no flashy UI, but for those who want unparalleled reporting
access to their data there are few alternatives.

Ledger uses text files for input.  It reads the files and generates
reports; there is no other database or stored state.  To use Ledger,
you create a file of your account names and transactions, run from the
command line with some options to specify input and requested reports, and
get output.  The output is generally plain text, though you could generate
a graph or html instead.  Ledger is simple in concept, surprisingly rich
in ability, and easy to use.")
    ;; There are some extra licenses in files which do not presently get
    ;; installed when you build this package.  Different versions of the GPL
    ;; are used in the contrib and python subdirectories.  The bundled version
    ;; of utfcpp is under the Boost 1.0 license. Also the file
    ;; `tools/update_copyright_year` has an Expat license.
    (license (list license:bsd-3
                   license:asl2.0     ; src/strptime.cc
                   (license:non-copyleft
                    "file://src/wcwidth.cc"
                    "See src/wcwidth.cc in the distribution.")
                   license:gpl2+))))  ; lisp/*
