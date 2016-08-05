;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 David Thompson <davet@gnu.org>
;;; Copyright © 2015 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
;;; Copyright © 2016 Lukas Gradl <lgradl@openmailbox>
;;; Copyright © 2016 Tobias Geerinckx-Rice <me@tobias.gr>
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

(define-module (gnu packages crypto)
  #:use-module (gnu packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages boost)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages libbsd)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages nettle)
  #:use-module (gnu packages password-utils)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages serialization)
  #:use-module (gnu packages tls)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu))

(define-public libsodium
  (package
    (name "libsodium")
    (version "1.0.10")
    (source (origin
            (method url-fetch)
            (uri (list (string-append
                        "http://download.libsodium.org/libsodium/"
                        "releases/libsodium-" version ".tar.gz")
                       (string-append
                        "https://download.libsodium.org/libsodium/"
                        "releases/old/libsodium-" version ".tar.gz")))
            (sha256
             (base32
              "1gn45g956lyz8l6iq187yc6l627vyivyp8qc5dkr6dnhdnlqddvi"))))
    (build-system gnu-build-system)
    (synopsis "Portable NaCl-based crypto library")
    (description
     "Sodium is a new easy-to-use high-speed software library for network
communication, encryption, decryption, signatures, etc.")
    (license license:isc)
    (home-page "http://libsodium.org")))

(define-public signify
  (package
    (name "signify")
    (version "18")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/aperezdc/signify/"
                                  "archive/v" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "00lbjiy0gv1b1fvrd6ni4qah96ah4qf6aig05vd2hji4vs00jgwg"))))
    (build-system gnu-build-system)
    ;; TODO Build with libwaive (described in README.md), to implement something
    ;; like OpenBSD's pledge().
    (arguments
     `(#:tests? #f ; no test suite
       #:make-flags
       (list "CC=gcc"
             (string-append "PREFIX=" (assoc-ref %outputs "out")))
       #:phases
       (modify-phases %standard-phases
         (delete 'configure))))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("libbsd" ,libbsd)))
    (synopsis "Create and verify cryptographic signatures")
    (description "The signify utility creates and verifies cryptographic
signatures using the elliptic curve Ed25519.  This is a Linux port of the
OpenBSD tool of the same name.")
    (home-page "https://github.com/aperezdc/signify")
    ;; This package includes third-party code that was originally released under
    ;; various non-copyleft licenses. See the source files for clarification.
    (license (list license:bsd-3 license:bsd-4 license:expat license:isc
                   license:public-domain (license:non-copyleft
                                          "file://base64.c"
                                          "See base64.c in the distribution for
                                           the license from IBM.")))))


(define-public opendht
  (package
    (name "opendht")
    (version "0.6.1")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append
         "https://github.com/savoirfairelinux/" name
         "/archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (modules '((guix build utils)))
       (snippet
        '(begin
           (delete-file-recursively "src/argon2")
           (substitute* "src/Makefile.am"
             (("./argon2/libargon2.la") "")
             (("SUBDIRS = argon2") ""))
           (substitute* "src/crypto.cpp"
             (("argon2/argon2.h") "argon2.h"))
           (substitute* "configure.ac"
             (("src/argon2/Makefile") ""))))
       (sha256
        (base32
         "09yvkmbqbym3b5md4n96qc1s9sf2n8ji404hagih45rmsj49599x"))))
    (build-system gnu-build-system)
    (inputs
     `(("gnutls" ,gnutls)
       ("nettle" ,nettle)
       ("msgpack" ,msgpack)
       ("readline" ,readline)
       ("argon2" ,argon2)))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("pkg-config" ,pkg-config)
       ("automake" ,automake)
       ("libtool" ,libtool)))
    (arguments
     `(#:configure-flags '("--disable-tools" "--disable-python")
       #:phases (modify-phases %standard-phases
                  (add-before 'configure 'autoconf
                    (lambda _
                      (zero? (system* "autoreconf" "-vfi")))))))
    (home-page "https://github.com/savoirfairelinux/opendht/")
    (synopsis "Distributed Hash Table (DHT) library")
    (description "OpenDHT is a Distributed Hash Table (DHT) library.  It may
be used to manage peer-to-peer network connections as needed for real time
communication.")
    (license license:gpl3)))

(define rlog
  (package
    (name "rlog")
    (version "1.4")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "http://rlog.googlecode.com/files/rlog-"
                       version ".tar.gz"))
       (sha256
        (base32
         "0y9zg0pd7vmnskwac1qdyzl282z7kb01nmn57lsg2mjdxgnywf59"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (add-before 'configure 'patch-/bin/sh
                    (lambda _
                      (substitute* "docs/Makefile.in"
                        (("/bin/sh") "sh")))))))
    (home-page "http://www.arg0.net/rlog")
    (synopsis "Flexible message logging library for EncFS")
    (description
     "RLog provides message logging for EncFS.  It is no longer maintained.")
    (license license:lgpl2.1+)))

(define-public encfs
  (package
    (name "encfs")
    (version "1.8.1")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "https://github.com/vgough/encfs/releases/download/v"
                       version "/encfs-" version ".tar.gz"))
       (sha256
        (base32
         "1lfmcsk187qr6ahy8c8959p7jrk9d5rd9kcsx572850ca3zmf0la"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags '("--with-boost-serialization=boost_wserialization"
                           "--with-boost-filesystem=boost_filesystem")
       #:phases (modify-phases %standard-phases
                  (add-before 'configure 'autoconf
                    (lambda _
                      (zero? (system* "autoreconf" "-vfi")))))))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("gettext" ,gnu-gettext)
       ("libtool" ,libtool)
       ("perl" ,perl)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("boost" ,boost)
       ("fuse" ,fuse)
       ("openssl" ,openssl)
       ("rlog" ,rlog)))
    (home-page "https://vgough.github.io/encfs")
    (synopsis "Encrypted virtual file system")
    (description
     "EncFS creates a virtual encrypted file system in user-space.  Each file
created under an EncFS mount point is stored as a separate encrypted file on
the underlying file system.  Like most encrypted file systems, EncFS is meant
to provide security against off-line attacks, such as a drive falling into
the wrong hands.")
    (license (list license:lgpl3+                 ;encfs library
                   license:gpl3+))))              ;command-line tools
