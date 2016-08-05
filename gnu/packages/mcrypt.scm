;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
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

(define-module (gnu packages mcrypt)
  #:use-module (guix packages)
  #:use-module ((guix licenses) #:select (gpl2+))
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages perl))

(define-public mcrypt
  (package
    (name "mcrypt")
    (version "2.6.8")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://sourceforge/mcrypt/MCrypt/"
                          version "/" name "-" version ".tar.gz"))
      (sha256
       (base32
        "161031n1w9pb4yzz9i47szc12a4mwpcpvyxnvafsik2l9s2aliai"))
      (patches (search-patches
                 "mcrypt-CVE-2012-4409.patch"
                 "mcrypt-CVE-2012-4426.patch"
                 "mcrypt-CVE-2012-4527.patch"))))
    (build-system gnu-build-system)
    (inputs
     `(("zlib" ,zlib)
       ("libmcrypt" ,libmcrypt)
       ("libmhash" ,libmhash)))
    (home-page "http://mcrypt.sourceforge.net/")
    (synopsis "Replacement for the popular Unix crypt command")
    (description
     "MCrypt is a replacement for the old crypt() package and crypt(1)
command, with extensions.  It allows developers to use a wide range of
encryption functions, without making drastic changes to their code.  It allows
users to encrypt files or data streams without having to be cryptographers.
The companion to MCrypt is Libmcrypt, which contains the actual encryption
functions themselves, and provides a standardized mechanism for accessing
them.")
    (license gpl2+)))

(define-public libmcrypt
  (package
    (name "libmcrypt")
    (version "2.5.8")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://sourceforge/mcrypt/Libmcrypt/" version
                          "/libmcrypt-" version ".tar.gz"))
      (sha256
       (base32
        "0gipgb939vy9m66d3k8il98rvvwczyaw2ixr8yn6icds9c3nrsz4"))))
    (build-system gnu-build-system)
    (home-page "http://mcrypt.sourceforge.net/")
    (synopsis "Encryption algorithm library")
    (description
     "Libmcrypt is a data encryption library.  The library is thread safe and
provides encryption and decryption functions.  This version of the library
supports many encryption algorithms and encryption modes.  Some algorithms
which are supported: SERPENT, RIJNDAEL, 3DES, GOST, SAFER+, CAST-256, RC2,
XTEA, 3WAY, TWOFISH, BLOWFISH, ARCFOUR, WAKE and more.")
    (license gpl2+)))

(define-public libmhash
  (package
    (name "libmhash")
    (version "0.9.9.9")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://sourceforge/mhash/mhash/" version
                          "/mhash-" version ".tar.bz2"))
      (sha256
       (base32
        "1w7yiljan8gf1ibiypi6hm3r363imm3sxl1j8hapjdq3m591qljn"))
      (patches (search-patches "mhash-keygen-test-segfault.patch"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("perl" ,perl)))                 ;for tests
    (home-page "http://mhash.sourceforge.net/")
    (synopsis "Thread-safe hash library")
    (description
     "Mhash is a thread-safe hash library, implemented in C, and provides a
uniform interface to a large number of hash algorithms.  These algorithms can
be used to compute checksums, message digests, and other signatures.  The HMAC
support implements the basics for message authentication, following RFC 2104.

Algorithms currently supplied are:

CRC-32, CRC-32B, ALDER-32, MD-2, MD-4, MD-5, RIPEMD-128, RIPEMD-160,
RIPEMD-256, RIPEMD-320, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, HAVAL-128,
HAVAL-160, HAVAL-192, HAVAL-256, TIGER, TIGER-128, TIGER-160, GOST, WHIRLPOOL,
SNEFRU-128, SNEFRU-256.")
    (license gpl2+)))
