;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2015 Andy Wingo <wingo@igalia.com>
;;; Copyright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
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

(define-module (gnu packages libusb)
  #:use-module (gnu packages)
  #:use-module (guix licenses)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system glib-or-gtk)
  #:use-module (guix build-system python)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages mp3)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages xiph))

(define-public libusb
  (package
    (name "libusb")
    (version "1.0.19")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://sourceforge/libusb/libusb-1.0/"
                          "libusb-" version "/libusb-" version ".tar.bz2"))
      (sha256
       (base32
        "0h38p9rxfpg9vkrbyb120i1diq57qcln82h5fr7hvy82c20jql3c"))))
    (build-system gnu-build-system)

    ;; XXX: Enabling udev is now recommended, but eudev indirectly depends on
    ;; libusb.
    (arguments `(#:configure-flags '("--disable-udev")))
    ;; (inputs `(("eudev" ,eudev)))

    (home-page "http://www.libusb.org")
    (synopsis "User-space USB library")
    (description
     "Libusb is a library that gives applications easy access to USB
devices on various operating systems.")
    (license lgpl2.1+)))

(define-public libusb-compat
  (package
    (name "libusb-compat")
    (version "0.1.5")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://sourceforge/libusb/"
                          name "-" (version-major+minor version) "/"
                          name "-" version "/"
                          name "-" version ".tar.bz2"))
      (sha256
       (base32
        "0nn5icrfm9lkhzw1xjvaks9bq3w6mjg86ggv3fn7kgi4nfvg8kj0"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("libusb" ,libusb)))
    (home-page "http://www.libusb.org")
    (synopsis "Compatibility shim for libusb")
    (description
     "Libusb-compat provides a shim allowing applications based on older
version of libusb to run with newer libusb.")
    (license lgpl2.1+)))

(define-public python-pyusb
  (package
    (name "python-pyusb")
    (version "1.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "PyUSB" version))
       (sha256
        (base32
         "0s2k4z06fapd5vp1gnrlf8a9sjpc03p9974lzw5k6ky39akzyd2v"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f  ;no tests
       #:modules ((srfi srfi-26)
                  (guix build utils)
                  (guix build python-build-system))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-libusb-reference
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "usb/libloader.py"
               (("lib = locate_library\\(candidates, find_library\\)")
                (string-append
                 "lib = \""
                 (car (find-files (assoc-ref inputs "libusb")
                                  (lambda (file stat)
                                    (and ((file-name-predicate
                                           "^libusb-.*\\.so\\..*") file stat)
                                         (not (symbolic-link? file))))))
                 "\"")))
             #t)))))
    (inputs
     `(("libusb" ,libusb)))
    (home-page "http://walac.github.io/pyusb/")
    (synopsis "Python bindings to the libusb library")
    (description
     "PyUSB aims to be an easy to use Python module to access USB devices.")
    (license bsd-3)))

(define-public python2-pyusb
  (package-with-python2 python-pyusb))

(define-public libmtp
  (package
    (name "libmtp")
    (version "1.1.11")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://sourceforge/libmtp/libmtp/" version
                                 "/libmtp-" version ".tar.gz"))
             (sha256
              (base32
               "1sc768q2cixwanlwrz95mp389iaadl4s95486caavxx4g7znvn8m"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     ;; libmtp.pc refers to all these.
     `(("libgcrypt" ,libgcrypt)
       ("libusb" ,libusb)))
    (arguments
     `(#:configure-flags
       (list (string-append "--with-udev="
                            (assoc-ref %outputs "out")
                            "/lib/udev"))))
    (home-page "http://libmtp.sourceforge.net/")
    (synopsis "Library implementing the Media Transfer Protocol")
    (description "Libmtp implements an MTP (Media Transfer Protocol)
initiator, which means that it initiates MTP sessions with devices.  The
devices responding are known as MTP responders.  Libmtp runs on devices
with a USB host controller interface.  It implements MTP Basic, which was
proposed for standardization.")
    ;; COPYING contains lgpl2.1, while files headers give
    ;; "GNU Lesser General Public License as published by the Free Software
    ;; Foundation; either version 2 of the License, or (at your option) any
    ;; later version."
    (license lgpl2.1+)))

(define-public gmtp
  (package
    (name "gmtp")
    (version "1.3.10")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/gmtp/gMTP-" version
                                  "/gmtp-" version ".tar.gz"))
              (sha256
               (base32
                "0fyi3pdl2g57vr0p46ip2wwzyap3l0by7iqaqygv0yxfcs79l6xj"))))
    (build-system glib-or-gtk-build-system)
    (arguments
     '(#:configure-flags
       (let ((libid3tag (assoc-ref %build-inputs "libid3tag")))
         (list
          ;; libid3tag provides no .pc file, so pkg-config fails to find them.
          (string-append "ID3TAG_CFLAGS=-I" libid3tag "/include")
          (string-append "ID3TAG_LIBS=-L" libid3tag "/lib -lid3tag -lz")))))
    (inputs
     `(("gtk+" ,gtk+)
       ("flac" ,flac)
       ("libvorbis" ,libvorbis)
       ("libid3tag" ,libid3tag)
       ("libmtp" ,libmtp)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://gmtp.sourceforge.net/")
    (synopsis "Simple graphical MTP client")
    (description "gMTP is a simple graphical client for the Media Transfer Protocol
  (MTP), which allows media files to be transferred to and from many portable
devices.")
    (license bsd-3)))
