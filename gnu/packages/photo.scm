;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015 Andreas Enge <andreas@enge.fr>
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

(define-module (gnu packages photo)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system perl)
  #:use-module (guix download)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages base)
  #:use-module (gnu packages boost)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages graphics)
  #:use-module (gnu packages image)
  #:use-module (gnu packages imagemagick)
  #:use-module (gnu packages libusb)
  #:use-module (gnu packages man)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages popt)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages web)
  #:use-module (gnu packages xfig)
  #:use-module (gnu packages xml))

(define-public libraw
  (package
    (name "libraw")
    (version "0.17.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.libraw.org/data/LibRaw-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "043kckxjqanw8dl3m9f6kvsf0l20ywxmgxd1xb0slj6m8l4w4hz6"))))
    (build-system gnu-build-system)
    (home-page "http://www.libraw.org")
    (synopsis "Raw image decoder")
    (description
     "LibRaw is a library for reading RAW files obtained from digital photo
cameras (CRW/CR2, NEF, RAF, DNG, and others).")
    (license license:lgpl2.1+)))

(define-public libexif
  (package
    (name "libexif")
    (version "0.6.21")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/libexif/libexif/"
                                  version "/libexif-" version ".tar.bz2"))
              (sha256
               (base32
                "06nlsibr3ylfwp28w8f5466l6drgrnydgxrm4jmxzrmk5svaxk8n"))))
    (build-system gnu-build-system)
    (home-page "http://libexif.sourceforge.net/")
    (synopsis "Read and manipulate EXIF data in digital photographs")
    (description
     "The libexif C library allows applications to read, edit, and save EXIF
data as produced by digital cameras.")
    (license license:lgpl2.1+)))

(define-public libgphoto2
  (package
    (name "libgphoto2")
    (version "2.5.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/gphoto/libgphoto/"
                                  version "/libgphoto2-" version ".tar.bz2"))
              (sha256
               (base32
                "0f1818l1vs5fbmrihzyv3qasddbqi3r01jik5crrxddwalsi2bd3"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)))
    (inputs
     `(;; ("libjpeg-turbo" ,libjpeg-turbo)
       ("libltdl" ,libltdl)
       ("libusb" ,libusb)))
    (propagated-inputs
     `(;; The .pc refers to libexif.
       ("libexif" ,libexif)))
    (home-page "http://www.gphoto.org/proj/libgphoto2/")
    (synopsis "Accessing digital cameras")
    (description
     "This is the library backend for gphoto2.  It contains the code for PTP,
MTP, and other vendor specific protocols for controlling and transferring data
from digital cameras.")

    ;; 'COPYING' says LGPLv2.1+, but in practices files are under LGPLv2+.
    (license license:lgpl2.1+)))

(define-public gphoto2
  (package
    (name "gphoto2")
    (version "2.5.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/gphoto/gphoto/" version
                                  "/gphoto2-" version ".tar.bz2"))
              (sha256
               (base32
                "16c8k1cxfypg7v5h8xi87grclw7a5ayaamn548ys3zkj727r5fcf"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("readline" ,readline)
       ;; ("libjpeg-turbo" ,libjpeg-turbo)
       ("popt" ,popt)
       ("libexif" ,libexif)
       ("libgphoto2" ,libgphoto2)))
    (arguments
     '(#:phases (alist-cons-before
                 'check 'pre-check
                 (lambda* (#:key inputs #:allow-other-keys)
                   (substitute* (find-files "tests/data" "\\.param$")
                     (("/usr/bin/env")
                      (which "env"))))
                 %standard-phases)

       ;; FIXME: There are 2 test failures, most likely related to the build
       ;; environment.
       #:tests? #f))

    (home-page "http://www.gphoto.org/")
    (synopsis "Command-line tools to access digital cameras")
    (description
     "Gphoto2 is a set of command line utilities for manipulating a large
number of different digital cameras.  Through libgphoto2, it supports PTP,
MTP, and much more.")

    ;; Files are typically under LGPLv2+, but 'COPYING' says GPLv2+.
    (license license:gpl2+)))

(define-public perl-image-exiftool
  (package
    (name "perl-image-exiftool")
    (version "10.20")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://cpan/authors/id/E/EX/EXIFTOOL/Image-ExifTool-"
                    version ".tar.gz"))
              (sha256
               (base32
                "0akdnxvb23ibcwa63ncibaj5m5k56cb34x8gy90z9lqcjl0f4sph"))))
    (build-system perl-build-system)
    (arguments
     '(#:phases (alist-cons-after
                 'install 'post-install
                 (lambda* (#:key outputs #:allow-other-keys)
                   ;; Make sure the 'exiftool' commands finds the library.
                   ;; XXX: Shouldn't it be handled by PERL-BUILD-SYSTEM?
                   (let* ((out (assoc-ref outputs "out"))
                          (pm  (find-files out "^ExifTool\\.pm$"))
                          (lib (dirname (dirname (car pm)))))
                     (wrap-program (string-append out "/bin/exiftool")
                                   `("PERL5LIB" prefix (,lib)))))
                 %standard-phases)))
    (home-page "http://search.cpan.org/dist/Image-ExifTool")
    (synopsis "Program and Perl library to manipulate EXIF tags")
    (description
     "This package provides the 'exiftool' command and the 'Image::ExifTool'
Perl library to manipulate EXIF tags of digital images.")
    (license (package-license perl))))

(define-public libpano13
  (package
    (name "libpano13")
    (version "2.9.19")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/panotools/libpano13/"
                                  "libpano13-" version "/"
                                  "libpano13-" version ".tar.gz"))
              (sha256
               (base32
                "1a4m3plmfcrrplqs9zfzhc5apibn10m5sajpizm1sd3q74w5fwq3"))))
    (build-system cmake-build-system)
    (inputs
     `(("libjpeg" ,libjpeg)
       ("libpng" ,libpng)
       ("libtiff" ,libtiff)
       ("zlib" ,zlib)))
    (home-page "http://panotools.sourceforge.net/")
    (synopsis "Library for panoramic images")
    (description
     "The libpano13 package contains the backend library written by the
Panorama Tools project for building panoramic images from a set of
overlapping images, as well as some command line tools.")
    (license license:gpl2+)))

(define-public enblend-enfuse
  (package
    (name "enblend-enfuse")
    (version "4.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/enblend/"
                                  name "/"
                                  name "-" (version-major+minor version) "/"
                                  name "-" version ".tar.gz"))
              (sha256
               (base32
                "0j5x011ilalb47ssah50ag0a4phgh1b0wdgxdbbp1gcyjcjf60w7"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("perl" ,perl)
       ("perl-timedate" ,perl-timedate)
       ;; for building the documentation
       ("gnuplot" ,gnuplot)
       ("help2man" ,help2man)
       ("imagemagick" ,imagemagick)
       ("libxml2" ,libxml2)
       ("texlive-minimal" ,texlive-minimal)
       ("tidy" ,tidy)
       ("transfig" ,transfig)))
    (inputs
     `(("boost" ,boost)
       ("gsl" ,gsl)
       ("lcms" ,lcms)
       ("libjpeg" ,libjpeg)
       ("libpng" ,libpng)
       ("libtiff" ,libtiff)
       ("openexr" ,openexr)
       ("vigra" ,vigra)
       ("zlib" ,zlib)))
    (arguments
     `(#:configure-flags `("--enable-openmp")))
    (home-page "http://enblend.sourceforge.net/")
    (synopsis "Tools for combining and blending images")
    (description
     "Enblend blends away the seams in a panoramic image mosaic using a
multi-resolution spline.  Enfuse merges different exposures of the same
scene to produce an image that looks much like a tone-mapped image.")
    (license license:gpl2+)))
