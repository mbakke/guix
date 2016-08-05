;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2015, 2016 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2014, 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014, 2015 Alex Kost <alezost@gmail.com>
;;; Copyright © 2014, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015 Taylan Ulrich Bayırlı/Kammer <taylanbayirli@gmail.com>
;;; Copyright © 2015 Amirouche Boubekki <amirouche@hypermove.net>
;;; Copyright © 2014 John Darrington <jmd@gnu.org>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
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

(define-module (gnu packages image)
  #:use-module (gnu packages)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages boost)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages graphics)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages zip)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system cmake)
  #:use-module (srfi srfi-1))

(define-public libpng
  (package
   (name "libpng")
   (version "1.5.26")
   (source (origin
            (method url-fetch)

            ;; Note: upstream removes older tarballs.
            (uri (list (string-append "mirror://sourceforge/libpng/libpng15/"
                                      version "/libpng-" version ".tar.xz")
                       (string-append
                        "ftp://ftp.simplesystems.org/pub/libpng/png/src"
                        "/libpng15/libpng-" version ".tar.xz")))
            (sha256
             (base32 "0kbissyd7d4ahwdpm968nnzl7q15p6hadg44i9x0vrkrzdgdi93v"))))
   (build-system gnu-build-system)

   ;; libpng.la says "-lz", so propagate it.
   (propagated-inputs `(("zlib" ,zlib)))

   (synopsis "Library for handling PNG files")
   (description
    "Libpng is the official PNG (Portable Network Graphics) reference
library.  It supports almost all PNG features and is extensible.")
   (license license:zlib)
   (home-page "http://www.libpng.org/pub/png/libpng.html")))

(define-public libpng-1.2
  (package
    (inherit libpng)
    (version "1.2.56")
    (source
     (origin
       (method url-fetch)
       ;; Note: upstream removes older tarballs.
       (uri (list (string-append "mirror://sourceforge/libpng/libpng12/"
                                 version "/libpng-" version ".tar.xz")
                  (string-append
                   "ftp://ftp.simplesystems.org/pub/libpng/png/src"
                   "/libpng12/libpng-" version ".tar.xz")))
       (sha256
        (base32 "1ghd03p353x0vi4dk83n1nlldg11w7vqdk3f99rkgfb82ic59ki4"))))))

(define-public libjpeg
  (package
   (name "libjpeg")
   (version "9a")
   (source (origin
            (method url-fetch)
            (uri (string-append "http://www.ijg.org/files/jpegsrc.v"
                   version ".tar.gz"))
            (sha256 (base32
                     "19q5zr4n60sjcvfbyv06n4pcl1mai3ipvnd2akflayciinj3wx9s"))))
   (build-system gnu-build-system)
   (synopsis "Library for handling JPEG files")
   (description
    "Libjpeg implements JPEG image encoding, decoding, and transcoding.
JPEG is a standardized compression method for full-color and gray-scale
images.
The included programs provide conversion between the JPEG format and
image files in PBMPLUS PPM/PGM, GIF, BMP, and Targa file formats.")
   (license license:ijg)
   (home-page "http://www.ijg.org/")))

(define-public libjpeg-8
  (package (inherit libjpeg)
   (version "8d")
   (source (origin
            (method url-fetch)
            (uri (string-append "http://www.ijg.org/files/jpegsrc.v"
                   version ".tar.gz"))
            (sha256 (base32
                     "1cz0dy05mgxqdgjf52p54yxpyy95rgl30cnazdrfmw7hfca9n0h0"))))))

(define-public jpegoptim
  (package
   (name "jpegoptim")
   (version "1.4.3")
   (source (origin
            (method url-fetch)
            (uri (string-append "http://www.kokkonen.net/tjko/src/jpegoptim-"
                                version ".tar.gz"))
            (sha256 (base32
                     "0k53q7dc8w5ashz8v261x2b5vvz7gdvg8w962rz9gjvkjbh4lg93"))))
   (build-system gnu-build-system)
   (inputs `(("libjpeg" ,libjpeg)))
   (arguments
    ;; no tests
    '(#:tests? #f))
   (synopsis "Optimize JPEG images")
   (description
    "jpegoptim provides lossless optimization (based on optimizing
the Huffman tables) and \"lossy\" optimization based on setting
maximum quality factor.")
   (license license:gpl2+)
   (home-page "http://www.kokkonen.net/tjko/projects.html#jpegoptim")))

(define-public libtiff
  (package
   (name "libtiff")
   (version "4.0.6")
   (source (origin
            (method url-fetch)
            (uri (string-append "ftp://ftp.remotesensing.org/pub/libtiff/tiff-"
                   version ".tar.gz"))
            (sha256 (base32
                     "136nf1rj9dp5jgv1p7z4dk0xy3wki1w0vfjbk82f645m0w4samsd"))
            (patches (search-patches
                      "libtiff-oob-accesses-in-decode.patch"
                      "libtiff-oob-write-in-nextdecode.patch"
                      "libtiff-CVE-2015-8665+CVE-2015-8683.patch"))))
   (build-system gnu-build-system)
   (outputs '("out"
              "doc"))                           ;1.3 MiB of HTML documentation
   (arguments
    ;; Instead of using --docdir, this package has its own --with-docdir.
    `(#:configure-flags (list (string-append "--with-docdir="
                                             (assoc-ref %outputs "doc")
                                             "/share/doc/"
                                             ,name "-" ,version))))
   (inputs `(("zlib" ,zlib)
             ("libjpeg" ,libjpeg)))
   (synopsis "Library for handling TIFF files")
   (description
    "Libtiff provides support for the Tag Image File Format (TIFF), a format
used for storing image data.
Included are a library, libtiff, for reading and writing TIFF and a small
collection of tools for doing simple manipulations of TIFF images.")
   (license (license:non-copyleft "file://COPYRIGHT"
                                  "See COPYRIGHT in the distribution."))
   (home-page "http://www.remotesensing.org/libtiff/")))

(define-public libwmf
  (package
    (name "libwmf")
    (version "0.2.8.4")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "mirror://sourceforge/wvware/"
                            name "/" version
                            "/" name "-" version ".tar.gz"))
        (sha256
         (base32 "1y3wba4q8pl7kr51212jwrsz1x6nslsx1gsjml1x0i8549lmqd2v"))
        (patches
         (search-patches "libwmf-CAN-2004-0941.patch"
                         "libwmf-CVE-2006-3376.patch"
                         "libwmf-CVE-2007-0455.patch"
                         "libwmf-CVE-2007-2756.patch"
                         "libwmf-CVE-2007-3472.patch"
                         "libwmf-CVE-2007-3473.patch"
                         "libwmf-CVE-2007-3477.patch"
                         "libwmf-CVE-2009-1364.patch"
                         "libwmf-CVE-2009-3546.patch"
                         "libwmf-CVE-2015-0848+CVE-2015-4588.patch"
                         "libwmf-CVE-2015-4695.patch"
                         "libwmf-CVE-2015-4696.patch"))))

    (build-system gnu-build-system)
    (inputs
      `(("freetype" ,freetype)
        ("libjpeg" ,libjpeg)
        ("libpng",libpng)
        ("libxml2" ,libxml2)
        ("zlib" ,zlib)))
    (native-inputs
      `(("pkg-config" ,pkg-config)))
    (synopsis "Library for reading images in the Microsoft WMF format")
    (description
      "libwmf is a library for reading vector images in Microsoft's native
Windows Metafile Format (WMF) and for either (a) displaying them in, e.g., an X
window; or (b) converting them to more standard/free file formats such as, e.g.,
the W3C's XML-based Scaleable Vector Graphic (SVG) format.")
    (home-page "http://wvware.sourceforge.net/libwmf.html")

    ;; 'COPYING' is the GPLv2, but file headers say LGPLv2.0+.
    (license license:lgpl2.0+)))

(define-public leptonica
  (package
    (name "leptonica")
    (version "1.72")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://www.leptonica.com/source/leptonica-"
                           version ".tar.gz"))
       (sha256
        (base32 "0mhzvqs0im04y1cpcc1yma70hgdac1frf33h73m9z3356bfymmbr"))
       (modules '((guix build utils)))
       ;; zlib and openjpg should be under Libs, not Libs.private.  See:
       ;; https://code.google.com/p/tesseract-ocr/issues/detail?id=1436
       (snippet
        '(substitute* "lept.pc.in"
           (("^(Libs\\.private: .*)@ZLIB_LIBS@(.*)" all pre post)
            (string-append pre post))
           (("^(Libs\\.private: .*)@JPEG_LIBS@(.*)" all pre post)
            (string-append pre post))
           (("^Libs: .*" all)
            (string-append all " @ZLIB_LIBS@ @JPEG_LIBS@"))))))
    (build-system gnu-build-system)
    (native-inputs
     `(("gnuplot" ,gnuplot)))           ;needed for test suite
    (inputs
     `(("giflib" ,giflib)
       ("libjpeg" ,libjpeg)
       ("libpng" ,libpng)
       ("libtiff" ,libtiff)
       ("libwebp" ,libwebp)))
    (propagated-inputs
     `(("openjpeg" ,openjpeg)
       ("zlib" ,zlib)))
    (arguments
     '(#:parallel-tests? #f ; XXX: cause fpix1_reg to fail
       #:phases
       (modify-phases %standard-phases
         ;; Prevent make from trying to regenerate config.h.in.
         (add-after
          'unpack 'set-config-h-in-file-time
          (lambda _
            (set-file-time "config/config.h.in" (stat "configure"))))
         (add-after
          'unpack 'patch-reg-wrapper
          (lambda _
            (substitute* "prog/reg_wrapper.sh"
              ((" /bin/sh ")
               (string-append " " (which "sh") " "))
              (("which gnuplot") (which "gnuplot")))))
         (add-before
          'check 'disable-failing-tests
          ;; XXX: 2 of 9 tests from webpio_reg fails.
          (lambda _
            (substitute* "prog/webpio_reg.c"
              ((".*DoWebpTest2.* 90.*") "")
              ((".*DoWebpTest2.* 100.*") "")))))))
    (home-page "http://www.leptonica.com/")
    (synopsis "Library and tools for image processing and analysis")
    (description
     "Leptonica is a C library and set of command-line tools for efficient
image processing and image analysis operations.  It supports rasterop, affine
transformations, binary and grayscale morphology, rank order, and convolution,
seedfill and connected components, image transformations combining changes in
scale and pixel depth, and pixelwise masking, blending, enhancement, and
arithmetic ops.")
    (license license:bsd-2)))

(define-public jbig2dec
  (package
    (name "jbig2dec")
    (version "0.11")
    (source
      (origin
        (method url-fetch)
        (uri             ;; The link on the homepage is dead.
          (string-append "http://distfiles.gentoo.org/distfiles/" name "-"
                          version ".tar.gz"))
        (sha256
          (base32 "1ffhgmf2fqzk0h4k736pp06z7q5y4x41fg844bd6a9vgncq86bby"))
        (patches (search-patches "jbig2dec-ignore-testtest.patch"))))

    (build-system gnu-build-system)
    (synopsis "Decoder of the JBIG2 image compression format")
    (description
      "JBIG2 is designed for lossy or lossless encoding of 'bilevel' (1-bit
monochrome) images at moderately high resolution, and in particular scanned
paper documents.  In this domain it is very efficient, offering compression
ratios on the order of 100:1.

This is a decoder only implementation, and currently is in the alpha
stage, meaning it doesn't completely work yet.  However, it is
maintaining parity with available encoders, so it is useful for real
work.")
    (home-page "http://jbig2dec.sourceforge.net/")
    (license license:gpl2+)))

(define-public openjpeg
  (package
    (name "openjpeg")
    (version "2.1.0")
    (source
      (origin
        (method url-fetch)
        (uri
         (string-append "mirror://sourceforge/openjpeg.mirror/" version "/"
                        name "-" version ".tar.gz"))
        (sha256
         (base32 "00zzm303zvv4ijzancrsb1cqbph3pgz0nky92k9qx3fq9y0vnchj"))
        (patches (search-patches "openjpeg-use-after-free-fix.patch"
                                 "openjpeg-CVE-2015-6581.patch"))))
    (build-system cmake-build-system)
    (arguments
      ;; Trying to run `$ make check' results in a no rule fault.
      '(#:tests? #f))
    (inputs
      `(("lcms" ,lcms)
        ("libpng" ,libpng)
        ("libtiff" ,libtiff)
        ("zlib" ,zlib)))
    (synopsis "JPEG 2000 codec")
    (description
      "The OpenJPEG library is a JPEG 2000 codec written in C.  It has
been developed in order to promote the use of JPEG 2000, the new
still-image compression standard from the Joint Photographic Experts
Group (JPEG).

In addition to the basic codec, various other features are under
development, among them the JP2 and MJ2 (Motion JPEG 2000) file formats,
an indexing tool useful for the JPIP protocol, JPWL-tools for
error-resilience, a Java-viewer for j2k-images, ...")
    (home-page "https://github.com/uclouvain/openjpeg")
    (license license:bsd-2)))

(define-public openjpeg-2.0
  (package (inherit openjpeg)
    (name "openjpeg")
    (version "2.0.1")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "mirror://sourceforge/openjpeg.mirror/" version "/"
                       name "-" version ".tar.gz"))
       (sha256
        (base32 "1c2xc3nl2mg511b63rk7hrckmy14681p1m44mzw3n1fyqnjm0b0z"))
       (patches (search-patches "openjpeg-use-after-free-fix.patch"
                                "openjpeg-CVE-2015-6581.patch"))))))

(define-public openjpeg-1
  (package (inherit openjpeg)
    (name "openjpeg")
    (version "1.5.2")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "mirror://sourceforge/openjpeg.mirror/" version "/"
                       name "-" version ".tar.gz"))
       (sha256
        (base32 "11waq9w215zvzxrpv40afyd18qf79mxc28fda80bm3ax98cpppqm"))))))

(define-public giflib
  (package
    (name "giflib")
    (version "5.1.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/giflib/giflib-"
                                  version ".tar.bz2"))
              (sha256
               (base32
                "1md83dip8rf29y40cm5r7nn19705f54iraz6545zhwa6y8zyq9yz"))))
    (build-system gnu-build-system)
    (outputs '("bin"                    ; utility programs
               "out"))                  ; library
    (inputs `(("libx11" ,libx11)
              ("libice" ,libice)
              ("libsm" ,libsm)
              ("perl" ,perl)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'disable-html-doc-gen
           (lambda _
             (substitute* "doc/Makefile.in"
               (("^all: allhtml manpages") ""))))
         (add-after 'install 'install-manpages
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((bin (assoc-ref outputs "bin"))
                    (man1dir (string-append bin "/share/man/man1")))
               (mkdir-p man1dir)
               (for-each (lambda (file)
                           (let ((base (basename file)))
                             (format #t "installing `~a' to `~a'~%"
                                     base man1dir)
                             (copy-file file
                                        (string-append
                                         man1dir "/" base))))
                         (find-files "doc" "\\.1"))))))))
    (synopsis "Tools and library for working with GIF images")
    (description
     "GIFLIB is a library for reading and writing GIF images.  It is API and
ABI compatible with libungif which was in wide use while the LZW compression
algorithm was patented.  Tools are also included to convert, manipulate,
compose, and analyze GIF images.")
    (home-page "http://giflib.sourceforge.net/")
    (license license:x11)))

(define-public libungif
  (package
    (name "libungif")
    (version "4.1.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/giflib/libungif-4.x/"
                                  "libungif-" version "/libungif-"
                                  version ".tar.bz2"))
              (sha256
               (base32
                "0cnksimmmjngdrys302ik1385sg1sj4i0gxivzldhgwd46n7x2kh"))))
    (build-system gnu-build-system)
    (inputs `(("perl" ,perl)))          ;package ships some perl tools
    (home-page "http://giflib.sourceforge.net/")
    (synopsis "GIF decompression library")
    (description
     "libungif is the old GIF decompression library by the GIFLIB project.")
    (license license:expat)))

(define-public imlib2
  (package
    (name "imlib2")
    (version "1.4.9")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://sourceforge/enlightenment/imlib2-src/" version
                    "/imlib2-" version ".tar.bz2"))
              (sha256
               (base32
                "08809xxk2555yj6glixzw9a0x3x8cx55imd89kj3r0h152bn8a3x"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkgconfig" ,pkg-config)))
    (inputs
     `(("libx11" ,libx11)
       ("libxext" ,libxext)
       ("freetype" ,freetype)
       ("libjpeg" ,libjpeg)
       ("libpng" ,libpng)
       ("libtiff" ,libtiff)
       ("giflib" ,giflib)
       ("bzip2" ,bzip2)))
    (home-page "http://sourceforge.net/projects/enlightenment/")
    (synopsis
     "Loading, saving, rendering and manipulating image files")
    (description
     "Imlib2 is a library that does image file loading and saving as well as
rendering, manipulation, arbitrary polygon support, etc.

It does ALL of these operations FAST.  Imlib2 also tries to be highly
intelligent about doing them, so writing naive programs can be done easily,
without sacrificing speed.

This is a complete rewrite over the Imlib 1.x series.  The architecture is
more modular, simple, and flexible.")
    (license license:imlib2)))

(define-public giblib
  (package
    (name "giblib")
    (version "1.2.4")
    (source (origin
              (method url-fetch)
              (uri (list
                     (string-append
                       "http://linuxbrit.co.uk/downloads/giblib-"
                       version ".tar.gz")
                     (string-append
                       "https://sourceforge.net/projects/slackbuildsdirectlinks/"
                       "files/giblib/giblib-" version ".tar.gz")))
              (sha256
               (base32
                "1b4bmbmj52glq0s898lppkpzxlprq9aav49r06j2wx4dv3212rhp"))))
    (build-system gnu-build-system)
    (inputs
     `(("libx11" ,libx11)
       ("imlib2" ,imlib2)))
    (home-page "http://linuxbrit.co.uk/software/") ; no real home-page
    (synopsis "Wrapper library for imlib2")
    (description
     "Giblib is a simple library which wraps imlib2's context API, avoiding
all the context_get/set calls, adds fontstyles to the truetype renderer and
supplies a generic doubly-linked list and some string functions.")
    ;; This license removes a clause about X Consortium from the original
    ;; X11 license.
    (license (license:x11-style "file://COPYING"
                                "See 'COPYING' in the distribution."))))

(define-public freeimage
  (package
   (name "freeimage")
   (version "3.17.0")
   (source (origin
            (method url-fetch)
            (uri (string-append
                  "mirror://sourceforge/freeimage/Source%20Distribution/"
                  version "/FreeImage"
                  (string-concatenate (string-split version #\.))
                  ".zip"))
            (sha256
             (base32
              "12bz57asdcfsz3zr9i9nska0fb6h3z2aizy412qjqkixkginbz7v"))
            (patches (search-patches "freeimage-CVE-2015-0852.patch"))))
   (build-system gnu-build-system)
   (arguments
    '(#:phases (alist-delete
                'configure
                (alist-cons-before
                 'build 'patch-makefile
                 (lambda* (#:key outputs #:allow-other-keys)
                   (substitute* "Makefile.gnu"
                     (("/usr") (assoc-ref outputs "out"))
                     (("-o root -g root") "")))
                 %standard-phases))
      #:make-flags '("CC=gcc")
      #:tests? #f)) ; no check target
   (native-inputs
    `(("unzip" ,unzip)))
   ;; Fails to build on MIPS due to assembly code in the source.
   (supported-systems (delete "mips64el-linux" %supported-systems))
   (synopsis "Library for handling popular graphics image formats")
   (description
    "FreeImage is a library for developers who would like to support popular
graphics image formats like PNG, BMP, JPEG, TIFF and others.")
   (license license:gpl2+)
   (home-page "http://freeimage.sourceforge.net")))

(define-public vigra
  (package
   (name "vigra")
   (version "1.11.0")
   (source
    (origin
      (method url-fetch)
      (uri (string-append "https://github.com/ukoethe/vigra/releases/download/"
                          "Version-1-11-0/vigra-"
                          version "-src.tar.gz"))
      (sha256 (base32
                "1jzm79kqiiilvys3b8mlzy9cvmiirrcwsrlg19qd9rza8zipsqb8"))))
   (build-system cmake-build-system)
   (inputs
    `(("boost" ,boost)
      ("fftw" ,fftw)
      ("fftwf" ,fftwf)
      ("hdf5" ,hdf5)
      ("ilmbase" ,ilmbase) ; propagated by openexr, but needed explicitly
                           ; to create a configure-flag
      ("libjpeg" ,libjpeg)
      ("libpng" ,libpng)
      ("libtiff" ,libtiff)
      ("openexr" ,openexr)
      ("python" ,python-2) ; print syntax
      ("python2-numpy" ,python2-numpy)
      ("zlib" ,zlib)))
   (native-inputs
    `(("doxygen" ,doxygen)
      ("python2-nose" ,python2-nose)
      ("python2-sphinx" ,python2-sphinx)))
   (arguments
    `(#:test-target "check"
      #:parallel-build? #f ; parallel builds trigger an ICE
      #:configure-flags
        (list "-Wno-dev" ; suppress developer mode with lots of warnings
              (string-append "-DVIGRANUMPY_INSTALL_DIR="
                             (assoc-ref %outputs "out")
                             "/lib/python2.7/site-packages")
              ;; OpenEXR is not enabled by default.
              "-DWITH_OPENEXR=1"
              ;; The header files of ilmbase are not found when included
              ;; by the header files of openexr, and an explicit flag
              ;; needs to be set.
              (string-append "-DCMAKE_CXX_FLAGS=-I"
                             (assoc-ref %build-inputs "ilmbase")
                             "/include/OpenEXR"))))
   (synopsis "Computer vision library")
   (description
    "VIGRA stands for Vision with Generic Algorithms.  It is an image
processing and analysis library that puts its main emphasis on customizable
algorithms and data structures.  It is particularly strong for
multi-dimensional image processing.")
   (license license:expat)
   (home-page "https://hci.iwr.uni-heidelberg.de/vigra")))

(define-public libwebp
  (package
    (name "libwebp")
    (version "0.4.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "http://downloads.webmproject.org/releases/webp/libwebp-" version
             ".tar.gz"))
       (sha256
        (base32 "1i4hfczjm3b1qj1g4cc9hgb69l47f3nkgf6hk7nz4dm9zmc0vgpg"))))
    (build-system gnu-build-system)
    (inputs
     `(("freeglut" ,freeglut)
       ("giflib" ,giflib)
       ("libjpeg" ,libjpeg)
       ("libpng" ,libpng)
       ("libtiff" ,libtiff)))
    (arguments
     '(#:configure-flags '("--enable-libwebpmux"
                           "--enable-libwebpdemux"
                           "--enable-libwebpdecoder")))
    (home-page "https://developers.google.com/speed/webp/")
    (synopsis "Lossless and lossy image compression")
    (description
     "WebP is a new image format that provides lossless and lossy compression
for images.  WebP lossless images are 26% smaller in size compared to
PNGs.  WebP lossy images are 25-34% smaller in size compared to JPEG images at
equivalent SSIM index.  WebP supports lossless transparency (also known as
alpha channel) with just 22% additional bytes.  Transparency is also supported
with lossy compression and typically provides 3x smaller file sizes compared
to PNG when lossy compression is acceptable for the red/green/blue color
channels.")
    (license license:bsd-3)))

(define-public libmng
  (package
    (name "libmng")
    (version "2.0.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/libmng/libmng-devel/"
                                  version "/" name "-" version ".tar.xz"))
              (sha256
               (base32
                "1lvxnpds0vcf0lil6ia2036ghqlbl740c4d2sz0q5g6l93fjyija"))))
    (build-system gnu-build-system)
    (propagated-inputs
     ;; These are all in the 'Libs.private' field of libmng.pc.
     `(("lcms" ,lcms)
       ("libjpeg" ,libjpeg)
       ("zlib" ,zlib)))
    (home-page "http://www.libmng.com/")
    (synopsis "Library for handling MNG files")
    (description
     "Libmng is the MNG (Multiple-image Network Graphics) reference library.")
    (license license:bsd-3)))

(define-public devil
  (package
    (name "devil")
    (version "1.7.8")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://downloads.sourceforge.net/openil/"
                                  "DevIL-" version ".tar.gz"))
              (sha256
               (base32
                "1zd850nn7nvkkhasrv7kn17kzgslr5ry933v6db62s4lr0zzlbv8"))
              ;; Backported from upstream:
              ;; https://github.com/DentonW/DevIL/commit/724194d7a9a91221a564579f64bdd6f0abd64219.patch
              (patches (search-patches "devil-fix-libpng.patch"
                                       "devil-CVE-2009-3994.patch"))
              (modules '((guix build utils)))
              (snippet
               ;; Fix old lcms include directives and lib flags.
               '(substitute* '("configure" "src-IL/src/il_profiles.c")
                  (("-llcms") "-llcms2")
                  (("lcms/lcms\\.h") "lcms2/lcms2.h")
                  (("lcms\\.h") "lcms2.h")))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags '("--enable-ILUT=yes") ; build utility library
       #:phases
       (modify-phases %standard-phases
         (add-before 'check 'fix-tests
           (lambda* (#:key inputs #:allow-other-keys)
             ;; Fix hard-coded /bin/bash reference.
             (substitute* '("test/Makefile")
               (("TESTS_ENVIRONMENT = /bin/bash")
                (string-append "TESTS_ENVIRONMENT = "
                               (assoc-ref inputs "bash")
                               "/bin/bash")))
             #t)))))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("lcms" ,lcms)
       ("libjpeg" ,libjpeg)
       ("libmng" ,libmng)
       ("libpng" ,libpng)
       ("libtiff" ,libtiff)
       ("openexr" ,openexr)
       ("zlib" ,zlib)))
    (synopsis "Library for manipulating many image formats")
    (description "Developer's Image Library (DevIL) is a library to develop
applications with support for many types of images.  DevIL can load, save,
convert, manipulate, filter and display a wide variety of image formats.")
    (home-page "http://openil.sourceforge.net")
    (license license:lgpl2.1+)))

(define-public jasper
  (package
    (name "jasper")
    (version "1.900.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://www.ece.uvic.ca/~frodo/jasper"
                                  "/software/jasper-" version ".zip"))
              (sha256
               (base32
                "154l7zk7yh3v8l2l6zm5s2alvd2fzkp6c9i18iajfbna5af5m43b"))
              (patches (search-patches
                        "jasper-CVE-2007-2721.patch"
                        "jasper-CVE-2008-3520.patch"
                        "jasper-CVE-2008-3522.patch"
                        "jasper-CVE-2011-4516-and-CVE-2011-4517.patch"
                        "jasper-CVE-2014-8137.patch"
                        "jasper-CVE-2014-8138.patch"
                        "jasper-CVE-2014-8157.patch"
                        "jasper-CVE-2014-8158.patch"
                        "jasper-CVE-2014-9029.patch"
                        "jasper-CVE-2016-1577.patch"
                        "jasper-CVE-2016-1867.patch"
                        "jasper-CVE-2016-2089.patch"
                        "jasper-CVE-2016-2116.patch"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("unzip" ,unzip)))
    (synopsis "JPEG-2000 library")
    (description "The JasPer Project is an initiative to provide a reference
implementation of the codec specified in the JPEG-2000 Part-1 standard (i.e.,
ISO/IEC 15444-1).")
    (home-page "https://www.ece.uvic.ca/~frodo/jasper/")
    (license (license:x11-style "file://LICENSE"))))

(define-public zimg
  (package
    (name "zimg")
    (version "2.1")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "https://github.com/sekrit-twc/zimg/archive/"
                            "release-" version ".tar.gz"))
        (file-name (string-append name "-" version ".tar.gz"))
        (sha256
         (base32
          "1hqp1gcsa2zhypms5dnasb1srjgxdqm7cip3w5i571kk9nxkn289"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)))
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'autogen
           (lambda _
             (zero? (system* "sh" "autogen.sh")))))))
    (synopsis "Scaling, colorspace conversion, and dithering library")
    (description "Zimg implements the commonly required image processing basics
of scaling, colorspace conversion, and depth conversion.  A simple API enables
conversion between any supported formats to operate with minimal knowledge from
the programmer.")
    (home-page "https://github.com/sekrit-twc/zimg")
    ;; test/extra/ contains musl-libm, 
    ;; which is MIT/expat licensed, but only used for tests
    (license (license:fsf-free "file://COPYING")))) ;WTFPL version 2

(define-public perceptualdiff
  (package
    (name "perceptualdiff")
    (version "1.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/myint/perceptualdiff/archive/v"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
        (sha256
         (base32
          "0zl6xmp971fffg7fzcz2fbgxg5x2w7l8qa65c008i4kbkc9016ps"))))
    (build-system cmake-build-system)
    (inputs `(("freeimage" ,freeimage)))
    (arguments
     '(#:phases (modify-phases %standard-phases
                  (add-after 'unpack 'fix-tests
                    ;; cmake-build-system uses a build/ directory outside
                    ;; of the source tree, one level higher than expected
                    (lambda _
                      (substitute* "test/run_tests.bash"
                        (("../build") "../../build")))))))
    (home-page "https://github.com/myint/perceptualdiff")
    (synopsis "Perceptual image comparison utility")
    (description "PerceptualDiff visually compares two images to determine
whether they look alike.  It uses a computational model of the human visual
system to detect similarities.  This allows it too see beyond irrelevant
differences in file encoding, image quality, and other small variations.")
    (license license:gpl2+)))
