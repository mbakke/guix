;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2015 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
;;; Copyright © 2016 Mark H Weaver <mhw@netris.org>
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

(define-module (gnu packages imagemagick)
  #:use-module (guix packages)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system perl)
  #:use-module (guix download)
  #:use-module (guix hg-download)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages graphviz)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages image)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg))

(define-public imagemagick
  (package
    (name "imagemagick")
    (version "6.9.7-0")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://imagemagick/ImageMagick-"
                                 version ".tar.xz"))
             (sha256
              (base32
               "0c6ff1am2mhc0dc26h50l78yx6acwqymwpwgkxgx69cb6jfpwrdx"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags '("--with-frozenpaths" "--without-gcc-arch")
       ;; FIXME: The test suite succeeded before version 6.9.6-2.
       ;; Try enabling it again with newer releases.
       #:tests? #f
       #:phases (modify-phases %standard-phases
                  (add-before
                   'build 'pre-build
                   (lambda* (#:key outputs #:allow-other-keys)
                     (substitute* "Makefile"
                       ;; Clear the `LIBRARY_PATH' setting, which otherwise
                       ;; interferes with our own use.
                       (("^LIBRARY_PATH[[:blank:]]*=.*$")
                        "")

                       ;; Since the Makefile overrides $docdir, modify it to
                       ;; refer to what we want.
                       (("^DOCUMENTATION_PATH[[:blank:]]*=.*$")
                        (let ((doc (assoc-ref outputs "doc")))
                          (string-append "DOCUMENTATION_PATH = "
                                         doc "/share/doc/"
                                         ,name "-" ,version "\n"))))))
                  (add-before
                   'configure 'strip-configure-xml
                   (lambda _
                     (substitute* "config/configure.xml.in"
                       ;; Do not record 'configure' arguments in the
                       ;; configure.xml file that gets installed: That would
                       ;; include --docdir, and thus retain a reference to the
                       ;; 'doc' output.
                       (("@CONFIGURE_ARGS@")
                        "not recorded")))))))
    ;; TODO: Add Jasper etc.
    (inputs `(("fftw" ,fftw)
              ("graphviz" ,graphviz)
              ("ghostscript" ,ghostscript)
              ("lcms" ,lcms)
              ("libx11" ,libx11)
              ("zlib" ,zlib)
              ("libxml2" ,libxml2)
              ("libtiff" ,libtiff)
              ("libpng" ,libpng)
              ("libjpeg" ,libjpeg)
              ("pango" ,pango)
              ("freetype" ,freetype)
              ("bzip2" ,bzip2)
              ("xz" ,xz)))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (outputs '("out"
               "doc"))                          ; 26 MiB of HTML documentation
    (home-page "http://www.imagemagick.org/")
    (synopsis "Create, edit, compose, or convert bitmap images")
    (description
     "ImageMagick is a software suite to create, edit, compose, or convert
bitmap images.  It can read and write images in a variety of formats (over 100)
including DPX, EXR, GIF, JPEG, JPEG-2000, PDF, PhotoCD, PNG, Postscript, SVG,
and TIFF.  Use ImageMagick to resize, flip, mirror, rotate, distort, shear and
transform images, adjust image colors, apply various special effects, or draw
text, lines, polygons, ellipses and Bézier curves.")
    (license (license:fsf-free "http://www.imagemagick.org/script/license.php"))))

(define-public perl-image-magick
  (package
    (name "perl-image-magick")
    (version "6.89")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/J/JC/JCRISTY/"
                           "PerlMagick-" version "-1.tar.gz"))
       (sha256
        (base32
         "0n9afy1z5bhf9phrbahnkwhgcmijn8jggpbzwrivw1zhliliiy68"))))
    (build-system perl-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)))
    (inputs `(("imagemagick" ,imagemagick)))
    (arguments
     `(#:tests? #f ;;Failed 2/23 test programs. 2/353 subtests failed.
       #:phases
       (modify-phases %standard-phases
         (add-before
          'configure 'image-magick-flags
          (lambda* (#:key inputs #:allow-other-keys)
            (let ((im (assoc-ref inputs "imagemagick")))
              (substitute* "Makefile.PL"
                (("my \\$INC_magick = .*")
                 "my $INC_magick = `pkg-config --cflags ImageMagick`;\n")
                (("my \\$LIBS_magick = .*")
                 "my $LIBS_magick = `pkg-config --libs ImageMagick`;\n")))))
         (add-before
          'check 'skip-mpeg-tests
          (lambda _
            ;; TODO: MPEG tests fail even though our imagemagick supports
            ;; MPEG.  Has been reported elsewhere,
            ;; http://www.imagemagick.org/discourse-server/viewtopic.php?f=7&t=25036,
            ;; so skip for now.
            (delete-file "t/mpeg/read.t"))))))
    (home-page "http://search.cpan.org/dist/PerlMagick")
    (synopsis "Perl interface to ImageMagick")
    (description "This Perl extension allows the reading, manipulation and
writing of a large number of image file formats using the ImageMagick library.
Use it to create, edit, compose, or convert bitmap images from within a Perl
script.")
    ;; See Magick.pm
    (license (package-license imagemagick))))

(define-public graphicsmagick
  (let ((changeset "56c8cae")  ; 3e01b
        (revision "1"))
    (package
      (name "graphicsmagick")
      (version (string-append "1.3.25-" revision "." changeset))
      (source (origin
                (method hg-fetch)
                (uri (hg-reference
                      (url "http://hg.code.sf.net/p/graphicsmagick/code")
                      (changeset changeset)))
                (file-name (string-append name "-" version "-checkout"))
                ;;(method url-fetch)
                ;;(uri (string-append "ftp://ftp.graphicsmagick.org/pub/"
                ;;                    "GraphicsMagick/" (version-major+minor version)
                ;;                    "/GraphicsMagick-" version ".tar.xz"))
                (sha256
                 (base32
                  "1s9apvkn0kxr6i4i5wlkfw1prja02rgk689n3cf822zc0dkycxdh"))))
      (build-system gnu-build-system)
      (arguments
       `(#:configure-flags
         (list "--with-frozenpaths"
               "--enable-shared=yes"
               "--with-x=yes"
               (string-append "--with-gs-font-dir="
                              (assoc-ref %build-inputs "gs-fonts")
                              "/share/fonts/type1/ghostscript"))))
      (inputs
       `(("graphviz" ,graphviz)
         ("ghostscript" ,ghostscript)
         ("gs-fonts" ,gs-fonts)
         ("lcms" ,lcms)
         ("libx11" ,libx11)
         ("libxml2" ,libxml2)
         ("libtiff" ,libtiff)
         ("libpng" ,libpng)
         ("libjpeg" ,libjpeg)
         ("freetype" ,freetype)
         ("bzip2" ,bzip2)
         ("xz" ,xz)
         ("zlib" ,zlib)))
      (native-inputs
       `(("pkg-config" ,pkg-config)))
      (outputs '("out"                  ; 13 MiB
                 "doc"))                ; ~7 MiB
      (home-page "http://www.graphicsmagick.org")
      (synopsis "Create, edit, compose, or convert bitmap images")
      (description
       "GraphicsMagick provides a comprehensive collection of utilities,
programming interfaces, and GUIs, to support file format conversion, image
processing, and 2D vector rendering.")
      (license license:expat))))
