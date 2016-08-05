;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2014, 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2013, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu packages ghostscript)
  #:use-module (gnu packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages image)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages tcl)
  #:use-module (gnu packages xorg)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial))

(define-public lcms
  (package
   (name "lcms")
   (version "2.6")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://sourceforge/lcms/lcms/" version
                                "/lcms2-" version ".tar.gz"))
            (sha256 (base32
                     "1c8lgq8gfs3nyplvbx9k8wzfj6r2bqi3f611vb1m8z3476454wji"))))
   (build-system gnu-build-system)
   (inputs `(("libjpeg-8" ,libjpeg-8)
             ("libtiff" ,libtiff)
             ("zlib" ,zlib)))
   (synopsis "Little CMS, a small-footprint colour management engine")
   (description
    "Little CMS is a small-footprint colour management engine, with special
focus on accuracy and performance.  It uses the International Color
Consortium standard (ICC), approved as ISO 15076-1.")
   (license license:x11)
   (home-page "http://www.littlecms.com/")))

(define-public libpaper
  (package
   (name "libpaper")
   (version "1.1.24")
   (source (origin
            (method url-fetch)
            (uri (string-append
                   ;; Debian moved their libpaper-1.1.24 to archive.debian.net
                   ;; but in the move the hash of their tarball changed.
                   "http://pkgs.fedoraproject.org/repo/pkgs/libpaper/libpaper_"
                   version ".tar.gz/5bc87d494ba470aba54f6d2d51471834/libpaper_"
                   version ".tar.gz"))
            (sha256 (base32
                     "0zhcx67afb6b5r936w5jmaydj3ks8zh83n9rm5sv3m3k8q8jib1q"))))
   (build-system gnu-build-system)
   (synopsis "Library for handling paper sizes")
   (description
    "The paper library and accompanying files are intended to provide a simple
way for applications to take actions based on a system- or user-specified
paper size.")
   (license license:gpl2)
   (home-page "https://packages.qa.debian.org/libp/libpaper.html")))

(define-public psutils
  (package
   (name "psutils")
   (version "17")
   (source (origin
            (method url-fetch)
            (uri "ftp://ftp.knackered.org/pub/psutils/psutils.tar.gz")
            (sha256 (base32
                     "1r4ab1fvgganm02kmm70b2r1azwzbav2am41gbigpa2bb1wynlrq"))))
   (build-system gnu-build-system)
   (inputs `(("perl" ,perl)))
   (arguments
    `(#:tests? #f ; none provided
      #:phases
      (alist-replace
       'configure
       (lambda* (#:key inputs outputs #:allow-other-keys #:rest args)
        (let ((perl (assoc-ref inputs "perl"))
              (out (assoc-ref outputs "out")))
         (copy-file "Makefile.unix" "Makefile")
         (substitute* "Makefile"
           (("/usr/local/bin/perl") (string-append perl "/bin/perl")))
         (substitute* "Makefile"
           (("/usr/local") out))
         ;; for the install phase
         (substitute* "Makefile"
           (("-mkdir") "mkdir -p"))
         ;; drop installation of non-free files
         (substitute* "Makefile"
           ((" install.include") ""))))
      %standard-phases)))
   (synopsis "Collection of utilities for manipulating PostScript documents")
   (description
    "PSUtils is a collection of utilities for manipulating PostScript
documents.  Programs included are psnup, for placing out several logical pages
on a single sheet of paper, psselect, for selecting pages from a document,
pstops, for general imposition, psbook, for signature generation for booklet
printing, and psresize, for adjusting page sizes.")
   (license (license:non-copyleft "file://LICENSE"
                                "See LICENSE in the distribution."))
   (home-page "http://knackered.org/angus/psutils/")))

(define-public ghostscript
  (package
   (name "ghostscript")
   (version "9.14.0")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/ghostscript/gnu-ghostscript-"
                                version ".tar.xz"))
            (sha256
             (base32
              "0q4jj41p0qbr4mgcc9q78f5zs8cm1g57wgryhsm2yq4lfslm3ib1"))
            (patches (search-patches "ghostscript-CVE-2015-3228.patch"
                                     "ghostscript-runpath.patch"))
            (modules '((guix build utils)))
            (snippet
             ;; Honor --docdir.
             '(substitute* "Makefile.in"
                (("^docdir=.*$") "docdir = @docdir@\n")
                (("^exdir=.*$") "exdir = $(docdir)/examples\n")))))
   (build-system gnu-build-system)
   (outputs '("out" "doc"))                  ;16 MiB of HTML/PS doc + examples
   (inputs `(("freetype" ,freetype)
             ("lcms" ,lcms)
             ("libjpeg-8" ,libjpeg-8)
             ("libpng" ,libpng)
             ("libpaper" ,libpaper)
             ("libtiff" ,libtiff)
             ("zlib" ,zlib)))
   (native-inputs
      `(("perl" ,perl)
        ("pkg-config" ,pkg-config) ; needed to find libtiff
        ("python" ,python-wrapper)
        ("tcl" ,tcl)))
   (arguments
    `(#:disallowed-references ("doc")
      #:phases
      (modify-phases %standard-phases
        (add-after 'configure 'patch-config-files
                   (lambda _
                     (substitute* "base/all-arch.mak"
                       (("/bin/sh") (which "bash")))
                     (substitute* "base/unixhead.mak"
                       (("/bin/sh") (which "bash")))))
        (add-after 'configure 'remove-doc-reference
                   (lambda _
                     ;; Don't retain a reference to the 'doc' output in 'gs'.
                     ;; The only use of this definition is in the output of
                     ;; 'gs --help', so this change is fine.
                     (substitute* "base/gscdef.c"
                       (("GS_DOCDIR")
                        "\"~/.guix-profile/share/doc/ghostscript\""))))
        (replace 'build
          (lambda _
            ;; Build 'libgs.so', but don't build the statically-linked 'gs'
            ;; binary (saves 18 MiB).
            (zero? (system* "make" "so" "-j"
                            (number->string (parallel-job-count))))))
        (replace 'install
          (lambda _
            (zero? (system* "make" "soinstall")))))))
   (synopsis "PostScript and PDF interpreter")
   (description
    "Ghostscript is an interpreter for the PostScript language and the PDF
file format.  It also includes a C library that implements the graphics
capabilities of the PostScript language.  It supports a wide variety of
output file formats and printers.")
   (license license:agpl3+)
   (home-page "http://www.gnu.org/software/ghostscript/")))

(define-public ghostscript/x
  (package (inherit ghostscript)
    (name (string-append (package-name ghostscript) "-with-x"))
    (inputs `(("libxext" ,libxext)
              ("libxt" ,libxt)
              ,@(package-inputs ghostscript)))))

(define (ghostscript-wrapper name ghostscript)
  ;; Return a GHOSTSCRIPT wrapper that provides the 'gs' command.
  ;; See <https://lists.gnu.org/archive/html/guix-devel/2016-07/msg00987.html>.
  (package
    (name name)
    (version (package-version ghostscript))
    (source #f)
    (build-system trivial-build-system)
    (inputs `(("ghostscript" ,ghostscript)))
    (arguments
     `(#:modules ((guix build utils))
       #:builder (begin
                   (use-modules (guix build utils))

                   (let* ((out (assoc-ref %outputs "out"))
                          (bin (string-append out "/bin"))
                          (gs  (assoc-ref %build-inputs "ghostscript")))
                     (mkdir-p bin)
                     (with-directory-excursion bin
                       (symlink (string-append gs "/bin/gsc") "gs")
                       #t)))))
    (synopsis "Wrapper providing Ghostscript's 'gs' command")
    (description
     "This package provides the @command{gs} command, which used to be
provided by Ghostscript itself and no longer is.")
    (license (package-license ghostscript))
    (home-page (package-home-page ghostscript))))

(define-public ghostscript-gs
  (ghostscript-wrapper "ghostscript-gs" ghostscript))

(define-public ghostscript-gs/x
  (ghostscript-wrapper "ghostscript-gs-with-x" ghostscript/x))

(define-public ijs
  (package
   (name "ijs")
   (version "9.14.0")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/ghostscript/gnu-ghostscript-"
                                version ".tar.xz"))
            (sha256 (base32
                     "0q4jj41p0qbr4mgcc9q78f5zs8cm1g57wgryhsm2yq4lfslm3ib1"))))
   (build-system gnu-build-system)
   (native-inputs
    `(("libtool"    ,libtool)
      ("automake"   ,automake)
      ("autoconf"   ,autoconf)))
   (arguments
    `(#:phases
      (alist-cons-after
       'unpack 'autogen
       (lambda _
         ;; need to regenerate macros
         (system* "autoreconf" "-if")
         ;; do not run configure
         (substitute* "autogen.sh"
           (("^.*\\$srcdir/configure.*") ""))
         (system* "bash" "autogen.sh")

         ;; create configure script in ./ijs/
         (chdir "ijs")
         ;; do not run configure
         (substitute* "autogen.sh"
           (("^.*\\$srcdir/configure.*") "")
           (("^ + && echo Now type.*$")  ""))
         (zero? (system* "bash" "autogen.sh")))
       %standard-phases)))
   (synopsis "IJS driver framework for inkjet and other raster devices")
   (description
    "IJS is a protocol for transmission of raster page images.  This package
provides the reference implementation of the raster printer driver
architecture.")
   (license license:expat)
   (home-page "http://www.gnu.org/software/ghostscript/")))

(define-public gs-fonts
  (package
   (name "gs-fonts")
   (version "8.11")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://sourceforge/gs-fonts/gs-fonts/"
                                version
                                "%20%28base%2035%2C%20GPL%29/ghostscript-fonts-std-"
                                version
                                ".tar.gz"))
            (sha256 (base32
                     "00f4l10xd826kak51wsmaz69szzm2wp8a41jasr4jblz25bg7dhf"))))
   (build-system gnu-build-system)
   (arguments
    `(#:tests? #f ; nothing to check, just files to copy
      #:modules ((guix build gnu-build-system)
                 (guix build utils)
                 (srfi srfi-1)) ; for alist-delete
      #:phases
       (alist-delete
        'configure
       (alist-delete
        'build
       (alist-replace
        'install
        (lambda* (#:key outputs #:allow-other-keys)
          (let* ((out (assoc-ref outputs "out"))
                 (dir (string-append out "/share/fonts/type1/ghostscript")))
            (mkdir-p dir)
            (for-each
              (lambda (file)
                (copy-file file (string-append dir "/" file)))
              (find-files "." "pfb|afm"))))
       %standard-phases)))))
   (synopsis "Free replacements for the PostScript fonts")
   (description
    "Ghostscript fonts provides fonts and font metrics customarily distributed with
Ghostscript.  It currently includes the 35 standard PostScript fonts.")
   (license license:gpl2)
   (home-page "http://sourceforge.net/projects/gs-fonts/")))

(define-public libspectre
  (package
   (name "libspectre")
   (version "0.2.7")
   (source (origin
            (method url-fetch)
            (uri (string-append "https://libspectre.freedesktop.org/releases/libspectre-"
                                version ".tar.gz"))
            (sha256 (base32
                     "1v63lqc6bhhxwkpa43qmz8phqs8ci4dhzizyy16d3vkb20m846z8"))))
   (build-system gnu-build-system)
   (inputs `(("ghostscript" ,ghostscript)))
   (native-inputs `(("pkg-config" ,pkg-config)))
   (synopsis "Postscript rendering library")
   (description
    "libspectre is a small library for rendering Postscript documents.
It provides a convenient easy to use API for handling and rendering
Postscript documents.")
   (license license:gpl2+)
   (home-page "http://www.freedesktop.org/wiki/Software/libspectre")))
