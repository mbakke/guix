;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2015 Federico Beffa <beffa@fbengineering.ch>
;;; Copyright © 2015 Paul van der Walt <paul@denknerd.org>
;;; Copyright © 2015 Sou Bunnbu <iyzsong@gmail.com>
;;; Copyright © 2015 Andy Wingo <wingo@igalia.com>
;;; Copyright © 2015 David Hashe <david.hashe@dhashe.com>
;;; Coypright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Fabian Harfert <fhmgufs@web.de>
;;; Copyright © 2016 Kei Kebreau <kei@openmailbox.org>
;;; Copyright © 2016 Patrick Hetu <patrick.hetu@auf.org>
;;; Coypright © 2016 ng0 <ng0@we.make.ritual.n0.is>
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

(define-module (gnu packages gtk)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix utils)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system python)
  #:use-module (guix build-system waf)
  #:use-module (gnu packages)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages check)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages docbook)
  #:use-module (gnu packages enchant)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages image)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages pdf)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages pretty-print)
  #:use-module (gnu packages python)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages cups)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages xdisorg))

(define-public atk
  (package
   (name "atk")
   (version "2.20.0")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnome/sources/" name "/"
                                (version-major+minor version)  "/"
                                name "-" version ".tar.xz"))
            (sha256
             (base32
              "1w1q29yfxcq67j7fyqrfm0l0n1vy4zn539c0sf4ga9d0qkv50fj9"))))
   (build-system gnu-build-system)
   (outputs '("out" "doc"))
   (arguments
    `(#:configure-flags
      (list (string-append "--with-html-dir="
                           (assoc-ref %outputs "doc")
                           "/share/gtk-doc/html"))))
   (propagated-inputs `(("glib" ,glib))) ; required by atk.pc
   (native-inputs
    `(("pkg-config" ,pkg-config)
      ("glib" ,glib "bin")                               ; glib-mkenums, etc.
      ("gobject-introspection" ,gobject-introspection))) ; g-ir-compiler, etc.
   (synopsis "GNOME accessibility toolkit")
   (description
    "ATK provides the set of accessibility interfaces that are implemented
by other toolkits and applications.  Using the ATK interfaces, accessibility
tools have full access to view and control running applications.")
   (license license:lgpl2.0+)
   (home-page "https://developer.gnome.org/atk/")))

(define-public cairo
  (package
   (name "cairo")
   (version "1.14.8")
   (source (origin
            (method url-fetch)
            (uri (string-append "https://cairographics.org/releases/cairo-"
                                version ".tar.xz"))
            (sha256
             (base32
              "082ypjlh03ss5616amgjp9ap3xwwccyh2knyyrj1a4d4x65dkwni"))
            (patches (search-patches "cairo-CVE-2016-9082.patch"))))
   (build-system gnu-build-system)
   (propagated-inputs
    `(("fontconfig" ,fontconfig)
      ("freetype" ,freetype)
      ("glib" ,glib)
      ("libpng" ,libpng)
      ("libx11" ,libx11)
      ("libxext" ,libxext)
      ("libxrender" ,libxrender)
      ("pixman" ,pixman)))
   (inputs
    `(("ghostscript" ,ghostscript)
      ("libspectre" ,libspectre)
      ("poppler" ,poppler)
      ("xextproto" ,xextproto)
      ("zlib" ,zlib)))
   (native-inputs
     `(("pkg-config" ,pkg-config)
      ("python" ,python-wrapper)))
    (arguments
     `(#:tests? #f  ; see http://lists.gnu.org/archive/html/bug-guix/2013-06/msg00085.html
       #:configure-flags '("--enable-tee")))  ; needed for GNU Icecat
   (synopsis "2D graphics library")
   (description
    "Cairo is a 2D graphics library with support for multiple output devices.
Currently supported output targets include the X Window System (via both
Xlib and XCB), Quartz, Win32, image buffers, PostScript, PDF, and SVG file
output.  Experimental backends include OpenGL, BeOS, OS/2, and DirectFB.

Cairo is designed to produce consistent output on all output media while
taking advantage of display hardware acceleration when available
eg. through the X Render Extension).

The cairo API provides operations similar to the drawing operators of
PostScript and PDF.  Operations in cairo including stroking and filling cubic
Bézier splines, transforming and compositing translucent images, and
antialiased text rendering.  All drawing operations can be transformed by any
affine transformation (scale, rotation, shear, etc.).")
   (license license:lgpl2.1) ; or Mozilla Public License 1.1
   (home-page "https://cairographics.org/")))

(define-public cairo-xcb
  (package
    (inherit cairo)
    (name "cairo-xcb")
    (inputs
     `(("mesa" ,mesa)
       ,@(package-inputs cairo)))
    (arguments
     `(#:tests? #f
       #:configure-flags
       '("--enable-xlib-xcb" "--enable-gl" "--enable-egl")))
    (synopsis "2D graphics library (with X11 support)")))

(define-public harfbuzz
  (package
   (name "harfbuzz")
   (version "1.3.4")
   (source (origin
             (method url-fetch)
             (uri (string-append "https://www.freedesktop.org/software/"
                                 "harfbuzz/release/harfbuzz-"
                                 version ".tar.bz2"))
             (sha256
              (base32
               "0ava7y24797k5ps3ghq2ccjjds97ri1gx32v6546a6pgmpyad2ki"))))
   (build-system gnu-build-system)
   (outputs '("out"
              "bin")) ; 160K, only hb-view depend on cairo
   (inputs
    `(("cairo" ,cairo)))
   (propagated-inputs
    ;; There are all in the Requires or Requires.private field of '.pc'.
    `(("glib" ,glib)
      ("graphite2" ,graphite2)
      ("icu4c" ,icu4c)))
   (native-inputs
    `(("gobject-introspection" ,gobject-introspection)
      ("pkg-config" ,pkg-config)
      ("python" ,python-2))) ; incompatible with Python 3 (print syntax)
   (arguments
    `(#:configure-flags `("--with-graphite2"
                          "--with-gobject"
                          ,(string-append
                            "--bindir=" (assoc-ref %outputs "bin") "/bin"))))
   (synopsis "OpenType text shaping engine")
   (description
    "HarfBuzz is an OpenType text shaping engine.")
   (license (license:x11-style "file://COPYING"
                       "See 'COPYING' in the distribution."))
   (home-page "https://www.freedesktop.org/wiki/Software/HarfBuzz/")))

(define-public pango
  (package
   (name "pango")
   (version "1.40.1")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnome/sources/pango/"
                                (version-major+minor version) "/"
                                name "-" version ".tar.xz"))
            (sha256
             (base32
              "0h0sbh0b5kh3lvrxrb82bs86rqakf33a9jakpv33lay7f90zayp2"))))
   (build-system gnu-build-system)
   (propagated-inputs
    `(("cairo" ,cairo)
      ("harfbuzz" ,harfbuzz)))
   (inputs
    `(("zlib" ,zlib)

      ;; Some packages, such as Openbox, expect Pango to be built with the
      ;; optional libxft support.
      ("libxft" ,libxft)))
   (native-inputs
    `(("pkg-config" ,pkg-config)
      ("glib" ,glib "bin")                               ; glib-mkenums, etc.
      ("gobject-introspection" ,gobject-introspection))) ; g-ir-compiler, etc.
   (synopsis "GNOME text and font handling library")
   (description
    "Pango is the core text and font handling library used in GNOME
applications.  It has extensive support for the different writing systems
used throughout the world.")
   (license license:lgpl2.0+)
   (home-page "https://developer.gnome.org/pango/")))

(define-public pangox-compat
  (package
    (name "pangox-compat")
    (version "0.0.2")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnome/sources/" name "/"
                                 (version-major+minor version)  "/"
                                 name "-" version ".tar.xz"))
             (sha256
              (base32
               "0ip0ziys6mrqqmz4n71ays0kf5cs1xflj1gfpvs4fgy2nsrr482m"))))
    (build-system gnu-build-system)
    (inputs
     `(("glib" ,glib)
       ("pango" ,pango)))
    (native-inputs
     `(("intltool" ,intltool)
       ("pkg-config" ,pkg-config)))
    (home-page "https://developer.gnome.org/pango")
    (synopsis "Obsolete pango functions")
    (description  "Pangox was a X backend to pango.  It is now obsolete and no
longer provided by recent pango releases.  pangox-compat provides the
functions which were removed.")
    (license license:lgpl2.0+)))

(define-public ganv
  (package
    (name "ganv")
    (version "1.4.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://download.drobilla.net/ganv-"
                                  version ".tar.bz2"))
              (sha256
               (base32
                "0g7s5mp14qgbfjdql0k1s8464r21g47ssn5dws6jazsnw6njhl0l"))))
    (build-system waf-build-system)
    (arguments
     `(#:phases (alist-cons-before
                 'configure 'set-flags
                 (lambda* (#:key outputs #:allow-other-keys)
                   ;; Compile with C++11, required by gtkmm.
                   (setenv "CXXFLAGS" "-std=c++11")
                   ;; Allow 'bin/ganv_bench' to find libganv-1.so.
                   (setenv "LDFLAGS"
                           (string-append "-Wl,-rpath="
                                          (assoc-ref outputs "out") "/lib")))
                 %standard-phases)
       #:tests? #f)) ; no check target
    (inputs
     `(("gtk" ,gtk+-2)
       ("gtkmm" ,gtkmm-2)))
    (native-inputs
     `(("glib" ,glib "bin")             ; for glib-genmarshal, etc.
       ("pkg-config" ,pkg-config)))
    (home-page "http://drobilla.net/software/ganv/")
    (synopsis "GTK+ widget for interactive graph-like environments")
    (description
     "Ganv is an interactive GTK+ widget for interactive “boxes and lines” or
graph-like environments, e.g. modular synths or finite state machine
diagrams.")
    (license license:gpl3+)))

(define-public ganv-devel
  (let ((commit "31685d283e9b811b61014f820c42807f4effa071")
        (revision "1"))
    (package
      (inherit ganv)
      (name "ganv")
      (version (string-append "1.4.2-" revision "."
                              (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "http://git.drobilla.net/ganv.git")
                      (commit commit)))
                (sha256
                 (base32
                  "0xmbykdl42jn9cgzrqrys5lng67d26nk5xq10wkkvjqldiwdck56")))))))

(define-public gtksourceview-2
  (package
    (name "gtksourceview")
    (version "2.10.5") ; This is the last version which builds against gtk+2
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnome/sources/" name "/"
                                  (version-major+minor version)  "/"
                                  name "-" version ".tar.bz2"))
              (sha256
               (base32
                "07hrabhpl6n8ajz10s0d960jdwndxs87szxyn428mpxi8cvpg1f5"))))
    (build-system gnu-build-system)
    (inputs
     `(("gtk" ,gtk+-2)
       ;; These two are needed only to allow the tests to run successfully.
       ("xorg-server" ,xorg-server)
       ("shared-mime-info" ,shared-mime-info)))
    (native-inputs
     `(("intltool" ,intltool)
       ("glib" ,glib "bin")             ; for glib-genmarshal, etc.
       ("pkg-config" ,pkg-config)))
    (propagated-inputs
     ;; As per the pkg-config file.
     `(("libxml2" ,libxml2)))
    (arguments
     `(#:phases
       ;; Unfortunately, some of the tests in "make check" are highly dependent
       ;; on the environment therefore, some black magic is required.
       (alist-cons-before
        'check 'start-xserver
        (lambda* (#:key inputs #:allow-other-keys)
          (let ((xorg-server (assoc-ref inputs "xorg-server"))
                (mime (assoc-ref inputs "shared-mime-info")))

            ;; There must be a running X server and make check doesn't start one.
            ;; Therefore we must do it.
            (system (format #f "~a/bin/Xvfb :1 &" xorg-server))
            (setenv "DISPLAY" ":1")

            ;; The .lang files must be found in $XDG_DATA_HOME/gtksourceview-2.0
            (system "ln -s gtksourceview gtksourceview-2.0")
            (setenv "XDG_DATA_HOME" (getcwd))

            ;; Finally, the mimetypes must be available.
            (setenv "XDG_DATA_DIRS" (string-append mime "/share/")) ))
        %standard-phases)))
    (synopsis "Widget that extends the standard GTK+ 2.x 'GtkTextView' widget")
    (description
     "GtkSourceView is a portable C library that extends the standard GTK+
framework for multiline text editing with support for configurable syntax
highlighting, unlimited undo/redo, search and replace, a completion framework,
printing and other features typical of a source code editor.")
    (license license:lgpl2.0+)
    (home-page "https://developer.gnome.org/gtksourceview/")))

(define-public gtksourceview
 (package
   (name "gtksourceview")
   (version "3.20.4")
   (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnome/sources/" name "/"
                                 (version-major+minor version) "/"
                                 name "-" version ".tar.xz"))
             (sha256
              (base32
               "009xag7df07ngav2wzs0rdrrx4s2m6ahx93pxzc2p1pkbz4nl3ks"))))
   (build-system gnu-build-system)
   (arguments
    '(#:phases
      (modify-phases %standard-phases
        (add-before
         'check 'pre-check
         (lambda* (#:key inputs #:allow-other-keys)
           (let ((xorg-server (assoc-ref inputs "xorg-server")))
             ;; Tests require a running X server.
             (system (format #f "~a/bin/Xvfb :1 &" xorg-server))
             (setenv "DISPLAY" ":1")
             ;; For the missing /etc/machine-id.
             (setenv "DBUS_FATAL_WARNINGS" "0")
             #t))))))
   (native-inputs
    `(("glib:bin" ,glib "bin") ; for glib-genmarshal, etc.
      ("intltool" ,intltool)
      ("itstool" ,itstool)
      ("gobject-introspection" ,gobject-introspection)
      ("pkg-config" ,pkg-config)
      ("vala" ,vala)
      ;; For testing.
      ("xorg-server" ,xorg-server)
      ("shared-mime-info" ,shared-mime-info)))
   (propagated-inputs
    ;; gtksourceview-3.0.pc refers to all these.
    `(("glib" ,glib)
      ("gtk+" ,gtk+)
      ("libxml2" ,libxml2)))
   (home-page "https://wiki.gnome.org/Projects/GtkSourceView")
   (synopsis "GNOME source code widget")
   (description "GtkSourceView is a text widget that extends the standard
GTK+ text widget GtkTextView.  It improves GtkTextView by implementing syntax
highlighting and other features typical of a source code editor.")
   (license license:lgpl2.1+)))

(define-public gdk-pixbuf
  (package
   (name "gdk-pixbuf")
   (version "2.34.0")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnome/sources/" name "/"
                                (version-major+minor version)  "/"
                                name "-" version ".tar.xz"))
            (sha256
             (base32
              "0yc8indbl3hf18z6x6kjg59xp9sngm1d8vmz4c7bs6g27qw5npnm"))))
   (build-system gnu-build-system)
   (arguments
    '(#:configure-flags '("--with-x11")
      #:phases
      (modify-phases %standard-phases
        (add-after
         'unpack 'disable-failing-tests
         (lambda _
           (substitute* "tests/Makefile.in"
             ;; XXX FIXME: This test fails on armhf machines with:
             ;; SKIP Not enough memory to load bitmap image
             ;; ERROR: cve-2015-4491 - too few tests run (expected 4, got 2)
             (("cve-2015-4491\\$\\(EXEEXT\\) ") "")
             ;; XXX FIXME: This test fails with:
             ;; ERROR:pixbuf-jpeg.c:74:test_type9_rotation_exif_tag:
             ;; assertion failed (error == NULL): Data differ
             ;; (gdk-pixbuf-error-quark, 0)
             (("pixbuf-jpeg\\$\\(EXEEXT\\) ") ""))
           #t)))))
   (propagated-inputs
    `(;; Required by gdk-pixbuf-2.0.pc
      ("glib" ,glib)
      ("libpng" ,libpng)
      ;; Used for testing and required at runtime.
      ("shared-mime-info" ,shared-mime-info)))
   (inputs
    `(("libjpeg" ,libjpeg)
      ("libtiff" ,libtiff)
      ("libx11"  ,libx11)))
   (native-inputs
     `(("pkg-config" ,pkg-config)
       ("glib" ,glib "bin")                               ; glib-mkenums, etc.
       ("gobject-introspection" ,gobject-introspection))) ; g-ir-compiler, etc.
   (synopsis "GNOME image loading and manipulation library")
   (description
    "GdkPixbuf is a library for image loading and manipulation developed
in the GNOME project.")
   (license license:lgpl2.0+)
   (home-page "https://developer.gnome.org/gdk-pixbuf/")))

;; To build gdk-pixbuf with SVG support, we need librsvg, and librsvg depends
;; on gdk-pixbuf, so this new varibale.  Also, librsvg adds 90MiB to the
;; closure size.
(define-public gdk-pixbuf+svg
  (package (inherit gdk-pixbuf)
    (name "gdk-pixbuf+svg")
    (inputs
     `(("librsvg" ,librsvg)
       ,@(package-inputs gdk-pixbuf)))
    (arguments
     '(#:configure-flags '("--with-x11")
       #:tests? #f ; tested by the gdk-pixbuf package already
       #:phases
       (modify-phases %standard-phases
         (add-after 'install 'register-svg-loader
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out     (assoc-ref outputs "out"))
                    (librsvg (assoc-ref inputs "librsvg"))
                    (loaders
                     (append
                      (find-files out "^libpixbufloader-.*\\.so$")
                      (find-files librsvg "^libpixbufloader-.*\\.so$")))
                    (gdk-pixbuf-query-loaders
                     (string-append out "/bin/gdk-pixbuf-query-loaders")))
               (zero? (apply system* `(,gdk-pixbuf-query-loaders
                                       "--update-cache" ,@loaders)))))))))
    (synopsis
     "GNOME image loading and manipulation library, with SVG support")))

(define-public at-spi2-core
  (package
   (name "at-spi2-core")
   (version "2.20.2")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnome/sources/" name "/"
                                (version-major+minor version)  "/"
                                name "-" version ".tar.xz"))
            (sha256
             (base32
              "0hx12snd9as4cq99ka3bn056xdf13f87pd1ilp6177qk8ffxx948"))))
   (build-system gnu-build-system)
   (outputs '("out" "doc"))
   (arguments
    '(#:configure-flags
      (list (string-append "--with-html-dir="
                           (assoc-ref %outputs "doc")
                           "/share/gtk-doc/html"))
      #:phases
      (modify-phases %standard-phases
        (replace 'check
                 ;; Run test-suite under a dbus session.
                 (lambda _
                   ;; Don't fail on missing  '/etc/machine-id'.
                   (setenv "DBUS_FATAL_WARNINGS" "0")
                   (zero? (system* "dbus-launch" "make" "check")))))))
   (propagated-inputs
    ;; atspi-2.pc refers to all these.
    `(("dbus" ,dbus)
      ("glib" ,glib)))
   (inputs
    `(("libxi" ,libxi)
      ("libxtst" ,libxtst)))
   (native-inputs
    `(("gobject-introspection" ,gobject-introspection)
      ("intltool" ,intltool)
      ("pkg-config" ,pkg-config)))
   (synopsis "Assistive Technology Service Provider Interface, core components")
   (description
    "The Assistive Technology Service Provider Interface, core components,
is part of the GNOME accessibility project.")
   (license license:lgpl2.0+)
   (home-page "https://projects.gnome.org/accessibility/")))

(define-public at-spi2-atk
  (package
   (name "at-spi2-atk")
   (version "2.20.1")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnome/sources/" name "/"
                                (version-major+minor version)  "/"
                                name "-" version ".tar.xz"))
            (sha256
             (base32
              "13mzfwra0izmkzn7dsdgy5zj19n8izp0wdy7w1yg9s0qx6aafn13"))))
   (build-system gnu-build-system)
   (arguments
    '(#:phases
      (modify-phases %standard-phases
        (replace 'check
                 ;; Run test-suite under a dbus session.
                 (lambda _
                   (setenv "DBUS_FATAL_WARNINGS" "0")
                   (zero? (system* "dbus-launch" "make" "check")))))))
   (propagated-inputs
    `(("at-spi2-core" ,at-spi2-core))) ; required by atk-bridge-2.0.pc
   (inputs
    `(("atk" ,atk)))
   (native-inputs
    `(("dbus" ,dbus) ; for testing
      ("pkg-config" ,pkg-config)))
   (synopsis "Assistive Technology Service Provider Interface, ATK bindings")
   (description
    "The Assistive Technology Service Provider Interface
is part of the GNOME accessibility project.")
   (license license:lgpl2.0+)
   (home-page "https://projects.gnome.org/accessibility/")))

(define-public gtk+-2
  (package
   (name "gtk+")
   (version "2.24.31")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnome/sources/" name "/"
                                (version-major+minor version)  "/"
                                name "-" version ".tar.xz"))
            (sha256
             (base32
              "0n26jm09n03nqbd00d2ij63xrby3vik56sk5yj6w1vy768kr5hb8"))
            (patches (search-patches "gtk2-respect-GUIX_GTK2_PATH.patch"
                                     "gtk2-respect-GUIX_GTK2_IM_MODULE_FILE.patch"
                                     "gtk2-theme-paths.patch"))))
   (build-system gnu-build-system)
   (outputs '("out" "doc"))
   (propagated-inputs
    `(("atk" ,atk)
      ("gdk-pixbuf" ,gdk-pixbuf+svg)
      ("pango" ,pango)))
   (inputs
    `(("cups" ,cups)
      ("libxcomposite" ,libxcomposite)
      ("libxcursor" ,libxcursor)
      ("libxdamage" ,libxdamage)
      ("libxi" ,libxi)
      ("libxinerama" ,libxinerama)
      ("libxrandr" ,libxrandr)))
   (native-inputs
    `(("perl" ,perl)
      ("gettext" ,gettext-minimal)
      ("glib" ,glib "bin")
      ("gobject-introspection" ,gobject-introspection)
      ("pkg-config" ,pkg-config)
      ("python-wrapper" ,python-wrapper)))
   (arguments
    `(#:configure-flags
      (list "--with-xinput=yes"
            (string-append "--with-html-dir="
                           (assoc-ref %outputs "doc")
                           "/share/gtk-doc/html"))
      #:phases
      (alist-cons-before
       'configure 'disable-tests
       (lambda _
         ;; FIXME: re-enable tests requiring an X server
         (substitute* "gtk/Makefile.in"
           (("SUBDIRS = theme-bits . tests") "SUBDIRS = theme-bits .")))
       %standard-phases)))
   (native-search-paths
    (list (search-path-specification
           (variable "GUIX_GTK2_PATH")
           (files '("lib/gtk-2.0")))))
   (synopsis "Cross-platform toolkit for creating graphical user interfaces")
   (description
    "GTK+, or the GIMP Toolkit, is a multi-platform toolkit for creating
graphical user interfaces.  Offering a complete set of widgets, GTK+ is
suitable for projects ranging from small one-off tools to complete
application suites.")
   (license license:lgpl2.0+)
   (home-page "http://www.gtk.org/")))

(define-public gtk+
  (package (inherit gtk+-2)
   (name "gtk+")
   (version "3.20.9")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnome/sources/" name "/"
                                (version-major+minor version)  "/"
                                name "-" version ".tar.xz"))
            (sha256
             (base32
              "05xcwvy68p7f4hdhi4bgdm3aycvqqr4pr5kkkr8ba91l5yx0k9l3"))
            (patches (search-patches "gtk3-respect-GUIX_GTK3_PATH.patch"
                                     "gtk3-respect-GUIX_GTK3_IM_MODULE_FILE.patch"))))
   (outputs '("out" "bin" "doc"))
   (propagated-inputs
    `(("at-spi2-atk" ,at-spi2-atk)
      ("atk" ,atk)
      ("gdk-pixbuf" ,gdk-pixbuf+svg)
      ("libepoxy" ,libepoxy)
      ("libxcursor" ,libxcursor)
      ("libxi" ,libxi)
      ("libxinerama" ,libxinerama)
      ("libxdamage" ,libxdamage)
      ("pango" ,pango)))
   (inputs
    `(("libxml2" ,libxml2)
      ;; XXX: colord depends on mozjs (through polkit), which fails on
      ;;      on non-intel systems now.
      ;;("colord" ,colord)
      ("cups" ,cups)                            ;for printing support
      ;; XXX: rest depends on p11-kit, which fails on mips64el now.
      ;;("rest" ,rest)
      ("json-glib" ,json-glib)))
   (native-inputs
    `(("perl" ,perl)
      ("glib" ,glib "bin")
      ("gettext" ,gettext-minimal)
      ("pkg-config" ,pkg-config)
      ("gobject-introspection" ,gobject-introspection)
      ("python-wrapper" ,python-wrapper)
      ("xorg-server" ,xorg-server)))
   (arguments
    `(;; 47 MiB goes to "out" (24 of which is locale data!), and 26 MiB goes
      ;; to "doc".
      #:configure-flags (list (string-append "--with-html-dir="
                                             (assoc-ref %outputs "doc")
                                             "/share/gtk-doc/html"))
      #:phases (modify-phases %standard-phases
        (add-before 'configure 'pre-configure
          (lambda _
            ;; Disable most tests, failing in the chroot with the message:
            ;; D-Bus library appears to be incorrectly set up; failed to read
            ;; machine uuid: Failed to open "/etc/machine-id": No such file or
            ;; directory.
            ;; See the manual page for dbus-uuidgen to correct this issue.
            (substitute* "testsuite/Makefile.in"
              (("SUBDIRS = gdk gtk a11y css reftests")
               "SUBDIRS = gdk"))
            #t))
        (add-after 'install 'move-desktop-files
          ;; Move desktop files into 'bin' to avoid cycle references.
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((out (assoc-ref outputs "out"))
                  (bin (assoc-ref outputs "bin")))
              (mkdir-p (string-append bin "/share"))
              (rename-file (string-append out "/share/applications")
                           (string-append bin "/share/applications"))
              #t))))))
   (native-search-paths
    (list (search-path-specification
           (variable "GUIX_GTK3_PATH")
           (files '("lib/gtk-3.0")))))))

;;;
;;; Guile bindings.
;;;

(define-public guile-cairo
  (package
    (name "guile-cairo")
    (version "1.4.1")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "http://download.gna.org/guile-cairo/guile-cairo-"
                   version
                   ".tar.gz"))
             (sha256
              (base32
               "1f5nd9n46n6cwfl1byjml02q3y2hgn7nkx98km1czgwarxl7ws3x"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (alist-cons-before
                 'configure 'set-module-directory
                 (lambda* (#:key outputs #:allow-other-keys)
                   ;; Install modules under $out/share/guile/site/2.0.
                   (let ((out (assoc-ref outputs "out")))
                     (substitute* "Makefile.in"
                       (("scmdir = ([[:graph:]]+).*" _ value)
                        (string-append "scmdir = " value "/2.0\n")))
                     (substitute* "cairo/Makefile.in"
                       (("moduledir = ([[:graph:]]+).*" _ value)
                        (string-append "moduledir = "
                                       "$(prefix)/share/guile/site/2.0/cairo\n'")))))
                 (alist-cons-after
                  'install 'install-missing-file
                  (lambda* (#:key outputs #:allow-other-keys)
                    ;; By default 'vector-types.scm' is not installed, so do
                    ;; it here.
                    (let ((out (assoc-ref outputs "out")))
                      (copy-file "cairo/vector-types.scm"
                                 (string-append out "/share/guile/site/2.0"
                                                "/cairo/vector-types.scm"))))
                  %standard-phases))))
    (inputs
     `(("guile-lib" ,guile-lib)
       ("expat" ,expat)
       ("guile" ,guile-2.0)))
    (propagated-inputs
     ;; The .pc file refers to 'cairo'.
     `(("cairo" ,cairo)))
    (native-inputs
      `(("pkg-config" ,pkg-config)))
    (home-page "http://www.nongnu.org/guile-cairo/")
    (synopsis "Cairo bindings for GNU Guile")
    (description
     "Guile-Cairo wraps the Cairo graphics library for Guile Scheme.
Guile-Cairo is complete, wrapping almost all of the Cairo API.  It is API
stable, providing a firm base on which to do graphics work.  Finally, and
importantly, it is pleasant to use.  You get a powerful and well-maintained
graphics library with all of the benefits of Scheme: memory management,
exceptions, macros, and a dynamic programming environment.")
    (license license:lgpl3+)))

(define-public guile-rsvg
  (package
    (name "guile-rsvg")
    (version "2.18.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://wingolog.org/pub/guile-rsvg/"
                                  name "-" version ".tar.gz"))
              (sha256
               (base32
                "136f236iw3yrrz6pkkp1ma9c5mrs5icqha6pnawinqpk892r3jh7"))
              (patches (search-patches "guile-rsvg-pkgconfig.patch"))
              (modules '((guix build utils)))
              (snippet
               '(substitute* (find-files "." "Makefile\\.am")
                  (("/share/guile/site")
                   "/share/guile/site/2.0")))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (add-before 'configure 'bootstrap
                              (lambda _
                                (zero? (system* "autoreconf" "-vfi")))))))
    (native-inputs `(("pkg-config" ,pkg-config)
                     ("autoconf" ,autoconf)
                     ("automake" ,automake)
                     ("libtool" ,libtool)
                     ("texinfo" ,texinfo)))
    (inputs `(("guile" ,guile-2.0)
              ("librsvg" ,librsvg)
              ("guile-lib" ,guile-lib)))          ;for (unit-test)
    (propagated-inputs `(("guile-cairo" ,guile-cairo)))
    (synopsis "Render SVG images using Cairo from Guile")
    (description
     "Guile-RSVG wraps the RSVG library for Guile, allowing you to render SVG
images onto Cairo surfaces.")
    (home-page "http://wingolog.org/projects/guile-rsvg/")
    (license license:lgpl2.1+)))

(define-public guile-present
  (package
    (name "guile-present")
    (version "0.3.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://wingolog.org/pub/guile-present/"
                                  "guile-present-" version ".tar.gz"))
              (sha256
               (base32
                "1qam447m05sxxv6x8dlzg7qnyfc4dh8apjw1idpfhpns671gfr6m"))
              (patches (search-patches "guile-present-coding.patch"))
              (modules '((guix build utils)))
              (snippet
               '(substitute* "Makefile.in"
                  (("godir = .*$")
                   "godir = $(moddir)\n")))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (alist-cons-after
                 'install 'post-install
                 (lambda* (#:key inputs outputs #:allow-other-keys)
                   (let* ((out   (assoc-ref outputs "out"))
                          (bin   (string-append out "/bin"))
                          (guile (assoc-ref inputs "guile")))
                     (substitute* (find-files bin ".*")
                       (("guile")
                        (string-append guile "/bin/guile -L "
                                       out "/share/guile/site/2.0 -C "
                                       out "/share/guile/site/2.0 ")))))
                 %standard-phases)))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (inputs `(("guile" ,guile-2.0)))
    (propagated-inputs
     ;; These are used by the (present …) modules.
     `(("guile-lib" ,guile-lib)
       ("guile-cairo" ,guile-cairo)
       ("guile-rsvg" ,guile-rsvg)))
    (home-page "http://wingolog.org/software/guile-present/")
    (synopsis "Create SVG or PDF presentations in Guile")
    (description
     "Guile-Present defines a declarative vocabulary for presentations,
together with tools to render presentation documents as SVG or PDF.
Guile-Present can be used to make presentations programmatically, but also
includes a tools to generate PDF presentations out of Org mode and Texinfo
documents.")
    (license license:lgpl3+)))

(define-public guile-gnome
   (package
    (name "guile-gnome")
    (version "2.16.4")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "mirror://gnu/" name
                              "/guile-gnome-platform/guile-gnome-platform-"
                              version ".tar.gz"))
             (sha256
              (base32
               "1hqnqbb2lmr3hgbcv9kds1himn3av6h0lkk0zll8agcrsn7d9axd"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("atk" ,atk)
       ;;("corba" ,corba) ; not packaged yet
       ("gconf" ,gconf)
       ("gobject-introspection" ,gobject-introspection)
       ;;("gthread" ,gthread) ; not packaged yet
       ("gnome-vfs" ,gnome-vfs)
       ("gdk-pixbuf" ,gdk-pixbuf)
       ("gtk+" ,gtk+-2)
       ("libglade" ,libglade)
       ("libgnome" ,libgnome)
       ("libgnomecanvas" ,libgnomecanvas)
       ("libgnomeui" ,libgnomeui)
       ("pango" ,pango)
       ("libffi" ,libffi)
       ("glib" ,glib)))
    (inputs `(("guile" ,guile-2.0)))
    (propagated-inputs
     `(("guile-cairo" ,guile-cairo)
       ("g-wrap" ,g-wrap)
       ("guile-lib" ,guile-lib)))
    (arguments
      `(#:tests? #f                               ;FIXME
        #:phases (modify-phases %standard-phases
                   (add-before 'configure 'pre-configure
                     (lambda* (#:key outputs #:allow-other-keys)
                       (let ((out (assoc-ref outputs "out")))
                         (substitute* (find-files "." "^Makefile.in$")
                           (("guilesite :=.*guile/site" all)
                            (string-append all "/2.0")))
                         #t))))))
    (outputs '("out" "debug"))
    (synopsis "Guile interface for GTK+ programming for GNOME")
    (description
     "Includes guile-clutter, guile-gnome-gstreamer,
guile-gnome-platform (GNOME developer libraries), and guile-gtksourceview.")
    (home-page "http://www.gnu.org/software/guile-gnome/")
    (license license:gpl2+)))

;;;
;;; C++ bindings.
;;;

(define-public cairomm
  (package
    (name "cairomm")
    (version "1.12.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnome/sources/cairomm/"
                                  (version-major+minor version) "/"
                                  name "-" version ".tar.xz"))
              (sha256
               (base32
                "1rmgs6zjj2vaxh9hsa0944m23fdn1psycqh7bi984qd8jj1xljm5"))))
    (build-system gnu-build-system)
    (arguments
     ;; The examples lack -lcairo.
     '(#:make-flags '("LDFLAGS=-lcairo")))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("libsigc++" ,libsigc++)
       ("freetype" ,freetype)
       ("fontconfig" ,fontconfig)
       ("cairo" ,cairo)))
    (home-page "http://cairographics.org/")
    (synopsis "C++ bindings to the Cairo 2D graphics library")
    (description
     "Cairomm provides a C++ programming interface to the Cairo 2D graphics
library.")
    (license license:lgpl2.0+)))

(define-public pangomm
  (package
    (name "pangomm")
    (version "2.40.1")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnome/sources/" name "/"
                                 (version-major+minor version)  "/"
                                 name "-" version ".tar.xz"))
             (sha256
              (base32
               "1bz3gciff23bpw9bqc4v2l3lkq9w7394v3a4jxkvx0ap5lmfwqlp"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("cairo" ,cairo)
       ("cairomm" ,cairomm)
       ("glibmm" ,glibmm)
       ("pango" ,pango)))
    (home-page "http://www.pango.org/")
    (synopsis "C++ interface to the Pango text rendering library")
    (description
     "Pangomm provides a C++ programming interface to the Pango text rendering
library.")
    (license license:lgpl2.1+)))

(define-public atkmm
  (package
    (name "atkmm")
    (version "2.24.2")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnome/sources/" name "/"
                                 (version-major+minor version)  "/"
                                 name "-" version ".tar.xz"))
             (sha256
              (base32
               "1gaqwhviadsmy0fsr47686yglv1p4mpkamj0in127bz2b5bki5gz"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("glibmm" ,glibmm) ("atk" ,atk)))
    (home-page "http://www.gtkmm.org")
    (synopsis "C++ interface to the ATK accessibility library")
    (description
     "ATKmm provides a C++ programming interface to the ATK accessibility
toolkit.")
    (license license:lgpl2.1+)))

(define-public gtkmm
  (package
    (name "gtkmm")
    (version "3.20.1")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnome/sources/" name "/"
                                 (version-major+minor version)  "/"
                                 name "-" version ".tar.xz"))
             (sha256
              (base32
               "04n631a127pyidaz82ypdy9syq1hzj636r32y9hyr9kcfnwf2785"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)
                     ("glib" ,glib "bin")        ;for 'glib-compile-resources'
                     ("xorg-server" ,xorg-server)))
    (propagated-inputs
     `(("pangomm" ,pangomm)
       ("cairomm" ,cairomm)
       ("atkmm" ,atkmm)
       ("gtk+" ,gtk+)
       ("glibmm" ,glibmm)))
    (arguments
     '(#:phases (modify-phases %standard-phases
                  (add-before 'check 'run-xvfb
                    (lambda* (#:key inputs #:allow-other-keys)
                      (let ((xorg-server (assoc-ref inputs "xorg-server")))
                        ;; Tests such as 'object_move/test' require a running
                        ;; X server.
                        (system (string-append xorg-server "/bin/Xvfb :1 &"))
                        (setenv "DISPLAY" ":1")
                        ;; Don't fail because of the missing /etc/machine-id.
                        (setenv "DBUS_FATAL_WARNINGS" "0")
                        #t))))))
    (home-page "http://gtkmm.org/")
    (synopsis
     "C++ interface to the GTK+ graphical user interface library")
    (description
     "gtkmm is the official C++ interface for the popular GUI library GTK+.
Highlights include typesafe callbacks, and a comprehensive set of widgets that
are easily extensible via inheritance.  You can create user interfaces either
in code or with the Glade User Interface designer, using libglademm.  There's
extensive documentation, including API reference and a tutorial.")
    (license license:lgpl2.1+)))


(define-public gtkmm-2
  (package (inherit gtkmm)
    (name "gtkmm")
    (version "2.24.4")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnome/sources/" name "/"
                                 (version-major+minor version)  "/"
                                 name "-" version ".tar.xz"))
             (sha256
              (base32
               "1vpmjqv0aqb1ds0xi6nigxnhlr0c74090xzi15b92amlzkrjyfj4"))))
    (arguments
     '(#:configure-flags '("CPPFLAGS=-std=c++11"))) ; required by libsigc++
    (native-inputs `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("pangomm" ,pangomm)
       ("cairomm" ,cairomm)
       ("atkmm" ,atkmm)
       ("gtk+" ,gtk+-2)
       ("glibmm" ,glibmm)))))

(define-public python-pycairo
  (package
    (name "python-pycairo")
    (version "1.10.0")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "http://cairographics.org/releases/pycairo-"
                          version ".tar.bz2"))
      (sha256
       (base32
        "1gjkf8x6hyx1skq3hhwcbvwifxvrf9qxis5vx8x5igmmgs70g94s"))
      (patches (search-patches "pycairo-wscript.patch"))))
    (build-system waf-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-waf" ,python-waf)))
    (propagated-inputs                  ;pycairo.pc references cairo
     `(("cairo" ,cairo)))
    (arguments
     `(#:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-before
          'configure 'patch-waf
          (lambda* (#:key inputs #:allow-other-keys)
            ;; The bundled `waf' doesn't work with python-3.4.x.
            (copy-file (assoc-ref %build-inputs "python-waf") "./waf"))))))
    (home-page "http://cairographics.org/pycairo/")
    (synopsis "Python bindings for cairo")
    (description
     "Pycairo is a set of Python bindings for the Cairo graphics library.")
    (license license:lgpl3+)
    (properties `((python2-variant . ,(delay python2-pycairo))))))

(define-public python2-pycairo
  (package (inherit (strip-python2-variant python-pycairo))
    (name "python2-pycairo")
    (version "1.10.0")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "http://cairographics.org/releases/py2cairo-"
                          version ".tar.bz2"))
      (sha256
       (base32
        "0cblk919wh6w0pgb45zf48xwxykfif16qk264yga7h9fdkq3j16k"))))
    (arguments
     `(#:python ,python-2
       ,@(substitute-keyword-arguments (package-arguments python-pycairo)
           ((#:phases phases)
            `(alist-delete 'patch-waf ,phases))
           ((#:native-inputs native-inputs)
            `(alist-delete "python-waf" ,native-inputs)))))
    ;; Dual-licensed under LGPL 2.1 or Mozilla Public License 1.1
    (license (list license:lgpl2.1 license:mpl1.1))))

(define-public python2-pygtk
  (package
    (name "python2-pygtk")
    (version "2.24.0")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnome/sources"
                          "/pygtk/" (version-major+minor version)
                          "/pygtk-" version ".tar.bz2"))
      (sha256
       (base32
        "04k942gn8vl95kwf0qskkv6npclfm31d78ljkrkgyqxxcni1w76d"))))
    (build-system gnu-build-system)
    (outputs '("out"
               "doc"))                            ;13 MiB of gtk-doc HTML
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("python" ,python-2)
       ("libglade" ,libglade)
       ("glib"   ,glib)))
    (propagated-inputs
     `(("python-pycairo"   ,python2-pycairo)     ;loaded at runtime
       ("python-pygobject" ,python2-pygobject-2) ;referenced in pc file
       ("gtk+"             ,gtk+-2)))
    (arguments
     `(#:tests? #f
       #:phases (modify-phases %standard-phases
                  (add-before 'configure 'set-gtk-doc-directory
                    (lambda* (#:key outputs #:allow-other-keys)
                      ;; Install documentation to "doc".
                      (let ((doc (assoc-ref outputs "doc")))
                        (substitute* "docs/Makefile.in"
                          (("TARGET_DIR = \\$\\(datadir\\)")
                           (string-append "TARGET_DIR = " doc))))))
                  (add-after 'configure 'fix-codegen
                    (lambda* (#:key inputs #:allow-other-keys)
                      (substitute* "pygtk-codegen-2.0"
                        (("^prefix=.*$")
                         (string-append
                          "prefix="
                          (assoc-ref inputs "python-pygobject") "\n")))))
                  (add-after 'install 'install-pth
                    (lambda* (#:key inputs outputs #:allow-other-keys)
                      ;; pygtk's modules are stored in a subdirectory of
                      ;; python's site-packages directory.  Add a .pth file so
                      ;; that python will add that subdirectory to its module
                      ;; search path.
                      (let* ((out    (assoc-ref outputs "out"))
                             (site   (string-append out "/lib/python"
                                                    ,(version-major+minor
                                                      (package-version python-2))
                                                    "/site-packages")))
                        (call-with-output-file (string-append site "/pygtk.pth")
                          (lambda (port)
                            (format port "gtk-2.0~%")))))))))
    (home-page "http://www.pygtk.org/")
    (synopsis "Python bindings for GTK+")
    (description
     "PyGTK allows you to write full featured GTK programs in Python.  It is
targetted at GTK 2.x, and can be used in conjunction with gnome-python to
write GNOME applications.")
    (license license:lgpl2.1+)))

(define-public girara
  (package
    (name "girara")
    (version "0.2.6")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "https://pwmt.org/projects/girara/download/girara-"
                              version ".tar.gz"))
              (sha256
               (base32
                "03wsxj27hvcbs3x96nah7j3paclifwlfag8kdph4kldl48srp9pb"))))
    (native-inputs `(("pkg-config" ,pkg-config)
                     ("gettext" ,gettext-minimal)))
    (inputs `(("gtk+" ,gtk+)
              ("check" ,check)))
    (arguments
     `(#:make-flags
       `(,(string-append "PREFIX=" (assoc-ref %outputs "out"))
         "COLOR=0" "CC=gcc")
       #:test-target "test"
       #:tests? #f ; Tests fail with "Gtk cannot open display:"
       #:phases
       (alist-delete 'configure %standard-phases)))
    (build-system gnu-build-system)
    (home-page "https://pwmt.org/projects/girara/")
    (synopsis "Library for minimalistic gtk+3 user interfaces")
    (description "Girara is a library that implements a user interface that
focuses on simplicity and minimalism.  Currently based on GTK+, a
cross-platform widget toolkit, it provides an interface that focuses on three
main components: a so-called view widget that represents the actual
application, an input bar that is used to execute commands of the
application and the status bar which provides the user with current
information.")
    (license license:zlib)))

(define-public gtk-doc
  (package
    (name "gtk-doc")
    (version "1.25")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnome/sources/" name "/"
                                  (version-major+minor version) "/"
                                  name "-" version ".tar.xz"))
              (sha256
               (base32
                "0hpxcij9xx9ny3gs9p0iz4r8zslw8wqymbyababiyl7603a6x90y"))))
    (build-system gnu-build-system)
    (arguments
     `(#:parallel-tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-before
             'configure 'fix-docbook
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "configure"
               ;; The configure check is overzealous about making sure that
               ;; things are in place -- it uses the xmlcatalog tool to make
               ;; sure that docbook-xsl is available, but this tool can only
               ;; look in one catalog file, unlike the $XML_CATALOG_FILES
               ;; variable that Guix defines.  Fool the test by using the
               ;; docbook-xsl catalog explicitly and get on with life.
               (("\"\\$XML_CATALOG_FILE\" \
\"http://docbook.sourceforge.net/release/xsl/")
                (string-append (car (find-files (assoc-ref inputs "docbook-xsl")
                                                "^catalog.xml$"))
                               " \"http://docbook.sourceforge.net/release/xsl/")))
             #t)))
       #:configure-flags
       (list (string-append "--with-xml-catalog="
                            (assoc-ref %build-inputs "docbook-xml")
                            "/xml/dtd/docbook/catalog.xml"))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("itstool" ,itstool)
       ("libxml" ,libxml2)
       ("gettext" ,gettext-minimal)
       ("bc" ,bc)))
    (inputs
     `(("perl" ,perl)
       ("python" ,python)
       ("xsltproc" ,libxslt)
       ("dblatex" ,dblatex)
       ("docbook-xml" ,docbook-xml-4.3)
       ("docbook-xsl" ,docbook-xsl)
       ("source-highlight" ,source-highlight)
       ("glib" ,glib)))
    (home-page "http://www.gtk.org/gtk-doc/")
    (synopsis "Documentation generator from C source code")
    (description
     "GTK-Doc generates API documentation from comments added to C code.  It is
typically used to document the public API of GTK+ and GNOME libraries, but it
can also be used to document application code.")
    (license license:gpl2+)))

(define-public gtk-engines
  (package
    (name "gtk-engines")
    (version "2.20.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnome/sources/" name "/"
                                  (version-major+minor version) "/"
                                  name "-" version ".tar.bz2"))
              (sha256
               (base32
                "1db65pb0j0mijmswrvpgkdabilqd23x22d95hp5kwxvcramq1dhm"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags
       `("--enable-animation")))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("intltool" ,intltool)))
    (inputs
     ;; Don't propagate GTK+ to reduce "profile pollution".
     `(("gtk+" ,gtk+-2))) ; required by gtk-engines-2.pc
    (home-page "http://live.gnome.org/GnomeArt")
    (synopsis "Theming engines for GTK+ 2.x")
    (description
     "This package contains the standard GTK+ 2.x theming engines including
Clearlooks, Crux, High Contrast, Industrial, LighthouseBlue, Metal, Mist,
Redmond95 and ThinIce.")
    (license (list license:gpl2+ license:lgpl2.1+))))

(define-public murrine
  (package
    (name "murrine")
    (version "0.98.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnome/sources/" name "/"
                                  (version-major+minor version) "/"
                                  name "-" version ".tar.xz"))
              (sha256
               (base32
                "129cs5bqw23i76h3nmc29c9mqkm9460iwc8vkl7hs4xr07h8mip9"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags
       `("--enable-animation"
         "--enable-animationrtl")))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("intltool" ,intltool)))
    (propagated-inputs
     `(("gtk+" ,gtk+-2)))
    (home-page "http://live.gnome.org/GnomeArt")
    (synopsis "Cairo-based theming engine for GTK+ 2.x")
    (description
     "Murrine is a cairo-based GTK+ theming engine.  It is named after the
glass artworks done by Venicians glass blowers.")
    (license license:gpl2+)))

(define-public gtkspell3
  (package
    (name "gtkspell3")
    (version "3.0.8")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/gtkspell/"
                                  version "/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "1zrz5pz4ryvcssk898liynmy2wyxgj95ak7mp2jv7x62yzihq6h1"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("intltool" ,intltool)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("enchant" ,enchant)
       ("gobject-introspection" ,gobject-introspection)
       ("gtk+" ,gtk+)
       ("pango" ,pango)))
    (home-page "http://gtkspell.sourceforge.net")
    (synopsis "Spell-checking addon for GTK's TextView widget")
    (description
     "GtkSpell provides word-processor-style highlighting and replacement of
misspelled words in a GtkTextView widget.")
    (license license:gpl2+)))

(define-public clipit
  (package
    (name "clipit")
    (version "1.4.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/downloads/ClipIt/clipit-"
                    version ".tar.gz"))
              (sha256
               (base32
                "0jrwn8qfgb15rwspdp1p8hb1nc0ngmpvgr87d4k3lhlvqg2cfqva"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("intltool" ,intltool)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("gtk+" ,gtk+-2)))
    (home-page "https://github.com/CristianHenzel/ClipIt")
    (synopsis "Lightweight GTK+ clipboard manager")
    (description
     "ClipIt is a clipboard manager with features such as a history, search
thereof, global hotkeys and clipboard item actions.  It was forked from
Parcellite and adds bugfixes and features.")
    (license license:gpl2+)))
