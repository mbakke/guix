;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Tomáš Čech <sleep_walker@suse.cz>
;;; Copyright © 2015 Daniel Pimentel <d4n1@member.fsf.org>
;;; Copyright © 2015, 2016 Efraim Flashner <efraim@flashner.co.il>
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

(define-module (gnu packages enlightenment)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system python)
  #:use-module (gnu packages)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages fribidi)
  #:use-module (gnu packages game-development)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gstreamer)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages image)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages lua)
  #:use-module (gnu packages pdf)
  #:use-module (gnu packages photo)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages video)
  #:use-module (gnu packages xorg))

(define-public efl
  (package
    (name "efl")
    (version "1.17.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://download.enlightenment.org/rel/libs/efl/efl-"
                    version ".tar.xz"))
              (sha256
               (base32
                "1dpq5flygrjg931nzsr2ra8icqffzrzbs1lnrzarbpsbmgq3zacs"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("compositeproto" ,compositeproto)
       ("curl" ,curl)
       ("giflib" ,giflib)
       ("gstreamer" ,gstreamer)
       ("gst-plugins-base" ,gst-plugins-base)
       ("harfbuzz" ,harfbuzz)
       ("libexif" ,libexif)
       ("libjpeg" ,libjpeg)
       ("librsvg" ,librsvg)
       ("libtiff" ,libtiff)
       ("libx11" ,libx11)
       ("libxcomposite" ,libxcomposite)
       ("libxcursor" ,libxcursor)
       ("libxdmcp" ,libxdmcp)
       ("libxext" ,libxext)
       ("libxi" ,libxi)
       ("libxkbfile" ,libxkbfile)
       ("libxinerama" ,libxinerama)
       ("libxp" ,libxp)
       ("libxrandr" ,libxrandr)
       ("libxscrnsaver" ,libxscrnsaver)
       ("libxtst" ,libxtst)
       ("mesa" ,mesa)
       ("printproto" ,printproto)
       ("scrnsaverproto" ,scrnsaverproto)
       ("xextproto" ,xextproto)
       ("xinput" ,xinput)
       ("xpr" ,xpr)
       ("xproto" ,xproto)))
    (propagated-inputs
     ;; All these inputs are in package config files in section
     ;; Require.private.
     `(("bullet" ,bullet) ; ephysics.pc
       ("dbus" ,dbus) ; eldbus.pc
       ("eudev" ,eudev) ; eeze.pc
       ("fontconfig" ,fontconfig) ; evas.pc
       ("freetype" ,freetype) ; evas.pc
       ("fribidi" ,fribidi) ; evas.pc
       ("glib" ,glib) ; ecore.pc
       ("libpng" ,libpng) ; evas.pc, evas-cxx.pc
       ("libsndfile" ,libsndfile) ; ecore-audio.pc, ecore-audio-cxx.pc
       ("luajit" ,luajit) ; evas.pc, edje.pc
       ("openssl" ,openssl) ; eet.pc, ecore-con.pc
       ("pulseaudio" ,pulseaudio) ; ecore-audio.pc, ecore-audio-cxx.pc
       ("util-linux" ,util-linux) ; eeze.pc
       ("zlib" ,zlib))) ; eet.pc
    (arguments
     `(#:configure-flags '("--disable-silent-rules")
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'patch-config-files
           (lambda _
             (substitute* "po/Makefile.in.in"
                          (("/bin/sh") (which "bash"))))))))
    (home-page "http://www.enlightenment.org")
    (synopsis "Enlightenment Foundation Libraries")
    (description
     "Enlightenment Foundation Libraries is a set of libraries developed
for Enlightenment.  Libraries covers data serialization, wide support for
graphics rendering, UI layout and themes, interaction with OS, access to
removable devices or support for multimedia.")
    ;; Different parts are under different licenses.
    (license (list license:bsd-2 license:lgpl2.1 license:zlib))))

(define-public elementary
  (package
    (name "elementary")
    (version "1.17.1")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "https://download.enlightenment.org/rel/libs/"
                              "elementary/elementary-" version ".tar.xz"))
              (sha256
               (base32
                "149xjq4z71l44w1kd8zks9b2g0wjc9656w46hzd27b58afj1dqc5"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("efl" ,efl))) ; elementary.pc, elementary-cxx.pc
    (home-page "http://www.enlightenment.org")
    (synopsis "Widget library of Enlightenment world")
    (description
     "Elementary is a widget library/toolkit, part of the Enlightenment
Foundation  Libraries.  It is build upon Edje and Evas libraries and uses
full capabilities of EFL.")
    (license license:lgpl2.1)))

(define-public evas-generic-loaders
  (package
    (name "evas-generic-loaders")
    (version "1.17.0")
    (source (origin
              (method url-fetch)
              (uri
               (string-append
                "https://download.enlightenment.org/rel/libs/"
                "evas_generic_loaders/evas_generic_loaders-"
                version ".tar.xz"))
              (sha256
               (base32
                "0ynq1nx0bfgg19p4vki1fap36yyip53zaxpzncx2slr6jcx1kxf2"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("efl" ,efl)
       ("gstreamer" ,gstreamer)
       ("gst-plugins-base" ,gst-plugins-base)
       ("librsvg" ,librsvg)
       ("libspectre" ,libspectre)
       ("poppler" ,poppler)))
    (home-page "http://www.enlightenment.org")
    (synopsis "Plugins for integration of various file types into Evas")
    (description
     "Evas-generic-loaders is a collection of interfaces to outside libraries
and applications allowing to natively open pictures, documents and media
files in Evas (EFL canvas library).")
    (license license:gpl2+)))

(define-public emotion-generic-players
  (package
    (name "emotion-generic-players")
    (version "1.17.0")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "https://download.enlightenment.org/rel/libs/"
                              "emotion_generic_players/emotion_generic_players"
                              "-" version ".tar.xz"))
              (sha256
               (base32
                "03kaql95mk0c5j50v3c5i5lmlr3gz7xlh8p8q87xz8zf9j5h1pp7"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("efl" ,efl)
       ("vlc" ,vlc)))
    (home-page "http://www.enlightenment.org")
    (synopsis "Plugins for integrating media players in EFL based applications")
    (description
     "Emotion-generic-players is a collection of interfaces to outside libraries
and applications allowing to natively play video files through Emotion.
The only supported now is VLC.")
    (license license:bsd-2)))

(define-public terminology
  (package
    (name "terminology")
    (version "0.9.1")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "https://download.enlightenment.org/rel/apps/"
                              "terminology/terminology-" version ".tar.xz"))
              (sha256
               (base32
                "1kwv9vkhngdm5v38q93xpcykghnyawhjjcb5bgy0p89gpbk7mvpc"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("efl" ,efl)
       ("elementary" ,elementary)))
    (home-page "http://www.enlightenment.org")
    (synopsis "Powerful terminal emulator based on EFL")
    (description
     "Terminology is fast and feature rich terminal emulator.  It is solely
based on Enlightenment Foundation Libraries.  It supports multiple tabs, UTF-8,
URL and local path detection, themes, popup based content viewer for non-text
contents and more.")
    (license license:bsd-2)))

(define-public rage
  (package
    (name "rage")
    (version "0.1.4")
    (source (origin
              (method url-fetch)
              (uri
               (string-append
                "https://download.enlightenment.org/rel/apps/rage/rage-"
                version ".tar.gz"))
              (sha256
               (base32 "10j3n8crk16jzqz2hn5djx6vms5f6x83qyiaphhqx94h9dgv2mgg"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("efl" ,efl)
       ("elementary" ,elementary)))
    (home-page "https://www.enlightenment.org/about-rage")
    (synopsis "Video and audio player based on EFL")
    (description
     "Rage is a video and audio player written with Enlightenment Foundation
Libraries with some extra bells and whistles.")
    (license license:bsd-2)))

(define-public enlightenment
  (package
    (name "enlightenment")
    (version "0.21.1")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "https://download.enlightenment.org/rel/apps/"
                              name "/" name "-" version ".tar.xz"))
              (sha256
               (base32
                "119sxrgrz163c01yx0q9n2jpmmbv0a58akmz0c2z4xy37f1m02rx"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags '("--enable-mount-eeze")))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("dbus" ,dbus)
       ("freetype" ,freetype)
       ("gettext" ,gnu-gettext)
       ("libxcb" ,libxcb)
       ("libxext" ,libxext)
       ("linux-pam" ,linux-pam)
       ("xcb-util-keysyms" ,xcb-util-keysyms)))
    (propagated-inputs
     ;; both these inputs are present in pkgconfig file in Require section
     `(("efl" ,efl) ; enlightenment.pc
       ("elementary" ,elementary))) ; enlightenment.pc
    (home-page "https://www.enlightenment.org")
    (synopsis "Lightweight desktop environment")
    (description
     "Enlightenment is resource friendly desktop environment with integrated
file manager, wide range of configuration options, plugin system allowing to
unload unused functionality, with support for touchscreen and suitable for
embedded systems.")
    (license license:bsd-2)))

(define-public python-efl
  (package
    (name "python-efl")
    (version "1.16.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "python-efl" version))
        (sha256
         (base32
          "1ihay90agl2jx12m7jj8j1cspd7vsak1w7q95rhb6r2srkq0ppxk"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
        (replace 'build
          (lambda _
            (zero?
              (system* "env" "ENABLE_CYTHON=1" "python" "setup.py" "build"))))
        (add-before 'build 'set-flags
         (lambda _
           (setenv "CFLAGS"
                   (string-append "-I" (assoc-ref %build-inputs "python-dbus")
                                  "/include/dbus-1.0")))))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-cython" ,python-cython)))
    (inputs
     `(("efl" ,efl)
       ("elementary" ,elementary)
       ("python-dbus" ,python-dbus)))
    (home-page "https://www.enlightenment.org/")
    (synopsis "Python bindings for EFL")
    (description
     "PYTHON-EFL are the python bindings for the whole Enlightenment Foundation
Libraries stack (eo, evas, ecore, edje, emotion, ethumb and elementary).")
    (license license:lgpl3)))

(define-public python2-efl
  (package-with-python2 python-efl))
