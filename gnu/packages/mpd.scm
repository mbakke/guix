;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015 David Thompson <dthompson2@worcester.edu>
;;; Copyright © 2014 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2014 Cyrill Schenkel <cyrill.schenkel@gmail.com>
;;; Copyright © 2014 Ian Denhardt <ian@zenhack.net>
;;; Copyright © 2015 Paul van der Walt <paul@denknerd.org>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
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

(define-module (gnu packages mpd)
  #:use-module (gnu packages)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system python)
  #:use-module (gnu packages avahi)
  #:use-module (gnu packages boost)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages mp3)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages video)
  #:use-module (gnu packages xiph))

(define-public libmpdclient
  (package
    (name "libmpdclient")
    (version "2.10")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "http://musicpd.org/download/libmpdclient/"
                              (car (string-split version #\.))
                              "/libmpdclient-" version ".tar.xz"))
              (sha256
               (base32
                "10pzs9z815a8hgbbbiliapyiw82bnplsccj5irgqjw5f5plcs22g"))))
    (build-system gnu-build-system)
    (native-inputs `(("doxygen" ,doxygen)))
    (synopsis "Music Player Daemon client library")
    (description "A stable, documented, asynchronous API library for
interfacing MPD in the C, C++ & Objective C languages.")
    (home-page "http://www.musicpd.org/libs/libmpdclient/")
    (license license:bsd-3)))

(define-public mpd
  (package
    (name "mpd")
    (version "0.19.19")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "http://musicpd.org/download/mpd/"
                              (version-major+minor version)
                              "/mpd-" version ".tar.xz"))
              (sha256
               (base32
                "07af1m2lgblyiq0gcs26zv8n22wrhrpmf49xsm338h1n87d6r1dw"))))
    (build-system gnu-build-system)
    (inputs `(("ao" ,ao)
              ("alsa-lib" ,alsa-lib)
              ("avahi" ,avahi)
              ("boost" ,boost)
              ("curl" ,curl)
              ("ffmpeg" ,ffmpeg)
              ("flac" ,flac)
              ("glib" ,glib)
              ("icu4c" ,icu4c)
              ("lame" ,lame)
              ("libid3tag" ,libid3tag)
              ("libmad" ,libmad)
              ("libmpdclient" ,libmpdclient)
              ("libsamplerate" ,libsamplerate)
              ("libsndfile" ,libsndfile)
              ("libvorbis" ,libvorbis)
              ("opus" ,opus)
              ("pulseaudio" ,pulseaudio)
              ("sqlite" ,sqlite)
              ("zlib" ,zlib)))
    (native-inputs `(("pkg-config" ,pkg-config)))
    ;; Missing optional inputs:
    ;;   libyajl
    ;;   libcdio_paranoia
    ;;   libmms
    ;;   libadplug
    ;;   libaudiofile
    ;;   faad2
    ;;   fluidsynth
    ;;   libgme
    ;;   libshout
    ;;   libmpg123
    ;;   libmodplug
    ;;   libmpcdec
    ;;   libsidplay2
    ;;   libwavpack
    ;;   libwildmidi
    ;;   libtwolame
    ;;   libroar
    ;;   libjack
    ;;   OpenAL
    (synopsis "Music Player Daemon")
    (description "Music Player Daemon (MPD) is a flexible, powerful,
server-side application for playing music.  Through plugins and libraries it
can play a variety of sound files while being controlled by its network
protocol.")
    (home-page "http://www.musicpd.org/")
    (license license:gpl2)))

(define-public mpd-mpc
  (package
    (name "mpd-mpc")
    (version "0.28")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "http://www.musicpd.org/download/mpc/"
                              (car (string-split version #\.))
                              "/mpc-" version ".tar.xz"))
              (sha256
               (base32
                "0iy5mdffkk61255f62si7p8mhyhkib70zlr1i1iimj2xr037scx4"))))
    (build-system gnu-build-system)
    (inputs `(("libmpdclient" ,libmpdclient)))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (synopsis "Music Player Daemon client")
    (description "MPC is a minimalist command line interface to MPD, the music
player daemon.")
    (home-page "http://www.musicpd.org/clients/mpc/")
    (license license:gpl2)))

(define-public ncmpc
  (package
    (name "ncmpc")
    (version "0.25")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "http://musicpd.org/download/ncmpc/"
                              (car (string-split version #\.))
                              "/ncmpc-" version ".tar.xz"))
              (sha256
               (base32
                "196f9s0qmc4srr10n4vk3amvqy5f52y9kvgwqpkfjsnhf75qlckf"))))
    (build-system gnu-build-system)
    (inputs `(("glib" ,glib)
              ("libmpdclient" ,libmpdclient)
              ("ncurses" ,ncurses)))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (synopsis "Curses Music Player Daemon client")
    (description "ncmpc is a fully featured MPD client, which runs in a
terminal using ncurses.")
    (home-page "http://www.musicpd.org/clients/ncmpc/")
    (license license:gpl2)))

(define-public ncmpcpp
  (package
    (name "ncmpcpp")
    (version "0.7.5")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "http://ncmpcpp.rybczak.net/stable/ncmpcpp-"
                              version ".tar.bz2"))
              (sha256
               (base32
                "0zg084m06y7dd8ccy6aq9hx8q7qi2s5kl0br5139hrmk40q68kvy"))))
    (build-system gnu-build-system)
    (inputs `(("libmpdclient" ,libmpdclient)
              ("boost"  ,boost)
              ("readline" ,readline)
              ("ncurses" ,ncurses)
              ("taglib" ,taglib)
              ("icu4c" ,icu4c)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (arguments
     '(#:configure-flags
       '("BOOST_LIB_SUFFIX=" "--with-taglib")))
    (synopsis "Featureful ncurses based MPD client inspired by ncmpc")
    (description "Ncmpcpp is an mpd client with a UI very similar to ncmpc,
but it provides new useful features such as support for regular expressions
for library searches, extended song format, items filtering, the ability to
sort playlists, and a local file system browser.")
    (home-page "http://ncmpcpp.rybczak.net/")
    (license license:gpl2+)))

(define-public mpdscribble
  (package
    (name "mpdscribble")
    (version "0.22")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.musicpd.org/download/mpdscribble/"
                                  version "/mpdscribble-" version ".tar.gz"))
              (sha256
               (base32
                "0f0ybx380x2z2g1qvdndpvcrhkrgsfqckhz3ryydq2w3pl12v27z"))))
    (build-system gnu-build-system)
    (inputs `(("libmpdclient" ,libmpdclient)
              ("curl" ,curl)
              ("glib" ,glib)))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (synopsis "MPD client for track scrobbling")
    (description "mpdscribble is a Music Player Daemon client which submits
information about tracks being played to a scrobbler, such as Libre.FM.")
    ;; musicpd.org doesn't mention mpdscribble.  It points users to this wiki
    ;; instead.
    (home-page "http://mpd.wikia.com/wiki/Client:Mpdscribble")
    (license license:gpl2+)))

(define-public python-mpd2
  (package
    (name "python-mpd2")
    (version "0.5.5")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "python-mpd2" version))
              (sha256
               (base32
                "0laypd7h1j14b4vrmiayqlzdsh2j5hc3zv4l0fqvbrbw9y6763ii"))))
    (build-system python-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _ (zero? (system* "python" "mpd_test.py")))))))
    (native-inputs `(("python-mock" ,python-mock)))
    (home-page "https://github.com/Mic92/python-mpd2")
    (synopsis "Python MPD client library")
    (description "Python-mpd2 is a Python library which provides a client
interface for the Music Player Daemon.")
    (license license:lgpl3+)))

(define-public python2-mpd2
  (package-with-python2 python-mpd2))

(define-public sonata
  (package
    (name "sonata")
    (version "1.7b1")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "https://github.com/multani/sonata/archive/v"
                              version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "07gq2nxqwxs0qyxjbay7k5j25zd386bn7wdr2dl1gk53diwnn7s0"))))
    (build-system python-build-system)
    (arguments
     `(#:modules ((guix build gnu-build-system)
                  (guix build python-build-system)
                  ((guix build glib-or-gtk-build-system) #:prefix glib-or-gtk:)
                  (guix build utils))
       #:imported-modules (,@%gnu-build-system-modules
                           (guix build python-build-system)
                           (guix build glib-or-gtk-build-system))
       #:phases
       (modify-phases %standard-phases
         (add-after 'install 'glib-or-gtk-wrap
           (assoc-ref glib-or-gtk:%standard-phases 'glib-or-gtk-wrap))
         (add-after 'install 'wrap-sonata
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out               (assoc-ref outputs "out"))
                   (gi-typelib-path   (getenv "GI_TYPELIB_PATH")))
               (wrap-program (string-append out "/bin/sonata")
                 `("GI_TYPELIB_PATH" ":" prefix (,gi-typelib-path))))
             #t)))))
    (native-inputs
     `(("gettext" ,gnu-gettext)))
    (inputs
     `(("python-mpd2" ,python-mpd2)
       ("gtk+" ,gtk+)
       ("gsettings-desktop-schemas" ,gsettings-desktop-schemas)
       ("gobject-introspection" ,gobject-introspection)
       ("adwaita-icon-theme" ,adwaita-icon-theme)
       ("python-pygobject" ,python-pygobject)))
    (synopsis "Elegant client for the Music Player Daemon")
    (description "Sonata is an elegant graphical client for the Music Player
Daemon (MPD).  It supports playlists, multiple profiles (connecting to different
MPD servers, search and multimedia key support.")
    (home-page "http://www.nongnu.org/sonata/")
    (license license:gpl3+)))
