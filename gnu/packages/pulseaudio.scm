;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
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

(define-module (gnu packages pulseaudio)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module ((guix licenses) #:prefix l:)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages avahi)
  #:use-module (gnu packages check)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages libcanberra)
  #:use-module (gnu packages web)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages m4)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages xiph))

(define-public libsndfile
  (package
    (name "libsndfile")
    (version "1.0.26")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://www.mega-nerd.com/libsndfile/files/libsndfile-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "14jhla289cj45946h0hq2an0a9g4wkwb3v4571bla6ixfvn20rfd"))))
    (build-system gnu-build-system)
    (inputs
     `(("libvorbis" ,libvorbis)
       ("libogg" ,libogg)
       ("flac" ,flac)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://www.mega-nerd.com/libsndfile/")
    (synopsis "Reading and writing files containing sampled sound")
    (description
     "Libsndfile is a C library for reading and writing files containing
sampled sound (such as MS Windows WAV and the Apple/SGI AIFF format) through
one standard library interface.

It was designed to handle both little-endian (such as WAV) and
big-endian (such as AIFF) data, and to compile and run correctly on
little-endian (such as Intel and DEC/Compaq Alpha) processor systems as well
as big-endian processor systems such as Motorola 68k, Power PC, MIPS and
SPARC.  Hopefully the design of the library will also make it easy to extend
for reading and writing new sound file formats.")
    (license l:gpl2+)))

(define-public libsamplerate
  (package
    (name "libsamplerate")                     ; aka. Secret Rabbit Code (SRC)
    (version "0.1.8")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://www.mega-nerd.com/SRC/libsamplerate-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "01hw5xjbjavh412y63brcslj5hi9wdgkjd3h9csx5rnm8vglpdck"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("libsndfile" ,libsndfile)
       ("fftw" ,fftw)))
    (home-page "http://www.mega-nerd.com/SRC/index.html")
    (synopsis "Audio sample rate conversion library")
    (description
     "Secret Rabbit Code (aka. libsamplerate) is a Sample Rate Converter for
audio.  One example of where such a thing would be useful is converting audio
from the CD sample rate of 44.1kHz to the 48kHz sample rate used by DAT
players.

SRC is capable of arbitrary and time varying conversions; from downsampling by
a factor of 256 to upsampling by the same factor.  Arbitrary in this case means
that the ratio of input and output sample rates can be an irrational
number.  The conversion ratio can also vary with time for speeding up and
slowing down effects.

SRC provides a small set of converters to allow quality to be traded off
against computation cost.  The current best converter provides a
signal-to-noise ratio of 145dB with -3dB passband extending from DC to 96% of
the theoretical best bandwidth for a given pair of input and output sample
rates.")
    (license l:gpl2+)))

(define-public pulseaudio
  (package
    (name "pulseaudio")
    (version "9.0")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "https://freedesktop.org/software/pulseaudio/releases/"
                   name "-" version ".tar.xz"))
             (sha256
              (base32
               "11j682g2mn723sz3bh4i44ggq29z053zcggy0glzn63zh9mxdly3"))
             (modules '((guix build utils)))
             (snippet
              ;; Disable console-kit support by default since it's deprecated
              ;; anyway.
              '(substitute* "src/daemon/default.pa.in"
                 (("load-module module-console-kit" all)
                  (string-append "#" all "\n"))))
             (patches (search-patches
                       "pulseaudio-fix-mult-test.patch"
                       "pulseaudio-longer-test-timeout.patch"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags (list "--localstatedir=/var" ;"--sysconfdir=/etc"
                               "--disable-oss-output"
                               "--enable-bluez5"
                               (string-append "--with-udev-rules-dir="
                                              (assoc-ref %outputs "out")
                                              "/lib/udev/rules.d"))
       #:phases (alist-cons-before
                 'check 'pre-check
                 (lambda _
                   ;; 'tests/lock-autospawn-test.c' wants to create a file
                   ;; under ~/.config/pulse.
                   (setenv "HOME" (getcwd))
                   ;; 'thread-test' needs more time on hydra and on slower
                   ;; machines, so we set the default timeout to 120 seconds.
                   (setenv "CK_DEFAULT_TIMEOUT" "120"))
                 %standard-phases)))
    (inputs
     ;; TODO: Add optional inputs (GTK+?).
     `(("alsa-lib" ,alsa-lib)
       ("bluez" ,bluez)
       ("sbc" ,sbc)
       ("json-c" ,json-c)
       ("speex" ,speex)
       ("libsndfile" ,libsndfile)
       ("libsamplerate" ,libsamplerate)
       ("dbus" ,dbus)
       ("glib" ,glib)
       ("intltool" ,intltool)
       ("m4" ,m4)
       ("libltdl" ,libltdl)
       ("fftwf" ,fftwf)
       ("avahi" ,avahi)
       ("eudev" ,eudev)           ;for the detection of hardware audio devices
       ("check" ,check)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     ;; 'libpulse*.la' contain `-lgdbm' and `-lcap', so propagate them.
     `(("libcap" ,libcap)
       ("gdbm" ,gdbm)))
    (home-page "http://www.pulseaudio.org/")
    (synopsis "Sound server")
    (description
     "PulseAudio is a sound server.  It is basically a proxy for your sound
applications.  It allows you to do advanced operations on your sound data as
it passes between your application and your hardware.  Things like
transferring the audio to a different machine, changing the sample format or
channel count and mixing several sounds into one are easily achieved using a
sound server.")

    ;; PulseAudio is LGPLv2+, but some of the optional dependencies (GNU dbm,
    ;; FFTW, etc.) are GPL'd, so the result is effectively GPLv2+.  See
    ;; 'LICENSE' for details.
    (license l:gpl2+)))

(define-public pavucontrol
  (package
    (name "pavucontrol")
    (version "3.0")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "https://freedesktop.org/software/pulseaudio/pavucontrol/pavucontrol-"
                   version
                   ".tar.xz"))
             (sha256
              (base32
               "14486c6lmmirkhscbfygz114f6yzf97h35n3h3pdr27w4mdfmlmk"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags '("CXXFLAGS=-std=c++11"))) ; required by gtkmm
    (inputs
     `(("libcanberra" ,libcanberra)
       ("gtkmm" ,gtkmm)
       ("pulseaudio" ,pulseaudio)))
    (native-inputs
     `(("intltool" ,intltool)
       ("pkg-config" ,pkg-config)))
    (home-page "http://freedesktop.org/software/pulseaudio/pavucontrol/")
    (synopsis "PulseAudio volume control")
    (description
     "PulseAudio Volume Control (pavucontrol) provides a GTK+
graphical user interface to connect to a PulseAudio server and
easily control the volume of all clients, sinks, etc.")
    (license l:gpl2+)))
