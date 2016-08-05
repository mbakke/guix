;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2013 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2013 David Thompson <dthompson2@worcester.edu>
;;; Copyright © 2014 Sree Harsha Totakura <sreeharsha@totakura.in>
;;; Copyright © 2014 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Paul van der Walt <paul@denknerd.org>
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

(define-module (gnu packages xiph)
  #:use-module (gnu packages)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages image)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages xml)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:export (libogg
            libvorbis
            libtheora
            speex
            ao
            flac
            libkate
            vorbis-tools
            opus
            opusfile
            opus-tools))

(define libogg
  (package
   (name "libogg")
   (version "1.3.2")
   (source (origin
            (method url-fetch)
            (uri (string-append "http://downloads.xiph.org/releases/ogg/libogg-"
                                version ".tar.xz"))
            (sha256
             (base32
              "16z74q422jmprhyvy7c9x909li8cqzmvzyr8cgbm52xcsp6pqs1z"))))
   (build-system gnu-build-system)
   (synopsis "Library for manipulating the ogg multimedia format")
   (description
    "The libogg library allows to manipulate the ogg multimedia container
format, which encapsulates raw compressed data and allows the interleaving of
audio and video data.  In addition to encapsulation and interleaving of
multiple data streams, ogg provides packet framing, error detection, and
periodic timestamps for seeking.")
   (license (license:non-copyleft "file://COPYING"
                               "See COPYING in the distribution."))
   (home-page "http://xiph.org/ogg/")))

(define libvorbis
  (package
   (name "libvorbis")
   (version "1.3.5")
   (source (origin
            (method url-fetch)
            (uri (string-append "http://downloads.xiph.org/releases/vorbis/"
                                "libvorbis-" version ".tar.xz"))
            (sha256
             (base32
              "1lg1n3a6r41492r7in0fpvzc7909mc5ir9z0gd3qh2pz4yalmyal"))))
   (build-system gnu-build-system)
   (propagated-inputs `(("libogg" ,libogg)))
   (arguments `(#:configure-flags '("LDFLAGS=-lm")
                #:parallel-tests? #f))
   (synopsis "Library implementing the vorbis audio format")
   (description
    "The libvorbis library implements the ogg vorbis audio format,
a fully open, non-proprietary, patent-and-royalty-free, general-purpose
compressed audio format for mid to high quality (8kHz-48.0kHz, 16+ bit,
polyphonic) audio and music at fixed and variable bitrates from 16 to
128 kbps/channel.")
   (license (license:non-copyleft "file://COPYING"
                               "See COPYING in the distribution."))
   (home-page "http://xiph.org/vorbis/")))

(define libtheora
  (package
    (name "libtheora")
    (version "1.1.1")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://downloads.xiph.org/releases/theora/"
                                 "libtheora-" version ".tar.xz"))
             (sha256
              (base32
               "0q8wark9ribij57dciym5vdikg2464p8q2mgqvfb78ksjh4s8vgk"))
             (patches (search-patches "libtheora-config-guess.patch"))))
    (build-system gnu-build-system)
    (inputs `(("libvorbis" ,libvorbis)))
    ;; The .pc files refer to libogg.
    (propagated-inputs `(("libogg" ,libogg)))
    (synopsis "Library implementing the Theora video format")
    (description
     "The libtheora library implements the ogg theora video format,
a fully open, non-proprietary, patent-and-royalty-free, general-purpose
compressed video format.")
    (license license:bsd-3)
    (home-page "http://xiph.org/theora/")))

(define speex
  (package
    (name "speex")
    (version "1.2rc1")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "http://downloads.xiph.org/releases/speex/speex-"
                          version ".tar.gz"))
      (sha256
       (base32
        "19mpkhbz3s08snvndn0h1dk2j139max6b0rr86nnsjmxazf30brl"))))
    (build-system gnu-build-system)
    (inputs `(("libogg" ,libogg)))
    (home-page "https://gnu.org/software/speex")
    (synopsis "Library for patent-free audio compression format")
    (description
     "GNU Speex is a patent-free audio compression codec specially designed
for speech.  It is well-adapted to internet applications, such as VoIP.  It
features compression of different bands in the same bitstream, intensity
stereo encoding, and voice activity detection.")
    ;; 'src/getopt.c' is under LGPLv2+
    (license (license:non-copyleft "file://COPYING"
                                "See COPYING in the distribution."))))

(define ao
  (package
    (name "ao")
    (version "1.2.0")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "http://downloads.xiph.org/releases/ao/libao-"
                          version ".tar.gz"))
      (sha256
       (base32
        "1bwwv1g9lchaq6qmhvj1pp3hnyqr64ydd4j38x94pmprs4d27b83"))))
    (build-system gnu-build-system)
    ;; FIXME: Add further backends, see the summary printed after configure.
    ;; XXX: Should back-ends be pushed to different outputs?  For instance,
    ;; "out" would include only the ALSA back-end, while "pulse" would
    ;; contain 'lib/ao/plugins-4/libpulse.*'.
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("pulseaudio" ,pulseaudio)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (synopsis "Cross platform audio library")
    (description
     "Libao is a cross-platform audio library that allows programs to
output audio using a simple API on a wide variety of platforms.
It currently supports:
@enumerate
@item Null output (handy for testing without a sound device),
@item WAV files,
@item AU files,
@item RAW files,
@item OSS (Open Sound System, used on Linux and FreeBSD),
@item ALSA (Advanced Linux Sound Architecture),
@item aRts (Analog RealTime Synth, used by KDE),
@item PulseAudio (next generation GNOME sound server),
@item esd (EsounD or Enlightened Sound Daemon),
@item Mac OS X,
@item Windows (98 and later),
@item AIX,
@item Sun/NetBSD/OpenBSD,
@item IRIX,
@item NAS (Network Audio Server),
@item RoarAudio (Modern, multi-OS, networked Sound System),
@item OpenBSD's sndio.
@end enumerate
")
    (license license:gpl2+)
    (home-page "http://www.xiph.org/ao/")))

(define flac
  (package
   (name "flac")
   (version "1.3.1")
   (source (origin
            (method url-fetch)
            (uri (string-append "http://downloads.xiph.org/releases/flac/flac-"
                                version ".tar.xz"))
            (sha256
             (base32
              "0v65w7ph6ldwp5a8fbhp0a3w8f737ck468fr7yb7sxmskl4w0ws7"))))
   (build-system gnu-build-system)
   (arguments
    `(#:parallel-tests? #f))
   ;; FIXME: configure also looks for xmms, input could be added once it exists
   (propagated-inputs `(("libogg" ,libogg))) ; required by flac.pc
   (synopsis "Free lossless audio codec")
   (description
"FLAC stands for Free Lossless Audio Codec, an audio format that is lossless,
meaning that audio is compressed in FLAC without any loss in quality.")
   (license (license:non-copyleft "file://COPYING"
                               "See COPYING in the distribution.")) ; and LGPL and GPL
   (home-page "http://xiph.org/flac/")))

(define libkate
  (package
   (name "libkate")
   (version "0.4.1")
   (source (origin
            (method url-fetch)
            (uri (string-append "http://libkate.googlecode.com/files/libkate-"
                                version ".tar.gz"))
            (sha256
             (base32
              "0s3vr2nxfxlf1k75iqpp4l78yf4gil3f0v778kvlngbchvaq23n4"))))
   (build-system gnu-build-system)
   (native-inputs `(("doxygen" ,doxygen)
                    ("pkg-config" ,pkg-config)))
   ;; FIXME: Add optional input liboggz
   (inputs `(("bison" ,bison)
             ("libogg" ,libogg)
             ("libpng" ,libpng)
("python" ,python-wrapper)
             ("zlib" ,zlib)))
   (synopsis "Karaoke and text codec for embedding in ogg")
   (description
    "Kate is an overlay codec, originally designed for karaoke and text,
that can be multiplixed in Ogg.  Text and images can be carried by a Kate
stream, and animated.  Most of the time, this would be multiplexed with
audio/video to carry subtitles, song lyrics (with or without karaoke data),
etc., but doesn't have to be.

Series of curves (splines, segments, etc.) may be attached to various
properties (text position, font size, etc.) to create animated overlays.
This allows scrolling or fading text to be defined.  This can even be used
to draw arbitrary shapes, so hand drawing can also be represented by a
Kate stream.")
   (license license:bsd-3)
   (home-page "http://code.google.com/p/libkate/")))

(define vorbis-tools
  (package
   (name "vorbis-tools")
   (version "1.4.0")
   (source (origin
            (method url-fetch)
            (uri (string-append "http://downloads.xiph.org/releases/vorbis/"
                                "vorbis-tools-" version ".tar.gz"))
            (sha256
             (base32
              "1g12bnh5ah08v529y72kfdz5lhvy75iaz7f9jskyby23m9dkk2d3"))
            (patches (search-patches 
                       "vorbis-tools-CVE-2014-9638+CVE-2014-9639.patch"
                       "vorbis-tools-CVE-2014-9640.patch"
                       "vorbis-tools-CVE-2015-6749.patch"))))
   (build-system gnu-build-system)
   (inputs `(("ao" ,ao)
             ("curl" ,curl)
             ("flac" ,flac)
             ("libkate" ,libkate)
             ("libogg" ,libogg)
             ("libvorbis" ,libvorbis)
             ("speex" ,speex)))
   (native-inputs `(("pkg-config" ,pkg-config)))
   (synopsis "Ogg vorbis tools")
   (description
    "Ogg vorbis is a non-proprietary, patent-and-royalty-free,
general-purpose compressed audio format.

The package vorbis-tools contains
ogg123,  an ogg vorbis command line audio player;
oggenc,  the ogg vorbis encoder;
oggdec,  a simple, portable command line decoder (to wav and raw);
ogginfo, to obtain information (tags, bitrate, length, etc.) about
         an ogg vorbis file.")
   (license license:gpl2)
   (home-page "http://xiph.org/vorbis/")))

(define opus
  (package
    (name "opus")
    (version "1.1.3")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://downloads.xiph.org/releases/opus/opus-" version
                    ".tar.gz"))
              (sha256
               (base32
                "0cxnd7pjxbgh6l3cbzsw29phpr5cq28fikfhjlp1hc3y5s0gxdjq"))))
    (build-system gnu-build-system)
    (synopsis "Versatile audio codec")
    (description
     "Opus is a totally open, royalty-free, highly versatile audio codec.  Opus
is unmatched for interactive speech and music transmission over the Internet,
but is also intended for storage and streaming applications.  It is
standardized by the Internet Engineering Task Force (IETF) as RFC 6716 which
incorporated technology from Skype's SILK codec and Xiph.Org's CELT codec.")
    (license license:bsd-3)
    (home-page "http://www.opus-codec.org")))

(define opus-tools
  (package
    (name "opus-tools")
    (version "0.1.9")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://downloads.xiph.org/releases/opus/opus-tools-"
                    version ".tar.gz"))
              (sha256
               (base32
                "0fk4nknvl111k89j5yckmyrh6b2wvgyhrqfncp7rig3zikbkv1xi"))))
    (build-system gnu-build-system)
    (arguments
     ;; The package developers misuse pkg-config such that it doesn't work
     ;; when cross compiling.  Therefore we avoid it completly and set the
     ;; necessary flags ourselves.
     `(#:configure-flags (list (string-append "CFLAGS=-I"
                                              (assoc-ref %build-inputs "libogg")
                                              "/include -I"
                                              (assoc-ref %build-inputs "opus")
                                              "/include/opus"))))
    (inputs `(("libogg" ,libogg)
              ("opus" ,opus)
              ("flac" ,flac)))
    (synopsis
     "Command line utilities to encode, inspect, and decode .opus files")
    (description "Opus is a royalty-free, highly versatile audio codec.
Opus-tools provide command line utilities for creating, inspecting and
decoding .opus files.")
    (license license:bsd-3)
    (home-page "http://www.opus-codec.org")))

(define opusfile
  (package
    (name "opusfile")
    (version "0.7")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://downloads.xiph.org/releases/opus/opusfile-" version
                    ".tar.gz"))
              (sha256
               (base32
                "00f3wwjv3hxwg05g22s6mkkxikz80ljsn70g39cmi43jph9ysawy"))))
    (build-system gnu-build-system)
    (propagated-inputs
     `(("opus" ,opus)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("libogg" ,libogg)
       ("openssl" ,openssl)))
    (synopsis "Versatile audio codec")
    (description
     "The opusfile library provides seeking, decode, and playback of Opus
streams in the Ogg container (.opus files) including over http(s) on posix and
windows systems.")
    (license license:bsd-3)
    (home-page "http://www.opus-codec.org")))

(define-public icecast
  (package
    (name "icecast")
    (version "2.4.3")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://downloads.xiph.org/releases/icecast/icecast-"
                    version ".tar.gz"))
              (sha256
               (base32
                "14n5vm2xnyn8y7kl46lnnlgv6v5fjykhc57ffdsh0qaxfs6a8p68"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("libxslt" ,libxslt)
       ("libxml2" ,libxml2)
       ("openssl" ,openssl)
       ("curl" ,curl)
       ("libogg" ,libogg)
       ("libvorbis" ,libvorbis)
       ("libtheora" ,libtheora)
       ("speex" ,speex)))
    (synopsis "Streaming media server")
    (description "Icecast is a streaming media server which currently supports
Ogg (Vorbis and Theora), Opus, WebM and MP3 audio streams.  It can be used to
create an Internet radio station or a privately running jukebox and many
things in between.")
    (home-page "http://icecast.org/")
    (license license:gpl2)))

(define-public libshout
  (package
    (name "libshout")
    (version "2.4.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://downloads.xiph.org/releases/libshout/"
                    name "-" version ".tar.gz"))
              (sha256
               (base32
                "0kgjpf8jkgyclw11nilxi8vyjk4s8878x23qyxnvybbgqbgbib7k"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     ;; shout.pc refers to all these.
     `(("libtheora" ,libtheora)
       ("libvorbis" ,libvorbis)
       ("speex"     ,speex)))
    (home-page "http://www.icecast.org/")
    (synopsis "Audio streaming library for icecast encoders")
    (description
     "Libshout is a library for communicating with and sending data to an
icecast server.  It handles the socket connection, the timing of the data,
and prevents bad data from getting to the icecast server.")
    (license license:gpl2+)))
