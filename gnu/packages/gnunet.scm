;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2014 Sree Harsha Totakura <sreeharsha@totakura.in>
;;; Copyright © 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 ng0 <ng0@we.make.ritual.n0.is>
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

(define-module (gnu packages gnunet)
  #:use-module (gnu packages)
  #:use-module (gnu packages file)
  #:use-module (gnu packages aidc)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages geeqie)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages groff)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages gstreamer)
  #:use-module (gnu packages libidn)
  #:use-module (gnu packages image)
  #:use-module (gnu packages libunistring)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages video)
  #:use-module (gnu packages xiph)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system gnu))

(define-public libextractor
  (package
   (name "libextractor")
   (version "1.3")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/libextractor/libextractor-"
                                version ".tar.gz"))
            (sha256
             (base32
              "0zvv7wd011npcx7yphw9bpgivyxz6mlp87a57n96nv85k96dd2l6"))
            (patches (search-patches "libextractor-ffmpeg-3.patch"))
            (modules '((guix build utils)))
            (snippet
             ;; Nowadays libmagic (from 'file') returns 'audio/ogg' and not
             ;; 'application/ogg'.  Adjust accordingly.
             '(substitute* "src/plugins/test_mime.c"
                (("application/ogg")
                 "audio/ogg")))))
   (build-system gnu-build-system)
   ;; WARNING: Checks require /dev/shm to be in the build chroot, especially
   ;; not to be a symbolic link to /run/shm.
   ;; FIXME:
   ;; The following dependencies are all optional, but should be
   ;; available for maximum coverage:
   ;; * libarchive
   ;; * libgif (giflib)
   ;; * libgtk+ >= 3.0.0 (may probably drop glib then as a propagated input of
   ;;                     gtk)
   ;; * libgsf
   ;; * libmagic (file)
   ;; * libmpeg2
   ;; * libmp4v2
   ;; * librpm
   ;; * libsmf
   ;; * libtidy
   (inputs
    `(("exiv2" ,exiv2)
      ("flac" ,flac)
      ("ffmpeg" ,ffmpeg)
      ("file" ,file)                           ;libmagic, for the MIME plug-in
      ("glib" ,glib)
      ("gstreamer" ,gstreamer)
      ("gst-plugins-base" ,gst-plugins-base)
      ("libjpeg" ,libjpeg)
      ("libogg" ,libogg)
      ("libtiff" ,libtiff)
      ("libltdl" ,libltdl)
      ("libvorbis" ,libvorbis)
      ("zlib" ,zlib)))
   (native-inputs
      `(("pkg-config" ,pkg-config)))
   (synopsis "Library to extract meta-data from media files")
   (description
    "GNU libextractor is a library for extracting metadata from files.  It
supports a very large number of file formats, including audio files, document
files, and archive files.  Each file format is implemented as a plugin, so
new formats can be added easily.  The package also contains a command-line
tool to extract metadata from a file and print the results.")
   (license license:gpl3+)
   (home-page "http://www.gnu.org/software/libextractor/")))

(define-public libmicrohttpd
  (package
   (name "libmicrohttpd")
   (version "0.9.50")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/libmicrohttpd/libmicrohttpd-"
                                version ".tar.gz"))
            (sha256
             (base32
              "1mzbqr6sqisppz88mh73bbh5sw57g8l87qvhcjdx5pmbd183idni"))))
   (build-system gnu-build-system)
   (inputs
    `(("curl" ,curl)
      ("gnutls" ,gnutls)
      ("libgcrypt" ,libgcrypt)
      ("openssl" ,openssl)
      ("zlib" ,zlib)))
   (arguments
    `(#:parallel-tests? #f))
   (synopsis "C library implementing an HTTP 1.1 server")
   (description
    "GNU libmicrohttpd is a small, embeddable HTTP server implemented as a
C library.  It makes it easy to run an HTTP server as part of another
application.  The library is fully HTTP 1.1 compliant.  It can listen on
multiple ports, supports four different threading models, and supports
IPv6.  It
also features security features such as basic and digest authentication
and support for SSL3 and TLS.")
   (license license:lgpl2.1+)
   (home-page "http://www.gnu.org/software/libmicrohttpd/")))

(define-public gnurl
  (package
   (name "gnurl")
   (version "7.48.0")
   (source (origin
            (method url-fetch)
            (uri (let ((version-with-underscores
                        (string-join (string-split version #\.) "_")))
                   (string-append "https://gnunet.org/sites/default/files/"
                                  name "-" version-with-underscores ".tar.bz2")))
            (sha256
             (base32
              "14gch4rdibrc8qs4mijsczxvl45dsclf234g17dk6c8nc2s4bm0a"))))
   (build-system gnu-build-system)
   (inputs `(("gnutls" ,gnutls)
             ("libidn" ,libidn)
             ("zlib" ,zlib)))
   (native-inputs
    `(("groff" ,groff)
      ("perl" ,perl)
      ("pkg-config" ,pkg-config)
      ("python" ,python-2)))
   (arguments
    `(#:configure-flags '("--enable-ipv6" "--with-gnutls" "--without-libssh2"
                          "--without-libmetalink" "--without-winidn"
                          "--without-librtmp" "--without-nghttp2"
                          "--without-nss" "--without-cyassl"
                          "--without-polarssl" "--without-ssl"
                          "--without-winssl" "--without-darwinssl"
                          "--disable-sspi" "--disable-ntlm-wb"
                          "--disable-ldap" "--disable-rtsp" "--disable-dict"
                          "--disable-telnet" "--disable-tftp" "--disable-pop3"
                          "--disable-imap" "--disable-smtp" "--disable-gopher"
                          "--disable-file" "--disable-ftp")
     #:test-target "test"
     #:parallel-tests? #f
     ;; We have to patch runtests.pl in tests/ directory
     #:phases
      (alist-cons-before
       'check 'patch-runtests
       (lambda _
         (substitute* "tests/runtests.pl"
                      (("/bin/sh") (which "sh"))))
       %standard-phases)))
   (synopsis "Microfork of cURL with support for the HTTP/HTTPS/GnuTLS subset of cURL")
   (description
    "Gnurl is a microfork of cURL, a command line tool for transferring data
with URL syntax.  While cURL supports many crypto backends, libgnurl only
supports HTTPS, HTTPS and GnuTLS.")
   (license (license:non-copyleft "file://COPYING"
                                  "See COPYING in the distribution."))
   (home-page "https://gnunet.org/gnurl")))

(define-public gnunet
  (package
   (name "gnunet")
   (version "0.10.1")
   (source
    (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/gnunet/gnunet-" version
                          ".tar.gz"))
      (sha256 (base32
               "04wxzm3wkgqbn42b8ksr4cx6m5cckyig5cls1adh0nwdczwvnp7n"))))
   (build-system gnu-build-system)
   (inputs
    `(("glpk" ,glpk)
      ("gnurl" ,gnurl)
      ("gstreamer" ,gstreamer)
      ("gst-plugins-base" ,gst-plugins-base)
      ("gnutls" ,gnutls)
      ("libextractor" ,libextractor)
      ("libgcrypt" ,libgcrypt)
      ("libidn" ,libidn)
      ("libmicrohttpd" ,libmicrohttpd)
      ("libltdl" ,libltdl)
      ("libunistring" ,libunistring)
      ("openssl" ,openssl)
      ("opus" ,opus)
      ("pulseaudio" ,pulseaudio)
      ("sqlite" ,sqlite)
      ("zlib" ,zlib)))
   (native-inputs
    `(("pkg-config" ,pkg-config)
      ("python" ,python-2)))
   (arguments
    '(#:configure-flags
      (list (string-append "--with-nssdir=" %output "/lib"))
      #:parallel-tests? #f
      ;; test_gnunet_service_arm fails; reported upstream
      #:tests? #f
      #:phases
        ;; swap check and install phases and set paths to installed binaries
        (alist-cons-before
         'check 'set-path-for-check
         (lambda* (#:key outputs #:allow-other-keys)
          (let ((out (assoc-ref outputs "out")))
           (setenv "GNUNET_PREFIX" (string-append out "/lib"))
           (setenv "PATH" (string-append (getenv "PATH") ":" out "/bin"))))
         (alist-cons-after
          'install 'check
          (assoc-ref %standard-phases 'check)
          (alist-delete
           'check
           %standard-phases)))))
   (synopsis "Secure, decentralized, peer-to-peer networking framework")
   (description
     "GNUnet is a framework for secure peer-to-peer networking.  The
high-level goal is to provide a strong foundation of free software for a
global, distributed network that provides security and privacy.  GNUnet in
that sense aims to replace the current internet protocol stack.  Along with
an application for secure publication of files, it has grown to include all
kinds of basic applications for the foundation of a GNU internet.")
   (license license:gpl3+)
   (home-page "https://gnunet.org/")))

(define-public guile-gnunet                       ;GSoC 2015!
  (let ((commit "383eac2aab175d8d9ea5315c2f1c8a5055c76a52"))
    (package
      (name "guile-gnunet")
      (version (string-append "0.0." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "git://git.sv.gnu.org/guix/gnunet.git")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "0k6mn28isjlxrnvbnblab3nh2xqx1b7san8k98kc35ap9lq0iz8w"))))
      (build-system gnu-build-system)
      (arguments
       '(#:phases (modify-phases %standard-phases
                    (add-before 'configure 'bootstrap
                      (lambda _
                        (zero? (system* "autoreconf" "-vfi")))))))
      (native-inputs `(("pkg-config" ,pkg-config)
                       ("autoconf" ,(autoconf-wrapper))
                       ("automake" ,automake)))
      (inputs `(("guile" ,guile-2.0)
                ("gnunet" ,gnunet)))
      (synopsis "Guile bindings for GNUnet services")
      (description
       "This package provides Guile bindings to the client libraries of various
GNUnet services, including the @dfn{identity} and @dfn{file sharing}
services.")
      (home-page "http://gnu.org/software/guix")
      (license license:gpl3+))))

;; FIXME: "gnunet-setup" segfaults under certain conditions and "gnunet-gtk"
;; does not seem to be fully functional.  This has been reported upstream:
;; http://lists.gnu.org/archive/html/gnunet-developers/2016-02/msg00004.html
(define-public gnunet-gtk
  (package (inherit gnunet)
    (name "gnunet-gtk")
    (version (package-version gnunet))
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/gnunet/gnunet-gtk-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1p38k1s6a2fmcfc9a7cf1zrdycm9h06kqdyand4s3k500nj6mb4g"))))
    (arguments
     `(#:configure-flags
       (list "--without-libunique"
             "--with-qrencode"
             (string-append "--with-gnunet="
                            (assoc-ref %build-inputs "gnunet")))))
    (inputs
     `(("gnunet" ,gnunet)
       ("libgcrypt" ,libgcrypt)
       ("gtk+" ,gtk+)
       ("libextractor" ,libextractor)
       ("glade3" ,glade3)
       ("qrencode" ,qrencode)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("libglade" ,libglade)))
    (synopsis "Graphical front-end tools for GNUnet")))
