;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 David Craven <david@craven.ch>
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

(define-module (gnu packages spice)
  #:use-module (gnu packages)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gstreamer)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages image)
  #:use-module (gnu packages libusb)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xiph)
  #:use-module (gnu packages xml)
  #:use-module (guix build-system gnu)
  #:use-module (guix download)
  #:use-module (guix packages)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix utils))

(define-public usbredir
  (package
    (name "usbredir")
    (version "0.7.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                "http://spice-space.org/download/usbredir/"
                "usbredir-" version ".tar.bz2"))
              (sha256
               (base32
                "1wsnmk4wjpdhbn1zaxg6bmyxspcki2zgy0am9lk037rnl4krwzj0"))))
    (build-system gnu-build-system)
    (propagated-inputs
      `(("libusb" ,libusb)))
    (native-inputs
      `(("pkg-config" ,pkg-config)))
    (synopsis "Tools for sending USB device traffic over a network")
    (description "Usbredir is a network protocol for sending USB device traffic
over a network connection.  It can be used to redirect traffic from a USB device
to a different (virtual) machine than the one to which the USB device is
attached.")
    (home-page "http://www.spice-space.org")
    (license (list license:gpl2+ license:lgpl2.0+ license:lgpl2.1+))))

(define-public virglrenderer
  (package
    (name "virglrenderer")
    (version "0.5.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                "https://www.freedesktop.org/software/virgl/"
                "virglrenderer-" version ".tar.bz2"))
              (sha256
               (base32
                "1dj0j8nbyr7nrpds4dqlp43ji8ixjyqhgw6ywlz1r9dn6cs5m5d1"))))
    (build-system gnu-build-system)
    (inputs
      `(("libepoxy" ,libepoxy)
        ("mesa" ,mesa)
        ("udev" ,eudev)))
    (native-inputs
      `(("pkg-config" ,pkg-config)))
    (synopsis "Virtual 3D GPU library")
    (description "A virtual 3D GPU library that enables a virtualized operating
system to use the host GPU to accelerate 3D rendering.")
    (home-page "https://virgil3d.github.io")
    (license (list license:expat license:bsd-3))))

(define-public spice-protocol
  (package
    (name "spice-protocol")
    (version "0.12.11")
    (source (origin
              (method url-fetch)
              (uri (string-append
                "http://www.spice-space.org/download/releases/"
                "spice-protocol-" version ".tar.bz2"))
              (sha256
               (base32
                "0c33kg3vdz3nnl2wjfbgmszz5hbjbvsw6map35dj9hxnpwwf9fi2"))))
    (build-system gnu-build-system)
    (synopsis "Protocol headers for the SPICE protocol")
    (description "SPICE (the Simple Protocol for Independent Computing
Environments) is a remote-display system built for virtual environments
which allows users to view a desktop computing environment.")
    (home-page "http://www.spice-space.org")
    (license (list license:bsd-3 license:lgpl2.1+))))

(define-public spice-gtk
  (package
    (name "spice-gtk")
    (version "0.32")
    (source (origin
              (method url-fetch)
              (uri (string-append
                "http://spice-space.org/download/gtk/"
                "spice-gtk-" version ".tar.bz2"))
              (sha256
               (base32
                "00pf94xh2xf0h1g13lnavxrysd0d0x22l5jl108cvq1mjc4z8j2c"))))
    (build-system gnu-build-system)
    (propagated-inputs
      `(("gstreamer" ,gstreamer)
        ("gst-libav" ,gst-libav)
        ("gst-plugins-base" ,gst-plugins-base)
        ("gst-plugins-good" ,gst-plugins-good)
        ("gst-plugins-bad" ,gst-plugins-bad)
        ("gst-plugins-ugly" ,gst-plugins-ugly)
        ("spice-protocol" ,spice-protocol)))
    (inputs
      `(("glib-networking" ,glib-networking)
        ("gtk+" ,gtk+)
        ("libepoxy" ,libepoxy)
        ("libjpeg" ,libjpeg)
        ("libxcb" ,libxcb)
        ("lz4" ,lz4)
        ("mesa" ,mesa)
        ("pixman" ,pixman)
        ("pulseaudio" ,pulseaudio)
        ("python" ,python)
        ("openssl" ,openssl)
        ("opus" ,opus)
        ("usbredir" ,usbredir)))
    (native-inputs
      `(("glib:bin" ,glib "bin")
        ("intltool" ,intltool)
        ("pkg-config" ,pkg-config)))
    (arguments
      `(#:configure-flags
        '("--enable-gstaudio"
          "--enable-gstvideo"
          "--enable-pulse")
        #:phases
         (modify-phases %standard-phases
           (add-after
            'install 'wrap-spicy
            (lambda* (#:key inputs outputs #:allow-other-keys)
              (let ((out             (assoc-ref outputs "out"))
                    (gst-plugin-path (getenv "GST_PLUGIN_SYSTEM_PATH")))
                (wrap-program (string-append out "/bin/spicy")
                  `("GST_PLUGIN_SYSTEM_PATH" ":" prefix (,gst-plugin-path))))
              #t)))))
    (synopsis "Gtk client and libraries for SPICE remote desktop servers")
    (description "Gtk client and libraries for SPICE remote desktop servers.")
    (home-page "http://www.spice-space.org")
    (license (list license:lgpl2.1+ license:lgpl2.0+))))

(define-public spice
  (package
    (name "spice")
    (version "0.13.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                "http://www.spice-space.org/download/releases/"
                "spice-" version ".tar.bz2"))
              (sha256
               (base32
                "18hxk47z58cqbix5h477qmvcdmsrwzv984jw4c6fj0ns4h217jwy"))))
    (build-system gnu-build-system)
    (propagated-inputs
      `(("openssl" ,openssl)
        ("pixman" ,pixman)
        ("spice-protocol" ,spice-protocol)))
    (inputs
      `(("glib" ,glib)
        ("libjpeg" ,libjpeg)
        ("lz4" ,lz4)
        ("opus" ,opus)
        ("zlib" ,zlib)))
    (native-inputs
      `(("pkg-config" ,pkg-config)
        ("python" ,python)
        ("spice-gtk" ,spice-gtk)))
    (arguments
      `(#:configure-flags
        '("--disable-celt051" ; Disable support for unpackaged audio codec
          "--enable-lz4"
          "--enable-automated-tests")))
    (synopsis "Server implementation of the SPICE protocol")
    (description "SPICE is a remote display system built for virtual
environments which allows you to view a computing 'desktop' environment
not only on the machine where it is running, but from anywhere on the
Internet and from a wide variety of machine architectures.")
    (home-page "http://www.spice-space.org")
    (license (list license:lgpl2.1+ license:lgpl2.0+))))

(define-public spice-vdagent
  (package
    (name "spice-vdagent")
    (version "0.17.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                "http://www.spice-space.org/download/releases/"
                "spice-vdagent-" version ".tar.bz2"))
              (sha256
               (base32
                "0gdkyylyg1hksg0i0anvznqfli2q39335fnrmcd6847frpc8njpi"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags
       '("--localstatedir=/var")
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-makefile.in
           (lambda _
             (substitute* "Makefile.in"
               (((string-append "\\$\\(mkdir_p\\) \\$\\(DESTDIR\\)"
                                "\\$\\(localstatedir\\)/run/spice-vdagentd"))
                 "-$(mkdir_p) $(DESTDIR)$(localstatedir)/run/spice-vdagentd"))
             #t)))))
    (inputs
      `(("alsa-lib" ,alsa-lib)
        ("dbus" ,dbus)
        ("glib" ,glib)
        ("libpciaccess" ,libpciaccess)
        ("libx11" ,libx11)
        ("libxext" ,libxext)
        ("libxfixes" ,libxfixes)
        ("libxinerama" ,libxinerama)
        ("libxrandr" ,libxrandr)
        ("spice-protocol" ,spice-protocol)))
    (native-inputs
      `(("pkg-config" ,pkg-config)))
    (synopsis "Spice agent for Linux")
    (description "Spice-vdagent enables sharing the clipboard and guest display
resolution scaling on graphical console window resize.")
    (home-page "http://www.spice-space.org")
    (license license:gpl3+)))

(define-public virt-viewer
  (package
    (name "virt-viewer")
    (version "4.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                "https://virt-manager.org/download/sources/virt-viewer/"
                "virt-viewer-" version ".tar.gz"))
              (sha256
               (base32
                "07zsi1fqg05mag1ayniaqj25fzb6dxg76d4ka5196lq4l477nhhw"))))
    (build-system gnu-build-system)
    (inputs
      `(("gtk+" ,gtk+)
        ("libcap" ,libcap)
        ("libxml2" ,libxml2)
        ("openssl" ,openssl)
        ("spice-gtk" ,spice-gtk)))
    (native-inputs
      `(("glib:bin" ,glib "bin")
        ("intltool" ,intltool)
        ("pkg-config" ,pkg-config)))
    (arguments
      `(#:configure-flags
        '("--with-spice-gtk")
        #:phases
         (modify-phases %standard-phases
           (add-after
            'install 'wrap-remote-viewer
            (lambda* (#:key inputs outputs #:allow-other-keys)
              (let ((out             (assoc-ref outputs "out"))
                    (gst-plugin-path (getenv "GST_PLUGIN_SYSTEM_PATH")))
                (wrap-program (string-append out "/bin/remote-viewer")
                  `("GST_PLUGIN_SYSTEM_PATH" ":" prefix (,gst-plugin-path))))
              #t)))))
    (synopsis "Graphical console client for virtual machines")
    (description "Graphical console client for virtual machines using SPICE or
VNC.")
    (home-page "https://virt-manager.org")
    (license license:gpl2+)))
