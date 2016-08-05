;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Kei Kebreau <kei@openmailbox.org>
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

(define-module (gnu packages gnustep)
  #:use-module (guix download)
  #:use-module (guix packages)
  #:use-module (guix build-system gnu)
  #:use-module (guix licenses)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages image)
  #:use-module (gnu packages pkg-config))

(define-public windowmaker
  (package
    (name "windowmaker")
    (version "0.95.6")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://windowmaker.org/pub/source/release/WindowMaker-"
                    version ".tar.gz"))
              (sha256
               (base32
                "1i3dw1yagsa3rs9x2na2ynqlgmbahayws0kz4vl00fla6550nns3"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (alist-cons-before
                 'configure 'pre-configure
                 (lambda* (#:key outputs #:allow-other-keys)
                   ;; 'wmaker' wants to invoke 'wmaker.inst' the first time,
                   ;; and the 'wmsetbg', so make sure it uses the right ones.
                   ;; We can't use a wrapper here because that would pollute
                   ;; $PATH in the whole session.
                   (let* ((out (assoc-ref outputs "out"))
                          (bin (string-append out "/bin")))
                     (substitute* "src/main.c"
                       (("\"wmaker\\.inst")
                        (string-append "\"" bin "/wmaker.inst")))
                     (substitute* '("src/defaults.c" "WPrefs.app/Menu.c")
                       (("\"wmsetbg")
                        (string-append "\"" bin "/wmsetbg")))))
                 (alist-cons-after
                  'install 'wrap
                  (lambda* (#:key outputs #:allow-other-keys)
                    (let* ((out (assoc-ref outputs "out"))
                           (bin (string-append out "/bin")))
                      ;; In turn, 'wmaker.inst' wants to invoke 'wmmenugen'
                      ;; etc., so make sure everything is in $PATH.
                      (wrap-program (string-append bin "/wmaker.inst")
                                    `("PATH" ":" prefix (,bin)))))
                  %standard-phases))))
    (inputs
     `(("libxmu" ,libxmu)
       ("libxft" ,libxft)
       ("libx11" ,libx11)
       ("fontconfig" ,fontconfig)
       ("libjpeg" ,libjpeg)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://windowmaker.org/")
    (synopsis "NeXTSTEP-like window manager")
    (description
     "Window Maker is an X11 window manager originally designed to provide
integration support for the GNUstep Desktop Environment.  In every way
possible, it reproduces the elegant look and feel of the NeXTSTEP user
interface.  It is fast, feature rich, easy to configure, and easy to use.")

    ;; Artwork is distributed under the WTFPL.
    (license gpl2+)))

(define-public wmbattery
  (package
    (name "wmbattery")
    (version "2.50")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://debian/pool/main/w/wmbattery/wmbattery_"
                    version ".orig.tar.gz"))
              (sha256
               (base32
                "0hi6bivv3xd2k68w08krndfl68wdx7nmc2wjzsmcd4q3qgwgyk44"))
              (modules '((guix build utils)))
              (snippet
               ;; Fix memory leak:
               ;; <https://lists.gnu.org/archive/html/guix-devel/2016-05/msg00466.html>.
               '(substitute* "upower.c"
                  (("up = up_client_new\\(\\);")
                   (string-append "if (!up)\n"
                                  "                up = up_client_new();"))))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f              ; no "check" target
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'autoconf
           (lambda _ (zero? (system* "autoreconf" "-vfi")))))))
    (inputs
     `(("glib" ,glib)
       ("libx11" ,libx11)
       ("libxext" ,libxext)
       ("libxpm" ,libxpm)
       ("upower" ,upower)))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("pkg-config" ,pkg-config)))
    (home-page "http://windowmaker.org/dockapps/?name=wmbattery")
    (synopsis "Display laptop battery info")
    (description
     "Wmbattery displays the status of your laptop's battery in a small icon.
This includes if it is plugged in, if the battery is charging, how many minutes
of battery life remain, battery life remaining (with both a percentage and a
graph), and battery status (high - green, low - yellow, or critical - red).")
    (license gpl2)))

(define-public wmnd
  (package
    (name "wmnd")
    (version "0.4.17")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://www.thregr.org/~wavexx/software/wmnd/releases/"
                    name "-" version ".tar.gz"))
              (sha256
               (base32
                "1amkbiwgr31gwkcp7wrjsr7aj1kns8bpmjpv70n86wb8v9mpm828"))))
    (build-system gnu-build-system)
    (inputs
     `(("libx11" ,libx11)
       ("libxext" ,libxext)
       ("libxpm" ,libxpm)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://www.thregr.org/~wavexx/software/wmnd/")
    (synopsis "Network interface monitor")
    (description
     "WMND is a dockapp for monitoring network interfaces under WindowMaker and
other compatible window managers.")
    (license gpl2+)))

(define-public wmcpuload
  (package
    (name "wmcpuload")
    (version "1.0.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://debian/pool/main/w/wmcpuload/"
                    name "_" version ".orig.tar.gz"))
              (sha256
               (base32
                "0irlns4cvxy2mnicx75bya166hdxq7h8bphds3ligijcl9fzgs6n"))))
    (build-system gnu-build-system)
    (inputs
     `(("libx11" ,libx11)
       ("libxext" ,libxext)
       ("libxpm" ,libxpm)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://windowmaker.org/dockapps/?name=wmcpuload")
    (synopsis "Monitor CPU usage")
    (description
     "Wmcpuload displays the current CPU usage, expressed as a percentile and a
chart, and has an LCD look-alike user interface.  The back-light may be turned
on and off by clicking the mouse button over the application.  If the CPU usage
hits a certain threshold, an alarm-mode will alert you by turning back-light
on.")
    (license gpl2+)))

(define-public wmclock
  (package
    (name "wmclock")
    (version "1.0.16")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://debian/pool/main/w/wmclock/"
                    name "_" version ".orig.tar.gz"))
              (sha256
               (base32
                "1lx276ba8r2yydhmwj1g586jdqg695ad89ng36fr3mb067gvb2rz"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'autoconf
           (lambda _ (zero? (system* "autoreconf" "-vfi")))))))
    ;; wmclock requires autoreconf to generate its configure script.
    (inputs
     `(("libx11" ,libx11)
       ("libxext" ,libxext)
       ("libxpm" ,libxpm)))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("pkg-config" ,pkg-config)))
    (home-page "http://windowmaker.org/dockapps/?name=wmclock")
    (synopsis "Display the date and time")
    (description
     "wmclock is an applet for Window Maker which displays the date and time in
a dockable tile.  It features multiple language support, 24h or 12h time
display, and can run a user-specified program on mouse click.")
    (license gpl2+)))

(define-public wmfire
  (package
    (name "wmfire")
    (version "1.2.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.improbability.net/"
                                  name "/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "101grahd80n97y2dczb629clmcgiavdpbbwy78kk5wgs362m12z3"))))
    (build-system gnu-build-system)
    (inputs
     `(("gtk+" ,gtk+-2)
       ("libgtop" ,libgtop)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://www.improbability.net/")
    (synopsis "Display flames to represent resource usage")
    (description
     "wmfire is an applet for Window Maker that can monitor the average cpu
load, or individual cpu load on SMP computers.  Additionally it can monitor the
memory, network load, a file or just be set to show a pretty flame.  On
entering the dock a burning spot replaces the cursor, and after two seconds
symbols to represent the current monitor are \"burnt\" onscreen.  The flame
colour can also be changed.")
    (license gpl2+)))
