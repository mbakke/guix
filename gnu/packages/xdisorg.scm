;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2014, 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2014, 2015 Alex Kost <alezost@gmail.com>
;;; Copyright © 2013, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Mathieu Lirzin <mthl@openmailbox.org>
;;; Copyright © 2015 Alexander I.Grafov <grafov@gmail.com>
;;; Copyright © 2015 Andy Wingo <wingo@igalia.com>
;;; Copyright © 2015 xd1le <elisp.vim@gmail.com>
;;; Copyright © 2015 Florian Paul Schmidt <mista.tapas@gmx.net>
;;; Copyright © 2016 Christopher Allan Webber <cwebber@dustycloud.org>
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

(define-module (gnu packages xdisorg)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system glib-or-gtk)
  #:use-module (guix build-system python)
  #:use-module (gnu packages)
  #:use-module (gnu packages asciidoc)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages image)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)               ;for libgudev
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages python)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages qt)
  #:use-module (gnu packages xorg))

;; packages outside the x.org system proper

(define-public arandr
  (package
    (name "arandr")
    (version "0.1.8")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://christian.amsuess.com/tools/" name
                                  "/files/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "0d574mbmhaqmh7kivaryj2hpghz6xkvic9ah43s1hf385y7c33kd"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2     ;incompatible with python 3
       #:tests? #f ;no tests
       #:phases
       (modify-phases %standard-phases
         (add-after 'install 'make-xrandr-available
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (wrap-program (string-append (assoc-ref outputs "out")
                                          "/bin/arandr")
               `("PATH" ":" prefix (,(string-append (assoc-ref inputs "xrandr")
                                                    "/bin"))))
             #t)))))
    (inputs `(("pygtk" ,python2-pygtk)
              ("xrandr" ,xrandr)))
    (native-inputs `(("gettext"           ,gnu-gettext)
                     ("python-docutils"   ,python2-docutils)
                     ("python-setuptools" ,python2-setuptools)))
    (home-page "https://christian.amsuess.com/tools/arandr/")
    (synopsis "Another RandR graphical user interface")
    ;; TRANSLATORS: "X11 resize-and-rotate" should not be translated.
    (description "ARandR is designed to provide a simple visual front end for
the X11 resize-and-rotate (RandR) extension.  Relative monitor positions are
shown graphically and can be changed in a drag-and-drop way.  Configurations
are saved as executable shell scripts which can be loaded without using this
program.")
    (license license:gpl3+)))

(define-public xclip
  (package
    (name "xclip")
    (version "0.12")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
              "mirror://sourceforge/" name "/" name "-" version ".tar.gz"))
        (sha256
          (base32
           "0ibcf46rldnv0r424qcnai1fa5iq3lm5q5rdd7snsi5sb78gmixp"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f))   ; There is no test suite
    (inputs `(("libxmu" ,libxmu)
              ("libxt" ,libxt)))
    (home-page "http://xclip.sourceforge.net/")
    (synopsis "Command line interface to X11 clipboard")
    (description "Xclip is a command line interface to the X11 clipboard.  It
can also be used for copying files, as an alternative to sftp/scp, thus
avoiding password prompts when X11 forwarding has already been setup.")
    (license license:gpl2+)))

(define-public xdotool
  (package
    (name "xdotool")
    (version "3.20150503.1")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
              "https://github.com/jordansissel/xdotool/releases/download/v"
              version "/xdotool-" version ".tar.gz"))
        (sha256
          (base32
           "1lcngsw33fy9my21rdiz1gs474bfdqcfxjrnfggbx4aypn1nhcp8"))
        (patches (list (search-patch "xdotool-fix-makefile.patch")))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ; Test suite requires a lot of black magic
       #:phases
       (alist-replace 'configure
                      (lambda* (#:key outputs #:allow-other-keys #:rest args)
                        (setenv "PREFIX" (assoc-ref outputs "out"))
                        (setenv "LDFLAGS" (string-append "-Wl,-rpath="
                                               (assoc-ref
                                                %outputs "out") "/lib"))
                        (setenv "CC" "gcc"))
                      %standard-phases)))
    (native-inputs `(("perl" ,perl))) ; for pod2man
    (inputs `(("libx11" ,libx11)
              ("libxext" ,libxext)
              ("libxi" ,libxi)
              ("libxinerama" ,libxinerama)
              ("libxtst" ,libxtst)
              ("libxkbcommon" ,libxkbcommon)))
    (home-page "http://www.semicomplete.com/projects/xdotool")
    (synopsis "Fake keyboard/mouse input, window management, and more")
    (description "Xdotool lets you simulate keyboard input and mouse activity,
move and resize windows, etc.  It does this using X11's XTEST extension and
other Xlib functions.  Additionally, you can search for windows and move,
resize, hide, and modify window properties like the title.  If your window
manager supports it, you can use xdotool to switch desktops, move windows
between desktops, and change the number of desktops.")
    (license license:bsd-3)))

(define-public xeyes
  (package
    (name "xeyes")
    (version "1.0.1")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
               "http://xeyes.sourcearchive.com/downloads/1.0.1/xeyes_"
               version
               ".orig.tar.gz"))
        (sha256
          (base32
            "04c3md570j67g55h3bix1qbngcslnq91skli51k3g1avki88zkm9"))))
    (build-system gnu-build-system)
    (inputs
      `(("libxext" ,libxext)
        ("libxmu" ,libxmu)
        ("libxt" ,libxt)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://xeyes.sourcearchive.com/")
    (synopsis "Follow-the-mouse X demo")
    (description "Xeyes is a demo program for x.org.  It shows eyes
following the mouse.")
    (license license:x11)))


(define-public pixman
  (package
    (name "pixman")
    (version "0.34.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://cairographics.org/releases/pixman-"
                    version ".tar.gz"))
              (sha256
               (base32
                "13m842m9ffac3m9r0b4lvwjhwzg3w4353djkjpf00s0wnm4v5di1"))))
    (build-system gnu-build-system)
    (inputs
     `(("libpng" ,libpng)
       ("zlib" ,zlib)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://www.pixman.org/")
    (synopsis "Low-level pixel manipulation library")
    (description "Pixman is a low-level software library for pixel
manipulation, providing features such as image compositing and trapezoid
rasterisation.")
    (license license:x11)))


(define-public libdrm
  (package
    (name "libdrm")
    (version "2.4.65")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
               "https://dri.freedesktop.org/libdrm/libdrm-"
               version
               ".tar.bz2"))
        (sha256
          (base32
            "1i4n7mz49l0j4kr0dg9n1j3hlc786ncqgj0v5fci1mz7pp40m5ki"))
        (patches (list (search-patch "libdrm-symbol-check.patch")))))
    (build-system gnu-build-system)
    (inputs
      `(("libpciaccess" ,libpciaccess)
        ("libpthread-stubs" ,libpthread-stubs)))
    (native-inputs
       `(("pkg-config" ,pkg-config)))
    (home-page "http://dri.freedesktop.org/wiki/")
    (synopsis "Direct rendering userspace library")
    (description "The Direct Rendering Infrastructure, also known as the DRI,
is a framework for allowing direct access to graphics hardware under the
X Window System in a safe and efficient manner.  It includes changes to the
X server, to several client libraries, and to the kernel (DRM, Direct
Rendering Manager).  The most important use for the DRI is to create fast
OpenGL implementations providing hardware acceleration for Mesa.
Several 3D accelerated drivers have been written to the DRI specification,
including drivers for chipsets produced by 3DFX, AMD (formerly ATI), Intel
and Matrox.")
    (license license:x11)))


(define-public mtdev
  (package
    (name "mtdev")
    (version "1.1.3")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
               "http://bitmath.org/code/mtdev/mtdev-"
               version ".tar.bz2"))
        (sha256
          (base32
            "159ndzwfpw0xr8mw4lhl47w9c2krshlfrscs7k6n186vknv2hk3d"))))
    (build-system gnu-build-system)
    (home-page "http://bitmath.org/code/mtdev/")
    (synopsis "Multitouch protocol translation library")
    (description "Mtdev is a stand-alone library which transforms all
variants of kernel MT events to the slotted type B protocol.  The events
put into mtdev may be from any MT device, specifically type A without
contact tracking, type A with contact tracking, or type B with contact
tracking.")
    (license license:x11)))

(define-public startup-notification
  (package
    (name "startup-notification")
    (version "0.12")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://www.freedesktop.org/software/" name
                           "/releases/" name "-" version ".tar.gz"))
       (sha256
        (base32
         "0jmyryrpqb35y9hd5sgxqy2z0r1snw7d3ljw0jak0n0cjdz1yf9w"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)))
    (inputs
     `(("libx11" ,libx11)
       ("xcb-util" ,xcb-util)))
    (home-page "http://www.freedesktop.org/wiki/Software/startup-notification/")
    (synopsis "Application startup notification and feedback library")
    (description
     "Startup-notification contains a reference implementation of the startup
notification protocol.  The reference implementation is mostly under an X Window
System style license, and has no special dependencies.")
    ;; Most of the code is provided under x11 license.
    (license license:lgpl2.0+)))

(define-public wmctrl
  (package
    (name "wmctrl")
    (version "1.07")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://sites.google.com/site/tstyblo/wmctrl/wmctrl-"
                    version ".tar.gz"))
              (sha256
               (base32
                "1afclc57b9017a73mfs9w7lbdvdipmf9q0xdk116f61gnvyix2np"))
              (patches (list (search-patch "wmctrl-64-fix.patch")))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags
       (list (string-append "--mandir="
                            (assoc-ref %outputs "out")
                            "/share/man"))))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("libx11" ,libx11)
       ("libxmu" ,libxmu)
       ("glib" ,glib)))
    (home-page "http://tomas.styblo.name/wmctrl/")
    (synopsis "Command-line tool to control X window managers")
    (description
     "Wmctrl allows to interact with an X window manager that is compatible
with the EWMH/NetWM specification.  It can query the window manager for
information, and request for certain window management actions (resize and
move windows, switch between desktops, etc.).")
    (license license:gpl2+)))

(define-public scrot
  (package
    (name "scrot")
    (version "0.8")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://linuxbrit.co.uk/downloads/scrot-"
                    version ".tar.gz"))
              (sha256
               (base32
                "1wll744rhb49lvr2zs6m93rdmiq59zm344jzqvijrdn24ksiqgb1"))))
    (build-system gnu-build-system)
    (arguments
     ;; By default, man and doc are put in PREFIX/{man,doc} instead of
     ;; PREFIX/share/{man,doc}.
     '(#:configure-flags
       (list (string-append "--mandir="
                            (assoc-ref %outputs "out")
                            "/share/man"))
       #:phases (alist-replace
                 'install
                 (lambda* (#:key inputs outputs #:allow-other-keys)
                   (let* ((out (assoc-ref outputs "out"))
                          (doc (string-append out "/share/doc/scrot")))
                     (mkdir-p doc)
                     (zero?
                      (system* "make" "install"
                               (string-append "docsdir=" doc)))))
                 %standard-phases)))
    (inputs
     `(("libx11" ,libx11)
       ("giblib" ,giblib)))
    (home-page "http://linuxbrit.co.uk/software/")
    (synopsis "Command-line screen capture utility for X Window System")
    (description
     "Scrot allows to save a screenshot of a full screen, a window or a part
of the screen selected by mouse.")
    ;; This license removes a clause about X Consortium from the original
    ;; X11 license.
    (license (license:x11-style "file://COPYING"
                                "See 'COPYING' in the distribution."))))

(define-public unclutter
  (package
    (name "unclutter")
    (version "8")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://ftp.x.org/contrib/utilities/unclutter-"
                    version ".tar.Z"))
              (sha256
               (base32
                "0ahrr5z6wxqqfyihm112hnq0859zlxisrb3y5232zav58j6sfmdq"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f                      ; no check target
       #:phases (alist-delete
                 'configure
                 (alist-replace
                  'install
                  (lambda* (#:key inputs outputs #:allow-other-keys)
                    (let* ((out  (assoc-ref outputs "out"))
                           (bin  (string-append out "/bin"))
                           (man1 (string-append out "/share/man/man1")))
                      (mkdir-p bin)
                      (mkdir-p man1)
                      (zero?
                       (system* "make" "install" "install.man"
                                (string-append "BINDIR=" bin)
                                (string-append "MANDIR=" man1)))))
                  %standard-phases))))
    (inputs `(("libx11" ,libx11)))
    (home-page "http://ftp.x.org/contrib/utilities/")
    (synopsis "Hide idle mouse cursor")
    (description
     "Unclutter is a program which runs permanently in the background of an
X11 session.  It checks on the X11 pointer (cursor) position every few
seconds, and when it finds it has not moved (and no buttons are pressed
on the mouse, and the cursor is not in the root window) it creates a
small sub-window as a child of the window the cursor is in.  The new
window installs a cursor of size 1x1 but a mask of all 0, i.e. an
invisible cursor.  This allows you to see all the text in an xterm or
xedit, for example.  The human factors crowd would agree it should make
things less distracting.")
    (license license:public-domain)))

(define-public xlockmore
  (package
    (name "xlockmore")
    (version "5.46")
    (source (origin
             (method url-fetch)
             (uri (list (string-append
                          "http://www.tux.org/~bagleyd/xlock/xlockmore-"
                          version ".tar.xz")
                        (string-append
                          "http://www.tux.org/~bagleyd/xlock/xlockmore-old"
                          "/xlockmore-" version
                          "/xlockmore-" version ".tar.bz2")))
             (sha256
              (base32
               "1ps0dmnh912x8mwns94y2607xk90rjxrjn5s1pkmmpjg5h9bxcrj"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags (list (string-append "--enable-appdefaultdir="
                                              (assoc-ref %outputs "out")
                                              "/lib/X11/app-defaults"))
       #:tests? #f))                            ;no such thing as a test suite
    (inputs
     `(("libX11" ,libx11)
       ("libXext" ,libxext)
       ("libXt" ,libxt)
       ("linux-pam" ,linux-pam)))
    (home-page "http://www.tux.org/~bagleyd/xlockmore.html")
    (synopsis "Screen locker for the X Window System")
    (description
     "XLockMore is a classic screen locker and screen saver for the
X Window System.")
    (license (license:non-copyleft #f "See xlock.c.")
             ;; + GPLv2 in modes/glx/biof.c.
             )))

(define-public xosd
  (package
    (name "xosd")
    (version "2.2.14")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://sourceforge/libxosd/xosd-"
                    version ".tar.gz"))
              (sha256
               (base32
                "025m7ha89q29swkc7s38knnbn8ysl24g2h5s7imfxflm91psj7sg"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags
       (list (string-append "--mandir=" %output "/share/man"))))
    (inputs
     `(("libx11" ,libx11)
       ("libxt" ,libxt)
       ("libxext" ,libxext)
       ("libxinerama" ,libxinerama)))
    (home-page "http://sourceforge.net/projects/libxosd/")
    (synopsis "X On Screen Display")
    (description
     "XOSD provides a C library and a simple utility (osd_cat) for displaying
transparent text on your screen.")
    (license license:gpl2+)))

(define-public xbindkeys
  (package
    (name "xbindkeys")
    (version "1.8.6")
    (source (origin
              (method url-fetch)
              ;; Download from the savannah mirror list fails
              (uri (string-append
                    "http://www.nongnu.org/xbindkeys/xbindkeys-"
                    version
                    ".tar.gz"))
              (sha256
               (base32
                "060df6d8y727jp1inp7blp44cs8a7jig7vcm8ndsn6gw36z1h3bc"))))
    (build-system gnu-build-system)
    (inputs
     `(("libx11" ,libx11)
       ("guile" ,guile-2.0)))
    (home-page "http://www.nongnu.org/xbindkeys/")
    (synopsis "Associate a combination of keys with a shell command")
    (description
     "XBindKeys is a program that allows you to launch shell commands with
your keyboard or your mouse under the X Window System.  It links commands to
keys or mouse buttons, using a configuration file.  It's independent of the
window manager and can capture all keyboard keys (ex: Power, Wake...).  It
optionally supports a Guile-based configuration file layout, which enables you
to access all XBindKeys internals, so you can have key combinations, double
clicks or timed double clicks take actions.  Also all functions that work in
Guile will work for XBindKeys.")
    (license license:gpl2+)))

(define-public sxhkd
  (package
    (name "sxhkd")
    (version "0.5.5")
    (source
     (origin
       (file-name (string-append name "-" version ".tar.gz"))
       (method url-fetch)
       (uri (string-append
             "https://github.com/baskerville/sxhkd/archive/"
             version ".tar.gz"))
       (sha256
        (base32
         "04s3y2bq9502gw72jj3y2zsh96yj3qg2av3zsa8ahd2farvrysg6"))))
    (build-system gnu-build-system)
    (inputs
     `(("asciidoc" ,asciidoc)
       ("libxcb" ,libxcb)
       ("xcb-util" ,xcb-util)
       ("xcb-util-keysyms" ,xcb-util-keysyms)
       ("xcb-util-wm" ,xcb-util-wm)))
    (arguments
     '(#:phases (alist-delete 'configure %standard-phases)
       #:tests? #f  ; no check target
       #:make-flags (list "CC=gcc"
                          (string-append "PREFIX=" %output))))
    (home-page "https://github.com/baskerville/sxhkd")
    (synopsis "Simple X hotkey daemon")
    (description "sxhkd is a simple X hotkey daemon with a powerful and
compact configuration syntax.")
    (license license:bsd-2)))

(define-public rxvt-unicode
  (package
    (name "rxvt-unicode")
    (version "9.21")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://dist.schmorp.de/rxvt-unicode/Attic/"
                                  name "-" version ".tar.bz2"))
              (sha256
               (base32
                "0swmi308v5yxsddrdhvi4cch88k2bbs2nffpl5j5m2f55gbhw9vm"))))
    (build-system gnu-build-system)
    (arguments
     ;; This sets the destination when installing the necessary terminal
     ;; capability data, which are not provided by 'ncurses'.  See
     ;; https://lists.gnu.org/archive/html/bug-ncurses/2009-10/msg00031.html
     '(#:make-flags (list (string-append "TERMINFO="
                                         (assoc-ref %outputs "out")
                                         "/share/terminfo"))))
    (inputs
     `(("libXft" ,libxft)
       ("libX11" ,libx11)))
    (native-inputs
     `(("ncurses" ,ncurses)         ;trigger the installation of terminfo data
       ("perl" ,perl)
       ("pkg-config" ,pkg-config)))
    ;; FIXME: This should only be located in 'ncurses'.  Nonetheless it is
    ;; provided for usability reasons.  See <https://bugs.gnu.org/22138>.
    (native-search-paths
     (list (search-path-specification
            (variable "TERMINFO_DIRS")
            (files '("share/terminfo")))))
    (home-page "http://software.schmorp.de/pkg/rxvt-unicode.html")
    (synopsis "Rxvt clone with XFT and unicode support")
    (description "Rxvt-unicode (urxvt) is a colour vt102 terminal emulator
intended as an xterm replacement for users who do not require features such as
Tektronix 4014 emulation and toolkit-style configurability.  It supports
unicode, XFT and may be extended with Perl plugins.  It also comes with a
client/daemon pair that lets you open any number of terminal windows from
within a single process.")
    (license license:gpl3+)))

(define-public xcape
  (package
    (name "xcape")
    (version "1.1")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "https://github.com/alols/" name
                            "/archive/v" version ".tar.gz"))
        (file-name (string-append name "-" version ".tar.gz"))
        (sha256
          (base32
            "0jkdiaxc6sryrbibdgi2y1c48n4l9xyazhxr16l6h4ibddx95bk9"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; no check target
       #:phases (alist-delete 'configure %standard-phases) ; no configure script
       #:make-flags (list (string-append "PREFIX=" (assoc-ref %outputs "out"))
                          "MANDIR=/share/man/man1"
                          "CC=gcc")))
    (inputs
     `(("libxtst" ,libxtst)
       ("libx11" ,libx11)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://github.com/alols/xcape")
    (synopsis "Use a modifier key in X.org as another key")
    (description
     "This utility for X.org allows to use modifier key as another key when
pressed and released on its own.  The default behaviour is to generate the
Escape key when Left Control is pressed and released on its own.")
    (license license:gpl3+)))

(define-public libwacom
  (package
    (name "libwacom")
    (version "0.12")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/linuxwacom/libwacom/"
                                  name "-" version ".tar.bz2"))
              (sha256
               (base32
                "022d0097dk2glgb6772zpcsqm1w42sbsbr3i72pdhzq6naqawys8"))))
    (build-system glib-or-gtk-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("gtk+" ,gtk+)
       ("libgudev" ,libgudev)
       ("eudev" ,eudev)
       ("libxml2" ,libxml2)))
    (propagated-inputs
     ;; libwacom includes header files that include GLib, and libinput uses
     ;; those header files.
     `(("glib" ,glib)))
    (home-page "http://linuxwacom.sourceforge.net/")
    (synopsis "Helper library for Wacom tablet settings")
    (description
     "Libwacom is a library to help implement Wacom tablet settings.  It is
intended to be used by client-programs that need model identification.  It is
already being used by the gnome-settings-daemon and the GNOME Control Center
Wacom tablet applet.")
    (license license:x11)))

(define-public xf86-input-wacom
  (package
    (name "xf86-input-wacom")
    (version "0.29.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://sourceforge/linuxwacom/xf86-input-wacom/"
                    name "-" version ".tar.bz2"))
              (sha256
               (base32
                "15lbzjkaf690i69qy0n0ibwczbclqq1nx0418c6a567by5v7wl48"))))
    (arguments
     `(#:configure-flags
       (list (string-append "--with-sdkdir="
                            (assoc-ref %outputs "out")
                            "/include/xorg")
             (string-append "--with-xorg-conf-dir="
                            (assoc-ref %outputs "out")
                            "/share/X11/xorg.conf.d"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("xorg-server" ,xorg-server)
       ("libxrandr" ,libxrandr)
       ("libxinerama" ,libxinerama)
       ("libxi" ,libxi)
       ("eudev" ,eudev)))
    (home-page "http://linuxwacom.sourceforge.net/")
    (synopsis "Wacom input driver for X")
    (description
     "The xf86-input-wacom driver is the wacom-specific X11 input driver for
the X.Org X Server version 1.7 and later (X11R7.5 or later).")
    (license license:x11)))

(define-public redshift
  (package
    (name "redshift")
    (version "1.11")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "https://github.com/jonls/redshift/"
                       "releases/download/v" version
                       "/redshift-" version ".tar.xz"))
       (sha256
        (base32
         "0ngkwj7rg8nfk806w0sg443w6wjr91xdc0zisqfm5h2i77wm1qqh"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("intltool" ,intltool)))
    (inputs
     `(("libdrm" ,libdrm)
       ("libx11" ,libx11)
       ("libxcb" ,libxcb)
       ("libxxf86vm" ,libxxf86vm)
       ("glib" ,glib)))                           ;for Geoclue2 support
    (home-page "https://github.com/jonls/redshift")
    (synopsis "Adjust the color temperature of your screen")
    (description
     "Redshift adjusts the color temperature according to the position of the
sun.  A different color temperature is set during night and daytime.  During
twilight and early morning, the color temperature transitions smoothly from
night to daytime temperature to allow your eyes to slowly adapt.  At night the
color temperature should be set to match the lamps in your room.")
    (license license:gpl3+)))
