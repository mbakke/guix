;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2014, 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2014, 2015, 2016 Alex Kost <alezost@gmail.com>
;;; Copyright © 2013, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015, 2016 Mathieu Lirzin <mthl@gnu.org>
;;; Copyright © 2015 Alexander I.Grafov <grafov@gmail.com>
;;; Copyright © 2015 Andy Wingo <wingo@igalia.com>
;;; Copyright © 2015 xd1le <elisp.vim@gmail.com>
;;; Copyright © 2015 Florian Paul Schmidt <mista.tapas@gmx.net>
;;; Copyright © 2016 Christopher Allan Webber <cwebber@dustycloud.org>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
;;; Copyright © 2016 Alex Kost <alezost@gmail.com>
;;; Copyright © 2016 Marius Bakke <mbakke@fastmail.com>
;;; Copyright © 2016 Petter <petter@mykolab.ch>
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
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system glib-or-gtk)
  #:use-module (guix build-system python)
  #:use-module (gnu packages)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages image)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages m4)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages python)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages bison))

;; packages outside the x.org system proper

(define-public arandr
  (package
    (name "arandr")
    (version "0.1.9")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://christian.amsuess.com/tools/" name
                                  "/files/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "1i3f1agixxbfy4kxikb2b241p7c2lg73cl9wqfvlwz3q6zf5faxv"))))
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
    (native-inputs `(("gettext"           ,gettext-minimal)
                     ("python-docutils"   ,python2-docutils)))
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
              "mirror://sourceforge/" name "/" name "/" version "/"
              name "-" version ".tar.gz"))
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

(define-public libxkbcommon
  (package
    (name "libxkbcommon")
    (version "0.6.1")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://xkbcommon.org/download/" name "-"
                                 version ".tar.xz"))
             (sha256
              (base32
               "0q47xa1szlxwgvwmhv4b7xwawnykz1hnc431d84nj8dlh2q8f22v"))))
    (build-system gnu-build-system)
    (inputs
     `(("libx11" ,libx11)
       ("libxcb" ,libxcb)
       ("xkeyboard-config" ,xkeyboard-config)))
    (native-inputs
     `(("bison" ,bison)
       ("pkg-config" ,pkg-config)))
    (arguments
     `(#:configure-flags
       (list (string-append "--with-xkb-config-root="
                            (assoc-ref %build-inputs "xkeyboard-config")
                            "/share/X11/xkb")
             (string-append "--with-x-locale-root="
                            (assoc-ref %build-inputs "libx11")
                            "/share/X11/locale"))))
    (home-page "http://xkbcommon.org/")
    (synopsis "Library to handle keyboard descriptions")
    (description "Xkbcommon is a library to handle keyboard descriptions,
including loading them from disk, parsing them and handling their
state.  It is mainly meant for client toolkits, window systems, and other
system applications; currently that includes Wayland, kmscon, GTK+, Qt,
Clutter, and more.  Despite the name, it is not currently used by anything
X11 (yet).")
    (license (license:x11-style "file://COPYING"
                                "See 'COPYING' in the distribution."))))

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
        (patches (search-patches "xdotool-fix-makefile.patch"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ; Test suite requires a lot of black magic
       #:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys #:rest args)
             (setenv "PREFIX" (assoc-ref outputs "out"))
             (setenv "LDFLAGS"
                     (string-append "-Wl,-rpath="
                                    (assoc-ref %outputs "out") "/lib"))
             (setenv "CC" "gcc"))))))
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
                "13m842m9ffac3m9r0b4lvwjhwzg3w4353djkjpf00s0wnm4v5di1"))
              (patches (search-patches "pixman-CVE-2016-5296.patch"))))
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
    (version "2.4.68")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
               "https://dri.freedesktop.org/libdrm/libdrm-"
               version
               ".tar.bz2"))
        (sha256
         (base32
          "1px91j6imaaq2fy8ksvgldmv0cdz3w379jqiciqvqa99jajxjjsv"))
        (patches (search-patches "libdrm-symbol-check.patch"))))
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
    (version "1.1.5")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
               "http://bitmath.org/code/mtdev/mtdev-"
               version ".tar.bz2"))
        (sha256
         (base32
          "0zxs7shzgbalkvlaiibi25bd902rbmkv9n1lww6q8j3ri9qdaxv6"))))
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
              (patches (search-patches "wmctrl-64-fix.patch"))))
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
              (uri (list (string-append
                           "http://linuxbrit.co.uk/downloads/scrot-"
                           version ".tar.gz")
                         (string-append
                           "https://fossies.org/linux/privat/old/scrot-"
                           version ".tar.gz")))
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
       #:phases
       (modify-phases %standard-phases
         (replace 'install
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (doc (string-append out "/share/doc/scrot")))
               (mkdir-p doc)
               (zero?
                (system* "make" "install"
                         (string-append "docsdir=" doc)))))))))
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

(define-public slop
  (package
    (name "slop")
    (version "4.3.21")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/naelstrof/slop/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0z0p4a3p5mc6fjh5f8js9ppb0maxyvfxpiw2n6nqc5nim1kv6bim"))))
    (build-system cmake-build-system)
    (arguments '(#:tests? #f))  ; no "check" target
    (inputs
     `(("libx11" ,libx11)
       ("libxrandr" ,libxrandr)
       ("libxext" ,libxext)
       ("imlib2" ,imlib2)
       ("glew" ,glew)
       ("mesa" ,mesa)))
    (home-page "https://github.com/naelstrof/slop")
    (synopsis "Select a region and print its bounds to stdout")
    (description
     "slop (Select Operation) is a tool that queries for a selection from a
user and prints the region to stdout.  It grabs the mouse and turns it into a
crosshair, lets the user click and drag to make a selection (or click on a
window) while drawing a pretty box around it, then finally prints the
selection's dimensions to stdout.")
    (license license:gpl3+)))

(define-public maim
  (package
    (name "maim")
    (version "3.4.47")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/naelstrof/maim/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0kfp7k55bxc5h6h0wv8bwmsc5ny66h9ra2z4dzs4yzszq16544pv"))))
    (build-system cmake-build-system)
    (arguments
     '(#:tests? #f              ; no "check" target
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-source
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((slop (string-append (assoc-ref inputs "slop")
                                        "/bin/slop")))
               ;; "slop" command is hardcoded in the source; replace it
               ;; with the full file name.
               (substitute* "src/main.cpp"
                 (("^( +slopcommand.*)\"slop\"" all front)
                  (string-append front "\"" slop "\"")))))))))
    (inputs
     `(("libx11" ,libx11)
       ("libxrandr" ,libxrandr)
       ("libxfixes" ,libxfixes)
       ("imlib2" ,imlib2)
       ("slop" ,slop)))
    (home-page "https://github.com/naelstrof/maim")
    (synopsis "Screenshot utility for X Window System")
    (description
     "maim (Make Image) is a tool that takes screenshots of your desktop and
saves it in any format.  Along with a full screen, it allows you to capture a
predefined region or a particular window.  Also, it makes it possible to
include cursor in the resulting image.")
    (license license:gpl3+)))

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
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'install
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out  (assoc-ref outputs "out"))
                    (bin  (string-append out "/bin"))
                    (man1 (string-append out "/share/man/man1")))
               (mkdir-p bin)
               (mkdir-p man1)
               (zero?
                 (system* "make" "install" "install.man"
                          (string-append "BINDIR=" bin)
                          (string-append "MANDIR=" man1)))))))))
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
    (version "5.47")
    (source (origin
             (method url-fetch)
             (uri (list (string-append
                          "http://www.tux.org/~bagleyd/xlock/xlockmore-"
                          version ".tar.xz")
                        (string-append
                          "http://www.tux.org/~bagleyd/xlock/xlockmore-old"
                          "/xlockmore-" version
                          "/xlockmore-" version ".tar.xz")))
             (sha256
              (base32
               "138d79b8zc2hambbr9fnxp3fhihlcljgqns04zf0kv2f53pavqwl"))))
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
             ))) ; + GPLv2 in modes/glx/biof.c.

(define-public xosd
  (package
    (name "xosd")
    (version "2.2.14")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://sourceforge/libxosd/libxosd/xosd-" version "/"
                    name "-" version ".tar.gz"))
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
    (version "0.5.6")
    (source
     (origin
       (file-name (string-append name "-" version ".tar.gz"))
       (method url-fetch)
       (uri (string-append
             "https://github.com/baskerville/sxhkd/archive/"
             version ".tar.gz"))
       (sha256
        (base32
         "15grmzpxz5fqlbfg2slj7gb7r6nzkvjmflmbkqx7mlby9pm6wdkj"))))
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
    (version "9.22")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://dist.schmorp.de/rxvt-unicode/Attic/"
                                  name "-" version ".tar.bz2"))
              (sha256
               (base32
                "1pddjn5ynblwfrdmskylrsxb9vfnk3w4jdnq2l8xn2pspkljhip9"))))
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
    (version "1.2")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "https://github.com/alols/" name
                            "/archive/v" version ".tar.gz"))
        (file-name (string-append name "-" version ".tar.gz"))
        (sha256
          (base32
            "0898zc3vwxia00h9kfknpf7jygxgwggrx8v5mxc31w4lzn2dhzm2"))))
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
       ("libjpeg" ,libjpeg)
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

(define-public xscreensaver
  (package
    (name "xscreensaver")
    (version "5.35")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "https://www.jwz.org/xscreensaver/xscreensaver-"
                       version ".tar.gz"))
       (sha256
        (base32
         "08kbb0ry7ih436ab4i5g6lnhaaz13zkcdmbdibrn4j5gm5qq8v0y"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f  ; no check target
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'adjust-gtk-resource-paths
           (lambda _
             (substitute* '("driver/Makefile.in" "po/Makefile.in.in")
               (("@GTK_DATADIR@") "@datadir@")
               (("@PO_DATADIR@") "@datadir@")))))
       #:configure-flags '("--with-pam" "--with-proc-interrupts"
                           "--without-readdisplay")
       #:make-flags (list (string-append "AD_DIR="
                                         (assoc-ref %outputs "out")
                                         "/usr/lib/X11/app-defaults"))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("intltool" ,intltool)))
    (inputs
     `(("libx11" ,libx11)
       ("libxext" ,libxext)
       ("libxi" ,libxi)
       ("libxt" ,libxt)
       ("libxft" ,libxft)
       ("libxmu" ,libxmu)
       ("libxpm" ,libxpm)
       ("libglade" ,libglade)
       ("libxml2" ,libxml2)
       ("libsm" ,libsm)
       ("libjpeg" ,libjpeg)
       ("linux-pam" ,linux-pam)
       ("pango" ,pango)
       ("gtk+" ,gtk+)
       ("perl" ,perl)
       ("cairo" ,cairo)
       ("bc" ,bc)
       ("libxrandr" ,libxrandr)
       ("glu" ,glu)
       ("glib" ,glib)))
    (home-page "https://www.jwz.org/xscreensaver/")
    (synopsis "Classic screen saver suite supporting screen locking")
    (description
     "xscreensaver is a popular screen saver collection with many entertaining
demos.  It also acts as a nice screen locker.")
    ;; xscreensaver doesn't have a single copyright file and instead relies on
    ;; source comment headers, though most files have the same lax
    ;; permissions.  To reduce complexity, we're pointing at Debian's
    ;; breakdown of the copyright information.
    (license (license:non-copyleft
              (string-append
               "http://metadata.ftp-master.debian.org/changelogs/"
               "/main/x/xscreensaver/xscreensaver_5.34-2_copyright")))))

(define-public xdpyprobe
  (package
    (name "xdpyprobe")
    (version "0.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/alezost/" name
                                  "/releases/download/v" version
                                  "/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "1h09wd2qcg08rj5hcakvdh9q01hkrj8vxly94ax3ch2x06lm0zq8"))))
    (build-system gnu-build-system)
    (inputs
     `(("libx11" ,libx11)))
    (home-page "https://github.com/alezost/xdpyprobe")
    (synopsis "Probe X server for connectivity")
    (description
     "Xdpyprobe is a tiny C program whose only purpose is to probe a
connectivity of the X server running on a particular @code{DISPLAY}.")
    (license license:gpl3+)))

(define-public rofi
  (package
    (name "rofi")
    (version "1.2.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/DaveDavenport/rofi/"
                                  "releases/download/"
                                  version "/rofi-" version ".tar.xz"))
              (sha256
               (base32
                "0xxx0xpxhrhlhi2axq9867zqrhwqavc1qrr833k1xr0pvm5m0aqc"))))
    (build-system gnu-build-system)
    (inputs
     `(("pango" ,pango)
       ("cairo" ,cairo)
       ("glib" ,glib)
       ("startup-notification" ,startup-notification)
       ("libxkbcommon" ,libxkbcommon)
       ("libxcb" ,libxcb)
       ("xcb-util" ,xcb-util)
       ("xcb-util-xrm" ,xcb-util-xrm)
       ("xcb-util-wm" ,xcb-util-wm)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'configure 'adjust-tests
           (lambda _
             (substitute* '("test/helper-expand.c")
               (("~root") "/root")
               (("~") "")
               (("g_get_home_dir \\(\\)") "\"/\"")))))))
    (home-page "https://davedavenport.github.io/rofi/")
    (synopsis "Application Launcher")
    (description "Rofi is a minimalist Application Launcher.  It memorizes which
applications you regularily use and also allows you to search for an application
by name.")
    (license license:expat)))

(define-public tint2
  (package
    (name "tint2")
    (version "0.12.11")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://gitlab.com/o9000/" name
                                  "/repository/archive.tar.gz?ref=" version))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0dv7zaj2ahnfclnwnwcz9arrvzxn65yy29z7fqdgifdh3jk1kl2h"))))
    (build-system cmake-build-system)
    (arguments
     '(#:tests? #f                      ;no test target
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-installation-prefix
           (lambda _
             (substitute* "CMakeLists.txt"
               (("/etc") "${CMAKE_INSTALL_PREFIX}/etc")))))))
    (inputs
     `(("gtk+" ,gtk+-2)
       ("imlib2" ,imlib2)
       ("librsvg" ,librsvg)
       ("libxcomposite" ,libxcomposite)
       ("libxdamage" ,libxdamage)
       ("libxft" ,libxft)
       ("libxinerama" ,libxinerama)
       ("libxrandr" ,libxrandr)
       ("startup-notification" ,startup-notification)))
    (native-inputs
     `(("gettext" ,gettext-minimal)
       ("pkg-config" ,pkg-config)))
    (home-page "https://gitlab.com/o9000/tint2")
    (synopsis "Lightweight task bar")
    (description
     "Tint2 is a simple task bar made for modern X window managers.  It was
specifically made for Openbox but it should also work with other window
managers (GNOME, KDE, XFCE etc.).

The taskbar includes transparency and color settings for the font, icons,
border, and background.  It also supports multihead setups, customized mouse
actions, a built-in clock, a battery monitor and a system tray.")
    (license license:gpl2)))

(define-public xcb-util-xrm
  (package
    (name "xcb-util-xrm")
    (version "1.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/Airblader/xcb-util-xrm/releases"
                    "/download/v" version "/xcb-util-xrm-" version ".tar.bz2"))
              (sha256
               (base32
                "0vbqhag51i0njc8d5fc8c6aa12496cwrc3s6s7sa5kfc17cwhppp"))
              (modules '((guix build utils)))
              (snippet
               ;; Drop bundled m4.
               '(delete-file-recursively "m4"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("m4" ,m4)
       ("libx11" ,libx11))) ; for tests
    (inputs
     `(("libxcb" ,libxcb)
       ("xcb-util" ,xcb-util)))
    (home-page "https://github.com/Airblader/xcb-util-xrm")
    (synopsis "XCB utility functions for the X resource manager")
    (description
     "The XCB util module provides a number of libraries which sit on
top of libxcb, the core X protocol library, and some of the extension
libraries.  These experimental libraries provide convenience functions
and interfaces which make the raw X protocol more usable.  Some of the
libraries also provide client-side code which is not strictly part of
the X protocol but which has traditionally been provided by Xlib.

XCB util-xrm module provides the following libraries:

- xrm: utility functions for the X resource manager.")
    (license license:x11)))

(define-public xcalib
  (package
    (name "xcalib")
    (version "0.8")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/xcalib/xcalib/" version
                                  "/xcalib-source-" version ".tar.gz"))
              (sha256
               (base32
                "1rh6xb51c5xz926dnn82a2fn643g0sr4a8z66rn6yi7523kjw4ca"))))
    (build-system gnu-build-system)
    (arguments
     '(#:make-flags '("CC=gcc")
       #:tests? #f   ; No test suite
       #:phases (modify-phases %standard-phases
                  (delete 'configure)
                  (replace 'install
                    (lambda* (#:key outputs #:allow-other-keys)
                      (let* ((out (assoc-ref outputs "out"))
                             (bin (string-append out "/bin")))
                        (install-file "xcalib" bin))))
                  (add-after 'install 'install-doc
                    (lambda* (#:key outputs #:allow-other-keys)
                      (let ((doc (string-append(assoc-ref outputs "out")
                                               "/share/doc/xcalib")))
                        (install-file "README" doc)
                        ;; Avoid unspecified return value.
                        #t))))))
    (inputs `(("libx11", libx11)
              ("libxext", libxext)
              ("libxxf86vm", libxxf86vm)))
    (synopsis "Tiny monitor calibration loader for XFree86 (or X.org)")
    (description "xcalib is a tiny tool to load the content of vcgt-Tags in ICC
profiles to the video card's gamma ramp.  It does work with most video card
drivers except the generic VESA driver.  Alter brightness, contrast, RGB, and
invert colors on a specific display/screen.")
    (home-page "http://xcalib.sourceforge.net/")
    (license license:gpl2)))
