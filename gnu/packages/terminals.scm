;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015, 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Mckinley Olsen <mck.olsen@gmail.com>
;;; Copyright © 2016 Alex Griffin <a@ajgrf.com>
;;; Copyright © 2016 David Craven <david@craven.ch>
;;; Copyright © 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu packages terminals)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix build utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system python)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages freedesktop)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages wm)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages docbook)
  #:use-module (srfi srfi-26))

(define-public tilda
  (package
    (name "tilda")
    (version "1.3.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/lanoxx/tilda/archive/"
                                  "tilda-" version ".tar.gz"))
              (sha256
               (base32
                "1cc4qbg1m3i04lj5p6i6xbd0zvy1320pxdgmjhz5p3j95ibsbfki"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                 (add-before 'patch-source-shebangs 'autogen
                  (lambda _       ; Avoid running ./configure.
                   (substitute* "autogen.sh"
                                (("^.*\\$srcdir/configure.*") ""))
                   (zero? (system* "sh" "autogen.sh")))))))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("gettext" ,gnu-gettext)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("glib" ,glib "bin")
       ("gtk+" ,gtk+)
       ("libconfuse" ,libconfuse)
       ("vte" ,vte)))
    (synopsis "GTK+-based drop-down terminal")
    (description "Tilda is a terminal emulator similar to normal terminals like
gnome-terminal (GNOME) or Konsole (KDE), with the difference that it drops down
from the edge of a screen when a certain configurable hotkey is pressed.  This
is similar to the built-in consoles in some applications.  Tilda is highly
configureable through a graphical wizard.")
    (home-page "https://github.com/lanoxx/tilda")
    (license license:gpl2+)))

(define-public termite
  (package
    (name "termite")
    (version "12")
    (source
      (origin
        (method git-fetch)
        (uri (git-reference
              (url (string-append "https://github.com/thestinger/"
                                  name ".git"))
              (commit (string-append "v" version))
              (recursive? #t)))
        (file-name (string-append name "-" version "-checkout"))
        (sha256
         (base32
          "0s6dyg3vcqk5qcx90bs24wdnd3p56rdjdcanx4pcxvp6ksjl61jz"))))
    (build-system gnu-build-system)
    (arguments
      `(#:phases
        (modify-phases %standard-phases
          (delete 'configure))
        #:tests? #f
        ;; This sets the destination when installing the necessary terminal
        ;; capability data, which are not provided by 'ncurses'.  See
        ;; <https://lists.gnu.org/archive/html/bug-ncurses/2009-10/msg00031.html>.
        #:make-flags (list "PREFIX="
                           (string-append "VERSION=v" (version))
                           (string-append "DESTDIR="
                                          (assoc-ref %outputs "out")))))
    (inputs
     `(("vte", vte-ng)
       ("gtk+", gtk+)
       ("ncurses", ncurses)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))

    ;; FIXME: This should only be located in 'ncurses'.  Nonetheless it is
    ;; provided for usability reasons.  See <https://bugs.gnu.org/22138>.
    (native-search-paths
      (list (search-path-specification
              (variable "TERMINFO_DIRS")
              (files '("share/terminfo")))))
    (home-page "https://github.com/thestinger/termite/")
    (synopsis "Keyboard-centric, VTE-based terminal")
    (description "Termite is a minimal terminal emulator designed for use with
tiling window managers.  It is a modal application, similar to Vim, with an
insert mode and command mode where keybindings have different functions.")

    ;; Files under util/ are under the Expat license; the rest is LGPLv2+.
    (license license:lgpl2.0+)))

(define-public asciinema
  (package
    (name "asciinema")
    (version "1.3.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/06/96/93947d9be78aebb7985014fdf"
             "4d84896dd0f62514d922ee03f5bb55a21fb/asciinema-" version
             ".tar.gz"))
       (sha256
        (base32
         "1crdm9zfdbjflvz1gsqvy5zsbgwdfkj34z69kg6h5by70rrs1hdc"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'build 'patch-exec-paths
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((ncurses (assoc-ref inputs "ncurses")))
               (substitute* "asciinema/recorder.py"
                 (("'tput'")
                  (string-append "'" ncurses "/bin/tput'"))))
             #t)))))
    (inputs `(("ncurses" ,ncurses)))
    (home-page "https://asciinema.org")
    (synopsis "Terminal session recorder")
    (description
     "Use asciinema to record and share your terminal sessions, the right way.
Forget screen recording apps and blurry video.  Enjoy a lightweight, purely
text-based approach to terminal recording.")
    (license license:gpl3)))

(define-public libtsm
  (package
    (name "libtsm")
    (version "3")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://freedesktop.org/software/kmscon/releases/"
                    "libtsm-" version ".tar.xz"))
              (sha256
               (base32
                "01ygwrsxfii0pngfikgqsb4fxp8n1bbs47l7hck81h9b9bc1ah8i"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("libxkbcommon" ,libxkbcommon)))
    (synopsis "Xterm state machine library")
    (description "TSM is a state machine for DEC VT100-VT520 compatible
terminal emulators.  It tries to support all common standards while keeping
compatibility to existing emulators like xterm, gnome-terminal, konsole, etc.")
    (home-page "https://www.freedesktop.org/wiki/Software/libtsm")
    ;; Hash table implementation is lgpl2.1+ licensed.
    ;; The wcwidth implementation in external/wcwidth.{h,c} uses a license
    ;; derived from ISC.
    ;; UCS-4 to UTF-8 encoding is copied from "terminology" which is released
    ;; under the bsd 2 license.
    (license (list license:expat license:lgpl2.1+ license:isc license:bsd-2))))

(define-public kmscon
  (package
    (name "kmscon")
    (version "8")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://freedesktop.org/software/kmscon/releases/"
                    "kmscon-" version ".tar.xz"))
              (sha256
               (base32
                "0axfwrp3c8f4gb67ap2sqnkn75idpiw09s35wwn6kgagvhf1rc0a"))
              (modules '((guix build utils)))
              (snippet
               ;; Use elogind instead of systemd.
               '(begin
                  (substitute* "configure"
                    (("libsystemd-daemon libsystemd-login")
                     "libelogind"))
                  (substitute* "src/uterm_systemd.c"
                    (("#include <systemd/sd-login.h>")
                     "#include <elogind/sd-login.h>")
                    ;; We don't have this header.
                    (("#include <systemd/sd-daemon\\.h>")
                     "")
                    ;; Replace the call to 'sd_booted' by the truth value.
                    (("sd_booted\\(\\)")
                     "1"))))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("libxslt" ,libxslt)                       ;to build the man page
       ("libxml2" ,libxml2)                       ;for XML_CATALOG_FILES
       ("docbook-xsl" ,docbook-xsl)))
    (inputs
     `(("libdrm" ,libdrm)
       ("libtsm" ,libtsm)
       ("libxkbcommon" ,libxkbcommon)
       ("logind" ,elogind)
       ("mesa" ,mesa)
       ("pango" ,pango)
       ("udev" ,eudev)))
    (synopsis "Linux KMS-based terminal emulator")
    (description "Kmscon is a terminal emulator based on Linux's @dfn{kernel
mode setting} (KMS).  It can replace the in-kernel virtual terminal (VT)
implementation with a user-space console.  Compared to the Linux console,
kmscon provides enhanced features including XKB-compatible internationalized
keyboard support, UTF-8 input/font support, hardware-accelerated rendering,
multi-seat support, a replacement for @command{mingetty}, and more.")
    (home-page "https://www.freedesktop.org/wiki/Software/kmscon")
    ;; Hash table implementation is lgpl2.1+ licensed.
    ;; The wcwidth implementation in external/wcwidth.{h,c} uses a license
    ;; derived from ISC.
    ;; UCS-4 to UTF-8 encoding is copied from "terminology" which is released
    ;; under the bsd 2 license.
    ;; Unifont-Font is from http://unifoundry.com/unifont.html and licensed
    ;; under the terms of the GNU GPL.
    (license (list license:expat license:lgpl2.1+ license:bsd-2
                   license:gpl2+))
    (supported-systems (filter (cut string-suffix? "-linux" <>)
                               %supported-systems))))

(define-public picocom
  (package
    (name "picocom")
    (version "2.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/npat-efault/picocom"
                    "/archive/" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1knl6dglnrynx1fhy21nylw56i1q3dkizkgxzkq42mb7ilah8f9y"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags '("CC=gcc")
       #:tests? #f ; No tests
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin"))
                    (man (string-append out "/share/man/man1")))
               (install-file "picocom" bin)
               (install-file "picocom.1" man)))))))
    (home-page "https://github.com/npat-efault/picocom")
    (synopsis "Minimal dumb-terminal emulation program")
    (description "It was designed to serve as a simple, manual, modem
configuration, testing, and debugging tool.  It has also serves well
as a low-tech serial communications program to allow access to all
types of devices that provide serial consoles.")
    (license license:gpl2+)))
