;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015, 2016 Alex Kost <alezost@gmail.com>
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

(define-module (gnu packages lirc)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages libusb)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages python))

(define-public lirc
  (package
    (name "lirc")
    (version "0.9.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/lirc/LIRC/" version
                                  "/lirc-" version ".tar.bz2"))
              (sha256
               (base32
                "1l2xzhnm4hrla51ik09hcafki0y8wnww7svfm7j63zbl2rssc66x"))
              (patches (search-patches "lirc-localstatedir.patch"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags '("--localstatedir=/var")
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-lirc-make-devinput
           (lambda* (#:key inputs #:allow-other-keys)
             ;; 'lirc-make-devinput' script assumes that linux headers
             ;; are placed in "/usr/...".
             (let ((headers (assoc-ref inputs "linux-headers")))
               (substitute* "tools/lirc-make-devinput"
                 (("/usr/include") (string-append headers "/include"))))
             #t))
         (add-after 'unpack 'patch-doc/Makefile.in
           (lambda _
             ;; Lirc wants to install several images and a useless html page
             ;; to "$(localstatedir)/lib/lirc/".  This makes 'install' phase
             ;; fail as localstatedir is "/var", so do not install these
             ;; files there (the same images are installed in
             ;; "share/doc/lirc/images/" anyway).
             (substitute* "doc/Makefile.in"
               (("^vardocs_DATA =.*") "vardocs_DATA =\n")
               (("^varimage_DATA =.*") "varimage_DATA =\n"))
             #t)))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("libxslt" ,libxslt)))
    (inputs
     `(("libx11" ,libx11)
       ("libusb-compat" ,libusb-compat)
       ("linux-headers" ,linux-libre-headers)
       ("alsa-lib" ,alsa-lib)
       ("python" ,python)))
    (home-page "http://www.lirc.org/")
    (synopsis "Linux Infrared Remote Control")
    (description
     "LIRC allows computers to send and receive IR signals of many commonly
used remote controls.  The most important part of LIRC is the 'lircd' daemon
that decodes IR signals received by the device drivers.  The second daemon
program 'lircmd' allows to translate IR signals to mouse movements.  The
user space applications allow you to control your computer with a remote
control: you can send X events to applications, start programs and much more
on just one button press.")
    (license license:gpl2+)))
