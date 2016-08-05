;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Raimon Grau <raimonster@gmail.com>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
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

(define-module (gnu packages stalonetray)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module ((guix licenses) #:select (gpl2+))
  #:use-module (gnu packages xorg))

(define-public stalonetray
  (package
    (name "stalonetray")
    (version "0.8.3")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "mirror://sourceforge/stalonetray/stalonetray/stalonetray-"
                       version "/stalonetray-" version ".tar.bz2"))
       (sha256
        (base32
         "0k7xnpdb6dvx25d67v0crlr32cdnzykdsi9j889njiididc8lm1n"))))
    (inputs `(("libx11" ,libx11)))
    (build-system gnu-build-system)
    (home-page "http://stalonetray.sourceforge.net")
    (synopsis "Standalone freedesktop.org and KDE systray implementation")
    (description
     "Stalonetray is a stand-alone freedesktop.org and KDE system
tray (notification area) for X Window System/X11 (e.g. X.Org or XFree86).  It
has full XEMBED support and minimal dependencies: an X11 lib only.  Stalonetray
works with virtually any EWMH-compliant window manager.")
    (license gpl2+)))
