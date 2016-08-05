;;; GNU Guix --- Functional package management for GNU
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

(define-module (gnu packages hexedit)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (gnu packages)
  #:use-module (gnu packages ncurses)
  #:use-module (guix download)
  #:use-module (guix build-system gnu))

(define-public hexedit
  (package
    (name "hexedit")
    (version "1.2.13")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://rigaux.org/"
                                  name "-" version ".src.tgz"))
              (sha256
               (base32
                "1mwdp1ikk64cqmagnrrps5jkn3li3n47maiqh2qc1xbp1ains4ka"))))
    (build-system gnu-build-system)
    (arguments '(#:tests? #f)) ; no check target
    (inputs `(("ncurses" ,ncurses)))
    (synopsis "View and edit files or devices in hexadecimal or ASCII")
    (description "hexedit shows a file both in ASCII and in hexadecimal.  The
file can be a device as the file is read a piece at a time.  You can modify
the file and search through it.")
    (home-page "http://rigaux.org/hexedit.html")
    (license license:gpl2+)))
