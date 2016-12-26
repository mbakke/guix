;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2015, 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Rene Saavedra <rennes@openmailbox.org>
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

(define-module (gnu packages nano)
  #:use-module (guix licenses)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages ncurses)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu))

(define-public nano
  (package
    (name "nano")
    (version "2.7.2")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/nano/nano-"
                          version ".tar.gz"))
      (sha256
       (base32
        "0g1mf28gjfjqqca5plgfcrnwywlrd91v7q8ld8kvfvqccgflbk49"))))
    (build-system gnu-build-system)
    (inputs
     `(("gettext" ,gettext-minimal)
       ("ncurses" ,ncurses)))
    (home-page "https://www.nano-editor.org/")
    (synopsis "Small, user-friendly console text editor")
    (description
     "GNU Nano is a small and simple text editor.  In addition to basic
editing, it supports interactive search and replace, go to line and column
number, auto-indentation and more.")
    (license gpl3+))) ; some files are under GPLv2+
