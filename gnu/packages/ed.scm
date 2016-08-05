;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2013, 2014 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu packages ed)
  #:use-module (guix licenses)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages compression))

(define-public ed
  (package
    (name "ed")
    (version "1.13")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/ed/ed-"
                                 version ".tar.lz"))
             (sha256
              (base32
               "1ly7i1iw02vbcd0zrx084z577ngxnarffmkm45dg6vndad5carnd"))))
    (build-system gnu-build-system)
    (native-inputs `(("lzip" ,lzip)))
    (arguments
     '(#:configure-flags '("CC=gcc")
       #:phases
       (modify-phases %standard-phases
         (add-before 'patch-source-shebangs 'patch-test-suite
                     (lambda _
                       (substitute* "testsuite/check.sh"
                         (("/bin/sh") (which "sh"))))))))
    (home-page "http://www.gnu.org/software/ed/")
    (synopsis "Line-oriented text editor")
    (description
     "Ed is a line-oriented text editor: rather than offering an overview of
a document, ed performs editing one line at a time.  It can be executed both
interactively and via shell scripts.  Its method of command input allows
complex tasks to be performed in an automated way.  GNU ed offers several
extensions over the standard utility.")
    (license gpl3+)))
