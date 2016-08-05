;;; GNU Guix --- Functional package management for GNU
;;; Copyright 2016 John Darrington <jmd@gnu.org>
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

(define-module (gnu packages marst)
  #:use-module (guix packages)
  #:use-module (guix licenses)
  #:use-module (guix download)
  #:use-module (gnu packages compression)
  #:use-module (guix build-system gnu))

(define-public marst
  (package
    (name "marst")
    (version "2.7")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "mirror://gnu/" name "/" name "-" version
             ".tar.gz"))
       (sha256
        (base32 "0l6swjy8fjrqw89ghc1vvakg21jmpfkpsw92yssrzkg3rg8vkrry"))))
    (build-system gnu-build-system)
    (home-page "http://www.gnu.org/software/marst")
    (synopsis "Algol-to-C translator")
    (description
     "GNU MARST is an Algol-to-C translator.  The package consists of the
translator itself, a library that contains the necessary Algol 60 procedures,
and a converter that converts existing Algol 60 programs from other
representations to the MARST representation.")
    (license gpl3+)))
