;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Paul van der Walt <paul@denknerd.org>
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

(define-module (gnu packages djvu)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu))

(define-public djvulibre
  (package
    (name "djvulibre")
    (version "3.5.27")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/djvu/DjVuLibre/"
                                  version "/djvulibre-" version ".tar.gz"))
              (sha256
               (base32
                "0psh3zl9dj4n4r3lx25390nx34xz0bg0ql48zdskhq354ljni5p6"))))
    (build-system gnu-build-system)
    (home-page "http://djvu.sourceforge.net/")
    (synopsis "Implementation of DjVu, the document format")
    (description "DjVuLibre is an implementation of DjVu,
including viewers, browser plugins, decoders, simple encoders, and
utilities.")
    (license license:gpl2+)))
