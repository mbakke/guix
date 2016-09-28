;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu packages key-mon)
  #:use-module (guix licenses)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (gnu packages)
  #:use-module (gnu packages python)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages gnome)
  #:use-module (guix build-system python))

(define-public key-mon
  (package
    (name "key-mon")
    (version "1.17")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://key-mon.googlecode.com/files/key-mon-"
                    version ".tar.gz"))
              (sha256
               (base32
                "1liz0dxcqmchbnl1xhlxkqm3gh76wz9jxdxn9pa7dy77fnrjkl5q"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2                    ;uses the Python 2 'print' syntax
       #:tests? #f))                         ;no tests
    (inputs
     `(("python2-xlib" ,python2-xlib)
       ("python2-pygtk" ,python2-pygtk)
       ("python2-rsvg" ,python2-rsvg)))
    (home-page "http://code.google.com/p/key-mon")
    (synopsis "Show keyboard and mouse status")
    (description
     "The key-mon utility displays the current keyboard and mouse status.
This is useful for teaching and screencasts.")
    (license asl2.0)))
