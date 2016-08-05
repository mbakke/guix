;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2013, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu packages gv)
  #:use-module (gnu packages)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages xorg)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu))

(define-public gv
  (package
   (name "gv")
   (version "3.7.4")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/gv/gv-"
                                version ".tar.gz"))
            (sha256 (base32
                     "0q8s43z14vxm41pfa8s5h9kyyzk1fkwjhkiwbf2x70alm6rv6qi1"))))
   (build-system gnu-build-system)
   (propagated-inputs `(("ghostscript" ,ghostscript-gs/x)))
   (inputs `(("libx11" ,libx11)
             ("libxaw3d" ,libxaw3d)
             ("libxinerama" ,libxinerama)
             ("libxpm" ,libxpm)
             ("zlib" ,zlib)))
   (native-inputs
     `(("pkg-config" ,pkg-config)))
   (synopsis "PostScript and PDF viewer using Ghostscript as a back-end")
   (description
    "GNU GV is a graphical user interface to the Ghostscript interpreter.
With it, one can view and navigate through PostScript and PDF documents in X
Windows.")
   (license license:gpl3+)
   (home-page "http://www.gnu.org/software/gv/")))
