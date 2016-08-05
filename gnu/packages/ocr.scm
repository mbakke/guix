;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu packages ocr)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages image))

(define-public ocrad
  (package
    (name "ocrad")
    (version "0.25")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/ocrad/ocrad-"
                                 version ".tar.lz"))
             (sha256
              (base32
               "1m2dblgvvjs48rsglfdwq0ib9zk8h9n34xsh67ibrg0g0ffbw477"))))
    (build-system gnu-build-system)
    (native-inputs `(("lzip" ,lzip)))
    (home-page "http://www.gnu.org/software/ocrad/")
    (synopsis "Optical character recognition based on feature extraction")
    (description
     "GNU Ocrad is an optical character recognition program based on a
feature extraction method.  It can read images in PBM, PGM or PPM formats and
it produces text in 8-bit or UTF-8 formats.")
    (license license:gpl3+)))

(define-public tesseract-ocr
  (package
    (name "tesseract-ocr")
    (version "3.04.01")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/tesseract-ocr/tesseract/archive/"
             version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32 "0snwd8as5i8vx7zkimpd2yg898jl96zf90r65a9w615f2hdkxxjp"))))
    (build-system gnu-build-system)
    (inputs
     `(("leptonica" ,leptonica)))
    (arguments
     '(#:configure-flags
       (let ((leptonica (assoc-ref %build-inputs "leptonica")))
         (list (string-append "LIBLEPT_HEADERSDIR=" leptonica "/include")))))
    (home-page "https://github.com/tesseract-ocr")
    (synopsis "Optical character recognition engine")
    (description
     "Tesseract is an optical character recognition (OCR) engine with very
high accuracy.  It supports many languages, output text formatting, hOCR
positional information and page layout analysis.  Several image formats are
supported through the Leptonica library.  It can also detect whether text is
monospaced or proportional.")
    (license license:asl2.0)))
