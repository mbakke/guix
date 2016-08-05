;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Siniša Biđin <sinisa@bidin.eu>
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

(define-module (gnu packages conky)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system cmake)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages lua)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages xorg))

(define-public conky
  (package
    (name "conky")
    (version "1.10.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/brndnmtthws/conky/archive/v"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32 "1m9byrmpc2sprzk44v447yaqjzsvw230a0mlw7y1ngz3m3y44qs5"))))
    (build-system cmake-build-system)
    (arguments
     `(#:tests? #f ; there are no tests
       #:configure-flags
       '("-DRELEASE=true"
         ;; XXX: it checks ncurses with pkg-config.
         ;; TODO: add 'ncurses.pc' to the ncurses package.
         "-DBUILD_NCURSES=false")
       #:phases
       (alist-cons-after
        'unpack 'add-freetype-to-search-path
        (lambda* (#:key inputs #:allow-other-keys)
          (substitute* "cmake/ConkyPlatformChecks.cmake"
            (("set\\(INCLUDE_SEARCH_PATH")
             (string-append
              "set(INCLUDE_SEARCH_PATH "
              (assoc-ref inputs "freetype") "/include/freetype2 ")))
          #t)
        (alist-replace
         'install
         (lambda* (#:key outputs #:allow-other-keys)
           (let ((bin (string-append (assoc-ref outputs "out") "/bin")))
             (mkdir-p bin)
             (copy-file "src/conky" (string-append bin "/conky"))))
         %standard-phases))))
    (inputs
     `(("freetype" ,freetype)
       ("ncurses" ,ncurses)
       ("libx11" ,libx11)
       ("libxdamage" ,libxdamage)
       ("libxft" ,libxft)
       ("libxinerama" ,libxinerama)
       ("lua" ,lua)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "https://github.com/brndnmtthws/conky")
    (synopsis "Lightweight system monitor for X")
    (description
     "Conky is a lightweight system monitor for X that displays operating
system statistics (CPU, disk, and memory usage, etc.) and more on the
desktop.")
    (license license:gpl3+)))
