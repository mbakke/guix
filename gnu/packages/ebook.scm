;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015, 2016 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Alex Griffin <a@ajgrf.com>
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

(define-module (gnu packages ebook)
  #:use-module ((guix licenses) #:select (gpl3 lgpl2.1+))
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (guix build-system python)
  #:use-module (gnu packages)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages freedesktop)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages image)
  #:use-module (gnu packages libusb)
  #:use-module (gnu packages pdf)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages qt)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages xorg))

(define-public chmlib
  (package
    (name "chmlib")
    (version "0.40")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://www.jedrea.com/chmlib/chmlib-"
                                 version ".tar.bz2"))
             (sha256
               (base32
                "18zzb4x3z0d7fjh1x5439bs62dmgsi4c1pg3qyr7h5gp1i5xcj9l"))
             (patches (search-patches "chmlib-inttypes.patch"))))
    (build-system gnu-build-system)
    (home-page "http://www.jedrea.com/chmlib/")
    (synopsis "Library for CHM files")
    (description "CHMLIB is a library for dealing with ITSS/CHM format files.")
    (license lgpl2.1+)))

(define-public calibre
  (package
    (name "calibre")
    (version "2.63.0")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "http://download.calibre-ebook.com/"
                            version "/calibre-"
                            version ".tar.xz"))
        (sha256
         (base32
          "1rwgv6rsmy3ljfwcpv42w203ghngw86s5kzb0yjm1zgsxmas2wh6"))
        ;; Remove non-free or doubtful code, see
        ;; https://lists.gnu.org/archive/html/guix-devel/2015-02/msg00478.html
        (modules '((guix build utils)))
        (snippet
          '(begin
            (delete-file-recursively "src/unrar")
            (delete-file "src/odf/thumbnail.py")))
        (patches (search-patches "calibre-drop-unrar.patch"
                                 "calibre-no-updates-dialog.patch"))))
    (build-system python-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("qt" ,qt) ; for qmake
       ;; xdg-utils is supposed to be used for desktop integration, but it
       ;; also creates lots of messages
       ;; mkdir: cannot create directory '/homeless-shelter': Permission denied
       ("xdg-utils" ,xdg-utils)))
    ;; FIXME: The following are missing inputs according to the documentation,
    ;; but the package can apparently be used without them,
    ;; They may need to be added if a deficiency is detected.
    ;; BeautifulSoup >= 3.0.5
    ;; dnspython >= 1.6.0
    ;; poppler >= 0.20.2
    ;; libwmf >= 0.2.8
    ;; psutil >= 0.6.1
    ;; python-pygments >= 2.0.1 ; used for ebook editing
    (inputs
     `(("chmlib" ,chmlib)
       ("fontconfig" ,fontconfig)
       ("glib" ,glib)
       ("icu4c" ,icu4c)
       ("libmtp" ,libmtp)
       ("libpng" ,libpng)
       ("libusb" ,libusb)
       ("libxrender" ,libxrender)
       ("openssl" ,openssl)
       ("podofo" ,podofo)
       ("python" ,python-2)
       ("python2-apsw" ,python2-apsw)
       ("python2-cssselect" ,python2-cssselect)
       ("python2-cssutils" ,python2-cssutils)
       ("python2-dateutil" ,python2-dateutil)
       ("python2-dbus" ,python2-dbus)
       ("python2-lxml" ,python2-lxml)
       ("python2-mechanize" ,python2-mechanize)
       ("python2-netifaces" ,python2-netifaces)
       ("python2-pillow" ,python2-pillow)
       ("python2-pyqt" ,python2-pyqt-5.5)
       ("python2-sip" ,python2-sip)
       ("qt" ,qt)
       ("sqlite" ,sqlite)))
    (arguments
     `(#:python ,python-2
       #:test-target "check"
       #:tests? #f ; FIXME: enable once flake8 is packaged
       #:phases
       (modify-phases %standard-phases
         (add-before 'build 'configure
          (lambda* (#:key inputs #:allow-other-keys)
            (let ((podofo (assoc-ref inputs "podofo"))
                  (pyqt (assoc-ref inputs "python2-pyqt")))
              (substitute* "setup/build_environment.py"
                (("sys.prefix") (string-append "'" pyqt "'")))
              (setenv "PODOFO_INC_DIR" (string-append podofo "/include/podofo"))
              (setenv "PODOFO_LIB_DIR" (string-append podofo "/lib"))))))))
    (home-page "http://calibre-ebook.com/")
    (synopsis "E-book library management software")
    (description "Calibre is an ebook library manager.  It can view, convert
and catalog ebooks in most of the major ebook formats.  It can also talk
to many ebook reader devices.  It can go out to the Internet and fetch
metadata for books.  It can download newspapers and convert them into
ebooks for convenient reading.")
    (license gpl3))) ; some files are under various other licenses, see COPYRIGHT
