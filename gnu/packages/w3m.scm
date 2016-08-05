;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
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

(define-module (gnu packages w3m)
  #:use-module ((guix licenses) #:select (x11-style))
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages bdw-gc)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu))

(define-public w3m
  (package
    (name "w3m")
    (version "0.5.3")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://sourceforge/" name "/" name "/"
                                 name "-" version "/"
                                 name "-" version ".tar.gz"))
             (sha256
              (base32
               "1qx9f0kprf92r1wxl3sacykla0g04qsi0idypzz24b7xy9ix5579"))

             ;; cf. https://bugs.archlinux.org/task/33397
             (patches (search-patches "w3m-libgc.patch"
                                      "w3m-force-ssl_verify_server-on.patch"
                                      "w3m-disable-sslv2-and-sslv3.patch"
                                      "w3m-disable-weak-ciphers.patch"))))
    (build-system gnu-build-system)
    (arguments `(#:tests? #f  ; no check target
                 #:phases (alist-cons-before
                           'configure 'fix-perl
                           (lambda _
                             ;; https://launchpad.net/bugs/935540
                             ;; 'struct file_handle' is used by 'glibc'
                             (substitute* '("istream.c" "istream.h")
                              (("struct[[:blank:]]+file_handle")
                               "struct w3m_file_handle"))
                             (substitute* '("scripts/w3mmail.cgi.in"
                                            "scripts/dirlist.cgi.in")
                               (("@PERL@") (which "perl"))))
                           %standard-phases)))
    (inputs
     `(("libgc" ,libgc)
       ("ncurses" ,ncurses)
       ("openssl" ,openssl)
       ("zlib" ,zlib)))
    (native-inputs
     `(("gettext" ,gnu-gettext)
       ("perl" ,perl)
       ("pkg-config" ,pkg-config)))
    (home-page "http://w3m.sourceforge.net/")
    (synopsis "Text-mode web browser")
    (description
     "w3m is a text-based web browser as well as a pager like 'more' or
'less'.  With w3m you can browse web pages through a terminal emulator
window.  Moreover, w3m can be used as a text formatting tool which
typesets HTML into plain text.")
    (license (x11-style "file://doc/README"
                        "See 'doc/README' in the distribution."))))
