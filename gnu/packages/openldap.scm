;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013 Andreas Enge <andreas@enge.fr>
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

(define-module (gnu packages openldap)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages cyrus-sasl)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages groff)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages tls)
  #:use-module ((guix licenses) #:select (openldap2.8))
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu))

(define-public openldap
  (package
   (name "openldap")
   (version "2.4.44")
   (source (origin
            (method url-fetch)

            ;; See <http://www.openldap.org/software/download/> for a list of
            ;; mirrors.
            (uri (list (string-append
                        "ftp://mirror.switch.ch/mirror/OpenLDAP/"
                        "openldap-release/openldap-" version ".tgz")
                       (string-append
                        "ftp://ftp.OpenLDAP.org/pub/OpenLDAP/"
                        "openldap-release/openldap-" version ".tgz")
                       (string-append
                        "ftp://ftp.dti.ad.jp/pub/net/OpenLDAP/"
                        "openldap-release/openldap-" version ".tgz")))
            (sha256
             (base32
              "0044p20hx07fwgw2mbwj1fkx04615hhs1qyx4mawj2bhqvrnppnp"))))
   (build-system gnu-build-system)
   (inputs `(("bdb" ,bdb-5.3)
             ("openssl" ,openssl)
             ("cyrus-sasl" ,cyrus-sasl)
             ("groff" ,groff)
             ("icu4c" ,icu4c)
             ("libgcrypt" ,libgcrypt)
             ;; FIXME: currently, openldap requires openssl or gnutls<3, see
             ;; http://www.openldap.org/its/index.cgi/Incoming?id=7430;page=17
             ;; Once this is fixed, switch to gnutls.
             ("zlib" ,zlib)))
   (native-inputs `(("libtool" ,libtool)))
   (arguments
    `(#:tests? #f
      #:phases
       (alist-cons-after
        'configure 'provide-libtool
        (lambda _ (copy-file (which "libtool") "libtool"))
       %standard-phases)))
   (synopsis "Implementation of the Lightweight Directory Access Protocol")
   (description
    "OpenLDAP is a free implementation of the Lightweight Directory Access Protocol.")
   (license openldap2.8)
   (home-page "http://www.openldap.org/")))
