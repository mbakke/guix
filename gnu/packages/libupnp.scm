;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Federico Beffa <beffa@fbengineering.ch>
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

(define-module (gnu packages libupnp)
  #:use-module (gnu packages)
  #:use-module (guix licenses)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu))

(define-public libupnp
  (package
    (name "libupnp")
    (version "1.6.20")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://sourceforge/pupnp/pupnp/libUPnP%20"
                          version "/" name "-" version ".tar.bz2"))
      (patches (search-patches "libupnp-CVE-2016-6255.patch"
                               "libupnp-CVE-2016-8863.patch"))
      (sha256
       (base32
        "0qrsdsb1qm85hc4jy04qph895613d148f0x1mmk6z99y3q43fdgf"))))
    (build-system gnu-build-system)
    (arguments
     ;; The tests require a network device capable of multicasting which is
     ;; not available in the build environment. See
     ;; https://lists.gnu.org/archive/html/guix-devel/2015-01/msg00312.html.
     `(#:tests? #f
       #:configure-flags '("--enable-ipv6")))
    (home-page "http://pupnp.sourceforge.net")
    (synopsis "Portable SDK for UPnP Devices")
    (description
     "The portable SDK for UPnP Devices (libupnp) provides developers with an
API and open source code for building control points, devices, and bridges
that are compliant with Version 1.0 of the Universal Plug and Play Device
Architecture Specification and support several operating systems like Linux,
*BSD, Solaris and others.")
    (license bsd-3)))
