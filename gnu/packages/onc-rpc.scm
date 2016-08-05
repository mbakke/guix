;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu packages onc-rpc)
  #:use-module (guix licenses)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu))

(define-public libtirpc
  (package
    (name "libtirpc")
    (version "0.2.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/libtirpc/libtirpc/"
                                  version "/libtirpc-"
                                  version ".tar.bz2"))
              (sha256
               (base32
                "18a337wa4amf0k21wnimp3yzs5l3cxqndz4x3x8bm993zhfy5hs5"))))
    (build-system gnu-build-system)
    (arguments
     '(;; Doesn't work with GNU GSS.
       #:configure-flags '("--disable-gssapi")

       #:phases (alist-cons-after
                 'unpack 'remote-dangling-symlink
                 (lambda _
                   ;; Remote the dangling symlinks since it breaks the
                   ;; 'patch-source-shebangs' file tree traversal.
                   (delete-file "INSTALL"))
                 %standard-phases)))
    (home-page "http://sourceforge.net/projects/libtirpc/")
    (synopsis "Transport-independent Sun/ONC RPC implementation")
    (description
     "This package provides a library that implements the Sun/ONC RPC (remote
procedure calls) protocol in a transport-independent manner.  It supports both
IPv4 and IPv6.  ONC RPC is notably used by the network file system (NFS).")
    (license bsd-3)))
