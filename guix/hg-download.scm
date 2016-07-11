;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
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

(define-module (guix hg-download)
  #:use-module (guix gexp)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix records)
  #:use-module (guix packages)
  #:autoload   (guix build-system gnu) (standard-packages)
  #:use-module (ice-9 match)
  #:export (hg-reference
            hg-reference?
            hg-reference-url
            hg-reference-changeset
            hg-reference-recursive?

            hg-fetch))

;;; Commentary:
;;;
;;; An <origin> method that fetches a specific changeset from a Mercurial
;;; repository.  The repository URL and changeset ID are specified with a
;;; <hg-reference> object.
;;;
;;; Code:

(define-record-type* <hg-reference>
  hg-reference make-hg-reference
  hg-reference?
  (url        hg-reference-url)
  (changeset  hg-reference-changeset))

(define (hg-package)
  "Return the default Mercurial package."
  (let ((distro (resolve-interface '(gnu packages version-control))))
    (module-ref distro 'mercurial)))

(define* (hg-fetch ref hash-algo hash
                   #:optional name
                   #:key (system (%current-system)) (guile (default-guile))
                   (hg (hg-package)))
  "Return a fixed-output derivation that fetches REF, a <hg-reference>
object.  The output is expected to have recursive hash HASH of type
HASH-ALGO (a symbol).  Use NAME as the file name, or a generic name if #f."
  (define build
    (with-imported-modules '((guix build hg)
                             (guix build utils))
      #~(begin
          (use-modules (guix build hg)
                       (guix build utils)
                       (ice-9 match))

          (hg-fetch '#$(hg-reference-url ref)
                    '#$(hg-reference-changeset ref)
                    #$output
                    #:hg-command (string-append #+hg "/bin/hg")))))

  (mlet %store-monad ((guile (package->derivation guile system)))
    (gexp->derivation (or name "hg-checkout") build
                      #:system system
                      #:local-build? #t           ;don't offload repo cloning
                      #:hash-algo hash-algo
                      #:hash hash
                      #:recursive? #t
                      #:guile-for-build guile)))

;;; hg-download.scm ends here
