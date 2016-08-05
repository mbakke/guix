;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014 Sree Harsha Totakura <sreeharsha@totakura.in>
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

(define-module (guix svn-download)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix packages)
  #:use-module (ice-9 match)
  #:export (svn-reference
            svn-reference?
            svn-reference-url
            svn-reference-revision
            svn-fetch))

;;; Commentary:
;;;
;;; An <origin> method that fetches a specific revision from a Subversion
;;; repository.  The repository URL and REVISION are specified with a
;;; <svn-reference> object.  REVISION should be specified as a number.
;;;
;;; Code:

(define-record-type* <svn-reference>
  svn-reference make-svn-reference
  svn-reference?
  (url       svn-reference-url)                    ; string
  (revision  svn-reference-revision)               ; number
  (user-name svn-reference-user-name (default #f))
  (password  svn-reference-password (default #f)))

(define (subversion-package)
  "Return the default Subversion package."
  (let ((distro (resolve-interface '(gnu packages version-control))))
    (module-ref distro 'subversion)))

(define* (svn-fetch ref hash-algo hash
                    #:optional name
                    #:key (system (%current-system)) (guile (default-guile))
                    (svn (subversion-package)))
  "Return a fixed-output derivation that fetches REF, a <svn-reference>
object.  The output is expected to have recursive hash HASH of type
HASH-ALGO (a symbol).  Use NAME as the file name, or a generic name if #f."
  (define build
    (with-imported-modules '((guix build svn)
                             (guix build utils))
      #~(begin
          (use-modules (guix build svn))
          (svn-fetch '#$(svn-reference-url ref)
                     '#$(svn-reference-revision ref)
                     #$output
                     #:svn-command (string-append #+svn "/bin/svn")
                     #:user-name #$(svn-reference-user-name ref)
                     #:password #$(svn-reference-password ref)))))

  (mlet %store-monad ((guile (package->derivation guile system)))
    (gexp->derivation (or name "svn-checkout") build
                      #:system system
                      #:hash-algo hash-algo
                      #:hash hash
                      #:recursive? #t
                      #:guile-for-build guile
                      #:local-build? #t)))

;;; svn-download.scm ends here
