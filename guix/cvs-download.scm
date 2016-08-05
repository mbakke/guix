;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014 Sree Harsha Totakura <sreeharsha@totakura.in>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
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

(define-module (guix cvs-download)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix packages)
  #:use-module (ice-9 match)
  #:export (cvs-reference
            cvs-reference?
            cvs-reference-url
            cvs-reference-revision
            cvs-fetch))

;;; Commentary:
;;;
;;; An <origin> method that fetches a specific revision or date from a CVS
;;; repository.  The CVS-ROOT-DIRECTORY, MODULE and REVISION are specified
;;; with a <cvs-reference> object.  REVISION should be specified as either a
;;; date string in ISO-8601 format (e.g. "2012-12-21") or a CVS tag.
;;;
;;; Code:

(define-record-type* <cvs-reference>
  cvs-reference make-cvs-reference
  cvs-reference?
  (root-directory cvs-reference-root-directory)         ; string
  (module         cvs-reference-module)                 ; string
  (revision       cvs-reference-revision))              ; string

(define (cvs-package)
  "Return the default CVS package."
  (let ((distro (resolve-interface '(gnu packages version-control))))
    (module-ref distro 'cvs)))

(define* (cvs-fetch ref hash-algo hash
                    #:optional name
                    #:key (system (%current-system)) (guile (default-guile))
                    (cvs (cvs-package)))
  "Return a fixed-output derivation that fetches REF, a <cvs-reference>
object.  The output is expected to have recursive hash HASH of type
HASH-ALGO (a symbol).  Use NAME as the file name, or a generic name if #f."
  (define build
    (with-imported-modules '((guix build cvs)
                             (guix build utils))
      #~(begin
          (use-modules (guix build cvs))
          (cvs-fetch '#$(cvs-reference-root-directory ref)
                     '#$(cvs-reference-module ref)
                     '#$(cvs-reference-revision ref)
                     #$output
                     #:cvs-command (string-append #+cvs "/bin/cvs")))))

  (mlet %store-monad ((guile (package->derivation guile system)))
    (gexp->derivation (or name "cvs-checkout") build
                      #:system system
                      #:hash-algo hash-algo
                      #:hash hash
                      #:recursive? #t
                      #:guile-for-build guile
                      #:local-build? #t)))

;;; cvs-download.scm ends here
