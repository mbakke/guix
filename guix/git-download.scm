;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (guix git-download)
  #:use-module (guix gexp)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix records)
  #:use-module (guix packages)
  #:autoload   (guix build-system gnu) (standard-packages)
  #:use-module (ice-9 match)
  #:export (git-reference
            git-reference?
            git-reference-url
            git-reference-commit
            git-reference-recursive?

            git-fetch))

;;; Commentary:
;;;
;;; An <origin> method that fetches a specific commit from a Git repository.
;;; The repository URL and commit hash are specified with a <git-reference>
;;; object.
;;;
;;; Code:

(define-record-type* <git-reference>
  git-reference make-git-reference
  git-reference?
  (url        git-reference-url)
  (commit     git-reference-commit)
  (recursive? git-reference-recursive?   ; whether to recurse into sub-modules
              (default #f)))

(define (git-package)
  "Return the default Git package."
  (let ((distro (resolve-interface '(gnu packages version-control))))
    (module-ref distro 'git)))

(define* (git-fetch ref hash-algo hash
                    #:optional name
                    #:key (system (%current-system)) (guile (default-guile))
                    (git (git-package)))
  "Return a fixed-output derivation that fetches REF, a <git-reference>
object.  The output is expected to have recursive hash HASH of type
HASH-ALGO (a symbol).  Use NAME as the file name, or a generic name if #f."
  (define inputs
    ;; When doing 'git clone --recursive', we need sed, grep, etc. to be
    ;; available so that 'git submodule' works.
    (if (git-reference-recursive? ref)
        (standard-packages)
        '()))

  (define build
    (with-imported-modules '((guix build git)
                             (guix build utils))
      #~(begin
          (use-modules (guix build git)
                       (guix build utils)
                       (ice-9 match))

          ;; The 'git submodule' commands expects Coreutils, sed,
          ;; grep, etc. to be in $PATH.
          (set-path-environment-variable "PATH" '("bin")
                                         (match '#+inputs
                                           (((names dirs) ...)
                                            dirs)))

          (git-fetch '#$(git-reference-url ref)
                     '#$(git-reference-commit ref)
                     #$output
                     #:recursive? '#$(git-reference-recursive? ref)
                     #:git-command (string-append #+git "/bin/git")))))

  (mlet %store-monad ((guile (package->derivation guile system)))
    (gexp->derivation (or name "git-checkout") build
                      #:system system
                      #:local-build? #t           ;don't offload repo cloning
                      #:hash-algo hash-algo
                      #:hash hash
                      #:recursive? #t
                      #:guile-for-build guile
                      #:local-build? #t)))

;;; git-download.scm ends here
