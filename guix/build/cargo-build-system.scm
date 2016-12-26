;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 David Craven <david@craven.ch>
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

(define-module (guix build cargo-build-system)
  #:use-module ((guix build gnu-build-system) #:prefix gnu:)
  #:use-module (guix build utils)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 format)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (%standard-phases
            cargo-build))

;; Commentary:
;;
;; Builder-side code of the standard Rust package build procedure.
;;
;; Code:

;; FIXME: Needs to be parsed from url not package name.
(define (package-name->crate-name name)
  "Return the crate name of NAME."
  (match (string-split name #\-)
    (("rust" rest ...)
     (string-join rest "-"))
    (_ #f)))

(define* (configure #:key inputs #:allow-other-keys)
  "Replace Cargo.toml [dependencies] section with guix inputs."
  (let ((port (open-file "Cargo.toml" "a" #:encoding "utf-8")))
    (format port "~%[replace]~%")
    (for-each
     (match-lambda
       ((name . path)
        (let ((crate (package-name->crate-name name)))
          (when (and crate path)
            (match (string-split (basename path) #\-)
              ((_ ... version)
               (format port "\"~a:~a\" = { path = \"~a/rustsrc\" }~%"
                       crate version path)))))))
     inputs)
    (close-port port))
  #t)

(define* (build #:key (cargo-build-flags '("--release" "--frozen"))
                #:allow-other-keys)
  "Build a given Cargo package."
  (zero? (apply system* `("cargo" "build" ,@cargo-build-flags))))

(define* (check #:key tests? #:allow-other-keys)
  "Run tests for a given Cargo package."
  (when tests?
    (zero? (system* "cargo" "test"))))

(define* (install #:key inputs outputs #:allow-other-keys)
  "Install a given Cargo package."
  (let* ((out (assoc-ref outputs "out"))
         (src (assoc-ref inputs "source"))
         (bin (string-append out "/bin"))
         (rsrc (string-append out "/rustsrc")))
    (mkdir-p rsrc)
    ;; Rust doesn't have a stable ABI yet. Because of this
    ;; Cargo doesn't have a search path for binaries yet.
    ;; Until this changes we are working around this by
    ;; distributing crates as source and replacing
    ;; references in Cargo.toml with store paths.
    (copy-recursively "src" (string-append rsrc "/src"))
    (install-file "Cargo.toml" rsrc)
    ;; When the package includes executables we install
    ;; it using cargo install. This fails when the crate
    ;; doesn't contain an executable.
    (system* "cargo" "install" "--root" bin)
    #t))

(define %standard-phases
  ;; 'configure' phase is not needed.
  (modify-phases gnu:%standard-phases
    (replace 'configure configure)
    (replace 'build build)
    (replace 'check check)
    (replace 'install install)))

(define* (cargo-build #:key inputs (phases %standard-phases)
                      #:allow-other-keys #:rest args)
  "Build the given Cargo package, applying all of PHASES in order."
  (apply gnu:gnu-build #:inputs inputs #:phases phases args))

;;; cargo-build-system.scm ends here
