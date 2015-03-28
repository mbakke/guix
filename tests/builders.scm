;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
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


(define-module (test-builders)
  #:use-module (guix download)
  #:use-module (guix build-system)
  #:use-module (guix build-system gnu)
  #:use-module (guix store)
  #:use-module (guix utils)
  #:use-module (guix base32)
  #:use-module (guix derivations)
  #:use-module (guix hash)
  #:use-module (guix tests)
  #:use-module ((guix packages)
                #:select (package-derivation package-native-search-paths))
  #:use-module (gnu packages bootstrap)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-64))

;; Test the higher-level builders.

(define %store
  (open-connection-for-tests))

(define %bootstrap-inputs
  ;; Use the bootstrap inputs so it doesn't take ages to run these tests.
  ;; This still involves building Make, Diffutils, and Findutils.
  ;; XXX: We're relying on the higher-level `package-derivations' here.
  (and %store
       (map (match-lambda
             ((name package)
              (list name (package-derivation %store package))))
            (@@ (gnu packages commencement) %boot0-inputs))))

(define %bootstrap-search-paths
  ;; Search path specifications that go with %BOOTSTRAP-INPUTS.
  (append-map (match-lambda
               ((name package _ ...)
                (package-native-search-paths package)))
              (@@ (gnu packages commencement) %boot0-inputs)))

(define url-fetch*
  (store-lower url-fetch))


(test-begin "builders")

(unless (network-reachable?) (test-skip 1))
(test-assert "url-fetch"
  (let* ((url      '("http://ftp.gnu.org/gnu/hello/hello-2.8.tar.gz"
                     "ftp://ftp.gnu.org/gnu/hello/hello-2.8.tar.gz"))
         (hash     (nix-base32-string->bytevector
                    "0wqd8sjmxfskrflaxywc7gqw7sfawrfvdxd9skxawzfgyy0pzdz6"))
         (drv      (url-fetch* %store url 'sha256 hash
                               #:guile %bootstrap-guile))
         (out-path (derivation->output-path drv)))
    (and (build-derivations %store (list drv))
         (file-exists? out-path)
         (valid-path? %store out-path))))

(test-assert "url-fetch, file"
  (let* ((file (search-path %load-path "guix.scm"))
         (hash (call-with-input-file file port-sha256))
         (out  (url-fetch* %store file 'sha256 hash)))
    (and (file-exists? out)
         (valid-path? %store out))))

(test-assert "url-fetch, file URI"
  (let* ((file (search-path %load-path "guix.scm"))
         (hash (call-with-input-file file port-sha256))
         (out  (url-fetch* %store
                           (string-append "file://" (canonicalize-path file))
                           'sha256 hash)))
    (and (file-exists? out)
         (valid-path? %store out))))

(test-assert "gnu-build-system"
  (build-system? gnu-build-system))

(when (or (not (network-reachable?)) (shebang-too-long?))
  (test-skip 1))
(test-assert "gnu-build"
  (let* ((url      "http://ftp.gnu.org/gnu/hello/hello-2.8.tar.gz")
         (hash     (nix-base32-string->bytevector
                    "0wqd8sjmxfskrflaxywc7gqw7sfawrfvdxd9skxawzfgyy0pzdz6"))
         (tarball  (url-fetch* %store url 'sha256 hash
                               #:guile %bootstrap-guile))
         (build    ((store-lower gnu-build) %store "hello-2.8"
                    %bootstrap-inputs
                    #:source tarball
                    #:guile %bootstrap-guile
                    #:search-paths %bootstrap-search-paths))
         (out      (derivation->output-path build)))
    (and (build-derivations %store (list (pk 'hello-drv build)))
         (valid-path? %store out)
         (file-exists? (string-append out "/bin/hello")))))

(test-end "builders")
