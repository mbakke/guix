;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 David Thompson <davet@gnu.org>
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

(define-module (test-crate)
  #:use-module (guix import crate)
  #:use-module (guix base32)
  #:use-module (guix build-system cargo)
  #:use-module (guix hash)
  #:use-module (guix tests)
  #:use-module (ice-9 iconv)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-64))

(define test-crate
  "{
  \"crate\": {
    \"max_version\": \"1.0.0\",
    \"name\": \"foo\",
    \"license\": \"MIT/Apache-2.0\",
    \"description\": \"summary\",
    \"homepage\": \"http://example.com\",
  }
}")

(define test-dependencies
  "{
  \"dependencies\": [
     {
       \"crate_id\": \"bar\",
       \"kind\": \"normal\",
     }
  ]
}")

(define test-source-hash
  "")

(test-begin "crate")

(test-equal "guix-package->crate-name"
  "rustc-serialize"
  (guix-package->crate-name
   (dummy-package
    "rust-rustc-serialize"
    (source (dummy-origin
     (uri (crate-uri "rustc-serialize" "1.0")))))))

(test-assert "crate->guix-package"
  ;; Replace network resources with sample data.
  (mock ((guix http-client) http-fetch
         (lambda (url)
           (match url
             ("https://crates.io/api/v1/crates/foo"
              (open-input-string test-crate))
             ("https://crates.io/api/v1/crates/foo/1.0.0/download"
              (set! test-source-hash
                (bytevector->nix-base32-string
                 (sha256 (string->bytevector "empty file\n" "utf-8"))))
              (open-input-string "empty file\n"))
             ("https://crates.io/api/v1/crates/foo/1.0.0/dependencies"
              (open-input-string test-dependencies))
             (_ (error "Unexpected URL: " url)))))
    (match (crate->guix-package "foo")
      (('package
         ('name "rust-foo")
         ('version "1.0.0")
         ('source ('origin
                    ('method 'url-fetch)
                    ('uri ('crate-uri "foo" 'version))
                    ('file-name ('string-append 'name "-" 'version ".tar.gz"))
                    ('sha256
                     ('base32
                      (? string? hash)))))
         ('build-system 'cargo-build-system)
         ('inputs
          ('quasiquote
           (("rust-bar" ('unquote 'rust-bar)))))
         ('home-page "http://example.com")
         ('synopsis "summary")
         ('description "summary")
         ('license ('list 'license:expat 'license:asl2.0)))
       (string=? test-source-hash hash))
      (x
       (pk 'fail x #f)))))

(test-end "crate")
