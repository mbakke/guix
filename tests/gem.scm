;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 David Thompson <davet@gnu.org>
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

(define-module (test-gem)
  #:use-module (guix import gem)
  #:use-module (guix base32)
  #:use-module (guix hash)
  #:use-module (guix tests)
  #:use-module ((guix build utils) #:select (delete-file-recursively))
  #:use-module (srfi srfi-64)
  #:use-module (ice-9 match))

(define test-json
  "{
  \"name\": \"foo\",
  \"version\": \"1.0.0\",
  \"sha\": \"f3676eafca9987cb5fe263df1edf2538bf6dafc712b30e17be3543a9680547a8\",
  \"info\": \"A cool gem\",
  \"homepage_uri\": \"https://example.com\",
  \"dependencies\": {
    \"runtime\": [
      { \"name\": \"bundler\" },
      { \"name\": \"bar\" }
    ]
  },
  \"licenses\": [\"MIT\", \"Apache 2.0\"]
}")

(test-begin "gem")

(test-assert "gem->guix-package"
  ;; Replace network resources with sample data.
  (mock ((guix http-client) http-fetch
         (lambda (url)
           (match url
             ("https://rubygems.org/api/v1/gems/foo.json"
              (values (open-input-string test-json)
                      (string-length test-json)))
             (_ (error "Unexpected URL: " url)))))
    (match (gem->guix-package "foo")
      (('package
         ('name "ruby-foo")
         ('version "1.0.0")
         ('source ('origin
                    ('method 'url-fetch)
                    ('uri ('rubygems-uri "foo" 'version))
                    ('sha256
                     ('base32
                      "1a270mlajhrmpqbhxcqjqypnvgrq4pgixpv3w9gwp1wrrapnwrzk"))))
         ('build-system 'ruby-build-system)
         ('propagated-inputs
          ('quasiquote
           (("bundler" ('unquote 'bundler))
            ("ruby-bar" ('unquote 'ruby-bar)))))
         ('synopsis "A cool gem")
         ('description "This package provides a cool gem")
         ('home-page "https://example.com")
         ('license ('list 'license:expat 'license:asl2.0)))
       #t)
      (x
       (pk 'fail x #f)))))

(test-end "gem")
