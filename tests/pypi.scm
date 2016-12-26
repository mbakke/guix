;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 David Thompson <davet@gnu.org>
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

(define-module (test-pypi)
  #:use-module (guix import pypi)
  #:use-module (guix base32)
  #:use-module (guix hash)
  #:use-module (guix tests)
  #:use-module ((guix build utils) #:select (delete-file-recursively which))
  #:use-module (srfi srfi-64)
  #:use-module (ice-9 match))

(define test-json
  "{
  \"info\": {
    \"version\": \"1.0.0\",
    \"name\": \"foo\",
    \"license\": \"GNU LGPL\",
    \"summary\": \"summary\",
    \"home_page\": \"http://example.com\",
  },
  \"releases\": {
    \"1.0.0\": [
      {
        \"url\": \"https://example.com/foo-1.0.0.egg\",
        \"packagetype\": \"bdist_egg\",
      }, {
        \"url\": \"https://example.com/foo-1.0.0.tar.gz\",
        \"packagetype\": \"sdist\",
      }, {
        \"url\": \"https://example.com/foo-1.0.0-py2.py3-none-any.whl\",
        \"packagetype\": \"bdist_wheel\",
      }
    ]
  }
}")

(define test-source-hash
  "")

(define test-requirements
"# A comment
 # A comment after a space
bar
baz > 13.37")

(define test-metadata
  "{
  \"run_requires\": [
    {
      \"requires\": [
        \"bar\",
        \"baz (>13.37)\"
      ]
    }
  ]
}")

(test-begin "pypi")

(test-equal "guix-package->pypi-name, old URL style"
  "psutil"
  (guix-package->pypi-name
   (dummy-package "foo"
                  (source (dummy-origin
                           (uri
                            "https://pypi.io/packages/source/p/psutil/psutil-4.3.0.tar.gz"))))))

(test-equal "guix-package->pypi-name, new URL style"
  "certbot"
  (guix-package->pypi-name
   (dummy-package "foo"
                  (source (dummy-origin
                           (uri
                            "https://pypi.python.org/packages/a2/3b/4756e6a0ceb14e084042a2a65c615d68d25621c6fd446d0fc10d14c4ce7d/certbot-0.8.1.tar.gz"))))))

(test-assert "pypi->guix-package"
  ;; Replace network resources with sample data.
    (mock ((guix import utils) url-fetch
           (lambda (url file-name)
             (match url
               ("https://example.com/foo-1.0.0.tar.gz"
                (begin
                  (mkdir "foo-1.0.0")
                  (with-output-to-file "foo-1.0.0/requirements.txt"
                    (lambda ()
                      (display test-requirements)))
                  (system* "tar" "czvf" file-name "foo-1.0.0/")
                  (delete-file-recursively "foo-1.0.0")
                  (set! test-source-hash
                    (call-with-input-file file-name port-sha256))))
               ("https://example.com/foo-1.0.0-py2.py3-none-any.whl" #f)
               (_ (error "Unexpected URL: " url)))))
          (mock ((guix http-client) http-fetch
                 (lambda (url)
                   (match url
                     ("https://pypi.python.org/pypi/foo/json"
                      (values (open-input-string test-json)
                              (string-length test-json)))
                     ("https://example.com/foo-1.0.0-py2.py3-none-any.whl" #f)
                     (_ (error "Unexpected URL: " url)))))
                (match (pypi->guix-package "foo")
                  (('package
                     ('name "python-foo")
                     ('version "1.0.0")
                     ('source ('origin
                                ('method 'url-fetch)
                                ('uri (string-append "https://example.com/foo-"
                                                     version ".tar.gz"))
                                ('sha256
                                 ('base32
                                  (? string? hash)))))
                     ('build-system 'python-build-system)
                     ('propagated-inputs
                      ('quasiquote
                       (("python-bar" ('unquote 'python-bar))
                        ("python-baz" ('unquote 'python-baz))
                        ("python-setuptools" ('unquote 'python-setuptools)))))
                     ('home-page "http://example.com")
                     ('synopsis "summary")
                     ('description "summary")
                     ('license 'license:lgpl2.0))
                   (string=? (bytevector->nix-base32-string
                              test-source-hash)
                             hash))
                  (x
                   (pk 'fail x #f))))))

(test-skip (if (which "zip") 0 1))
(test-assert "pypi->guix-package, wheels"
  ;; Replace network resources with sample data.
  (mock ((guix import utils) url-fetch
         (lambda (url file-name)
           (match url
             ("https://example.com/foo-1.0.0.tar.gz"
               (begin
                 (mkdir "foo-1.0.0")
                 (with-output-to-file "foo-1.0.0/requirements.txt"
                   (lambda ()
                     (display test-requirements)))
                 (system* "tar" "czvf" file-name "foo-1.0.0/")
                 (delete-file-recursively "foo-1.0.0")
                 (set! test-source-hash
                       (call-with-input-file file-name port-sha256))))
             ("https://example.com/foo-1.0.0-py2.py3-none-any.whl"
               (begin
                 (mkdir "foo-1.0.0.dist-info")
                 (with-output-to-file "foo-1.0.0.dist-info/metadata.json"
                   (lambda ()
                     (display test-metadata)))
                 (let ((zip-file (string-append file-name ".zip")))
                   ;; zip always adds a "zip" extension to the file it creates,
                   ;; so we need to rename it.
                   (system* "zip" zip-file "foo-1.0.0.dist-info/metadata.json")
                   (rename-file zip-file file-name))
                 (delete-file-recursively "foo-1.0.0.dist-info")))
             (_ (error "Unexpected URL: " url)))))
        (mock ((guix http-client) http-fetch
               (lambda (url)
                 (match url
                   ("https://pypi.python.org/pypi/foo/json"
                    (values (open-input-string test-json)
                            (string-length test-json)))
                   ("https://example.com/foo-1.0.0-py2.py3-none-any.whl" #f)
                   (_ (error "Unexpected URL: " url)))))
              (match (pypi->guix-package "foo")
                (('package
                   ('name "python-foo")
                   ('version "1.0.0")
                   ('source ('origin
                              ('method 'url-fetch)
                              ('uri (string-append "https://example.com/foo-"
                                                   version ".tar.gz"))
                              ('sha256
                               ('base32
                                (? string? hash)))))
                   ('build-system 'python-build-system)
                   ('propagated-inputs
                    ('quasiquote
                     (("python-bar" ('unquote 'python-bar))
                      ("python-baz" ('unquote 'python-baz))
                      ("python-setuptools" ('unquote 'python-setuptools)))))
                   ('home-page "http://example.com")
                   ('synopsis "summary")
                   ('description "summary")
                   ('license 'license:lgpl2.0))
                 (string=? (bytevector->nix-base32-string
                            test-source-hash)
                           hash))
                (x
                 (pk 'fail x #f))))))

(test-end "pypi")
