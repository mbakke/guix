;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013 Cyril Roelandt <tipecaml@gmail.com>
;;; Copyright © 2014, 2015, 2016 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015, 2016 Mathieu Lirzin <mthl@gnu.org>
;;; Copyright © 2016 Hartmut Goebel <h.goebel@crazy-compilers.com>
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

;; Avoid interference.
(unsetenv "http_proxy")

(define-module (test-lint)
  #:use-module (guix tests)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system gnu)
  #:use-module (guix packages)
  #:use-module (guix scripts lint)
  #:use-module (guix ui)
  #:use-module (gnu packages)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (web server)
  #:use-module (web server http)
  #:use-module (web response)
  #:use-module (ice-9 match)
  #:use-module (ice-9 threads)
  #:use-module (srfi srfi-9 gnu)
  #:use-module (srfi srfi-64))

;; Test the linter.

(define %http-server-port
  ;; TCP port to use for the stub HTTP server.
  9999)

(define %local-url
  ;; URL to use for 'home-page' tests.
  (string-append "http://localhost:" (number->string %http-server-port)
                 "/foo/bar"))

(define %null-sha256
  ;; SHA256 of the empty string.
  (base32
   "0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73"))

(define %http-server-socket
  ;; Socket used by the Web server.
  (catch 'system-error
    (lambda ()
      (let ((sock (socket PF_INET SOCK_STREAM 0)))
        (setsockopt sock SOL_SOCKET SO_REUSEADDR 1)
        (bind sock
              (make-socket-address AF_INET INADDR_LOOPBACK
                                   %http-server-port))
        sock))
    (lambda args
      (let ((err (system-error-errno args)))
        (format (current-error-port)
                "warning: cannot run Web server for tests: ~a~%"
                (strerror err))
        #f))))

(define (http-write server client response body)
  "Write RESPONSE."
  (let* ((response (write-response response client))
         (port     (response-port response)))
    (cond
     ((not body))                                 ;pass
     (else
      (write-response-body response body)))
    (close-port port)
    (quit #t)                                     ;exit the server thread
    (values)))

;; Mutex and condition variable to synchronize with the HTTP server.
(define %http-server-lock (make-mutex))
(define %http-server-ready (make-condition-variable))

(define (http-open . args)
  "Start listening for HTTP requests and signal %HTTP-SERVER-READY."
  (with-mutex %http-server-lock
    (let ((result (apply (@@ (web server http) http-open) args)))
      (signal-condition-variable %http-server-ready)
      result)))

(define-server-impl stub-http-server
  ;; Stripped-down version of Guile's built-in HTTP server.
  http-open
  (@@ (web server http) http-read)
  http-write
  (@@ (web server http) http-close))

(define (call-with-http-server code data thunk)
  "Call THUNK with an HTTP server running and returning CODE and DATA (a
string) on HTTP requests."
  (define (server-body)
    (define (handle request body)
      (values (build-response #:code code
                              #:reason-phrase "Such is life")
              data))

    (catch 'quit
      (lambda ()
        (run-server handle stub-http-server
                    `(#:socket ,%http-server-socket)))
      (const #t)))

  (with-mutex %http-server-lock
    (let ((server (make-thread server-body)))
      (wait-condition-variable %http-server-ready %http-server-lock)
      ;; Normally SERVER exits automatically once it has received a request.
      (thunk))))

(define-syntax-rule (with-http-server code data body ...)
  (call-with-http-server code data (lambda () body ...)))

(define %long-string
  (make-string 2000 #\a))


(test-begin "lint")

(define (call-with-warnings thunk)
  (let ((port (open-output-string)))
    (parameterize ((guix-warning-port port))
      (thunk))
    (get-output-string port)))

(define-syntax-rule (with-warnings body ...)
  (call-with-warnings (lambda () body ...)))

(test-assert "description: not a string"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (description 'foobar))))
                        (check-description-style pkg)))
                    "invalid description")))

(test-assert "description: not empty"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (description ""))))
                        (check-description-style pkg)))
                    "description should not be empty")))

(test-assert "description: valid Texinfo markup"
  (->bool
   (string-contains
    (with-warnings
      (check-description-style (dummy-package "x" (description "f{oo}b@r"))))
    "Texinfo markup in description is invalid")))

(test-assert "description: does not start with an upper-case letter"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (description "bad description."))))
                        (check-description-style pkg)))
                    "description should start with an upper-case letter")))

(test-assert "description: may start with a digit"
  (string-null?
   (with-warnings
     (let ((pkg (dummy-package "x"
                  (description "2-component library."))))
       (check-description-style pkg)))))

(test-assert "description: may start with lower-case package name"
  (string-null?
   (with-warnings
     (let ((pkg (dummy-package "x"
                  (description "x is a dummy package."))))
       (check-description-style pkg)))))

(test-assert "description: two spaces after end of sentence"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (description "Bad. Quite bad."))))
                        (check-description-style pkg)))
                    "sentences in description should be followed by two spaces")))

(test-assert "description: end-of-sentence detection with abbreviations"
  (string-null?
   (with-warnings
     (let ((pkg (dummy-package "x"
                  (description
                   "E.g. Foo, i.e. Bar resp. Baz (a.k.a. DVD)."))))
       (check-description-style pkg)))))

(test-assert "description: may not contain trademark signs"
  (and (->bool
        (string-contains (with-warnings
                           (let ((pkg (dummy-package "x"
                                        (description "Does The Right Thing™"))))
                             (check-description-style pkg)))
                         "should not contain trademark sign"))
       (->bool
        (string-contains (with-warnings
                           (let ((pkg (dummy-package "x"
                                        (description "Works with Format®"))))
                             (check-description-style pkg)))
                         "should not contain trademark sign"))))

(test-assert "description: suggest ornament instead of quotes"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (description "This is a 'quoted' thing."))))
                        (check-description-style pkg)))
                    "use @code")))

(test-assert "synopsis: not a string"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (synopsis #f))))
                        (check-synopsis-style pkg)))
                    "invalid synopsis")))

(test-assert "synopsis: not empty"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (synopsis ""))))
                        (check-synopsis-style pkg)))
                    "synopsis should not be empty")))

(test-assert "synopsis: does not start with an upper-case letter"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (synopsis "bad synopsis."))))
                        (check-synopsis-style pkg)))
                    "synopsis should start with an upper-case letter")))

(test-assert "synopsis: may start with a digit"
  (string-null?
   (with-warnings
     (let ((pkg (dummy-package "x"
                  (synopsis "5-dimensional frobnicator"))))
       (check-synopsis-style pkg)))))

(test-assert "synopsis: ends with a period"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (synopsis "Bad synopsis."))))
                        (check-synopsis-style pkg)))
                    "no period allowed at the end of the synopsis")))

(test-assert "synopsis: ends with 'etc.'"
  (string-null? (with-warnings
                  (let ((pkg (dummy-package "x"
                               (synopsis "Foo, bar, etc."))))
                    (check-synopsis-style pkg)))))

(test-assert "synopsis: starts with 'A'"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (synopsis "A bad synopŝis"))))
                        (check-synopsis-style pkg)))
                    "no article allowed at the beginning of the synopsis")))

(test-assert "synopsis: starts with 'An'"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (synopsis "An awful synopsis"))))
                        (check-synopsis-style pkg)))
                    "no article allowed at the beginning of the synopsis")))

(test-assert "synopsis: starts with 'a'"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (synopsis "a bad synopsis"))))
                        (check-synopsis-style pkg)))
                    "no article allowed at the beginning of the synopsis")))

(test-assert "synopsis: starts with 'an'"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (synopsis "an awful synopsis"))))
                        (check-synopsis-style pkg)))
                    "no article allowed at the beginning of the synopsis")))

(test-assert "synopsis: too long"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (synopsis (make-string 80 #\x)))))
                        (check-synopsis-style pkg)))
                    "synopsis should be less than 80 characters long")))

(test-assert "synopsis: start with package name"
  (->bool
   (string-contains (with-warnings
                      (let ((pkg (dummy-package "x"
                                   (name "foo")
                                   (synopsis "foo, a nice package"))))
                        (check-synopsis-style pkg)))
                    "synopsis should not start with the package name")))

(test-assert "synopsis: start with package name prefix"
  (string-null?
   (with-warnings
     (let ((pkg (dummy-package "arb"
                  (synopsis "Arbitrary precision"))))
       (check-synopsis-style pkg)))))

(test-assert "synopsis: start with abbreviation"
  (string-null?
   (with-warnings
     (let ((pkg (dummy-package "uucp"
                  ;; Same problem with "APL interpreter", etc.
                  (synopsis "UUCP implementation")
                  (description "Imagine this is Taylor UUCP."))))
       (check-synopsis-style pkg)))))

(test-assert "inputs: pkg-config is probably a native input"
  (->bool
   (string-contains
     (with-warnings
       (let ((pkg (dummy-package "x"
                    (inputs `(("pkg-config" ,pkg-config))))))
         (check-inputs-should-be-native pkg)))
         "'pkg-config' should probably be a native input")))

(test-assert "inputs: glib:bin is probably a native input"
  (->bool
    (string-contains
      (with-warnings
        (let ((pkg (dummy-package "x"
                     (inputs `(("glib" ,glib "bin"))))))
          (check-inputs-should-be-native pkg)))
          "'glib:bin' should probably be a native input")))

(test-assert
    "inputs: python-setuptools should not be an input at all (input)"
  (->bool
   (string-contains
     (with-warnings
       (let ((pkg (dummy-package "x"
                    (inputs `(("python-setuptools" ,python-setuptools))))))
         (check-inputs-should-not-be-an-input-at-all pkg)))
         "'python-setuptools' should probably not be an input at all")))

(test-assert
    "inputs: python-setuptools should not be an input at all (native-input)"
  (->bool
   (string-contains
     (with-warnings
       (let ((pkg (dummy-package "x"
                    (native-inputs
                     `(("python-setuptools" ,python-setuptools))))))
         (check-inputs-should-not-be-an-input-at-all pkg)))
         "'python-setuptools' should probably not be an input at all")))

(test-assert
    "inputs: python-setuptools should not be an input at all (propagated-input)"
  (->bool
   (string-contains
     (with-warnings
       (let ((pkg (dummy-package "x"
                    (propagated-inputs
                     `(("python-setuptools" ,python-setuptools))))))
         (check-inputs-should-not-be-an-input-at-all pkg)))
         "'python-setuptools' should probably not be an input at all")))

(test-assert "patches: file names"
  (->bool
   (string-contains
     (with-warnings
       (let ((pkg (dummy-package "x"
                    (source
                     (dummy-origin
                       (patches (list "/path/to/y.patch")))))))
         (check-patch-file-names pkg)))
     "file names of patches should start with the package name")))

(test-assert "patches: not found"
  (->bool
   (string-contains
     (with-warnings
       (let ((pkg (dummy-package "x"
                    (source
                     (dummy-origin
                       (patches
                        (list (search-patch "this-patch-does-not-exist!"))))))))
         (check-patch-file-names pkg)))
     "patch not found")))

(test-assert "derivation: invalid arguments"
  (->bool
   (string-contains
    (with-warnings
      (let ((pkg (dummy-package "x"
                   (arguments
                    '(#:imported-modules (invalid-module))))))
        (check-derivation pkg)))
    "failed to create derivation")))

(test-assert "license: invalid license"
  (string-contains
   (with-warnings
     (check-license (dummy-package "x" (license #f))))
   "invalid license"))

(test-assert "home-page: wrong home-page"
  (->bool
   (string-contains
    (with-warnings
      (let ((pkg (package
                   (inherit (dummy-package "x"))
                   (home-page #f))))
        (check-home-page pkg)))
    "invalid")))

(test-assert "home-page: invalid URI"
  (->bool
   (string-contains
    (with-warnings
      (let ((pkg (package
                   (inherit (dummy-package "x"))
                   (home-page "foobar"))))
        (check-home-page pkg)))
    "invalid home page URL")))

(test-assert "home-page: host not found"
  (->bool
   (string-contains
    (with-warnings
      (let ((pkg (package
                   (inherit (dummy-package "x"))
                   (home-page "http://does-not-exist"))))
        (check-home-page pkg)))
    "domain not found")))

(test-skip (if %http-server-socket 0 1))
(test-assert "home-page: Connection refused"
  (->bool
   (string-contains
    (with-warnings
      (let ((pkg (package
                   (inherit (dummy-package "x"))
                   (home-page %local-url))))
        (check-home-page pkg)))
    "Connection refused")))

(test-skip (if %http-server-socket 0 1))
(test-equal "home-page: 200"
  ""
  (with-warnings
   (with-http-server 200 %long-string
     (let ((pkg (package
                  (inherit (dummy-package "x"))
                  (home-page %local-url))))
       (check-home-page pkg)))))

(test-skip (if %http-server-socket 0 1))
(test-assert "home-page: 200 but short length"
  (->bool
   (string-contains
    (with-warnings
      (with-http-server 200 "This is too small."
        (let ((pkg (package
                     (inherit (dummy-package "x"))
                     (home-page %local-url))))
          (check-home-page pkg))))
    "suspiciously small")))

(test-skip (if %http-server-socket 0 1))
(test-assert "home-page: 404"
  (->bool
   (string-contains
    (with-warnings
      (with-http-server 404 %long-string
        (let ((pkg (package
                     (inherit (dummy-package "x"))
                     (home-page %local-url))))
          (check-home-page pkg))))
    "not reachable: 404")))

(test-assert "source-file-name"
  (->bool
   (string-contains
    (with-warnings
      (let ((pkg (dummy-package "x"
                   (version "3.2.1")
                   (source
                    (origin
                      (method url-fetch)
                      (uri "http://www.example.com/3.2.1.tar.gz")
                      (sha256 %null-sha256))))))
        (check-source-file-name pkg)))
    "file name should contain the package name")))

(test-assert "source-file-name: v prefix"
  (->bool
   (string-contains
    (with-warnings
      (let ((pkg (dummy-package "x"
                   (version "3.2.1")
                   (source
                    (origin
                      (method url-fetch)
                      (uri "http://www.example.com/v3.2.1.tar.gz")
                      (sha256 %null-sha256))))))
        (check-source-file-name pkg)))
    "file name should contain the package name")))

(test-assert "source-file-name: bad checkout"
  (->bool
   (string-contains
    (with-warnings
      (let ((pkg (dummy-package "x"
                   (version "3.2.1")
                   (source
                    (origin
                      (method git-fetch)
                      (uri (git-reference
                            (url "http://www.example.com/x.git")
                            (commit "0")))
                      (sha256 %null-sha256))))))
        (check-source-file-name pkg)))
    "file name should contain the package name")))

(test-assert "source-file-name: good checkout"
  (not
   (->bool
    (string-contains
     (with-warnings
       (let ((pkg (dummy-package "x"
                    (version "3.2.1")
                    (source
                     (origin
                       (method git-fetch)
                       (uri (git-reference
                             (url "http://git.example.com/x.git")
                             (commit "0")))
                       (file-name (string-append "x-" version))
                       (sha256 %null-sha256))))))
         (check-source-file-name pkg)))
     "file name should contain the package name"))))

(test-assert "source-file-name: valid"
  (not
   (->bool
    (string-contains
     (with-warnings
       (let ((pkg (dummy-package "x"
                    (version "3.2.1")
                    (source
                     (origin
                       (method url-fetch)
                       (uri "http://www.example.com/x-3.2.1.tar.gz")
                       (sha256 %null-sha256))))))
         (check-source-file-name pkg)))
     "file name should contain the package name"))))

(test-skip (if %http-server-socket 0 1))
(test-equal "source: 200"
  ""
  (with-warnings
   (with-http-server 200 %long-string
     (let ((pkg (package
                  (inherit (dummy-package "x"))
                  (source (origin
                            (method url-fetch)
                            (uri %local-url)
                            (sha256 %null-sha256))))))
       (check-source pkg)))))

(test-skip (if %http-server-socket 0 1))
(test-assert "source: 200 but short length"
  (->bool
   (string-contains
    (with-warnings
      (with-http-server 200 "This is too small."
        (let ((pkg (package
                     (inherit (dummy-package "x"))
                     (source (origin
                               (method url-fetch)
                               (uri %local-url)
                               (sha256 %null-sha256))))))
          (check-source pkg))))
    "suspiciously small")))

(test-skip (if %http-server-socket 0 1))
(test-assert "source: 404"
  (->bool
   (string-contains
    (with-warnings
      (with-http-server 404 %long-string
        (let ((pkg (package
                     (inherit (dummy-package "x"))
                     (source (origin
                               (method url-fetch)
                               (uri %local-url)
                               (sha256 %null-sha256))))))
          (check-source pkg))))
    "not reachable: 404")))

(test-assert "cve"
  (mock ((guix scripts lint) package-vulnerabilities (const '()))
        (string-null?
         (with-warnings (check-vulnerabilities (dummy-package "x"))))))

(test-assert "cve: one vulnerability"
  (mock ((guix scripts lint) package-vulnerabilities
         (lambda (package)
           (list (make-struct (@@ (guix cve) <vulnerability>) 0
                              "CVE-2015-1234"
                              (list (cons (package-name package)
                                          (package-version package)))))))
        (string-contains
         (with-warnings
           (check-vulnerabilities (dummy-package "pi" (version "3.14"))))
         "vulnerable to CVE-2015-1234")))

(test-assert "cve: one patched vulnerability"
  (mock ((guix scripts lint) package-vulnerabilities
         (lambda (package)
           (list (make-struct (@@ (guix cve) <vulnerability>) 0
                              "CVE-2015-1234"
                              (list (cons (package-name package)
                                          (package-version package)))))))
        (string-null?
         (with-warnings
           (check-vulnerabilities
            (dummy-package "pi"
                           (version "3.14")
                           (source
                            (dummy-origin
                             (patches
                              (list "/a/b/pi-CVE-2015-1234.patch"))))))))))

(test-assert "cve: vulnerability fixed in replacement version"
  (mock ((guix scripts lint) package-vulnerabilities
         (lambda (package)
           (match (package-version package)
             ("0"
              (list (make-struct (@@ (guix cve) <vulnerability>) 0
                                 "CVE-2015-1234"
                                 (list (cons (package-name package)
                                             (package-version package))))))
             ("1"
              '()))))
        (and (not (string-null?
                   (with-warnings
                     (check-vulnerabilities
                      (dummy-package "foo" (version "0"))))))
             (string-null?
              (with-warnings
                (check-vulnerabilities
                 (dummy-package
                  "foo" (version "0")
                  (replacement (dummy-package "foo" (version "1"))))))))))

(test-assert "cve: patched vulnerability in replacement"
  (mock ((guix scripts lint) package-vulnerabilities
         (lambda (package)
           (list (make-struct (@@ (guix cve) <vulnerability>) 0
                              "CVE-2015-1234"
                              (list (cons (package-name package)
                                          (package-version package)))))))
        (string-null?
         (with-warnings
           (check-vulnerabilities
            (dummy-package
             "pi" (version "3.14") (source (dummy-origin))
             (replacement (dummy-package
                           "pi" (version "3.14")
                           (source
                            (dummy-origin
                             (patches
                              (list "/a/b/pi-CVE-2015-1234.patch"))))))))))))

(test-assert "formatting: lonely parentheses"
  (string-contains
   (with-warnings
     (check-formatting
      (
       dummy-package "ugly as hell!"
      )
      ))
   "lonely"))

(test-assert "formatting: tabulation"
  (string-contains
   (with-warnings
     (check-formatting (dummy-package "leave the tab here:	")))
   "tabulation"))

(test-assert "formatting: trailing white space"
  (string-contains
   (with-warnings
     ;; Leave the trailing white space on the next line!
     (check-formatting (dummy-package "x")))            
   "trailing white space"))

(test-assert "formatting: long line"
  (string-contains
   (with-warnings
     (check-formatting
      (dummy-package "x"                          ;here is a stupid comment just to make a long line
                     )))
   "too long"))

(test-assert "formatting: alright"
  (string-null?
   (with-warnings
     (check-formatting (dummy-package "x")))))

(test-end "lint")

;; Local Variables:
;; eval: (put 'with-http-server 'scheme-indent-function 2)
;; eval: (put 'with-warnings 'scheme-indent-function 0)
;; End:
