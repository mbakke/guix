;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (guix tests)
  #:use-module (guix store)
  #:use-module (guix derivations)
  #:use-module (guix packages)
  #:use-module (guix base32)
  #:use-module (guix serialization)
  #:use-module (guix hash)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages bootstrap)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-64)
  #:use-module (rnrs bytevectors)
  #:use-module (rnrs io ports)
  #:use-module (web uri)
  #:export (open-connection-for-tests
            random-text
            random-bytevector
            file=?
            network-reachable?
            shebang-too-long?
            mock
            %test-substitute-urls
            test-assertm
            %substitute-directory
            with-derivation-narinfo
            with-derivation-substitute
            dummy-package
            dummy-origin))

;;; Commentary:
;;;
;;; This module provide shared infrastructure for the test suite.  For
;;; internal use only.
;;;
;;; Code:

(define %test-substitute-urls
  ;; URLs where to look for substitutes during tests.
  (make-parameter
   (or (and=> (getenv "GUIX_BINARY_SUBSTITUTE_URL") list)
       '())))

(define* (open-connection-for-tests #:optional (file (%daemon-socket-file)))
  "Open a connection to the build daemon for tests purposes and return it."
  (guard (c ((nix-error? c)
             (format (current-error-port)
                     "warning: build daemon error: ~s~%" c)
             #f))
    (let ((store (open-connection file)))
      ;; Make sure we build everything by ourselves.
      (set-build-options store
                         #:use-substitutes? #f
                         #:substitute-urls (%test-substitute-urls))

      ;; Use the bootstrap Guile when running tests, so we don't end up
      ;; building everything in the temporary test store.
      (%guile-for-build (package-derivation store %bootstrap-guile))

      store)))

(define (random-seed)
  (or (and=> (getenv "GUIX_TESTS_RANDOM_SEED")
             number->string)
      (logxor (getpid) (car (gettimeofday)))))

(define %seed
  (let ((seed (random-seed)))
    (format (current-error-port) "random seed for tests: ~a~%"
            seed)
    (seed->random-state seed)))

(define (random-text)
  "Return the hexadecimal representation of a random number."
  (number->string (random (expt 2 256) %seed) 16))

(define (random-bytevector n)
  "Return a random bytevector of N bytes."
  (let ((bv (make-bytevector n)))
    (let loop ((i 0))
      (if (< i n)
          (begin
            (bytevector-u8-set! bv i (random 256 %seed))
            (loop (1+ i)))
          bv))))

(define (file=? a b)
  "Return true if files A and B have the same type and same content."
  (and (eq? (stat:type (lstat a)) (stat:type (lstat b)))
       (case (stat:type (lstat a))
         ((regular)
          (equal?
           (call-with-input-file a get-bytevector-all)
           (call-with-input-file b get-bytevector-all)))
         ((symlink)
          (string=? (readlink a) (readlink b)))
         (else
          (error "what?" (lstat a))))))

(define (network-reachable?)
  "Return true if we can reach the Internet."
  (false-if-exception (getaddrinfo "www.gnu.org" "80" AI_NUMERICSERV)))

(define-syntax-rule (mock (module proc replacement) body ...)
  "Within BODY, replace the definition of PROC from MODULE with the definition
given by REPLACEMENT."
  (let* ((m (resolve-module 'module))
         (original (module-ref m 'proc)))
    (dynamic-wind
      (lambda () (module-set! m 'proc replacement))
      (lambda () body ...)
      (lambda () (module-set! m 'proc original)))))

(define-syntax-rule (test-assertm name exp)
  "Like 'test-assert', but EXP has a monadic value.  A new connection to the
store is opened."
  (test-assert name
    (with-store store
      (run-with-store store exp
                      #:guile-for-build (%guile-for-build)))))


;;;
;;; Narinfo files, as used by the substituter.
;;;

(define* (derivation-narinfo drv #:key (nar "example.nar")
                             (sha256 (make-bytevector 32 0))
                             (references '()))
  "Return the contents of the narinfo corresponding to DRV, with the specified
REFERENCES (a list of store items); NAR should be the file name of the archive
containing the substitute for DRV, and SHA256 is the expected hash."
  (format #f "StorePath: ~a
URL: ~a
Compression: none
NarSize: 1234
NarHash: sha256:~a
References: ~a
System: ~a
Deriver: ~a~%"
          (derivation->output-path drv)       ; StorePath
          nar                                 ; URL
          (bytevector->nix-base32-string sha256)  ; NarHash
          (string-join (map basename references)) ; References
          (derivation-system drv)             ; System
          (basename
           (derivation-file-name drv))))      ; Deriver

(define %substitute-directory
  (make-parameter
   (and=> (getenv "GUIX_BINARY_SUBSTITUTE_URL")
          (compose uri-path string->uri))))

(define* (call-with-derivation-narinfo drv thunk
                                       #:key
                                       (sha256 (make-bytevector 32 0))
                                       (references '()))
  "Call THUNK in a context where fake substituter data, as read by 'guix
substitute', has been installed for DRV.  SHA256 is the hash of the
expected output of DRV."
  (let* ((output  (derivation->output-path drv))
         (dir     (%substitute-directory))
         (info    (string-append dir "/nix-cache-info"))
         (narinfo (string-append dir "/" (store-path-hash-part output)
                                 ".narinfo")))
    (dynamic-wind
      (lambda ()
        (call-with-output-file info
          (lambda (p)
            (format p "StoreDir: ~a\nWantMassQuery: 0\n"
                    (%store-prefix))))
        (call-with-output-file narinfo
          (lambda (p)
            (display (derivation-narinfo drv #:sha256 sha256
                                         #:references references)
                     p))))
      thunk
      (lambda ()
        (delete-file narinfo)
        (delete-file info)))))

(define-syntax with-derivation-narinfo
  (syntax-rules (sha256 references =>)
    "Evaluate BODY in a context where DRV looks substitutable from the
substituter's viewpoint."
    ((_ drv (sha256 => hash) (references => refs) body ...)
     (call-with-derivation-narinfo drv
       (lambda () body ...)
       #:sha256 hash
       #:references refs))
    ((_ drv (sha256 => hash) body ...)
     (with-derivation-narinfo drv
       (sha256 => hash) (references => '())
       body ...))
    ((_ drv body ...)
     (call-with-derivation-narinfo drv
       (lambda ()
         body ...)))))

(define* (call-with-derivation-substitute drv contents thunk
                                          #:key
                                          sha256
                                          (references '()))
  "Call THUNK in a context where a substitute for DRV has been installed,
using CONTENTS, a string, as its contents.  If SHA256 is true, use it as the
expected hash of the substitute; otherwise use the hash of the nar containing
CONTENTS."
  (define dir (%substitute-directory))
  (dynamic-wind
    (lambda ()
      (call-with-output-file (string-append dir "/example.out")
        (lambda (port)
          (display contents port)))
      (call-with-output-file (string-append dir "/example.nar")
        (lambda (p)
          (write-file (string-append dir "/example.out") p))))
    (lambda ()
      (let ((hash (call-with-input-file (string-append dir "/example.nar")
                    port-sha256)))
        ;; Create fake substituter data, to be read by 'guix substitute'.
        (call-with-derivation-narinfo drv
          thunk
          #:sha256 (or sha256 hash)
          #:references references)))
    (lambda ()
      (delete-file (string-append dir "/example.out"))
      (delete-file (string-append dir "/example.nar")))))

(define (shebang-too-long?)
  "Return true if the typical shebang in the current store would exceed
Linux's static limit---the BINPRM_BUF_SIZE constant, normally 128 characters
all included."
  (define shebang
    (string-append "#!" (%store-prefix) "/"
                   (make-string 32 #\a)
                   "-bootstrap-binaries-0/bin/bash\0"))

  (> (string-length shebang) 128))

(define-syntax with-derivation-substitute
  (syntax-rules (sha256 references =>)
    "Evaluate BODY in a context where DRV is substitutable with the given
CONTENTS."
    ((_ drv contents (sha256 => hash) (references => refs) body ...)
     (call-with-derivation-substitute drv contents
       (lambda () body ...)
       #:sha256 hash
       #:references refs))
    ((_ drv contents (sha256 => hash) body ...)
     (with-derivation-substitute drv contents
       (sha256 => hash) (references => '())
       body ...))
    ((_ drv contents body ...)
     (call-with-derivation-substitute drv contents
       (lambda ()
         body ...)))))

(define-syntax-rule (dummy-package name* extra-fields ...)
  "Return a \"dummy\" package called NAME*, with all its compulsory fields
initialized with default values, and with EXTRA-FIELDS set as specified."
  (package extra-fields ...
           (name name*) (version "0") (source #f)
           (build-system gnu-build-system)
           (synopsis #f) (description #f)
           (home-page #f) (license #f)))

(define-syntax-rule (dummy-origin extra-fields ...)
  "Return a \"dummy\" origin, with all its compulsory fields initialized with
default values, and with EXTRA-FIELDS set as specified."
  (origin extra-fields ...
          (method #f) (uri "http://www.example.com")
          (sha256 (base32 (make-string 52 #\x)))))

;; Local Variables:
;; eval: (put 'call-with-derivation-narinfo 'scheme-indent-function 1)
;; eval: (put 'call-with-derivation-substitute 'scheme-indent-function 2)
;; End:

;;; tests.scm ends here
