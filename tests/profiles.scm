;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014 Alex Kost <alezost@gmail.com>
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

(define-module (test-profiles)
  #:use-module (guix tests)
  #:use-module (guix profiles)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix grafts)
  #:use-module (guix packages)
  #:use-module (guix derivations)
  #:use-module (guix build-system trivial)
  #:use-module (gnu packages bootstrap)
  #:use-module ((gnu packages base) #:prefix packages:)
  #:use-module ((gnu packages guile) #:prefix packages:)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 popen)
  #:use-module (rnrs io ports)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-64))

;; Test the (guix profiles) module.

(define %store
  (open-connection-for-tests))

;; Globally disable grafts because they can trigger early builds.
(%graft? #f)

(define-syntax-rule (test-assertm name exp)
  (test-assert name
    (run-with-store %store exp
                    #:guile-for-build (%guile-for-build))))

;; Example manifest entries.

(define guile-1.8.8
  (manifest-entry
    (name "guile")
    (version "1.8.8")
    (item "/gnu/store/...")
    (output "out")))

(define guile-2.0.9
  (manifest-entry
    (name "guile")
    (version "2.0.9")
    (item "/gnu/store/...")
    (output "out")))

(define guile-2.0.9:debug
  (manifest-entry (inherit guile-2.0.9)
    (output "debug")))

(define glibc
  (manifest-entry
    (name "glibc")
    (version "2.19")
    (item "/gnu/store/...")
    (output "out")))


(test-begin "profiles")

(test-assert "manifest-installed?"
  (let ((m (manifest (list guile-2.0.9 guile-2.0.9:debug))))
    (and (manifest-installed? m (manifest-pattern (name "guile")))
         (manifest-installed? m (manifest-pattern
                                  (name "guile") (output "debug")))
         (manifest-installed? m (manifest-pattern
                                  (name "guile") (output "out")
                                  (version "2.0.9")))
         (not (manifest-installed?
               m (manifest-pattern (name "guile") (version "1.8.8"))))
         (not (manifest-installed?
               m (manifest-pattern (name "guile") (output "foobar")))))))

(test-assert "manifest-matching-entries"
  (let* ((e (list guile-2.0.9 guile-2.0.9:debug))
         (m (manifest e)))
    (and (null? (manifest-matching-entries m
                                           (list (manifest-pattern
                                                   (name "python")))))
         (equal? e
                 (manifest-matching-entries m
                                            (list (manifest-pattern
                                                    (name "guile")
                                                    (output #f)))))
         (equal? (list guile-2.0.9)
                 (manifest-matching-entries m
                                            (list (manifest-pattern
                                                    (name "guile")
                                                    (version "2.0.9"))))))))

(test-assert "manifest-remove"
  (let* ((m0 (manifest (list guile-2.0.9 guile-2.0.9:debug)))
         (m1 (manifest-remove m0
                              (list (manifest-pattern (name "guile")))))
         (m2 (manifest-remove m1
                              (list (manifest-pattern (name "guile"))))) ; same
         (m3 (manifest-remove m2
                              (list (manifest-pattern
                                      (name "guile") (output "debug")))))
         (m4 (manifest-remove m3
                              (list (manifest-pattern (name "guile"))))))
    (match (manifest-entries m2)
      ((($ <manifest-entry> "guile" "2.0.9" "debug"))
       (and (equal? m1 m2)
            (null? (manifest-entries m3))
            (null? (manifest-entries m4)))))))

(test-assert "manifest-add"
  (let* ((m0 (manifest '()))
         (m1 (manifest-add m0 (list guile-1.8.8)))
         (m2 (manifest-add m1 (list guile-2.0.9)))
         (m3 (manifest-add m2 (list guile-2.0.9:debug)))
         (m4 (manifest-add m3 (list guile-2.0.9:debug))))
    (and (match (manifest-entries m1)
           ((($ <manifest-entry> "guile" "1.8.8" "out")) #t)
           (_ #f))
         (match (manifest-entries m2)
           ((($ <manifest-entry> "guile" "2.0.9" "out")) #t)
           (_ #f))
         (equal? m3 m4))))

(test-assert "manifest-perform-transaction"
  (let* ((m0 (manifest (list guile-2.0.9 guile-2.0.9:debug)))
         (t1 (manifest-transaction
              (install (list guile-1.8.8))
              (remove (list (manifest-pattern (name "guile")
                                              (output "debug"))))))
         (t2 (manifest-transaction
              (remove (list (manifest-pattern (name "guile")
                                              (version "2.0.9")
                                              (output #f))))))
         (m1 (manifest-perform-transaction m0 t1))
         (m2 (manifest-perform-transaction m1 t2))
         (m3 (manifest-perform-transaction m0 t2)))
    (and (match (manifest-entries m1)
           ((($ <manifest-entry> "guile" "1.8.8" "out")) #t)
           (_ #f))
         (equal? m1 m2)
         (null? (manifest-entries m3)))))

(test-assert "manifest-transaction-effects"
  (let* ((m0 (manifest (list guile-1.8.8)))
         (t  (manifest-transaction
              (install (list guile-2.0.9 glibc))
              (remove (list (manifest-pattern (name "coreutils")))))))
    (let-values (((remove install upgrade downgrade)
                  (manifest-transaction-effects m0 t)))
      (and (null? remove) (null? downgrade)
           (equal? (list glibc) install)
           (equal? (list (cons guile-1.8.8 guile-2.0.9)) upgrade)))))

(test-assert "manifest-transaction-effects and downgrades"
  (let* ((m0 (manifest (list guile-2.0.9)))
         (t  (manifest-transaction (install (list guile-1.8.8)))))
    (let-values (((remove install upgrade downgrade)
                  (manifest-transaction-effects m0 t)))
      (and (null? remove) (null? install) (null? upgrade)
           (equal? (list (cons guile-2.0.9 guile-1.8.8)) downgrade)))))

(test-assert "manifest-transaction-effects and pseudo-upgrades"
  (let* ((m0 (manifest (list guile-2.0.9)))
         (t  (manifest-transaction (install (list guile-2.0.9)))))
    (let-values (((remove install upgrade downgrade)
                  (manifest-transaction-effects m0 t)))
      (and (null? remove) (null? install) (null? downgrade)
           (equal? (list (cons guile-2.0.9 guile-2.0.9)) upgrade)))))

(test-assert "manifest-transaction-null?"
  (manifest-transaction-null? (manifest-transaction)))

(test-assertm "profile-derivation"
  (mlet* %store-monad
      ((entry ->   (package->manifest-entry %bootstrap-guile))
       (guile      (package->derivation %bootstrap-guile))
       (drv        (profile-derivation (manifest (list entry))
                                       #:hooks '()
                                       #:locales? #f))
       (profile -> (derivation->output-path drv))
       (bindir ->  (string-append profile "/bin"))
       (_          (built-derivations (list drv))))
    (return (and (file-exists? (string-append bindir "/guile"))
                 (string=? (dirname (readlink bindir))
                           (derivation->output-path guile))))))

(test-assertm "profile-derivation, inputs"
  (mlet* %store-monad
      ((entry ->   (package->manifest-entry packages:glibc "debug"))
       (drv        (profile-derivation (manifest (list entry))
                                       #:hooks '()
                                       #:locales? #f)))
    (return (derivation-inputs drv))))

(test-assert "package->manifest-entry defaults to \"out\""
  (let ((outputs (package-outputs packages:glibc)))
    (equal? (manifest-entry-output
             (package->manifest-entry (package
                                        (inherit packages:glibc)
                                        (outputs (reverse outputs)))))
            (manifest-entry-output
             (package->manifest-entry packages:glibc))
            "out")))

(test-assertm "profile-manifest, search-paths"
  (mlet* %store-monad
      ((guile ->   (package
                     (inherit %bootstrap-guile)
                     (native-search-paths
                      (package-native-search-paths packages:guile-2.0))))
       (entry ->   (package->manifest-entry guile))
       (drv        (profile-derivation (manifest (list entry))
                                       #:hooks '()
                                       #:locales? #f))
       (profile -> (derivation->output-path drv)))
    (mbegin %store-monad
      (built-derivations (list drv))

      ;; Read the manifest back and make sure search paths are preserved.
      (let ((manifest (profile-manifest profile)))
        (match (manifest-entries manifest)
          ((result)
           (return (equal? (manifest-entry-search-paths result)
                           (manifest-entry-search-paths entry)
                           (package-native-search-paths
                            packages:guile-2.0)))))))))

(test-assert "package->manifest-entry, search paths"
  ;; See <http://bugs.gnu.org/22073>.
  (let ((mpl (@ (gnu packages python) python2-matplotlib)))
    (lset= eq?
           (package-transitive-native-search-paths mpl)
           (manifest-entry-search-paths
            (package->manifest-entry mpl)))))

(test-assertm "etc/profile"
  ;; Make sure we get an 'etc/profile' file that at least defines $PATH.
  (mlet* %store-monad
      ((guile ->   (package
                     (inherit %bootstrap-guile)
                     (native-search-paths
                      (package-native-search-paths packages:guile-2.0))))
       (entry ->   (package->manifest-entry guile))
       (drv        (profile-derivation (manifest (list entry))
                                       #:hooks '()
                                       #:locales? #f))
       (profile -> (derivation->output-path drv)))
    (mbegin %store-monad
      (built-derivations (list drv))
      (let* ((pipe (open-input-pipe
                    (string-append "unset GUIX_PROFILE; "
                                   ;; 'source' is a Bashism; use '.' (dot).
                                   ". " profile "/etc/profile; "
                                   ;; Don't try to parse set(1) output because
                                   ;; it differs among shells; just use echo.
                                   "echo $PATH")))
             (path (get-string-all pipe)))
        (return
         (and (zero? (close-pipe pipe))
              (string-contains path (string-append profile "/bin"))))))))

(test-assertm "etc/profile when etc/ already exists"
  ;; Here 'union-build' makes the profile's etc/ a symlink to the package's
  ;; etc/ directory, which makes it read-only.  Make sure the profile build
  ;; handles that.
  (mlet* %store-monad
      ((thing ->   (dummy-package "dummy"
                     (build-system trivial-build-system)
                     (arguments
                      `(#:guile ,%bootstrap-guile
                        #:builder
                        (let ((out (assoc-ref %outputs "out")))
                          (mkdir out)
                          (mkdir (string-append out "/etc"))
                          (call-with-output-file (string-append out "/etc/foo")
                            (lambda (port)
                              (display "foo!" port))))))))
       (entry ->   (package->manifest-entry thing))
       (drv        (profile-derivation (manifest (list entry))
                                       #:hooks '()
                                       #:locales? #f))
       (profile -> (derivation->output-path drv)))
    (mbegin %store-monad
      (built-derivations (list drv))
      (return (and (file-exists? (string-append profile "/etc/profile"))
                   (string=? (call-with-input-file
                                 (string-append profile "/etc/foo")
                               get-string-all)
                             "foo!"))))))

(test-assertm "etc/profile when etc/ is a symlink"
  ;; When etc/ is a symlink, the unsymlink code in 0.8.2 would fail
  ;; gracelessly because 'scandir' would return #f.
  (mlet* %store-monad
      ((thing ->   (dummy-package "dummy"
                     (build-system trivial-build-system)
                     (arguments
                      `(#:guile ,%bootstrap-guile
                        #:builder
                        (let ((out (assoc-ref %outputs "out")))
                          (mkdir out)
                          (mkdir (string-append out "/foo"))
                          (symlink "foo" (string-append out "/etc"))
                          (call-with-output-file (string-append out "/etc/bar")
                            (lambda (port)
                              (display "foo!" port))))))))
       (entry ->   (package->manifest-entry thing))
       (drv        (profile-derivation (manifest (list entry))
                                       #:hooks '()
                                       #:locales? #f))
       (profile -> (derivation->output-path drv)))
    (mbegin %store-monad
      (built-derivations (list drv))
      (return (and (file-exists? (string-append profile "/etc/profile"))
                   (string=? (call-with-input-file
                                 (string-append profile "/etc/bar")
                               get-string-all)
                             "foo!"))))))

(test-end "profiles")

;;; Local Variables:
;;; eval: (put 'dummy-package 'scheme-indent-function 1)
;;; End:
