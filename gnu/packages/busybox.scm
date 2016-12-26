;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 John Darrington <jmd@gnu.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
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

(define-module (gnu packages busybox)
  #:use-module (guix licenses)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages zip))

(define-public busybox
  (package
    (name "busybox")
    (version "1.26.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://www.busybox.net/downloads/" name "-"
                    version ".tar.bz2"))
              (sha256
               (base32
                "0k0g3hk58m99c2sfq97ngnixb2rv2wzyhv3z00lxaw78bqvjglis"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda _ (zero? (system* "make" "defconfig"))))
         (replace 'check
           (lambda _
           (substitute* '("testsuite/du/du-s-works"
                           "testsuite/du/du-works")
               (("/bin") "/etc"))  ; there is no /bin but there is a /etc

           ;; There is no /usr/bin or /bin - replace it with /gnu/store
           (substitute* "testsuite/cpio.tests"
               (("/usr/bin") (%store-directory))
               (("usr") (car (filter (negate string-null?)
                                       (string-split (%store-directory) #\/)))))

           (substitute* "testsuite/date/date-works-1"
               (("/bin/date") (which "date")))

           ;; The pidof tests assume that pid 1 is called "init" but that is not
           ;; true in guix build environment
           (substitute* "testsuite/pidof.tests"
               (("-s init") "-s $(cat /proc/1/comm)"))

           ;; This test cannot possibly pass.
           ;; It is trying to test that "which ls" returns "/bin/ls" when PATH is not set.
           ;; However, this relies on /bin/ls existing.  Which it does not in guix.
           (delete-file "testsuite/which/which-uses-default-path")
           (rmdir "testsuite/which")

           (zero? (system* "make"
                           ;; "V=1"
                           "SKIP_KNOWN_BUGS=1"
                           "SKIP_INTERNET_TESTS=1"
                           "check"))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (zero?
                (system* "make"
                         (string-append "CONFIG_PREFIX=" out)
                         "install"))))))))
    (native-inputs `(("perl" ,perl) ; needed to generate the man pages (pod2man)
                     ;; The following are needed by the tests.
                     ("inetutils" ,inetutils)
                     ("which" ,(@ (gnu packages base) which))
                     ("zip" ,zip)))
    (synopsis "Many common UNIX utilities in a single executable")
    (description "BusyBox combines tiny versions of many common UNIX utilities
into a single small executable.  It provides a fairly complete environment for
any small or embedded system.")
    (home-page "https://www.busybox.net")
    ;; Some files are gplv2+
    (license gpl2)))
