;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu system linux)
  #:use-module (guix store)
  #:use-module (guix records)
  #:use-module (guix derivations)
  #:use-module (guix monads)
  #:use-module (guix gexp)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module ((guix utils) #:select (%current-system))
  #:export (pam-service
            pam-entry
            pam-services->directory
            unix-pam-service
            base-pam-services))

;;; Commentary:
;;;
;;; Configuration of Linux-related things, including pluggable authentication
;;; modules (PAM).
;;;
;;; Code:

;; PAM services (see
;; <http://www.linux-pam.org/Linux-PAM-html/sag-configuration-file.html>.)
(define-record-type* <pam-service> pam-service
  make-pam-service
  pam-service?
  (name       pam-service-name)                   ; string

  ;; The four "management groups".
  (account    pam-service-account                 ; list of <pam-entry>
              (default '()))
  (auth       pam-service-auth
              (default '()))
  (password   pam-service-password
              (default '()))
  (session    pam-service-session
              (default '())))

(define-record-type* <pam-entry> pam-entry
  make-pam-entry
  pam-entry?
  (control    pam-entry-control)         ; string
  (module     pam-entry-module)          ; file name
  (arguments  pam-entry-arguments        ; list of string-valued g-expressions
              (default '())))

(define (pam-service->configuration service)
  "Return the derivation building the configuration file for SERVICE, to be
dumped in /etc/pam.d/NAME, where NAME is the name of SERVICE."
  (define (entry->gexp type entry)
    (match entry
      (($ <pam-entry> control module (arguments ...))
       #~(format #t "~a ~a ~a ~a~%"
                 #$type #$control #$module
                 (string-join (list #$@arguments))))))

  (match service
    (($ <pam-service> name account auth password session)
     (define builder
       #~(begin
           (with-output-to-file #$output
             (lambda ()
               #$@(append (map (cut entry->gexp "account" <>) account)
                          (map (cut entry->gexp "auth" <>) auth)
                          (map (cut entry->gexp "password" <>) password)
                          (map (cut entry->gexp "session" <>) session))
               #t))))

     (gexp->derivation name builder))))

(define (pam-services->directory services)
  "Return the derivation to build the configuration directory to be used as
/etc/pam.d for SERVICES."
  (mlet %store-monad
      ((names -> (map pam-service-name services))
       (files (sequence %store-monad
                        (map pam-service->configuration
                             ;; XXX: Eventually, SERVICES may be a list of
                             ;; monadic values instead of plain values.
                             services))))
    (define builder
      #~(begin
          (use-modules (ice-9 match)
                       (srfi srfi-1))

          (mkdir #$output)
          (for-each (match-lambda
                     ((name file)
                      (symlink file (string-append #$output "/" name))))

                    ;; Since <pam-service> objects cannot be compared with
                    ;; 'equal?' since they contain gexps, which contain
                    ;; closures, use 'delete-duplicates' on the build-side
                    ;; instead.  See <http://bugs.gnu.org/20037>.
                    (delete-duplicates '#$(zip names files)))))

    (gexp->derivation "pam.d" builder)))

(define %pam-other-services
  ;; The "other" PAM configuration, which denies everything (see
  ;; <http://www.linux-pam.org/Linux-PAM-html/sag-configuration-example.html>.)
  (let ((deny (pam-entry
               (control "required")
               (module "pam_deny.so"))))
    (pam-service
     (name "other")
     (account (list deny))
     (auth (list deny))
     (password (list deny))
     (session (list deny)))))

(define unix-pam-service
  (let ((unix (pam-entry
               (control "required")
               (module "pam_unix.so"))))
    (lambda* (name #:key allow-empty-passwords? motd
                   (additional-session-modules '()))
      "Return a standard Unix-style PAM service for NAME.  When
ALLOW-EMPTY-PASSWORDS? is true, allow empty passwords.  When MOTD is true, it
should be the name of a file used as the message-of-the-day."
      ;; See <http://www.linux-pam.org/Linux-PAM-html/sag-configuration-example.html>.
      (let ((name* name))
        (pam-service
         (name name*)
         (account (list unix))
         (auth (list (if allow-empty-passwords?
                         (pam-entry
                          (control "required")
                          (module "pam_unix.so")
                          (arguments '("nullok")))
                         unix)))
         (password (list (pam-entry
                          (control "required")
                          (module "pam_unix.so")
                          ;; Store SHA-512 encrypted passwords in /etc/shadow.
                          (arguments '("sha512" "shadow")))))
         (session (append
                   (if motd
                       (list unix
                             (pam-entry
                              (control "optional")
                              (module "pam_motd.so")
                              (arguments
                               (list #~(string-append "motd=" #$motd)))))
                       (list unix))
                   additional-session-modules)))))))

(define (rootok-pam-service command)
  "Return a PAM service for COMMAND such that 'root' does not need to
authenticate to run COMMAND."
  (let ((unix (pam-entry
               (control "required")
               (module "pam_unix.so"))))
    (pam-service
     (name command)
     (account (list unix))
     (auth (list (pam-entry
                  (control "sufficient")
                  (module "pam_rootok.so"))))
     (password (list unix))
     (session (list unix)))))

(define* (base-pam-services #:key allow-empty-passwords?
                            (additional-session-modules '()))
  "Return the list of basic PAM services everyone would want."
  ;; TODO: Add other Shadow programs?
  (append (list %pam-other-services)

          ;; These programs are setuid-root.
          (map (cut unix-pam-service <>
                    #:allow-empty-passwords? allow-empty-passwords?
                    #:additional-session-modules additional-session-modules)
               '("su" "passwd" "sudo"
                 "xlock" "xscreensaver"))

          ;; These programs are not setuid-root, and we want root to be able
          ;; to run them without having to authenticate (notably because
          ;; 'useradd' and 'groupadd' are run during system activation.)
          (map rootok-pam-service
               '("useradd" "userdel" "usermod"
                 "groupadd" "groupdel" "groupmod"))))

;;; linux.scm ends here
