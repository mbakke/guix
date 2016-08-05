;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 David Thompson <davet@gnu.org>
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

(define-module (gnu system linux-container)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1)
  #:use-module (guix config)
  #:use-module (guix store)
  #:use-module (guix gexp)
  #:use-module (guix derivations)
  #:use-module (guix monads)
  #:use-module (gnu build linux-container)
  #:use-module (gnu services)
  #:use-module (gnu system)
  #:use-module (gnu system file-systems)
  #:export (mapping->file-system
            system-container
            containerized-operating-system
            container-script))

(define (mapping->file-system mapping)
  "Return a file system that realizes MAPPING."
  (match mapping
    (($ <file-system-mapping> source target writable?)
     (file-system
       (mount-point target)
       (device source)
       (type "none")
       (flags (if writable?
                  '(bind-mount)
                  '(bind-mount read-only)))
       (check? #f)
       (create-mount-point? #t)))))

(define (containerized-operating-system os mappings)
  "Return an operating system based on OS for use in a Linux container
environment.  MAPPINGS is a list of <file-system-mapping> to realize in the
containerized OS."
  (define user-file-systems
    (remove (lambda (fs)
              (let ((target (file-system-mount-point fs))
                    (source (file-system-device fs)))
                (or (string=? target (%store-prefix))
                    (string=? target "/")
                    (and (string? source)
                         (string-prefix? "/dev/" source))
                    (string-prefix? "/dev" target)
                    (string-prefix? "/sys" target))))
            (operating-system-file-systems os)))

  (define (mapping->fs fs)
    (file-system (inherit (mapping->file-system fs))
      (needed-for-boot? #t)))

  (operating-system (inherit os)
    (swap-devices '()) ; disable swap
    (file-systems (append (map mapping->fs (cons %store-mapping mappings))
                          %container-file-systems
                          user-file-systems))))

(define* (container-script os #:key (mappings '()))
  "Return a derivation of a script that runs OS as a Linux container.
MAPPINGS is a list of <file-system> objects that specify the files/directories
that will be shared with the host system."
  (let* ((os           (containerized-operating-system os mappings))
         (file-systems (filter file-system-needed-for-boot?
                               (operating-system-file-systems os)))
         (specs        (map file-system->spec file-systems)))

    (mlet* %store-monad ((os-drv (operating-system-derivation
                                  os
                                  #:container? #t)))

      (define script
        (with-imported-modules '((guix config)
                                 (guix utils)
                                 (guix combinators)
                                 (guix build utils)
                                 (guix build syscalls)
                                 (guix build bournish)
                                 (gnu build file-systems)
                                 (gnu build linux-container))
          #~(begin
              (use-modules (gnu build linux-container)
                           (guix build utils))

              (call-with-container '#$specs
                (lambda ()
                  (setenv "HOME" "/root")
                  (setenv "TMPDIR" "/tmp")
                  (setenv "GUIX_NEW_SYSTEM" #$os-drv)
                  (for-each mkdir-p '("/run" "/bin" "/etc" "/home" "/var"))
                  (primitive-load (string-append #$os-drv "/boot")))
                ;; A range of 65536 uid/gids is used to cover 16 bits worth of
                ;; users and groups, which is sufficient for most cases.
                ;;
                ;; See: http://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#--private-users=
                #:host-uids 65536))))

      (gexp->script "run-container" script))))
