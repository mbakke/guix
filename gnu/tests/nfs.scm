;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 John Darrington <jmd@gnu.org>
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

(define-module (gnu tests nfs)
  #:use-module (gnu tests)
  #:use-module (gnu system)
  #:use-module (gnu system grub)
  #:use-module (gnu system file-systems)
  #:use-module (gnu system shadow)
  #:use-module (gnu system vm)
  #:use-module (gnu services)
  #:use-module (gnu services base)
  #:use-module (gnu services nfs)
  #:use-module (gnu services networking)
  #:use-module (gnu packages onc-rpc)
  #:use-module (guix gexp)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:export (%test-nfs))

(define %base-os
  (operating-system
    (host-name "olitupmok")
    (timezone "Europe/Berlin")
    (locale "en_US.UTF-8")

    (bootloader (grub-configuration (device "/dev/sdX")))
    (file-systems %base-file-systems)
    (users %base-user-accounts)
    (packages (cons*
               rpcbind
               %base-packages))
    (services (cons*
               (service rpcbind-service-type
                        (rpcbind-configuration))
               (dhcp-client-service)
               %base-services))))

(define (run-nfs-test name socket)
  "Run a test of an OS running RPC-SERVICE, which should create SOCKET."
  (mlet* %store-monad ((os ->   (marionette-operating-system
                                 %base-os
                                 #:imported-modules '((gnu services herd)
                                                      (guix combinators))))
                       (command (system-qemu-image/shared-store-script
                                 os #:graphic? #f)))
    (define test
      (with-imported-modules '((gnu build marionette))
        #~(begin
            (use-modules (gnu build marionette)
                         (srfi srfi-64))

            (define marionette
              (make-marionette (list #$command)))

            (define (wait-for-socket file)
              ;; Wait until SOCKET  exists in the guest
              (marionette-eval
               `(let loop ((i 10))
                  (cond ((and (file-exists? ,file)
                              (eq? 'socket (stat:type (stat ,file))))
                         #t)
                        ((> i 0)
                         (sleep 1)
                         (loop (- i 1)))
                        (else
                         (error "Socket didn't show up: " ,file))))
               marionette))

            (mkdir #$output)
            (chdir #$output)

            (test-begin "rpc-daemon")

            ;; Wait for the rpcbind daemon to be up and running.
            (test-eq "RPC service running"
              'running!
              (marionette-eval
               '(begin
                  (use-modules (gnu services herd))
                  (start-service 'rpcbind-daemon)
                  'running!)
               marionette))

            ;; Check the socket file and that the service is still running.
            (test-assert "RPC socket exists"
              (and
                (wait-for-socket #$socket)
                (marionette-eval
                 '(begin
                    (use-modules (gnu services herd)
                                 (srfi srfi-1))

                    (live-service-running
                     (find (lambda (live)
                             (memq 'rpcbind-daemon
                                   (live-service-provision live)))
                           (current-services))))
                 marionette)))

            (test-assert "Probe RPC daemon"
              (marionette-eval
               '(zero? (system* "rpcinfo" "-p"))
               marionette))

            (test-end)
            (exit (= (test-runner-fail-count (test-runner-current)) 0)))))

    (gexp->derivation name test)))

(define %test-nfs
  (system-test
   (name "nfs")
   (description "Test some things related to NFS.")
   (value (run-nfs-test name "/var/run/rpcbind.sock"))))
