;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 Jan Nieuwenhuizen <janneke@gnu.org>
;;; Copyright © 2016 Ludovic Courtès <ludo@gnu.org>
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
;;; You should have received a copy of thye GNU General Public License
;;; along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

(define-module (gnu services admin)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages base)
  #:use-module (gnu services)
  #:use-module (gnu services mcron)
  #:use-module (gnu services shepherd)
  #:use-module (guix gexp)
  #:use-module (guix packages)
  #:use-module (guix records)
  #:use-module (srfi srfi-1)
  #:export (%default-rotations
            %rotated-files
            rottlog-configuration
            rottlog-configuration?
            rottlog-service
            rottlog-service-type))

;;; Commentary:
;;;
;;; This module implements configuration of rottlog by writing
;;; /etc/rottlog/{rc,hourly|daily|weekly}.  Example usage
;;;
;;;     (mcron-service)
;;;     (service rottlog-service-type (rottlog-configuration))
;;;
;;; Code:

(define %rotated-files
  ;; Syslog files subject to rotation.
  '("/var/log/messages" "/var/log/secure" "/var/log/maillog"))

(define (syslog-rotation-config files)
  #~(string-append #$(string-join files ",")
                 " {
        sharedscripts
        postrotate
        " #$coreutils "/bin/kill -HUP $(cat /var/run/syslog.pid) 2> /dev/null
        endscript
}
"))

(define (simple-rotation-config files)
  #~(string-append #$(string-join files ",") " {
        sharedscripts
}
"))

(define %default-rotations
  `(("weekly"
     ,(computed-file "rottlog.weekly"
                     #~(call-with-output-file #$output
                         (lambda (port)
                           (display #$(syslog-rotation-config %rotated-files)
                                    port)
                           (display #$(simple-rotation-config
                                       '("/var/log/shepherd.log"
                                         "/var/log/guix-daemon.log"))
                                    port)))))))

(define (default-jobs rottlog)
  (list #~(job '(next-hour '(0))                  ;midnight
               (lambda ()
                 (system* #$(file-append rottlog "/sbin/rottlog"))))
        #~(job '(next-hour '(12))                 ;noon
               (lambda ()
                 (system* #$(file-append rottlog "/sbin/rottlog"))))))

(define-record-type* <rottlog-configuration>
  rottlog-configuration make-rottlog-configuration
  rottlog-configuration?
  (rottlog            rottlog-rottlog             ;package
                      (default rottlog))
  (rc-file            rottlog-rc-file             ;file-like
                      (default (file-append rottlog "/etc/rc")))
  (periodic-rotations rottlog-periodic-rotations  ;list of (name file) tuples
                      (default %default-rotations))
  (jobs               rottlog-jobs                ;list of <mcron-job>
                      (default #f)))

(define (rottlog-etc config)
  `(("rottlog" ,(file-union "rottlog"
                            (cons `("rc" ,(rottlog-rc-file config))
                                  (rottlog-periodic-rotations config))))))

(define (rottlog-jobs-or-default config)
  (or (rottlog-jobs config)
      (default-jobs (rottlog-rottlog config))))

(define rottlog-service-type
  (service-type
   (name 'rottlog)
   (extensions (list (service-extension etc-service-type rottlog-etc)
                     (service-extension mcron-service-type
                                        rottlog-jobs-or-default)

                     ;; Add Rottlog to the global profile so users can access
                     ;; the documentation.
                     (service-extension profile-service-type
                                        (compose list rottlog-rottlog))))))

;;; admin.scm ends here
