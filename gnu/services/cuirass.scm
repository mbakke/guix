;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 Mathieu Lirzin <mthl@gnu.org>
;;; Copyright © 2016 Ludovic Courtès <ludo@gnu.org>
;;;
;;; This file is part of GNU Guix.
;;;
;;; GNU Guix is free software: you can redistribute it and/or modify
;;; it under the terms of the GNU General Public License as published by
;;; the Free Software Foundation, either version 3 of the License, or
;;; (at your option) any later version.
;;;
;;; GNU Guix is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

(define-module (gnu services cuirass)
  #:use-module (guix gexp)
  #:use-module (guix records)
  #:use-module (gnu packages admin)
  #:autoload   (gnu packages ci) (cuirass)
  #:use-module (gnu services)
  #:use-module (gnu services base)
  #:use-module (gnu services shepherd)
  #:use-module (gnu system shadow)
  #:export (<cuirass-configuration>
            cuirass-configuration
            cuirass-configuration?

            cuirass-service-type
            cuirass-service))

;;;; Commentary:
;;;
;;; This module implements a service that to run instances of Cuirass, a
;;; continuous integration tool.
;;;
;;;; Code:

(define-record-type* <cuirass-configuration>
  cuirass-configuration make-cuirass-configuration
  cuirass-configuration?
  (cuirass          cuirass-configuration-cuirass ;package
                    (default cuirass))
  (log-file         cuirass-configuration-log-file ;string
                    (default "/var/log/cuirass.log"))
  (cache-directory  cuirass-configuration-cache-directory ;string (dir-name)
                    (default "/var/cache/cuirass"))
  (user             cuirass-configuration-user ;string
                    (default "cuirass"))
  (group            cuirass-configuration-group ;string
                    (default "cuirass"))
  (interval         cuirass-configuration-interval ;integer (seconds)
                    (default 60))
  (database         cuirass-configuration-database ;string (file-name)
                    (default "/var/run/cuirass/cuirass.db"))
  (specifications   cuirass-configuration-specifications ;specification-alist
                    (default '()))
  (use-substitutes? cuirass-configuration-use-substitutes? ;boolean
                    (default #f))
  (one-shot?        cuirass-configuration-one-shot? ;boolean
                    (default #f)))

(define (cuirass-shepherd-service config)
  "Return a <shepherd-service> for the Cuirass service with CONFIG."
  (and
   (cuirass-configuration? config)
   (let ((cuirass          (cuirass-configuration-cuirass config))
         (cache-directory  (cuirass-configuration-cache-directory config))
         (log-file         (cuirass-configuration-log-file config))
         (user             (cuirass-configuration-user config))
         (group            (cuirass-configuration-group config))
         (interval         (cuirass-configuration-interval config))
         (database         (cuirass-configuration-database config))
         (specs            (cuirass-configuration-specifications config))
         (use-substitutes? (cuirass-configuration-use-substitutes? config))
         (one-shot?        (cuirass-configuration-one-shot? config)))
     (list (shepherd-service
            (documentation "Run Cuirass.")
            (provision '(cuirass))
            (requirement '(guix-daemon))
            (start #~(make-forkexec-constructor
                      (list (string-append #$cuirass "/bin/cuirass")
                            "--cache-directory" #$cache-directory
                            #$@(if (null? specs)
                                   '()
                                   (let ((str (format #f "'~S" specs)))
                                     (list "--specifications"
                                           (plain-file "specs.scm" str))))
                            "--database" #$database
                            "--interval" #$(number->string interval)
                            #$@(if use-substitutes? '("--use-substitutes") '())
                            #$@(if one-shot? '("--one-shot") '()))
                      #:user #$user
                      #:group #$group
                      #:log-file #$log-file))
            (stop #~(make-kill-destructor)))))))

(define (cuirass-account config)
  "Return the user accounts and user groups for CONFIG."
  (let ((cuirass-user  (cuirass-configuration-user config))
        (cuirass-group (cuirass-configuration-group config)))
    (list (user-group
           (name cuirass-group)
           (system? #t))
          (user-account
           (name cuirass-user)
           (group cuirass-group)
           (system? #t)
           (comment "Cuirass privilege separation user")
           (home-directory (string-append "/var/run/" cuirass-user))
           (shell #~(string-append #$shadow "/sbin/nologin"))))))

(define (cuirass-activation config)
  "Return the activation code for CONFIG."
  (let ((cache (cuirass-configuration-cache-directory config))
        (db    (dirname (cuirass-configuration-database config)))
        (user  (cuirass-configuration-user config))
        (group (cuirass-configuration-group config)))
    (with-imported-modules '((guix build utils))
      #~(begin
          (use-modules (guix build utils))

          (mkdir-p #$cache)
          (mkdir-p #$db)

          (let ((uid (passwd:uid (getpw #$user)))
                (gid (group:gid (getgr #$group))))
            (chown #$cache uid gid)
            (chown #$db uid gid))))))

(define cuirass-service-type
  (service-type
   (name 'cuirass)
   (extensions
    (list
     (service-extension profile-service-type      ;for 'info cuirass'
                        (compose list cuirass-configuration-cuirass))
     (service-extension activation-service-type cuirass-activation)
     (service-extension shepherd-root-service-type cuirass-shepherd-service)
     (service-extension account-service-type cuirass-account)))))

(define* (cuirass-service #:key (config (cuirass-configuration)))
  "Return a service that runs cuirass according to CONFIG."
  (service cuirass-service-type config))
