;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 David Thompson <davet@gnu.org>
;;; Copyright © 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 ng0 <ng0@we.make.ritual.n0.is>
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

(define-module (gnu services web)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu system shadow)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages web)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (ice-9 match)
  #:export (nginx-configuration
            nginx-configuration?
            nginx-service
            nginx-service-type))

;;; Commentary:
;;;
;;; Web services.
;;;
;;; Code:

(define-record-type* <nginx-configuration>
  nginx-configuration make-nginx-configuration
  nginx-configuration?
  (nginx         nginx-configuration-nginx)         ;<package>
  (log-directory nginx-configuration-log-directory) ;string
  (run-directory nginx-configuration-run-directory) ;string
  (file          nginx-configuration-file))         ;string | file-like

(define (default-nginx-config log-directory run-directory)
  (plain-file "nginx.conf"
              (string-append
               "user nginx nginx;\n"
               "pid " run-directory "/pid;\n"
               "error_log " log-directory "/error.log info;\n"
               "http {\n"
               "    access_log " log-directory "/access.log;\n"
               "    root /var/www;\n"
               "    server {}\n"
               "}\n"
               "events {}\n")))

(define %nginx-accounts
  (list (user-group (name "nginx") (system? #t))
        (user-account
         (name "nginx")
         (group "nginx")
         (system? #t)
         (comment "nginx server user")
         (home-directory "/var/empty")
         (shell #~(string-append #$shadow "/sbin/nologin")))))

(define nginx-activation
  (match-lambda
    (($ <nginx-configuration> nginx log-directory run-directory config-file)
     #~(begin
         (use-modules (guix build utils))

         (format #t "creating nginx log directory '~a'~%" #$log-directory)
         (mkdir-p #$log-directory)
         (format #t "creating nginx run directory '~a'~%" #$run-directory)
         (mkdir-p #$run-directory)
         ;; Check configuration file syntax.
         (system* (string-append #$nginx "/bin/nginx")
                  "-c" #$config-file "-t")))))

(define nginx-shepherd-service
  (match-lambda
    (($ <nginx-configuration> nginx log-directory run-directory config-file)
     (let* ((nginx-binary #~(string-append #$nginx "/sbin/nginx"))
            (nginx-action
             (lambda args
               #~(lambda _
                   (zero?
                    (system* #$nginx-binary "-c" #$config-file #$@args))))))

       ;; TODO: Add 'reload' action.
       (list (shepherd-service
              (provision '(nginx))
              (documentation "Run the nginx daemon.")
              (requirement '(user-processes loopback))
              (start (nginx-action "-p" run-directory))
              (stop (nginx-action "-s" "stop"))))))))

(define nginx-service-type
  (service-type (name 'nginx)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          nginx-shepherd-service)
                       (service-extension activation-service-type
                                          nginx-activation)
                       (service-extension account-service-type
                                          (const %nginx-accounts))))))

(define* (nginx-service #:key (nginx nginx)
                        (log-directory "/var/log/nginx")
                        (run-directory "/var/run/nginx")
                        (config-file
                         (default-nginx-config log-directory run-directory)))
  "Return a service that runs NGINX, the nginx web server.

The nginx daemon loads its runtime configuration from CONFIG-FILE, stores log
files in LOG-DIRECTORY, and stores temporary runtime files in RUN-DIRECTORY."
  (service nginx-service-type
           (nginx-configuration
            (nginx nginx)
            (log-directory log-directory)
            (run-directory run-directory)
            (file config-file))))
