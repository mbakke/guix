;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Alex Kost <alezost@gmail.com>
;;; Copyright © 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu services lirc)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu packages lirc)
  #:use-module (guix gexp)
  #:use-module (guix records)
  #:use-module (ice-9 match)
  #:export (lirc-configuration
            lirc-configuation?
            lirc-service
            lirc-service-type))

;;; Commentary:
;;;
;;; LIRC service.
;;;
;;; Code:

(define-record-type* <lirc-configuration>
  lirc-configuration make-lirc-configuration
  lirc-configuation?
  (lirc          lirc-configuration-lirc          ;<package>
                 (default lirc))
  (device        lirc-configuration-device)       ;string
  (driver        lirc-configuration-driver)       ;string
  (config-file   lirc-configuration-file)         ;string | file-like object
  (extra-options lirc-configuration-options       ;list of strings
                 (default '())))

(define %lirc-activation
  #~(begin
      (use-modules (guix build utils))
      (mkdir-p "/var/run/lirc")))

(define lirc-shepherd-service
  (match-lambda
    (($ <lirc-configuration> lirc device driver config-file options)
     (list (shepherd-service
            (provision '(lircd))
            (documentation "Run the LIRC daemon.")
            (requirement '(user-processes))
            (start #~(make-forkexec-constructor
                      (list (string-append #$lirc "/sbin/lircd")
                            "--nodaemon"
                            #$@(if device
                                   #~("--device" #$device)
                                   #~())
                            #$@(if driver
                                   #~("--driver" #$driver)
                                   #~())
                            #$@(if config-file
                                   #~(#$config-file)
                                   #~())
                            #$@options)))
            (stop #~(make-kill-destructor)))))))

(define lirc-service-type
  (service-type (name 'lirc)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          lirc-shepherd-service)
                       (service-extension activation-service-type
                                          (const %lirc-activation))))))

(define* (lirc-service #:key (lirc lirc)
                       device driver config-file
                       (extra-options '()))
  "Return a service that runs @url{http://www.lirc.org,LIRC}, a daemon that
decodes infrared signals from remote controls.

The daemon will use specified @var{device}, @var{driver} and
@var{config-file} (configuration file name).

Finally, @var{extra-options} is a list of additional command-line options
passed to @command{lircd}."
  (service lirc-service-type
           (lirc-configuration
            (lirc lirc)
            (device device) (driver driver)
            (config-file config-file)
            (extra-options extra-options))))

;;; lirc.scm ends here
