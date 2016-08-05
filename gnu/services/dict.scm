;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 Sou Bunnbu <iyzsong@gmail.com>
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
;;; You should have received a copy of the GNU General Public License
;;; along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

(define-module (gnu services dict)
  #:use-module (guix gexp)
  #:use-module (guix records)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu system shadow)
  #:use-module ((gnu packages admin) #:select (shadow))
  #:use-module (gnu packages dico)
  #:use-module (gnu packages dictionaries)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)
  #:export (dicod-service
            dicod-service-type
            dicod-configuration
            dicod-database
            %dicod-database:gcide))


;;;
;;; GNU Dico.
;;;

(define-record-type* <dicod-configuration>
  dicod-configuration make-dicod-configuration
  dicod-configuration?
  (dico        dicod-configuration-dico       (default dico))
  (interfaces  dicod-configuration-interfaces     ;list of strings
               (default '("localhost")))
  (databases   dicod-configuration-databases
               ;; list of <dicod-database>
               (default (list %dicod-database:gcide))))

(define-record-type* <dicod-database>
  dicod-database make-dicod-database
  dicod-database?
  (name        dicod-database-name)
  (module      dicod-database-module)
  (options     dicod-database-options        (default '())))

(define %dicod-database:gcide
  (dicod-database
   (name "gcide")
   (module "gcide")
   (options (list #~(string-append "dbdir=" #$gcide "/share/gcide")
                  "idxdir=/var/run/dicod"))))

(define %dicod-accounts
  (list (user-group
         (name "dicod")
         (system? #t))
        (user-account
         (name "dicod")
         (group "dicod")
         (system? #t)
         (home-directory "/var/empty")
         (shell #~(string-append #$shadow "/sbin/nologin")))))

(define (dicod-configuration-file config)
  (define database->text
    (match-lambda
      (($ <dicod-database> name module options)
       `("
load-module " ,module ";
database {
   name \"" ,name "\";
   handler \"" ,module
   (string-join (list ,@options) " " 'prefix) "\";
}\n"))))

  (define configuration->text
    (match-lambda
      (($ <dicod-configuration> dico (interfaces ...) databases)
       (append `("listen ("
                 ,(string-join interfaces ", ") ");\n")
               (append-map database->text databases)))))

  (apply mixed-text-file "dicod.conf" (configuration->text config)))

(define %dicod-activation
  #~(begin
      (use-modules (guix build utils))
      (let ((user   (getpwnam "dicod"))
            (rundir "/var/run/dicod"))
        (mkdir-p rundir)
        (chown rundir (passwd:uid user) (passwd:gid user)))))

(define (dicod-shepherd-service config)
  (list (shepherd-service
         (provision '(dicod))
         (documentation "Run the dicod daemon.")
         (start #~(make-forkexec-constructor
                   (list (string-append #$dico "/bin/dicod") "--foreground"
                         (string-append
                          "--config=" #$(dicod-configuration-file config)))
                   #:user "dicod" #:group "dicod"))
         (stop #~(make-kill-destructor)))))

(define dicod-service-type
  (service-type
   (name 'dict)
   (extensions
    (list (service-extension account-service-type
                             (const %dicod-accounts))
          (service-extension activation-service-type
                             (const %dicod-activation))
          (service-extension shepherd-root-service-type
                             dicod-shepherd-service)))))

(define* (dicod-service #:key (config (dicod-configuration)))
  "Return a service that runs the @command{dicod} daemon, an implementation
of DICT server (@pxref{Dicod,,, dico, GNU Dico Manual}).

The optional @var{config} argument specifies the configuration for
@command{dicod}, which should be a @code{<dicod-configuration>} object, by
default it serves the GNU Collaborative International Dictonary of English.

You can add @command{open localhost} to your @file{~/.dico} file to make
@code{localhost} the default server for @command{dico}
client (@pxref{Initialization File,,, dico, GNU Dico Manual})."
  (service dicod-service-type config))
