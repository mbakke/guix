;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2020, 2022 Marius Bakke <marius@gnu.org>
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

(define-module (gnu services ganeti)
  #:use-module (gnu packages virtualization)
  #:use-module (gnu services)
  #:use-module (gnu services mcron)
  #:use-module (gnu services shepherd)
  #:use-module (guix gexp)
  #:use-module (guix records)

  #:use-module (srfi srfi-1)
  #:use-module (ice-9 match)

  #:export (ganeti-noded-configuration
            ganeti-noded-configuration?
            ganeti-noded-configuration-ganeti
            ganeti-noded-configuration-port
            ganeti-noded-configuration-address
            ganeti-noded-configuration-interface
            ganeti-noded-configuration-max-clients
            ganeti-noded-configuration-ssl?
            ganeti-noded-configuration-ssl-key
            ganeti-noded-configuration-ssl-cert
            ganeti-noded-configuration-debug?
            ganeti-noded-service-type

            ganeti-confd-configuration
            ganeti-confd-configuration?
            ganeti-confd-configuration-ganeti
            ganeti-confd-configuration-port
            ganeti-confd-configuration-address
            ganeti-confd-configuration-debug
            ganeti-confd-service-type

            ganeti-wconfd-configuration
            ganeti-wconfd-configuration?
            ganeti-wconfd-configuration-ganeti
            ganeti-wconfd-configuration-no-voting?
            ganeti-wconfd-configuration-debug?
            ganeti-wconfd-service-type

            ganeti-luxid-configuration
            ganeti-luxid-configuration?
            ganeti-luxid-configuration-ganeti
            ganeti-luxid-configuration-no-voting?
            ganeti-luxid-configuration-debug?
            ganeti-luxid-service-type

            ganeti-rapi-configuration
            ganeti-rapi-configuration?
            ganeti-rapi-configuration-ganeti
            ganeti-rapi-configuration-require-authentication?
            ganeti-rapi-configuration-port
            ganeti-rapi-configuration-address
            ganeti-rapi-configuration-interface
            ganeti-rapi-configuration-max-clients
            ganeti-rapi-configuration-ssl?
            ganeti-rapi-configuration-ssl-key
            ganeti-rapi-configuration-ssl-cert
            ganeti-rapi-configuration-debug?
            ganeti-rapi-service-type

            ganeti-kvmd-configuration
            ganeti-kvmd-configuration?
            ganeti-kvmd-configuration-ganeti
            ganeti-kvmd-configuration-debug?
            ganeti-kvmd-service-type

            ganeti-mond-configuration
            ganeti-mond-configuration?
            ganeti-mond-configuration-ganeti
            ganeti-mond-configuration-port
            ganeti-mond-configuration-address
            ganeti-mond-configuration-debug?
            ganeti-mond-service-type

            ganeti-metad-configuration
            ganeti-metad-configuration?
            ganeti-metad-configuration-ganeti
            ganeti-metad-configuration-port
            ganeti-metad-configuration-address
            ganeti-metad-configuration-debug?
            ganeti-metad-service-type

            ganeti-watcher-configuration
            ganeti-watcher-configuration?
            ganeti-watcher-configuration-ganeti
            ganeti-watcher-configuration-schedule
            ganeti-watcher-configuration-rapi-ip
            ganeti-watcher-configuration-job-age
            ganeti-watcher-configuration-verify-disks?
            ganeti-watcher-configuration-debug?
            ganeti-watcher-service-type

            ganeti-cleaner-configuration
            ganeti-cleaner-configuration?
            ganeti-cleaner-configuration-ganeti
            ganeti-cleaner-configuration-master-schedule
            ganeti-cleaner-configuration-node-schedule
            ganeti-cleaner-service-type

            ganeti-os
            ganeti-os?
            ganeti-os-name
            ganeti-os-extension
            ganeti-os-variants

            ganeti-os-variant
            ganeti-os-variant?
            ganeti-os-variant-name
            ganeti-os-variant-configuration

            %debootstrap-interfaces-hook
            %debootstrap-grub-hook
            %default-debootstrap-hooks
            %default-debootstrap-extra-pkgs
            debootstrap-configuration
            debootstrap-configuration?
            debootstrap-configuration-hooks
            debootstrap-configuration-proxy
            debootstrap-configuration-mirror
            debootstrap-configuration-arch
            debootstrap-configuration-suite
            debootstrap-configuration-extra-pkgs
            debootstrap-configuration-components
            debootstrap-configuration-generate-cache?
            debootstrap-configuration-clean-cache
            debootstrap-configuration-partition-style
            debootstrap-configuration-partition-alignment

            debootstrap-variant
            debootstrap-os
            %default-debootstrap-variants

            guix-variant
            guix-os
            %default-guix-variants

            %default-ganeti-os

            ganeti-configuration
            ganeti-configuration?
            ganeti-configuration-noded-configuration
            ganeti-configuration-confd-configuration
            ganeti-configuration-wconfd-configuration
            ganeti-configuration-luxid-configuration
            ganeti-configuration-rapi-configuration
            ganeti-configuration-kvmd-configuration
            ganeti-configuration-mond-configuration
            ganeti-configuration-metad-configuration
            ganeti-configuration-watcher-configuration
            ganeti-configuration-cleaner-configuration
            ganeti-configuration-file-storage-paths
            ganeti-configuration-os
            ganeti-service-type))

;;;
;;; Service definitions for running a Ganeti cluster.
;;;
;;; Planned improvements: run daemons (except ganeti-noded) under unprivileged
;;; user accounts and/or containers.  The account names must match the ones
;;; given to Ganetis configure script.  metad needs "setcap" or root in order
;;; to bind on port 80.

;; Set PATH so the various daemons are able to find the 'ip' executable, LVM,
;; Ceph, Gluster, etc, without having to add absolute references to everything.
(define %default-ganeti-environment-variables
  (list (string-append "PATH="
                       (string-join '("/run/setuid-programs"
                                      "/run/current-system/profile/sbin"
                                      "/run/current-system/profile/bin")
                                    ":"))))

(define-record-type* <ganeti-noded-configuration>
  ganeti-noded-configuration make-ganeti-noded-configuration
  ganeti-noded-configuration?
  (ganeti      ganeti-noded-configuration-ganeti        ;file-like
               (default ganeti))
  (port        ganeti-noded-configuration-port          ;integer
               (default 1811))
  (address     ganeti-noded-configuration-address       ;string
               (default "0.0.0.0"))
  (interface   ganeti-noded-configuration-interface     ;string | #f
               (default #f))
  (max-clients ganeti-noded-configuration-max-clients   ;integer
               (default 20))
  (ssl?        ganeti-noded-configuration-ssl?          ;Boolean
               (default #t))
  (ssl-key     ganeti-noded-configuration-ssl-key       ;string
               (default "/var/lib/ganeti/server.pem"))
  (ssl-cert    ganeti-noded-configuration-ssl-cert      ;string
               (default "/var/lib/ganeti/server.pem"))
  (debug?      ganeti-noded-configuration-debug?        ;Boolean
               (default #f)))

(define ganeti-noded-service
  (match-lambda
    (($ <ganeti-noded-configuration> ganeti port address interface max-clients
                                     ssl? ssl-key ssl-cert debug?)
     (list (shepherd-service
            (documentation "Run the Ganeti node daemon.")
            (provision '(ganeti-noded))
            (requirement '(user-processes networking))

            ;; If the daemon stops, it is probably for a good reason;
            ;; otherwise ganeti-watcher will restart it for us anyway.
            (respawn? #f)

            (start #~(make-forkexec-constructor
                      (list #$(file-append ganeti "/sbin/ganeti-noded")
                            #$(string-append "--port=" (number->string port))
                            #$(string-append "--bind=" address)
                            #$@(if interface
                                   #~((string-append "--interface=" #$interface))
                                   #~())
                            #$(string-append "--max-clients="
                                             (number->string max-clients))
                            #$@(if ssl?
                                   #~((string-append "--ssl-key=" #$ssl-key)
                                      (string-append "--ssl-cert=" #$ssl-cert))
                                   #~("--no-ssl"))
                            #$@(if debug?
                                   #~("--debug")
                                   #~()))
                      #:environment-variables
                      '#$%default-ganeti-environment-variables
                      #:pid-file "/var/run/ganeti/ganeti-noded.pid"))
            (stop #~(make-kill-destructor)))))))

(define ganeti-noded-service-type
  (service-type (name 'ganeti-noded)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          ganeti-noded-service)))
                (default-value (ganeti-noded-configuration))
                (description
                 "@command{ganeti-noded} is the daemon which is responsible
for the node functions in the Ganeti system.")))

(define-record-type* <ganeti-confd-configuration>
  ganeti-confd-configuration make-ganeti-confd-configuration
  ganeti-confd-configuration?
  (ganeti      ganeti-confd-configuration-ganeti        ;file-like
               (default ganeti))
  (port        ganeti-confd-configuration-port          ;integer
               (default 1814))
  (address     ganeti-confd-configuration-address       ;string
               (default "0.0.0.0"))
  (debug?      ganeti-confd-configuration-debug?        ;Boolean
               (default #f)))

(define ganeti-confd-service
  (match-lambda
    (($ <ganeti-confd-configuration> ganeti port address debug?)
     (list (shepherd-service
            (documentation "Run the Ganeti confd daemon.")
            (provision '(ganeti-confd))
            (requirement '(user-processes networking))
            (respawn? #f)
            (start #~(make-forkexec-constructor
                      (list #$(file-append ganeti "/sbin/ganeti-confd")
                            #$(string-append "--port=" (number->string port))
                            #$(string-append "--bind=" address)
                            #$@(if debug?
                                   #~("--debug")
                                   #~()))
                      #:environment-variables
                      '#$%default-ganeti-environment-variables
                      #:pid-file "/var/run/ganeti/ganeti-confd.pid"))
            (stop #~(make-kill-destructor)))))))

(define ganeti-confd-service-type
  (service-type (name 'ganeti-confd)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          ganeti-confd-service)))
                (default-value (ganeti-confd-configuration))
                (description
                 "@command{ganeti-confd} is a daemon used to answer queries
related to the configuration of a Ganeti cluster.")))

(define-record-type* <ganeti-wconfd-configuration>
  ganeti-wconfd-configuration make-ganeti-wconfd-configuration
  ganeti-wconfd-configuration?
  (ganeti      ganeti-wconfd-configuration-ganeti       ;file-like
               (default ganeti))
  (no-voting?  ganeti-wconfd-configuration-no-voting?   ;Boolean
               (default #f))
  (debug?      ganeti-wconfd-configuration-debug?       ;Boolean
               (default #f)))

;; If this file exists, the wconfd daemon will be forcefully started even on
;; non-master nodes.  It is used to accommodate a master-failover scenario.
(define %wconfd-force-node-hint
  "/var/lib/ganeti/guix_wconfd_force_node_hint")

(define (wconfd-wrapper ganeti args)
  ;; Wrapper for the wconfd daemon that looks for the force-node hint.
  (program-file
   "wconfd-wrapper"
   #~(begin
       (let ((wconfd #$(file-append ganeti "/sbin/ganeti-wconfd"))
             (force-node? (file-exists? #$%wconfd-force-node-hint)))
         (if force-node?
             (execl wconfd wconfd "--force-node" "--no-voting" "--yes-do-it" #$@args)
             (execl wconfd wconfd #$@args))))))

(define shepherd-wconfd-force-start-action
  ;; Shepherd action to create the force-node hint and start wconfd.
  (shepherd-action
   (name 'force-start)
   (documentation
    "Forcefully start wconfd even on non-master nodes (dangerous!).")
   (procedure #~(lambda _
                  (format #t "Forcefully starting the wconfd daemon...~%")
                  (action 'ganeti-wconfd 'enable)
                  (dynamic-wind
                    (lambda ()
                      (false-if-exception
                       (call-with-output-file #$%wconfd-force-node-hint
                         (lambda (port)
                           (const #t)))))
                    (lambda ()
                      (action 'ganeti-wconfd 'restart))
                    (lambda ()
                      (delete-file #$%wconfd-force-node-hint)))
                    #t))))

(define ganeti-wconfd-service
  (match-lambda
    (($ <ganeti-wconfd-configuration> ganeti no-voting? debug?)
     (list (shepherd-service
            (documentation "Run the Ganeti wconfd daemon.")
            (provision '(ganeti-wconfd))
            (requirement '(user-processes))

            ;; Shepherd action to support a master-failover scenario.  It is
            ;; automatically invoked during 'gnt-cluster master-failover' (see
            ;; related Ganeti patch) and not intended for interactive use.
            (actions (list shepherd-wconfd-force-start-action))

            ;; wconfd will disable itself when not running on the master
            ;; node.  Don't attempt to restart it.
            (respawn? #f)

            (start
             #~(make-forkexec-constructor
                (list #$(wconfd-wrapper ganeti
                                        (append
                                         (if no-voting?
                                             '("--no-voting" "--yes-do-it")
                                             '())
                                         (if debug?
                                             '("--debug")
                                             '()))))
                #:environment-variables
                '#$%default-ganeti-environment-variables
                #:pid-file "/var/run/ganeti/ganeti-wconfd.pid"))
            (stop #~(make-kill-destructor)))))))

(define ganeti-wconfd-service-type
  (service-type (name 'ganeti-wconfd)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          ganeti-wconfd-service)))
                (default-value (ganeti-wconfd-configuration))
                (description
                 "@command{ganeti-wconfd} is the daemon that has authoritative
knowledge about the configuration and is the only entity that can accept changes
to it.  All jobs that need to modify the configuration will do so by sending
appropriate requests to this daemon.")))

(define-record-type* <ganeti-luxid-configuration>
  ganeti-luxid-configuration make-ganeti-luxid-configuration
  ganeti-luxid-configuration?
  (ganeti      ganeti-luxid-configuration-ganeti        ;file-like
               (default ganeti))
  (no-voting?  ganeti-luxid-configuration-no-voting?    ;Boolean
               (default #f))
  (debug?      ganeti-luxid-configuration-debug?        ;Boolean
               (default #f)))

(define ganeti-luxid-service
  (match-lambda
    (($ <ganeti-luxid-configuration> ganeti no-voting? debug?)
     (list (shepherd-service
            (documentation "Run the Ganeti LUXI daemon.")
            (provision '(ganeti-luxid))
            (requirement '(user-processes))

            ;; This service will automatically disable itself when not
            ;; running on the master node.  Don't attempt to restart it.
            (respawn? #f)

            (start #~(make-forkexec-constructor
                      (list #$(file-append ganeti "/sbin/ganeti-luxid")
                            #$@(if no-voting?
                                   #~("--no-voting" "--yes-do-it")
                                   #~())
                            #$@(if debug?
                                   #~("--debug")
                                   #~()))
                      #:environment-variables
                      '#$%default-ganeti-environment-variables
                      #:pid-file "/var/run/ganeti/ganeti-luxid.pid"))
            (stop #~(make-kill-destructor)))))))

(define ganeti-luxid-service-type
  (service-type (name 'ganeti-luxid)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          ganeti-luxid-service)))
                (default-value (ganeti-luxid-configuration))
                (description
                 "@command{ganeti-luxid} is a daemon used to answer queries
related to the configuration and the current live state of a Ganeti cluster.
Additionally, it is the authoritative daemon for the Ganeti job queue.  Jobs can
be submitted via this daemon and it schedules and starts them.")))

(define-record-type* <ganeti-rapi-configuration>
  ganeti-rapi-configuration make-ganeti-rapi-configuration
  ganeti-rapi-configuration?
  (ganeti      ganeti-rapi-configuration-ganeti         ;file-like
               (default ganeti))
  (require-authentication?
   ganeti-rapi-configuration-require-authentication?    ;Boolean
   (default #f))
  (port        ganeti-rapi-configuration-port           ;integer
               (default 5080))
  (address     ganeti-rapi-configuration-address        ;string
               (default "0.0.0.0"))
  (interface   ganeti-rapi-configuration-interface      ;string | #f
               (default #f))
  (max-clients ganeti-rapi-configuration-max-clients    ;integer
               (default 20))
  (ssl?        ganeti-rapi-configuration-ssl?           ;Boolean
               (default #t))
  (ssl-key     ganeti-rapi-configuration-ssl-key        ;string
               (default "/var/lib/ganeti/server.pem"))
  (ssl-cert    ganeti-rapi-configuration-ssl-cert       ;string
               (default "/var/lib/ganeti/server.pem"))
  (debug?      ganeti-rapi-configuration-debug?         ;Boolean
               (default #f)))

(define ganeti-rapi-service
  (match-lambda
    (($ <ganeti-rapi-configuration> ganeti require-authentication? port address
                                    interface max-clients ssl? ssl-key ssl-cert
                                    debug?)
     (list (shepherd-service
            (documentation "Run the Ganeti RAPI daemon.")
            (provision '(ganeti-rapi))
            (requirement '(user-processes networking))

            ;; This service will automatically disable itself when not
            ;; running on the master node.  Don't attempt to restart it.
            (respawn? #f)

            (start #~(make-forkexec-constructor
                      (list #$(file-append ganeti "/sbin/ganeti-rapi")
                            #$@(if require-authentication?
                                   #~("--require-authentication")
                                   #~())
                            #$(string-append "--port=" (number->string port))
                            #$(string-append "--bind=" address)
                            #$@(if interface
                                   #~((string-append "--interface=" #$interface))
                                   #~())
                            #$(string-append "--max-clients="
                                             (number->string max-clients))
                            #$@(if ssl?
                                   #~((string-append "--ssl-key=" #$ssl-key)
                                      (string-append "--ssl-cert=" #$ssl-cert))
                                   #~("--no-ssl"))
                            #$@(if debug?
                                   #~("--debug")
                                   #~()))
                      #:environment-variables
                      '#$%default-ganeti-environment-variables
                      #:pid-file "/var/run/ganeti/ganeti-rapi.pid"))
            (stop #~(make-kill-destructor)))))))

(define ganeti-rapi-service-type
  (service-type (name 'ganeti-rapi)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          ganeti-rapi-service)))
                (default-value (ganeti-rapi-configuration))
                (description
                 "@command{ganeti-rapi} is the daemon providing a remote API
for Ganeti clusters.")))

(define-record-type* <ganeti-kvmd-configuration>
  ganeti-kvmd-configuration make-ganeti-kvmd-configuration
  ganeti-kvmd-configuration?
  (ganeti      ganeti-kvmd-configuration-ganeti         ;file-like
               (default ganeti))
  (debug?      ganeti-kvmd-configuration-debug?         ;Boolean
               (default #f)))

(define ganeti-kvmd-service
  (match-lambda
    (($ <ganeti-kvmd-configuration> ganeti debug?)
     (list (shepherd-service
            (documentation "Run the Ganeti KVM daemon.")
            (provision '(ganeti-kvmd))
            (requirement '(user-processes))

            ;; This service will automatically disable itself when not
            ;; needed.  Don't attempt to restart it.
            (respawn? #f)

            (start #~(make-forkexec-constructor
                      (list #$(file-append ganeti "/sbin/ganeti-kvmd")
                            #$@(if debug?
                                   #~("--debug")
                                   #~()))
                      #:environment-variables
                      '#$%default-ganeti-environment-variables
                      #:pid-file "/var/run/ganeti/ganeti-kvmd.pid"))
            (stop #~(make-kill-destructor)))))))

(define ganeti-kvmd-service-type
  (service-type (name 'ganeti-kvmd)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          ganeti-kvmd-service)))
                (default-value (ganeti-kvmd-configuration))
                (description
                 "@command{ganeti-kvmd} is responsible for determining whether
a given KVM instance was shutdown by an administrator or a user.

The KVM daemon monitors, using @code{inotify}, KVM instances through their QMP
sockets, which are provided by KVM.  Using the QMP sockets, the KVM daemon
listens for particular shutdown, powerdown, and stop events which will determine
if a given instance was shutdown by the user or Ganeti, and this result is
communicated to Ganeti via a special file in the file system.")))

(define-record-type* <ganeti-mond-configuration>
  ganeti-mond-configuration make-ganeti-mond-configuration
  ganeti-mond-configuration?
  (ganeti      ganeti-mond-configuration-ganeti         ;file-like
               (default ganeti))
  (port        ganeti-mond-configuration-port           ;integer
               (default 1815))
  (address     ganeti-mond-configuration-address        ;string
               (default "0.0.0.0"))
  (debug?      ganeti-mond-configuration-debug?         ;Boolean
               (default #f)))

(define ganeti-mond-service
  (match-lambda
    (($ <ganeti-mond-configuration> ganeti port address debug?)
     (list (shepherd-service
            (documentation "Run the Ganeti monitoring daemon.")
            (provision '(ganeti-mond))
            (requirement '(user-processes networking))
            (respawn? #f)
            (start #~(make-forkexec-constructor
                      (list #$(file-append ganeti "/sbin/ganeti-mond")
                            #$(string-append "--port=" (number->string port))
                            #$(string-append "--bind=" address)
                            #$@(if debug?
                                   #~("--debug")
                                   #~()))
                      #:pid-file "/var/run/ganeti/ganeti-mond.pid"))
            (stop #~(make-kill-destructor)))))))

(define ganeti-mond-service-type
  (service-type (name 'ganeti-mond)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          ganeti-mond-service)))
                (default-value (ganeti-mond-configuration))
                (description
                 "@command{ganeti-mond} is a daemon providing monitoring
functionality.  It is responsible for running the data collectors and to
provide the collected information through a HTTP interface.")))

(define-record-type* <ganeti-metad-configuration>
  ganeti-metad-configuration make-ganeti-metad-configuration
  ganeti-metad-configuration?
  (ganeti      ganeti-metad-configuration-ganeti        ;file-like
               (default ganeti))
  (port        ganeti-metad-configuration-port          ;integer
               (default 80))
  (address     ganeti-metad-configuration-address       ;string | #f
               (default #f))
  (debug?      ganeti-metad-configuration-debug?        ;Boolean
               (default #f)))

(define ganeti-metad-service
  (match-lambda
    (($ <ganeti-metad-configuration> ganeti port address debug?)
     (list (shepherd-service
            (documentation "Run the Ganeti metadata daemon.")
            (provision '(ganeti-metad))
            (requirement '(user-processes networking))

            ;; This service is started on demand.
            (auto-start? #f)
            (respawn? #f)

            (start #~(make-forkexec-constructor
                      (list #$(file-append ganeti "/sbin/ganeti-metad")
                            #$(string-append "--port=" (number->string port))
                            #$@(if address
                                   #~((string-append "--bind=" #$address))
                                   #~())
                            #$@(if debug?
                                   #~("--debug")
                                   #~()))
                      #:pid-file "/var/run/ganeti/ganeti-metad.pid"))
            (stop #~(make-kill-destructor)))))))

(define ganeti-metad-service-type
  (service-type (name 'ganeti-metad)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          ganeti-metad-service)))
                (default-value (ganeti-metad-configuration))
                (description
                 "@command{ganeti-metad} is a daemon that can be used to pass
information to OS install scripts or instances.")))

(define-record-type* <ganeti-watcher-configuration>
  ganeti-watcher-configuration make-ganeti-watcher-configuration
  ganeti-watcher-configuration?
  (ganeti        ganeti-watcher-configuration-ganeti        ;file-like
                 (default ganeti))
  (schedule      ganeti-watcher-configuration-schedule      ;list | string
                 (default '(next-second-from
                            ;; Run every five minutes.
                            (next-minute (range 0 60 5)))))
  (rapi-ip       ganeti-watcher-configuration-rapi-ip       ;#f | string
                 (default #f))
  (job-age       ganeti-watcher-configuration-job-age       ;integer
                 (default (* 6 3600)))
  (verify-disks? ganeti-watcher-configuration-verify-disks? ;Boolean
                 (default #t))
  (debug?        ganeti-watcher-configuration-debug?        ;Boolean
                 (default #f)))

(define ganeti-watcher-command
  (match-lambda
    (($ <ganeti-watcher-configuration> ganeti _ rapi-ip job-age verify-disks?
                                       debug?)
     #~(lambda ()
         (system* #$(file-append ganeti "/sbin/ganeti-watcher")
                  #$@(if rapi-ip
                         #~((string-append "--rapi-ip=" #$rapi-ip))
                         #~())
                  #$(string-append "--job-age=" (number->string job-age))
                  #$@(if verify-disks?
                         #~()
                         #~("--no-verify-disks"))
                  #$@(if debug?
                         #~("--debug")
                         #~()))))))

(define (ganeti-watcher-jobs config)
  (match config
    (($ <ganeti-watcher-configuration> _ schedule)
     (list
      #~(job #$@(match schedule
                  ((? string?)
                   #~(#$schedule))
                  ((? list?)
                   #~('#$schedule)))
             #$(ganeti-watcher-command config))))))

(define ganeti-watcher-service-type
  (service-type (name 'ganeti-watcher)
                (extensions
                 (list (service-extension mcron-service-type
                                          ganeti-watcher-jobs)))
                (default-value (ganeti-watcher-configuration))
                (description
                 "@command{ganeti-watcher} is a periodically run script that
performs a number of maintenance actions on the cluster.  It will automatically
restart instances that are marked as ERROR_down, i.e., instances that should be
running, but are not; and it will also try to repair DRBD links in case a
secondary node has rebooted.  In addition it is responsible for archiving old
cluster jobs, and it will restart any down Ganeti daemons that are appropriate
for the current node.  If the cluster parameter @code{maintain_node_health} is
enabled, the watcher will also shutdown instances and DRBD devices if the node
is declared offline by known master candidates.")))

(define-record-type* <ganeti-cleaner-configuration>
  ganeti-cleaner-configuration make-ganeti-cleaner-configuration
  ganeti-cleaner-configuration?
  (ganeti          ganeti-cleaner-configuration-ganeti          ;file-like
                   (default ganeti))
  (master-schedule ganeti-cleaner-configuration-master-schedule ;list | string
                   ;; Run the master cleaner at 01:45 every day.
                   (default "45 1 * * *"))
  (node-schedule ganeti-cleaner-configuration-node-schedule     ;list | string
                   ;; Run the node cleaner at 02:45 every day.
                   (default "45 2 * * *")))

(define ganeti-cleaner-jobs
  (match-lambda
    (($ <ganeti-cleaner-configuration> ganeti master-schedule node-schedule)
     (list
      #~(job #$@(match master-schedule
                  ((? string?)
                   #~(#$master-schedule))
                  ((? list?)
                   #~('#$master-schedule)))
             (lambda ()
              (system* #$(file-append ganeti "/sbin/ganeti-cleaner")
                       "master")))
      #~(job #$@(match node-schedule
                  ((? string?)
                   #~(#$node-schedule))
                  ((? list?)
                   #~('#$node-schedule)))
             (lambda ()
               (system* #$(file-append ganeti "/sbin/ganeti-cleaner")
                        "node")))))))

(define ganeti-cleaner-service-type
  (service-type (name 'ganeti-cleaner)
                (extensions
                 (list (service-extension mcron-service-type
                                          ganeti-cleaner-jobs)))
                (default-value (ganeti-cleaner-configuration))
                (description
                 "@command{ganeti-cleaner} is a script that removes old files
from the cluster.  When called with @code{node} as argument it removes expired
X509 certificates and keys from @file{/var/run/ganeti/crypto}, as well as
outdated @command{ganeti-watcher} information.

When called with @code{master} as argument, it instead removes files older
than 21 days from @file{/var/lib/ganeti/queue/archive}.")))

(define-record-type* <ganeti-configuration>
  ganeti-configuration make-ganeti-configuration
  ganeti-configuration?
  (ganeti                 ganeti-configuration-ganeti
                          (default ganeti))
  (noded-configuration    ganeti-configuration-noded-configuration
                          (default (ganeti-noded-configuration)))
  (confd-configuration    ganeti-configuration-confd-configuration
                          (default (ganeti-confd-configuration)))
  (wconfd-configuration   ganeti-configuration-wconfd-configuration
                          (default (ganeti-wconfd-configuration)))
  (luxid-configuration    ganeti-configuration-luxid-configuration
                          (default (ganeti-luxid-configuration)))
  (rapi-configuration     ganeti-configuration-rapi-configuration
                          (default (ganeti-rapi-configuration)))
  (kvmd-configuration     ganeti-configuration-kvmd-configuration
                          (default (ganeti-kvmd-configuration)))
  (mond-configuration     ganeti-configuration-mond-configuration
                          (default (ganeti-mond-configuration)))
  (metad-configuration    ganeti-configuration-metad-configuration
                          (default (ganeti-metad-configuration)))
  (watcher-configuration  ganeti-configuration-watcher-configuration
                          (default (ganeti-watcher-configuration)))
  (cleaner-configuration  ganeti-configuration-cleaner-configuration
                          (default (ganeti-cleaner-configuration)))
  (file-storage-paths     ganeti-configuration-file-storage-paths ;list of strings | gexp
                          (default '()))
  (hooks                  ganeti-configuration-hooks  ;<file-like> | #f
                          (default #f))
  (os                     ganeti-configuration-os  ;list of <ganeti-os>
                          (default '())))

(define (ganeti-activation config)
  (with-imported-modules '((guix build utils))
    #~(begin
        (use-modules (guix build utils))
        (for-each mkdir-p
                  '("/var/log/ganeti"
                    "/var/log/ganeti/kvm"
                    "/var/log/ganeti/os"
                    "/var/lib/ganeti/rapi"
                    "/var/lib/ganeti/queue"
                    "/var/lib/ganeti/queue/archive"
                    "/var/run/ganeti/bdev-cache"
                    "/var/run/ganeti/crypto"
                    "/var/run/ganeti/socket"
                    "/var/run/ganeti/instance-disks"
                    "/var/run/ganeti/instance-reason"
                    "/var/run/ganeti/livelocks")))))

(define ganeti-shepherd-services
  (match-lambda
    (($ <ganeti-configuration> _ noded confd wconfd luxid rapi kvmd mond metad)
     (append (ganeti-noded-service noded)
             (ganeti-confd-service confd)
             (ganeti-wconfd-service wconfd)
             (ganeti-luxid-service luxid)
             (ganeti-rapi-service rapi)
             (ganeti-kvmd-service kvmd)
             (ganeti-mond-service mond)
             (ganeti-metad-service metad)))))

(define ganeti-mcron-jobs
  (match-lambda
    (($ <ganeti-configuration> _ _ _ _ _ _ _ _ _ watcher cleaner)
     (append (ganeti-watcher-jobs watcher)
             (ganeti-cleaner-jobs cleaner)))))

(define-record-type* <ganeti-os>
  ganeti-os make-ganeti-os ganeti-os?
  (name ganeti-os-name)                     ;string
  (extension ganeti-os-extension            ;#f | string
             (default #f))
  (variants ganeti-os-variants              ;<file-like> | list of <ganeti-os-variant>
            (default '())))

(define-record-type* <ganeti-os-variant>
  ganeti-os-variant make-ganeti-os-variant ganeti-os-variant?
  (name ganeti-os-variant-name)                       ;string
  (configuration ganeti-os-variant-configuration))    ;<file-like>

(define %debootstrap-interfaces-hook
  (file-append ganeti-instance-debootstrap
               "/share/doc/ganeti-instance-debootstrap/examples/interfaces"))

;; The GRUB hook shipped with instance-debootstrap does not work with GRUB2.
;; For convenience, provide one that work with modern Debians here.
;; Note: it would be neat to reuse Guix' bootloader infrastructure instead.
(define %debootstrap-grub-hook
  (plain-file "grub"
              "#!/usr/bin/env bash
CLEANUP=( )
cleanup() {
  if [ ${#CLEANUP[*]} -gt 0 ]; then
    LAST_ELEMENT=$((${#CLEANUP[*]}-1))
    REVERSE_INDEXES=$(seq ${LAST_ELEMENT} -1 0)
    for i in $REVERSE_INDEXES; do
      ${CLEANUP[$i]}
    done
  fi
}

trap cleanup EXIT

mount -t proc proc $TARGET/proc
CLEANUP+=(\"umount $TARGET/proc\")
mount -t sysfs sysfs $TARGET/sys
CLEANUP+=(\"umount $TARGET/sys\")
mount -o bind /dev $TARGET/dev
CLEANUP+=(\"umount $TARGET/dev\")

echo '
GRUB_TIMEOUT_STYLE=menu
GRUB_CMDLINE_LINUX_DEFAULT=\"console=ttyS0,115200 net.ifnames=0\"
GRUB_TERMINAL=\"serial\"
GRUB_SERIAL_COMMAND=\"serial --unit=0 --speed=115200\"
' >> $TARGET/etc/default/grub

# This PATH is propagated into the chroot and necessary to make grub-install
# and related commands visible.
export PATH=\"/usr/sbin:/usr/bin:/sbin:/bin:$PATH\"

chroot \"$TARGET\" grub-install $BLOCKDEV
chroot \"$TARGET\" update-grub

cleanup
trap - EXIT
"))

(define %default-debootstrap-hooks
  `((10-interfaces . ,%debootstrap-interfaces-hook)
    (90-grub . ,%debootstrap-grub-hook)))

(define %default-debootstrap-extra-pkgs
  ;; Packages suitable for a fully virtualized KVM guest.
  '("acpi-support-base" "udev" "linux-image-amd64" "openssh-server"
    "locales-all" "grub-pc"))

(define-record-type* <debootstrap-configuration>
  debootstrap-configuration make-debootstrap-configuration
  debootstrap-configuration?
  (hooks debootstrap-configuration-hooks                     ;#f | gexp | '((name . gexp))
         (default %default-debootstrap-hooks))
  (proxy debootstrap-configuration-proxy (default #f))       ;#f | string
  (mirror debootstrap-configuration-mirror                   ;#f | string
          (default #f))
  (arch debootstrap-configuration-arch (default #f))         ;#f | string
  (suite debootstrap-configuration-suite                     ;#f | string
         (default "stable"))
  (extra-pkgs debootstrap-configuration-extra-pkgs           ;list of strings
              (default %default-debootstrap-extra-pkgs))
  (components debootstrap-configuration-components           ;list of strings
              (default '()))
  (generate-cache? debootstrap-configuration-generate-cache? ;Boolean
                   (default #t))
  (clean-cache debootstrap-configuration-clean-cache         ;#f | integer
               (default 14))
  (partition-style debootstrap-configuration-partition-style ;#f | symbol | string
                   (default 'msdos))
  (partition-alignment debootstrap-configuration-partition-alignment ;#f | integer
                       (default 2048)))

(define (debootstrap-hooks->directory hooks)
  (match hooks
    ((? file-like?)
     hooks)
    ((? list?)
     (let ((names (map car hooks))
           (files (map cdr hooks)))
       (with-imported-modules '((guix build utils))
         (computed-file "debootstrap-hooks"
                        #~(begin
                            (use-modules (guix build utils)
                                         (ice-9 match))
                            (mkdir-p #$output)
                            (with-directory-excursion #$output
                              (for-each (match-lambda
                                          ((name hook)
                                           (let ((file-name (string-append
                                                             #$output "/"
                                                             (symbol->string name))))
                                             ;; Copy to the destination to ensure
                                             ;; the file is executable.
                                             (copy-file hook file-name)
                                             (chmod file-name #o555))))
                                        '#$(zip names files))))))))
    (_ #f)))

(define-gexp-compiler (debootstrap-configuration-compiler
                       (file <debootstrap-configuration>) system target)
  (match file
    (($ <debootstrap-configuration> hooks proxy mirror arch suite extra-pkgs
                                    components generate-cache? clean-cache
                                    partition-style partition-alignment)
     (let ((customize-dir (debootstrap-hooks->directory hooks)))
       (gexp->derivation
        "debootstrap-variant"
        #~(call-with-output-file (ungexp output "out")
            (lambda (port)
              (display
               (string-append
                (ungexp-splicing
                 `(,@(if proxy
                          `("PROXY=" ,proxy "\n")
                          '())
                    ,@(if mirror
                          `("MIRROR=" ,mirror "\n")
                          '())
                    ,@(if arch
                          `("ARCH=" ,arch "\n")
                          '())
                    ,@(if suite
                          `("SUITE=" ,suite "\n")
                          '())
                    ,@(if (not (null? extra-pkgs))
                          `("EXTRA_PKGS=" ,(string-join extra-pkgs ",") "\n")
                          '())
                    ,@(if (not (null? components))
                          `("COMPONENTS=" ,(string-join components ",") "\n")
                          '())
                    ,@(if customize-dir
                          `("CUSTOMIZE_DIR=" ,customize-dir "\n")
                          '())
                    ,@(if generate-cache?
                          '("GENERATE_CACHE=yes\n")
                          '("GENERATE_CACHE=no\n"))
                    ,@(if clean-cache
                          `("CLEAN_CACHE=" ,(number->string clean-cache) "\n")
                          '())
                    ,@(if partition-style
                          (if (symbol? partition-style)
                              `("PARTITION_STYLE="
                                ,(symbol->string partition-style) "\n")
                              `("PARTITION_STYLE=" ,partition-style "\n"))
                          '())
                    ,@(if partition-alignment
                          `("PARTITION_ALIGNMENT="
                            ,(number->string partition-alignment) "\n")
                          '()))))
               port)))
        #:local-build? #t)))))

(define (ganeti-os->directory os)
  "Return the derivation to build the configuration directory to be installed
in /etc/ganeti/instance-$os for OS."
  (let ((name      (ganeti-os-name os))
        (extension (ganeti-os-extension os))
        (variants  (ganeti-os-variants os)))
    (define builder
      (with-imported-modules '((guix build utils))
        (if (file-like? variants)
            #~(begin
                (use-modules (guix build utils))
                (mkdir-p #$output)
                (symlink #$variants
                         (string-append #$output "/variants")))
            #~(begin
                (use-modules (guix build utils)
                             (ice-9 format)
                             (ice-9 match)
                             (srfi srfi-1))
                (mkdir-p #$output)
                (let ((variants-dir (string-append #$output "/variants"))
                      (names   '#$(map ganeti-os-variant-name variants))
                      (configs '#$(map ganeti-os-variant-configuration variants)))
                  (mkdir-p variants-dir)
                  (unless (null? names)
                    (call-with-output-file (string-append variants-dir
                                                          "/variants.list")
                      (lambda (port)
                        (format port "~a~%"
                                (string-join names "\n"))))
                    (for-each (match-lambda
                                ((name file)
                                 (let ((file-name
                                        (if #$extension
                                            (string-append name #$extension)
                                            name)))
                                   (symlink file
                                            (string-append variants-dir "/"
                                                           file-name)))))
                              (zip names configs))))))))

    (computed-file (string-append name "-os") builder
                   #:local-build? #t)))

(define (ganeti-directory file-storage-file hooks os)
  (let ((dirs (map ganeti-os->directory os))
        (names (map ganeti-os-name os)))
    (define builder
      #~(begin
          (use-modules (ice-9 match))
          (mkdir #$output)
          (when #$file-storage-file
            (symlink #$file-storage-file
                     (string-append #$output "/file-storage-paths")))
          (when #$hooks
            (symlink #$hooks
                     (string-append #$output "/hooks")))
          (for-each (match-lambda
                      ((name dest)
                       (symlink dest
                                (string-append #$output "/instance-" name))))
                    '#$(zip names dirs))))
    (computed-file "etc-ganeti" builder)))

(define (file-storage-file paths)
  (match paths
    ((? null?) #f)
    ((? list?) (plain-file
                "file-storage-paths"
                (string-join paths "\n")))
    (_ paths)))

(define (ganeti-etc-service config)
  (list `("ganeti" ,(ganeti-directory
                     (file-storage-file
                      (ganeti-configuration-file-storage-paths config))
                     (ganeti-configuration-hooks config)
                     (ganeti-configuration-os config)))))

(define (debootstrap-os variants)
  (ganeti-os
   (name "debootstrap")
   (extension ".conf")
   (variants variants)))

(define (debootstrap-variant name configuration)
  (ganeti-os-variant
   (name name)
   (configuration configuration)))

(define %default-debootstrap-variants
  (list (debootstrap-variant
         "default"
         (debootstrap-configuration))))

(define (guix-os variants)
  (ganeti-os
   (name "guix")
   (extension ".scm")
   (variants variants)))

(define (guix-variant name configuration)
  (ganeti-os-variant
   (name name)
   (configuration configuration)))

(define %default-guix-variants
  (list (guix-variant
         "default"
         (file-append ganeti-instance-guix
                      "/share/doc/ganeti-instance-guix/examples/dynamic.scm"))))

;; The OS configurations usually come with a default OS.  To make them work
;; out of the box, follow suit.
(define %default-ganeti-os
  (list (debootstrap-os %default-debootstrap-variants)
        (guix-os %default-guix-variants)))

(define ganeti-service-type
  (service-type (name 'ganeti)
                (extensions
                 (list (service-extension activation-service-type
                                          ganeti-activation)
                       (service-extension shepherd-root-service-type
                                          ganeti-shepherd-services)
                       (service-extension etc-service-type
                                          ganeti-etc-service)
                       (service-extension profile-service-type
                                          (compose list ganeti-configuration-ganeti))
                       (service-extension mcron-service-type
                                          ganeti-mcron-jobs)))
                (default-value (ganeti-configuration (os %default-ganeti-os)))
                (description
                 "Ganeti is a family of services that are designed to run
on a fleet of machines and facilitate deployment and maintenance of virtual
servers (@dfn{instances}).  It can migrate instances between nodes, automatically
restart failed instances, evacuate nodes, and much more.")))
