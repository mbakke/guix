;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015, 2016 Alex Kost <alezost@gmail.com>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Sou Bunnbu <iyzsong@gmail.com>
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

(define-module (gnu services base)
  #:use-module (guix store)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu services networking)
  #:use-module (gnu system pam)
  #:use-module (gnu system shadow)                ; 'user-account', etc.
  #:use-module (gnu system file-systems)          ; 'file-system', etc.
  #:use-module (gnu packages admin)
  #:use-module ((gnu packages linux)
                #:select (eudev kbd e2fsprogs lvm2 fuse alsa-utils crda gpm))
  #:use-module ((gnu packages base)
                #:select (canonical-package glibc))
  #:use-module (gnu packages package-management)
  #:use-module (gnu packages lsh)
  #:use-module (gnu packages lsof)
  #:use-module ((gnu build file-systems)
                #:select (mount-flags->bit-mask))
  #:use-module (guix gexp)
  #:use-module (guix records)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)
  #:use-module (ice-9 format)
  #:export (fstab-service-type
            root-file-system-service
            file-system-service
            user-unmount-service
            device-mapping-service
            swap-service
            user-processes-service
            session-environment-service
            session-environment-service-type
            host-name-service
            console-keymap-service
            console-font-service

            udev-configuration
            udev-configuration?
            udev-configuration-rules
            udev-service-type
            udev-service
            udev-rule

            mingetty-configuration
            mingetty-configuration?
            mingetty-service
            mingetty-service-type

            %nscd-default-caches
            %nscd-default-configuration

            nscd-configuration
            nscd-configuration?

            nscd-cache
            nscd-cache?

            nscd-service-type
            nscd-service
            syslog-service
            %default-syslog.conf

            guix-configuration
            guix-configuration?
            guix-service
            guix-service-type
            guix-publish-configuration
            guix-publish-configuration?
            guix-publish-service
            guix-publish-service-type
            gpm-service-type
            gpm-service

            %base-services))

;;; Commentary:
;;;
;;; Base system services---i.e., services that 99% of the users will want to
;;; use.
;;;
;;; Code:


;;;
;;; File systems.
;;;

(define (file-system->fstab-entry file-system)
  "Return a @file{/etc/fstab} entry for @var{file-system}."
  (string-append (case (file-system-title file-system)
                   ((label)
                    (string-append "LABEL=" (file-system-device file-system)))
                   ((uuid)
                    (string-append
                     "UUID="
                     (uuid->string (file-system-device file-system))))
                   (else
                    (file-system-device file-system)))
                 "\t"
                 (file-system-mount-point file-system) "\t"
                 (file-system-type file-system) "\t"
                 (or (file-system-options file-system) "defaults") "\t"

                 ;; XXX: Omit the 'fs_freq' and 'fs_passno' fields because we
                 ;; don't have anything sensible to put in there.
                 ))

(define (file-systems->fstab file-systems)
  "Return a @file{/etc} entry for an @file{fstab} describing
@var{file-systems}."
  `(("fstab" ,(plain-file "fstab"
                          (string-append
                           "\
# This file was generated from your GuixSD configuration.  Any changes
# will be lost upon reboot or reconfiguration.\n\n"
                           (string-join (map file-system->fstab-entry
                                             file-systems)
                                        "\n")
                           "\n")))))

(define fstab-service-type
  ;; The /etc/fstab service.
  (service-type (name 'fstab)
                (extensions
                 (list (service-extension etc-service-type
                                          file-systems->fstab)))
                (compose identity)
                (extend append)))

(define %root-file-system-shepherd-service
  (shepherd-service
   (documentation "Take care of the root file system.")
   (provision '(root-file-system))
   (start #~(const #t))
   (stop #~(lambda _
             ;; Return #f if successfully stopped.
             (sync)

             (call-with-blocked-asyncs
              (lambda ()
                (let ((null (%make-void-port "w")))
                  ;; Close 'shepherd.log'.
                  (display "closing log\n")
                  ((@ (shepherd comm) stop-logging))

                  ;; Redirect the default output ports..
                  (set-current-output-port null)
                  (set-current-error-port null)

                  ;; Close /dev/console.
                  (for-each close-fdes '(0 1 2))

                  ;; At this point, there are no open files left, so the
                  ;; root file system can be re-mounted read-only.
                  (mount #f "/" #f
                         (logior MS_REMOUNT MS_RDONLY)
                         #:update-mtab? #f)

                  #f)))))
   (respawn? #f)))

(define root-file-system-service-type
  (shepherd-service-type 'root-file-system
                         (const %root-file-system-shepherd-service)))

(define (root-file-system-service)
  "Return a service whose sole purpose is to re-mount read-only the root file
system upon shutdown (aka. cleanly \"umounting\" root.)

This service must be the root of the service dependency graph so that its
'stop' action is invoked when shepherd is the only process left."
  (service root-file-system-service-type #f))

(define (file-system->shepherd-service-name file-system)
  "Return the symbol that denotes the service mounting and unmounting
FILE-SYSTEM."
  (symbol-append 'file-system-
                 (string->symbol (file-system-mount-point file-system))))

(define (mapped-device->shepherd-service-name md)
  "Return the symbol that denotes the shepherd service of MD, a <mapped-device>."
  (symbol-append 'device-mapping-
                 (string->symbol (mapped-device-target md))))

(define dependency->shepherd-service-name
  (match-lambda
    ((? mapped-device? md)
     (mapped-device->shepherd-service-name md))
    ((? file-system? fs)
     (file-system->shepherd-service-name fs))))

(define (file-system-shepherd-service file-system)
  "Return a list containing the shepherd service for @var{file-system}."
  (let ((target  (file-system-mount-point file-system))
        (device  (file-system-device file-system))
        (type    (file-system-type file-system))
        (title   (file-system-title file-system))
        (check?  (file-system-check? file-system))
        (create? (file-system-create-mount-point? file-system))
        (dependencies (file-system-dependencies file-system)))
    (if (file-system-mount? file-system)
        (list
         (shepherd-service
          (provision (list (file-system->shepherd-service-name file-system)))
          (requirement `(root-file-system
                         ,@(map dependency->shepherd-service-name dependencies)))
          (documentation "Check, mount, and unmount the given file system.")
          (start #~(lambda args
                     ;; FIXME: Use or factorize with 'mount-file-system'.
                     (let ((device (canonicalize-device-spec #$device '#$title))
                           (flags  #$(mount-flags->bit-mask
                                      (file-system-flags file-system))))
                       #$(if create?
                             #~(mkdir-p #$target)
                             #~#t)
                       #$(if check?
                             #~(begin
                                 ;; Make sure fsck.ext2 & co. can be found.
                                 (setenv "PATH"
                                         (string-append
                                          #$e2fsprogs "/sbin:"
                                          "/run/current-system/profile/sbin:"
                                          (getenv "PATH")))
                                 (check-file-system device #$type))
                             #~#t)

                       (mount device #$target #$type flags
                              #$(file-system-options file-system))

                       ;; For read-only bind mounts, an extra remount is
                       ;; needed, as per <http://lwn.net/Articles/281157/>,
                       ;; which still applies to Linux 4.0.
                       (when (and (= MS_BIND (logand flags MS_BIND))
                                  (= MS_RDONLY (logand flags MS_RDONLY)))
                         (mount device #$target #$type
                                (logior MS_BIND MS_REMOUNT MS_RDONLY))))
                     #t))
          (stop #~(lambda args
                    ;; Normally there are no processes left at this point, so
                    ;; TARGET can be safely unmounted.

                    ;; Make sure PID 1 doesn't keep TARGET busy.
                    (chdir "/")

                    (umount #$target)
                    #f))

          ;; We need an additional module.
          (modules `(((gnu build file-systems)
                      #:select (check-file-system canonicalize-device-spec))
                     ,@%default-modules))
          (imported-modules `((gnu build file-systems)
                              (guix build bournish)
                              ,@%default-imported-modules))))
        '())))

(define file-system-service-type
  ;; TODO(?): Make this an extensible service that takes <file-system> objects
  ;; and returns a list of <shepherd-service>.
  (service-type (name 'file-system)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          file-system-shepherd-service)
                       (service-extension fstab-service-type
                                          identity)))))

(define* (file-system-service file-system)
  "Return a service that mounts @var{file-system}, a @code{<file-system>}
object."
  (service file-system-service-type file-system))

(define user-unmount-service-type
  (shepherd-service-type
   'user-file-systems
   (lambda (known-mount-points)
     (shepherd-service
      (documentation "Unmount manually-mounted file systems.")
      (provision '(user-file-systems))
      (start #~(const #t))
      (stop #~(lambda args
                (define (known? mount-point)
                  (member mount-point
                          (cons* "/proc" "/sys" '#$known-mount-points)))

                ;; Make sure we don't keep the user's mount points busy.
                (chdir "/")

                (for-each (lambda (mount-point)
                            (format #t "unmounting '~a'...~%" mount-point)
                            (catch 'system-error
                              (lambda ()
                                (umount mount-point))
                              (lambda args
                                (let ((errno (system-error-errno args)))
                                  (format #t "failed to unmount '~a': ~a~%"
                                          mount-point (strerror errno))))))
                          (filter (negate known?) (mount-points)))
                #f))))))

(define (user-unmount-service known-mount-points)
  "Return a service whose sole purpose is to unmount file systems not listed
in KNOWN-MOUNT-POINTS when it is stopped."
  (service user-unmount-service-type known-mount-points))

(define %do-not-kill-file
  ;; Name of the file listing PIDs of processes that must survive when halting
  ;; the system.  Typical example is user-space file systems.
  "/etc/shepherd/do-not-kill")

(define user-processes-service-type
  (shepherd-service-type
   'user-processes
   (match-lambda
     ((requirements grace-delay)
      (shepherd-service
       (documentation "When stopped, terminate all user processes.")
       (provision '(user-processes))
       (requirement (cons* 'root-file-system 'user-file-systems
                           (map file-system->shepherd-service-name
                                requirements)))
       (start #~(const #t))
       (stop #~(lambda _
                 (define (kill-except omit signal)
                   ;; Kill all the processes with SIGNAL except those listed
                   ;; in OMIT and the current process.
                   (let ((omit (cons (getpid) omit)))
                     (for-each (lambda (pid)
                                 (unless (memv pid omit)
                                   (false-if-exception
                                    (kill pid signal))))
                               (processes))))

                 (define omitted-pids
                   ;; List of PIDs that must not be killed.
                   (if (file-exists? #$%do-not-kill-file)
                       (map string->number
                            (call-with-input-file #$%do-not-kill-file
                              (compose string-tokenize
                                       (@ (ice-9 rdelim) read-string))))
                       '()))

                 (define (now)
                   (car (gettimeofday)))

                 (define (sleep* n)
                   ;; Really sleep N seconds.
                   ;; Work around <http://bugs.gnu.org/19581>.
                   (define start (now))
                   (let loop ((elapsed 0))
                     (when (> n elapsed)
                       (sleep (- n elapsed))
                       (loop (- (now) start)))))

                 (define lset= (@ (srfi srfi-1) lset=))

                 (display "sending all processes the TERM signal\n")

                 (if (null? omitted-pids)
                     (begin
                       ;; Easy: terminate all of them.
                       (kill -1 SIGTERM)
                       (sleep* #$grace-delay)
                       (kill -1 SIGKILL))
                     (begin
                       ;; Kill them all except OMITTED-PIDS.  XXX: We would
                       ;; like to (kill -1 SIGSTOP) to get a fixed list of
                       ;; processes, like 'killall5' does, but that seems
                       ;; unreliable.
                       (kill-except omitted-pids SIGTERM)
                       (sleep* #$grace-delay)
                       (kill-except omitted-pids SIGKILL)
                       (delete-file #$%do-not-kill-file)))

                 (let wait ()
                   (let ((pids (processes)))
                     (unless (lset= = pids (cons 1 omitted-pids))
                       (format #t "waiting for process termination\
 (processes left: ~s)~%"
                               pids)
                       (sleep* 2)
                       (wait))))

                 (display "all processes have been terminated\n")
                 #f))
       (respawn? #f))))))

(define* (user-processes-service file-systems #:key (grace-delay 4))
  "Return the service that is responsible for terminating all the processes so
that the root file system can be re-mounted read-only, just before
rebooting/halting.  Processes still running GRACE-DELAY seconds after SIGTERM
has been sent are terminated with SIGKILL.

The returned service will depend on 'root-file-system' and on all the shepherd
services corresponding to FILE-SYSTEMS.

All the services that spawn processes must depend on this one so that they are
stopped before 'kill' is called."
  (service user-processes-service-type
           (list (filter file-system-mount? file-systems) grace-delay)))


;;;
;;; System-wide environment variables.
;;;

(define (environment-variables->environment-file vars)
  "Return a file for pam_env(8) that contains environment variables VARS."
  (apply mixed-text-file "environment"
         (append-map (match-lambda
                       ((key . value)
                        (list key "=" value "\n")))
                     vars)))

(define session-environment-service-type
  (service-type
   (name 'session-environment)
   (extensions
    (list (service-extension
           etc-service-type
           (lambda (vars)
             (list `("environment"
                     ,(environment-variables->environment-file vars)))))))
   (compose concatenate)
   (extend append)))

(define (session-environment-service vars)
  "Return a service that builds the @file{/etc/environment}, which can be read
by PAM-aware applications to set environment variables for sessions.

VARS should be an association list in which both the keys and the values are
strings or string-valued gexps."
  (service session-environment-service-type vars))


;;;
;;; Console & co.
;;;

(define host-name-service-type
  (shepherd-service-type
   'host-name
   (lambda (name)
     (shepherd-service
      (documentation "Initialize the machine's host name.")
      (provision '(host-name))
      (start #~(lambda _
                 (sethostname #$name)))
      (respawn? #f)))))

(define (host-name-service name)
  "Return a service that sets the host name to @var{name}."
  (service host-name-service-type name))

(define (unicode-start tty)
  "Return a gexp to start Unicode support on @var{tty}."

  ;; We have to run 'unicode_start' in a pipe so that when it invokes the
  ;; 'tty' command, that command returns TTY.
  #~(begin
      (let ((pid (primitive-fork)))
        (case pid
          ((0)
           (close-fdes 0)
           (dup2 (open-fdes #$tty O_RDONLY) 0)
           (close-fdes 1)
           (dup2 (open-fdes #$tty O_WRONLY) 1)
           (execl (string-append #$kbd "/bin/unicode_start")
                  "unicode_start"))
          (else
           (zero? (cdr (waitpid pid))))))))

(define console-keymap-service-type
  (shepherd-service-type
   'console-keymap
   (lambda (file)
     (shepherd-service
      (documentation (string-append "Load console keymap (loadkeys)."))
      (provision '(console-keymap))
      (start #~(lambda _
                 (zero? (system* (string-append #$kbd "/bin/loadkeys")
                                 #$file))))
      (respawn? #f)))))

(define (console-keymap-service file)
  "Return a service to load console keymap from @var{file}."
  (service console-keymap-service-type file))

(define console-font-service-type
  (shepherd-service-type
   'console-font
   (match-lambda
     ((tty font)
      (let ((device (string-append "/dev/" tty)))
        (shepherd-service
         (documentation "Load a Unicode console font.")
         (provision (list (symbol-append 'console-font-
                                         (string->symbol tty))))

         ;; Start after mingetty has been started on TTY, otherwise the settings
         ;; are ignored.
         (requirement (list (symbol-append 'term-
                                           (string->symbol tty))))

         (start #~(lambda _
                    (and #$(unicode-start device)
                         (zero?
                          (system* (string-append #$kbd "/bin/setfont")
                                   "-C" #$device #$font)))))
         (stop #~(const #t))
         (respawn? #f)))))))

(define* (console-font-service tty #:optional (font "LatGrkCyr-8x16"))
  "Return a service that sets up Unicode support in @var{tty} and loads
@var{font} for that tty (fonts are per virtual console in Linux.)"
  ;; Note: 'LatGrkCyr-8x16' has the advantage of providing three common
  ;; scripts as well as glyphs for em dash, quotation marks, and other Unicode
  ;; codepoints notably found in the UTF-8 manual.
  (service console-font-service-type (list tty font)))

(define-record-type* <mingetty-configuration>
  mingetty-configuration make-mingetty-configuration
  mingetty-configuration?
  (mingetty       mingetty-configuration-mingetty ;<package>
                  (default mingetty))
  (tty            mingetty-configuration-tty)     ;string
  (motd           mingetty-configuration-motd     ;file-like
                  (default (plain-file "motd" "Welcome.\n")))
  (auto-login     mingetty-auto-login             ;string | #f
                  (default #f))
  (login-program  mingetty-login-program          ;gexp
                  (default #f))
  (login-pause?   mingetty-login-pause?           ;Boolean
                  (default #f))

  ;; Allow empty passwords by default so that first-time users can log in when
  ;; the 'root' account has just been created.
  (allow-empty-passwords? mingetty-configuration-allow-empty-passwords?
                          (default #t)))          ;Boolean

(define (mingetty-pam-service conf)
  "Return the list of PAM service needed for CONF."
  ;; Let 'login' be known to PAM.  All the mingetty services will have that
  ;; PAM service, but that's fine because they're all identical and duplicates
  ;; are removed.
  (list (unix-pam-service "login"
                          #:allow-empty-passwords?
                          (mingetty-configuration-allow-empty-passwords? conf)
                          #:motd
                          (mingetty-configuration-motd conf))))

(define mingetty-shepherd-service
  (match-lambda
    (($ <mingetty-configuration> mingetty tty motd auto-login login-program
                                 login-pause? allow-empty-passwords?)
     (list
      (shepherd-service
       (documentation "Run mingetty on an tty.")
       (provision (list (symbol-append 'term- (string->symbol tty))))

       ;; Since the login prompt shows the host name, wait for the 'host-name'
       ;; service to be done.  Also wait for udev essentially so that the tty
       ;; text is not lost in the middle of kernel messages (XXX).
       (requirement '(user-processes host-name udev))

       (start  #~(make-forkexec-constructor
                  (list (string-append #$mingetty "/sbin/mingetty")
                        "--noclear" #$tty
                        #$@(if auto-login
                               #~("--autologin" #$auto-login)
                               #~())
                        #$@(if login-program
                               #~("--loginprog" #$login-program)
                               #~())
                        #$@(if login-pause?
                               #~("--loginpause")
                               #~()))))
       (stop   #~(make-kill-destructor)))))))

(define mingetty-service-type
  (service-type (name 'mingetty)
                (extensions (list (service-extension shepherd-root-service-type
                                                     mingetty-shepherd-service)
                                  (service-extension pam-root-service-type
                                                     mingetty-pam-service)))))

(define* (mingetty-service config)
  "Return a service to run mingetty according to @var{config}, which specifies
the tty to run, among other things."
  (service mingetty-service-type config))

(define-record-type* <nscd-configuration> nscd-configuration
  make-nscd-configuration
  nscd-configuration?
  (log-file    nscd-configuration-log-file        ;string
               (default "/var/log/nscd.log"))
  (debug-level nscd-debug-level                   ;integer
               (default 0))
  ;; TODO: See nscd.conf in glibc for other options to add.
  (caches     nscd-configuration-caches           ;list of <nscd-cache>
              (default %nscd-default-caches))
  (name-services nscd-configuration-name-services ;list of <packages>
                 (default '()))
  (glibc      nscd-configuration-glibc            ;<package>
              (default (canonical-package glibc))))

(define-record-type* <nscd-cache> nscd-cache make-nscd-cache
  nscd-cache?
  (database              nscd-cache-database)              ;symbol
  (positive-time-to-live nscd-cache-positive-time-to-live) ;integer
  (negative-time-to-live nscd-cache-negative-time-to-live
                         (default 20))             ;integer
  (suggested-size        nscd-cache-suggested-size ;integer ("default module
                                                   ;of hash table")
                         (default 211))
  (check-files?          nscd-cache-check-files?  ;Boolean
                         (default #t))
  (persistent?           nscd-cache-persistent?   ;Boolean
                         (default #t))
  (shared?               nscd-cache-shared?       ;Boolean
                         (default #t))
  (max-database-size     nscd-cache-max-database-size ;integer
                         (default (* 32 (expt 2 20))))
  (auto-propagate?       nscd-cache-auto-propagate? ;Boolean
                         (default #t)))

(define %nscd-default-caches
  ;; Caches that we want to enable by default.  Note that when providing an
  ;; empty nscd.conf, all caches are disabled.
  (list (nscd-cache (database 'hosts)

                    ;; Aggressively cache the host name cache to improve
                    ;; privacy and resilience.
                    (positive-time-to-live (* 3600 12))
                    (negative-time-to-live 20)
                    (persistent? #t))

        (nscd-cache (database 'services)

                    ;; Services are unlikely to change, so we can be even more
                    ;; aggressive.
                    (positive-time-to-live (* 3600 24))
                    (negative-time-to-live 3600)
                    (check-files? #t)             ;check /etc/services changes
                    (persistent? #t))))

(define %nscd-default-configuration
  ;; Default nscd configuration.
  (nscd-configuration))

(define (nscd.conf-file config)
  "Return the @file{nscd.conf} configuration file for @var{config}, an
@code{<nscd-configuration>} object."
  (define cache->config
    (match-lambda
      (($ <nscd-cache> (= symbol->string database)
                       positive-ttl negative-ttl size check-files?
                       persistent? shared? max-size propagate?)
       (string-append "\nenable-cache\t" database "\tyes\n"

                      "positive-time-to-live\t" database "\t"
                      (number->string positive-ttl) "\n"
                      "negative-time-to-live\t" database "\t"
                      (number->string negative-ttl) "\n"
                      "suggested-size\t" database "\t"
                      (number->string size) "\n"
                      "check-files\t" database "\t"
                      (if check-files? "yes\n" "no\n")
                      "persistent\t" database "\t"
                      (if persistent? "yes\n" "no\n")
                      "shared\t" database "\t"
                      (if shared? "yes\n" "no\n")
                      "max-db-size\t" database "\t"
                      (number->string max-size) "\n"
                      "auto-propagate\t" database "\t"
                      (if propagate? "yes\n" "no\n")))))

  (match config
    (($ <nscd-configuration> log-file debug-level caches)
     (plain-file "nscd.conf"
                 (string-append "\
# Configuration of libc's name service cache daemon (nscd).\n\n"
                                (if log-file
                                    (string-append "logfile\t" log-file)
                                    "")
                                "\n"
                                (if debug-level
                                    (string-append "debug-level\t"
                                                   (number->string debug-level))
                                    "")
                                "\n"
                                (string-concatenate
                                 (map cache->config caches)))))))

(define (nscd-shepherd-service config)
  "Return a shepherd service for CONFIG, an <nscd-configuration> object."
  (let ((nscd.conf     (nscd.conf-file config))
        (name-services (nscd-configuration-name-services config)))
    (list (shepherd-service
           (documentation "Run libc's name service cache daemon (nscd).")
           (provision '(nscd))
           (requirement '(user-processes))
           (start #~(make-forkexec-constructor
                     (list (string-append #$(nscd-configuration-glibc config)
                                          "/sbin/nscd")
                           "-f" #$nscd.conf "--foreground")

                     #:environment-variables
                     (list (string-append "LD_LIBRARY_PATH="
                                          (string-join
                                           (map (lambda (dir)
                                                  (string-append dir "/lib"))
                                                (list #$@name-services))
                                           ":")))))
           (stop #~(make-kill-destructor))

           (respawn? #f)))))

(define nscd-activation
  ;; Actions to take before starting nscd.
  #~(begin
      (use-modules (guix build utils))
      (mkdir-p "/var/run/nscd")
      (mkdir-p "/var/db/nscd")))                  ;for the persistent cache

(define nscd-service-type
  (service-type (name 'nscd)
                (extensions
                 (list (service-extension activation-service-type
                                          (const nscd-activation))
                       (service-extension shepherd-root-service-type
                                          nscd-shepherd-service)))

                ;; This can be extended by providing additional name services
                ;; such as nss-mdns.
                (compose concatenate)
                (extend (lambda (config name-services)
                          (nscd-configuration
                           (inherit config)
                           (name-services (append
                                           (nscd-configuration-name-services config)
                                           name-services)))))))

(define* (nscd-service #:optional (config %nscd-default-configuration))
  "Return a service that runs libc's name service cache daemon (nscd) with the
given @var{config}---an @code{<nscd-configuration>} object.  @xref{Name
Service Switch}, for an example."
  (service nscd-service-type config))

(define syslog-service-type
  (shepherd-service-type
   'syslog
   (lambda (config-file)
     (shepherd-service
      (documentation "Run the syslog daemon (syslogd).")
      (provision '(syslogd))
      (requirement '(user-processes))
      (start #~(make-forkexec-constructor
                (list (string-append #$inetutils "/libexec/syslogd")
                      "--no-detach" "--rcfile" #$config-file)))
      (stop #~(make-kill-destructor))))))

;; Snippet adapted from the GNU inetutils manual.
(define %default-syslog.conf
  (plain-file "syslog.conf" "
     # Log all error messages, authentication messages of
     # level notice or higher and anything of level err or
     # higher to the console.
     # Don't log private authentication messages!
     *.alert;auth.notice;authpriv.none       /dev/console

     # Log anything (except mail) of level info or higher.
     # Don't log private authentication messages!
     *.info;mail.none;authpriv.none          /var/log/messages

     # Same, in a different place.
     *.info;mail.none;authpriv.none          /dev/tty12

     # The authpriv file has restricted access.
     authpriv.*                              /var/log/secure

     # Log all the mail messages in one place.
     mail.*                                  /var/log/maillog
"))

(define* (syslog-service #:key (config-file %default-syslog.conf))
  "Return a service that runs @command{syslogd}.  If configuration file
name @var{config-file} is not specified, use some reasonable default
settings.

@xref{syslogd invocation,,, inetutils, GNU Inetutils}, for more
information on the configuration file syntax."
  (service syslog-service-type config-file))


;;;
;;; Guix services.
;;;

(define* (guix-build-accounts count #:key
                              (group "guixbuild")
                              (first-uid 30001)
                              (shadow shadow))
  "Return a list of COUNT user accounts for Guix build users, with UIDs
starting at FIRST-UID, and under GID."
  (unfold (cut > <> count)
          (lambda (n)
            (user-account
             (name (format #f "guixbuilder~2,'0d" n))
             (system? #t)
             (uid (+ first-uid n -1))
             (group group)

             ;; guix-daemon expects GROUP to be listed as a
             ;; supplementary group too:
             ;; <http://lists.gnu.org/archive/html/bug-guix/2013-01/msg00239.html>.
             (supplementary-groups (list group "kvm"))

             (comment (format #f "Guix Build User ~2d" n))
             (home-directory "/var/empty")
             (shell #~(string-append #$shadow "/sbin/nologin"))))
          1+
          1))

(define (hydra-key-authorization guix)
  "Return a gexp with code to register the hydra.gnu.org public key with
GUIX."
  #~(unless (file-exists? "/etc/guix/acl")
      (let ((pid (primitive-fork)))
        (case pid
          ((0)
           (let* ((key  (string-append #$guix
                                       "/share/guix/hydra.gnu.org.pub"))
                  (port (open-file key "r0b")))
             (format #t "registering public key '~a'...~%" key)
             (close-port (current-input-port))
             (dup port 0)
             (execl (string-append #$guix "/bin/guix")
                    "guix" "archive" "--authorize")
             (exit 1)))
          (else
           (let ((status (cdr (waitpid pid))))
             (unless (zero? status)
               (format (current-error-port) "warning: \
failed to register hydra.gnu.org public key: ~a~%" status))))))))

(define-record-type* <guix-configuration>
  guix-configuration make-guix-configuration
  guix-configuration?
  (guix             guix-configuration-guix       ;<package>
                    (default guix))
  (build-group      guix-configuration-build-group ;string
                    (default "guixbuild"))
  (build-accounts   guix-configuration-build-accounts ;integer
                    (default 10))
  (authorize-key?   guix-configuration-authorize-key? ;Boolean
                    (default #t))
  (use-substitutes? guix-configuration-use-substitutes? ;Boolean
                    (default #t))
  (substitute-urls  guix-configuration-substitute-urls ;list of strings
                    (default %default-substitute-urls))
  (extra-options    guix-configuration-extra-options ;list of strings
                    (default '()))
  (lsof             guix-configuration-lsof       ;<package>
                    (default lsof))
  (lsh              guix-configuration-lsh        ;<package>
                    (default lsh)))

(define %default-guix-configuration
  (guix-configuration))

(define (guix-shepherd-service config)
  "Return a <shepherd-service> for the Guix daemon service with CONFIG."
  (match config
    (($ <guix-configuration> guix build-group build-accounts authorize-key?
                             use-substitutes? substitute-urls extra-options
                             lsof lsh)
     (list (shepherd-service
            (documentation "Run the Guix daemon.")
            (provision '(guix-daemon))
            (requirement '(user-processes))
            (start
             #~(make-forkexec-constructor
                (list (string-append #$guix "/bin/guix-daemon")
                      "--build-users-group" #$build-group
                      #$@(if use-substitutes?
                             '()
                             '("--no-substitutes"))
                      "--substitute-urls" #$(string-join substitute-urls)
                      #$@extra-options)

                ;; Add 'lsof' (for the GC) and 'lsh' (for offloading) to the
                ;; daemon's $PATH.
                #:environment-variables
                (list (string-append "PATH=" #$lsof "/bin:" #$lsh "/bin"))))
            (stop #~(make-kill-destructor)))))))

(define (guix-accounts config)
  "Return the user accounts and user groups for CONFIG."
  (match config
    (($ <guix-configuration> _ build-group build-accounts)
     (cons (user-group
            (name build-group)
            (system? #t)

            ;; Use a fixed GID so that we can create the store with the right
            ;; owner.
            (id 30000))
           (guix-build-accounts build-accounts
                                #:group build-group)))))

(define (guix-activation config)
  "Return the activation gexp for CONFIG."
  (match config
    (($ <guix-configuration> guix build-group build-accounts authorize-key?)
     ;; Assume that the store has BUILD-GROUP as its group.  We could
     ;; otherwise call 'chown' here, but the problem is that on a COW unionfs,
     ;; chown leads to an entire copy of the tree, which is a bad idea.

     ;; Optionally authorize hydra.gnu.org's key.
     (and authorize-key?
          (hydra-key-authorization guix)))))

(define guix-service-type
  (service-type
   (name 'guix)
   (extensions
    (list (service-extension shepherd-root-service-type guix-shepherd-service)
          (service-extension account-service-type guix-accounts)
          (service-extension activation-service-type guix-activation)
          (service-extension profile-service-type
                             (compose list guix-configuration-guix))))))

(define* (guix-service #:optional (config %default-guix-configuration))
  "Return a service that runs the Guix build daemon according to
@var{config}."
  (service guix-service-type config))


(define-record-type* <guix-publish-configuration>
  guix-publish-configuration make-guix-publish-configuration
  guix-publish-configuration?
  (guix    guix-publish-configuration-guix        ;package
           (default guix))
  (port    guix-publish-configuration-port        ;number
           (default 80))
  (host    guix-publish-configuration-host        ;string
           (default "localhost")))

(define guix-publish-shepherd-service
  (match-lambda
    (($ <guix-publish-configuration> guix port host)
     (list (shepherd-service
            (provision '(guix-publish))
            (requirement '(guix-daemon))
            (start #~(make-forkexec-constructor
                      (list (string-append #$guix "/bin/guix")
                            "publish" "-u" "guix-publish"
                            "-p" #$(number->string port)
                            (string-append "--listen=" #$host))))
            (stop #~(make-kill-destructor)))))))

(define %guix-publish-accounts
  (list (user-group (name "guix-publish") (system? #t))
        (user-account
         (name "guix-publish")
         (group "guix-publish")
         (system? #t)
         (comment "guix publish user")
         (home-directory "/var/empty")
         (shell #~(string-append #$shadow "/sbin/nologin")))))

(define guix-publish-service-type
  (service-type (name 'guix-publish)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          guix-publish-shepherd-service)
                       (service-extension account-service-type
                                          (const %guix-publish-accounts))))))

(define* (guix-publish-service #:key (guix guix) (port 80) (host "localhost"))
  "Return a service that runs @command{guix publish} listening on @var{host}
and @var{port} (@pxref{Invoking guix publish}).

This assumes that @file{/etc/guix} already contains a signing key pair as
created by @command{guix archive --generate-key} (@pxref{Invoking guix
archive}).  If that is not the case, the service will fail to start."
  (service guix-publish-service-type
           (guix-publish-configuration (guix guix) (port port) (host host))))


;;;
;;; Udev.
;;;

(define-record-type* <udev-configuration>
  udev-configuration make-udev-configuration
  udev-configuration?
  (udev   udev-configuration-udev                 ;<package>
          (default udev))
  (rules  udev-configuration-rules                ;list of <package>
          (default '())))

(define (udev-rules-union packages)
  "Return the union of the @code{lib/udev/rules.d} directories found in each
item of @var{packages}."
  (define build
    #~(begin
        (use-modules (guix build union)
                     (guix build utils)
                     (srfi srfi-1)
                     (srfi srfi-26))

        (define %standard-locations
          '("/lib/udev/rules.d" "/libexec/udev/rules.d"))

        (define (rules-sub-directory directory)
          ;; Return the sub-directory of DIRECTORY containing udev rules, or
          ;; #f if none was found.
          (find directory-exists?
                (map (cut string-append directory <>) %standard-locations)))

        (mkdir-p (string-append #$output "/lib/udev"))
        (union-build (string-append #$output "/lib/udev/rules.d")
                     (filter-map rules-sub-directory '#$packages))))

  (computed-file "udev-rules" build
                 #:modules '((guix build union)
                             (guix build utils))))

(define (udev-rule file-name contents)
  "Return a directory with a udev rule file FILE-NAME containing CONTENTS."
  (computed-file file-name
                 #~(begin
                     (use-modules (guix build utils))

                     (define rules.d
                       (string-append #$output "/lib/udev/rules.d"))

                     (mkdir-p rules.d)
                     (call-with-output-file
                         (string-append rules.d "/" #$file-name)
                       (lambda (port)
                         (display #$contents port))))
                 #:modules '((guix build utils))))

(define kvm-udev-rule
  ;; Return a directory with a udev rule that changes the group of /dev/kvm to
  ;; "kvm" and makes it #o660.  Apparently QEMU-KVM used to ship this rule,
  ;; but now we have to add it by ourselves.

  ;; Build users are part of the "kvm" group, so we can fearlessly make
  ;; /dev/kvm 660 (see <http://bugs.gnu.org/18994>, for background.)
  (udev-rule "90-kvm.rules"
             "KERNEL==\"kvm\", GROUP=\"kvm\", MODE=\"0660\"\n"))

(define udev-shepherd-service
  ;; Return a <shepherd-service> for UDEV with RULES.
  (match-lambda
    (($ <udev-configuration> udev rules)
     (let* ((rules     (udev-rules-union (cons* udev kvm-udev-rule rules)))
            (udev.conf (computed-file "udev.conf"
                                      #~(call-with-output-file #$output
                                          (lambda (port)
                                            (format port
                                                    "udev_rules=\"~a/lib/udev/rules.d\"\n"
                                                    #$rules))))))
       (list
        (shepherd-service
         (provision '(udev))

         ;; Udev needs /dev to be a 'devtmpfs' mount so that new device nodes can
         ;; be added: see
         ;; <http://www.linuxfromscratch.org/lfs/view/development/chapter07/udev.html>.
         (requirement '(root-file-system))

         (documentation "Populate the /dev directory, dynamically.")
         (start #~(lambda ()
                    (define find
                      (@ (srfi srfi-1) find))

                    (define udevd
                      ;; Choose the right 'udevd'.
                      (find file-exists?
                            (map (lambda (suffix)
                                   (string-append #$udev suffix))
                                 '("/libexec/udev/udevd" ;udev
                                   "/sbin/udevd"))))     ;eudev

                    (define (wait-for-udevd)
                      ;; Wait until someone's listening on udevd's control
                      ;; socket.
                      (let ((sock (socket AF_UNIX SOCK_SEQPACKET 0)))
                        (let try ()
                          (catch 'system-error
                            (lambda ()
                              (connect sock PF_UNIX "/run/udev/control")
                              (close-port sock))
                            (lambda args
                              (format #t "waiting for udevd...~%")
                              (usleep 500000)
                              (try))))))

                    ;; Allow udev to find the modules.
                    (setenv "LINUX_MODULE_DIRECTORY"
                            "/run/booted-system/kernel/lib/modules")

                    ;; The first one is for udev, the second one for eudev.
                    (setenv "UDEV_CONFIG_FILE" #$udev.conf)
                    (setenv "EUDEV_RULES_DIRECTORY"
                            (string-append #$rules "/lib/udev/rules.d"))

                    (let ((pid (primitive-fork)))
                      (case pid
                        ((0)
                         (exec-command (list udevd)))
                        (else
                         ;; Wait until udevd is up and running.  This
                         ;; appears to be needed so that the events
                         ;; triggered below are actually handled.
                         (wait-for-udevd)

                         ;; Trigger device node creation.
                         (system* (string-append #$udev "/bin/udevadm")
                                  "trigger" "--action=add")

                         ;; Wait for things to settle down.
                         (system* (string-append #$udev "/bin/udevadm")
                                  "settle")
                         pid)))))
         (stop #~(make-kill-destructor))

         ;; When halting the system, 'udev' is actually killed by
         ;; 'user-processes', i.e., before its own 'stop' method was called.
         ;; Thus, make sure it is not respawned.
         (respawn? #f)))))))

(define udev-service-type
  (service-type (name 'udev)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          udev-shepherd-service)))

                (compose concatenate)           ;concatenate the list of rules
                (extend (lambda (config rules)
                          (match config
                            (($ <udev-configuration> udev initial-rules)
                             (udev-configuration
                              (udev udev)
                              (rules (append initial-rules rules)))))))))

(define* (udev-service #:key (udev eudev) (rules '()))
  "Run @var{udev}, which populates the @file{/dev} directory dynamically.  Get
extra rules from the packages listed in @var{rules}."
  (service udev-service-type
           (udev-configuration (udev udev) (rules rules))))

(define device-mapping-service-type
  (shepherd-service-type
   'device-mapping
   (match-lambda
     ((target open close)
      (shepherd-service
       (provision (list (symbol-append 'device-mapping- (string->symbol target))))
       (requirement '(udev))
       (documentation "Map a device node using Linux's device mapper.")
       (start #~(lambda () #$open))
       (stop #~(lambda _ (not #$close)))
       (respawn? #f))))))

(define (device-mapping-service target open close)
  "Return a service that maps device @var{target}, a string such as
@code{\"home\"} (meaning @code{/dev/mapper/home}).  Evaluate @var{open}, a
gexp, to open it, and evaluate @var{close} to close it."
  (service device-mapping-service-type
           (list target open close)))

(define swap-service-type
  (shepherd-service-type
   'swap
   (lambda (device)
     (define requirement
       (if (string-prefix? "/dev/mapper/" device)
           (list (symbol-append 'device-mapping-
                                (string->symbol (basename device))))
           '()))

     (shepherd-service
      (provision (list (symbol-append 'swap- (string->symbol device))))
      (requirement `(udev ,@requirement))
      (documentation "Enable the given swap device.")
      (start #~(lambda ()
                 (restart-on-EINTR (swapon #$device))
                 #t))
      (stop #~(lambda _
                (restart-on-EINTR (swapoff #$device))
                #f))
      (respawn? #f)))))

(define (swap-service device)
  "Return a service that uses @var{device} as a swap device."
  (service swap-service-type device))


(define-record-type* <gpm-configuration>
  gpm-configuration make-gpm-configuration gpm-configuration?
  (gpm      gpm-configuration-gpm)                ;package
  (options  gpm-configuration-options))           ;list of strings

(define gpm-shepherd-service
  (match-lambda
    (($ <gpm-configuration> gpm options)
     (list (shepherd-service
            (requirement '(udev))
            (provision '(gpm))
            (start #~(lambda ()
                       ;; 'gpm' runs in the background and sets a PID file.
                       ;; Note that it requires running as "root".
                       (false-if-exception (delete-file "/var/run/gpm.pid"))
                       (fork+exec-command (list (string-append #$gpm "/sbin/gpm")
                                                #$@options))

                       ;; Wait for the PID file to appear; declare failure if
                       ;; it doesn't show up.
                       (let loop ((i 3))
                         (or (file-exists? "/var/run/gpm.pid")
                             (if (zero? i)
                                 #f
                                 (begin
                                   (sleep 1)
                                   (loop (1- i))))))))

            (stop #~(lambda (_)
                      ;; Return #f if successfully stopped.
                      (not (zero? (system* (string-append #$gpm "/sbin/gpm")
                                           "-k"))))))))))

(define gpm-service-type
  (service-type (name 'gpm)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          gpm-shepherd-service)))))

(define* (gpm-service #:key (gpm gpm)
                      (options '("-m" "/dev/input/mice" "-t" "ps2")))
  "Run @var{gpm}, the general-purpose mouse daemon, with the given
command-line @var{options}.  GPM allows users to use the mouse in the console,
notably to select, copy, and paste text.  The default value of @var{options}
uses the @code{ps2} protocol, which works for both USB and PS/2 mice.

This service is not part of @var{%base-services}."
  ;; To test in QEMU, use "-usbdevice mouse" and then, in the monitor, use
  ;; "info mice" and "mouse_set X" to use the right mouse.
  (service gpm-service-type
           (gpm-configuration (gpm gpm) (options options))))


(define %base-services
  ;; Convenience variable holding the basic services.
  (let ((motd (plain-file "motd" "
This is the GNU operating system, welcome!\n\n")))
    (list (console-font-service "tty1")
          (console-font-service "tty2")
          (console-font-service "tty3")
          (console-font-service "tty4")
          (console-font-service "tty5")
          (console-font-service "tty6")

          (mingetty-service (mingetty-configuration
                             (tty "tty1") (motd motd)))
          (mingetty-service (mingetty-configuration
                             (tty "tty2") (motd motd)))
          (mingetty-service (mingetty-configuration
                             (tty "tty3") (motd motd)))
          (mingetty-service (mingetty-configuration
                             (tty "tty4") (motd motd)))
          (mingetty-service (mingetty-configuration
                             (tty "tty5") (motd motd)))
          (mingetty-service (mingetty-configuration
                             (tty "tty6") (motd motd)))

          (static-networking-service "lo" "127.0.0.1"
                                     #:provision '(loopback))
          (syslog-service)
          (guix-service)
          (nscd-service)

          ;; The LVM2 rules are needed as soon as LVM2 or the device-mapper is
          ;; used, so enable them by default.  The FUSE and ALSA rules are
          ;; less critical, but handy.
          (udev-service #:rules (list lvm2 fuse alsa-utils crda)))))

;;; base.scm ends here
