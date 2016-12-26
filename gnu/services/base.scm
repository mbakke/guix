;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015, 2016 Alex Kost <alezost@gmail.com>
;;; Copyright © 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Sou Bunnbu <iyzsong@gmail.com>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
;;; Copyright © 2016 David Craven <david@craven.ch>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
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
  #:use-module (gnu system mapped-devices)
  #:use-module (gnu packages admin)
  #:use-module ((gnu packages linux)
                #:select (alsa-utils crda eudev e2fsprogs fuse gpm kbd lvm2 rng-tools))
  #:use-module ((gnu packages base)
                #:select (canonical-package glibc))
  #:use-module (gnu packages package-management)
  #:use-module (gnu packages lsof)
  #:use-module (gnu packages terminals)
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
            file-system-service-type
            user-unmount-service
            swap-service
            user-processes-service
            session-environment-service
            session-environment-service-type
            host-name-service
            console-keymap-service
            %default-console-font
            console-font-service-type
            console-font-service

            udev-configuration
            udev-configuration?
            udev-configuration-rules
            udev-service-type
            udev-service
            udev-rule

            login-configuration
            login-configuration?
            login-service-type
            login-service

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

            syslog-configuration
            syslog-configuration?
            syslog-service
            syslog-service-type
            %default-syslog.conf

            %default-authorized-guix-keys
            guix-configuration
            guix-configuration?
            guix-service
            guix-service-type
            guix-publish-configuration
            guix-publish-configuration?
            guix-publish-service
            guix-publish-service-type

            gpm-configuration
            gpm-configuration?
            gpm-service-type
            gpm-service

            urandom-seed-service-type
            urandom-seed-service

            rngd-configuration
            rngd-configuration?
            rngd-service-type
            rngd-service

            kmscon-configuration
            kmscon-configuration?
            kmscon-service-type

            pam-limits-service-type
            pam-limits-service

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
                (compose concatenate)
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
  "Return the shepherd service for @var{file-system}, or @code{#f} if
@var{file-system} is not auto-mounted upon boot."
  (let ((target  (file-system-mount-point file-system))
        (device  (file-system-device file-system))
        (type    (file-system-type file-system))
        (title   (file-system-title file-system))
        (flags   (file-system-flags file-system))
        (options (file-system-options file-system))
        (check?  (file-system-check? file-system))
        (create? (file-system-create-mount-point? file-system))
        (dependencies (file-system-dependencies file-system)))
    (and (file-system-mount? file-system)
         (with-imported-modules '((gnu build file-systems)
                                  (guix build bournish))
           (shepherd-service
            (provision (list (file-system->shepherd-service-name file-system)))
            (requirement `(root-file-system
                           ,@(map dependency->shepherd-service-name dependencies)))
            (documentation "Check, mount, and unmount the given file system.")
            (start #~(lambda args
		       #$(if create?
                             #~(mkdir-p #$target)
                             #t)

                       (let (($PATH (getenv "PATH")))
                         ;; Make sure fsck.ext2 & co. can be found.
                         (dynamic-wind
                           (lambda ()
                             (setenv "PATH"
                                     (string-append
                                      #$e2fsprogs "/sbin:"
                                      "/run/current-system/profile/sbin:"
                                      $PATH)))
                           (lambda ()
                             (mount-file-system
                              `(#$device #$title #$target #$type #$flags
                                         #$options #$check?)
                              #:root "/"))
                           (lambda ()
                             (setenv "PATH" $PATH)))
                         #t)))
            (stop #~(lambda args
                      ;; Normally there are no processes left at this point, so
                      ;; TARGET can be safely unmounted.

                      ;; Make sure PID 1 doesn't keep TARGET busy.
                      (chdir "/")

                      (umount #$target)
                      #f))

            ;; We need an additional module.
            (modules `(((gnu build file-systems)
                        #:select (mount-file-system))
                       ,@%default-modules)))))))

(define file-system-service-type
  (service-type (name 'file-systems)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          (lambda (file-systems)
                                            (filter-map file-system-shepherd-service
                                                        file-systems)))
                       (service-extension fstab-service-type
                                          identity)))
                (compose concatenate)
                (extend append)))

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
;;; Preserve entropy to seed /dev/urandom on boot.
;;;

(define %random-seed-file
  "/var/lib/random-seed")

(define (urandom-seed-shepherd-service _)
  "Return a shepherd service for the /dev/urandom seed."
  (list (shepherd-service
         (documentation "Preserve entropy across reboots for /dev/urandom.")
         (provision '(urandom-seed))
         (requirement '(user-processes))
         (start #~(lambda _
                    ;; On boot, write random seed into /dev/urandom.
                    (when (file-exists? #$%random-seed-file)
                      (call-with-input-file #$%random-seed-file
                        (lambda (seed)
                          (call-with-output-file "/dev/urandom"
                            (lambda (urandom)
                              (dump-port seed urandom))))))
                    ;; Immediately refresh the seed in case the system doesn't
                    ;; shut down cleanly.
                    (call-with-input-file "/dev/urandom"
                      (lambda (urandom)
                        (let ((previous-umask (umask #o077))
                              (buf (make-bytevector 512)))
                          (mkdir-p (dirname #$%random-seed-file))
                          (get-bytevector-n! urandom buf 0 512)
                          (call-with-output-file #$%random-seed-file
                            (lambda (seed)
                              (put-bytevector seed buf)))
                          (umask previous-umask))))
                    #t))
         (stop #~(lambda _
                   ;; During shutdown, write from /dev/urandom into random seed.
                   (let ((buf (make-bytevector 512)))
                     (call-with-input-file "/dev/urandom"
                       (lambda (urandom)
                         (let ((previous-umask (umask #o077)))
                           (get-bytevector-n! urandom buf 0 512)
                           (mkdir-p (dirname #$%random-seed-file))
                           (call-with-output-file #$%random-seed-file
                             (lambda (seed)
                               (put-bytevector seed buf)))
                           (umask previous-umask))
                         #t)))))
         (modules `((rnrs bytevectors)
                    (rnrs io ports)
                    ,@%default-modules)))))

(define urandom-seed-service-type
  (service-type (name 'urandom-seed)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          urandom-seed-shepherd-service)))))

(define (urandom-seed-service)
  (service urandom-seed-service-type #f))


;;;
;;; Add hardware random number generator to entropy pool.
;;;

(define-record-type* <rngd-configuration>
  rngd-configuration make-rngd-configuration
  rngd-configuration?
  (rng-tools rngd-configuration-rng-tools)        ;package
  (device    rngd-configuration-device))          ;string

(define rngd-service-type
  (shepherd-service-type
    'rngd
    (lambda (config)
      (define rng-tools (rngd-configuration-rng-tools config))
      (define device (rngd-configuration-device config))

      (define rngd-command
        (list (file-append rng-tools "/sbin/rngd")
              "-f" "-r" device))

      (shepherd-service
        (documentation "Add TRNG to entropy pool.")
        (requirement '(udev))
        (provision '(trng))
        (start #~(make-forkexec-constructor #$@rngd-command))
        (stop #~(make-kill-destructor))))))

(define* (rngd-service #:key
                       (rng-tools rng-tools)
                       (device "/dev/hwrng"))
  "Return a service that runs the @command{rngd} program from @var{rng-tools}
to add @var{device} to the kernel's entropy pool.  The service will fail if
@var{device} does not exist."
  (service rngd-service-type
           (rngd-configuration
            (rng-tools rng-tools)
            (device device))))


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
           (execl #$(file-append kbd "/bin/unicode_start")
                  "unicode_start"))
          (else
           (zero? (cdr (waitpid pid))))))))

(define console-keymap-service-type
  (shepherd-service-type
   'console-keymap
   (lambda (files)
     (shepherd-service
      (documentation (string-append "Load console keymap (loadkeys)."))
      (provision '(console-keymap))
      (start #~(lambda _
                 (zero? (system* #$(file-append kbd "/bin/loadkeys")
                                 #$@files))))
      (respawn? #f)))))

(define (console-keymap-service . files)
  "Return a service to load console keymaps from @var{files}."
  (service console-keymap-service-type files))

(define %default-console-font
  ;; Note: 'LatGrkCyr-8x16' has the advantage of providing three common
  ;; scripts as well as glyphs for em dash, quotation marks, and other Unicode
  ;; codepoints notably found in the UTF-8 manual.
  "LatGrkCyr-8x16")

(define (console-font-shepherd-services tty+font)
  "Return a list of Shepherd services for each pair in TTY+FONT."
  (map (match-lambda
         ((tty . font)
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
                              (system* #$(file-append kbd "/bin/setfont")
                                       "-C" #$device #$font)))))
             (stop #~(const #t))
             (respawn? #f)))))
       tty+font))

(define console-font-service-type
  (service-type (name 'console-fonts)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          console-font-shepherd-services)))
                (compose concatenate)
                (extend append)))

(define* (console-font-service tty #:optional (font "LatGrkCyr-8x16"))
  "This procedure is deprecated in favor of @code{console-font-service-type}.

Return a service that sets up Unicode support in @var{tty} and loads
@var{font} for that tty (fonts are per virtual console in Linux.)"
  (simple-service (symbol-append 'console-font- (string->symbol tty))
                  console-font-service-type `((,tty . ,font))))

(define %default-motd
  (plain-file "motd" "This is the GNU operating system, welcome!\n\n"))

(define-record-type* <login-configuration>
  login-configuration make-login-configuration
  login-configuration?
  (motd                   login-configuration-motd     ;file-like
                          (default %default-motd))
  ;; Allow empty passwords by default so that first-time users can log in when
  ;; the 'root' account has just been created.
  (allow-empty-passwords? login-configuration-allow-empty-passwords?
                          (default #t)))               ;Boolean

(define (login-pam-service config)
  "Return the list of PAM service needed for CONF."
  ;; Let 'login' be known to PAM.
  (list (unix-pam-service "login"
                          #:allow-empty-passwords?
                          (login-configuration-allow-empty-passwords? config)
                          #:motd
                          (login-configuration-motd config))))

(define login-service-type
  (service-type (name 'login)
                (extensions (list (service-extension pam-root-service-type
                                                     login-pam-service)))))

(define* (login-service #:optional (config (login-configuration)))
  "Return a service configure login according to @var{config}, which specifies
the message of the day, among other things."
  (service login-service-type config))

(define-record-type* <mingetty-configuration>
  mingetty-configuration make-mingetty-configuration
  mingetty-configuration?
  (mingetty       mingetty-configuration-mingetty ;<package>
                  (default mingetty))
  (tty            mingetty-configuration-tty)     ;string
  (auto-login     mingetty-auto-login             ;string | #f
                  (default #f))
  (login-program  mingetty-login-program          ;gexp
                  (default #f))
  (login-pause?   mingetty-login-pause?           ;Boolean
                  (default #f)))

(define mingetty-shepherd-service
  (match-lambda
    (($ <mingetty-configuration> mingetty tty auto-login login-program
                                 login-pause?)
     (list
      (shepherd-service
       (documentation "Run mingetty on an tty.")
       (provision (list (symbol-append 'term- (string->symbol tty))))

       ;; Since the login prompt shows the host name, wait for the 'host-name'
       ;; service to be done.  Also wait for udev essentially so that the tty
       ;; text is not lost in the middle of kernel messages (XXX).
       (requirement '(user-processes host-name udev))

       (start  #~(make-forkexec-constructor
                  (list #$(file-append mingetty "/sbin/mingetty")
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
                                                     mingetty-shepherd-service)))))

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
                     (list #$(file-append (nscd-configuration-glibc config)
                                          "/sbin/nscd")
                           "-f" #$nscd.conf "--foreground")

                     ;; Wait for the PID file.  However, the PID file is
                     ;; written before nscd is actually listening on its
                     ;; socket (XXX).
                     #:pid-file "/var/run/nscd/nscd.pid"

                     #:environment-variables
                     (list (string-append "LD_LIBRARY_PATH="
                                          (string-join
                                           (map (lambda (dir)
                                                  (string-append dir "/lib"))
                                                (list #$@name-services))
                                           ":")))))
           (stop #~(make-kill-destructor))))))

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


(define-record-type* <syslog-configuration>
  syslog-configuration  make-syslog-configuration
  syslog-configuration?
  (syslogd              syslog-configuration-syslogd
                        (default (file-append inetutils "/libexec/syslogd")))
  (config-file          syslog-configuration-config-file
                        (default %default-syslog.conf)))

(define syslog-service-type
  (shepherd-service-type
   'syslog
   (lambda (config)
     (shepherd-service
      (documentation "Run the syslog daemon (syslogd).")
      (provision '(syslogd))
      (requirement '(user-processes))
      (start #~(make-forkexec-constructor
                (list #$(syslog-configuration-syslogd config)
                      "--rcfile" #$(syslog-configuration-config-file config))
                #:pid-file "/var/run/syslog.pid"))
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

(define* (syslog-service #:optional (config (syslog-configuration)))
  "Return a service that runs @command{syslogd} and takes
@var{<syslog-configuration>} as a parameter.

@xref{syslogd invocation,,, inetutils, GNU Inetutils}, for more
information on the configuration file syntax."
  (service syslog-service-type config))


(define pam-limits-service-type
  (let ((security-limits
         ;; Create /etc/security containing the provided "limits.conf" file.
         (lambda (limits-file)
           `(("security"
              ,(computed-file
                "security"
                #~(begin
                    (mkdir #$output)
                    (stat #$limits-file)
                    (symlink #$limits-file
                             (string-append #$output "/limits.conf"))))))))
        (pam-extension
         (lambda (pam)
           (let ((pam-limits (pam-entry
                              (control "required")
                              (module "pam_limits.so")
                              (arguments '("conf=/etc/security/limits.conf")))))
             (if (member (pam-service-name pam)
                         '("login" "su" "slim"))
                 (pam-service
                  (inherit pam)
                  (session (cons pam-limits
                                 (pam-service-session pam))))
                 pam)))))
    (service-type
     (name 'limits)
     (extensions
      (list (service-extension etc-service-type security-limits)
            (service-extension pam-root-service-type
                               (lambda _ (list pam-extension))))))))

(define* (pam-limits-service #:optional (limits '()))
  "Return a service that makes selected programs respect the list of
pam-limits-entry specified in LIMITS via pam_limits.so."
  (service pam-limits-service-type
           (plain-file "limits.conf"
                       (string-join (map pam-limits-entry->string limits)
                                    "\n"))))


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
             (shell (file-append shadow "/sbin/nologin"))))
          1+
          1))

(define (hydra-key-authorization key guix)
  "Return a gexp with code to register KEY, a file containing a 'guix archive'
public key, with GUIX."
  #~(unless (file-exists? "/etc/guix/acl")
      (let ((pid (primitive-fork)))
        (case pid
          ((0)
           (let* ((key  #$key)
                  (port (open-file key "r0b")))
             (format #t "registering public key '~a'...~%" key)
             (close-port (current-input-port))
             (dup port 0)
             (execl #$(file-append guix "/bin/guix")
                    "guix" "archive" "--authorize")
             (exit 1)))
          (else
           (let ((status (cdr (waitpid pid))))
             (unless (zero? status)
               (format (current-error-port) "warning: \
failed to register hydra.gnu.org public key: ~a~%" status))))))))

(define %default-authorized-guix-keys
  ;; List of authorized substitute keys.
  (list (file-append guix "/share/guix/hydra.gnu.org.pub")))

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
  (authorized-keys  guix-configuration-authorized-keys ;list of gexps
                    (default %default-authorized-guix-keys))
  (use-substitutes? guix-configuration-use-substitutes? ;Boolean
                    (default #t))
  (substitute-urls  guix-configuration-substitute-urls ;list of strings
                    (default %default-substitute-urls))
  (extra-options    guix-configuration-extra-options ;list of strings
                    (default '()))
  (log-file         guix-configuration-log-file   ;string
                    (default "/var/log/guix-daemon.log"))
  (lsof             guix-configuration-lsof       ;<package>
                    (default lsof)))

(define %default-guix-configuration
  (guix-configuration))

(define (guix-shepherd-service config)
  "Return a <shepherd-service> for the Guix daemon service with CONFIG."
  (match config
    (($ <guix-configuration> guix build-group build-accounts
                             authorize-key? keys
                             use-substitutes? substitute-urls extra-options
                             log-file lsof)
     (list (shepherd-service
            (documentation "Run the Guix daemon.")
            (provision '(guix-daemon))
            (requirement '(user-processes))
            (start
             #~(make-forkexec-constructor
                (list #$(file-append guix "/bin/guix-daemon")
                      "--build-users-group" #$build-group
                      #$@(if use-substitutes?
                             '()
                             '("--no-substitutes"))
                      "--substitute-urls" #$(string-join substitute-urls)
                      #$@extra-options)

                ;; Add 'lsof' (for the GC) to the daemon's $PATH.
                #:environment-variables
                (list (string-append "PATH=" #$lsof "/bin"))

                #:log-file #$log-file))
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
    (($ <guix-configuration> guix build-group build-accounts authorize-key? keys)
     ;; Assume that the store has BUILD-GROUP as its group.  We could
     ;; otherwise call 'chown' here, but the problem is that on a COW unionfs,
     ;; chown leads to an entire copy of the tree, which is a bad idea.

     ;; Optionally authorize hydra.gnu.org's key.
     (if authorize-key?
         #~(begin
             #$@(map (cut hydra-key-authorization <> guix) keys))
         #~#f))))

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
                      (list #$(file-append guix "/bin/guix")
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
         (shell (file-append shadow "/sbin/nologin")))))

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
    (with-imported-modules '((guix build union)
                             (guix build utils))
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
                       (filter-map rules-sub-directory '#$packages)))))

  (computed-file "udev-rules" build))

(define (udev-rule file-name contents)
  "Return a directory with a udev rule file FILE-NAME containing CONTENTS."
  (computed-file file-name
                 (with-imported-modules '((guix build utils))
                   #~(begin
                       (use-modules (guix build utils))

                       (define rules.d
                         (string-append #$output "/lib/udev/rules.d"))

                       (mkdir-p rules.d)
                       (call-with-output-file
                           (string-append rules.d "/" #$file-name)
                         (lambda (port)
                           (display #$contents port)))))))

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
                            #$(file-append rules "/lib/udev/rules.d"))

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
                         (system* #$(file-append udev "/bin/udevadm")
                                  "trigger" "--action=add")

                         ;; Wait for things to settle down.
                         (system* #$(file-append udev "/bin/udevadm")
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
                       (fork+exec-command (list #$(file-append gpm "/sbin/gpm")
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
                      (not (zero? (system* #$(file-append gpm "/sbin/gpm")
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

(define-record-type* <kmscon-configuration>
  kmscon-configuration     make-kmscon-configuration
  kmscon-configuration?
  (kmscon                  kmscon-configuration-kmscon
                           (default kmscon))
  (virtual-terminal        kmscon-configuration-virtual-terminal)
  (login-program           kmscon-configuration-login-program
                           (default (file-append shadow "/bin/login")))
  (login-arguments         kmscon-configuration-login-arguments
                           (default '("-p")))
  (hardware-acceleration?  kmscon-configuration-hardware-acceleration?
                           (default #f))) ; #t causes failure

(define kmscon-service-type
  (shepherd-service-type
   'kmscon
   (lambda (config)
     (let ((kmscon (kmscon-configuration-kmscon config))
           (virtual-terminal (kmscon-configuration-virtual-terminal config))
           (login-program (kmscon-configuration-login-program config))
           (login-arguments (kmscon-configuration-login-arguments config))
           (hardware-acceleration? (kmscon-configuration-hardware-acceleration? config)))

       (define kmscon-command
         #~(list
            #$(file-append kmscon "/bin/kmscon") "--login"
            "--vt" #$virtual-terminal
            #$@(if hardware-acceleration? '("--hwaccel") '())
            "--" #$login-program #$@login-arguments))

       (shepherd-service
        (documentation "kmscon virtual terminal")
        (requirement '(user-processes udev dbus-system))
        (provision (list (symbol-append 'term- (string->symbol virtual-terminal))))
        (start #~(make-forkexec-constructor #$kmscon-command))
        (stop #~(make-kill-destructor)))))))


(define %base-services
  ;; Convenience variable holding the basic services.
  (list (login-service)

        (service console-font-service-type
                 (map (lambda (tty)
                        (cons tty %default-console-font))
                      '("tty1" "tty2" "tty3" "tty4" "tty5" "tty6")))

        (mingetty-service (mingetty-configuration
                           (tty "tty1")))
        (mingetty-service (mingetty-configuration
                           (tty "tty2")))
        (mingetty-service (mingetty-configuration
                           (tty "tty3")))
        (mingetty-service (mingetty-configuration
                           (tty "tty4")))
        (mingetty-service (mingetty-configuration
                           (tty "tty5")))
        (mingetty-service (mingetty-configuration
                           (tty "tty6")))

        (static-networking-service "lo" "127.0.0.1"
                                   #:provision '(loopback))
        (syslog-service)
        (urandom-seed-service)
        (guix-service)
        (nscd-service)

        ;; The LVM2 rules are needed as soon as LVM2 or the device-mapper is
        ;; used, so enable them by default.  The FUSE and ALSA rules are
        ;; less critical, but handy.
        (udev-service #:rules (list lvm2 fuse alsa-utils crda))))

;;; base.scm ends here
