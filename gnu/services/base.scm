;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Alex Kost <alezost@gmail.com>
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
  #:use-module (gnu services networking)
  #:use-module (gnu system shadow)                ; 'user-account', etc.
  #:use-module (gnu system linux)                 ; 'pam-service', etc.
  #:use-module (gnu packages admin)
  #:use-module ((gnu packages linux)
                #:select (eudev kbd e2fsprogs lvm2 fuse alsa-utils crda))
  #:use-module ((gnu packages base)
                #:select (canonical-package glibc))
  #:use-module (gnu packages package-management)
  #:use-module (gnu packages lsh)
  #:use-module (gnu packages lsof)
  #:use-module ((gnu build file-systems)
                #:select (mount-flags->bit-mask))
  #:use-module (guix gexp)
  #:use-module (guix monads)
  #:use-module (guix records)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)
  #:use-module (ice-9 format)
  #:export (root-file-system-service
            file-system-service
            user-unmount-service
            device-mapping-service
            swap-service
            user-processes-service
            host-name-service
            console-keymap-service
            console-font-service
            udev-service
            mingetty-service

            %nscd-default-caches
            %nscd-default-configuration

            nscd-configuration
            nscd-configuration?

            nscd-cache
            nscd-cache?

            nscd-service
            syslog-service
            guix-service
            %base-services))

;;; Commentary:
;;;
;;; Base system services---i.e., services that 99% of the users will want to
;;; use.
;;;
;;; Code:

(define (root-file-system-service)
  "Return a service whose sole purpose is to re-mount read-only the root file
system upon shutdown (aka. cleanly \"umounting\" root.)

This service must be the root of the service dependency graph so that its
'stop' action is invoked when dmd is the only process left."
  (with-monad %store-monad
    (return
     (service
      (documentation "Take care of the root file system.")
      (provision '(root-file-system))
      (start #~(const #t))
      (stop #~(lambda _
                ;; Return #f if successfully stopped.
                (sync)

                (call-with-blocked-asyncs
                 (lambda ()
                   (let ((null (%make-void-port "w")))
                     ;; Close 'dmd.log'.
                     (display "closing log\n")
                     ;; XXX: Ideally we'd use 'stop-logging', but that one
                     ;; doesn't actually close the port as of dmd 0.1.
                     (close-port (@@ (dmd comm) log-output-port))
                     (set! (@@ (dmd comm) log-output-port) null)

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
      (respawn? #f)))))

(define* (file-system-service device target type
                              #:key (flags '()) (check? #t)
                              create-mount-point? options (title 'any)
                              (requirements '()))
  "Return a service that mounts DEVICE on TARGET as a file system TYPE with
OPTIONS.  TITLE is a symbol specifying what kind of name DEVICE is: 'label for
a partition label, 'device for a device file name, or 'any.  When CHECK? is
true, check the file system before mounting it.  When CREATE-MOUNT-POINT? is
true, create TARGET if it does not exist yet.  FLAGS is a list of symbols,
such as 'read-only' etc.  Optionally, REQUIREMENTS may be a list of service
names such as device-mapping services."
  (with-monad %store-monad
    (return
     (service
      (provision (list (symbol-append 'file-system- (string->symbol target))))
      (requirement `(root-file-system ,@requirements))
      (documentation "Check, mount, and unmount the given file system.")
      (start #~(lambda args
                 ;; FIXME: Use or factorize with 'mount-file-system'.
                 (let ((device (canonicalize-device-spec #$device '#$title))
                       (flags  #$(mount-flags->bit-mask flags)))
                   #$(if create-mount-point?
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

                   (mount device #$target #$type flags #$options)

                   ;; For read-only bind mounts, an extra remount is needed,
                   ;; as per <http://lwn.net/Articles/281157/>, which still
                   ;; applies to Linux 4.0.
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
                #f))))))

(define (user-unmount-service known-mount-points)
  "Return a service whose sole purpose is to unmount file systems not listed
in KNOWN-MOUNT-POINTS when it is stopped."
  (with-monad %store-monad
    (return
     (service
      (documentation "Unmount manually-mounted file systems.")
      (provision '(user-unmount))
      (start #~(const #t))
      (stop #~(lambda args
                (define (known? mount-point)
                  (member mount-point
                          (cons* "/proc" "/sys"
                                 '#$known-mount-points)))

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

(define %do-not-kill-file
  ;; Name of the file listing PIDs of processes that must survive when halting
  ;; the system.  Typical example is user-space file systems.
  "/etc/dmd/do-not-kill")

(define* (user-processes-service requirements #:key (grace-delay 4))
  "Return the service that is responsible for terminating all the processes so
that the root file system can be re-mounted read-only, just before
rebooting/halting.  Processes still running GRACE-DELAY seconds after SIGTERM
has been sent are terminated with SIGKILL.

The returned service will depend on 'root-file-system' and on all the services
listed in REQUIREMENTS.

All the services that spawn processes must depend on this one so that they are
stopped before 'kill' is called."
  (with-monad %store-monad
    (return (service
             (documentation "When stopped, terminate all user processes.")
             (provision '(user-processes))
             (requirement (cons 'root-file-system requirements))
             (start #~(const #t))
             (stop #~(lambda _
                       (define (kill-except omit signal)
                         ;; Kill all the processes with SIGNAL except those
                         ;; listed in OMIT and the current process.
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
                             ;; Kill them all except OMITTED-PIDS.  XXX: We
                             ;; would like to (kill -1 SIGSTOP) to get a fixed
                             ;; list of processes, like 'killall5' does, but
                             ;; that seems unreliable.
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
             (respawn? #f)))))

(define (host-name-service name)
  "Return a service that sets the host name to @var{name}."
  (with-monad %store-monad
    (return (service
             (documentation "Initialize the machine's host name.")
             (provision '(host-name))
             (start #~(lambda _
                        (sethostname #$name)))
             (respawn? #f)))))

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

(define (console-keymap-service file)
  "Return a service to load console keymap from @var{file}."
  (with-monad %store-monad
    (return
     (service
      (documentation
       (string-append "Load console keymap (loadkeys)."))
      (provision '(console-keymap))
      (start #~(lambda _
                 (zero? (system* (string-append #$kbd "/bin/loadkeys")
                                 #$file))))
      (respawn? #f)))))

(define* (console-font-service tty #:optional (font "LatGrkCyr-8x16"))
  "Return a service that sets up Unicode support in @var{tty} and loads
@var{font} for that tty (fonts are per virtual console in Linux.)"
  ;; Note: 'LatGrkCyr-8x16' has the advantage of providing three common
  ;; scripts as well as glyphs for em dash, quotation marks, and other Unicode
  ;; codepoints notably found in the UTF-8 manual.
  (let ((device (string-append "/dev/" tty)))
    (with-monad %store-monad
      (return (service
               (documentation "Load a Unicode console font.")
               (provision (list (symbol-append 'console-font-
                                               (string->symbol tty))))

               ;; Start after mingetty has been started on TTY, otherwise the
               ;; settings are ignored.
               (requirement (list (symbol-append 'term-
                                                 (string->symbol tty))))

               (start #~(lambda _
                          (and #$(unicode-start device)
                               (zero?
                                (system* (string-append #$kbd "/bin/setfont")
                                         "-C" #$device #$font)))))
               (stop #~(const #t))
               (respawn? #f))))))

(define* (mingetty-service tty
                           #:key
                           (motd (text-file "motd" "Welcome.\n"))
                           auto-login
                           login-program
                           login-pause?

                           ;; Allow empty passwords by default so that
                           ;; first-time users can log in when the 'root'
                           ;; account has just been created.
                           (allow-empty-passwords? #t)
                           (additional-session-modules '()))
  "Return a service to run mingetty on @var{tty}.

When @var{allow-empty-passwords?} is true, allow empty log-in password.  When
@var{auto-login} is true, it must be a user name under which to log-in
automatically.  @var{login-pause?} can be set to @code{#t} in conjunction with
@var{auto-login}, in which case the user will have to press a key before the
login shell is launched.

When true, @var{login-program} is a gexp or a monadic gexp denoting the name
of the log-in program (the default is the @code{login} program from the Shadow
tool suite.)

@var{motd} is a monadic value containing a text file to use as
the ``message of the day''."
  (mlet %store-monad ((motd motd)
                      (login-program (cond ((gexp? login-program)
                                            (return login-program))
                                           ((not login-program)
                                            (return #f))
                                           (else
                                            login-program))))
    (return
     (service
      (documentation (string-append "Run mingetty on " tty "."))
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
      (stop   #~(make-kill-destructor))

      (pam-services
       ;; Let 'login' be known to PAM.  All the mingetty services will have
       ;; that PAM service, but that's fine because they're all identical and
       ;; duplicates are removed.
       (list (unix-pam-service "login"
                               #:allow-empty-passwords? allow-empty-passwords?
                               #:motd motd
                               #:additional-session-modules additional-session-modules)))))))

(define-record-type* <nscd-configuration> nscd-configuration
  make-nscd-configuration
  nscd-configuration?
  (log-file    nscd-configuration-log-file        ;string
               (default "/var/log/nscd.log"))
  (debug-level nscd-debug-level                   ;integer
               (default 0))
  ;; TODO: See nscd.conf in glibc for other options to add.
  (caches     nscd-configuration-caches           ;list of <nscd-cache>
              (default %nscd-default-caches)))

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
     (text-file "nscd.conf"
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

(define* (nscd-service #:optional (config %nscd-default-configuration)
                       #:key (glibc (canonical-package glibc))
                       (name-services '()))
  "Return a service that runs libc's name service cache daemon (nscd) with the
given @var{config}---an @code{<nscd-configuration>} object.  Optionally,
@code{#:name-services} is a list of packages that provide name service switch
 (NSS) modules needed by nscd.  @xref{Name Service Switch}, for an example."
  (mlet %store-monad ((nscd.conf (nscd.conf-file config)))
    (return (service
             (documentation "Run libc's name service cache daemon (nscd).")
             (provision '(nscd))
             (requirement '(user-processes))

             (activate #~(begin
                           (use-modules (guix build utils))
                           (mkdir-p "/var/run/nscd")
                           (mkdir-p "/var/db/nscd"))) ;for the persistent cache

             (start #~(make-forkexec-constructor
                       (list (string-append #$glibc "/sbin/nscd")
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

(define* (syslog-service #:key config-file)
  "Return a service that runs @code{syslogd}.
If configuration file name @var{config-file} is not specified, use some
reasonable default settings."

  ;; Snippet adapted from the GNU inetutils manual.
  (define contents "
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
")

  (mlet %store-monad
      ((syslog.conf (text-file "syslog.conf" contents)))
    (return
     (service
      (documentation "Run the syslog daemon (syslogd).")
      (provision '(syslogd))
      (requirement '(user-processes))
      (start
       #~(make-forkexec-constructor
          (list (string-append #$inetutils "/libexec/syslogd")
                "--no-detach" "--rcfile" #$(or config-file syslog.conf))))
      (stop #~(make-kill-destructor))))))

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

(define* (guix-service #:key (guix guix) (builder-group "guixbuild")
                       (build-accounts 10) (authorize-hydra-key? #t)
                       (use-substitutes? #t)
                       (extra-options '())
                       (lsof lsof) (lsh lsh))
  "Return a service that runs the build daemon from @var{guix}, and has
@var{build-accounts} user accounts available under @var{builder-group}.

When @var{authorize-hydra-key?} is true, the @code{hydra.gnu.org} public key
provided by @var{guix} is authorized upon activation, meaning that substitutes
from @code{hydra.gnu.org} are used by default.

If @var{use-substitutes?} is false, the daemon is run with
@option{--no-substitutes} (@pxref{Invoking guix-daemon,
@option{--no-substitutes}}).

Finally, @var{extra-options} is a list of additional command-line options
passed to @command{guix-daemon}."
  (define activate
    ;; Assume that the store has BUILDER-GROUP as its group.  We could
    ;; otherwise call 'chown' here, but the problem is that on a COW unionfs,
    ;; chown leads to an entire copy of the tree, which is a bad idea.

    ;; Optionally authorize hydra.gnu.org's key.
    (and authorize-hydra-key?
         (hydra-key-authorization guix)))

  (with-monad %store-monad
    (return (service
             (documentation "Run the Guix daemon.")
             (provision '(guix-daemon))
             (requirement '(user-processes))
             (start
              #~(make-forkexec-constructor
                 (list (string-append #$guix "/bin/guix-daemon")
                       "--build-users-group" #$builder-group
                       #$@(if use-substitutes?
                              '()
                              '("--no-substitutes"))
                       #$@extra-options)

                 ;; Add 'lsof' (for the GC) and 'lsh' (for offloading) to the
                 ;; daemon's $PATH.
                 #:environment-variables
                 (list (string-append "PATH=" #$lsof "/bin:"
                                      #$lsh "/bin"))))
             (stop #~(make-kill-destructor))
             (user-accounts (guix-build-accounts build-accounts
                                                 #:group builder-group))
             (user-groups (list (user-group
                                 (name builder-group)
                                 (system? #t)

                                 ;; Use a fixed GID so that we can create the
                                 ;; store with the right owner.
                                 (id 30000))))
             (activate activate)))))

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

  (gexp->derivation "udev-rules" build
                    #:modules '((guix build union)
                                (guix build utils))
                    #:local-build? #t))

(define* (kvm-udev-rule)
  "Return a directory with a udev rule that changes the group of
@file{/dev/kvm} to \"kvm\" and makes it #o660."
  ;; Apparently QEMU-KVM used to ship this rule, but now we have to add it by
  ;; ourselves.
  (gexp->derivation "kvm-udev-rules"
                    #~(begin
                        (use-modules (guix build utils))

                        (define rules.d
                          (string-append #$output "/lib/udev/rules.d"))

                        (mkdir-p rules.d)
                        (call-with-output-file
                            (string-append rules.d "/90-kvm.rules")
                          (lambda (port)
                            ;; Build users are part of the "kvm" group, so we
                            ;; can fearlessly make /dev/kvm 660 (see
                            ;; <http://bugs.gnu.org/18994>, for background.)
                            (display "\
KERNEL==\"kvm\", GROUP=\"kvm\", MODE=\"0660\"\n" port))))
                    #:modules '((guix build utils))))

(define* (udev-service #:key (udev eudev) (rules '()))
  "Run @var{udev}, which populates the @file{/dev} directory dynamically.  Get
extra rules from the packages listed in @var{rules}."
  (mlet* %store-monad ((kvm       (kvm-udev-rule))
                       (rules     (udev-rules-union (cons* udev kvm rules)))
                       (udev.conf (text-file* "udev.conf"
                                              "udev_rules=\"" rules
                                              "/lib/udev/rules.d\"\n")))
    (return (service
             (provision '(udev))

             ;; Udev needs /dev to be a 'devtmpfs' mount so that new device
             ;; nodes can be added: see
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
             ;; 'user-processes', i.e., before its own 'stop' method was
             ;; called.  Thus, make sure it is not respawned.
             (respawn? #f)))))

(define (device-mapping-service target open close)
  "Return a service that maps device @var{target}, a string such as
@code{\"home\"} (meaning @code{/dev/mapper/home}).  Evaluate @var{open}, a
gexp, to open it, and evaluate @var{close} to close it."
  (with-monad %store-monad
    (return (service
             (provision (list (symbol-append 'device-mapping-
                                             (string->symbol target))))
             (requirement '(udev))
             (documentation "Map a device node using Linux's device mapper.")
             (start #~(lambda () #$open))
             (stop #~(lambda _ (not #$close)))
             (respawn? #f)))))

(define (swap-service device)
  "Return a service that uses @var{device} as a swap device."
  (define requirement
    (if (string-prefix? "/dev/mapper/" device)
        (list (symbol-append 'device-mapping-
                             (string->symbol (basename device))))
        '()))

  (with-monad %store-monad
    (return (service
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

(define %base-services
  ;; Convenience variable holding the basic services.
  (let ((motd (text-file "motd" "
This is the GNU operating system, welcome!\n\n")))
    (list (console-font-service "tty1")
          (console-font-service "tty2")
          (console-font-service "tty3")
          (console-font-service "tty4")
          (console-font-service "tty5")
          (console-font-service "tty6")

          (mingetty-service "tty1" #:motd motd)
          (mingetty-service "tty2" #:motd motd)
          (mingetty-service "tty3" #:motd motd)
          (mingetty-service "tty4" #:motd motd)
          (mingetty-service "tty5" #:motd motd)
          (mingetty-service "tty6" #:motd motd)
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
