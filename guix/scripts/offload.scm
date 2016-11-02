;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (guix scripts offload)
  #:use-module (ssh key)
  #:use-module (ssh auth)
  #:use-module (ssh session)
  #:use-module (ssh channel)
  #:use-module (guix config)
  #:use-module (guix records)
  #:use-module (guix store)
  #:use-module (guix derivations)
  #:use-module ((guix serialization)
                #:select (nar-error? nar-error-file))
  #:use-module (guix nar)
  #:use-module (guix utils)
  #:use-module ((guix build syscalls) #:select (fcntl-flock))
  #:use-module ((guix build utils) #:select (which mkdir-p))
  #:use-module (guix ui)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:use-module (ice-9 popen)
  #:use-module (ice-9 rdelim)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 format)
  #:use-module (ice-9 binary-ports)
  #:export (build-machine
            build-requirements
            guix-offload))

;;; Commentary:
;;;
;;; Attempt to offload builds to the machines listed in
;;; /etc/guix/machines.scm, transferring missing dependencies over SSH, and
;;; retrieving the build output(s) over SSH upon success.
;;;
;;; This command should not be used directly; instead, it is called on-demand
;;; by the daemon, unless it was started with '--no-build-hook' or a client
;;; inhibited build hooks.
;;;
;;; Code:


(define-record-type* <build-machine>
  build-machine make-build-machine
  build-machine?
  (name            build-machine-name)            ; string
  (port            build-machine-port             ; number
                   (default 22))
  (system          build-machine-system)          ; string
  (user            build-machine-user)            ; string
  (private-key     build-machine-private-key      ; file name
                   (default (user-openssh-private-key)))
  (host-key        build-machine-host-key)        ; string
  (parallel-builds build-machine-parallel-builds  ; number
                   (default 1))
  (speed           build-machine-speed            ; inexact real
                   (default 1.0))
  (features        build-machine-features         ; list of strings
                   (default '())))

(define-record-type* <build-requirements>
  build-requirements make-build-requirements
  build-requirements?
  (system          build-requirements-system)     ; string
  (features        build-requirements-features    ; list of strings
                   (default '())))

(define %machine-file
  ;; File that lists machines available as build slaves.
  (string-append %config-directory "/machines.scm"))

(define (user-openssh-private-key)
  "Return the user's default SSH private key, or #f if it could not be
determined."
  (and=> (getenv "HOME")
         (cut string-append <> "/.ssh/id_rsa")))

(define %user-module
  ;; Module in which the machine description file is loaded.
  (let ((module (make-fresh-user-module)))
    (module-use! module (resolve-interface '(guix scripts offload)))
    module))

(define* (build-machines #:optional (file %machine-file))
  "Read the list of build machines from FILE and return it."
  (catch #t
    (lambda ()
      ;; Avoid ABI incompatibility with the <build-machine> record.
      (set! %fresh-auto-compile #t)

      (save-module-excursion
       (lambda ()
         (set-current-module %user-module)
         (primitive-load file))))
    (lambda args
      (match args
        (('system-error . rest)
         (let ((err (system-error-errno args)))
           ;; Silently ignore missing file since this is a common case.
           (if (= ENOENT err)
               '()
               (leave (_ "failed to open machine file '~a': ~a~%")
                      file (strerror err)))))
        (('syntax-error proc message properties form . rest)
         (let ((loc (source-properties->location properties)))
           (leave (_ "~a: ~a~%")
                  (location->string loc) message)))
        (x
         (leave (_ "failed to load machine file '~a': ~s~%")
                file args))))))

(define (host-key->type+key host-key)
  "Destructure HOST-KEY, an OpenSSH host key string, and return two values:
its key type as a symbol, and the actual base64-encoded string."
  (define (type->symbol type)
    (and (string-prefix? "ssh-" type)
         (string->symbol (string-drop type 4))))

  (match (string-tokenize host-key)
    ((type key _)
     (values (type->symbol type) key))
    ((type key)
     (values (type->symbol type) key))))

(define (open-ssh-session machine)
  "Open an SSH session for MACHINE and return it.  Throw an error on failure."
  (let ((private (private-key-from-file (build-machine-private-key machine)))
        (public  (public-key-from-file
                  (string-append (build-machine-private-key machine)
                                 ".pub")))
        (session (make-session #:user (build-machine-user machine)
                               #:host (build-machine-name machine)
                               #:timeout 5        ;seconds
                               ;; #:log-verbosity 'protocol
                               #:identity (build-machine-private-key machine)

                               ;; We need lightweight compression when
                               ;; exchanging full archives.
                               #:compression "zlib"
                               #:compression-level 3)))
    (connect! session)

    ;; Authenticate the server.  XXX: Guile-SSH 0.10.1 doesn't know about
    ;; ed25519 keys and 'get-key-type' returns #f in that case.
    (let-values (((server)   (get-server-public-key session))
                 ((type key) (host-key->type+key
                              (build-machine-host-key machine))))
      (unless (and (or (not (get-key-type server))
                       (eq? (get-key-type server) type))
                   (string=? (public-key->string server) key))
        ;; Key mismatch: something's wrong.  XXX: It could be that the server
        ;; provided its Ed25519 key when we where expecting its RSA key.
        (leave (_ "server at '~a' returned host key '~a' of type '~a' \
instead of '~a' of type '~a'~%")
               (build-machine-name machine)
               (public-key->string server) (get-key-type server)
               key type)))

    (let ((auth (userauth-public-key! session private)))
      (unless (eq? 'success auth)
        (leave (_ "SSH public key authentication failed: ~a~%")
               (get-error session))))

    session))

(define* (remote-pipe session command
                      #:key (quote? #t))
  "Run COMMAND (a list) on SESSION, and return an open input/output port,
which is also an SSH channel.  When QUOTE? is true, perform shell-quotation of
all the elements of COMMAND."
  (define (shell-quote str)
    ;; Sort-of shell-quote STR so it can be passed as an argument to the
    ;; shell.
    (with-output-to-string
      (lambda ()
        (write str))))

  (let* ((channel (make-channel session)))
    (channel-open-session channel)
    (channel-request-exec channel
                          (string-join (if quote?
                                           (map shell-quote command)
                                           command)))
    channel))


;;;
;;; Synchronization.
;;;

(define (lock-file file)
  "Wait and acquire an exclusive lock on FILE.  Return an open port."
  (mkdir-p (dirname file))
  (let ((port (open-file file "w0")))
    (fcntl-flock port 'write-lock)
    port))

(define (unlock-file lock)
  "Unlock LOCK."
  (fcntl-flock lock 'unlock)
  (close-port lock)
  #t)

(define-syntax-rule (with-file-lock file exp ...)
  "Wait to acquire a lock on FILE and evaluate EXP in that context."
  (let ((port (lock-file file)))
    (dynamic-wind
      (lambda ()
        #t)
      (lambda ()
        exp ...)
      (lambda ()
        (unlock-file port)))))

(define-syntax-rule (with-machine-lock machine hint exp ...)
  "Wait to acquire MACHINE's exclusive lock for HINT, and evaluate EXP in that
context."
  (with-file-lock (machine-lock-file machine hint)
    exp ...))


(define (machine-slot-file machine slot)
  "Return the file name of MACHINE's file for SLOT."
  ;; For each machine we have a bunch of files representing each build slot.
  ;; When choosing a build machine, we attempt to get an exclusive lock on one
  ;; of these; if we fail, that means all the build slots are already taken.
  ;; Inspired by Nix's build-remote.pl.
  (string-append  (string-append %state-directory "/offload/"
                                 (build-machine-name machine)
                                 "/" (number->string slot))))

(define (acquire-build-slot machine)
  "Attempt to acquire a build slot on MACHINE.  Return the port representing
the slot, or #f if none is available.

This mechanism allows us to set a hard limit on the number of simultaneous
connections allowed to MACHINE."
  (mkdir-p (dirname (machine-slot-file machine 0)))
  (with-machine-lock machine 'slots
    (any (lambda (slot)
           (let ((port (open-file (machine-slot-file machine slot)
                                  "w0")))
             (catch 'flock-error
               (lambda ()
                 (fcntl-flock port 'write-lock #:wait? #f)
                 ;; Got it!
                 (format (current-error-port)
                         "process ~a acquired build slot '~a'~%"
                         (getpid) (port-filename port))
                 port)
               (lambda args
                 ;; PORT is already locked by another process.
                 (close-port port)
                 #f))))
         (iota (build-machine-parallel-builds machine)))))

(define (release-build-slot slot)
  "Release SLOT, a build slot as returned as by 'acquire-build-slot'."
  (close-port slot))


;;;
;;; Offloading.
;;;

(define (build-log-port)
  "Return the default port where build logs should be sent.  The default is
file descriptor 4, which is open by the daemon before running the offload
hook."
  (let ((port (fdopen 4 "w0")))
    ;; Make sure file descriptor 4 isn't closed when PORT is GC'd.
    (set-port-revealed! port 1)
    port))

(define %gc-root-file
  ;; File name of the temporary GC root we install.
  (format #f "offload-~a-~a" (gethostname) (getpid)))

(define (register-gc-root file session)
  "Mark FILE, a store item, as a garbage collector root in SESSION.  Return
the exit status, zero on success."
  (define script
    `(begin
       (use-modules (guix config))

       ;; Note: we can't use 'add-indirect-root' because dangling links under
       ;; gcroots/auto are automatically deleted by the GC.  This strategy
       ;; doesn't have this problem, but it requires write access to that
       ;; directory.
       (let ((root-directory (string-append %state-directory
                                            "/gcroots/tmp")))
         (catch 'system-error
           (lambda ()
             (mkdir root-directory))
           (lambda args
             (unless (= EEXIST (system-error-errno args))
               (error "failed to create remote GC root directory"
                      root-directory (system-error-errno args)))))

         (catch 'system-error
           (lambda ()
             (symlink ,file
                      (string-append root-directory "/" ,%gc-root-file)))
           (lambda args
             ;; If FILE already exists, we can assume that either it's a stale
             ;; reference (which is fine), or another process is already
             ;; building the derivation represented by FILE (which is fine
             ;; too.)  Thus, do nothing in that case.
             (unless (= EEXIST (system-error-errno args))
               (apply throw args)))))))

  (let ((pipe (remote-pipe session
                           `("guile" "-c" ,(object->string script)))))
    (read-string pipe)
    (let ((status (channel-get-exit-status pipe)))
      (close-port pipe)
      (unless (zero? status)
        ;; Better be safe than sorry: if we ignore the error here, then FILE
        ;; may be GC'd just before we start using it.
        (leave (_ "failed to register GC root for '~a' on '~a' (status: ~a)~%")
               file (session-get session 'host) status)))))

(define (remove-gc-roots session)
  "Remove in SESSION the GC roots previously installed with
'register-gc-root'."
  (define script
    `(begin
       (use-modules (guix config) (ice-9 ftw)
                    (srfi srfi-1) (srfi srfi-26))

       (let ((root-directory (string-append %state-directory
                                            "/gcroots/tmp")))
         (false-if-exception
          (delete-file
           (string-append root-directory "/" ,%gc-root-file)))

         ;; These ones were created with 'guix build -r' (there can be more
         ;; than one in case of multiple-output derivations.)
         (let ((roots (filter (cut string-prefix? ,%gc-root-file <>)
                              (scandir "."))))
           (for-each (lambda (file)
                       (false-if-exception (delete-file file)))
                     roots)))))

  (let ((pipe (remote-pipe session
                           `("guile" "-c" ,(object->string script)))))
    (read-string pipe)
    (close-port pipe)))

(define* (offload drv session
                  #:key print-build-trace? (max-silent-time 3600)
                  build-timeout (log-port (build-log-port)))
  "Perform DRV in SESSION, assuming DRV and its prerequisites are available
there, and write the build log to LOG-PORT.  Return the exit status."
  ;; Normally DRV has already been protected from GC when it was transferred.
  ;; The '-r' flag below prevents the build result from being GC'd.
  (let ((pipe (remote-pipe session
                           `("guix" "build"
                             "-r" ,%gc-root-file
                             ,(format #f "--max-silent-time=~a"
                                      max-silent-time)
                             ,@(if build-timeout
                                   (list (format #f "--timeout=~a"
                                                 build-timeout))
                                   '())
                             ,(derivation-file-name drv))

                           ;; Since 'guix build' writes the build log to its
                           ;; stderr, everything will go directly to LOG-PORT.
                           ;; #:error-port log-port ;; FIXME
                           )))
    ;; Make standard error visible.
    (channel-set-stream! pipe 'stderr)

    (let loop ((line (read-line pipe)))
      (unless (eof-object? line)
        (display line log-port)
        (newline log-port)
        (loop (read-line pipe))))

    (let loop ((status (channel-get-exit-status pipe)))
      (close-port pipe)
      status)))

(define* (transfer-and-offload drv machine
                               #:key
                               (inputs '())
                               (outputs '())
                               (max-silent-time 3600)
                               build-timeout
                               print-build-trace?)
  "Offload DRV to MACHINE.  Prior to the actual offloading, transfer all of
INPUTS to MACHINE; if building DRV succeeds, retrieve all of OUTPUTS from
MACHINE."
  (define session
    (open-ssh-session machine))

  (when (begin
          (register-gc-root (derivation-file-name drv) session)
          (send-files (cons (derivation-file-name drv) inputs)
                      session))
    (format (current-error-port) "offloading '~a' to '~a'...~%"
            (derivation-file-name drv) (build-machine-name machine))
    (format (current-error-port) "@ build-remote ~a ~a~%"
            (derivation-file-name drv) (build-machine-name machine))

    (let ((status (offload drv session
                           #:print-build-trace? print-build-trace?
                           #:max-silent-time max-silent-time
                           #:build-timeout build-timeout)))
      (if (zero? status)
          (begin
            (retrieve-files outputs session)
            (remove-gc-roots session)
            (format (current-error-port)
                    "done with offloaded '~a'~%"
                    (derivation-file-name drv)))
          (begin
            (remove-gc-roots session)
            (format (current-error-port)
                    "derivation '~a' offloaded to '~a' failed \
with exit code ~a~%"
                    (derivation-file-name drv)
                    (build-machine-name machine)
                    status)

            ;; Use exit code 100 for a permanent build failure.  The daemon
            ;; interprets other non-zero codes as transient build failures.
            (primitive-exit 100))))))

(define (send-files files session)
  "Send the subset of FILES that's missing to SESSION's store.  Return #t on
success, #f otherwise."
  (define (missing-files files)
    ;; Return the subset of FILES not already on SESSION.  Use 'head' as a
    ;; hack to make sure the remote end stops reading when we're done.
    (let* ((pipe (remote-pipe session
                              `("guix" "archive" "--missing")
                              #:quote? #f)))
      (format pipe "~{~a~%~}" files)
      (channel-send-eof! pipe)
      (string-tokenize (read-string pipe))))

  (with-store store
    (guard (c ((nix-protocol-error? c)
               (warning (_ "failed to export files for '~a': ~s~%")
                        (session-get session 'host) c)
               #f))

      ;; Compute the subset of FILES missing on SESSION, and send them in
      ;; topologically sorted order so that they can actually be imported.
      (let* ((files (missing-files (topologically-sorted store files)))
             (pipe  (remote-pipe session
                                 '("guix" "archive" "--import")
                                 #:quote? #f)))
        (format #t (_ "sending ~a store files to '~a'...~%")
                (length files) (session-get session 'host))

        (export-paths store files pipe)
        (channel-send-eof! pipe)

        ;; Wait for the remote process to complete.
        (let ((status (channel-get-exit-status pipe)))
          (close pipe)
          status)))))

(define (retrieve-files files session)
  "Retrieve FILES from SESSION's store, and import them."
  (define host
    (session-get session 'host))

  (let ((pipe (remote-pipe session
                           `("guix" "archive" "--export" ,@files)
                           #:quote? #f)))
    (and pipe
         (with-store store
           (guard (c ((nix-protocol-error? c)
                      (warning (_ "failed to import files from '~a': ~s~%")
                               host c)
                      #f))
             (format (current-error-port) "retrieving ~a files from '~a'...~%"
                     (length files) host)

             ;; We cannot use the 'import-paths' RPC here because we already
             ;; hold the locks for FILES.
             (restore-file-set pipe
                               #:log-port (current-error-port)
                               #:lock? #f)

             (close-port pipe))))))


;;;
;;; Scheduling.
;;;

(define (machine-matches? machine requirements)
  "Return #t if MACHINE matches REQUIREMENTS."
  (and (string=? (build-requirements-system requirements)
                 (build-machine-system machine))
       (lset<= string=?
               (build-requirements-features requirements)
               (build-machine-features machine))))

(define (machine-load machine)
  "Return the load of MACHINE, divided by the number of parallel builds
allowed on MACHINE."
  (let* ((session (open-ssh-session machine))
         (pipe    (remote-pipe session '("cat" "/proc/loadavg")))
         (line    (read-line pipe)))
    (close-port pipe)

    (if (eof-object? line)
        +inf.0    ;MACHINE does not respond, so assume it is infinitely loaded
        (match (string-tokenize line)
          ((one five fifteen . _)
           (let* ((raw        (string->number five))
                  (jobs       (build-machine-parallel-builds machine))
                  (normalized (/ raw jobs)))
             (format (current-error-port) "load on machine '~a' is ~s\
 (normalized: ~s)~%"
                     (build-machine-name machine) raw normalized)
             normalized))
          (_
           +inf.0)))))           ;something's fishy about MACHINE, so avoid it

(define (machine-power-factor m)
  "Return a factor that aggregates the speed and load of M.  The higher the
better."
  (/ (build-machine-speed m)
     (+ 1 (machine-load m))))

(define (machine-less-loaded-or-faster? m1 m2)
  "Return #t if M1 is either less loaded or faster than M2.  (This relation
defines a total order on machines.)"
  (> (machine-power-factor m1) (machine-power-factor m2)))

(define (machine-lock-file machine hint)
  "Return the name of MACHINE's lock file for HINT."
  (string-append %state-directory "/offload/"
                 (build-machine-name machine)
                 "." (symbol->string hint) ".lock"))

(define (machine-choice-lock-file)
  "Return the name of the file used as a lock when choosing a build machine."
  (string-append %state-directory "/offload/machine-choice.lock"))


(define %slots
  ;; List of acquired build slots (open ports).
  '())

(define (choose-build-machine machines)
  "Return the best machine among MACHINES, or #f."

  ;; Proceed like this:
  ;;   1. Acquire the global machine-choice lock.
  ;;   2. For all MACHINES, attempt to acquire a build slot, and filter out
  ;;      those machines for which we failed.
  ;;   3. Choose the best machine among those that are left.
  ;;   4. Release the previously-acquired build slots of the other machines.
  ;;   5. Release the global machine-choice lock.

  (with-file-lock (machine-choice-lock-file)
    (define machines+slots
      (filter-map (lambda (machine)
                    (let ((slot (acquire-build-slot machine)))
                      (and slot (list machine slot))))
                  machines))

    (define (undecorate pred)
      (lambda (a b)
        (match a
          ((machine1 slot1)
           (match b
             ((machine2 slot2)
              (pred machine1 machine2)))))))

    (let loop ((machines+slots
                (sort machines+slots
                      (undecorate machine-less-loaded-or-faster?))))
      (match machines+slots
        (((best slot) others ...)
         ;; Return the best machine unless it's already overloaded.
         (if (< (machine-load best) 2.)
             (match others
               (((machines slots) ...)
                ;; Release slots from the uninteresting machines.
                (for-each release-build-slot slots)

                ;; Prevent SLOT from being GC'd.
                (set! %slots (cons slot %slots))
                best))
             (begin
               ;; BEST is overloaded, so try the next one.
               (release-build-slot slot)
               (loop others))))
        (() #f)))))

(define* (process-request wants-local? system drv features
                          #:key
                          print-build-trace? (max-silent-time 3600)
                          build-timeout)
  "Process a request to build DRV."
  (let* ((local?     (and wants-local? (string=? system (%current-system))))
         (reqs       (build-requirements
                      (system system)
                      (features features)))
         (candidates (filter (cut machine-matches? <> reqs)
                             (build-machines))))
    (match candidates
      (()
       ;; We'll never be able to match REQS.
       (display "# decline\n"))
      ((_ ...)
       (let ((machine (choose-build-machine candidates)))
         (if machine
             (begin
               ;; Offload DRV to MACHINE.
               (display "# accept\n")
               (let ((inputs  (string-tokenize (read-line)))
                     (outputs (string-tokenize (read-line))))
                 (transfer-and-offload drv machine
                                       #:inputs inputs
                                       #:outputs outputs
                                       #:max-silent-time max-silent-time
                                       #:build-timeout build-timeout
                                       #:print-build-trace? print-build-trace?)))

             ;; Not now, all the machines are busy.
             (display "# postpone\n")))))))

(define-syntax-rule (with-nar-error-handling body ...)
  "Execute BODY with any &nar-error suitably reported to the user."
  (guard (c ((nar-error? c)
             (let ((file (nar-error-file c)))
               (if (condition-has-type? c &message)
                   (leave (_ "while importing file '~a': ~a~%")
                          file (gettext (condition-message c)))
                   (leave (_ "failed to import file '~a'~%")
                          file)))))
    body ...))


;;;
;;; Entry point.
;;;

(define (guix-offload . args)
  (define request-line-rx
    ;; The request format.  See 'tryBuildHook' method in build.cc.
    (make-regexp "([01]) ([a-z0-9_-]+) (/[[:graph:]]+.drv) ([[:graph:]]*)"))

  (define not-coma
    (char-set-complement (char-set #\,)))

  ;; Make sure $HOME really corresponds to the current user.  This is
  ;; necessary since lsh uses that to determine the location of the yarrow
  ;; seed file, and fails if it's owned by someone else.
  (and=> (passwd:dir (getpw (getuid)))
         (cut setenv "HOME" <>))

  (match args
    ((system max-silent-time print-build-trace? build-timeout)
     (let ((max-silent-time    (string->number max-silent-time))
           (build-timeout      (string->number build-timeout))
           (print-build-trace? (string=? print-build-trace? "1")))
       (parameterize ((%current-system system))
         (let loop ((line (read-line)))
           (unless (eof-object? line)
             (cond ((regexp-exec request-line-rx line)
                    =>
                    (lambda (match)
                      (with-nar-error-handling
                       (process-request (equal? (match:substring match 1) "1")
                                        (match:substring match 2) ; system
                                        (call-with-input-file
                                            (match:substring match 3)
                                          read-derivation)
                                        (string-tokenize
                                         (match:substring match 4) not-coma)
                                        #:print-build-trace? print-build-trace?
                                        #:max-silent-time max-silent-time
                                        #:build-timeout build-timeout))))
                   (else
                    (leave (_ "invalid request line: ~s~%") line)))
             (loop (read-line)))))))
    (("--version")
     (show-version-and-exit "guix offload"))
    (("--help")
     (format #t (_ "Usage: guix offload SYSTEM PRINT-BUILD-TRACE
Process build offload requests written on the standard input, possibly
offloading builds to the machines listed in '~a'.~%")
             %machine-file)
     (display (_ "
This tool is meant to be used internally by 'guix-daemon'.\n"))
     (show-bug-report-information))
    (x
     (leave (_ "invalid arguments: ~{~s ~}~%") x))))

;;; Local Variables:
;;; eval: (put 'with-machine-lock 'scheme-indent-function 2)
;;; eval: (put 'with-file-lock 'scheme-indent-function 1)
;;; eval: (put 'with-error-to-port 'scheme-indent-function 1)
;;; End:

;;; offload.scm ends here
