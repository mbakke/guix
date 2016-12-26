;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015 David Thompson <davet@gnu.org>
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

(define-module (guix scripts environment)
  #:use-module (guix ui)
  #:use-module (guix store)
  #:use-module (guix grafts)
  #:use-module (guix derivations)
  #:use-module (guix packages)
  #:use-module (guix profiles)
  #:use-module (guix search-paths)
  #:use-module (guix build utils)
  #:use-module (guix monads)
  #:use-module ((guix gexp) #:select (lower-inputs))
  #:use-module (guix scripts)
  #:use-module (guix scripts build)
  #:use-module (gnu build linux-container)
  #:use-module (gnu system linux-container)
  #:use-module (gnu system file-systems)
  #:use-module (gnu packages)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages commencement)
  #:use-module (gnu packages guile)
  #:use-module ((gnu packages bootstrap) #:select (%bootstrap-guile))
  #:use-module (ice-9 format)
  #:use-module (ice-9 match)
  #:use-module (ice-9 rdelim)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-37)
  #:use-module (srfi srfi-98)
  #:export (guix-environment))

(define (evaluate-profile-search-paths profile search-paths)
  "Evaluate SEARCH-PATHS, a list of search-path specifications, for the
directories in PROFILE, the store path of a profile."
  (evaluate-search-paths search-paths (list profile)))

;; Protect some env vars from purification.  Borrowed from nix-shell.
(define %precious-variables
  '("HOME" "USER" "LOGNAME" "DISPLAY" "TERM" "TZ" "PAGER"))

(define %default-shell
  (or (getenv "SHELL") "/bin/sh"))

(define %network-configuration-files
  '("/etc/resolv.conf"
    "/etc/nsswitch.conf"
    "/etc/services"
    "/etc/hosts"))

(define (purify-environment)
  "Unset almost all environment variables.  A small number of variables such
as 'HOME' and 'USER' are left untouched."
  (for-each unsetenv
            (remove (cut member <> %precious-variables)
                    (match (get-environment-variables)
                      (((names . _) ...)
                       names)))))

(define (create-environment profile paths pure?)
  "Set the environment variables specified by PATHS for PROFILE.  When PURE?
is #t, unset the variables in the current environment.  Otherwise, augment
existing enviroment variables with additional search paths."
  (when pure? (purify-environment))
  (for-each (match-lambda
              ((($ <search-path-specification> variable _ separator) . value)
               (let ((current (getenv variable)))
                 (setenv variable
                         (if (and current (not pure?))
                             (string-append value separator current)
                             value)))))
            (evaluate-profile-search-paths profile paths))

  ;; Give users a way to know that they're in 'guix environment', so they can
  ;; adjust 'PS1' accordingly, for instance.  Set it to PROFILE so users can
  ;; conveniently access its contents.
  (setenv "GUIX_ENVIRONMENT" profile))

(define (show-search-paths profile search-paths pure?)
  "Display SEARCH-PATHS applied to PROFILE.  When PURE? is #t, do not augment
existing environment variables with additional search paths."
  (for-each (match-lambda
              ((search-path . value)
               (display
                (search-path-definition search-path value
                                        #:kind (if pure? 'exact 'prefix)))
               (newline)))
            (evaluate-profile-search-paths profile search-paths)))

(define (strip-input-name input)
  "Remove the name element from the tuple INPUT."
  (match input
    ((_ package) package)
    ((_ package output)
     (list package output))))

(define (package+propagated-inputs package output)
  "Return the union of PACKAGE's OUTPUT and its transitive propagated inputs."
  (cons (list package output)
        (map strip-input-name
             (package-transitive-propagated-inputs package))))

(define (package-or-package+output? expr)
  "Return #t if EXPR is a package or a 2 element list consisting of a package
and an output string."
  (match expr
    ((or (? package?) ; bare package object
         ((? package?) (? string?))) ; package+output tuple
     #t)
    (_ #f)))

(define (package-environment-inputs package)
  "Return a list of the transitive input packages for PACKAGE."
  ;; Remove non-package inputs such as origin records.
  (filter package-or-package+output?
          (map strip-input-name
               (bag-transitive-inputs
                (package->bag package)))))

(define (show-help)
  (display (_ "Usage: guix environment [OPTION]... PACKAGE... [-- COMMAND...]
Build an environment that includes the dependencies of PACKAGE and execute
COMMAND or an interactive shell in that environment.\n"))
  (display (_ "
  -e, --expression=EXPR  create environment for the package that EXPR
                         evaluates to"))
  (display (_ "
  -l, --load=FILE        create environment for the package that the code within
                         FILE evaluates to"))
  (display (_ "
      --ad-hoc           include all specified packages in the environment instead
                         of only their inputs"))
  (display (_ "
      --pure             unset existing environment variables"))
  (display (_ "
      --search-paths     display needed environment variable definitions"))
  (display (_ "
  -s, --system=SYSTEM    attempt to build for SYSTEM--e.g., \"i686-linux\""))
  (display (_ "
  -r, --root=FILE        make FILE a symlink to the result, and register it
                         as a garbage collector root"))
  (display (_ "
  -C, --container        run command within an isolated container"))
  (display (_ "
  -N, --network          allow containers to access the network"))
  (display (_ "
      --share=SPEC       for containers, share writable host file system
                         according to SPEC"))
  (display (_ "
      --expose=SPEC      for containers, expose read-only host file system
                         according to SPEC"))
  (display (_ "
      --bootstrap        use bootstrap binaries to build the environment"))
  (newline)
  (show-build-options-help)
  (newline)
  (display (_ "
  -h, --help             display this help and exit"))
  (display (_ "
  -V, --version          display version information and exit"))
  (newline)
  (show-bug-report-information))

(define %default-options
  `((system . ,(%current-system))
    (substitutes? . #t)
    (graft? . #t)
    (max-silent-time . 3600)
    (verbosity . 0)))

(define (tag-package-arg opts arg)
  "Return a two-element list with the form (TAG ARG) that tags ARG with either
'ad-hoc' in OPTS has the 'ad-hoc?' key set to #t, or 'inputs' otherwise."
  ;; Normally, the transitive inputs to a package are added to an environment,
  ;; but the ad-hoc? flag changes the meaning of a package argument such that
  ;; the package itself is added to the environment instead.
  (if (assoc-ref opts 'ad-hoc?)
      `(ad-hoc-package ,arg)
      `(package ,arg)))

(define %options
  ;; Specification of the command-line options.
  (cons* (option '(#\h "help") #f #f
                 (lambda args
                   (show-help)
                   (exit 0)))
         (option '(#\V "version") #f #f
                 (lambda args
                   (show-version-and-exit "guix environment")))
         (option '("pure") #f #f
                 (lambda (opt name arg result)
                   (alist-cons 'pure #t result)))
         (option '(#\E "exec") #t #f ; deprecated
                 (lambda (opt name arg result)
                   (alist-cons 'exec (list %default-shell "-c" arg) result)))
         (option '("search-paths") #f #f
                 (lambda (opt name arg result)
                   (alist-cons 'search-paths #t result)))
         (option '(#\l "load") #t #f
                 (lambda (opt name arg result)
                   (alist-cons 'load
                               (tag-package-arg result arg)
                               result)))
         (option '(#\e "expression") #t #f
                 (lambda (opt name arg result)
                   (alist-cons 'expression
                               (tag-package-arg result arg)
                               result)))
         (option '("ad-hoc") #f #f
                 (lambda (opt name arg result)
                   (alist-cons 'ad-hoc? #t result)))
         (option '(#\n "dry-run") #f #f
                 (lambda (opt name arg result)
                   (alist-cons 'dry-run? #t (alist-cons 'graft? #f result))))
         (option '(#\s "system") #t #f
                 (lambda (opt name arg result)
                   (alist-cons 'system arg
                               (alist-delete 'system result eq?))))
         (option '(#\C "container") #f #f
                 (lambda (opt name arg result)
                   (alist-cons 'container? #t result)))
         (option '(#\N "network") #f #f
                 (lambda (opt name arg result)
                   (alist-cons 'network? #t result)))
         (option '("share") #t #f
                 (lambda (opt name arg result)
                   (alist-cons 'file-system-mapping
                               (specification->file-system-mapping arg #t)
                               result)))
         (option '("expose") #t #f
                 (lambda (opt name arg result)
                   (alist-cons 'file-system-mapping
                               (specification->file-system-mapping arg #f)
                               result)))
         (option '(#\r "root") #t #f
                 (lambda (opt name arg result)
                   (alist-cons 'gc-root arg result)))
         (option '("bootstrap") #f #f
                 (lambda (opt name arg result)
                   (alist-cons 'bootstrap? #t result)))
         %standard-build-options))

(define (pick-all alist key)
  "Return a list of values in ALIST associated with KEY."
  (define same-key? (cut eq? key <>))

  (fold (lambda (pair memo)
          (match pair
            (((? same-key? k) . v)
             (cons v memo))
            (_ memo)))
        '() alist))

(define (compact lst)
  "Remove all #f elements from LST."
  (filter identity lst))

(define (options/resolve-packages opts)
  "Return OPTS with package specification strings replaced by actual
packages."
  (define (package->output package mode)
    (match package
      ((? package?)
       (list mode package "out"))
      (((? package? package) (? string? output))
       (list mode package output))))

  (define (packages->outputs packages mode)
    (match packages
      ((? package-or-package+output? package) ; single package
       (list (package->output package mode)))
      (((? package-or-package+output?) ...) ; many packages
       (map (cut package->output <> mode) packages))))

  (compact
   (append-map (match-lambda
                 (('package mode (? string? spec))
                  (let-values (((package output)
                                (specification->package+output spec)))
                    (list (list mode package output))))
                 (('expression mode str)
                  ;; Add all the outputs of the package STR evaluates to.
                  (packages->outputs (read/eval str) mode))
                 (('load mode file)
                  ;; Add all the outputs of the package defined in FILE.
                  (let ((module (make-user-module '())))
                    (packages->outputs (load* file module) mode)))
                 (_ '(#f)))
               opts)))

(define* (build-environment derivations opts)
  "Build the DERIVATIONS required by the environment using the build options
in OPTS."
  (let ((substitutes? (assoc-ref opts 'substitutes?))
        (dry-run?     (assoc-ref opts 'dry-run?)))
    (mbegin %store-monad
      (show-what-to-build* derivations
                           #:use-substitutes? substitutes?
                           #:dry-run? dry-run?)
      (if dry-run?
          (return #f)
          (mbegin %store-monad
            (set-build-options-from-command-line* opts)
            (built-derivations derivations))))))

(define (inputs->profile-derivation inputs system bootstrap?)
  "Return the derivation for a profile consisting of INPUTS for SYSTEM.
BOOTSTRAP?  specifies whether to use the bootstrap Guile to build the
profile."
  (profile-derivation (packages->manifest inputs)
                      #:system system
                      #:hooks (if bootstrap?
                                  '()
                                  %default-profile-hooks)
                      #:locales? (not bootstrap?)))

(define requisites* (store-lift requisites))

(define (inputs->requisites inputs)
  "Convert INPUTS, a list of input tuples or store path strings, into a set of
requisite store items i.e. the union closure of all the inputs."
  (define (input->requisites input)
    (requisites*
     (match input
       ((drv output)
        (list (derivation->output-path drv output)))
       ((drv)
        (list (derivation->output-path drv)))
       ((? direct-store-path? path)
        (list path)))))

  (mlet %store-monad ((reqs (sequence %store-monad
                                      (map input->requisites inputs))))
    (return (delete-duplicates (concatenate reqs)))))

(define (status->exit-code status)
  "Compute the exit code made from STATUS, a value as returned by 'waitpid',
and suitable for 'exit'."
  ;; See <bits/waitstatus.h>.
  (or (status:exit-val status)
      (logior #x80 (status:term-sig status))))

(define exit/status (compose exit status->exit-code))
(define primitive-exit/status (compose primitive-exit status->exit-code))

(define (launch-environment command inputs paths pure?)
  "Run COMMAND in a new environment containing INPUTS, using the native search
paths defined by the list PATHS.  When PURE?, pre-existing environment
variables are cleared before setting the new ones."
  ;; Properly handle SIGINT, so pressing C-c in an interactive terminal
  ;; application works.
  (sigaction SIGINT SIG_DFL)
  (create-environment inputs paths pure?)
  (match command
    ((program . args)
     (apply execlp program program args))))

(define (launch-environment/fork command inputs paths pure?)
  "Run COMMAND in a new process with an environment containing INPUTS, using
the native search paths defined by the list PATHS.  When PURE?, pre-existing
environment variables are cleared before setting the new ones."
  (match (primitive-fork)
    (0 (launch-environment command inputs paths pure?))
    (pid (match (waitpid pid)
           ((_ . status) status)))))

(define* (launch-environment/container #:key command bash user-mappings
                                       profile paths network?)
  "Run COMMAND within a container that features the software in PROFILE.
Environment variables are set according to PATHS, a list of native search
paths.  The global shell is BASH, a file name for a GNU Bash binary in the
store.  When NETWORK?, access to the host system network is permitted.
USER-MAPPINGS, a list of file system mappings, contains the user-specified
host file systems to mount inside the container."
  (mlet %store-monad ((reqs (inputs->requisites
                             (list (direct-store-path bash) profile))))
    (return
     (let* ((cwd (getcwd))
            (passwd (getpwuid (getuid)))
            ;; Bind-mount all requisite store items, user-specified mappings,
            ;; /bin/sh, the current working directory, and possibly networking
            ;; configuration files within the container.
            (mappings
             (append user-mappings
                     ;; Current working directory.
                     (list (file-system-mapping
                            (source cwd)
                            (target cwd)
                            (writable? #t)))
                     ;; When in Rome, do as Nix build.cc does: Automagically
                     ;; map common network configuration files.
                     (if network?
                         (filter-map (lambda (file)
                                       (and (file-exists? file)
                                            (file-system-mapping
                                             (source file)
                                             (target file)
                                             ;; XXX: On some GNU/Linux
                                             ;; systems, /etc/resolv.conf is a
                                             ;; symlink to a file in a tmpfs
                                             ;; which, for an unknown reason,
                                             ;; cannot be bind mounted
                                             ;; read-only within the
                                             ;; container.
                                             (writable?
                                              (string=? "/etc/resolv.conf")))))
                                     %network-configuration-files)
                         '())
                     ;; Mappings for the union closure of all inputs.
                     (map (lambda (dir)
                            (file-system-mapping
                             (source dir)
                             (target dir)
                             (writable? #f)))
                          reqs)))
            (file-systems (append %container-file-systems
                                  (map mapping->file-system mappings))))
       (exit/status
        (call-with-container file-systems
          (lambda ()
            ;; Setup global shell.
            (mkdir-p "/bin")
            (symlink bash "/bin/sh")

            ;; Set a reasonable default PS1.
            (setenv "PS1" "\\u@\\h \\w [env]\\$ ")

            ;; Setup directory for temporary files.
            (mkdir-p "/tmp")
            (for-each (lambda (var)
                        (setenv var "/tmp"))
                      ;; The same variables as in Nix's 'build.cc'.
                      '("TMPDIR" "TEMPDIR" "TMP" "TEMP"))

            ;; Create a dummy home directory under the same name as on the
            ;; host.
            (mkdir-p (passwd:dir passwd))
            (setenv "HOME" (passwd:dir passwd))

            ;; Create a dummy /etc/passwd to satisfy applications that demand
            ;; to read it, such as 'git clone' over SSH, a valid use-case when
            ;; sharing the host's network namespace.
            (mkdir-p "/etc")
            (call-with-output-file "/etc/passwd"
              (lambda (port)
                (display (string-join (list (passwd:name passwd)
                                            "x" ; but there is no shadow
                                            "0" "0" ; user is now root
                                            (passwd:gecos passwd)
                                            (passwd:dir passwd)
                                            bash)
                                      ":")
                         port)
                (newline port)))

            ;; For convenience, start in the user's current working
            ;; directory rather than the root directory.
            (chdir cwd)

            (primitive-exit/status
             ;; A container's environment is already purified, so no need to
             ;; request it be purified again.
             (launch-environment command profile paths #f)))
          #:namespaces (if network?
                           (delq 'net %namespaces) ; share host network
                           %namespaces)))))))

(define (environment-bash container? bootstrap? system)
  "Return a monadic value in the store monad for the version of GNU Bash
needed in the environment for SYSTEM, if any.  If CONTAINER? is #f, return #f.
If CONTAINER? and BOOTSTRAP?, return the store path for the bootstrap Bash.
Otherwise, return the derivation for the Bash package."
  (with-monad %store-monad
    (cond
     ((and container? (not bootstrap?))
      (package->derivation bash))
     ;; Use the bootstrap Bash instead.
     ((and container? bootstrap?)
      (interned-file
       (search-bootstrap-binary "bash" system)))
     (else
      (return #f)))))

(define (parse-args args)
  "Parse the list of command line arguments ARGS."
  (define (handle-argument arg result)
    (alist-cons 'package (tag-package-arg result arg) result))

  ;; The '--' token is used to separate the command to run from the rest of
  ;; the operands.
  (let-values (((args command) (break (cut string=? "--" <>) args)))
    (let ((opts (parse-command-line args %options (list %default-options)
                                    #:argument-handler handle-argument)))
      (match command
        (() opts)
        (("--") opts)
        (("--" command ...) (alist-cons 'exec command opts))))))

(define (assert-container-features)
  "Check if containers can be created and exit with an informative error
message if any test fails."
  (unless (user-namespace-supported?)
    (report-error (_ "cannot create container: user namespaces unavailable\n"))
    (leave (_ "is your kernel version < 3.10?\n")))

  (unless (unprivileged-user-namespace-supported?)
    (report-error (_ "cannot create container: unprivileged user cannot create user namespaces\n"))
    (leave (_ "please set /proc/sys/kernel/unprivileged_userns_clone to \"1\"\n")))

  (unless (setgroups-supported?)
    (report-error (_ "cannot create container: /proc/self/setgroups does not exist\n"))
    (leave (_ "is your kernel version < 3.19?\n"))))

(define (register-gc-root target root)
  "Make ROOT an indirect root to TARGET.  This is procedure is idempotent."
  (let* ((root (string-append (canonicalize-path (dirname root))
                              "/" root)))
    (catch 'system-error
      (lambda ()
        (symlink target root)
        ((store-lift add-indirect-root) root))
      (lambda args
        (if (and (= EEXIST (system-error-errno args))
                 (equal? (false-if-exception (readlink root)) target))
            (with-monad %store-monad
              (return #t))
            (apply throw args))))))


;;;
;;; Entry point.
;;;

(define (guix-environment . args)
  (with-error-handling
    (let* ((opts       (parse-args args))
           (pure?      (assoc-ref opts 'pure))
           (container? (assoc-ref opts 'container?))
           (network?   (assoc-ref opts 'network?))
           (bootstrap? (assoc-ref opts 'bootstrap?))
           (system     (assoc-ref opts 'system))
           (command    (or (assoc-ref opts 'exec)
                           ;; Spawn a shell if the user didn't specify
                           ;; anything in particular.
                           (if container?
                               ;; The user's shell is likely not available
                               ;; within the container.
                               '("/bin/sh")
                               (list %default-shell))))
           (packages   (options/resolve-packages opts))
           (mappings   (pick-all opts 'file-system-mapping))
           (inputs     (delete-duplicates
                        (append-map (match-lambda
                                      (('ad-hoc-package package output)
                                       (package+propagated-inputs package
                                                                  output))
                                      (('package package _)
                                       (package-environment-inputs package)))
                                    packages)))
           (paths      (delete-duplicates
                        (cons $PATH
                              (append-map (match-lambda
                                            ((or ((? package? p) _ ...)
                                                 (? package? p))
                                             (package-native-search-paths p))
                                            (_ '()))
                                          inputs))
                        eq?)))

      (when container? (assert-container-features))

      (with-store store
        ;; Use the bootstrap Guile when requested.
        (parameterize ((%graft? (assoc-ref opts 'graft?))
                       (%guile-for-build
                        (package-derivation
                         store
                         (if bootstrap?
                             %bootstrap-guile
                             (canonical-package guile-2.0)))))
          (set-build-options-from-command-line store opts)
          (run-with-store store
            ;; Containers need a Bourne shell at /bin/sh.
            (mlet* %store-monad ((bash       (environment-bash container?
                                                               bootstrap?
                                                               system))
                                 (prof-drv   (inputs->profile-derivation
                                              inputs system bootstrap?))
                                 (profile -> (derivation->output-path prof-drv))
                                 (gc-root -> (assoc-ref opts 'gc-root)))

              ;; First build the inputs.  This is necessary even for
              ;; --search-paths.  Additionally, we might need to build bash for
              ;; a container.
              (mbegin %store-monad
                (build-environment (if (derivation? bash)
                                       (list prof-drv bash)
                                       (list prof-drv))
                                   opts)
                (mwhen gc-root
                  (register-gc-root profile gc-root))

                (cond
                 ((assoc-ref opts 'dry-run?)
                  (return #t))
                 ((assoc-ref opts 'search-paths)
                  (show-search-paths profile paths pure?)
                  (return #t))
                 (container?
                  (let ((bash-binary
                         (if bootstrap?
                             bash
                             (string-append (derivation->output-path bash)
                                            "/bin/sh"))))
                    (launch-environment/container #:command command
                                                  #:bash bash-binary
                                                  #:user-mappings mappings
                                                  #:profile profile
                                                  #:paths paths
                                                  #:network? network?)))
                 (else
                  (return
                   (exit/status
                    (launch-environment/fork command profile
                                             paths pure?)))))))))))))
