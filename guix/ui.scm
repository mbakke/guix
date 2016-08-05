;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2013 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2014 Cyril Roelandt <tipecaml@gmail.com>
;;; Copyright © 2014 Cyrill Schenkel <cyrill.schenkel@gmail.com>
;;; Copyright © 2014, 2015 Alex Kost <alezost@gmail.com>
;;; Copyright © 2015 David Thompson <davet@gnu.org>
;;; Copyright © 2015, 2016 Mathieu Lirzin <mthl@gnu.org>
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

(define-module (guix ui)
  #:use-module (guix utils)
  #:use-module (guix store)
  #:use-module (guix config)
  #:use-module (guix packages)
  #:use-module (guix profiles)
  #:use-module (guix derivations)
  #:use-module (guix combinators)
  #:use-module (guix build-system)
  #:use-module (guix serialization)
  #:use-module ((guix build utils) #:select (mkdir-p))
  #:use-module ((guix licenses) #:select (license? license-name))
  #:use-module ((guix build syscalls) #:select (terminal-columns))
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-19)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-31)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:autoload   (ice-9 ftw)  (scandir)
  #:use-module (ice-9 match)
  #:use-module (ice-9 format)
  #:use-module (ice-9 regex)
  #:autoload   (system repl repl)  (start-repl)
  #:autoload   (system repl debug) (make-debug stack->vector)
  #:use-module (texinfo)
  #:use-module (texinfo plain-text)
  #:use-module (texinfo string-utils)
  #:export (_
            N_
            P_
            report-error
            leave
            make-user-module
            load*
            warn-about-load-error
            show-version-and-exit
            show-bug-report-information
            make-regexp*
            string->number*
            size->number
            show-derivation-outputs
            show-what-to-build
            show-what-to-build*
            show-manifest-transaction
            call-with-error-handling
            with-error-handling
            leave-on-EPIPE
            read/eval
            read/eval-package-expression
            location->string
            config-directory
            fill-paragraph
            texi->plain-text
            package-description-string
            string->recutils
            package->recutils
            package-specification->name+version+output
            string->generations
            string->duration
            matching-generations
            display-generation
            display-profile-content
            roll-back*
            switch-to-generation*
            delete-generation*
            run-guix-command
            run-guix
            program-name
            guix-warning-port
            warning
            info
            guix-main))

;;; Commentary:
;;;
;;; User interface facilities for command-line tools.
;;;
;;; Code:

(define %gettext-domain
  ;; Text domain for strings used in the tools.
  "guix")

(define %package-text-domain
  ;; Text domain for package synopses and descriptions.
  "guix-packages")

(define _ (cut gettext <> %gettext-domain))
(define N_ (cut ngettext <> <> <> %gettext-domain))

(define (P_ msgid)
  "Return the translation of the package description or synopsis MSGID."
  ;; Descriptions/synopses might occasionally be empty strings, even if that
  ;; is something we try to avoid.  Since (gettext "") can return a non-empty
  ;; string, explicitly check for that case.
  (if (string-null? msgid)
      msgid
      (gettext msgid %package-text-domain)))

(define-syntax-rule (define-diagnostic name prefix)
  "Create a diagnostic macro (i.e., NAME), which will prepend PREFIX to all
messages."
  (define-syntax name
    (lambda (x)
      (define (augmented-format-string fmt)
        (string-append "~:[~*~;guix ~a: ~]~a" (syntax->datum fmt)))

      (syntax-case x ()
        ((name (underscore fmt) args (... ...))
         (and (string? (syntax->datum #'fmt))
              (free-identifier=? #'underscore #'_))
         (with-syntax ((fmt*   (augmented-format-string #'fmt))
                       (prefix (datum->syntax x prefix)))
           #'(format (guix-warning-port) (gettext fmt*)
                     (program-name) (program-name) prefix
                     args (... ...))))
        ((name (N-underscore singular plural n) args (... ...))
         (and (string? (syntax->datum #'singular))
              (string? (syntax->datum #'plural))
              (free-identifier=? #'N-underscore #'N_))
         (with-syntax ((s      (augmented-format-string #'singular))
                       (p      (augmented-format-string #'plural))
                       (prefix (datum->syntax x prefix)))
           #'(format (guix-warning-port)
                     (ngettext s p n %gettext-domain)
                     (program-name) (program-name) prefix
                     args (... ...))))))))

(define-diagnostic warning "warning: ") ; emit a warning
(define-diagnostic info "")

(define-diagnostic report-error "error: ")
(define-syntax-rule (leave args ...)
  "Emit an error message and exit."
  (begin
    (report-error args ...)
    (exit 1)))

(define (make-user-module modules)
  "Return a new user module with the additional MODULES loaded."
  ;; Module in which the machine description file is loaded.
  (let ((module (make-fresh-user-module)))
    (for-each (lambda (iface)
                (module-use! module (resolve-interface iface)))
              modules)
    module))

(define* (load* file user-module
                #:key (on-error 'nothing-special))
  "Load the user provided Scheme source code FILE."
  (define (frame-with-source frame)
    ;; Walk from FRAME upwards until source location information is found.
    (let loop ((frame    frame)
               (previous frame))
      (if (not frame)
          previous
          (if (frame-source frame)
              frame
              (loop (frame-previous frame) frame)))))

  (define (error-string frame args)
    (call-with-output-string
     (lambda (port)
       (apply display-error frame port (cdr args)))))

  (define tag
    (make-prompt-tag "user-code"))

  (catch #t
    (lambda ()
      ;; XXX: Force a recompilation to avoid ABI issues.
      (set! %fresh-auto-compile #t)
      (set! %load-should-auto-compile #t)

      (save-module-excursion
       (lambda ()
         (set-current-module user-module)

         ;; Hide the "auto-compiling" messages.
         (parameterize ((current-warning-port (%make-void-port "w")))
           (call-with-prompt tag
             (lambda ()
               ;; Give 'load' an absolute file name so that it doesn't try to
               ;; search for FILE in %LOAD-PATH.  Note: use 'load', not
               ;; 'primitive-load', so that FILE is compiled, which then allows us
               ;; to provide better error reporting with source line numbers.
               (load (canonicalize-path file)))
             (const #f))))))
    (lambda _
      ;; XXX: Errors are reported from the pre-unwind handler below, but
      ;; calling 'exit' from there has no effect, so we call it here.
      (exit 1))
    (rec (handle-error . args)
         ;; Capture the stack up to this procedure call, excluded, and pass
         ;; the faulty stack frame to 'report-load-error'.
         (let* ((stack (make-stack #t handle-error tag))
                (depth (stack-length stack))
                (last  (and (> depth 0) (stack-ref stack 0)))
                (frame (frame-with-source
                        (if (> depth 1)
                            (stack-ref stack 1)   ;skip the 'throw' frame
                            last))))

           (report-load-error file args frame)

           (case on-error
             ((debug)
              (newline)
              (display (_ "entering debugger; type ',bt' for a backtrace\n"))
              (start-repl #:debug (make-debug (stack->vector stack) 0
                                              (error-string frame args)
                                              #f)))
             ((backtrace)
              (newline (current-error-port))
              (display-backtrace stack (current-error-port)))
             (else
              #t))))))

(define* (report-load-error file args #:optional frame)
  "Report the failure to load FILE, a user-provided Scheme file.
ARGS is the list of arguments received by the 'throw' handler."
  (match args
    (('system-error . _)
     (let ((err (system-error-errno args)))
       (report-error (_ "failed to load '~a': ~a~%") file (strerror err))))
    (('syntax-error proc message properties form . rest)
     (let ((loc (source-properties->location properties)))
       (format (current-error-port) (_ "~a: error: ~a~%")
               (location->string loc) message)))
    (('srfi-34 obj)
     (report-error (_ "exception thrown: ~s~%") obj))
    ((error args ...)
     (report-error (_ "failed to load '~a':~%") file)
     (apply display-error frame (current-error-port) args))))

(define (warn-about-load-error file args)         ;FIXME: factorize with ↑
  "Report the failure to load FILE, a user-provided Scheme file, without
exiting.  ARGS is the list of arguments received by the 'throw' handler."
  (match args
    (('system-error . _)
     (let ((err (system-error-errno args)))
       (warning (_ "failed to load '~a': ~a~%") file (strerror err))))
    (('syntax-error proc message properties form . rest)
     (let ((loc (source-properties->location properties)))
       (format (current-error-port) (_ "~a: warning: ~a~%")
               (location->string loc) message)))
    (('srfi-34 obj)
     (warning (_ "failed to load '~a': exception thrown: ~s~%")
              file obj))
    ((error args ...)
     (warning (_ "failed to load '~a':~%") file)
     (apply display-error #f (current-error-port) args))))

(define (install-locale)
  "Install the current locale settings."
  (catch 'system-error
    (lambda _
      (setlocale LC_ALL ""))
    (lambda args
      (warning (_ "failed to install locale: ~a~%")
               (strerror (system-error-errno args))))))

(define (initialize-guix)
  "Perform the usual initialization for stand-alone Guix commands."
  (install-locale)
  (textdomain %gettext-domain)

  ;; Ignore SIGPIPE.  If the daemon closes the connection, we prefer to be
  ;; notified via an EPIPE later.
  (sigaction SIGPIPE SIG_IGN)

  (setvbuf (current-output-port) _IOLBF)
  (setvbuf (current-error-port) _IOLBF))

(define* (show-version-and-exit #:optional (command (car (command-line))))
  "Display version information for COMMAND and `(exit 0)'."
  (simple-format #t "~a (~a) ~a~%"
                 command %guix-package-name %guix-version)
  (display (_ "Copyright (C) 2016 the Guix authors
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
"))
  (exit 0))

(define (show-bug-report-information)
  ;; TRANSLATORS: The placeholder indicates the bug-reporting address for this
  ;; package.  Please add another line saying "Report translation bugs to
  ;; ...\n" with the address for translation bugs (typically your translation
  ;; team's web or email address).
  (format #t (_ "
Report bugs to: ~a.") %guix-bug-report-address)
  (format #t (_ "
~a home page: <~a>") %guix-package-name %guix-home-page-url)
  (display (_ "
General help using GNU software: <http://www.gnu.org/gethelp/>"))
  (newline))

(set! symlink
  ;; We 'set!' the global binding because (gnu build ...) modules and similar
  ;; typically don't use (guix ui).
  (let ((real-symlink (@ (guile) symlink)))
    (lambda (target link)
      "This is a 'symlink' replacement that provides proper error reporting."
      (catch 'system-error
        (lambda ()
          (real-symlink target link))
        (lambda (key proc fmt args errno)
          ;; Augment the FMT and ARGS with information about LINK (this
          ;; information is missing as of Guile 2.0.11, making the exception
          ;; uninformative.)
          (apply throw key proc "~A: ~S"
                 (list (strerror (car errno)) link)
                 (list errno)))))))

(set! copy-file
  ;; Note: here we use 'set!', not #:replace, because UIs typically use
  ;; 'copy-recursively', which doesn't use (guix ui).
  (let ((real-copy-file (@ (guile) copy-file)))
    (lambda (source target)
      "This is a 'copy-file' replacement that provides proper error reporting."
      (catch 'system-error
        (lambda ()
          (real-copy-file source target))
        (lambda (key proc fmt args errno)
          ;; Augment the FMT and ARGS with information about TARGET (this
          ;; information is missing as of Guile 2.0.11, making the exception
          ;; uninformative.)
          (apply throw key proc "~A: ~S"
                 (list (strerror (car errno)) target)
                 (list errno)))))))

(define (make-regexp* regexp . flags)
  "Like 'make-regexp' but error out if REGEXP is invalid, reporting the error
nicely."
  (catch 'regular-expression-syntax
    (lambda ()
      (apply make-regexp regexp flags))
    (lambda (key proc message . rest)
      (leave (_ "'~a' is not a valid regular expression: ~a~%")
             regexp message))))

(define (string->number* str)
  "Like `string->number', but error out with an error message on failure."
  (or (string->number str)
      (leave (_ "~a: invalid number~%") str)))

(define (size->number str)
  "Convert STR, a storage measurement representation such as \"1024\" or
\"1MiB\", to a number of bytes.  Raise an error if STR could not be
interpreted."
  (define unit-pos
    (string-rindex str char-set:digit))

  (define unit
    (and unit-pos (substring str (+ 1 unit-pos))))

  (let* ((numstr (if unit-pos
                     (substring str 0 (+ 1 unit-pos))
                     str))
         (num    (string->number numstr)))
    (unless num
      (leave (_ "invalid number: ~a~%") numstr))

    ((compose inexact->exact round)
     (* num
        (match unit
          ((or "KiB" "K" "k") (expt 2 10))
          ((or "MiB" "M")     (expt 2 20))
          ((or "GiB" "G")     (expt 2 30))
          ((or "TiB" "T")     (expt 2 40))
          ((or "PiB" "P")     (expt 2 50))
          ((or "EiB" "E")     (expt 2 60))
          ((or "ZiB" "Z")     (expt 2 70))
          ((or "YiB" "Y")     (expt 2 80))
          ("kB"  (expt 10 3))
          ("MB"  (expt 10 6))
          ("GB"  (expt 10 9))
          ("TB"  (expt 10 12))
          ("PB"  (expt 10 15))
          ("EB"  (expt 10 18))
          ("ZB"  (expt 10 21))
          ("YB"  (expt 10 24))
          (""    1)
          (_
           (leave (_ "unknown unit: ~a~%") unit)))))))

(define (call-with-error-handling thunk)
  "Call THUNK within a user-friendly error handler."
  (define (port-filename* port)
    ;; 'port-filename' returns #f for non-file ports, but it raises an
    ;; exception for file ports that are closed.  Work around that.
    (and (not (port-closed? port))
         (port-filename port)))

  (guard (c ((package-input-error? c)
             (let* ((package  (package-error-package c))
                    (input    (package-error-invalid-input c))
                    (location (package-location package))
                    (file     (location-file location))
                    (line     (location-line location))
                    (column   (location-column location)))
               (leave (_ "~a:~a:~a: package `~a' has an invalid input: ~s~%")
                      file line column
                      (package-full-name package) input)))
            ((package-cross-build-system-error? c)
             (let* ((package (package-error-package c))
                    (loc     (package-location package))
                    (system  (package-build-system package)))
               (leave (_ "~a: ~a: build system `~a' does not support cross builds~%")
                      (location->string loc)
                      (package-full-name package)
                      (build-system-name system))))
            ((profile-not-found-error? c)
             (leave (_ "profile '~a' does not exist~%")
                    (profile-error-profile c)))
            ((missing-generation-error? c)
             (leave (_ "generation ~a of profile '~a' does not exist~%")
                    (missing-generation-error-generation c)
                    (profile-error-profile c)))
            ((nar-error? c)
             (let ((file (nar-error-file c))
                   (port (nar-error-port c)))
               (if file
                   (leave (_ "corrupt input while restoring '~a' from ~s~%")
                          file (or (port-filename* port) port))
                   (leave (_ "corrupt input while restoring archive from ~s~%")
                          (or (port-filename* port) port)))))
            ((nix-connection-error? c)
             (leave (_ "failed to connect to `~a': ~a~%")
                    (nix-connection-error-file c)
                    (strerror (nix-connection-error-code c))))
            ((nix-protocol-error? c)
             ;; FIXME: Server-provided error messages aren't i18n'd.
             (leave (_ "build failed: ~a~%")
                    (nix-protocol-error-message c)))
            ((derivation-missing-output-error? c)
             (leave (_ "reference to invalid output '~a' of derivation '~a'~%")
                    (derivation-missing-output c)
                    (derivation-file-name (derivation-error-derivation c))))
            ((file-search-error? c)
             (leave (_ "file '~a' could not be found in these \
directories:~{ ~a~}~%")
                    (file-search-error-file-name c)
                    (file-search-error-search-path c)))
            ((message-condition? c)
             ;; Normally '&message' error conditions have an i18n'd message.
             (leave (_ "~a~%")
                    (gettext (condition-message c) %gettext-domain))))
    ;; Catch EPIPE and the likes.
    (catch 'system-error
      thunk
      (lambda (key proc format-string format-args . rest)
        (leave (_ "~a: ~a~%") proc
               (apply format #f format-string format-args))))))

(define-syntax-rule (leave-on-EPIPE exp ...)
  "Run EXP... in a context when EPIPE errors are caught and lead to 'exit'
with successful exit code.  This is useful when writing to the standard output
may lead to EPIPE, because the standard output is piped through 'head' or
similar."
  (catch 'system-error
    (lambda ()
      exp ...)
    (lambda args
      ;; We really have to exit this brutally, otherwise Guile eventually
      ;; attempts to flush all the ports, leading to an uncaught EPIPE down
      ;; the path.
      (if (= EPIPE (system-error-errno args))
          (primitive-_exit 0)
          (apply throw args)))))

(define %guix-user-module
  ;; Module in which user expressions are evaluated.
  ;; Compute lazily to avoid circularity with (guix gexp).
  (delay
    (let ((module (make-module)))
      (beautify-user-module! module)
      ;; Use (guix gexp) so that one can use #~ & co.
      (module-use! module (resolve-interface '(guix gexp)))
      module)))

(define (read/eval str)
  "Read and evaluate STR, raising an error if something goes wrong."
  (let ((exp (catch #t
               (lambda ()
                 (call-with-input-string str read))
               (lambda args
                 (leave (_ "failed to read expression ~s: ~s~%")
                        str args)))))
    (catch #t
      (lambda ()
        (eval exp (force %guix-user-module)))
      (lambda args
        (report-error (_ "failed to evaluate expression '~a':~%") exp)
        (match args
          (('syntax-error proc message properties form . rest)
           (report-error (_ "syntax error: ~a~%") message))
          (('srfi-34 obj)
           (report-error (_ "exception thrown: ~s~%") obj))
          ((error args ...)
           (apply display-error #f (current-error-port) args))
          (what? #f))
        (exit 1)))))

(define (read/eval-package-expression str)
  "Read and evaluate STR and return the package it refers to, or exit an
error."
  (match (read/eval str)
    ((? package? p) p)
    (_
     (leave (_ "expression ~s does not evaluate to a package~%")
            str))))

(define (show-derivation-outputs derivation)
  "Show the output file names of DERIVATION."
  (format #t "~{~a~%~}"
          (map (match-lambda
                 ((out-name . out)
                  (derivation->output-path derivation out-name)))
               (derivation-outputs derivation))))

(define* (show-what-to-build store drv
                             #:key dry-run? (use-substitutes? #t)
                             (mode (build-mode normal)))
  "Show what will or would (depending on DRY-RUN?) be built in realizing the
derivations listed in DRV using MODE, a 'build-mode' value.  Return #t if
there's something to build, #f otherwise.  When USE-SUBSTITUTES?, check and
report what is prerequisites are available for download."
  (define substitutable?
    ;; Call 'substitutation-oracle' upfront so we don't end up launching the
    ;; substituter many times.  This makes a big difference, especially when
    ;; DRV is a long list as is the case with 'guix environment'.
    (if use-substitutes?
        (substitution-oracle store drv #:mode mode)
        (const #f)))

  (define (built-or-substitutable? drv)
    (or (null? (derivation-outputs drv))
        (let ((out (derivation->output-path drv))) ;XXX: assume "out" exists
          (or (valid-path? store out)
              (substitutable? out)))))

  (let*-values (((build download)
                 (fold2 (lambda (drv build download)
                          (let-values (((b d)
                                        (derivation-prerequisites-to-build
                                         store drv
                                         #:mode mode
                                         #:substitutable? substitutable?)))
                            (values (append b build)
                                    (append d download))))
                        '() '()
                        drv))
                ((build)                          ; add the DRV themselves
                 (delete-duplicates
                  (append (map derivation-file-name
                               (remove built-or-substitutable? drv))
                          (map derivation-input-path build))))
                ((download)                   ; add the references of DOWNLOAD
                 (if use-substitutes?
                     (delete-duplicates
                      (append download
                              (remove (cut valid-path? store <>)
                                      (append-map
                                       substitutable-references
                                       (substitutable-path-info store
                                                                download)))))
                     download)))
    ;; TODO: Show the installed size of DOWNLOAD.
    (if dry-run?
        (begin
          (format (current-error-port)
                  (N_ "~:[The following derivation would be built:~%~{   ~a~%~}~;~]"
                      "~:[The following derivations would be built:~%~{   ~a~%~}~;~]"
                      (length build))
                  (null? build) build)
          (format (current-error-port)
                  (N_ "~:[The following file would be downloaded:~%~{   ~a~%~}~;~]"
                      "~:[The following files would be downloaded:~%~{   ~a~%~}~;~]"
                      (length download))
                  (null? download) download))
        (begin
          (format (current-error-port)
                  (N_ "~:[The following derivation will be built:~%~{   ~a~%~}~;~]"
                      "~:[The following derivations will be built:~%~{   ~a~%~}~;~]"
                      (length build))
                  (null? build) build)
          (format (current-error-port)
                  (N_ "~:[The following file will be downloaded:~%~{   ~a~%~}~;~]"
                      "~:[The following files will be downloaded:~%~{   ~a~%~}~;~]"
                      (length download))
                  (null? download) download)))
    (pair? build)))

(define show-what-to-build*
  (store-lift show-what-to-build))

(define (right-arrow port)
  "Return either a string containing the 'RIGHT ARROW' character, or an ASCII
replacement if PORT is not Unicode-capable."
  (with-fluids ((%default-port-encoding (port-encoding port)))
    (let ((arrow "→"))
      (catch 'encoding-error
        (lambda ()
          (call-with-output-string
            (lambda (port)
              (set-port-conversion-strategy! port 'error)
              (display arrow port))))
        (lambda (key . args)
          "->")))))

(define* (show-manifest-transaction store manifest transaction
                                    #:key dry-run?)
  "Display what will/would be installed/removed from MANIFEST by TRANSACTION."
  (define (package-strings name version output item)
    (map (lambda (name version output item)
           (format #f "   ~a~:[:~a~;~*~]\t~a\t~a"
                   name
                   (equal? output "out") output version
                   (if (package? item)
                       (package-output store item output)
                       item)))
         name version output item))

  (define →                        ;an arrow that can be represented on stderr
    (right-arrow (current-error-port)))

  (define (upgrade-string name old-version new-version output item)
    (format #f "   ~a~:[:~a~;~*~]\t~a ~a ~a\t~a"
            name (equal? output "out") output
            old-version → new-version
            (if (package? item)
                (package-output store item output)
                item)))

  (let-values (((remove install upgrade downgrade)
                (manifest-transaction-effects manifest transaction)))
    (match remove
      ((($ <manifest-entry> name version output item) ..1)
       (let ((len    (length name))
             (remove (package-strings name version output item)))
         (if dry-run?
             (format (current-error-port)
                     (N_ "The following package would be removed:~%~{~a~%~}~%"
                         "The following packages would be removed:~%~{~a~%~}~%"
                         len)
                     remove)
             (format (current-error-port)
                     (N_ "The following package will be removed:~%~{~a~%~}~%"
                         "The following packages will be removed:~%~{~a~%~}~%"
                         len)
                     remove))))
      (_ #f))
    (match downgrade
      (((($ <manifest-entry> name old-version)
         . ($ <manifest-entry> _ new-version output item)) ..1)
       (let ((len       (length name))
             (downgrade (map upgrade-string
                             name old-version new-version output item)))
         (if dry-run?
             (format (current-error-port)
                     (N_ "The following package would be downgraded:~%~{~a~%~}~%"
                         "The following packages would be downgraded:~%~{~a~%~}~%"
                         len)
                     downgrade)
             (format (current-error-port)
                     (N_ "The following package will be downgraded:~%~{~a~%~}~%"
                         "The following packages will be downgraded:~%~{~a~%~}~%"
                         len)
                     downgrade))))
      (_ #f))
    (match upgrade
      (((($ <manifest-entry> name old-version)
         . ($ <manifest-entry> _ new-version output item)) ..1)
       (let ((len     (length name))
             (upgrade (map upgrade-string
                           name old-version new-version output item)))
         (if dry-run?
             (format (current-error-port)
                     (N_ "The following package would be upgraded:~%~{~a~%~}~%"
                         "The following packages would be upgraded:~%~{~a~%~}~%"
                         len)
                     upgrade)
             (format (current-error-port)
                     (N_ "The following package will be upgraded:~%~{~a~%~}~%"
                         "The following packages will be upgraded:~%~{~a~%~}~%"
                         len)
                     upgrade))))
      (_ #f))
    (match install
      ((($ <manifest-entry> name version output item _) ..1)
       (let ((len     (length name))
             (install (package-strings name version output item)))
         (if dry-run?
             (format (current-error-port)
                     (N_ "The following package would be installed:~%~{~a~%~}~%"
                         "The following packages would be installed:~%~{~a~%~}~%"
                         len)
                     install)
             (format (current-error-port)
                     (N_ "The following package will be installed:~%~{~a~%~}~%"
                         "The following packages will be installed:~%~{~a~%~}~%"
                         len)
                     install))))
      (_ #f))))

(define-syntax with-error-handling
  (syntax-rules ()
    "Run BODY within a user-friendly error condition handler."
    ((_ body ...)
     (call-with-error-handling
      (lambda ()
        body ...)))))

(define (location->string loc)
  "Return a human-friendly, GNU-standard representation of LOC."
  (match loc
    (#f (_ "<unknown location>"))
    (($ <location> file line column)
     (format #f "~a:~a:~a" file line column))))

(define (config-directory)
  "Return the name of the configuration directory, after making sure that it
exists.  Honor the XDG specs,
<http://standards.freedesktop.org/basedir-spec/basedir-spec-latest.html>."
  (let ((dir (and=> (or (getenv "XDG_CONFIG_HOME")
                        (and=> (getenv "HOME")
                               (cut string-append <> "/.config")))
                    (cut string-append <> "/guix"))))
    (catch 'system-error
      (lambda ()
        (mkdir-p dir)
        dir)
      (lambda args
        (let ((err (system-error-errno args)))
          ;; ERR is necessarily different from EEXIST.
          (leave (_ "failed to create configuration directory `~a': ~a~%")
                 dir (strerror err)))))))

(define* (fill-paragraph str width #:optional (column 0))
  "Fill STR such that each line contains at most WIDTH characters, assuming
that the first character is at COLUMN.

When STR contains a single line break surrounded by other characters, it is
converted to a space; sequences of more than one line break are preserved."
  (define (maybe-break chr result)
    (match result
      ((column newlines chars)
       (case chr
         ((#\newline)
          `(,column ,(+ 1 newlines) ,chars))
         (else
          (let* ((spaces (if (and (pair? chars) (eqv? (car chars) #\.)) 2 1))
                 (chars  (case newlines
                           ((0) chars)
                           ((1)
                            (append (make-list spaces #\space) chars))
                           (else
                            (append (make-list newlines #\newline) chars))))
                 (column (case newlines
                           ((0) column)
                           ((1) (+ spaces column))
                           (else 0))))
            (let ((chars  (cons chr chars))
                  (column (+ 1 column)))
              (if (> column width)
                  (let*-values (((before after)
                                 (break (cut eqv? #\space <>) chars))
                                ((len)
                                 (length before)))
                    (if (<= len width)
                        `(,len
                          0
                          ,(if (null? after)
                               before
                               (append before
                                       (cons #\newline
                                             (drop-while (cut eqv? #\space <>)
                                                         after)))))
                        `(,column 0 ,chars)))     ; unbreakable
                  `(,column 0 ,chars)))))))))

  (match (string-fold maybe-break
                      `(,column 0 ())
                      str)
    ((_ _ chars)
     (list->string (reverse chars)))))


;;;
;;; Packages.
;;;

(define %text-width
  (make-parameter (terminal-columns)))

(set! (@@ (texinfo plain-text) wrap*)
      ;; XXX: Monkey patch this private procedure to let 'package->recutils'
      ;; parameterize the fill of description field correctly.
      (lambda strings
        (let ((indent (fluid-ref (@@ (texinfo plain-text) *indent*))))
          (fill-string (string-concatenate strings)
                       #:line-width (%text-width) #:initial-indent indent
                       #:subsequent-indent indent))))

(define (texi->plain-text str)
  "Return a plain-text representation of texinfo fragment STR."
  ;; 'texi-fragment->stexi' uses a string port so make sure it's a
  ;; Unicode-capable one (see <http://bugs.gnu.org/11197>.)
  (with-fluids ((%default-port-encoding "UTF-8"))
    (stexi->plain-text (texi-fragment->stexi str))))

(define (package-description-string package)
  "Return a plain-text representation of PACKAGE description field."
  (and=> (package-description package)
         (compose texi->plain-text P_)))

(define (string->recutils str)
  "Return a version of STR where newlines have been replaced by newlines
followed by \"+ \", which makes for a valid multi-line field value in the
`recutils' syntax."
  (list->string
   (string-fold-right (lambda (chr result)
                        (if (eqv? chr #\newline)
                            (cons* chr #\+ #\space result)
                            (cons chr result)))
                      '()
                      str)))

(define* (package->recutils p port #:optional (width (%text-width)))
  "Write to PORT a `recutils' record of package P, arranging to fit within
WIDTH columns."
  (define width*
    ;; The available number of columns once we've taken into account space for
    ;; the initial "+ " prefix.
    (if (> width 2) (- width 2) width))

  (define (dependencies->recutils packages)
    (let ((list (string-join (map package-full-name
                                  (sort packages package<?)) " ")))
      (string->recutils
       (fill-paragraph list width*
                       (string-length "dependencies: ")))))

  (define (package<? p1 p2)
    (string<? (package-full-name p1) (package-full-name p2)))

  ;; Note: Don't i18n field names so that people can post-process it.
  (format port "name: ~a~%" (package-name p))
  (format port "version: ~a~%" (package-version p))
  (format port "outputs: ~a~%" (string-join (package-outputs p)))
  (format port "systems: ~a~%"
          (string-join (package-transitive-supported-systems p)))
  (format port "dependencies: ~a~%"
          (match (package-direct-inputs p)
            (((labels inputs . _) ...)
             (dependencies->recutils (filter package? inputs)))))
  (format port "location: ~a~%"
          (or (and=> (package-location p) location->string)
              (_ "unknown")))

  ;; Note: Starting from version 1.6 or recutils, hyphens are not allowed in
  ;; field identifiers.
  (format port "homepage: ~a~%" (package-home-page p))

  (format port "license: ~a~%"
          (match (package-license p)
            (((? license? licenses) ...)
             (string-join (map license-name licenses)
                          ", "))
            ((? license? license)
             (license-name license))
            (x
             (_ "unknown"))))
  (format port "synopsis: ~a~%"
          (string-map (match-lambda
                       (#\newline #\space)
                       (chr       chr))
                      (or (and=> (package-synopsis p) P_)
                          "")))
  (format port "~a~2%"
          (string->recutils
           (string-trim-right
            (parameterize ((%text-width width*))
              (texi->plain-text
               (string-append "description: "
                              (or (and=> (package-description p) P_)
                                  ""))))
            #\newline))))

(define (string->generations str)
  "Return the list of generations matching a pattern in STR.  This function
accepts the following patterns: \"1\", \"1,2,3\", \"1..9\", \"1..\", \"..9\"."
  (define (maybe-integer)
    (let ((x (string->number str)))
      (and (integer? x)
           x)))

  (define (maybe-comma-separated-integers)
    (let ((lst (delete-duplicates
                (map string->number
                     (string-split str #\,)))))
      (and (every integer? lst)
           lst)))

  (cond ((maybe-integer)
         =>
         list)
        ((maybe-comma-separated-integers)
         =>
         identity)
        ((string-match "^([0-9]+)\\.\\.([0-9]+)$" str)
         =>
         (lambda (match)
           (let ((s (string->number (match:substring match 1)))
                 (e (string->number (match:substring match 2))))
             (and (every integer? (list s e))
                  (<= s e)
                  (iota (1+ (- e s)) s)))))
        ((string-match "^([0-9]+)\\.\\.$" str)
         =>
         (lambda (match)
           (let ((s (string->number (match:substring match 1))))
             (and (integer? s)
                  `(>= ,s)))))
        ((string-match "^\\.\\.([0-9]+)$" str)
         =>
         (lambda (match)
           (let ((e (string->number (match:substring match 1))))
             (and (integer? e)
                  `(<= ,e)))))
        (else #f)))

(define (string->duration str)
  "Return the duration matching a pattern in STR.  This function accepts the
following patterns: \"1d\", \"1w\", \"1m\"."
  (define (hours->duration hours match)
    (make-time time-duration 0
               (* 3600 hours (string->number (match:substring match 1)))))

  (cond ((string-match "^([0-9]+)s$" str)
         =>
         (lambda (match)
           (make-time time-duration 0
                      (string->number (match:substring match 1)))))
        ((string-match "^([0-9]+)h$" str)
         (lambda (match)
           (hours->duration 1 match)))
        ((string-match "^([0-9]+)d$" str)
         =>
         (lambda (match)
           (hours->duration 24 match)))
        ((string-match "^([0-9]+)w$" str)
         =>
         (lambda (match)
           (hours->duration (* 24 7) match)))
        ((string-match "^([0-9]+)m$" str)
         =>
         (lambda (match)
           (hours->duration (* 24 30) match)))
        (else #f)))

(define* (matching-generations str profile
                               #:key (duration-relation <=))
  "Return the list of available generations matching a pattern in STR.  See
'string->generations' and 'string->duration' for the list of valid patterns.
When STR is a duration pattern, return all the generations whose ctime has
DURATION-RELATION with the current time."
  (define (valid-generations lst)
    (define (valid-generation? n)
      (any (cut = n <>) (generation-numbers profile)))

    (fold-right (lambda (x acc)
                  (if (valid-generation? x)
                      (cons x acc)
                      acc))
                '()
                lst))

  (define (filter-generations generations)
    (match generations
      (() '())
      (('>= n)
       (drop-while (cut > n <>)
                   (generation-numbers profile)))
      (('<= n)
       (valid-generations (iota n 1)))
      ((lst ..1)
       (valid-generations lst))
      (_ #f)))

  (define (filter-by-duration duration)
    (define (time-at-midnight time)
      ;; Return TIME at midnight by setting nanoseconds, seconds, minutes, and
      ;; hours to zeros.
      (let ((d (time-utc->date time)))
         (date->time-utc
          (make-date 0 0 0 0
                     (date-day d) (date-month d)
                     (date-year d) (date-zone-offset d)))))

    (define generation-ctime-alist
      (map (lambda (number)
             (cons number
                   (time-second
                    (time-at-midnight
                     (generation-time profile number)))))
           (generation-numbers profile)))

    (match duration
      (#f #f)
      (res
       (let ((s (time-second
                 (subtract-duration (time-at-midnight (current-time))
                                    duration))))
         (delete #f (map (lambda (x)
                           (and (duration-relation s (cdr x))
                                (first x)))
                         generation-ctime-alist))))))

  (cond ((string->generations str)
         =>
         filter-generations)
        ((string->duration str)
         =>
         filter-by-duration)
        (else #f)))

(define (display-generation profile number)
  "Display a one-line summary of generation NUMBER of PROFILE."
  (unless (zero? number)
    (let ((header (format #f (_ "Generation ~a\t~a") number
                          (date->string
                           (time-utc->date
                            (generation-time profile number))
                           "~b ~d ~Y ~T")))
          (current (generation-number profile)))
      (if (= number current)
          ;; TRANSLATORS: The word "current" here is an adjective for
          ;; "Generation", as in "current generation".  Use the appropriate
          ;; gender where applicable.
          (format #t (_ "~a\t(current)~%") header)
          (format #t "~a~%" header)))))

(define (display-profile-content profile number)
  "Display the packages in PROFILE, generation NUMBER, in a human-readable
way."
  (for-each (match-lambda
              (($ <manifest-entry> name version output location _)
               (format #t "  ~a\t~a\t~a\t~a~%"
                       name version output location)))

            ;; Show most recently installed packages last.
            (reverse
             (manifest-entries
              (profile-manifest (generation-file-name profile number))))))

(define (display-generation-change previous current)
  (format #t (_ "switched from generation ~a to ~a~%") previous current))

(define (roll-back* store profile)
  "Like 'roll-back', but display what is happening."
  (call-with-values
      (lambda ()
        (roll-back store profile))
    display-generation-change))

(define (switch-to-generation* profile number)
  "Like 'switch-generation', but display what is happening."
  (let ((previous (switch-to-generation profile number)))
    (display-generation-change previous number)))

(define (delete-generation* store profile generation)
  "Like 'delete-generation', but display what is going on."
  (format #t (_ "deleting ~a~%")
          (generation-file-name profile generation))
  (delete-generation store profile generation))

(define* (package-specification->name+version+output spec
                                                     #:optional (output "out"))
  "Parse package specification SPEC and return three value: the specified
package name, version number (or #f), and output name (or OUTPUT).  SPEC may
optionally contain a version number and an output name, as in these examples:

  guile
  guile@2.0.9
  guile:debug
  guile@2.0.9:debug
"
  (let*-values (((name sub-drv)
                 (match (string-rindex spec #\:)
                   (#f    (values spec output))
                   (colon (values (substring spec 0 colon)
                                  (substring spec (+ 1 colon))))))
                ((name version)
                 (package-name->name+version name)))
    (values name version sub-drv)))


;;;
;;; Command-line option processing.
;;;

(define (show-guix-usage)
  (format (current-error-port)
          (_ "Try `guix --help' for more information.~%"))
  (exit 1))

(define (command-files)
  "Return the list of source files that define Guix sub-commands."
  (define directory
    (and=> (search-path %load-path "guix.scm")
           (compose (cut string-append <> "/guix/scripts")
                    dirname)))

  (define dot-scm?
    (cut string-suffix? ".scm" <>))

  (if directory
      (scandir directory dot-scm?)
      '()))

(define (commands)
  "Return the list of Guix command names."
  (map (compose (cut string-drop-right <> 4)
                basename)
       (command-files)))

(define (show-guix-help)
  (define (internal? command)
    (member command '("substitute" "authenticate" "offload")))

  (format #t (_ "Usage: guix COMMAND ARGS...
Run COMMAND with ARGS.\n"))
  (newline)
  (format #t (_ "COMMAND must be one of the sub-commands listed below:\n"))
  (newline)
  ;; TODO: Display a synopsis of each command.
  (format #t "~{   ~a~%~}" (sort (remove internal? (commands))
                                 string<?))
  (show-bug-report-information))

(define program-name
  ;; Name of the command-line program currently executing, or #f.
  (make-parameter #f))

(define (run-guix-command command . args)
  "Run COMMAND with the given ARGS.  Report an error when COMMAND is not
found."
  (define module
    (catch 'misc-error
      (lambda ()
        (resolve-interface `(guix scripts ,command)))
      (lambda -
        (format (current-error-port)
                (_ "guix: ~a: command not found~%") command)
        (show-guix-usage))))

  (let ((command-main (module-ref module
                                  (symbol-append 'guix- command))))
    (parameterize ((program-name command))
      (apply command-main args))))

(define (run-guix . args)
  "Run the 'guix' command defined by command line ARGS.
Unlike 'guix-main', this procedure assumes that locale, i18n support,
and signal handling has already been set up."
  (define option? (cut string-prefix? "-" <>))

  (match args
    (()
     (format (current-error-port)
             (_ "guix: missing command name~%"))
     (show-guix-usage))
    ((or ("-h") ("--help"))
     (show-guix-help))
    (("--version")
     (show-version-and-exit "guix"))
    (((? option? o) args ...)
     (format (current-error-port)
             (_ "guix: unrecognized option '~a'~%") o)
     (show-guix-usage))
    (("help" command)
     (apply run-guix-command (string->symbol command)
            '("--help")))
    (("help" args ...)
     (show-guix-help))
    ((command args ...)
     (apply run-guix-command
            (string->symbol command)
            args))))

(define guix-warning-port
  (make-parameter (current-warning-port)))

(define (guix-main arg0 . args)
  (initialize-guix)
  (apply run-guix args))

;;; ui.scm ends here
