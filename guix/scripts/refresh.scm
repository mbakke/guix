;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2015 Alex Kost <alezost@gmail.com>
;;; Copyright © 2016 Ben Woodcroft <donttrustben@gmail.com>
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

(define-module (guix scripts refresh)
  #:use-module (guix ui)
  #:use-module (guix hash)
  #:use-module (guix scripts)
  #:use-module (guix store)
  #:use-module (guix utils)
  #:use-module (guix packages)
  #:use-module (guix upstream)
  #:use-module (guix graph)
  #:use-module (guix scripts graph)
  #:use-module (guix monads)
  #:use-module ((guix gnu-maintenance)
                #:select (%gnu-updater
                          %gnome-updater
                          %kde-updater
                          %xorg-updater
                          %kernel.org-updater))
  #:use-module (guix import elpa)
  #:use-module (guix import cran)
  #:use-module (guix import hackage)
  #:use-module (guix gnupg)
  #:use-module (gnu packages)
  #:use-module ((gnu packages commencement) #:select (%final-inputs))
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 vlist)
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-37)
  #:use-module (ice-9 binary-ports)
  #:export (guix-refresh
            %updaters))


;;;
;;; Command-line options.
;;;

(define %default-options
  ;; Alist of default option values.
  '())

(define %options
  ;; Specification of the command-line options.
  (list (option '(#\u "update") #f #f
                (lambda (opt name arg result)
                  (alist-cons 'update? #t result)))
        (option '(#\s "select") #t #f
                (lambda (opt name arg result)
                  (match arg
                    ((or "core" "non-core")
                     (alist-cons 'select (string->symbol arg)
                                 result))
                    (x
                     (leave (_ "~a: invalid selection; expected `core' or `non-core'~%")
                            arg)))))
        (option '(#\t "type") #t #f
                (lambda (opt name arg result)
                  (let* ((not-comma (char-set-complement (char-set #\,)))
                         (names (map string->symbol
                                     (string-tokenize arg not-comma))))
                    (alist-cons 'updaters names result))))
        (option '(#\L "list-updaters") #f #f
                (lambda args
                  (list-updaters-and-exit)))
        (option '(#\e "expression") #t #f
                (lambda (opt name arg result)
                  (alist-cons 'expression arg result)))
        (option '(#\l "list-dependent") #f #f
                (lambda (opt name arg result)
                  (alist-cons 'list-dependent? #t result)))

        (option '("key-server") #t #f
                (lambda (opt name arg result)
                  (alist-cons 'key-server arg result)))
        (option '("gpg") #t #f
                (lambda (opt name arg result)
                  (alist-cons 'gpg-command arg result)))
        (option '("key-download") #t #f
                (lambda (opt name arg result)
                  (match arg
                    ((or "interactive" "always" "never")
                     (alist-cons 'key-download (string->symbol arg)
                                 result))
                    (x
                     (leave (_ "unsupported policy: ~a~%")
                            arg)))))

        (option '(#\h "help") #f #f
                (lambda args
                  (show-help)
                  (exit 0)))
        (option '(#\V "version") #f #f
                (lambda args
                  (show-version-and-exit "guix refresh")))))

(define (show-help)
  (display (_ "Usage: guix refresh [OPTION]... [PACKAGE]...
Update package definitions to match the latest upstream version.

When PACKAGE... is given, update only the specified packages.  Otherwise
update all the packages of the distribution, or the subset thereof
specified with `--select'.\n"))
  (display (_ "
  -e, --expression=EXPR  consider the package EXPR evaluates to"))
  (display (_ "
  -u, --update           update source files in place"))
  (display (_ "
  -s, --select=SUBSET    select all the packages in SUBSET, one of
                         `core' or `non-core'"))
  (display (_ "
  -t, --type=UPDATER,... restrict to updates from the specified updaters
                         (e.g., 'gnu')"))
  (display (_ "
  -L, --list-updaters    list available updaters and exit"))
  (display (_ "
  -l, --list-dependent   list top-level dependent packages that would need to
                         be rebuilt as a result of upgrading PACKAGE..."))
  (newline)
  (display (_ "
      --key-server=HOST  use HOST as the OpenPGP key server"))
  (display (_ "
      --gpg=COMMAND      use COMMAND as the GnuPG 2.x command"))
  (display (_ "
      --key-download=POLICY
                         handle missing OpenPGP keys according to POLICY:
                         'always', 'never', and 'interactive', which is also
                         used when 'key-download' is not specified"))
  (newline)
  (display (_ "
  -h, --help             display this help and exit"))
  (display (_ "
  -V, --version          display version information and exit"))
  (newline)
  (show-bug-report-information))


;;;
;;; Updates.
;;;

(define-syntax maybe-updater
  ;; Helper macro for 'list-updaters'.
  (syntax-rules (=>)
    ((_ ((module => updater) rest ...) result)
     (maybe-updater (rest ...)
                    (let ((iface (false-if-exception
                                  (resolve-interface 'module)))
                          (tail  result))
                      (if iface
                          (cons (module-ref iface 'updater) tail)
                          tail))))
    ((_ (updater rest ...) result)
     (maybe-updater (rest ...)
                    (cons updater result)))
    ((_ () result)
     (reverse result))))

(define-syntax-rule (list-updaters updaters ...)
  "Expand to '(list UPDATERS ...)' but only the subset of UPDATERS that are
either unconditional, or have their requirement met.

A conditional updater has this form:

  ((SOME MODULE) => UPDATER)

meaning that UPDATER is added to the list if and only if (SOME MODULE) could
be resolved at run time.

This is a way to discard at macro expansion time updaters that depend on
unavailable optional dependencies such as Guile-JSON."
  (maybe-updater (updaters ...) '()))

(define %updaters
  ;; List of "updaters" used by default.  They are consulted in this order.
  (list-updaters %gnu-updater
                 %gnome-updater
                 %kde-updater
                 %xorg-updater
                 %kernel.org-updater
                 %elpa-updater
                 %cran-updater
                 %bioconductor-updater
                 %hackage-updater
                 ((guix import cpan) => %cpan-updater)
                 ((guix import pypi) => %pypi-updater)
                 ((guix import gem) => %gem-updater)
                 ((guix import github) => %github-updater)
                 ((guix import crate) => %crate-updater)))

(define (lookup-updater-by-name name)
  "Return the updater called NAME."
  (or (find (lambda (updater)
              (eq? name (upstream-updater-name updater)))
            %updaters)
      (leave (_ "~a: no such updater~%") name)))

(define (list-updaters-and-exit)
  "Display available updaters and exit."
  (format #t (_ "Available updaters:~%"))
  (newline)

  (let* ((packages (fold-packages cons '()))
         (total    (length packages)))
    (define covered
      (fold (lambda (updater covered)
              (let ((matches (count (upstream-updater-predicate updater)
                                    packages)))
                ;; TRANSLATORS: The parenthetical expression here is rendered
                ;; like "(42% coverage)" and denotes the fraction of packages
                ;; covered by the given updater.
                (format #t (_ "  - ~a: ~a (~2,1f% coverage)~%")
                        (upstream-updater-name updater)
                        (_ (upstream-updater-description updater))
                        (* 100. (/ matches total)))
                (+ covered matches)))
            0
            %updaters))

    (newline)
    (format #t (_ "~2,1f% of the packages are covered by these updaters.~%")
            (* 100. (/ covered total))))
  (exit 0))

(define (warn-no-updater package)
  (format (current-error-port)
          (_ "~a: warning: no updater for ~a~%")
          (location->string (package-location package))
          (package-name package)))

(define* (update-package store package updaters
                         #:key (key-download 'interactive) warn?)
  "Update the source file that defines PACKAGE with the new version.
KEY-DOWNLOAD specifies a download policy for missing OpenPGP keys; allowed
values: 'interactive' (default), 'always', and 'never'.  When WARN? is true,
warn about packages that have no matching updater."
  (if (lookup-updater package updaters)
      (let-values (((version tarball)
                    (package-update store package updaters
                                    #:key-download key-download))
                   ((loc)
                    (or (package-field-location package 'version)
                        (package-location package))))
        (when version
          (if (and=> tarball file-exists?)
              (begin
                (format (current-error-port)
                        (_ "~a: ~a: updating from version ~a to version ~a...~%")
                        (location->string loc)
                        (package-name package)
                        (package-version package) version)
                (let ((hash (call-with-input-file tarball
                              port-sha256)))
                  (update-package-source package version hash)))
              (warning (_ "~a: version ~a could not be \
downloaded and authenticated; not updating~%")
                       (package-name package) version))))
      (when warn?
        (warn-no-updater package))))

(define* (check-for-package-update package updaters #:key warn?)
  "Check whether an update is available for PACKAGE and print a message.  When
WARN? is true and no updater exists for PACKAGE, print a warning."
  (match (package-latest-release package updaters)
    ((? upstream-source? source)
     (when (version>? (upstream-source-version source)
                      (package-version package))
       (let ((loc (or (package-field-location package 'version)
                      (package-location package))))
         (format (current-error-port)
                 (_ "~a: ~a would be upgraded from ~a to ~a~%")
                 (location->string loc)
                 (package-name package) (package-version package)
                 (upstream-source-version source)))))
    (#f
     (when warn?
       (warn-no-updater package)))))



;;;
;;; Dependents.
;;;

(define (all-packages)
  "Return the list of all the distro's packages."
  (fold-packages cons '()))

(define (list-dependents packages)
  "List all the things that would need to be rebuilt if PACKAGES are changed."
  ;; Using %BAG-NODE-TYPE is more accurate than using %PACKAGE-NODE-TYPE
  ;; because it includes implicit dependencies.
  (mlet %store-monad ((edges (node-back-edges %bag-node-type
                                              (all-packages))))
    (let* ((dependents (node-transitive-edges packages edges))
           (covering   (filter (lambda (node)
                                 (null? (edges node)))
                               dependents)))
      (match dependents
        (()
         (format (current-output-port)
                 (N_ "No dependents other than itself: ~{~a~}~%"
                     "No dependents other than themselves: ~{~a~^ ~}~%"
                     (length packages))
                 (map package-full-name packages)))

        ((x)
         (format (current-output-port)
                 (_ "A single dependent package: ~a~%")
                 (package-full-name x)))
        (lst
         (format (current-output-port)
                 (N_ "Building the following package would ensure ~d \
dependent packages are rebuilt: ~*~{~a~^ ~}~%"
                     "Building the following ~d packages would ensure ~d \
dependent packages are rebuilt: ~{~a~^ ~}~%"
                     (length covering))
                 (length covering) (length dependents)
                 (map package-full-name covering))))
      (return #t))))


;;;
;;; Entry point.
;;;

(define (guix-refresh . args)
  (define (parse-options)
    ;; Return the alist of option values.
    (args-fold* args %options
                (lambda (opt name arg result)
                  (leave (_ "~A: unrecognized option~%") name))
                (lambda (arg result)
                  (alist-cons 'argument arg result))
                %default-options))

  (define (options->updaters opts)
    ;; Return the list of updaters to use.
    (match (filter-map (match-lambda
                         (('updaters . names)
                          (map lookup-updater-by-name names))
                         (_ #f))
                       opts)
      (()
       ;; Use the default updaters.
       %updaters)
      (lists
       (concatenate lists))))

  (define (keep-newest package lst)
    ;; If a newer version of PACKAGE is already in LST, return LST; otherwise
    ;; return LST minus the other version of PACKAGE in it, plus PACKAGE.
    (let ((name (package-name package)))
      (match (find (lambda (p)
                     (string=? (package-name p) name))
                   lst)
        ((? package? other)
         (if (version>? (package-version other) (package-version package))
             lst
             (cons package (delq other lst))))
        (_
         (cons package lst)))))

  (define core-package?
    (let* ((input->package (match-lambda
                             ((name (? package? package) _ ...) package)
                             (_ #f)))
           (final-inputs   (map input->package %final-inputs))
           (core           (append final-inputs
                                   (append-map (compose (cut filter-map input->package <>)
                                                        package-transitive-inputs)
                                               final-inputs)))
           (names          (delete-duplicates (map package-name core))))
      (lambda (package)
        "Return true if PACKAGE is likely a \"core package\"---i.e., one whose
update would trigger a complete rebuild."
        ;; Compare by name because packages in base.scm basically inherit
        ;; other packages.  So, even if those packages are not core packages
        ;; themselves, updating them would also update those who inherit from
        ;; them.
        ;; XXX: Fails to catch MPFR/MPC, whose *source* is used as input.
        (member (package-name package) names))))

  (let* ((opts            (parse-options))
         (update?         (assoc-ref opts 'update?))
         (updaters        (options->updaters opts))
         (list-dependent? (assoc-ref opts 'list-dependent?))
         (key-download    (assoc-ref opts 'key-download))

         ;; Warn about missing updaters when a package is explicitly given on
         ;; the command line.
         (warn?           (or (assoc-ref opts 'argument)
                              (assoc-ref opts 'expression)))

         (packages
          (match (filter-map (match-lambda
                               (('argument . spec)
                                ;; Take either the specified version or the
                                ;; latest one.
                                (specification->package spec))
                               (('expression . exp)
                                (read/eval-package-expression exp))
                               (_ #f))
                             opts)
            (()                                   ; default to all packages
             (let ((select? (match (assoc-ref opts 'select)
                              ('core core-package?)
                              ('non-core (negate core-package?))
                              (_ (const #t)))))
               (fold-packages (lambda (package result)
                                (if (select? package)
                                    (keep-newest package result)
                                    result))
                              '())))
            (some                                 ; user-specified packages
             some))))
    (with-error-handling
      (with-store store
        (run-with-store store
          (cond
           (list-dependent?
            (list-dependents packages))
           (update?
            (parameterize ((%openpgp-key-server
                            (or (assoc-ref opts 'key-server)
                                (%openpgp-key-server)))
                           (%gpg-command
                            (or (assoc-ref opts 'gpg-command)
                                (%gpg-command))))
              (for-each
               (cut update-package store <> updaters
                    #:key-download key-download
                    #:warn? warn?)
               packages)
              (with-monad %store-monad
                (return #t))))
           (else
            (for-each (cut check-for-package-update <> updaters
                           #:warn? warn?)
                      packages)
            (with-monad %store-monad
              (return #t)))))))))
