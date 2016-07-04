;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Chris Marusich <cmmarusich@gmail.com>
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

(define-module (gnu services)
  #:use-module (guix gexp)
  #:use-module (guix monads)
  #:use-module (guix store)
  #:use-module (guix records)
  #:use-module (guix profiles)
  #:use-module (guix sets)
  #:use-module (guix ui)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-9 gnu)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:use-module (ice-9 vlist)
  #:use-module (ice-9 match)
  #:export (service-extension
            service-extension?

            service-type
            service-type?
            service-type-name
            service-type-extensions
            service-type-compose
            service-type-extend

            service
            service?
            service-kind
            service-parameters

            modify-services
            service-back-edges
            fold-services

            service-error?
            missing-target-service-error?
            missing-target-service-error-service
            missing-target-service-error-target-type
            ambiguous-target-service-error?
            ambiguous-target-service-error-service
            ambiguous-target-service-error-target-type

            system-service-type
            boot-service-type
            cleanup-service-type
            activation-service-type
            activation-service->script
            %linux-bare-metal-service
            etc-service-type
            etc-directory
            setuid-program-service-type
            profile-service-type
            firmware-service-type
            gc-root-service-type

            %boot-service
            %activation-service
            etc-service

            file-union))                      ;XXX: for lack of a better place

;;; Comment:
;;;
;;; This module defines a broad notion of "service types" and "services."
;;;
;;; A service type describe how its instances extend instances of other
;;; service types.  For instance, some services extend the instance of
;;; ACCOUNT-SERVICE-TYPE by providing it with accounts and groups to create;
;;; others extend SHEPHERD-ROOT-SERVICE-TYPE by passing it instances of
;;; <shepherd-service>.
;;;
;;; When applicable, the service type defines how it can itself be extended,
;;; by providing one procedure to compose extensions, and one procedure to
;;; extend itself.
;;;
;;; A notable service type is SYSTEM-SERVICE-TYPE, which has a single
;;; instance, which is the root of the service DAG.  Its value is the
;;; derivation that produces the 'system' directory as returned by
;;; 'operating-system-derivation'.
;;;
;;; The 'fold-services' procedure can be passed a list of procedures, which it
;;; "folds" by propagating extensions down the graph; it returns the root
;;; service after the applying all its extensions.
;;;
;;; Code:

(define-record-type <service-extension>
  (service-extension target compute)
  service-extension?
  (target  service-extension-target)              ;<service-type>
  (compute service-extension-compute))            ;params -> params

(define-record-type* <service-type> service-type make-service-type
  service-type?
  (name       service-type-name)                  ;symbol (for debugging)

  ;; Things extended by services of this type.
  (extensions service-type-extensions)            ;list of <service-extensions>

  ;; Given a list of extensions, "compose" them.
  (compose    service-type-compose                ;list of Any -> Any
              (default #f))

  ;; Extend the services' own parameters with the extension composition.
  (extend     service-type-extend                 ;list of Any -> parameters
              (default #f)))

(define (write-service-type type port)
  (format port "#<service-type ~a ~a>"
          (service-type-name type)
          (number->string (object-address type) 16)))

(set-record-type-printer! <service-type> write-service-type)

;; Services of a given type.
(define-record-type <service>
  (service type parameters)
  service?
  (type       service-kind)
  (parameters service-parameters))


(define-syntax %modify-service
  (syntax-rules (=>)
    ((_ service)
     service)
    ((_ svc (kind param => exp ...) clauses ...)
     (if (eq? (service-kind svc) kind)
         (let ((param (service-parameters svc)))
           (service (service-kind svc)
                    (begin exp ...)))
         (%modify-service svc clauses ...)))))

(define-syntax modify-services
  (syntax-rules ()
    "Modify the services listed in SERVICES according to CLAUSES and return
the resulting list of services.  Each clause must have the form:

  (TYPE VARIABLE => BODY)

where TYPE is a service type, such as 'guix-service-type', and VARIABLE is an
identifier that is bound within BODY to the value of the service of that
TYPE.  Consider this example:

  (modify-services %base-services
    (guix-service-type config =>
                       (guix-configuration
                        (inherit config)
                        (use-substitutes? #f)
                        (extra-options '(\"--gc-keep-derivations\"))))
    (mingetty-service-type config =>
                           (mingetty-configuration
                            (inherit config)
                            (motd (plain-file \"motd\" \"Hi there!\")))))

It changes the configuration of the GUIX-SERVICE-TYPE instance, and that of
all the MINGETTY-SERVICE-TYPE instances.

This is a shorthand for (map (lambda (svc) ...) %base-services)."
    ((_ services clauses ...)
     (map (lambda (service)
            (%modify-service service clauses ...))
          services))))


;;;
;;; Core services.
;;;

(define (system-derivation mentries mextensions)
  "Return as a monadic value the derivation of the 'system' directory
containing the given entries."
  (mlet %store-monad ((entries    mentries)
                      (extensions (sequence %store-monad mextensions)))
    (lower-object
     (file-union "system"
                 (append entries (concatenate extensions))))))

(define system-service-type
  ;; This is the ultimate service type, the root of the service DAG.  The
  ;; service of this type is extended by monadic name/item pairs.  These items
  ;; end up in the "system directory" as returned by
  ;; 'operating-system-derivation'.
  (service-type (name 'system)
                (extensions '())
                (compose identity)
                (extend system-derivation)))

(define (compute-boot-script _ mexps)
  (mlet %store-monad ((gexps (sequence %store-monad mexps)))
    (gexp->file "boot"
                ;; Clean up and activate the system, then spawn shepherd.
                #~(begin #$@gexps))))

(define (boot-script-entry mboot)
  "Return, as a monadic value, an entry for the boot script in the system
directory."
  (mlet %store-monad ((boot mboot))
    (return `(("boot" ,boot)))))

(define boot-service-type
  ;; The service of this type is extended by being passed gexps as monadic
  ;; values.  It aggregates them in a single script, as a monadic value, which
  ;; becomes its 'parameters'.  It is the only service that extends nothing.
  (service-type (name 'boot)
                (extensions
                 (list (service-extension system-service-type
                                          boot-script-entry)))
                (compose append)
                (extend compute-boot-script)))

(define %boot-service
  ;; The service that produces the boot script.
  (service boot-service-type #t))

(define (cleanup-gexp _)
  "Return as a monadic value a gexp to clean up /tmp and similar places upon
boot."
  (with-monad %store-monad
    (with-imported-modules '((guix build utils))
      (return #~(begin
                  (use-modules (guix build utils))

                  ;; Clean out /tmp and /var/run.
                  ;;
                  ;; XXX This needs to happen before service activations, so it
                  ;; has to be here, but this also implicitly assumes that /tmp
                  ;; and /var/run are on the root partition.
                  (letrec-syntax ((fail-safe (syntax-rules ()
                                               ((_ exp rest ...)
                                                (begin
                                                  (catch 'system-error
                                                    (lambda () exp)
                                                    (const #f))
                                                  (fail-safe rest ...)))
                                               ((_)
                                                #t))))
                    ;; Ignore I/O errors so the system can boot.
                    (fail-safe
                     (delete-file-recursively "/tmp")
                     (delete-file-recursively "/var/run")
                     (mkdir "/tmp")
                     (chmod "/tmp" #o1777)
                     (mkdir "/var/run")
                     (chmod "/var/run" #o755))))))))

(define cleanup-service-type
  ;; Service that cleans things up in /tmp and similar.
  (service-type (name 'cleanup)
                (extensions
                 (list (service-extension boot-service-type
                                          cleanup-gexp)))))

(define* (file-union name files)                  ;FIXME: Factorize.
  "Return a <computed-file> that builds a directory containing all of FILES.
Each item in FILES must be a list where the first element is the file name to
use in the new directory, and the second element is a gexp denoting the target
file."
  (computed-file name
                 #~(begin
                     (mkdir #$output)
                     (chdir #$output)
                     #$@(map (match-lambda
                               ((target source)
                                #~(begin
                                    ;; Stat the source to abort early if it
                                    ;; does not exist.
                                    (stat #$source)

                                    (symlink #$source #$target))))
                             files))))

(define (directory-union name things)
  "Return a directory that is the union of THINGS."
  (match things
    ((one)
     ;; Only one thing; return it.
     one)
    (_
     (computed-file name
                    (with-imported-modules '((guix build union))
                      #~(begin
                          (use-modules (guix build union))
                          (union-build #$output '#$things)))))))

(define* (activation-service->script service)
  "Return as a monadic value the activation script for SERVICE, a service of
ACTIVATION-SCRIPT-TYPE."
  (activation-script (service-parameters service)))

(define (activation-script gexps)
  "Return the system's activation script, which evaluates GEXPS."
  (define %modules
    '((gnu build activation)
      (gnu build linux-boot)
      (gnu build linux-modules)
      (gnu build file-systems)
      (guix build utils)
      (guix build syscalls)
      (guix build bournish)
      (guix elf)))

  (define (service-activations)
    ;; Return the activation scripts for SERVICES.
    (mapm %store-monad
          (cut gexp->file "activate-service" <>)
          gexps))

  (mlet* %store-monad ((actions (service-activations)))
    (gexp->file "activate"
                (with-imported-modules %modules
                  #~(begin
                      (use-modules (gnu build activation))

                      ;; Make sure /bin/sh is valid and current.
                      (activate-/bin/sh
                       (string-append #$(canonical-package bash) "/bin/sh"))

                      ;; Run the services' activation snippets.
                      ;; TODO: Use 'load-compiled'.
                      (for-each primitive-load '#$actions)

                      ;; Set up /run/current-system.
                      (activate-current-system))))))

(define (gexps->activation-gexp gexps)
  "Return a gexp that runs the activation script containing GEXPS."
  (mlet %store-monad ((script (activation-script gexps)))
    (return #~(primitive-load #$script))))

(define (second-argument a b) b)

(define activation-service-type
  (service-type (name 'activate)
                (extensions
                 (list (service-extension boot-service-type
                                          gexps->activation-gexp)))
                (compose append)
                (extend second-argument)))

(define %activation-service
  ;; The activation service produces the activation script from the gexps it
  ;; receives.
  (service activation-service-type #t))

(define %modprobe-wrapper
  ;; Wrapper for the 'modprobe' command that knows where modules live.
  ;;
  ;; This wrapper is typically invoked by the Linux kernel ('call_modprobe',
  ;; in kernel/kmod.c), a situation where the 'LINUX_MODULE_DIRECTORY'
  ;; environment variable is not set---hence the need for this wrapper.
  (let ((modprobe "/run/current-system/profile/bin/modprobe"))
    (program-file "modprobe"
                  #~(begin
                      (setenv "LINUX_MODULE_DIRECTORY"
                              "/run/booted-system/kernel/lib/modules")
                      (apply execl #$modprobe
                             (cons #$modprobe (cdr (command-line))))))))

(define %linux-kernel-activation
  ;; Activation of the Linux kernel running on the bare metal (as opposed to
  ;; running in a container.)
  #~(begin
      ;; Tell the kernel to use our 'modprobe' command.
      (activate-modprobe #$%modprobe-wrapper)

      ;; Let users debug their own processes!
      (activate-ptrace-attach)))

(define linux-bare-metal-service-type
  (service-type (name 'linux-bare-metal)
                (extensions
                 (list (service-extension activation-service-type
                                          (const %linux-kernel-activation))))))

(define %linux-bare-metal-service
  ;; The service that does things that are needed on the "bare metal", but not
  ;; necessary or impossible in a container.
  (service linux-bare-metal-service-type #f))

(define (etc-directory service)
  "Return the directory for SERVICE, a service of type ETC-SERVICE-TYPE."
  (files->etc-directory (service-parameters service)))

(define (files->etc-directory files)
  (file-union "etc" files))

(define (etc-entry files)
  "Return an entry for the /etc directory consisting of FILES in the system
directory."
  (with-monad %store-monad
    (return `(("etc" ,(files->etc-directory files))))))

(define etc-service-type
  (service-type (name 'etc)
                (extensions
                 (list
                  (service-extension activation-service-type
                                     (lambda (files)
                                       (let ((etc
                                              (files->etc-directory files)))
                                         #~(activate-etc #$etc))))
                  (service-extension system-service-type etc-entry)))
                (compose concatenate)
                (extend append)))

(define (etc-service files)
  "Return a new service of ETC-SERVICE-TYPE that populates /etc with FILES.
FILES must be a list of name/file-like object pairs."
  (service etc-service-type files))

(define setuid-program-service-type
  (service-type (name 'setuid-program)
                (extensions
                 (list (service-extension activation-service-type
                                          (lambda (programs)
                                            #~(activate-setuid-programs
                                               (list #$@programs))))))
                (compose concatenate)
                (extend append)))

(define (packages->profile-entry packages)
  "Return a system entry for the profile containing PACKAGES."
  (mlet %store-monad ((profile (profile-derivation
                                (packages->manifest
                                 (delete-duplicates packages eq?)))))
    (return `(("profile" ,profile)))))

(define profile-service-type
  ;; The service that populates the system's profile---i.e.,
  ;; /run/current-system/profile.  It is extended by package lists.
  (service-type (name 'profile)
                (extensions
                 (list (service-extension system-service-type
                                          packages->profile-entry)))
                (compose concatenate)
                (extend append)))

(define (firmware->activation-gexp firmware)
  "Return a gexp to make the packages listed in FIRMWARE loadable by the
kernel."
  (let ((directory (directory-union "firmware" firmware)))
    ;; Tell the kernel where firmware is.
    #~(activate-firmware (string-append #$directory "/lib/firmware"))))

(define firmware-service-type
  ;; The service that collects firmware.
  (service-type (name 'firmware)
                (extensions
                 (list (service-extension activation-service-type
                                          firmware->activation-gexp)))
                (compose concatenate)
                (extend append)))

(define (gc-roots->system-entry roots)
  "Return an entry in the system's output containing symlinks to ROOTS."
  (mlet %store-monad ((entry (gexp->derivation
                              "gc-roots"
                              #~(let ((roots '#$roots))
                                  (mkdir #$output)
                                  (chdir #$output)
                                  (for-each symlink
                                            roots
                                            (map number->string
                                                 (iota (length roots))))))))
    (return (if (null? roots)
                '()
                `(("gc-roots" ,entry))))))

(define gc-root-service-type
  ;; A service to associate extra garbage-collector roots to the system.  This
  ;; is a simple hack that guarantees that the system retains references to
  ;; the given list of roots.  Roots must be "lowerable" objects like
  ;; packages, or derivations.
  (service-type (name 'gc-roots)
                (extensions
                 (list (service-extension system-service-type
                                          gc-roots->system-entry)))
                (compose concatenate)
                (extend append)))


;;;
;;; Service folding.
;;;

(define-condition-type &service-error &error
  service-error?)

(define-condition-type &missing-target-service-error &service-error
  missing-target-service-error?
  (service      missing-target-service-error-service)
  (target-type  missing-target-service-error-target-type))

(define-condition-type &ambiguous-target-service-error &service-error
  ambiguous-target-service-error?
  (service      ambiguous-target-service-error-service)
  (target-type  ambiguous-target-service-error-target-type))

(define (service-back-edges services)
  "Return a procedure that, when passed a <service>, returns the list of
<service> objects that depend on it."
  (define (add-edges service edges)
    (define (add-edge extension edges)
      (let ((target-type (service-extension-target extension)))
        (match (filter (lambda (service)
                         (eq? (service-kind service) target-type))
                       services)
          ((target)
           (vhash-consq target service edges))
          (()
           (raise
            (condition (&missing-target-service-error
                        (service service)
                        (target-type target-type))
                       (&message
                        (message
                         (format #f (_ "no target of type '~a' for service ~s")
                                 (service-type-name target-type)
                                 service))))))
          (x
           (raise
            (condition (&ambiguous-target-service-error
                        (service service)
                        (target-type target-type))
                       (&message
                        (message
                         (format #f
                                 (_ "more than one target service of type '~a'")
                                 (service-type-name target-type))))))))))

    (fold add-edge edges (service-type-extensions (service-kind service))))

  (let ((edges (fold add-edges vlist-null services)))
    (lambda (node)
      (reverse (vhash-foldq* cons '() node edges)))))

(define* (fold-services services
                        #:key (target-type system-service-type))
  "Fold SERVICES by propagating their extensions down to the root of type
TARGET-TYPE; return the root service adjusted accordingly."
  (define dependents
    (service-back-edges services))

  (define (matching-extension target)
    (let ((target (service-kind target)))
      (match-lambda
        (($ <service-extension> type)
         (eq? type target)))))

  (define (apply-extension target)
    (lambda (service)
      (match (find (matching-extension target)
                   (service-type-extensions (service-kind service)))
        (($ <service-extension> _ compute)
         (compute (service-parameters service))))))

  (match (filter (lambda (service)
                   (eq? (service-kind service) target-type))
                 services)
    ((sink)
     (let loop ((sink sink))
       (let* ((dependents (map loop (dependents sink)))
              (extensions (map (apply-extension sink) dependents))
              (extend     (service-type-extend (service-kind sink)))
              (compose    (service-type-compose (service-kind sink)))
              (params     (service-parameters sink)))
         ;; We distinguish COMPOSE and EXTEND because PARAMS typically has a
         ;; different type than the elements of EXTENSIONS.
         (if extend
             (service (service-kind sink)
                      (extend params (compose extensions)))
             sink))))
    (()
     (raise
      (condition (&missing-target-service-error
                  (service #f)
                  (target-type target-type))
                 (&message
                  (message (format #f (_ "service of type '~a' not found")
                                   (service-type-name target-type)))))))
    (x
     (raise
      (condition (&ambiguous-target-service-error
                  (service #f)
                  (target-type target-type))
                 (&message
                  (message
                   (format #f
                           (_ "more than one target service of type '~a'")
                           (service-type-name target-type)))))))))

;;; services.scm ends here.
