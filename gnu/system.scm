;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015, 2016 Alex Kost <alezost@gmail.com>
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

(define-module (gnu system)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix gexp)
  #:use-module (guix records)
  #:use-module (guix packages)
  #:use-module (guix derivations)
  #:use-module (guix profiles)
  #:use-module (guix ui)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages pciutils)
  #:use-module (gnu packages package-management)
  #:use-module (gnu packages less)
  #:use-module (gnu packages zile)
  #:use-module (gnu packages nano)
  #:use-module (gnu packages lsof)
  #:use-module (gnu packages gawk)
  #:use-module (gnu packages man)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages firmware)
  #:autoload   (gnu packages cryptsetup) (cryptsetup)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu services base)
  #:use-module (gnu system grub)
  #:use-module (gnu system shadow)
  #:use-module (gnu system nss)
  #:use-module (gnu system locale)
  #:use-module (gnu system pam)
  #:use-module (gnu system linux-initrd)
  #:use-module (gnu system file-systems)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:export (operating-system
            operating-system?

            operating-system-bootloader
            operating-system-services
            operating-system-user-services
            operating-system-packages
            operating-system-host-name
            operating-system-hosts-file
            operating-system-kernel
            operating-system-kernel-arguments
            operating-system-initrd
            operating-system-users
            operating-system-groups
            operating-system-issue
            operating-system-timezone
            operating-system-locale
            operating-system-locale-definitions
            operating-system-locale-libcs
            operating-system-mapped-devices
            operating-system-file-systems
            operating-system-store-file-system
            operating-system-activation-script

            operating-system-derivation
            operating-system-profile
            operating-system-grub.cfg
            operating-system-etc-directory
            operating-system-locale-directory
            operating-system-boot-script

            boot-parameters
            boot-parameters?
            boot-parameters-label
            boot-parameters-root-device
            boot-parameters-kernel
            boot-parameters-kernel-arguments
            read-boot-parameters

            local-host-aliases
            %setuid-programs
            %base-packages
            %base-firmware

            luks-device-mapping))

;;; Commentary:
;;;
;;; This module supports whole-system configuration.
;;;
;;; Code:

;; System-wide configuration.
;; TODO: Add per-field docstrings/stexi.
(define-record-type* <operating-system> operating-system
  make-operating-system
  operating-system?
  (kernel operating-system-kernel                 ; package
          (default linux-libre))
  (kernel-arguments operating-system-kernel-arguments
                    (default '()))                ; list of gexps/strings
  (bootloader operating-system-bootloader)        ; <grub-configuration>

  (initrd operating-system-initrd                 ; (list fs) -> M derivation
          (default base-initrd))
  (firmware operating-system-firmware             ; list of packages
            (default %base-firmware))

  (host-name operating-system-host-name)          ; string
  (hosts-file operating-system-hosts-file         ; file-like | #f
              (default #f))

  (mapped-devices operating-system-mapped-devices ; list of <mapped-device>
                  (default '()))
  (file-systems operating-system-file-systems)    ; list of fs
  (swap-devices operating-system-swap-devices     ; list of strings
                (default '()))

  (users operating-system-users                   ; list of user accounts
         (default %base-user-accounts))
  (groups operating-system-groups                 ; list of user groups
          (default %base-groups))

  (skeletons operating-system-skeletons           ; list of name/monadic value
             (default (default-skeletons)))
  (issue operating-system-issue                   ; string
         (default %default-issue))

  (packages operating-system-packages             ; list of (PACKAGE OUTPUT...)
            (default %base-packages))             ; or just PACKAGE

  (timezone operating-system-timezone)            ; string
  (locale   operating-system-locale               ; string
            (default "en_US.utf8"))
  (locale-definitions operating-system-locale-definitions ; list of <locale-definition>
                      (default %default-locale-definitions))
  (locale-libcs operating-system-locale-libcs     ; list of <packages>
                (default %default-locale-libcs))
  (name-service-switch operating-system-name-service-switch ; <name-service-switch>
                       (default %default-nss))

  (services operating-system-user-services        ; list of monadic services
            (default %base-services))

  (pam-services operating-system-pam-services     ; list of PAM services
                (default (base-pam-services)))
  (setuid-programs operating-system-setuid-programs
                   (default %setuid-programs))    ; list of string-valued gexps

  (sudoers-file operating-system-sudoers-file     ; file-like
                (default %sudoers-specification)))


;;;
;;; Services.
;;;

(define (open-luks-device source target)
  "Return a gexp that maps SOURCE to TARGET as a LUKS device, using
'cryptsetup'."
  #~(zero? (system* (string-append #$cryptsetup "/sbin/cryptsetup")
                    "open" "--type" "luks"
                    #$source #$target)))

(define (close-luks-device source target)
  "Return a gexp that closes TARGET, a LUKS device."
  #~(zero? (system* (string-append #$cryptsetup "/sbin/cryptsetup")
                    "close" #$target)))

(define luks-device-mapping
  ;; The type of LUKS mapped devices.
  (mapped-device-kind
   (open open-luks-device)
   (close close-luks-device)))

(define (other-file-system-services os)
  "Return file system services for the file systems of OS that are not marked
as 'needed-for-boot'."
  (define file-systems
    (remove file-system-needed-for-boot?
            (operating-system-file-systems os)))

  (define (device-mappings fs)
    (let ((device (file-system-device fs)))
      (if (string? device)                        ;title is 'device
          (filter (lambda (md)
                    (string=? (string-append "/dev/mapper/"
                                             (mapped-device-target md))
                              device))
                  (operating-system-mapped-devices os))
          '())))

  (define (add-dependencies fs)
    ;; Add the dependencies due to device mappings to FS.
    (file-system
      (inherit fs)
      (dependencies
       (delete-duplicates (append (device-mappings fs)
                                  (file-system-dependencies fs))
                          eq?))))

  (map (compose file-system-service add-dependencies) file-systems))

(define (mapped-device-user device file-systems)
  "Return a file system among FILE-SYSTEMS that uses DEVICE, or #f."
  (let ((target (string-append "/dev/mapper/" (mapped-device-target device))))
    (find (lambda (fs)
            (and (eq? 'device (file-system-title fs))
                 (string=? (file-system-device fs) target)))
          file-systems)))

(define (operating-system-user-mapped-devices os)
  "Return the subset of mapped devices that can be installed in
user-land--i.e., those not needed during boot."
  (let ((devices      (operating-system-mapped-devices os))
        (file-systems (operating-system-file-systems os)))
   (filter (lambda (md)
             (let ((user (mapped-device-user md file-systems)))
               (or (not user)
                   (not (file-system-needed-for-boot? user)))))
           devices)))

(define (operating-system-boot-mapped-devices os)
  "Return the subset of mapped devices that must be installed during boot,
from the initrd."
  (let ((devices      (operating-system-mapped-devices os))
        (file-systems (operating-system-file-systems os)))
   (filter (lambda (md)
             (let ((user (mapped-device-user md file-systems)))
               (and user (file-system-needed-for-boot? user))))
           devices)))

(define (device-mapping-services os)
  "Return the list of device-mapping services for OS as a list."
  (map (lambda (md)
         (let* ((source (mapped-device-source md))
                (target (mapped-device-target md))
                (type   (mapped-device-type md))
                (open   (mapped-device-kind-open type))
                (close  (mapped-device-kind-close type)))
           (device-mapping-service target
                                   (open source target)
                                   (close source target))))
       (operating-system-user-mapped-devices os)))

(define (swap-services os)
  "Return the list of swap services for OS."
  (map swap-service (operating-system-swap-devices os)))

(define* (operating-system-directory-base-entries os #:key container?)
  "Return the basic entries of the 'system' directory of OS for use as the
value of the SYSTEM-SERVICE-TYPE service."
  (mlet %store-monad ((locale (operating-system-locale-directory os)))
    (if container?
        (return `(("locale" ,locale)))
        (mlet %store-monad
            ((kernel  ->  (operating-system-kernel os))
             (initrd      (operating-system-initrd-file os))
             (params      (operating-system-parameters-file os)))
          (return `(("kernel" ,kernel)
                    ("parameters" ,params)
                    ("initrd" ,initrd)
                    ("locale" ,locale)))))))      ;used by libc

(define* (essential-services os #:key container?)
  "Return the list of essential services for OS.  These are special services
that implement part of what's declared in OS are responsible for low-level
bookkeeping.  CONTAINER? determines whether to return the list of services for
a container or that of a \"bare metal\" system."
  (define known-fs
    (map file-system-mount-point (operating-system-file-systems os)))

  (let* ((mappings  (device-mapping-services os))
         (root-fs   (root-file-system-service))
         (other-fs  (other-file-system-services os))
         (unmount   (user-unmount-service known-fs))
         (swaps     (swap-services os))
         (procs     (user-processes-service
                     (map service-parameters other-fs)))
         (host-name (host-name-service (operating-system-host-name os)))
         (entries   (operating-system-directory-base-entries
                     os #:container? container?)))
    (cons* (service system-service-type entries)
           %boot-service

           ;; %SHEPHERD-ROOT-SERVICE must come first so that the gexp that
           ;; execs shepherd comes last in the boot script (XXX).  Likewise,
           ;; the cleanup service must come last so that its gexp runs before
           ;; activation code.
           %shepherd-root-service
           %activation-service
           (service cleanup-service-type #f)

           (pam-root-service (operating-system-pam-services os))
           (account-service (append (operating-system-accounts os)
                                    (operating-system-groups os))
                            (operating-system-skeletons os))
           (operating-system-etc-service os)
           (service fstab-service-type '())
           (session-environment-service
            (operating-system-environment-variables os))
           host-name procs root-fs unmount
           (service setuid-program-service-type
                    (operating-system-setuid-programs os))
           (service profile-service-type
                    (operating-system-packages os))
           (append other-fs mappings swaps

                   ;; Add the firmware service, unless we are building for a
                   ;; container.
                   (if container?
                       '()
                       (list %linux-bare-metal-service
                             (service firmware-service-type
                                      (operating-system-firmware os))))))))

(define* (operating-system-services os #:key container?)
  "Return all the services of OS, including \"internal\" services that do not
explicitly appear in OS."
  (append (operating-system-user-services os)
          (essential-services os #:container? container?)))


;;;
;;; /etc.
;;;

(define %base-firmware
  ;; Firmware usable by default.
  (list ath9k-htc-firmware))

(define %base-packages
  ;; Default set of packages globally visible.  It should include anything
  ;; required for basic administrator tasks.
  (cons* procps psmisc which less zile nano
         lsof                                 ;for Guix's 'list-runtime-roots'
         pciutils usbutils
         util-linux inetutils isc-dhcp

         ;; wireless-tools is deprecated in favor of iw, but it's still what
         ;; many people are familiar with, so keep it around.
         iw wireless-tools rfkill

         iproute
         net-tools                        ; XXX: remove when Inetutils suffices
         man-db
         texinfo                               ;for the standalone Info reader

         ;; The 'sudo' command is already in %SETUID-PROGRAMS, but we also
         ;; want the other commands and the man pages (notably because
         ;; auto-completion in Emacs shell relies on man pages.)
         sudo

         ;; Get 'insmod' & co. from kmod, not module-init-tools, since udev
         ;; already depends on it anyway.
         kmod eudev

         e2fsprogs kbd

         bash-completion

         ;; The packages below are also in %FINAL-INPUTS, so take them from
         ;; there to avoid duplication.
         (map canonical-package
              (list guile-2.0 bash coreutils findutils grep sed
                    diffutils patch gawk tar gzip bzip2 xz lzip))))

(define %default-issue
  ;; Default contents for /etc/issue.
  "
This is the GNU system.  Welcome.\n")

(define (local-host-aliases host-name)
  "Return aliases for HOST-NAME, to be used in /etc/hosts."
  (string-append "127.0.0.1 localhost " host-name "\n"
                 "::1       localhost " host-name "\n"))

(define (default-/etc/hosts host-name)
  "Return the default /etc/hosts file."
  (plain-file "hosts" (local-host-aliases host-name)))

(define (emacs-site-file)
  "Return the Emacs 'site-start.el' file.  That file contains the necessary
settings for 'guix.el' to work out-of-the-box."
  (scheme-file "site-start.el"
               #~(progn
                  ;; Add the "normal" elisp directory to the search path;
                  ;; guix.el may be there.
                  (add-to-list
                   'load-path
                   "/run/current-system/profile/share/emacs/site-lisp")

                  ;; Attempt to load guix.el.
                  (require 'guix-init nil t)

                  ;; Attempt to load geiser.
                  (require 'geiser-install nil t))))

(define (emacs-site-directory)
  "Return the Emacs site directory, aka. /etc/emacs."
  (computed-file "emacs"
                 #~(begin
                     (mkdir #$output)
                     (chdir #$output)
                     (symlink #$(emacs-site-file) "site-start.el"))))

(define* (operating-system-etc-service os)
  "Return a <service> that builds containing the static part of the /etc
directory."
  (let ((login.defs (plain-file "login.defs" "# Empty for now.\n"))

        (emacs      (emacs-site-directory))
        (issue      (plain-file "issue" (operating-system-issue os)))
        (nsswitch   (plain-file "nsswitch.conf"
                                (name-service-switch->string
                                 (operating-system-name-service-switch os))))

        ;; Startup file for POSIX-compliant login shells, which set system-wide
        ;; environment variables.
        (profile    (mixed-text-file "profile"  "\
# Crucial variables that could be missing in the profiles' 'etc/profile'
# because they would require combining both profiles.
# FIXME: See <http://bugs.gnu.org/20255>.
export MANPATH=$HOME/.guix-profile/share/man:/run/current-system/profile/share/man
export INFOPATH=$HOME/.guix-profile/share/info:/run/current-system/profile/share/info
export XDG_DATA_DIRS=$HOME/.guix-profile/share:/run/current-system/profile/share
export XDG_CONFIG_DIRS=$HOME/.guix-profile/etc/xdg:/run/current-system/profile/etc/xdg

# Ignore the default value of 'PATH'.
unset PATH

# Load the system profile's settings.
GUIX_PROFILE=/run/current-system/profile \\
. /run/current-system/profile/etc/profile

# Prepend setuid programs.
export PATH=/run/setuid-programs:$PATH

if [ -f \"$HOME/.guix-profile/etc/profile\" ]
then
  # Load the user profile's settings.
  GUIX_PROFILE=\"$HOME/.guix-profile\" \\
  . \"$HOME/.guix-profile/etc/profile\"
else
  # At least define this one so that basic things just work
  # when the user installs their first package.
  export PATH=\"$HOME/.guix-profile/bin:$PATH\"
fi

# Since 'lshd' does not use pam_env, /etc/environment must be explicitly
# loaded when someone logs in via SSH.  See <http://bugs.gnu.org/22175>.
# We need 'PATH' to be defined here, for 'cat' and 'cut'.
if [ -f /etc/environment -a -n \"$SSH_CLIENT\" \\
     -a -z \"$LINUX_MODULE_DIRECTORY\" ]
then
  . /etc/environment
  export `cat /etc/environment | cut -d= -f1`
fi

# Set the umask, notably for users logging in via 'lsh'.
# See <http://bugs.gnu.org/22650>.
umask 022

# Allow GStreamer-based applications to find plugins.
export GST_PLUGIN_PATH=\"$HOME/.guix-profile/lib/gstreamer-1.0\"

if [ -n \"$BASH_VERSION\" -a -f /etc/bashrc ]
then
  # Load Bash-specific initialization code.
  . /etc/bashrc
fi
"))

        (bashrc    (plain-file "bashrc" "\
# Bash-specific initialization.

# The 'bash-completion' package.
if [ -f /run/current-system/profile/etc/profile.d/bash_completion.sh ]
then
  # Bash-completion sources ~/.bash_completion.  It installs a dynamic
  # completion loader that searches its own completion files as well
  # as those in ~/.guix-profile and /run/current-system/profile.
  source /run/current-system/profile/etc/profile.d/bash_completion.sh
fi\n")))
    (etc-service
     `(("services" ,#~(string-append #$net-base "/etc/services"))
       ("protocols" ,#~(string-append #$net-base "/etc/protocols"))
       ("rpc" ,#~(string-append #$net-base "/etc/rpc"))
       ("emacs" ,#~#$emacs)
       ("login.defs" ,#~#$login.defs)
       ("issue" ,#~#$issue)
       ("nsswitch.conf" ,#~#$nsswitch)
       ("profile" ,#~#$profile)
       ("bashrc" ,#~#$bashrc)
       ("hosts" ,#~#$(or (operating-system-hosts-file os)
                         (default-/etc/hosts (operating-system-host-name os))))
       ("localtime" ,#~(string-append #$tzdata "/share/zoneinfo/"
                                      #$(operating-system-timezone os)))
       ("sudoers" ,(operating-system-sudoers-file os))))))

(define %root-account
  ;; Default root account.
  (user-account
   (name "root")
   (password "")
   (uid 0) (group "root")
   (comment "System administrator")
   (home-directory "/root")))

(define (operating-system-accounts os)
  "Return the user accounts for OS, including an obligatory 'root' account,
and excluding accounts requested by services."
  ;; Make sure there's a root account.
  (if (find (lambda (user)
              (and=> (user-account-uid user) zero?))
            (operating-system-users os))
      (operating-system-users os)
      (cons %root-account (operating-system-users os))))

(define (maybe-string->file file-name thing)
  "If THING is a string, return a <plain-file> with THING as its content.
Otherwise just return THING.

This is for backward-compatibility of fields that used to be strings and are
now file-like objects.."
  (match thing
    ((? string?)
     (warning (_ "using a string for file '~a' is deprecated; \
use 'plain-file' instead~%")
              file-name)
     (plain-file file-name thing))
    (x
     x)))

(define (maybe-file->monadic file-name thing)
  "If THING is a value in %STORE-MONAD, return it as is; otherwise return
THING in the %STORE-MONAD.

This is for backward-compatibility of fields that used to be monadic values
and are now file-like objects."
  (with-monad %store-monad
    (match thing
      ((? procedure?)
       (warning (_ "using a monadic value for '~a' is deprecated; \
use 'plain-file' instead~%")
                file-name)
       thing)
      (x
       (return x)))))

(define (operating-system-etc-directory os)
  "Return that static part of the /etc directory of OS."
  (etc-directory
   (fold-services (operating-system-services os)
                  #:target-type etc-service-type)))

(define (operating-system-environment-variables os)
  "Return the environment variables of OS for
@var{session-environment-service-type}, to be used in @file{/etc/environment}."
  `(("LANG" . ,(operating-system-locale os))
    ("TZ" . ,(operating-system-timezone os))
    ("TZDIR" . ,#~(string-append #$tzdata "/share/zoneinfo"))
    ;; Tell 'modprobe' & co. where to look for modules.
    ("LINUX_MODULE_DIRECTORY" . "/run/booted-system/kernel/lib/modules")
    ;; These variables are honored by OpenSSL (libssl) and Git.
    ("SSL_CERT_DIR" . "/etc/ssl/certs")
    ("SSL_CERT_FILE" . "/etc/ssl/certs/ca-certificates.crt")
    ("GIT_SSL_CAINFO" . "/etc/ssl/certs/ca-certificates.crt")
    ;; Prepend the directory of 'site-start.el' to the search path, so
    ;; that it has higher precedence than the 'site-start.el' file our
    ;; Emacs package provides.
    ("EMACSLOADPATH" . "/etc/emacs:")
    ;; By default, applications that use D-Bus, such as Emacs, abort at startup
    ;; when /etc/machine-id is missing.  Make sure these warnings are non-fatal.
    ("DBUS_FATAL_WARNINGS" . "0")))

(define %setuid-programs
  ;; Default set of setuid-root programs.
  (let ((shadow (@ (gnu packages admin) shadow)))
    (list #~(string-append #$shadow "/bin/passwd")
          #~(string-append #$shadow "/bin/su")
          #~(string-append #$inetutils "/bin/ping")
          #~(string-append #$inetutils "/bin/ping6")
          #~(string-append #$sudo "/bin/sudo")
          #~(string-append #$fuse "/bin/fusermount"))))

(define %sudoers-specification
  ;; Default /etc/sudoers contents: 'root' and all members of the 'wheel'
  ;; group can do anything.  See
  ;; <http://www.sudo.ws/sudo/man/1.8.10/sudoers.man.html>.
  ;; TODO: Add a declarative API.
  (plain-file "sudoers" "\
root ALL=(ALL) ALL
%wheel ALL=(ALL) ALL\n"))

(define* (operating-system-activation-script os #:key container?)
  "Return the activation script for OS---i.e., the code that \"activates\" the
stateful part of OS, including user accounts and groups, special directories,
etc."
  (let* ((services   (operating-system-services os #:container? container?))
         (activation (fold-services services
                                    #:target-type activation-service-type)))
    (activation-service->script activation)))

(define* (operating-system-boot-script os #:key container?)
  "Return the boot script for OS---i.e., the code started by the initrd once
we're running in the final root.  When CONTAINER? is true, skip all
hardware-related operations as necessary when booting a Linux container."
  (let* ((services (operating-system-services os #:container? container?))
         (boot     (fold-services services #:target-type boot-service-type)))
    ;; BOOT is the script as a monadic value.
    (service-parameters boot)))

(define* (operating-system-derivation os #:key container?)
  "Return a derivation that builds OS."
  (let* ((services (operating-system-services os #:container? container?))
         (system   (fold-services services)))
    ;; SYSTEM contains the derivation as a monadic value.
    (service-parameters system)))

(define* (operating-system-profile os #:key container?)
  "Return a derivation that builds the system profile of OS."
  (mlet* %store-monad
      ((services -> (operating-system-services os #:container? container?))
       (profile (fold-services services
                               #:target-type profile-service-type)))
    (match profile
      (("profile" profile)
       (return profile)))))

(define (operating-system-root-file-system os)
  "Return the root file system of OS."
  (find (match-lambda
         (($ <file-system> _ _ "/") #t)
         (_ #f))
        (operating-system-file-systems os)))

(define (operating-system-initrd-file os)
  "Return a gexp denoting the initrd file of OS."
  (define boot-file-systems
    (filter file-system-needed-for-boot?
            (operating-system-file-systems os)))

  (define mapped-devices
    (operating-system-boot-mapped-devices os))

  (define make-initrd
    (operating-system-initrd os))

  (mlet %store-monad ((initrd (make-initrd boot-file-systems
                                           #:linux (operating-system-kernel os)
                                           #:mapped-devices mapped-devices)))
    (return #~(string-append #$initrd "/initrd"))))

(define (locale-name->definition* name)
  "Variant of 'locale-name->definition' that raises an error upon failure."
  (match (locale-name->definition name)
    (#f
     (raise (condition
             (&message
              (message (format #f (_ "~a: invalid locale name") name))))))
    (def def)))

(define (operating-system-locale-directory os)
  "Return the directory containing the locales compiled for the definitions
listed in OS.  The C library expects to find it under
/run/current-system/locale."
  (define name
    (operating-system-locale os))

  (define definitions
    ;; While we're at it, check whether NAME is defined and add it if needed.
    (if (member name (map locale-definition-name
                          (operating-system-locale-definitions os)))
        (operating-system-locale-definitions os)
        (cons (locale-name->definition* name)
              (operating-system-locale-definitions os))))

  (locale-directory definitions
                    #:libcs (operating-system-locale-libcs os)))

(define (kernel->grub-label kernel)
  "Return a label for the GRUB menu entry that boots KERNEL."
  (string-append "GNU with "
                 (string-titlecase (package-name kernel)) " "
                 (package-version kernel)
                 " (beta)"))

(define (store-file-system file-systems)
  "Return the file system object among FILE-SYSTEMS that contains the store."
  (match (filter (lambda (fs)
                   (and (file-system-mount? fs)
                        (not (memq 'bind-mount (file-system-flags fs)))
                        (string-prefix? (file-system-mount-point fs)
                                        (%store-prefix))))
                 file-systems)
    ((and candidates (head . tail))
     (reduce (lambda (fs1 fs2)
               (if (> (string-length (file-system-mount-point fs1))
                      (string-length (file-system-mount-point fs2)))
                   fs1
                   fs2))
             head
             candidates))))

(define (operating-system-store-file-system os)
  "Return the file system that contains the store of OS."
  (store-file-system (operating-system-file-systems os)))

(define* (operating-system-grub.cfg os #:optional (old-entries '()))
  "Return the GRUB configuration file for OS.  Use OLD-ENTRIES to populate the
\"old entries\" menu."
  (mlet* %store-monad
      ((system      (operating-system-derivation os))
       (root-fs ->  (operating-system-root-file-system os))
       (store-fs -> (operating-system-store-file-system os))
       (kernel ->   (operating-system-kernel os))
       (root-device -> (if (eq? 'uuid (file-system-title root-fs))
                           (uuid->string (file-system-device root-fs))
                           (file-system-device root-fs)))
       (entries ->  (list (menu-entry
                           (label (kernel->grub-label kernel))
                           (linux kernel)
                           (linux-arguments
                            (cons* (string-append "--root=" root-device)
                                   #~(string-append "--system=" #$system)
                                   #~(string-append "--load=" #$system
                                                    "/boot")
                                   (operating-system-kernel-arguments os)))
                           (initrd #~(string-append #$system "/initrd"))))))
    (grub-configuration-file (operating-system-bootloader os)
                             store-fs entries
                             #:old-entries old-entries)))

(define (operating-system-parameters-file os)
  "Return a file that describes the boot parameters of OS.  The primary use of
this file is the reconstruction of GRUB menu entries for old configurations."
  (mlet %store-monad ((initrd   (operating-system-initrd-file os))
                      (root ->  (operating-system-root-file-system os))
                      (label -> (kernel->grub-label
                                 (operating-system-kernel os))))
    (gexp->file "parameters"
                #~(boot-parameters (version 0)
                                   (label #$label)
                                   (root-device #$(file-system-device root))
                                   (kernel #$(operating-system-kernel os))
                                   (kernel-arguments
                                    #$(operating-system-kernel-arguments os))
                                   (initrd #$initrd)))))


;;;
;;; Boot parameters
;;;

(define-record-type* <boot-parameters>
  boot-parameters make-boot-parameters boot-parameters?
  (label            boot-parameters-label)
  (root-device      boot-parameters-root-device)
  (kernel           boot-parameters-kernel)
  (kernel-arguments boot-parameters-kernel-arguments))

(define (read-boot-parameters port)
  "Read boot parameters from PORT and return the corresponding
<boot-parameters> object or #f if the format is unrecognized."
  (match (read port)
    (('boot-parameters ('version 0)
                       ('label label) ('root-device root)
                       ('kernel linux)
                       rest ...)
     (boot-parameters
      (label label)
      (root-device root)
      (kernel linux)
      (kernel-arguments
       (match (assq 'kernel-arguments rest)
         ((_ args) args)
         (#f       '())))))                       ;the old format
    (x                                            ;unsupported format
     (warning (_ "unrecognized boot parameters for '~a'~%")
              system)
     #f)))

;;; system.scm ends here
