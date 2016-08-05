;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Andy Wingo <wingo@igalia.com>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 Sou Bunnbu <iyzsong@gmail.com>
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

(define-module (gnu services desktop)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu services base)
  #:use-module (gnu services dbus)
  #:use-module (gnu services avahi)
  #:use-module (gnu services xorg)
  #:use-module (gnu services networking)
  #:use-module (gnu system shadow)
  #:use-module (gnu system pam)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages freedesktop)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages xfce)
  #:use-module (gnu packages avahi)
  #:use-module (gnu packages polkit)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages suckless)
  #:use-module (gnu packages linux)
  #:use-module (guix records)
  #:use-module (guix packages)
  #:use-module (guix store)
  #:use-module (guix gexp)
  #:use-module (srfi srfi-1)
  #:use-module (ice-9 match)
  #:export (upower-configuration
            upower-configuration?
            upower-service
            upower-service-type

            udisks-configuration
            udisks-configuration?
            udisks-service
            udisks-service-type

            colord-service

            geoclue-application
            geoclue-configuration
            geoclue-configuration?
            %standard-geoclue-applications
            geoclue-service
            geoclue-service-type

            bluetooth-service

            polkit-configuration
            polkit-configuration?
            polkit-service
            polkit-service-type

            elogind-configuration
            elogind-configuration?
            elogind-service
            elogind-service-type

            gnome-desktop-configuration
            gnome-desktop-configuration?
            gnome-desktop-service
            gnome-desktop-service-type

            xfce-desktop-configuration
            xfce-desktop-configuration?
            xfce-desktop-service
            xfce-desktop-service-type

            %desktop-services))

;;; Commentary:
;;;
;;; This module contains service definitions for a "desktop" environment.
;;;
;;; Code:


;;;
;;; Helpers.
;;;

(define (bool value)
  (if value "true\n" "false\n"))

(define (package-direct-input-selector input)
  (lambda (package)
    (match (assoc-ref (package-direct-inputs package) input)
      ((package . _) package))))


(define (wrapped-dbus-service service program variable value)
  "Return a wrapper for @var{service}, a package containing a D-Bus service,
where @var{program} is wrapped such that environment variable @var{variable}
is set to @var{value} when the bus daemon launches it."
  (define wrapper
    (program-file (string-append (package-name service) "-program-wrapper")
                  #~(begin
                      (setenv #$variable #$value)
                      (apply execl (string-append #$service "/" #$program)
                             (string-append #$service "/" #$program)
                             (cdr (command-line))))))

  (define build
    (with-imported-modules '((guix build utils))
      #~(begin
          (use-modules (guix build utils))

          (define service-directory
            "/share/dbus-1/system-services")

          (mkdir-p (dirname (string-append #$output
                                           service-directory)))
          (copy-recursively (string-append #$service
                                           service-directory)
                            (string-append #$output
                                           service-directory))
          (symlink (string-append #$service "/etc") ;for etc/dbus-1
                   (string-append #$output "/etc"))

          (for-each (lambda (file)
                      (substitute* file
                        (("Exec[[:blank:]]*=[[:blank:]]*([[:graph:]]+)(.*)$"
                          _ original-program arguments)
                         (string-append "Exec=" #$wrapper arguments
                                        "\n"))))
                    (find-files #$output "\\.service$")))))

  (computed-file (string-append (package-name service) "-wrapper")
                 build))


;;;
;;; Upower D-Bus service.
;;;

;; TODO: Export.
(define-record-type* <upower-configuration>
  upower-configuration make-upower-configuration
  upower-configuration?
  (upower        upower-configuration-upower
                 (default upower))
  (watts-up-pro? upower-configuration-watts-up-pro?)
  (poll-batteries? upower-configuration-poll-batteries?)
  (ignore-lid? upower-configuration-ignore-lid?)
  (use-percentage-for-policy? upower-configuration-use-percentage-for-policy?)
  (percentage-low upower-configuration-percentage-low)
  (percentage-critical upower-configuration-percentage-critical)
  (percentage-action upower-configuration-percentage-action)
  (time-low upower-configuration-time-low)
  (time-critical upower-configuration-time-critical)
  (time-action upower-configuration-time-action)
  (critical-power-action upower-configuration-critical-power-action))

(define* upower-configuration-file
  ;; Return an upower-daemon configuration file.
  (match-lambda
    (($ <upower-configuration> upower
        watts-up-pro? poll-batteries? ignore-lid? use-percentage-for-policy?
        percentage-low percentage-critical percentage-action time-low
        time-critical time-action critical-power-action)
     (plain-file "UPower.conf"
                 (string-append
                  "[UPower]\n"
                  "EnableWattsUpPro=" (bool watts-up-pro?)
                  "NoPollBatteries=" (bool (not poll-batteries?))
                  "IgnoreLid=" (bool ignore-lid?)
                  "UsePercentageForPolicy=" (bool use-percentage-for-policy?)
                  "PercentageLow=" (number->string percentage-low) "\n"
                  "PercentageCritical=" (number->string percentage-critical) "\n"
                  "PercentageAction=" (number->string percentage-action) "\n"
                  "TimeLow=" (number->string time-low) "\n"
                  "TimeCritical=" (number->string time-critical) "\n"
                  "TimeAction=" (number->string time-action) "\n"
                  "CriticalPowerAction=" (match critical-power-action
                                           ('hybrid-sleep "HybridSleep")
                                           ('hibernate "Hibernate")
                                           ('power-off "PowerOff"))
                  "\n")))))

(define %upower-activation
  #~(begin
      (use-modules (guix build utils))
      (mkdir-p "/var/lib/upower")))

(define (upower-dbus-service config)
  (list (wrapped-dbus-service (upower-configuration-upower config)
                              "libexec/upowerd"
                              "UPOWER_CONF_FILE_NAME"
                              (upower-configuration-file config))))

(define (upower-shepherd-service config)
  "Return a shepherd service for UPower with CONFIG."
  (let ((upower (upower-configuration-upower config))
        (config (upower-configuration-file config)))
    (list (shepherd-service
           (documentation "Run the UPower power and battery monitor.")
           (provision '(upower-daemon))
           (requirement '(dbus-system udev))

           (start #~(make-forkexec-constructor
                     (list (string-append #$upower "/libexec/upowerd"))
                     #:environment-variables
                     (list (string-append "UPOWER_CONF_FILE_NAME="
                                          #$config))))
           (stop #~(make-kill-destructor))))))

(define upower-service-type
  (let ((upower-package (compose list upower-configuration-upower)))
    (service-type (name 'upower)
                  (extensions
                   (list (service-extension dbus-root-service-type
                                            upower-dbus-service)
                         (service-extension shepherd-root-service-type
                                            upower-shepherd-service)
                         (service-extension activation-service-type
                                            (const %upower-activation))
                         (service-extension udev-service-type
                                            upower-package)

                         ;; Make the 'upower' command visible.
                         (service-extension profile-service-type
                                            upower-package))))))

(define* (upower-service #:key (upower upower)
                         (watts-up-pro? #f)
                         (poll-batteries? #t)
                         (ignore-lid? #f)
                         (use-percentage-for-policy? #f)
                         (percentage-low 10)
                         (percentage-critical 3)
                         (percentage-action 2)
                         (time-low 1200)
                         (time-critical 300)
                         (time-action 120)
                         (critical-power-action 'hybrid-sleep))
  "Return a service that runs @uref{http://upower.freedesktop.org/,
@command{upowerd}}, a system-wide monitor for power consumption and battery
levels, with the given configuration settings.  It implements the
@code{org.freedesktop.UPower} D-Bus interface, and is notably used by GNOME."
  (let ((config (upower-configuration
                 (watts-up-pro? watts-up-pro?)
                 (poll-batteries? poll-batteries?)
                 (ignore-lid? ignore-lid?)
                 (use-percentage-for-policy? use-percentage-for-policy?)
                 (percentage-low percentage-low)
                 (percentage-critical percentage-critical)
                 (percentage-action percentage-action)
                 (time-low time-low)
                 (time-critical time-critical)
                 (time-action time-action)
                 (critical-power-action critical-power-action))))
    (service upower-service-type config)))


;;;
;;; GeoClue D-Bus service.
;;;

;; TODO: Export.
(define-record-type* <geoclue-configuration>
  geoclue-configuration make-geoclue-configuration
  geoclue-configuration?
  (geoclue geoclue-configuration-geoclue
           (default geoclue))
  (whitelist geoclue-configuration-whitelist)
  (wifi-geolocation-url geoclue-configuration-wifi-geolocation-url)
  (submit-data? geoclue-configuration-submit-data?)
  (wifi-submission-url geoclue-configuration-wifi-submission-url)
  (submission-nick geoclue-configuration-submission-nick)
  (applications geoclue-configuration-applications))

(define* (geoclue-application name #:key (allowed? #t) system? (users '()))
  "Configure default GeoClue access permissions for an application.  NAME is
the Desktop ID of the application, without the .desktop part.  If ALLOWED? is
true, the application will have access to location information by default.
The boolean SYSTEM? value indicates that an application is a system component
or not.  Finally USERS is a list of UIDs of all users for which this
application is allowed location info access.  An empty users list means all
users are allowed."
  (string-append
   "[" name "]\n"
   "allowed=" (bool allowed?)
   "system=" (bool system?)
   "users=" (string-join users ";") "\n"))

(define %standard-geoclue-applications
  (list (geoclue-application "gnome-datetime-panel" #:system? #t)
        (geoclue-application "epiphany" #:system? #f)
        (geoclue-application "firefox" #:system? #f)))

(define* (geoclue-configuration-file config)
  "Return a geoclue configuration file."
  (plain-file "geoclue.conf"
              (string-append
               "[agent]\n"
               "whitelist="
               (string-join (geoclue-configuration-whitelist config)
                            ";") "\n"
               "[wifi]\n"
               "url=" (geoclue-configuration-wifi-geolocation-url config) "\n"
               "submit-data=" (bool (geoclue-configuration-submit-data? config))
               "submission-url="
               (geoclue-configuration-wifi-submission-url config) "\n"
               "submission-nick="
               (geoclue-configuration-submission-nick config)
               "\n"
               (string-join (geoclue-configuration-applications config)
                            "\n"))))

(define (geoclue-dbus-service config)
  (list (wrapped-dbus-service (geoclue-configuration-geoclue config)
                              "libexec/geoclue"
                              "GEOCLUE_CONFIG_FILE"
                              (geoclue-configuration-file config))))

(define %geoclue-accounts
  (list (user-group (name "geoclue") (system? #t))
        (user-account
         (name "geoclue")
         (group "geoclue")
         (system? #t)
         (comment "GeoClue daemon user")
         (home-directory "/var/empty")
         (shell "/run/current-system/profile/sbin/nologin"))))

(define geoclue-service-type
  (service-type (name 'geoclue)
                (extensions
                 (list (service-extension dbus-root-service-type
                                          geoclue-dbus-service)
                       (service-extension account-service-type
                                          (const %geoclue-accounts))))))

(define* (geoclue-service #:key (geoclue geoclue)
                          (whitelist '())
                          (wifi-geolocation-url
                           ;; Mozilla geolocation service:
                           "https://location.services.mozilla.com/v1/geolocate?key=geoclue")
                          (submit-data? #f)
                          (wifi-submission-url
                           "https://location.services.mozilla.com/v1/submit?key=geoclue")
                          (submission-nick "geoclue")
                          (applications %standard-geoclue-applications))
  "Return a service that runs the @command{geoclue} location service.  This
service provides a D-Bus interface to allow applications to request access to
a user's physical location, and optionally to add information to online
location databases.  By default, only the GNOME date-time panel and the Icecat
and Epiphany web browsers are able to ask for the user's location, and in the
case of Icecat and Epiphany, both will ask the user for permission first.  See
@uref{https://wiki.freedesktop.org/www/Software/GeoClue/, the geoclue web
site} for more information."
  (service geoclue-service-type
           (geoclue-configuration
            (geoclue geoclue)
            (whitelist whitelist)
            (wifi-geolocation-url wifi-geolocation-url)
            (submit-data? submit-data?)
            (wifi-submission-url wifi-submission-url)
            (submission-nick submission-nick)
            (applications applications))))


;;;
;;; Bluetooth.
;;;

(define (bluetooth-shepherd-service bluez)
  "Return a shepherd service for @command{bluetoothd}."
  (shepherd-service
   (provision '(bluetooth))
   (requirement '(dbus-system udev))
   (documentation "Run the bluetoothd daemon.")
   (start #~(make-forkexec-constructor
             (string-append #$bluez "/libexec/bluetooth/bluetoothd")))
   (stop #~(make-kill-destructor))))

(define bluetooth-service-type
  (service-type
   (name 'bluetooth)
   (extensions
    (list (service-extension dbus-root-service-type list)
          (service-extension udev-service-type list)
          (service-extension shepherd-root-service-type
                             (compose list bluetooth-shepherd-service))))))

(define* (bluetooth-service #:key (bluez bluez))
  "Return a service that runs the @command{bluetoothd} daemon, which manages
all the Bluetooth devices and provides a number of D-Bus interfaces.

Users need to be in the @code{lp} group to access the D-Bus service.
"
  (service bluetooth-service-type bluez))


;;;
;;; Polkit privilege management service.
;;;

(define-record-type* <polkit-configuration>
  polkit-configuration make-polkit-configuration
  polkit-configuration?
  (polkit   polkit-configuration-polkit           ;<package>
            (default polkit))
  (actions  polkit-configuration-actions          ;list of <package>
            (default '())))

(define %polkit-accounts
  (list (user-group (name "polkitd") (system? #t))
        (user-account
         (name "polkitd")
         (group "polkitd")
         (system? #t)
         (comment "Polkit daemon user")
         (home-directory "/var/empty")
         (shell "/run/current-system/profile/sbin/nologin"))))

(define %polkit-pam-services
  (list (unix-pam-service "polkit-1")))

(define (polkit-directory packages)
  "Return a directory containing an @file{actions} and possibly a
@file{rules.d} sub-directory, for use as @file{/etc/polkit-1}."
  (with-imported-modules '((guix build union))
    (computed-file "etc-polkit-1"
                   #~(begin
                       (use-modules (guix build union) (srfi srfi-26))

                       (union-build #$output
                                    (map (cut string-append <>
                                              "/share/polkit-1")
                                         (list #$@packages)))))))

(define polkit-etc-files
  (match-lambda
    (($ <polkit-configuration> polkit packages)
     `(("polkit-1" ,(polkit-directory (cons polkit packages)))))))

(define polkit-setuid-programs
  (match-lambda
    (($ <polkit-configuration> polkit)
     (list #~(string-append #$polkit
                            "/lib/polkit-1/polkit-agent-helper-1")
           #~(string-append #$polkit "/bin/pkexec")))))

(define polkit-service-type
  (service-type (name 'polkit)
                (extensions
                 (list (service-extension account-service-type
                                          (const %polkit-accounts))
                       (service-extension pam-root-service-type
                                          (const %polkit-pam-services))
                       (service-extension dbus-root-service-type
                                          (compose
                                           list
                                           polkit-configuration-polkit))
                       (service-extension etc-service-type
                                          polkit-etc-files)
                       (service-extension setuid-program-service-type
                                          polkit-setuid-programs)))

                ;; Extensions are lists of packages that provide polkit rules
                ;; or actions under share/polkit-1/{actions,rules.d}.
                (compose concatenate)
                (extend (lambda (config actions)
                          (polkit-configuration
                           (inherit config)
                           (actions
                            (append (polkit-configuration-actions config)
                                    actions)))))))

(define* (polkit-service #:key (polkit polkit))
  "Return a service that runs the
@uref{http://www.freedesktop.org/wiki/Software/polkit/, Polkit privilege
management service}, which allows system administrators to grant access to
privileged operations in a structured way.  By querying the Polkit service, a
privileged system component can know when it should grant additional
capabilities to ordinary users.  For example, an ordinary user can be granted
the capability to suspend the system if the user is logged in locally."
  (service polkit-service-type
           (polkit-configuration (polkit polkit))))


;;;
;;; Colord D-Bus service.
;;;

(define %colord-activation
  #~(begin
      (use-modules (guix build utils))
      (mkdir-p "/var/lib/colord")
      (let ((user (getpwnam "colord")))
        (chown "/var/lib/colord"
               (passwd:uid user) (passwd:gid user)))))

(define %colord-accounts
  (list (user-group (name "colord") (system? #t))
        (user-account
         (name "colord")
         (group "colord")
         (system? #t)
         (comment "colord daemon user")
         (home-directory "/var/empty")
         (shell #~(string-append #$shadow "/sbin/nologin")))))

(define colord-service-type
  (service-type (name 'colord)
                (extensions
                 (list (service-extension account-service-type
                                          (const %colord-accounts))
                       (service-extension activation-service-type
                                          (const %colord-activation))

                       ;; Colord is a D-Bus service that dbus-daemon can
                       ;; activate.
                       (service-extension dbus-root-service-type list)

                       ;; Colord provides "color device" rules for udev.
                       (service-extension udev-service-type list)

                       ;; It provides polkit "actions".
                       (service-extension polkit-service-type list)))))

(define* (colord-service #:key (colord colord))
  "Return a service that runs @command{colord}, a system service with a D-Bus
interface to manage the color profiles of input and output devices such as
screens and scanners.  It is notably used by the GNOME Color Manager graphical
tool.  See @uref{http://www.freedesktop.org/software/colord/, the colord web
site} for more information."
  (service colord-service-type colord))


;;;
;;; UDisks.
;;;

(define-record-type* <udisks-configuration>
  udisks-configuration make-udisks-configuration
  udisks-configuration?
  (udisks   udisks-configuration-udisks
            (default udisks)))

(define udisks-service-type
  (let ((udisks-package (lambda (config)
                          (list (udisks-configuration-udisks config)))))
    (service-type (name 'udisks)
                  (extensions
                   (list (service-extension polkit-service-type
                                            udisks-package)
                         (service-extension dbus-root-service-type
                                            udisks-package)
                         (service-extension udev-service-type
                                            udisks-package)

                         ;; Profile 'udisksctl' & co. in the system profile.
                         (service-extension profile-service-type
                                            udisks-package))))))

(define* (udisks-service #:key (udisks udisks))
  "Return a service for @uref{http://udisks.freedesktop.org/docs/latest/,
UDisks}, a @dfn{disk management} daemon that provides user interfaces with
notifications and ways to mount/unmount disks.  Programs that talk to UDisks
include the @command{udisksctl} command, part of UDisks, and GNOME Disks."
  (service udisks-service-type
           (udisks-configuration (udisks udisks))))


;;;
;;; Elogind login and seat management service.
;;;

(define-record-type* <elogind-configuration> elogind-configuration
  make-elogind-configuration
  elogind-configuration
  (elogind                         elogind-package
                                   (default elogind))
  (kill-user-processes?            elogind-kill-user-processes?
                                   (default #f))
  (kill-only-users                 elogind-kill-only-users
                                   (default '()))
  (kill-exclude-users              elogind-kill-exclude-users
                                   (default '("root")))
  (inhibit-delay-max-seconds       elogind-inhibit-delay-max-seconds
                                   (default 5))
  (handle-power-key                elogind-handle-power-key
                                   (default 'poweroff))
  (handle-suspend-key              elogind-handle-suspend-key
                                   (default 'suspend))
  (handle-hibernate-key            elogind-handle-hibernate-key
                                   ;; (default 'hibernate)
                                   ;; XXX Ignore it for now, since we don't
                                   ;; yet handle resume-from-hibernation in
                                   ;; our initrd.
                                   (default 'ignore))
  (handle-lid-switch               elogind-handle-lid-switch
                                   (default 'suspend))
  (handle-lid-switch-docked        elogind-handle-lid-switch-docked
                                   (default 'ignore))
  (power-key-ignore-inhibited?     elogind-power-key-ignore-inhibited?
                                   (default #f))
  (suspend-key-ignore-inhibited?   elogind-suspend-key-ignore-inhibited?
                                   (default #f))
  (hibernate-key-ignore-inhibited? elogind-hibernate-key-ignore-inhibited?
                                   (default #f))
  (lid-switch-ignore-inhibited?    elogind-lid-switch-ignore-inhibited?
                                   (default #t))
  (holdoff-timeout-seconds         elogind-holdoff-timeout-seconds
                                   (default 30))
  (idle-action                     elogind-idle-action
                                   (default 'ignore))
  (idle-action-seconds             elogind-idle-action-seconds
                                   (default (* 30 60)))
  (runtime-directory-size-percent  elogind-runtime-directory-size-percent
                                   (default 10))
  (runtime-directory-size          elogind-runtime-directory-size
                                   (default #f))
  (remove-ipc?                     elogind-remove-ipc?
                                   (default #t))

  (suspend-state                   elogind-suspend-state
                                   (default '("mem" "standby" "freeze")))
  (suspend-mode                    elogind-suspend-mode
                                   (default '()))
  (hibernate-state                 elogind-hibernate-state
                                   (default '("disk")))
  (hibernate-mode                  elogind-hibernate-mode
                                   (default '("platform" "shutdown")))
  (hybrid-sleep-state              elogind-hybrid-sleep-state
                                   (default '("disk")))
  (hybrid-sleep-mode               elogind-hybrid-sleep-mode
                                   (default
                                     '("suspend" "platform" "shutdown"))))

(define (elogind-configuration-file config)
  (define (yesno x)
    (match x
      (#t "yes")
      (#f "no")
      (_ (error "expected #t or #f, instead got:" x))))
  (define char-set:user-name
    (string->char-set "abcdefghijklmnopqrstuvwxyz0123456789_-"))
  (define (valid-list? l pred)
    (and-map (lambda (x) (string-every pred x)) l))
  (define (user-name-list users)
    (unless (valid-list? users char-set:user-name)
      (error "invalid user list" users))
    (string-join users " "))
  (define (enum val allowed)
    (unless (memq val allowed)
      (error "invalid value" val allowed))
    (symbol->string val))
  (define (non-negative-integer x)
    (unless (exact-integer? x) (error "not an integer" x))
    (when (negative? x) (error "negative number not allowed" x))
    (number->string x))
  (define handle-actions
    '(ignore poweroff reboot halt kexec suspend hibernate hybrid-sleep lock))
  (define (handle-action x)
    (enum x handle-actions))
  (define (sleep-list tokens)
    (unless (valid-list? tokens char-set:user-name)
      (error "invalid sleep list" tokens))
    (string-join tokens " "))
  (define-syntax ini-file-clause
    (syntax-rules ()
      ((_ config (prop (parser getter)))
       (string-append prop "=" (parser (getter config)) "\n"))
      ((_ config str)
       (string-append str "\n"))))
  (define-syntax-rule (ini-file config file clause ...)
    (plain-file file (string-append (ini-file-clause config clause) ...)))
  (ini-file
   config "logind.conf"
   "[Login]"
   ("KillUserProcesses" (yesno elogind-kill-user-processes?))
   ("KillOnlyUsers" (user-name-list elogind-kill-only-users))
   ("KillExcludeUsers" (user-name-list elogind-kill-exclude-users))
   ("InhibitDelayMaxSecs" (non-negative-integer elogind-inhibit-delay-max-seconds))
   ("HandlePowerKey" (handle-action elogind-handle-power-key))
   ("HandleSuspendKey" (handle-action elogind-handle-suspend-key))
   ("HandleHibernateKey" (handle-action elogind-handle-hibernate-key))
   ("HandleLidSwitch" (handle-action elogind-handle-lid-switch))
   ("HandleLidSwitchDocked" (handle-action elogind-handle-lid-switch-docked))
   ("PowerKeyIgnoreInhibited" (yesno elogind-power-key-ignore-inhibited?))
   ("SuspendKeyIgnoreInhibited" (yesno elogind-suspend-key-ignore-inhibited?))
   ("HibernateKeyIgnoreInhibited" (yesno elogind-hibernate-key-ignore-inhibited?))
   ("LidSwitchIgnoreInhibited" (yesno elogind-lid-switch-ignore-inhibited?))
   ("HoldoffTimeoutSecs" (non-negative-integer elogind-holdoff-timeout-seconds))
   ("IdleAction" (handle-action elogind-idle-action))
   ("IdleActionSeconds" (non-negative-integer elogind-idle-action-seconds))
   ("RuntimeDirectorySize"
    (identity
     (lambda (config)
       (match (elogind-runtime-directory-size-percent config)
         (#f (non-negative-integer (elogind-runtime-directory-size config)))
         (percent (string-append (non-negative-integer percent) "%"))))))
   ("RemoveIpc" (yesno elogind-remove-ipc?))
   "[Sleep]"
   ("SuspendState" (sleep-list elogind-suspend-state))
   ("SuspendMode" (sleep-list elogind-suspend-mode))
   ("HibernateState" (sleep-list elogind-hibernate-state))
   ("HibernateMode" (sleep-list elogind-hibernate-mode))
   ("HybridSleepState" (sleep-list elogind-hybrid-sleep-state))
   ("HybridSleepMode" (sleep-list elogind-hybrid-sleep-mode))))

(define (elogind-dbus-service config)
  (list (wrapped-dbus-service (elogind-package config)
                              "libexec/elogind/elogind"
                              "ELOGIND_CONF_FILE"
                              (elogind-configuration-file config))))

(define (pam-extension-procedure config)
  "Return an extension for PAM-ROOT-SERVICE-TYPE that ensures that all the PAM
services use 'pam_elogind.so', a module that allows elogind to keep track of
logged-in users (run 'loginctl' to see elogind's world view of users and
seats.)"
  (define pam-elogind
    (pam-entry
     (control "required")
     (module #~(string-append #$(elogind-package config)
                              "/lib/security/pam_elogind.so"))))

  (list (lambda (pam)
          (pam-service
           (inherit pam)
           (session (cons pam-elogind (pam-service-session pam)))))))

(define elogind-service-type
  (service-type (name 'elogind)
                (extensions
                 (list (service-extension dbus-root-service-type
                                          elogind-dbus-service)
                       (service-extension udev-service-type
                                          (compose list elogind-package))
                       (service-extension polkit-service-type
                                          (compose list elogind-package))

                       ;; Provide the 'loginctl' command.
                       (service-extension profile-service-type
                                          (compose list elogind-package))

                       ;; Extend PAM with pam_elogind.so.
                       (service-extension pam-root-service-type
                                          pam-extension-procedure)))))

(define* (elogind-service #:key (config (elogind-configuration)))
  "Return a service that runs the @command{elogind} login and seat management
service.  The @command{elogind} service integrates with PAM to allow other
system components to know the set of logged-in users as well as their session
types (graphical, console, remote, etc.).  It can also clean up after users
when they log out."
  (service elogind-service-type config))


;;;
;;; GNOME desktop service.
;;;

(define-record-type* <gnome-desktop-configuration> gnome-desktop-configuration
  make-gnome-desktop-configuration
  gnome-desktop-configuration
  (gnome-package gnome-package (default gnome)))

(define gnome-desktop-service-type
  (service-type
   (name 'gnome-desktop)
   (extensions
    (list (service-extension polkit-service-type
                             (compose list
                                      (package-direct-input-selector
                                       "gnome-settings-daemon")
                                      gnome-package))
          (service-extension profile-service-type
                             (compose list
                                      gnome-package))))))

(define* (gnome-desktop-service #:key (config (gnome-desktop-configuration)))
  "Return a service that adds the @code{gnome} package to the system profile,
and extends polkit with the actions from @code{gnome-settings-daemon}."
  (service gnome-desktop-service-type config))


;;;
;;; XFCE desktop service.
;;;

(define-record-type* <xfce-desktop-configuration> xfce-desktop-configuration
  make-xfce-desktop-configuration
  xfce-desktop-configuration
  (xfce xfce-package (default xfce)))

(define xfce-desktop-service-type
  (service-type
   (name 'xfce-desktop)
   (extensions
    (list (service-extension polkit-service-type
                             (compose list
                                      (package-direct-input-selector
                                       "thunar")
                                      xfce-package))
          (service-extension profile-service-type
                             (compose list
                                      xfce-package))))))

(define* (xfce-desktop-service #:key (config (xfce-desktop-configuration)))
  "Return a service that adds the @code{xfce} package to the system profile,
and extends polkit with the abilit for @code{thunar} to manipulate the file
system as root from within a user session, after the user has authenticated
with the administrator's password."
  (service xfce-desktop-service-type config))


;;;
;;; The default set of desktop services.
;;;

(define %desktop-services
  ;; List of services typically useful for a "desktop" use case.
  (cons* (slim-service)

         ;; Screen lockers are a pretty useful thing and these are small.
         (screen-locker-service slock)
         (screen-locker-service xlockmore "xlock")

         ;; The D-Bus clique.
         (avahi-service)
         (wicd-service)
         (udisks-service)
         (upower-service)
         (colord-service)
         (geoclue-service)
         (polkit-service)
         (elogind-service)
         (dbus-service)

         (ntp-service)

         %base-services))

;;; desktop.scm ends here
