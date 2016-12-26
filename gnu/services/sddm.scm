;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 David Craven <david@craven.ch>
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

(define-module (gnu services sddm)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages display-managers)
  #:use-module (gnu packages freedesktop)
  #:use-module (gnu packages xorg)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu services xorg)
  #:use-module (gnu system pam)
  #:use-module (gnu system shadow)
  #:use-module (guix gexp)
  #:use-module (guix records)
  #:export (sddm-configuration
            sddm-configuration?
            sddm-service-type
            sddm-service))

(define-record-type* <sddm-configuration>
  sddm-configuration      make-sddm-configuration
  sddm-configuration?
  (sddm                   sddm-configuration-sddm
                          (default sddm))

  ;; [General]
  ;; valid values are x11 and wayland
  ;; currently doesn't do anything is enabled by wayland greeter PR
  (display-server         sddm-configuration-display-server
                          (default "x11"))
  ;; valid values are on, off or none
  (numlock                sddm-configuration-numlock
                          (default "on"))
  (halt-command           sddm-configuration-halt-command
                          (default (file-append shepherd "/sbin/halt")))
  (reboot-command         sddm-configuration-reboot-command
                          (default (file-append shepherd "/sbin/reboot")))

  ;; [Theme]
  ;; valid values are elarun or maldives
  (theme                  sddm-configuration-theme
                          (default "maldives"))
  (themes-directory       sddm-configuration-themes-directory
                          (default "/run/current-system/profile/share/sddm/themes"))
  (faces-directory        sddm-configuration-faces-directory
                          (default "/run/current-system/profile/share/sddm/faces"))

  ;; [Users]
  (default-path           sddm-configuration-default-path
                          (default "/run/current-system/profile/bin"))
  (minimum-uid            sddm-configuration-minimum-uid
                          (default 1000))
  (maximum-uid            sddm-configuration-maximum-uid
                          (default 2000))
  (remember-last-user?    sddm-configuration-remember-last-user?
                          (default #t))
  (remember-last-session? sddm-configuration-remember-last-session?
                          (default #t))
  (hide-users             sddm-configuration-hide-users
                          (default ""))
  (hide-shells            sddm-configuration-hide-shells
                          (default (file-append shadow "/sbin/nologin")))

  ;; [Wayland]
  (session-command        sddm-configuration-session-command
                          (default (file-append sddm "/share/sddm/scripts/wayland-session")))
  (sessions-directory     sddm-configuration-sessions-directory
                          (default "/run/current-system/profile/share/wayland-sessions"))
  ;; [X11]
  (xorg-server-path       sddm-configuration-xorg-server-path
                          (default (xorg-start-command)))
  (xauth-path             sddm-configuration-xauth-path
                          (default (file-append xauth "/bin/xauth")))
  (xephyr-path            sddm-configuration-xephyr-path
                          (default (file-append xorg-server "/bin/Xephyr")))
  (xdisplay-start         sddm-configuration-xdisplay-start
                          (default (file-append sddm "/share/sddm/scripts/Xsetup")))
  (xdisplay-stop          sddm-configuration-xdisplay-stop
                          (default (file-append sddm "/share/sddm/scripts/Xstop")))
  (xsession-command       sddm-configuration-xsession-command
                          (default (xinitrc)))
  (xsessions-directory    sddm-configuration-xsessions-directory
                          (default "/run/current-system/profile/share/xsessions"))
  (minimum-vt             sddm-configuration-minimum-vt
                          (default 7))
  (xserver-arguments      sddm-configuration-xserver-arguments
                          (default "-nolisten tcp"))

  ;; [Autologin]
  (auto-login-user        sddm-configuration-auto-login-user
                          (default ""))
  ;; valid values are xfce.desktop gnome.desktop weston.desktop hawaii.desktop
  (auto-login-session     sddm-configuration-auto-login-session
                          (default ""))
  (relogin?               sddm-configuration-relogin?
                          (default #f)))

(define (sddm-configuration-file config)
  (mixed-text-file "sddm.conf" "
[General]
DisplayServer="        (sddm-configuration-display-server config)              "
Numlock="              (sddm-configuration-numlock config)                     "
HaltCommand="          (sddm-configuration-halt-command config)                "
RebootCommand="        (sddm-configuration-reboot-command config)              "

[Users]
DefaultPath="          (sddm-configuration-default-path config)                "
MinimumUid="           (number->string (sddm-configuration-minimum-uid config))"
MaximumUid="           (number->string (sddm-configuration-maximum-uid config))"
RememberLastUser="     (if (sddm-configuration-remember-last-user? config)
                           "true" "false")                                     "
RememberLastSession="  (if (sddm-configuration-remember-last-session? config)
                           "true" "false")                                     "
HideUsers="            (sddm-configuration-hide-users config)                  "
Hideshells="           (sddm-configuration-hide-shells config)                 "

[Theme]
Current="              (sddm-configuration-theme config)                       "
ThemeDir="             (sddm-configuration-themes-directory config)            "
FacesDir="             (sddm-configuration-faces-directory config)             "

[Wayland]
SessionCommand="       (sddm-configuration-session-command config)             "
SessionDir="           (sddm-configuration-sessions-directory config)          "

[X11]
ServerPath="           (sddm-configuration-xorg-server-path config)            "
XauthPath="            (sddm-configuration-xauth-path config)                  "
XephyrPath="           (sddm-configuration-xephyr-path config)                 "
DisplayCommand="       (sddm-configuration-xdisplay-start config)              "
DisplayStopCommand="   (sddm-configuration-xdisplay-stop config)               "
SessionCommand="       (sddm-configuration-xsession-command config)            "
SessionDir="           (sddm-configuration-xsessions-directory config)         "
MinimumVT="            (number->string (sddm-configuration-minimum-vt config)) "
ServerArguments="      (sddm-configuration-xserver-arguments config)           "

[Autologin]
User="                 (sddm-configuration-auto-login-user config)             "
Session="              (sddm-configuration-auto-login-session config)          "
Relogin="              (if (sddm-configuration-relogin? config)
                           "true" "false")                                     "
"))

(define (sddm-shepherd-service config)
  "Return a <shepherd-service> for sddm with CONFIG."

  (define sddm-command
    #~(list (string-append #$(sddm-configuration-sddm config) "/bin/sddm")))

  (list (shepherd-service
         (documentation "SDDM display manager.")
         (requirement '(user-processes))
         (provision '(display-manager))
         (start #~(make-forkexec-constructor #$sddm-command))
         (stop #~(make-kill-destructor)))))

(define (sddm-etc-service config)
  (list `("sddm.conf" ,(sddm-configuration-file config))))

(define (sddm-pam-service)
  "Return a PAM service for @command{sddm}."
  (pam-service
   (name "sddm")
   (auth
    (list
     (pam-entry
      (control "requisite")
      (module "pam_nologin.so"))
     (pam-entry
      (control "required")
      (module "pam_env.so"))
     (pam-entry
      (control "required")
      (module "pam_succeed_if.so")
      (arguments (list "uid >= 1000" "quiet")))
     ;; should be factored out into system-auth
     (pam-entry
      (control "required")
      (module "pam_unix.so"))))
   (account
    (list
     ;; should be factored out into system-account
     (pam-entry
      (control "required")
      (module "pam_unix.so"))))
   (password
    (list
     ;; should be factored out into system-password
     (pam-entry
      (control "required")
      (module "pam_unix.so")
      (arguments (list "sha512" "shadow" "try_first_pass")))))
   (session
    (list
     ;; lfs has a required pam_limits.so
     ;; should be factored out into system-session
     (pam-entry
      (control "required")
      (module "pam_unix.so"))))))

(define (sddm-greeter-pam-service)
  "Return a PAM service for @command{sddm-greeter}."
  (pam-service
   (name "sddm-greeter")
   (auth
    (list
     ;; Load environment from /etc/environment and ~/.pam_environment
     (pam-entry
      (control "required")
      (module "pam_env.so"))
     ;; Always let the greeter start without authentication
     (pam-entry
      (control "required")
      (module "pam_permit.so"))))
   (account
    (list
     ;; No action required for account management
     (pam-entry
      (control "required")
      (module "pam_permit.so"))))
   (password
    (list
     ;; Can't change password
     (pam-entry
      (control "required")
      (module "pam_deny.so"))))
   (session
    (list
     ;; Setup session
     (pam-entry
      (control "required")
      (module "pam_unix.so"))))))

(define (sddm-autologin-pam-service)
  "Return a PAM service for @command{sddm-autologin}"
  (pam-service
   (name "sddm-autologin")
   (auth
    (list
     (pam-entry
      (control "requisite")
      (module "pam_nologin.so"))
     (pam-entry
      (control "required")
      (module "pam_succeed_if.so")
      (arguments (list "uid >= 1000" "quiet")))
     (pam-entry
      (control "required")
      (module "pam_permit.so"))))
   (account
    (list
     (pam-entry
      (control "include")
      (module "sddm"))))
   (password
    (list
     (pam-entry
      (control "required")
      (module "pam_deny.so"))))
   (session
    (list
     (pam-entry
      (control "include")
      (module "sddm"))))))

(define (sddm-pam-services config)
  (list (sddm-pam-service)
        (sddm-greeter-pam-service)
        (sddm-autologin-pam-service)))

(define %sddm-accounts
  (list (user-group (name "sddm") (system? #t))
        (user-account
         (name "sddm")
         (group "sddm")
         (system? #t)
         (comment "SDDM user")
         (home-directory "/var/lib/sddm")
         (shell (file-append shadow "/sbin/nologin")))))

;; Add default themes to profile
(define sddm-profile-service
  (compose list sddm-configuration-sddm))

(define sddm-service-type
  (service-type (name 'sddm)
                (extensions
                  (list (service-extension shepherd-root-service-type
                                           sddm-shepherd-service)
                        (service-extension etc-service-type
                                           sddm-etc-service)
                        (service-extension pam-root-service-type
                                           sddm-pam-services)
                        (service-extension account-service-type
                                           (const %sddm-accounts))
                        (service-extension profile-service-type
                                           sddm-profile-service)))))

(define* (sddm-service #:optional (config (sddm-configuration)))
  "Run the @uref{https://github.com/sddm/sddm,SSDM display manager}
with the given @var{config}, a @code{<sddm-configuration>} object."
  (service sddm-service-type config))
