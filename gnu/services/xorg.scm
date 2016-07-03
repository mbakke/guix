;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Sou Bunnbu <iyzsong@gmail.com>
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

(define-module (gnu services xorg)
  #:use-module (gnu artwork)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu system pam)
  #:use-module ((gnu packages base) #:select (canonical-package))
  #:use-module (gnu packages guile)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages slim)
  #:use-module (gnu packages gnustep)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages bash)
  #:use-module (guix gexp)
  #:use-module (guix store)
  #:use-module (guix packages)
  #:use-module (guix derivations)
  #:use-module (guix records)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)
  #:export (xorg-configuration-file
            %default-xorg-modules
            xorg-start-command
            %default-slim-theme
            %default-slim-theme-name
            slim-configuration
            slim-service-type
            slim-service

            screen-locker-service-type
            screen-locker-service))

;;; Commentary:
;;;
;;; Services that relate to the X Window System.
;;;
;;; Code:

(define* (xorg-configuration-file #:key (drivers '()) (resolutions '())
                                  (extra-config '()))
  "Return a configuration file for the Xorg server containing search paths for
all the common drivers.

@var{drivers} must be either the empty list, in which case Xorg chooses a
graphics driver automatically, or a list of driver names that will be tried in
this order---e.g., @code{(\"modesetting\" \"vesa\")}.

Likewise, when @var{resolutions} is the empty list, Xorg chooses an
appropriate screen resolution; otherwise, it must be a list of
resolutions---e.g., @code{((1024 768) (640 480))}.

Last, @var{extra-config} is a list of strings or objects appended to the
@code{mixed-text-file} argument list.  It is used to pass extra text to be
added verbatim to the configuration file."
  (define (device-section driver)
    (string-append "
Section \"Device\"
  Identifier \"device-" driver "\"
  Driver \"" driver "\"
EndSection"))

  (define (screen-section driver resolutions)
    (string-append "
Section \"Screen\"
  Identifier \"screen-" driver "\"
  Device \"device-" driver "\"
  SubSection \"Display\"
    Modes "
  (string-join (map (match-lambda
                      ((x y)
                       (string-append "\"" (number->string x)
                                      "x" (number->string y) "\"")))
                    resolutions)) "
  EndSubSection
EndSection"))

  (apply mixed-text-file "xserver.conf" "
Section \"Files\"
  FontPath \"" font-alias "/share/fonts/X11/75dpi\"
  FontPath \"" font-alias "/share/fonts/X11/100dpi\"
  FontPath \"" font-alias "/share/fonts/X11/misc\"
  FontPath \"" font-alias "/share/fonts/X11/cyrillic\"
  FontPath \"" font-adobe75dpi "/share/fonts/X11/75dpi\"
  ModulePath \"" xf86-video-vesa "/lib/xorg/modules/drivers\"
  ModulePath \"" xf86-video-fbdev "/lib/xorg/modules/drivers\"
  ModulePath \"" xf86-video-modesetting "/lib/xorg/modules/drivers\"
  ModulePath \"" xf86-video-cirrus "/lib/xorg/modules/drivers\"
  ModulePath \"" xf86-video-intel "/lib/xorg/modules/drivers\"
  ModulePath \"" xf86-video-mach64 "/lib/xorg/modules/drivers\"
  ModulePath \"" xf86-video-nouveau "/lib/xorg/modules/drivers\"
  ModulePath \"" xf86-video-nv "/lib/xorg/modules/drivers\"
  ModulePath \"" xf86-video-sis "/lib/xorg/modules/drivers\"

  # Libinput is the new thing and is recommended over evdev/synaptics
  # by those who know:
  # <http://who-t.blogspot.fr/2015/01/xf86-input-libinput-compatibility-with.html>.
  ModulePath \"" xf86-input-libinput "/lib/xorg/modules/input\"

  ModulePath \"" xf86-input-evdev "/lib/xorg/modules/input\"
  ModulePath \"" xf86-input-keyboard "/lib/xorg/modules/input\"
  ModulePath \"" xf86-input-mouse "/lib/xorg/modules/input\"
  ModulePath \"" xf86-input-synaptics "/lib/xorg/modules/input\"
  ModulePath \"" xorg-server "/lib/xorg/modules\"
  ModulePath \"" xorg-server "/lib/xorg/modules/extensions\"
  ModulePath \"" xorg-server "/lib/xorg/modules/multimedia\"
EndSection

Section \"ServerFlags\"
  Option \"AllowMouseOpenFail\" \"on\"
EndSection
"
  (string-join (map device-section drivers) "\n") "\n"
  (string-join (map (cut screen-section <> resolutions)
                    drivers)
               "\n")

  "\n"
  extra-config))

(define %default-xorg-modules
  (list xf86-video-vesa
        xf86-video-fbdev
        xf86-video-modesetting
        xf86-video-cirrus
        xf86-video-intel
        xf86-video-mach64
        xf86-video-nouveau
        xf86-video-nv
        xf86-video-sis
        xf86-input-libinput
        xf86-input-evdev
        xf86-input-keyboard
        xf86-input-mouse
        xf86-input-synaptics))

(define (xorg-configuration-directory modules)
  "Return a directory that contains the @code{.conf} files for X.org that
includes the @code{share/X11/xorg.conf.d} directories of each package listed
in @var{modules}."
  (with-imported-modules '((guix build utils))
    (computed-file "xorg.conf.d"
                   #~(begin
                       (use-modules (guix build utils)
                                    (srfi srfi-1))

                       (define files
                         (append-map (lambda (module)
                                       (find-files (string-append
                                                    module
                                                    "/share/X11/xorg.conf.d")
                                                   "\\.conf$"))
                                     (list #$@modules)))

                       (mkdir #$output)
                       (for-each (lambda (file)
                                   (symlink file
                                            (string-append #$output "/"
                                                           (basename file))))
                                 files)
                       #t))))

(define* (xorg-start-command #:key
                             (guile (canonical-package guile-2.0))
                             (configuration-file (xorg-configuration-file))
                             (modules %default-xorg-modules)
                             (xorg-server xorg-server))
  "Return a derivation that builds a @var{guile} script to start the X server
from @var{xorg-server}.  @var{configuration-file} is the server configuration
file or a derivation that builds it; when omitted, the result of
@code{xorg-configuration-file} is used.

Usually the X server is started by a login manager."
  (define exp
    ;; Write a small wrapper around the X server.
    #~(begin
        (setenv "XORG_DRI_DRIVER_PATH" (string-append #$mesa "/lib/dri"))
        (setenv "XKB_BINDIR" (string-append #$xkbcomp "/bin"))

        (apply execl (string-append #$xorg-server "/bin/X")
               (string-append #$xorg-server "/bin/X") ;argv[0]
               "-logverbose" "-verbose"
               "-xkbdir" (string-append #$xkeyboard-config "/share/X11/xkb")
               "-config" #$configuration-file
               "-configdir" #$(xorg-configuration-directory modules)
               "-nolisten" "tcp" "-terminate"

               ;; Note: SLiM and other display managers add the
               ;; '-auth' flag by themselves.
               (cdr (command-line)))))

  (program-file "start-xorg" exp))

(define* (xinitrc #:key
                  (guile (canonical-package guile-2.0))
                  fallback-session)
  "Return a system-wide xinitrc script that starts the specified X session,
which should be passed to this script as the first argument.  If not, the
@var{fallback-session} will be used."
  (define builder
    #~(begin
        (use-modules (ice-9 match))

        (define (close-all-fdes)
          ;; Close all the open file descriptors except 0 to 2.
          (let loop ((fd 3))
            (when (< fd 4096)               ;FIXME: use sysconf + _SC_OPEN_MAX
              (false-if-exception (close-fdes fd))
              (loop (+ 1 fd)))))

        (define (exec-from-login-shell command . args)
          ;; Run COMMAND from a login shell so that it gets to see the same
          ;; environment variables that one gets when logging in on a tty, for
          ;; instance.
          (let* ((pw    (getpw (getuid)))
                 (shell (passwd:shell pw)))
            ;; Close any open file descriptors.  This is all the more
            ;; important that SLiM itself exec's us directly without closing
            ;; its own file descriptors!
            (close-all-fdes)

            ;; The '--login' option is supported at least by Bash and zsh.
            (execl shell shell "--login" "-c"
                   (string-join (cons command args)))))

        (let* ((home          (getenv "HOME"))
               (xsession-file (string-append home "/.xsession"))
               (session       (match (command-line)
                                ((_)       (list #$fallback-session))
                                ((_ x ..1) x))))
          (if (file-exists? xsession-file)
              ;; Run ~/.xsession when it exists.
              (apply exec-from-login-shell xsession-file session)
              ;; Otherwise, start the specified session.
              (apply exec-from-login-shell session)))))

  (program-file "xinitrc" builder))


;;;
;;; SLiM log-in manager.
;;;

(define %default-slim-theme
  ;; Theme based on work by Felipe López.
  #~(string-append #$%artwork-repository "/slim"))

(define %default-slim-theme-name
  ;; This must be the name of the sub-directory in %DEFAULT-SLIM-THEME that
  ;; contains the actual theme files.
  "0.x")

(define-record-type* <slim-configuration>
  slim-configuration make-slim-configuration
  slim-configuration?
  (slim slim-configuration-slim
        (default slim))
  (allow-empty-passwords? slim-configuration-allow-empty-passwords?)
  (auto-login? slim-configuration-auto-login?)
  (default-user slim-configuration-default-user)
  (theme slim-configuration-theme)
  (theme-name slim-configuration-theme-name)
  (xauth slim-configuration-xauth
         (default xauth))
  (shepherd slim-configuration-shepherd
            (default shepherd))
  (bash slim-configuration-bash
        (default bash))
  (auto-login-session slim-configuration-auto-login-session)
  (startx slim-configuration-startx))

(define (slim-pam-service config)
  "Return a PAM service for @command{slim}."
  (list (unix-pam-service
         "slim"
         #:allow-empty-passwords?
         (slim-configuration-allow-empty-passwords? config))))

(define (slim-shepherd-service config)
  (define slim.cfg
    (let ((xinitrc (xinitrc #:fallback-session
                            (slim-configuration-auto-login-session config)))
          (slim    (slim-configuration-slim config))
          (xauth   (slim-configuration-xauth config))
          (startx  (slim-configuration-startx config))
          (shepherd   (slim-configuration-shepherd config))
          (theme-name (slim-configuration-theme-name config)))
      (mixed-text-file "slim.cfg"  "
default_path /run/current-system/profile/bin
default_xserver " startx "
xserver_arguments :0 vt7
xauth_path " xauth "/bin/xauth
authfile /var/run/slim.auth

# The login command.  '%session' is replaced by the chosen session name, one
# of the names specified in the 'sessions' setting: 'wmaker', 'xfce', etc.
login_cmd  exec " xinitrc " %session
sessiondir /run/current-system/profile/share/xsessions
session_msg session (F1 to change):

halt_cmd " shepherd "/sbin/halt
reboot_cmd " shepherd "/sbin/reboot\n"
(if (slim-configuration-auto-login? config)
    (string-append "auto_login yes\ndefault_user "
                   (slim-configuration-default-user config) "\n")
    "")
(if theme-name
    (string-append "current_theme " theme-name "\n")
    ""))))

  (define theme
    (slim-configuration-theme config))

  (list (shepherd-service
         (documentation "Xorg display server")
         (provision '(xorg-server))
         (requirement '(user-processes host-name udev))
         (start
          #~(lambda ()
              ;; A stale lock file can prevent SLiM from starting, so remove it to
              ;; be on the safe side.
              (false-if-exception (delete-file "/var/run/slim.lock"))

              (fork+exec-command
               (list (string-append #$slim "/bin/slim") "-nodaemon")
               #:environment-variables
               (list (string-append "SLIM_CFGFILE=" #$slim.cfg)
                     #$@(if theme
                            (list #~(string-append "SLIM_THEMESDIR=" #$theme))
                            #~())))))
         (stop #~(make-kill-destructor))
         (respawn? #t))))

(define slim-service-type
  (service-type (name 'slim)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          slim-shepherd-service)
                       (service-extension pam-root-service-type
                                          slim-pam-service)

                       ;; Unconditionally add xterm to the system profile, to
                       ;; avoid bad surprises.
                       (service-extension profile-service-type
                                          (const (list xterm)))))))

(define* (slim-service #:key (slim slim)
                       (allow-empty-passwords? #t) auto-login?
                       (default-user "")
                       (theme %default-slim-theme)
                       (theme-name %default-slim-theme-name)
                       (xauth xauth) (shepherd shepherd) (bash bash)
                       (auto-login-session #~(string-append #$windowmaker
                                                            "/bin/wmaker"))
                       (startx (xorg-start-command)))
  "Return a service that spawns the SLiM graphical login manager, which in
turn starts the X display server with @var{startx}, a command as returned by
@code{xorg-start-command}.

@cindex X session

SLiM automatically looks for session types described by the @file{.desktop}
files in @file{/run/current-system/profile/share/xsessions} and allows users
to choose a session from the log-in screen using @kbd{F1}.  Packages such as
@var{xfce}, @var{sawfish}, and @var{ratpoison} provide @file{.desktop} files;
adding them to the system-wide set of packages automatically makes them
available at the log-in screen.

In addition, @file{~/.xsession} files are honored.  When available,
@file{~/.xsession} must be an executable that starts a window manager
and/or other X clients.

When @var{allow-empty-passwords?} is true, allow logins with an empty
password.  When @var{auto-login?} is true, log in automatically as
@var{default-user} with @var{auto-login-session}.

If @var{theme} is @code{#f}, the use the default log-in theme; otherwise
@var{theme} must be a gexp denoting the name of a directory containing the
theme to use.  In that case, @var{theme-name} specifies the name of the
theme."
  (service slim-service-type
           (slim-configuration
            (slim slim)
            (allow-empty-passwords? allow-empty-passwords?)
            (auto-login? auto-login?) (default-user default-user)
            (theme theme) (theme-name theme-name)
            (xauth xauth) (shepherd shepherd) (bash bash)
            (auto-login-session auto-login-session)
            (startx startx))))


;;;
;;; Screen lockers & co.
;;;

(define-record-type <screen-locker>
  (screen-locker name program empty?)
  screen-locker?
  (name    screen-locker-name)                     ;string
  (program screen-locker-program)                  ;gexp
  (empty?  screen-locker-allows-empty-passwords?)) ;Boolean

(define screen-locker-pam-services
  (match-lambda
    (($ <screen-locker> name _ empty?)
     (list (unix-pam-service name
                             #:allow-empty-passwords? empty?)))))

(define screen-locker-setuid-programs
  (compose list screen-locker-program))

(define screen-locker-service-type
  (service-type (name 'screen-locker)
                (extensions
                 (list (service-extension pam-root-service-type
                                          screen-locker-pam-services)
                       (service-extension setuid-program-service-type
                                          screen-locker-setuid-programs)))))

(define* (screen-locker-service package
                                #:optional
                                (program (package-name package))
                                #:key allow-empty-passwords?)
  "Add @var{package}, a package for a screen-locker or screen-saver whose
command is @var{program}, to the set of setuid programs and add a PAM entry
for it.  For example:

@lisp
(screen-locker-service xlockmore \"xlock\")
@end lisp

makes the good ol' XlockMore usable."
  (service screen-locker-service-type
           (screen-locker program
                          #~(string-append #$package
                                           #$(string-append "/bin/" program))
                          allow-empty-passwords?)))

;;; xorg.scm ends here
