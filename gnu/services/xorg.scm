;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
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
  #:use-module (gnu system linux)                 ; 'pam-service'
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
  #:use-module (guix monads)
  #:use-module (guix derivations)
  #:use-module (guix records)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)
  #:export (xorg-configuration-file
            xorg-start-command
            %default-slim-theme
            %default-slim-theme-name
            slim-service))

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
@code{text-file*} argument list.  It is used to pass extra text to be added
verbatim to the configuration file."
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

  (apply text-file* "xserver.conf" "
Section \"Files\"
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

(define* (xorg-start-command #:key
                             (guile (canonical-package guile-2.0))
                             configuration-file
                             (xorg-server xorg-server))
  "Return a derivation that builds a @var{guile} script to start the X server
from @var{xorg-server}.  @var{configuration-file} is the server configuration
file or a derivation that builds it; when omitted, the result of
@code{xorg-configuration-file} is used.

Usually the X server is started by a login manager."
  (mlet %store-monad ((config (if configuration-file
                                  (return configuration-file)
                                  (xorg-configuration-file))))
    (define script
      ;; Write a small wrapper around the X server.
      #~(begin
          (setenv "XORG_DRI_DRIVER_PATH" (string-append #$mesa "/lib/dri"))
          (setenv "XKB_BINDIR" (string-append #$xkbcomp "/bin"))

          (apply execl (string-append #$xorg-server "/bin/X")
                 (string-append #$xorg-server "/bin/X") ;argv[0]
                 "-logverbose" "-verbose"
                 "-xkbdir" (string-append #$xkeyboard-config "/share/X11/xkb")
                 "-config" #$config
                 "-nolisten" "tcp" "-terminate"

                 ;; Note: SLiM and other display managers add the
                 ;; '-auth' flag by themselves.
                 (cdr (command-line)))))

    (gexp->script "start-xorg" script)))

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
                                ((_ x) x)
                                (_     #$fallback-session))))
          (if (file-exists? xsession-file)
              ;; Run ~/.xsession when it exists.
              (exec-from-login-shell xsession-file session)
              ;; Otherwise, start the specified session.
              (exec-from-login-shell session)))))
  (gexp->script "xinitrc" builder))


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

(define* (slim-service #:key (slim slim)
                       (allow-empty-passwords? #t) auto-login?
                       (default-user "")
                       (theme %default-slim-theme)
                       (theme-name %default-slim-theme-name)
                       (xauth xauth) (dmd dmd) (bash bash)
                       (auto-login-session #~(string-append #$windowmaker
                                                            "/bin/wmaker"))
                       startx
                       (additional-session-modules '()))
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

  (define (slim.cfg)
    (mlet %store-monad ((startx  (if startx
                                     (return startx)
                                     (xorg-start-command)))
                        (xinitrc (xinitrc #:fallback-session
                                          auto-login-session)))
      (text-file* "slim.cfg"  "
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

halt_cmd " dmd "/sbin/halt
reboot_cmd " dmd "/sbin/reboot
"
(if auto-login?
    (string-append "auto_login yes\ndefault_user " default-user "\n")
    "")
(if theme-name
    (string-append "current_theme " theme-name "\n")
    ""))))

  (mlet %store-monad ((slim.cfg (slim.cfg)))
    (return
     (service
      (documentation "Xorg display server")
      (provision '(xorg-server))
      (requirement '(user-processes host-name udev))
      (start
       #~(lambda ()
           ;; A stale lock file can prevent SLiM from starting, so remove it
           ;; to be on the safe side.
           (false-if-exception (delete-file "/var/run/slim.lock"))

           (fork+exec-command
            (list (string-append #$slim "/bin/slim") "-nodaemon")
            #:environment-variables
            (list (string-append "SLIM_CFGFILE=" #$slim.cfg)
                  #$@(if theme
                         (list #~(string-append "SLIM_THEMESDIR=" #$theme))
                         #~())))))
      (stop #~(make-kill-destructor))
      (respawn? #t)
      (pam-services
       ;; Tell PAM about 'slim'.
       (list (unix-pam-service
              "slim"
              #:allow-empty-passwords? allow-empty-passwords?
              #:additional-session-modules additional-session-modules)))))))

;;; xorg.scm ends here
