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

(define-module (gnu services avahi)
  #:use-module (gnu services)
  #:use-module (gnu services base)
  #:use-module (gnu services shepherd)
  #:use-module (gnu services dbus)
  #:use-module (gnu system shadow)
  #:use-module (gnu packages avahi)
  #:use-module (gnu packages admin)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:export (avahi-configuration
            avahi-service
            avahi-service-type))

;;; Commentary:
;;;
;;; This module provides service definitions for the Avahi
;;; "zero-configuration" tool set.
;;;
;;; Code:

  ;; TODO: Export.
(define-record-type* <avahi-configuration>
  avahi-configuration make-avahi-configuration
  avahi-configuration?
  (avahi             avahi-configuration-avahi    ;<package>
                     (default avahi))
  (debug?            avahi-configuration-debug?   ;Boolean
                     (default #f))
  (host-name         avahi-configuration-host-name) ;string
  (publish?          avahi-configuration-publish?)  ;Boolean
  (ipv4?             avahi-configuration-ipv4?)     ;Boolean
  (ipv6?             avahi-configuration-ipv6?)     ;Boolean
  (wide-area?        avahi-configuration-wide-area?) ;Boolean
  (domains-to-browse avahi-configuration-domains-to-browse)) ;list of strings

(define* (configuration-file config)
  "Return an avahi-daemon configuration file based on CONFIG, an
<avahi-configuration>."
  (define (bool value)
    (if value "yes\n" "no\n"))

  (define host-name (avahi-configuration-host-name config))

  (plain-file "avahi-daemon.conf"
              (string-append
               "[server]\n"
               (if host-name
                   (string-append "host-name=" host-name "\n")
                   "")

               "browse-domains=" (string-join
                                  (avahi-configuration-domains-to-browse
                                   config))
               "\n"
               "use-ipv4=" (bool (avahi-configuration-ipv4? config))
               "use-ipv6=" (bool (avahi-configuration-ipv6? config))
               "[wide-area]\n"
               "enable-wide-area=" (bool (avahi-configuration-wide-area? config))
               "[publish]\n"
               "disable-publishing="
               (bool (not (avahi-configuration-publish? config))))))

(define %avahi-accounts
  ;; Account and group for the Avahi daemon.
  (list (user-group (name "avahi") (system? #t))
        (user-account
         (name "avahi")
         (group "avahi")
         (system? #t)
         (comment "Avahi daemon user")
         (home-directory "/var/empty")
         (shell #~(string-append #$shadow "/sbin/nologin")))))

(define %avahi-activation
  ;; Activation gexp.
  #~(begin
      (use-modules (guix build utils))
      (mkdir-p "/var/run/avahi-daemon")))

(define (avahi-shepherd-service config)
  "Return a list of <shepherd-service> for CONFIG."
  (let ((config (configuration-file config))
        (debug? (avahi-configuration-debug? config))
        (avahi  (avahi-configuration-avahi config)))
    (list (shepherd-service
           (documentation "Run the Avahi mDNS/DNS-SD responder.")
           (provision '(avahi-daemon))
           (requirement '(dbus-system networking))

           (start #~(make-forkexec-constructor
                     (list (string-append #$avahi "/sbin/avahi-daemon")
                           "--daemonize"
                           #$@(if debug? #~("--debug") #~())
                           "-f" #$config)
                     #:pid-file "/var/run/avahi-daemon/pid"))
           (stop #~(make-kill-destructor))))))

(define avahi-service-type
  (let ((avahi-package (compose list avahi-configuration-avahi)))
    (service-type (name 'avahi)
                  (extensions
                   (list (service-extension shepherd-root-service-type
                                            avahi-shepherd-service)
                         (service-extension dbus-root-service-type
                                            avahi-package)
                         (service-extension account-service-type
                                            (const %avahi-accounts))
                         (service-extension activation-service-type
                                            (const %avahi-activation))
                         (service-extension nscd-service-type
                                            (const (list nss-mdns)))

                         ;; Provide 'avahi-browse', 'avahi-resolve', etc. in
                         ;; the system profile.
                         (service-extension profile-service-type
                                            avahi-package))))))

(define* (avahi-service #:key (avahi avahi) debug?
                        host-name
                        (publish? #t)
                        (ipv4? #t) (ipv6? #t)
                        wide-area?
                        (domains-to-browse '()))
  "Return a service that runs @command{avahi-daemon}, a system-wide
mDNS/DNS-SD responder that allows for service discovery and
\"zero-configuration\" host name lookups (see @uref{http://avahi.org/}), and
extends the name service cache daemon (nscd) so that it can resolve
@code{.local} host names using
@uref{http://0pointer.de/lennart/projects/nss-mdns/, nss-mdns}.  Additionally,
add the @var{avahi} package to the system profile so that commands such as
@command{avahi-browse} are directly usable.

If @var{host-name} is different from @code{#f}, use that as the host name to
publish for this machine; otherwise, use the machine's actual host name.

When @var{publish?} is true, publishing of host names and services is allowed;
in particular, avahi-daemon will publish the machine's host name and IP
address via mDNS on the local network.

When @var{wide-area?} is true, DNS-SD over unicast DNS is enabled.

Boolean values @var{ipv4?} and @var{ipv6?} determine whether to use IPv4/IPv6
sockets."
  (service avahi-service-type
           (avahi-configuration
            (avahi avahi) (debug? debug?) (host-name host-name)
            (publish? publish?) (ipv4? ipv4?) (ipv6? ipv6?)
            (wide-area? wide-area?)
            (domains-to-browse domains-to-browse))))

;;; avahi.scm ends here
