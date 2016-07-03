;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
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

(define-module (gnu services networking)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu services dbus)
  #:use-module (gnu system shadow)
  #:use-module (gnu system pam)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages connman)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages tor)
  #:use-module (gnu packages messaging)
  #:use-module (gnu packages ntp)
  #:use-module (gnu packages wicd)
  #:use-module (gnu packages gnome)
  #:use-module (guix gexp)
  #:use-module (guix records)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)
  #:export (%facebook-host-aliases
            static-networking-service
            dhcp-client-service
            %ntp-servers
            ntp-service
            tor-hidden-service
            tor-service
            bitlbee-service
            wicd-service
            network-manager-service
            connman-service))

;;; Commentary:
;;;
;;; Networking services.
;;;
;;; Code:

(define %facebook-host-aliases
  ;; This is the list of known Facebook hosts to be added to /etc/hosts if you
  ;; are to block it.
  "\
# Block Facebook IPv4.
127.0.0.1   www.facebook.com
127.0.0.1   facebook.com
127.0.0.1   login.facebook.com
127.0.0.1   www.login.facebook.com
127.0.0.1   fbcdn.net
127.0.0.1   www.fbcdn.net
127.0.0.1   fbcdn.com
127.0.0.1   www.fbcdn.com
127.0.0.1   static.ak.fbcdn.net
127.0.0.1   static.ak.connect.facebook.com
127.0.0.1   connect.facebook.net
127.0.0.1   www.connect.facebook.net
127.0.0.1   apps.facebook.com

# Block Facebook IPv6.
fe80::1%lo0 facebook.com
fe80::1%lo0 login.facebook.com
fe80::1%lo0 www.login.facebook.com
fe80::1%lo0 fbcdn.net
fe80::1%lo0 www.fbcdn.net
fe80::1%lo0 fbcdn.com
fe80::1%lo0 www.fbcdn.com
fe80::1%lo0 static.ak.fbcdn.net
fe80::1%lo0 static.ak.connect.facebook.com
fe80::1%lo0 connect.facebook.net
fe80::1%lo0 www.connect.facebook.net
fe80::1%lo0 apps.facebook.com\n")


(define-record-type* <static-networking>
  static-networking make-static-networking
  static-networking?
  (interface static-networking-interface)
  (ip static-networking-ip)
  (gateway static-networking-gateway)
  (provision static-networking-provision)
  (name-servers static-networking-name-servers)
  (net-tools static-networking-net-tools))

(define static-networking-service-type
  (shepherd-service-type
   'static-networking
   (match-lambda
     (($ <static-networking> interface ip gateway provision
                             name-servers net-tools)
      (let ((loopback? (memq 'loopback provision)))

        ;; TODO: Eventually replace 'route' with bindings for the appropriate
        ;; ioctls.
        (shepherd-service

         ;; Unless we're providing the loopback interface, wait for udev to be up
         ;; and running so that INTERFACE is actually usable.
         (requirement (if loopback? '() '(udev)))

         (documentation
          "Bring up the networking interface using a static IP address.")
         (provision provision)
         (start #~(lambda _
                    ;; Return #t if successfully started.
                    (let* ((addr     (inet-pton AF_INET #$ip))
                           (sockaddr (make-socket-address AF_INET addr 0)))
                      (configure-network-interface #$interface sockaddr
                                                   (logior IFF_UP
                                                           #$(if loopback?
                                                                 #~IFF_LOOPBACK
                                                                 0))))
                    #$(if gateway
                          #~(zero? (system* (string-append #$net-tools
                                                           "/sbin/route")
                                            "add" "-net" "default"
                                            "gw" #$gateway))
                          #t)
                    #$(if (pair? name-servers)
                          #~(call-with-output-file "/etc/resolv.conf"
                              (lambda (port)
                                (display
                                 "# Generated by 'static-networking-service'.\n"
                                 port)
                                (for-each (lambda (server)
                                            (format port "nameserver ~a~%"
                                                    server))
                                          '#$name-servers)))
                          #t)))
         (stop #~(lambda _
                   ;; Return #f is successfully stopped.
                   (let ((sock (socket AF_INET SOCK_STREAM 0)))
                     (set-network-interface-flags sock #$interface 0)
                     (close-port sock))
                   (not #$(if gateway
                              #~(system* (string-append #$net-tools
                                                        "/sbin/route")
                                         "del" "-net" "default")
                              #t))))
         (respawn? #f)))))))

(define* (static-networking-service interface ip
                                    #:key
                                    gateway
                                    (provision '(networking))
                                    (name-servers '())
                                    (net-tools net-tools))
  "Return a service that starts @var{interface} with address @var{ip}.  If
@var{gateway} is true, it must be a string specifying the default network
gateway."
  (service static-networking-service-type
           (static-networking (interface interface) (ip ip)
                              (gateway gateway)
                              (provision provision)
                              (name-servers name-servers)
                              (net-tools net-tools))))

(define dhcp-client-service-type
  (shepherd-service-type
   'dhcp-client
   (lambda (dhcp)
     (define dhclient
       #~(string-append #$dhcp "/sbin/dhclient"))

     (define pid-file
       "/var/run/dhclient.pid")

     (shepherd-service
      (documentation "Set up networking via DHCP.")
      (requirement '(user-processes udev))

      ;; XXX: Running with '-nw' ("no wait") avoids blocking for a minute when
      ;; networking is unavailable, but also means that the interface is not up
      ;; yet when 'start' completes.  To wait for the interface to be ready, one
      ;; should instead monitor udev events.
      (provision '(networking))

      (start #~(lambda _
                 ;; When invoked without any arguments, 'dhclient' discovers all
                 ;; non-loopback interfaces *that are up*.  However, the relevant
                 ;; interfaces are typically down at this point.  Thus we perform
                 ;; our own interface discovery here.
                 (define valid?
                   (negate loopback-network-interface?))
                 (define ifaces
                   (filter valid? (all-network-interface-names)))

                 ;; XXX: Make sure the interfaces are up so that 'dhclient' can
                 ;; actually send/receive over them.
                 (for-each set-network-interface-up ifaces)

                 (false-if-exception (delete-file #$pid-file))
                 (let ((pid (fork+exec-command
                             (cons* #$dhclient "-nw"
                                    "-pf" #$pid-file ifaces))))
                   (and (zero? (cdr (waitpid pid)))
                        (let loop ()
                          (catch 'system-error
                            (lambda ()
                              (call-with-input-file #$pid-file read))
                            (lambda args
                              ;; 'dhclient' returned before PID-FILE was created,
                              ;; so try again.
                              (let ((errno (system-error-errno args)))
                                (if (= ENOENT errno)
                                    (begin
                                      (sleep 1)
                                      (loop))
                                    (apply throw args))))))))))
      (stop #~(make-kill-destructor))))))

(define* (dhcp-client-service #:key (dhcp isc-dhcp))
  "Return a service that runs @var{dhcp}, a Dynamic Host Configuration
Protocol (DHCP) client, on all the non-loopback network interfaces."
  (service dhcp-client-service-type dhcp))

(define %ntp-servers
  ;; Default set of NTP servers.
  '("0.pool.ntp.org"
    "1.pool.ntp.org"
    "2.pool.ntp.org"))


;;;
;;; NTP.
;;;

;; TODO: Export.
(define-record-type* <ntp-configuration>
  ntp-configuration make-ntp-configuration
  ntp-configuration?
  (ntp      ntp-configuration-ntp
            (default ntp))
  (servers  ntp-configuration-servers))

(define ntp-shepherd-service
  (match-lambda
    (($ <ntp-configuration> ntp servers)
     (let ()
       ;; TODO: Add authentication support.
       (define config
         (string-append "driftfile /var/run/ntp.drift\n"
                        (string-join (map (cut string-append "server " <>)
                                          servers)
                                     "\n")
                        "
# Disable status queries as a workaround for CVE-2013-5211:
# <http://support.ntp.org/bin/view/Main/SecurityNotice#DRDoS_Amplification_Attack_using>.
restrict default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery

# Yet, allow use of the local 'ntpq'.
restrict 127.0.0.1
restrict -6 ::1\n"))

       (define ntpd.conf
         (plain-file "ntpd.conf" config))

       (list (shepherd-service
              (provision '(ntpd))
              (documentation "Run the Network Time Protocol (NTP) daemon.")
              (requirement '(user-processes networking))
              (start #~(make-forkexec-constructor
                        (list (string-append #$ntp "/bin/ntpd") "-n"
                              "-c" #$ntpd.conf "-u" "ntpd")))
              (stop #~(make-kill-destructor))))))))

(define %ntp-accounts
  (list (user-account
         (name "ntpd")
         (group "nogroup")
         (system? #t)
         (comment "NTP daemon user")
         (home-directory "/var/empty")
         (shell #~(string-append #$shadow "/sbin/nologin")))))

(define ntp-service-type
  (service-type (name 'ntp)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          ntp-shepherd-service)
                       (service-extension account-service-type
                                          (const %ntp-accounts))))))

(define* (ntp-service #:key (ntp ntp)
                      (servers %ntp-servers))
  "Return a service that runs the daemon from @var{ntp}, the
@uref{http://www.ntp.org, Network Time Protocol package}.  The daemon will
keep the system clock synchronized with that of @var{servers}."
  (service ntp-service-type
           (ntp-configuration (ntp ntp) (servers servers))))


;;;
;;; Tor.
;;;

(define-record-type* <tor-configuration>
  tor-configuration make-tor-configuration
  tor-configuration?
  (tor              tor-configuration-tor
                    (default tor))
  (config-file      tor-configuration-config-file)
  (hidden-services  tor-configuration-hidden-services
                    (default '())))

(define %tor-accounts
  ;; User account and groups for Tor.
  (list (user-group (name "tor") (system? #t))
        (user-account
         (name "tor")
         (group "tor")
         (system? #t)
         (comment "Tor daemon user")
         (home-directory "/var/empty")
         (shell #~(string-append #$shadow "/sbin/nologin")))))

(define-record-type <hidden-service>
  (hidden-service name mapping)
  hidden-service?
  (name    hidden-service-name)                   ;string
  (mapping hidden-service-mapping))               ;list of port/address tuples

(define (tor-configuration->torrc config)
  "Return a 'torrc' file for CONFIG."
  (match config
    (($ <tor-configuration> tor config-file services)
     (computed-file
      "torrc"
      (with-imported-modules '((guix build utils))
        #~(begin
            (use-modules (guix build utils)
                         (ice-9 match))

            (call-with-output-file #$output
              (lambda (port)
                (display "\
# The beginning was automatically added.
User tor
DataDirectory /var/lib/tor
Log notice syslog\n" port)

                (for-each (match-lambda
                            ((service (ports hosts) ...)
                             (format port "\
HiddenServiceDir /var/lib/tor/hidden-services/~a~%"
                                     service)
                             (for-each (lambda (tcp-port host)
                                         (format port "\
HiddenServicePort ~a ~a~%"
                                                 tcp-port host))
                                       ports hosts)))
                          '#$(map (match-lambda
                                    (($ <hidden-service> name mapping)
                                     (cons name mapping)))
                                  services))

                ;; Append the user's config file.
                (call-with-input-file #$config-file
                  (lambda (input)
                    (dump-port input port)))
                #t))))))))

(define (tor-shepherd-service config)
  "Return a <shepherd-service> running TOR."
  (match config
    (($ <tor-configuration> tor)
     (let ((torrc (tor-configuration->torrc config)))
       (list (shepherd-service
              (provision '(tor))

              ;; Tor needs at least one network interface to be up, hence the
              ;; dependency on 'loopback'.
              (requirement '(user-processes loopback syslogd))

              (start #~(make-forkexec-constructor
                        (list (string-append #$tor "/bin/tor") "-f" #$torrc)))
              (stop #~(make-kill-destructor))
              (documentation "Run the Tor anonymous network overlay.")))))))

(define (tor-hidden-service-activation config)
  "Return the activation gexp for SERVICES, a list of hidden services."
  #~(begin
      (use-modules (guix build utils))

      (define %user
        (getpw "tor"))

      (define (initialize service)
        (let ((directory (string-append "/var/lib/tor/hidden-services/"
                                        service)))
          (mkdir-p directory)
          (chown directory (passwd:uid %user) (passwd:gid %user))

          ;; The daemon bails out if we give wider permissions.
          (chmod directory #o700)))

      (mkdir-p "/var/lib/tor")
      (chown "/var/lib/tor" (passwd:uid %user) (passwd:gid %user))
      (chmod "/var/lib/tor" #o700)

      (for-each initialize
                '#$(map hidden-service-name
                        (tor-configuration-hidden-services config)))))

(define tor-service-type
  (service-type (name 'tor)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          tor-shepherd-service)
                       (service-extension account-service-type
                                          (const %tor-accounts))
                       (service-extension activation-service-type
                                          tor-hidden-service-activation)))

                ;; This can be extended with hidden services.
                (compose concatenate)
                (extend (lambda (config services)
                          (tor-configuration
                           (inherit config)
                           (hidden-services
                            (append (tor-configuration-hidden-services config)
                                    services)))))))

(define* (tor-service #:optional
                      (config-file (plain-file "empty" ""))
                      #:key (tor tor))
  "Return a service to run the @uref{https://torproject.org, Tor} anonymous
networking daemon.

The daemon runs as the @code{tor} unprivileged user.  It is passed
@var{config-file}, a file-like object, with an additional @code{User tor} line
and lines for hidden services added via @code{tor-hidden-service}.  Run
@command{man tor} for information about the configuration file."
  (service tor-service-type
           (tor-configuration (tor tor)
                              (config-file config-file))))

(define tor-hidden-service-type
  ;; A type that extends Tor with hidden services.
  (service-type (name 'tor-hidden-service)
                (extensions
                 (list (service-extension tor-service-type list)))))

(define (tor-hidden-service name mapping)
  "Define a new Tor @dfn{hidden service} called @var{name} and implementing
@var{mapping}.  @var{mapping} is a list of port/host tuples, such as:

@example
 '((22 \"127.0.0.1:22\")
   (80 \"127.0.0.1:8080\"))
@end example

In this example, port 22 of the hidden service is mapped to local port 22, and
port 80 is mapped to local port 8080.

This creates a @file{/var/lib/tor/hidden-services/@var{name}} directory, where
the @file{hostname} file contains the @code{.onion} host name for the hidden
service.

See @uref{https://www.torproject.org/docs/tor-hidden-service.html.en, the Tor
project's documentation} for more information."
  (service tor-hidden-service-type
           (hidden-service name mapping)))


;;;
;;; BitlBee.
;;;

(define-record-type* <bitlbee-configuration>
  bitlbee-configuration make-bitlbee-configuration
  bitlbee-configuration?
  (bitlbee bitlbee-configuration-bitlbee
           (default bitlbee))
  (interface bitlbee-configuration-interface)
  (port bitlbee-configuration-port)
  (extra-settings bitlbee-configuration-extra-settings))

(define bitlbee-shepherd-service
  (match-lambda
    (($ <bitlbee-configuration> bitlbee interface port extra-settings)
     (let ((conf (plain-file "bitlbee.conf"
                             (string-append "
  [settings]
  User = bitlbee
  ConfigDir = /var/lib/bitlbee
  DaemonInterface = " interface "
  DaemonPort = " (number->string port) "
" extra-settings))))

       (list (shepherd-service
              (provision '(bitlbee))
              (requirement '(user-processes loopback))
              (start #~(make-forkexec-constructor
                        (list (string-append #$bitlbee "/sbin/bitlbee")
                              "-n" "-F" "-u" "bitlbee" "-c" #$conf)))
              (stop  #~(make-kill-destructor))))))))

(define %bitlbee-accounts
  ;; User group and account to run BitlBee.
  (list (user-group (name "bitlbee") (system? #t))
        (user-account
         (name "bitlbee")
         (group "bitlbee")
         (system? #t)
         (comment "BitlBee daemon user")
         (home-directory "/var/empty")
         (shell #~(string-append #$shadow "/sbin/nologin")))))

(define %bitlbee-activation
  ;; Activation gexp for BitlBee.
  #~(begin
      (use-modules (guix build utils))

      ;; This directory is used to store OTR data.
      (mkdir-p "/var/lib/bitlbee")
      (let ((user (getpwnam "bitlbee")))
        (chown "/var/lib/bitlbee"
               (passwd:uid user) (passwd:gid user)))))

(define bitlbee-service-type
  (service-type (name 'bitlbee)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          bitlbee-shepherd-service)
                       (service-extension account-service-type
                                          (const %bitlbee-accounts))
                       (service-extension activation-service-type
                                          (const %bitlbee-activation))))))

(define* (bitlbee-service #:key (bitlbee bitlbee)
                          (interface "127.0.0.1") (port 6667)
                          (extra-settings ""))
  "Return a service that runs @url{http://bitlbee.org,BitlBee}, a daemon that
acts as a gateway between IRC and chat networks.

The daemon will listen to the interface corresponding to the IP address
specified in @var{interface}, on @var{port}.  @code{127.0.0.1} means that only
local clients can connect, whereas @code{0.0.0.0} means that connections can
come from any networking interface.

In addition, @var{extra-settings} specifies a string to append to the
configuration file."
  (service bitlbee-service-type
           (bitlbee-configuration
            (bitlbee bitlbee)
            (interface interface) (port port)
            (extra-settings extra-settings))))


;;;
;;; Wicd.
;;;

(define %wicd-activation
  ;; Activation gexp for Wicd.
  #~(begin
      (use-modules (guix build utils))

      (mkdir-p "/etc/wicd")
      (let ((file-name "/etc/wicd/dhclient.conf.template.default"))
        (unless (file-exists? file-name)
          (copy-file (string-append #$wicd file-name)
                     file-name)))))

(define (wicd-shepherd-service wicd)
  "Return a shepherd service for WICD."
  (list (shepherd-service
         (documentation "Run the Wicd network manager.")
         (provision '(networking))
         (requirement '(user-processes dbus-system loopback))
         (start #~(make-forkexec-constructor
                   (list (string-append #$wicd "/sbin/wicd")
                         "--no-daemon")))
         (stop #~(make-kill-destructor)))))

(define wicd-service-type
  (service-type (name 'wicd)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          wicd-shepherd-service)
                       (service-extension dbus-root-service-type
                                          list)
                       (service-extension activation-service-type
                                          (const %wicd-activation))

                       ;; Add Wicd to the global profile.
                       (service-extension profile-service-type list)))))

(define* (wicd-service #:key (wicd wicd))
  "Return a service that runs @url{https://launchpad.net/wicd,Wicd}, a network
management daemon that aims to simplify wired and wireless networking.

This service adds the @var{wicd} package to the global profile, providing
several commands to interact with the daemon and configure networking:
@command{wicd-client}, a graphical user interface, and the @command{wicd-cli}
and @command{wicd-curses} user interfaces."
  (service wicd-service-type wicd))


;;;
;;; NetworkManager
;;;

(define %network-manager-activation
  ;; Activation gexp for NetworkManager.
  #~(begin
      (use-modules (guix build utils))
      (mkdir-p "/etc/NetworkManager/system-connections")))

(define (network-manager-shepherd-service network-manager)
  "Return a shepherd service for NETWORK-MANAGER."
  (list (shepherd-service
         (documentation "Run the NetworkManager.")
         (provision '(networking))
         (requirement '(user-processes dbus-system loopback))
         (start #~(make-forkexec-constructor
                   (list (string-append #$network-manager
                                        "/sbin/NetworkManager")
                         "--no-daemon")))
         (stop #~(make-kill-destructor)))))

(define network-manager-service-type
  (service-type (name 'network-manager)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          network-manager-shepherd-service)
                       (service-extension dbus-root-service-type list)
                       (service-extension activation-service-type
                                          (const %network-manager-activation))
                       ;; Add network-manager to the system profile.
                       (service-extension profile-service-type list)))))

(define* (network-manager-service #:key (network-manager network-manager))
  "Return a service that runs NetworkManager, a network connection manager
that attempting to keep active network connectivity when available."
  (service network-manager-service-type network-manager))


;;;
;;; Connman
;;;

(define %connman-activation
  ;; Activation gexp for Connman.
  #~(begin
      (use-modules (guix build utils))
      (mkdir-p "/var/lib/connman/")
      (mkdir-p "/var/lib/connman-vpn/")))

(define (connman-shepherd-service connman)
  "Return a shepherd service for Connman"
  (list (shepherd-service
         (documentation "Run Connman")
         (provision '(networking))
         (requirement '(user-processes dbus-system loopback))
         (start #~(make-forkexec-constructor
                   (list (string-append #$connman
                                        "/sbin/connmand")
                         "-n" "-r")))
         (stop #~(make-kill-destructor)))))

(define connman-service-type
  (service-type (name 'connman)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          connman-shepherd-service)
                       (service-extension dbus-root-service-type list)
                       (service-extension activation-service-type
                                          (const %connman-activation))
                       ;; Add connman to the system profile.
                       (service-extension profile-service-type list)))))

(define* (connman-service #:key (connman connman))
  "Return a service that runs @url{https://01.org/connman,Connman}, a network
connection manager.

This service adds the @var{connman} package to the global profile, providing
several the @command{connmanctl} command to interact with the daemon and
configure networking."
  (service connman-service-type connman))

;;; networking.scm ends here
