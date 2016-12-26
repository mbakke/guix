;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2013, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2015 Jeff Mickey <j@codemac.net>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Tobias Geerinckx-Rice <me@tobias.gr>
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

(define-module (gnu packages vpn)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system python)
  #:use-module (gnu packages)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages xml))

(define-public gvpe
  (package
    (name "gvpe")
    (version "3.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/gvpe/gvpe-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1v61mj25iyd91z0ir7cmradkkcm1ffbk52c96v293ibsvjs2s2hf"))))
    (build-system gnu-build-system)
    (home-page "http://software.schmorp.de/pkg/gvpe.html")
    (inputs `(("openssl" ,openssl)
              ("zlib" ,zlib)))
    (synopsis "Secure VPN among multiple nodes over an untrusted network")
    (description
     "The GNU Virtual Private Ethernet creates a virtual network
with multiple nodes using a variety of transport protocols.  It works
by creating encrypted host-to-host tunnels between multiple
endpoints.")
    (license license:gpl3+)))

(define-public vpnc
  (package
   (name "vpnc")
   (version "0.5.3")
   (source (origin
            (method url-fetch)
            (uri (string-append "https://www.unix-ag.uni-kl.de/~massar/vpnc/vpnc-"
                                version ".tar.gz"))
            (sha256 (base32
                     "1128860lis89g1s21hqxvap2nq426c9j4bvgghncc1zj0ays7kj6"))
            (patches (search-patches "vpnc-script.patch"))))
   (build-system gnu-build-system)
   (inputs `(("libgcrypt" ,libgcrypt)
             ("perl" ,perl)

             ;; The following packages provide commands that 'vpnc-script'
             ;; expects.
             ("net-tools" ,net-tools)             ;ifconfig, route
             ("iproute2" ,iproute)))              ;ip
   (arguments
    `(#:tests? #f ; there is no check target
      #:phases
      (modify-phases %standard-phases
        (replace 'configure
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((out (assoc-ref outputs "out")))
              (substitute* "Makefile"
                (("PREFIX=/usr/local") (string-append "PREFIX=" out)))
              (substitute* "Makefile"
                (("ETCDIR=/etc/vpnc") (string-append "ETCDIR=" out
                                                     "/etc/vpnc"))))))
        (add-after 'install 'wrap-vpnc-script
          (lambda* (#:key inputs outputs #:allow-other-keys)
            ;; Wrap 'etc/vpnc/vpnc-script' so that it finds the commands it
            ;; needs.  Assume coreutils/grep/sed are in $PATH.
            (let ((out (assoc-ref outputs "out")))
              (wrap-program (string-append out "/etc/vpnc/vpnc-script")
                `("PATH" ":" prefix
                  (,(string-append (assoc-ref inputs "net-tools")
                                   "/sbin")
                   ,(string-append (assoc-ref inputs "net-tools")
                                   "/bin")
                   ,(string-append (assoc-ref inputs "iproute2")
                                   "/sbin"))))))))))
   (synopsis "Client for Cisco VPN concentrators")
   (description
    "vpnc is a VPN client compatible with Cisco's EasyVPN equipment.
It supports IPSec (ESP) with Mode Configuration and Xauth.  It supports only
shared-secret IPSec authentication with Xauth, AES (256, 192, 128), 3DES,
1DES, MD5, SHA1, DH1/2/5 and IP tunneling.  It runs entirely in userspace.
Only \"Universal TUN/TAP device driver support\" is needed in the kernel.")
   (license license:gpl2+) ; some file are bsd-2, see COPYING
   (home-page "http://www.unix-ag.uni-kl.de/~massar/vpnc/")))


(define-public openconnect
  (package
   (name "openconnect")
   (version "7.08")
   (source (origin
            (method url-fetch)
            (uri (string-append "ftp://ftp.infradead.org/pub/openconnect/"
                                "openconnect-" version ".tar.gz"))
            (sha256 (base32
                     "00wacb79l2c45f94gxs63b9z25wlciarasvjrb8jb8566wgyqi0w"))))
   (build-system gnu-build-system)
   (inputs
    `(("libxml2" ,libxml2)
      ("gnutls" ,gnutls)
      ("vpnc" ,vpnc)
      ("zlib" ,zlib)))
   (native-inputs
    `(("gettext" ,gettext-minimal)
      ("pkg-config" ,pkg-config)))
   (arguments
    `(#:configure-flags
      `(,(string-append "--with-vpnc-script="
                        (assoc-ref %build-inputs "vpnc")
                        "/etc/vpnc/vpnc-script"))))
   (synopsis "Client for Cisco VPN")
   (description
    "OpenConnect is a client for Cisco's AnyConnect SSL VPN, which is
supported by the ASA5500 Series, by IOS 12.4(9)T or later on Cisco SR500,
870, 880, 1800, 2800, 3800, 7200 Series and Cisco 7301 Routers,
and probably others.")
   (license license:lgpl2.1)
   (home-page "http://www.infradead.org/openconnect/")))

(define-public openvpn
  (package
    (name "openvpn")
    (version "2.3.9")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://swupdate.openvpn.org/community/releases/openvpn-"
                    version ".tar.xz"))
              (sha256
               (base32
                "1hfwmdsp7s34qx34qgwrpp89h30744lbsks6y619cdh27bpnpwaj"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags '("--enable-iproute2=yes")))
    (native-inputs
     `(("iproute2" ,iproute)))
    (inputs
     `(("lzo" ,lzo)
       ("openssl" ,openssl)
       ("linux-pam" ,linux-pam)))
    (home-page "https://openvpn.net/")
    (synopsis "Virtual private network daemon")
    (description "OpenVPN implements virtual private network (VPN) techniques
for creating secure point-to-point or site-to-site connections in routed or
bridged configurations and remote access facilities.  It uses a custom
security protocol that utilizes SSL/TLS for key exchange.  It is capable of
traversing network address translators (NATs) and firewalls.")
    (license license:gpl2)))

(define-public tinc
  (package
    (name "tinc")
    (version "1.0.28")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://tinc-vpn.org/packages/"
                                  name "-" version ".tar.gz"))
              (sha256
               (base32
                "0i5kx3hza359nclyhb60kxlzqyx0phmg175350hww28g6scjcl0b"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags
       '("--sysconfdir=/etc"
         "--localstatedir=/var")))
    (inputs `(("zlib" ,zlib)
              ("lzo" ,lzo)
              ("openssl" ,openssl)))
    (home-page "http://tinc-vpn.org")
    (synopsis "Virtual Private Network (VPN) daemon")
    (description
     "Tinc is a VPN that uses tunnelling and encryption to create a secure
private network between hosts on the internet.")
    (license license:gpl2+)))

(define-public sshuttle
  (package
    (name "sshuttle")
    (version "0.78.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri name version))
       (sha256
        (base32
         "0g1dpqigz02vafzh84z5990lnj9d95raknav0xmf0va7rr41d9q3"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest-runner" ,python-pytest-runner)
       ("python-setuptools-scm" ,python-setuptools-scm)
       ;; For tests only.
       ("python-mock" ,python-mock)
       ("python-pytest" ,python-pytest)))
    (home-page "https://github.com/sshuttle/sshuttle")
    (synopsis "VPN that transparently forwards connections over SSH")
    (description "sshuttle creates an encrypted virtual private network (VPN)
connection to any remote server to which you have secure shell (SSH) access.
The only requirement is a suitable version of Python on the server;
administrative privileges are required only on the client.  Unlike most VPNs,
sshuttle forwards entire sessions, not packets, using kernel transparent
proxying.  This makes it faster and more reliable than SSH's own tunneling and
port forwarding features.  It can forward both TCP and UDP traffic, including
DNS domain name queries.")
    (license license:lgpl2.0))) ; incorrectly identified as GPL in ‘setup.py’

(define-public sshoot
  (package
    (name "sshoot")
    (version "1.2.5")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri name version))
       (sha256
        (base32
         "0a92lk8790dpp9j64vb6p4sazax0x3nby01lnfll7mxs1hx6n27q"))))
    (build-system python-build-system)
    (inputs
     `(("python-argcomplete" ,python-argcomplete)
       ("python-prettytable" ,python-prettytable)
       ("python-pyyaml" ,python-pyyaml)))
    ;; For tests only.
    (native-inputs
     `(("python-fixtures" ,python-fixtures)
       ("python-pbr" ,python-pbr)
       ("python-testtools" ,python-testtools)))
    (home-page "https://bitbucket.org/ack/sshoot")
    (synopsis "sshuttle VPN session manager")
    (description "sshoot provides a command-line interface to manage multiple
@command{sshuttle} virtual private networks.  It supports flexible profiles
with configuration options for most of @command{sshuttle}’s features.")
    (license license:gpl3+)))
