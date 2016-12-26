;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Taylan Ulrich Bayırlı/Kammer <taylanbayirli@gmail.com>
;;; Copyright © 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 John Darrington <jmd@gnu.org>
;;; Copyright © 2016 ng0 <ng0@we.make.ritual.n0.is>
;;; Copyright © 2016 Tobias Geerinckx-Rice <me@tobias.gr>
;;; Copyright © 2016 Marius Bakke <mbakke@fastmail.com>
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

(define-module (gnu packages dns)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages base)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages crypto)
  #:use-module (gnu packages groff)
  #:use-module (gnu packages libevent)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages xml)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu))

(define-public dnsmasq
  (package
    (name "dnsmasq")
    (version "2.76")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://www.thekelleys.org.uk/dnsmasq/dnsmasq-"
                    version ".tar.xz"))
              (sha256
               (base32
                "15lzih6671gh9knzpl8mxchiml7z5lfqzr7jm2r0rjhrxs6nk4jb"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (alist-delete 'configure %standard-phases)
       #:make-flags (list (string-append "PREFIX=" (assoc-ref %outputs "out"))
                          "CC=gcc")
       ;; No 'check' target.
       #:tests? #f))
    (home-page "http://www.thekelleys.org.uk/dnsmasq/doc.html")
    (synopsis "Small caching DNS proxy and DHCP/TFTP server")
    (description
     "Dnsmasq is a lightweight DNS forwarder and DHCP server.  It is designed
to provide DNS and optionally, DHCP, to a small network.  It can serve the
names of local machines which are not in the global DNS.  The DHCP server
integrates with the DNS server and allows machines with DHCP-allocated
addresses to appear in the DNS with names configured either in each host or in
a central configuration file.  Dnsmasq supports static and dynamic DHCP leases
and BOOTP/TFTP for network booting of diskless machines.")
    ;; Source files only say GPL2 and GPL3 are allowed.
    (license (list license:gpl2 license:gpl3))))

(define-public bind
  (package
    (name "bind")
    (version "9.10.4-P4")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "ftp://ftp.isc.org/isc/bind9/" version "/" name "-"
                    version ".tar.gz"))
              (sha256
               (base32
                "11lxkb7d79c75scrs28q4xmr0ii2li69zj1c650al3qxir8yf754"))))
    (build-system gnu-build-system)
    (outputs `("out" "utils"))
    (inputs
     ;; it would be nice to add GeoIP and gssapi once there is package
     `(("libcap" ,libcap)
       ("libxml2" ,libxml2)
       ("openssl" ,openssl)
       ("p11-kit" ,p11-kit)))
    (native-inputs `(("perl" ,perl)
                     ("net-tools" ,net-tools)))
    (arguments
     `(#:configure-flags
       (list (string-append "--with-openssl="
                            (assoc-ref %build-inputs "openssl"))
             (string-append "--with-pkcs11="
                            (assoc-ref %build-inputs "p11-kit")))
       #:phases
       (modify-phases %standard-phases
         (add-after 'strip 'move-to-utils
           (lambda _
             (for-each
              (lambda (file)
                (let ((target  (string-append (assoc-ref %outputs "utils") file))
                      (src  (string-append (assoc-ref %outputs "out") file)))
                  (mkdir-p (dirname target))
                  (link src target)
                  (delete-file src)))
              '("/bin/dig" "/bin/delv" "/bin/nslookup" "/bin/host" "/bin/nsupdate"
                "/share/man/man1/dig.1"
                "/share/man/man1/host.1"
                "/share/man/man1/nslookup.1"
                "/share/man/man1/nsupdate.1"))))
         ;; When and if guix provides user namespaces for the build process,
         ;; then the following can be uncommented and the subsequent "force-test"
         ;; will not be necessary.
         ;;
         ;;   (add-before 'check 'set-up-loopback
         ;;     (lambda _
         ;;          (system "bin/tests/system/ifconfig.sh up")))
         (replace 'check
           (lambda _
             (zero? (system* "make" "force-test")))))))
    (synopsis "An implementation of the Domain Name System")
    (description "BIND is an implementation of the Domain Name System (DNS)
protocols for the Internet.  It is a reference implementation of those
protocols, but it is also production-grade software, suitable for use in
high-volume and high-reliability applications. The name BIND stands for
\"Berkeley Internet Name Domain\", because the software originated in the early
1980s at the University of California at Berkeley.")
    (home-page "https://www.isc.org/downloads/bind")
    (license (list license:isc))))

(define-public dnscrypt-proxy
  (package
    (name "dnscrypt-proxy")
    (version "1.8.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://download.dnscrypt.org/dnscrypt-proxy/"
                    "dnscrypt-proxy-" version ".tar.bz2"))
              (sha256
               (base32
                "1dz0knslf7ysc2xx33ljrdlqyr4b0fpm9ifrwvwgcjaxgh94l7m8"))
              (modules '((guix build utils)))
              (snippet
               ;; Delete bundled libltdl. XXX: This package also bundles
               ;; a modified libevent that cannot currently be removed.
               '(delete-file-recursively "libltdl"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'configure 'autoreconf
           (lambda _
             ;; Re-generate build files due to unbundling ltdl.
             ;; TODO: Prevent generating new libltdl and building it.
             ;; The system version is still favored and referenced.
             (zero? (system* "autoreconf" "-vif")))))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("automake" ,automake)
       ("autoconf" ,autoconf)
       ("libtool" ,libtool)))
    (inputs
     `(("libltdl" ,libltdl)
       ("libsodium" ,libsodium)))
    (home-page "https://www.dnscrypt.org/")
    (synopsis "Securely send DNS requests to a remote server")
    (description
     "@command{dnscrypt-proxy} is a tool for securing communications
between a client and a DNS resolver.  It verifies that responses you get
from a DNS provider was actually sent by that provider, and haven't been
tampered with.  For optimal performance it is recommended to use this as
a forwarder for a caching DNS resolver such as @command{dnsmasq}, but it
can also be used as a normal DNS \"server\".  A list of public dnscrypt
servers is included, and an up-to-date version is available at
@url{https://download.dnscrypt.org/dnscrypt-proxy/dnscrypt-resolvers.csv}.")
    (license (list license:isc
                   ;; Libevent and src/ext/queue.h is 3-clause BSD.
                   license:bsd-3))))

(define-public dnscrypt-wrapper
  (package
    (name "dnscrypt-wrapper")
    (version "0.2.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/cofyc/dnscrypt-wrapper/releases"
                    "/download/v" version "/" name "-v" version ".tar.bz2"))
              (sha256
               (base32
                "1vhg4g0r687f51wcdn7z9w1hxapazx6vyh5rsr8wa48sljzd583g"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags '("CC=gcc")
       ;; TODO: Tests require ruby-cucumber and ruby-aruba.
       #:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'create-configure
           (lambda _
             (zero? (system* "make" "configure")))))))
    (native-inputs
     `(("autoconf" ,autoconf)))
    (inputs
     `(("libevent" ,libevent)
       ("libsodium" ,libsodium)))
    (home-page "https://github.com/Cofyc/dnscrypt-wrapper")
    (synopsis "Server-side dnscrypt proxy")
    (description
     "@command{dnscrypt-wrapper} is a tool to expose a name server over
the @code{dnscrypt} protocol.  It can be used as an endpoint for the
@command{dnscrypt-proxy} client to securely tunnel DNS requests between
the two.")
    (license (list license:isc
                   ;; Bundled argparse is MIT. TODO: package and unbundle.
                   license:expat
                   ;; dns-protocol.h and rfc1035.{c,h} is gpl2 or gpl3 (either).
                   license:gpl2
                   license:gpl3))))

(define-public libasr
  (package
    (name "libasr")
    (version "201602131606")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://www.opensmtpd.org/archives/"
                           name "-" version ".tar.gz"))
       (sha256
        (base32
         "18kdmbjsxrfai16d66qslp48b1zf7gr8him2jj5dcqgbsl44ls75"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("pkg-config" ,pkg-config)
       ("groff" ,groff)))
    (home-page "https://www.opensmtpd.org")
    (synopsis "Asynchronous resolver library by the OpenBSD project")
    (description
     "libasr is a free, simple and portable asynchronous resolver library.
It allows to run DNS queries and perform hostname resolutions in a fully
asynchronous fashion.")
    (license (list license:isc
                   license:bsd-2 ; last part of getrrsetbyname_async.c
                   license:bsd-3
                   (license:non-copyleft "file://LICENSE") ; includes.h
                   license:openssl))))

(define-public yadifa
  (package
    (name "yadifa")
    (version "2.2.3")
    (source
     (let ((revision "6711"))
       (origin
         (method url-fetch)
         (uri
          (string-append "http://cdn.yadifa.eu/sites/default/files/releases/"
                         name "-" version "-" revision ".tar.gz"))
         (sha256
          (base32
           "0ikfm40gx0zjw3gnxsw3rn1k4wb8jacgklja3ygcj1knq6hy2zaa")))))
    (build-system gnu-build-system)
    (native-inputs
     `(("which" ,which)))
    (inputs
     `(("openssl" ,openssl)))
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (add-before 'configure 'omit-example-configurations
                              (lambda _ (substitute* "Makefile.in"
                                          ((" (etc|var)") "")))))
       #:configure-flags (list "--sysconfdir=/etc"      "--localstatedir=/var"
                               "--enable-shared"        "--disable-static"
                               "--enable-messages"      "--enable-ctrl"
                               "--enable-nsec"          "--enable-nsec3"
                               "--enable-tsig"          "--enable-caching"
                               ;; NSID is a rarely-used debugging aid, that also
                               ;; causes the build to fail. Just disable it.
                               "--disable-nsid")))
    (home-page "http://www.yadifa.eu/")
    (synopsis "Authoritative DNS name server")
    (description "YADIFA is an authorative name server for the Domain Name
System (DNS).  It aims for both higher performance and a smaller memory
footprint than other implementations, while remaining fully RFC-compliant.
YADIFA supports dynamic record updates and the Domain Name System Security
Extensions (DNSSEC).")
    (license license:bsd-3)))
