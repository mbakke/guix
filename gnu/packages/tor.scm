;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 ng0 <ng0@we.make.ritual.n0.is>
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

(define-module (gnu packages tor)
  #:use-module ((guix licenses) #:select (bsd-3 gpl3+ gpl2+ gpl2))
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system python)
  #:use-module (gnu packages)
  #:use-module (gnu packages libevent)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages python)
  #:use-module (gnu packages qt)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages w3m))

(define-public tor
  (package
    (name "tor")
    (version "0.2.9.8")
    (source (origin
             (method url-fetch)
             (uri (string-append "https://dist.torproject.org/tor-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "0sklgmx4nikcfhqd606kvpwy1l8840w24ikli1xjjx25739k7pgv"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("python" ,python-2)))  ; for tests
    (inputs
     `(("zlib" ,zlib)
       ("openssl" ,openssl)
       ("libevent" ,libevent)))
    (home-page "https://www.torproject.org/")
    (synopsis "Anonymous network router to improve privacy on the Internet")
    (description
     "Tor protects you by bouncing your communications around a distributed
network of relays run by volunteers all around the world: it prevents
somebody watching your Internet connection from learning what sites you
visit, and it prevents the sites you visit from learning your physical
location.  Tor works with many of your existing applications, including
web browsers, instant messaging clients, remote login, and other
applications based on the TCP protocol.

To @code{torify} applications (to take measures to ensure that an application,
which has not been designed for use with Tor such as ssh, will use only Tor for
internet connectivity, and also ensures that there are no leaks from DNS, UDP or
the application layer) you need to install @code{torsocks}.")
    (license bsd-3)))

(define-public torsocks
  (package
    (name "torsocks")
    (version "2.2.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://people.torproject.org/~dgoulet/"
                                  name "/" name "-" version ".tar.xz"))
              (sha256
               (base32
                "0byr9ga9w79qz4vp0m11sbmspad7fsal9wm67r4znzb7zb7cis19"))))
    (build-system gnu-build-system)
    (home-page "https://www.torproject.org/")
    (synopsis "Use socks-friendly applications with Tor")
    (description
     "Torsocks allows you to use most socks-friendly applications in a safe
way with Tor.  It ensures that DNS requests are handled safely and explicitly
rejects UDP traffic from the application you're using.")

    ;; All the files explicitly say "version 2 only".
    (license gpl2)))

(define-public privoxy
  (package
    (name "privoxy")
    (version "3.0.26")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://sourceforge/ijbswa/Sources/"
                                 version "%20%28stable%29/privoxy-"
                                 version "-stable-src.tar.gz"))
             (sha256
              (base32
               "1n4wpxmahl8m2y3d1azxa8lrdbpaad007k458skxrpz57ss1br2p"))))
    (build-system gnu-build-system)
    (arguments
     '(;; The default 'sysconfdir' is $out/etc; change that to
       ;; $out/etc/privoxy.
       #:configure-flags (list (string-append "--sysconfdir="
                                              (assoc-ref %outputs "out")
                                              "/etc/privoxy"))
       #:phases (alist-cons-after
                 'unpack 'autoconf
                 (lambda _
                   ;; Unfortunately, this is not a tarball produced by
                   ;; "make dist".
                   (zero? (system* "autoreconf" "-vfi")))
                 %standard-phases)
       #:tests? #f))
    (inputs
     `(("w3m" ,w3m)
       ("pcre" ,pcre)
       ("zlib" ,zlib)
       ("autoconf" ,autoconf)
       ("automake" ,automake)))
    (home-page "https://www.privoxy.org")
    (synopsis "Web proxy with advanced filtering capabilities for enhancing privacy")
    (description
     "Privoxy is a non-caching web proxy with advanced filtering capabilities
for enhancing privacy, modifying web page data and HTTP headers, controlling
access, and removing ads and other obnoxious Internet junk.  Privoxy has a
flexible configuration and can be customized to suit individual needs and
tastes.  It has application for both stand-alone systems and multi-user
networks.")
    (license gpl2+)))

(define-public onionshare
  (package
    (name "onionshare")
    (version "0.9.2")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "https://github.com/micahflee/onionshare/archive/v"
                            version ".tar.gz"))
        (file-name (string-append name "-" version ".tar.gz"))
        (sha256
         (base32
          "02iv7dg15da57gy3zvfchnwwpr21n1gva7mqwpwr958ni2034smk"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-install-path
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out        (assoc-ref outputs "out"))
                    (onionshare (string-append out "/share/onionshare")))
               (substitute* "onionshare/strings.py"
                 ;; correct the locale directory
                 (("helpers.get_resource_path\\('locale'\\)")
                  (string-append "'" onionshare "/locale'")))
               (substitute* "onionshare/helpers.py"
                 ;; correct the location of version.txt
                 (("get_resource_path\\('version.txt'\\)")
                  (string-append "'" onionshare "/version.txt'"))
                 (("get_resource_path\\('wordlist.txt'\\)")
                  (string-append "'" onionshare "/wordlist.txt'")))
               (substitute* "onionshare/web.py"
                 ;; fix the location of the html files
                 (("helpers.get_resource_path\\('html/denied.html'\\)")
                  (string-append "'" onionshare "/html/denied.html'"))
                 (("helpers.get_resource_path\\('html/404.html'\\)")
                  (string-append "'" onionshare "/html/404.html'"))
                 (("helpers.get_resource_path\\('html/index.html'\\)")
                  (string-append "'" onionshare "/html/index.html'")))
               (substitute* "onionshare_gui/file_selection.py"
                 ;; fancy box image in the GUI
                 (("helpers.get_resource_path\\('images/drop_files.png'\\)")
                  (string-append "'" onionshare "/images/drop_files.png'")))
               (substitute* "onionshare_gui/server_status.py"
                 (("helpers.get_resource_path\\('images/server_stopped.png'\\)")
                  (string-append "'" onionshare "/images/server_stopped.png'"))
                 (("helpers.get_resource_path\\('images/server_working.png'\\)")
                  (string-append "'" onionshare "/images/server_working.png'"))
                 (("helpers.get_resource_path\\('images/server_started.png'\\)")
                  (string-append "'" onionshare "/images/server_started.png'")))
               (substitute* "onionshare_gui/onionshare_gui.py"
                  ;; for the icon on the GUI
                 (("helpers.get_resource_path\\('images/logo.png'\\)")
                  (string-append "'" onionshare "/images/logo.png'")))
               (substitute* '("setup.py" "onionshare/helpers.py")
                 (("sys.prefix,") (string-append "'" out "',")))
               (substitute* "setup.py"
                 ;; for the nautilus plugin
                 (("/usr/share/nautilus") "share/nautilus"))
             #t)))
         (delete 'check)
         (add-before 'strip 'tests
           ;; After all the patching we run the tests after installing.
           ;; This is also a known issue:
           ;; https://github.com/micahflee/onionshare/issues/284
           (lambda _ (zero? (system* "nosetests" "test")))))))
    (native-inputs
     `(("python-nose" ,python-nose)))
    (inputs
     `(("python-flask" ,python-flask)
       ("python-nautilus" ,python-nautilus)
       ("python-sip" ,python-sip)
       ("python-stem" ,python-stem)
       ("python-pyqt" ,python-pyqt)))
    (home-page "https://onionshare.org/")
    (synopsis "Securely and anonymously share files")
    (description "OnionShare lets you securely and anonymously share files of
any size.  It works by starting a web server, making it accessible as a Tor
hidden service, and generating an unguessable URL to access and download the
files.  It doesn't require setting up a server on the internet somewhere or
using a third party filesharing service.  You host the file on your own computer
and use a Tor hidden service to make it temporarily accessible over the
internet.  The other user just needs to use Tor Browser to download the file
from you.")
    (license (list gpl3+
                   bsd-3)))) ; onionshare/socks.py
