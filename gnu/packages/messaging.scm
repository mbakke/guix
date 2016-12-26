;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014 Julien Lepiller <julien@lepiller.eu>
;;; Copyright © 2015 Taylan Ulrich Bayırlı/Kammer <taylanbayirli@gmail.com>
;;; Copyright © 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 ng0 <ng0@libertad.pw>
;;; Copyright © 2016 Andy Patterson <ajpatter@uwaterloo.ca>
;;; Copyright © 2016 Clément Lassieur <clement@lassieur.org>
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

(define-module (gnu packages messaging)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix utils)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system glib-or-gtk)
  #:use-module (guix build-system python)
  #:use-module (guix build-system perl)
  #:use-module (guix build-system cmake)
  #:use-module (gnu packages)
  #:use-module (gnu packages aidc)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages avahi)
  #:use-module (gnu packages check)
  #:use-module (gnu packages crypto)
  #:use-module (gnu packages cyrus-sasl)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages enchant)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages libcanberra)
  #:use-module (gnu packages man)
  #:use-module (gnu packages networking)
  #:use-module (gnu packages libidn)
  #:use-module (gnu packages lua)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages python)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages tcl)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages check)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages qt)
  #:use-module (gnu packages video)
  #:use-module (gnu packages web)
  #:use-module (gnu packages xiph)
  #:use-module (gnu packages audio)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages fontutils))

(define-public libotr
  (package
    (name "libotr")
    (version "4.1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://otr.cypherpunks.ca/libotr-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1x8rliydhbibmzwdbyr7pd7n87m2jmxnqkpvaalnf4154hj1hfwb"))
              (patches (search-patches "libotr-test-auth-fix.patch"))))
    (build-system gnu-build-system)
    (propagated-inputs
     `(("libgcrypt" ,libgcrypt)))  ; libotr headers include gcrypt.h
    (inputs `(("libgpg-error" ,libgpg-error)))
    (native-inputs `(("perl" ,perl))) ; for the test suite
    (synopsis "Off-the-Record (OTR) Messaging Library and Toolkit")
    (description
     "OTR allows you to have private conversations over instant messaging by
providing: (1) Encryption: No one else can read your instant messages.  (2)
Authentication: You are assured the correspondent is who you think it is.  (3)
Deniability: The messages you send do not have digital signatures that are
checkable by a third party.  Anyone can forge messages after a conversation to
make them look like they came from you.  However, during a conversation, your
correspondent is assured the messages he sees are authentic and
unmodified.  (4) Perfect forward secrecy: If you lose control of your private
keys, no previous conversation is compromised.")
    (home-page "https://otr.cypherpunks.ca/")
    (license (list license:lgpl2.1 license:gpl2))))

;; These patches together fix https://github.com/bitlbee/bitlbee/pull/55, are
;; already upstream, and should be unnecessary when the next bitlbee comes
;; out.
(define %bitlbee-buddy-nick-change-patch
  (origin
    (method url-fetch)
    (uri "https://github.com/bitlbee/bitlbee/commit/a42fda42.patch")
    (sha256
     (base32
      "1mzjhcdn0rxir5mzgqz9kv142ai38p1iq2lajqx89wb7x0bp51zx"))))
(define %bitlbee-always-use-nicks-patch
  (origin
    (method url-fetch)
    (uri "https://github.com/bitlbee/bitlbee/commit/3320d6d9.patch")
    (sha256
     (base32
      "14d9kb5zdzh5hzakdvrbviz83rix0j2lq9rzb58b2fn92fp8yixd"))))

(define-public bitlbee
  (package
    (name "bitlbee")
    (version "3.4.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://get.bitlbee.org/src/bitlbee-"
                                  version ".tar.gz"))
              (sha256
               (base32 "0mza8lnfwibmklz8hdzg4f7p83hblf4h6fbf7d732kzpvra5bj39"))
              (patches
               (list %bitlbee-buddy-nick-change-patch
                     %bitlbee-always-use-nicks-patch))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)
                     ("check" ,check)))
    (inputs `(("glib" ,glib)
              ("libotr" ,libotr)
              ("gnutls" ,gnutls)
              ("python" ,python-2)
              ("perl" ,perl)))
    (arguments
     `(#:phases (alist-cons-after
                 'install 'install-etc
                 (lambda* (#:key (make-flags '()) #:allow-other-keys)
                   (zero? (apply system* "make" "install-etc" make-flags)))
                 (alist-replace
                  'configure
                  ;; bitlbee's configure script does not tolerate many of the
                  ;; variable settings that Guix would pass to it.
                  (lambda* (#:key outputs #:allow-other-keys)
                    (zero? (system* "./configure"
                                    (string-append "--prefix="
                                                   (assoc-ref outputs "out"))
                                    "--otr=1")))
                  %standard-phases))))
    (synopsis "IRC to instant messaging gateway")
    (description "BitlBee brings IM (instant messaging) to IRC clients, for
people who have an IRC client running all the time and don't want to run an
additional IM client.  BitlBee currently supports XMPP/Jabber (including
Google Talk), MSN Messenger, Yahoo!  Messenger, AIM and ICQ, and the Twitter
microblogging network (plus all other Twitter API compatible services like
identi.ca and status.net).")
    (home-page "http://www.bitlbee.org/")
    (license (list license:gpl2+ license:bsd-2))))

(define-public hexchat
  (package
    (name "hexchat")
    (version "2.12.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://dl.hexchat.net/hexchat/hexchat-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "1xnclfbrgbkqndxygi5f27q00jd7yy54jbd1061jmhxa6wzpibbd"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)
                     ("intltool" ,intltool)))
    (inputs `(("dbus-glib" ,dbus-glib)
              ("dbus" ,dbus)
              ("enchant" ,enchant)
              ("glib:bin" ,glib "bin")            ;need glib-genmarshal
              ("gtk" ,gtk+-2)
              ("libcanberra" ,libcanberra)
              ("libnotify" ,libnotify)
              ("openssl" ,openssl)

              ;; Bindings for add-on scripts.
              ("luajit" ,luajit)
              ("perl-xml-parser" ,perl-xml-parser)
              ("python-2" ,python-2)))
    (synopsis "Graphical IRC Client")
    (description
     "HexChat lets you connect to multiple IRC networks at once.  The main
window shows the list of currently connected networks and their channels, the
current conversation and the list of users.  It uses colors to differentiate
between users and to highlight messages.  It checks spelling using available
dictionaries.  HexChat can be extended with multiple addons.")
    (home-page "http://hexchat.net/")
    (license license:gpl2+)))

(define-public ngircd
  (package
    (name "ngircd")
    (version "22")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://arthur.barton.de/pub/ngircd/ngircd-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "17k3g9qd9d010czk5846qxvzkmw4fihv8l6m2a2287crbxm3xhd4"))
              (patches (search-patches "ngircd-no-dns-in-tests.patch"
                                       "ngircd-handle-zombies.patch"))))
    (build-system gnu-build-system)
    ;; Needed for the test suite.
    (native-inputs `(("procps" ,procps)
                     ("expect" ,expect)
                     ("inetutils" ,inetutils)))
    ;; XXX Add libident.
    (inputs `(("zlib" ,zlib)
              ("libwrap" ,tcp-wrappers)
              ("gnutls" ,gnutls)
              ,@(if (string-suffix? "-linux"
                                    (or (%current-target-system)
                                        (%current-system)))
                    `(("linux-pam" ,linux-pam))
                    '())))
    (arguments
     `(#:configure-flags
       '("--with-gnutls" "--with-iconv" "--enable-ipv6" "--with-tcp-wrappers"
         ,@(if (string-suffix? "-linux"
                               (or (%current-target-system)
                                   (%current-system)))
               '("--with-pam")
               '()))
       #:phases
       ;; Necessary for the test suite.
       (alist-cons-after
        'configure 'post-configure
        (lambda _
          (substitute* "src/ngircd/Makefile"
            (("/bin/sh") (which "sh")))
          ;; The default getpid.sh does a sloppy grep over 'ps -ax' output,
          ;; which fails arbitrarily.
          (with-output-to-file "src/testsuite/getpid.sh"
            (lambda ()
              (display
               (string-append
                "#!" (which "sh") "\n"
                "ps -C \"$1\" -o pid=\n"))))
          ;; Our variant of getpid.sh does not work for interpreter names if a
          ;; shebang script is run directly as "./foo", so patch cases where
          ;; the test suite relies on this.
          (substitute* "src/testsuite/start-server.sh"
            ;; It runs 'getpid.sh sh' to test if it works at all.  Run it on
            ;; 'make' instead.
            (("getpid.sh sh") "getpid.sh make")))
        %standard-phases)))
    (home-page "http://ngircd.barton.de/")
    (synopsis "Lightweight Internet Relay Chat server for small networks")
    (description
     "ngIRCd is a lightweight Internet Relay Chat server for small or private
networks.  It is easy to configure, can cope with dynamic IP addresses, and
supports IPv6, SSL-protected connections as well as PAM for authentication.")
    (license license:gpl2+)))

(define-public pidgin
  (package
    (name "pidgin")
    (version "2.11.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/pidgin/Pidgin/"
                           version "/" name "-" version ".tar.bz2"))
       (sha256
        (base32
         "0crkggjj6y07v1kdwil9vw532b0vrs6p33nmlvdkpnl60m2169pp"))
       (patches (search-patches "pidgin-add-search-path.patch"))))
    (build-system glib-or-gtk-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("check" ,check)
       ("intltool" ,intltool)
       ("gconf" ,gconf)
       ("python" ,python-2)
       ("doxygen" ,doxygen)))
    (inputs
     `(("gtk+" ,gtk+-2)
       ("libgcrypt" ,libgcrypt)
       ("gnutls" ,gnutls)
       ("cyrus-sasl" ,cyrus-sasl)
       ("dbus" ,dbus)
       ("dbus-glib" ,dbus-glib)
       ("python2-dbus" ,python2-dbus)
       ("libidn" ,libidn)
       ("libltdl" ,libltdl)
       ("libxml2" ,libxml2)
       ;; TODO: gstreamer: patches needed to support gstreamer-1.0 or later
       ;; TODO: farstream
       ;; TODO: meanwhile
       ;; TODO: network-manager
       ;; TODO: gtkspell
       ;; TODO: libxephyr
       ;; TODO: libgadu
       ("libxslt" ,libxslt)
       ("avahi" ,avahi)
       ("ncurses" ,ncurses)
       ("sqlite" ,sqlite)
       ("libice" ,libice)
       ("libsm" ,libsm)
       ("libxscrnsaver" ,libxscrnsaver)
       ("startup-notification" ,startup-notification)))
    (arguments
     `(#:configure-flags
       (list "--disable-gtkspell"
             "--disable-tcl"
             "--disable-meanwhile"
             "--disable-nm"  ; XXX remove when we have network-manager
             "--disable-vv"  ; XXX remove when we have farstream and gstreamer
             "--disable-gstreamer" ; XXX patches needed to support gstreamer-1.0
             "--enable-cyrus-sasl"
             (string-append "--with-ncurses-headers="
                            (assoc-ref %build-inputs "ncurses")
                            "/include"))))
    (native-search-paths
     (list (search-path-specification
            (variable "PURPLE_PLUGIN_PATH")
            (files (list (string-append "lib/purple-"
                                        (version-prefix version 1))
                         "lib/pidgin")))))
    (home-page "http://www.pidgin.im/")
    (synopsis "Graphical multi-protocol instant messaging client")
    (description
     "Pidgin is a modular instant messaging client that supports many popular
chat protocols.")
    (license
     (list
      license:gpl2+    ; Most of the code
      license:lgpl2.1  ; GG protocol plugin (libpurple/protocols/gg/lib)
      license:lgpl2.0+ ; OSCAR protocol plugin (libpurple/protocols/oscar)
      ;; The following licenses cover the zephyr protocol plugin:
      (license:non-copyleft
       "file://libpurple/protocols/zephyr/mit-copyright.h"
       "See libpurple/protocols/zephyr/mit-copyright.h in the distribution.")
      (license:non-copyleft
       "file://libpurple/protocols/zephyr/mit-sipb-copyright.h"
       "See libpurple/protocols/zephyr/mit-sipb-copyright.h in the distribution.")))))

(define-public pidgin-otr
  (package
    (name "pidgin-otr")
    (version "4.0.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://otr.cypherpunks.ca/"
                                  name "-" version ".tar.gz"))
              (sha256
               (base32
                "1i5s9rrgbyss9rszq6c6y53hwqyw1k86s40cpsfx5ccl9bprxdgl"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("intltool" ,intltool)))
    (inputs
     `(("pidgin" ,pidgin)
       ("libotr" ,libotr)
       ("libgpg-error" ,libgpg-error)
       ("libgcrypt" ,libgcrypt)
       ("glib" ,glib)
       ("gtk+" ,gtk+-2)))
    (home-page "https://otr.cypherpunks.ca/")
    (synopsis "Off-the-Record Messaging plugin for Pidgin")
    (description
     "Pidgin-OTR is a plugin that adds support for OTR to the Pidgin instant
messaging client.  OTR (Off-the-Record) Messaging allows you to have private
conversations over instant messaging by providing: (1) Encryption: No one else
can read your instant messages.  (2) Authentication: You are assured the
correspondent is who you think it is.  (3) Deniability: The messages you send
do not have digital signatures that are checkable by a third party.  Anyone
can forge messages after a conversation to make them look like they came from
you.  However, during a conversation, your correspondent is assured the
messages he sees are authentic and unmodified.  (4) Perfect forward secrecy:
If you lose control of your private keys, no previous conversation is
compromised.")
    (license license:gpl2)))

(define-public znc
  (package
    (name "znc")
    (version "1.6.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://znc.in/releases/archive/znc-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "09xqi5fs40x6nj9gq99bnw1a7saq96bvqxknxx0ilq7yfvg4c733"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ; tries to download GoogleTest with wget
       #:configure-flags '("--enable-python"
                           "--enable-perl"
                           "--enable-cyrus")))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("perl" ,perl)
       ("python" ,python)))
    (inputs
     `(("openssl" ,openssl)
       ("zlib" ,zlib)
       ("icu4c" ,icu4c)
       ("cyrus-sasl" ,cyrus-sasl)))
    (home-page "http://znc.in")
    (synopsis "IRC network bouncer")
    (description "ZNC is an IRC network bouncer or BNC.  It can detach the
client from the actual IRC server, and also from selected channels.  Multiple
clients from different locations can connect to a single ZNC account
simultaneously and therefore appear under the same nickname on IRC.")
    (license license:asl2.0)))

(define-public python-nbxmpp
  (package
    (name "python-nbxmpp")
    (version "0.5.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/n/nbxmpp/"
                           "nbxmpp-" version ".tar.gz"))
       (sha256
        (base32
         "0dcr786dyips1fdvgsn8yvpgcz5j7217fi05c29cfypdl8jnp6mp"))))
    (build-system python-build-system)
    ;; No tests included
    (arguments `(#:tests? #f))
    (home-page "http://python-nbxmpp.gajim.org")
    (synopsis "Non-blocking Jabber/XMPP module")
    (description
     "The goal of this python library is to provide a way for Python
applications to use Jabber/XMPP networks in a non-blocking way.  This library
was initially a fork of xmpppy, but is using non-blocking sockets.")
    (license license:gpl3+)))

(define-public python2-nbxmpp
  (package-with-python2 python-nbxmpp))

(define-public gajim
  (package
    (name "gajim")
    (version "0.16.6")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://gajim.org/downloads/"
                                  (version-major+minor version)
                                  "/gajim-" version ".tar.bz2"))
              (sha256
               (base32
                "1p3qwzy07f0wkika9yigyiq167l2k6wn12flqa7x55z4ihbysmqk"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'install 'wrap-program
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Make sure all Python scripts run with the correct PYTHONPATH.
             (let ((out (assoc-ref outputs "out"))
                   (path (getenv "PYTHONPATH")))
               (for-each (lambda (name)
                           (let ((file (string-append out "/bin/" name)))
                             ;; Wrapping destroys identification of intended
                             ;; application, so we need to override "APP".
                             (substitute* file
                               (("APP=`basename \\$0`")
                                (string-append "APP=" name)))
                             (wrap-program file
                               `("PYTHONPATH" ":" prefix (,path)))))
                         '("gajim" "gajim-remote" "gajim-history-manager")))
             #t)))))
    (native-inputs
     `(("intltool" ,intltool)))
    (propagated-inputs
     `(("python2-nbxmpp" ,python2-nbxmpp)
       ("python2-pyopenssl" ,python2-pyopenssl)
       ("python2-gnupg" ,python2-gnupg)))
    (inputs
     `(("python2-pygtk" ,python2-pygtk)
       ("python" ,python-2)))
    (home-page "https://gajim.org/")
    (synopsis "Jabber (XMPP) client")
    (description "Gajim is a feature-rich and easy to use Jabber/XMPP client.
Among its features are: a tabbed chat window and single window modes; support
for group chat (with Multi-User Chat protocol), invitation, chat to group chat
transformation; audio and video conferences; file transfer; TLS, GPG and
end-to-end encryption support; XML console.")
    (license license:gpl3)))

(define-public prosody
  (package
    (name "prosody")
    (version "0.9.10")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://prosody.im/downloads/source/"
                                  "prosody-" version ".tar.gz"))
              (sha256
               (base32
                "0bv6s5c0iizz015hh1lxlwlw1iwvisywajm2rcrbdfyrskzfwdj8"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; no "check" target
       #:configure-flags (list "--no-example-certs")
       #:modules ((ice-9 match)
                  (srfi srfi-1)
                  (guix build gnu-build-system)
                  (guix build utils))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-configure-script
           (lambda _
             ;; The configure script aborts when it encounters unexpected
             ;; arguments.  Make it more tolerant.
             (substitute* "configure"
               (("exit 1") ""))
             #t))
         (add-after 'install 'wrap-programs
           (lambda* (#:key inputs outputs #:allow-other-keys)
             ;; Make sure all executables in "bin" find the required Lua
             ;; modules at runtime.
             (let* ((out   (assoc-ref outputs "out"))
                    (bin   (string-append out "/bin/"))
                    (deps  (delete #f (map (match-lambda
                                             ((label . directory)
                                              (if (string-prefix? "lua" label)
                                                  directory #f)))
                                           inputs)))
                    (path  (string-join
                            (map (lambda (path)
                                   (string-append path "/share/lua/5.1/?.lua;"
                                                  path "/share/lua/5.1/?/?.lua"))
                                 (cons out deps))
                            ";"))
                    (cpath (string-join
                            (map (lambda (path)
                                   (string-append path "/lib/lua/5.1/?.so;"
                                                  path "/lib/lua/5.1/?/?.so"))
                                 (cons out deps))
                            ";")))
               (for-each (lambda (file)
                           (wrap-program file
                             `("LUA_PATH"  ";" = (,path))
                             `("LUA_CPATH" ";" = (,cpath))))
                         (find-files bin ".*"))
               #t))))))
    (inputs
     `(("libidn" ,libidn)
       ("openssl" ,openssl)
       ("lua" ,lua-5.1)
       ("lua5.1-expat" ,lua5.1-expat)
       ("lua5.1-socket" ,lua5.1-socket)
       ("lua5.1-filesystem" ,lua5.1-filesystem)
       ;; See <https://prosody.im/doc/depends#luasec>.
       ("lua5.1-sec" ,lua5.1-sec-0.5)))
    (home-page "https://prosody.im/")
    (synopsis "Jabber (XMPP) server")
    (description "Prosody is a modern XMPP communication server.  It aims to
be easy to set up and configure, and efficient with system resources.
Additionally, for developers it aims to be easy to extend and give a flexible
system on which to rapidly develop added functionality, or prototype new
protocols.")
    (license license:x11)))

(define-public libtoxcore
  (let ((revision "1")
        (commit "755f084e8720b349026c85afbad58954cb7ff1d4"))
    (package
      (name "libtoxcore")
      (version (string-append "0.0.0" "-"
                              revision "."(string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/irungentoo/toxcore.git")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "0ap1gvlyihnfivv235dbrgsxsiiz70bhlmlr5gn1027w3h5kqz8w"))))
      (build-system gnu-build-system)
      (native-inputs
       `(("autoconf" ,autoconf)
         ("automake" ,automake)
         ("libtool" ,libtool)
         ;; TODO: Add when test suite is capable of passing.
         ;; ("check" ,check)
         ("pkg-config" ,pkg-config)))
      (inputs
       `(("libsodium" ,libsodium)
         ("opus" ,opus)
         ("libvpx" ,libvpx)))
      (arguments
       `(#:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'autoconf
             (lambda _
               (zero? (system* "autoreconf" "-vfi")))))
         #:tests? #f)) ; FIXME: Testsuite fails, reasons unspecific.
      (synopsis "Library for the Tox encrypted messenger protocol")
      (description
       "C library implementation of the Tox encrypted messenger protocol.")
      (license license:gpl3+)
      (home-page "https://tox.chat"))))

;; Some tox clients move to c-toxcore, which seems to be where all the
;; recent development happens. It is run by the same developers as toxcore,
;; forked into a group namespace.
(define-public c-toxcore
  (package
    (name "c-toxcore")
    (version "0.1.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/TokTok/c-toxcore/archive/v"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0dybpz44pi0zm8djppjna0r8yh5wvl3l885dv2f1wp5366bk59n3"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)
       ("check" ,check)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("libsodium" ,libsodium)
       ("opus" ,opus)
       ("libvpx" ,libvpx)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'autoconf
           ;; The tarball source is not bootstrapped.
           (lambda _
             (zero? (system* "autoreconf" "-vfi")))))
       #:tests? #f)) ; FIXME: Testsuite fails, needs internet connection.
    (synopsis "Library for the Tox encrypted messenger protocol")
    (description
     "Official fork of the C library implementation of the Tox
encrypted messenger protocol.")
    (license license:gpl3+)
    (home-page "https://tox.chat")))

(define-public utox
  (package
   (name "utox")
   (version "0.11.0")
   (source
    (origin
     (method url-fetch)
     (uri (string-append "https://github.com/uTox/uTox/archive/v"
                         version ".tar.gz"))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32
       "15s4iwjk1s0kihjqn0f07c9618clbphpr827mds3xddkiwnjz37v"))))
   (build-system cmake-build-system)
   (arguments
    '(#:tests? #f ; No test phase.
      #:phases
      (modify-phases %standard-phases
        (add-after 'unpack 'fix-freetype-include
          (lambda _
            (substitute* "CMakeLists.txt"
              (("/usr/include/freetype2")
               (string-append (assoc-ref %build-inputs "freetype")
                              "/include/freetype2")))))
        (add-before 'install 'patch-cmake-find-utox
          (lambda _
            (substitute* "../build/cmake_install.cmake"
              (("/uTox-0.11.0/utox")
               "/build/utox")))))))
   (inputs
    ;; TODO: Fix the file chooser dialog; which input does it need?
    `(("dbus" ,dbus)
      ("filteraudio" ,filteraudio)
      ("fontconfig" ,fontconfig)
      ("freetype" ,freetype)
      ("libsodium" ,libsodium)
      ("c-toxcore" ,c-toxcore)
      ("libvpx" ,libvpx)
      ("libx11" ,libx11)
      ("libxext" ,libxext)
      ("libxrender" ,libxrender)
      ("openal" ,openal)
      ("v4l-utils" ,v4l-utils)))
   (synopsis "Lightweight Tox client")
   (description
    "Utox is a lightweight Tox client.  Tox is a distributed and secure
instant messenger with audio and video chat capabilities.")
   (home-page "http://utox.org/")
   (license license:gpl3)))

(define-public qtox
  (package
    (name "qtox")
    (version "1.5.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/qTox/qTox/archive/v"
                           version ".tar.gz"))
       (sha256
        (base32 "0y15mc39x54k1kz36cw9412kl1p1p6nzlx97gagv4gg3vybfhbjv"))
       (file-name (string-append name "-" version ".tar.gz"))))
    (inputs
     `(("ffmpeg" ,ffmpeg)
       ("glib" ,glib)
       ("gtk+" ,gtk+-2)
       ("libsodium" ,libsodium)
       ("libtoxcore" ,libtoxcore)
       ("libvpx" ,libvpx)
       ("libxscrnsaver" ,libxscrnsaver)
       ("libx11" ,libx11)
       ("openal" ,openal)
       ("qrencode" ,qrencode)
       ("qt" ,qt)
       ("sqlcipher" ,sqlcipher)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("qmake" ,qt)))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-reproducibility-issues
           (lambda _
             (substitute* "src/main.cpp"
               (("__DATE__") "\"\"")
               (("__TIME__") "\"\"")
               (("TIMESTAMP") "\"\""))
             #t))
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (zero?
              (system* "qmake"
                       (string-append "PREFIX="
                                      (assoc-ref outputs "out")))))))))
    (home-page "https://qtox.github.io/")
    (synopsis "Tox chat client using Qt")
    (description "qTox is a Tox client that follows the Tox design
guidelines.  It provides an easy to use application that allows you to
connect with friends and family without anyone else listening in.")
    (license license:gpl3+)))

(define-public pybitmessage
  (package
    (name "pybitmessage")
    (version "0.6.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/Bitmessage/"
                           "PyBitmessage/archive/v" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1ffj7raxpp277kphj98190fxrwfx16vmbspk7k3azg3bh5f5idnf"))))
    (inputs
     `(("python" ,python-2)
       ("python:tk" ,python-2 "tk")
       ("openssl" ,openssl)
       ("sqlite" ,sqlite)
       ("qt" ,qt-4)
       ("python2-pyqt-4" ,python2-pyqt-4)
       ("python2-sip" ,python2-sip)
       ("python2-pysqlite" ,python2-pysqlite)
       ("python2-pyopenssl" ,python2-pyopenssl)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (build-system gnu-build-system)
    (arguments
     `(#:imported-modules ((guix build python-build-system)
                           ,@%gnu-build-system-modules)
       #:make-flags (list (string-append "PREFIX="
                                         (assoc-ref %outputs "out")))
       #:tests? #f ; no test target
       #:phases
       (modify-phases %standard-phases
         (add-before 'build 'fix-makefile
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "Makefile"
               (("mkdir -p \\$\\{DESTDIR\\}/usr") "")
               (("/usr/local") "")
               (("/usr") "")
               (("#!/bin/sh") (string-append "#!" (which "bash")))
               (("python2") (which "python"))
               (("/opt/openssl-compat-bitcoin/lib/")
                (string-append (assoc-ref inputs "openssl") "/lib/")))
             #t))
         (add-after 'unpack 'fix-unmatched-python-shebangs
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "src/bitmessagemain.py"
               (("#!/usr/bin/env python2.7")
                (string-append "#!" (which "python"))))
             (substitute* "src/bitmessagecli.py"
               (("#!/usr/bin/env python2.7.x")
                (string-append "#!" (which "python"))))
             #t))
         (add-after 'unpack 'fix-depends
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "src/depends.py"
               (("libcrypto.so")
                (string-append (assoc-ref inputs "openssl")
                               "/lib/libcrypto.so")))
             #t))
         (add-after 'unpack 'fix-local-files-in-paths
           (lambda* (#:key outputs #:allow-other-keys)
             (substitute* "src/proofofwork.py"
               (("bitmsghash.so")
                (string-append (assoc-ref outputs "out")
                               "/lib/bitmsghash.so")))
             #t))
         (add-after 'unpack 'fix-pyelliptic
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "src/pyelliptic/openssl.py"
               (("libcrypto.so")
                (string-append (assoc-ref inputs "openssl")
                               "/lib/libcrypto.so"))
               (("libssl.so")
                (string-append (assoc-ref inputs "openssl")
                               "/lib/libssl.so")))
             #t))
         ;; XXX: Make does not build and install bitmsghash, do it
         ;; and place it in /lib.
         (add-before 'build 'build-and-install-bitmsghash
           (lambda* (#:key outputs #:allow-other-keys)
             (chdir "src/bitmsghash")
             (system* "make")
             (chdir "../..")
             (install-file "src/bitmsghash/bitmsghash.so"
                           (string-append (assoc-ref outputs "out") "/lib"))
             #t))
         (add-after 'install 'wrap
           (@@ (guix build python-build-system) wrap)))))
    (license license:expat)
    (description
     "Distributed and trustless peer-to-peer communications protocol
for sending encrypted messages to one person or many subscribers.")
    (synopsis "Distributed peer-to-peer communication")
    (home-page "https://bitmessage.org/")))

(define-public ytalk
  (package
    (name "ytalk")
    (version "3.3.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "ftp://ftp.ourproject.org/pub/ytalk/ytalk-"
                           version  ".tar.gz"))
       (sha256
        (base32
         "1d3jhnj8rgzxyxjwfa22vh45qwzjvxw1qh8fz6b7nfkj3zvk9jvf"))))
    (build-system gnu-build-system)
    (inputs
     `(("ncurses" ,ncurses)))
    (home-page "http://ytalk.ourproject.org")
    (synopsis "Multi-user chat program")
    (description "Ytalk is a replacement for the BSD talk program.  Its main
advantage is the ability to communicate with any arbitrary number of users at
once.  It supports both talk protocols (\"talk\" and \"ntalk\") and can communicate
with several different talk daemons at the same time.")
    (license license:gpl2+)))

(define-public gloox
  (package
    (name "gloox")
    (version "1.0.17")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://camaya.net/download/gloox-"
                           version ".tar.bz2"))
       (sha256
        (base32
         "09c01jr5nrm7f1ly42wg0pqqscmp48pv8y2fjx1vwbavjxdq59ri"))))
    (build-system gnu-build-system)
    (inputs
     `(("libidn" ,libidn)
       ("gnutls" ,gnutls)
       ("zlib" ,zlib)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (synopsis "Portable high-level Jabber/XMPP library for C++")
    (description
     "gloox is a full-featured Jabber/XMPP client library,
written in ANSI C++.  It makes writing spec-compliant clients easy
and allows for hassle-free integration of Jabber/XMPP functionality
into existing applications.")
    (home-page "https://camaya.net/gloox")
    (license license:gpl3)))

(define-public perl-net-psyc
  (package
    (name "perl-net-psyc")
    (version "1.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://perlpsyc.psyc.eu/"
                           "perlpsyc-" version ".zip"))
       (file-name (string-append name "-" version ".zip"))
       (sha256
        (base32
         "1lw6807qrbmvzbrjn1rna1dhir2k70xpcjvyjn45y35hav333a42"))
       ;; psycmp3 currently depends on MP3::List and rxaudio (shareware),
       ;; we can add it back when this is no longer the case.
       (snippet '(delete-file "contrib/psycmp3"))))
    (build-system perl-build-system)
    (inputs
     `(("perl-curses" ,perl-curses)
       ("perl-io-socket-ssl" ,perl-io-socket-ssl)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (delete 'configure) ; No configure script
         ;; There is a Makefile, but it does not install everything
         ;; (leaves out psycion) and says
         ;; "# Just to give you a rough idea". XXX: Fix it upstream.
         (replace 'build
           (lambda _
             (zero? (system* "make" "manuals"))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (doc (string-append out "/share/doc/perl-net-psyc"))
                    (man1 (string-append out "/share/man/man1"))
                    (man3 (string-append out "/share/man/man3"))
                    (bin (string-append out "/bin"))
                    (libpsyc (string-append out "/lib/psyc/ion"))
                    (libperl (string-append out "/lib/perl5/site_perl/"
                                            ,(package-version perl))))

               (copy-recursively "lib/perl5" libperl)
               (copy-recursively "lib/psycion" libpsyc)
               (copy-recursively "bin" bin)
               (install-file "cgi/psycpager" (string-append doc "/cgi"))
               (copy-recursively "contrib" (string-append doc "/contrib"))
               (copy-recursively "hooks" (string-append doc "/hooks"))
               (copy-recursively "sdj" (string-append doc "/sdj"))
               (install-file "README.txt" doc)
               (install-file "TODO.txt" doc)
               (copy-recursively "share/man/man1" man1)
               (copy-recursively "share/man/man3" man3)
               #t)))
         (add-after 'install 'wrap-programs
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Make sure all executables in "bin" find the Perl modules
             ;; provided by this package at runtime.
             (let* ((out  (assoc-ref outputs "out"))
                    (bin  (string-append out "/bin/"))
                    (path (getenv "PERL5LIB")))
               (for-each (lambda (file)
                           (wrap-program file
                             `("PERL5LIB" ":" prefix (,path))))
                         (find-files bin "\\.*$"))
               #t))))))
    (description
     "@code{Net::PSYC} with support for TCP, UDP, Event.pm, @code{IO::Select} and
Gtk2 event loops.  This package includes 12 applications and additional scripts:
psycion (a @uref{http://about.psyc.eu,PSYC} chat client), remotor (a control console
for @uref{https://torproject.org,tor} router) and many more.")
    (synopsis "Perl implementation of PSYC protocol")
    (home-page "http://perlpsyc.psyc.eu/")
    (license (list license:gpl2
                   (package-license perl)
                   ;; contrib/irssi-psyc.pl:
                   license:public-domain
                   ;; bin/psycplay states AGPL with no version:
                   license:agpl3+))))

(define-public libpsyc
  (package
    (name "libpsyc")
    (version "20160913")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.psyced.org/files/"
                                  name "-" version ".tar.xz"))
              (sha256
               (base32
                "14q89fxap05ajkfn20rnhc6b1h4i3i2adyr7y6hs5zqwb2lcmc1p"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("perl" ,perl)
       ("netcat" ,netcat)
       ("procps" ,procps)))
    (arguments
     `(#:make-flags
       (list "CC=gcc"
             (string-append "PREFIX=" (assoc-ref %outputs "out")))
       #:phases
       (modify-phases %standard-phases
         ;; The rust bindings are the only ones in use, the lpc bindings
         ;; are in psyclpc.  The other bindings are not used by anything,
         ;; the chances are high that the bindings do not even work,
         ;; therefore we do not include them.
         ;; TODO: Get a cargo build system in Guix.
         (delete 'configure)))) ; no configure script
    (home-page "http://about.psyc.eu/libpsyc")
    (description
     "@code{libpsyc} is a PSYC library in C which implements
core aspects of PSYC, useful for all kinds of clients and servers
including psyced.")
    (synopsis "PSYC library in C")
    (license license:agpl3+)))

;; This commit removes the historic bundled pcre and makes psyclpc reproducible.
(define-public psyclpc
  (let* ((commit "61cf9aa81297085e5c40170fd01221c752f8deba")
         (revision "2"))
  (package
    (name "psyclpc")
    (version (string-append "20160821-" revision "." (string-take commit 7)))
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "git://git.psyced.org/git/psyclpc")
                    (commit commit)))
              (file-name (string-append name "-" version "-checkout"))
              (sha256
               (base32
                "1viwqymbhn3cwvx0zl58rlzl5gw47zxn0ldg2nbi55ghm5zxl1z5"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; There are no tests/checks.
       #:configure-flags
       ;; If you have questions about this part, look at
       ;; "src/settings/psyced" and the ebuild.
       (list
        "--enable-use-tls=yes"
        "--enable-use-mccp" ; Mud Client Compression Protocol, leave this enabled.
        (string-append "--prefix="
                       (assoc-ref %outputs "out"))
        ;; src/Makefile: Set MUD_LIB to the directory which contains
        ;; the mud data. defaults to MUD_LIB = @libdir@
        (string-append "--libdir="
                       (assoc-ref %outputs "out")
                       "/opt/psyced/world")
        (string-append "--bindir="
                       (assoc-ref %outputs "out")
                       "/opt/psyced/bin")
        ;; src/Makefile: Set ERQ_DIR to directory which contains the
        ;; stuff which ERQ can execute (hopefully) savely.  Was formerly
        ;; defined in config.h. defaults to ERQ_DIR= @libexecdir@
        (string-append "--libexecdir="
                       (assoc-ref %outputs "out")
                       "/opt/psyced/run"))
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'chdir-to-src
           ;; We need to pass this as env variables
           ;; and manually change the directory.
           (lambda _
             (chdir "src")
             (setenv "CONFIG_SHELL" (which "sh"))
             (setenv "SHELL" (which "sh"))
             #t)))
       #:make-flags (list "install-all")))
    (inputs
     `(("zlib" ,zlib)
       ("openssl" ,openssl)
       ("pcre" ,pcre)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("bison" ,bison)
       ("gettext" ,gettext-minimal)
       ("help2man" ,help2man)
       ("autoconf" ,autoconf)
       ("automake" ,automake)))
    (home-page "http://lpc.psyc.eu/")
    (synopsis "psycLPC is a multi-user network server programming language")
    (description
     "LPC is a bytecode language, invented to specifically implement
multi user virtual environments on the internet.  This technology is used for
MUDs and also the psyced implementation of the Protocol for SYnchronous
Conferencing (PSYC).  psycLPC is a fork of LDMud with some new features and
many bug fixes.")
    (license license:gpl2))))

;;; messaging.scm ends here
