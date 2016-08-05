;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Taylan Ulrich Bayirli/Kammer <taylanbayirli@gmail.com>
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
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

(define-module (gnu packages bittorrent)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system python)
  #:use-module (guix build-system glib-or-gtk)
  #:use-module ((guix licenses) #:prefix l:)
  #:use-module (gnu packages adns)
  #:use-module (gnu packages check)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages cyrus-sasl)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages file)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages libevent)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages nettle)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages ssh)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages xml))

(define-public transmission
  (package
    (name "transmission")
    (version "2.84")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://transmission.cachefly.net/transmission-"
                    version ".tar.xz"))
              (sha256
               (base32
                "1sxr1magqb5s26yvr5yhs1f7bmir8gl09niafg64lhgfnhv1kz59"))))
    (build-system glib-or-gtk-build-system)
    (outputs '("out"                      ; library and command-line interface
               "gui"))                    ; graphical user interface
    (arguments
     '(#:glib-or-gtk-wrap-excluded-outputs '("out")
       #:phases (alist-cons-after
                 'install 'move-gui
                 (lambda* (#:key outputs #:allow-other-keys)
                   ;; Move the GUI to its own output, so that "out" doesn't
                   ;; depend on GTK+.
                   (let ((out (assoc-ref outputs "out"))
                         (gui (assoc-ref outputs "gui")))
                     (mkdir-p (string-append gui "/bin"))
                     (rename-file (string-append out "/bin/transmission-gtk")
                                  (string-append gui
                                                 "/bin/transmission-gtk"))

                     ;; Move the '.desktop' file as well.
                     (mkdir (string-append gui "/share"))
                     (rename-file (string-append out "/share/applications")
                                  (string-append gui "/share/applications"))))
                 %standard-phases)))
    (inputs
     `(("inotify-tools" ,inotify-tools)
       ("libevent" ,libevent)
       ("curl" ,curl)
       ("openssl" ,openssl)
       ("file" ,file)
       ("zlib" ,zlib)
       ("gtk+" ,gtk+)))
    (native-inputs
     `(("intltool" ,intltool)
       ("pkg-config" ,pkg-config)))
    (home-page "http://www.transmissionbt.com/")
    (synopsis "Fast and easy BitTorrent client")
    (description
     "Transmission is a BitTorrent client that comes with graphical,
textual, and Web user interfaces.  Transmission also has a daemon for
unattended operations.  It supports local peer discovery, full encryption,
DHT, µTP, PEX and Magnet Links.")

    ;; COPYING reads:
    ;;
    ;;     Transmission can be redistributed and/or modified under the terms of
    ;; the GNU GPLv2 (http://www.gnu.org/licenses/license-list.html#GPLv2),
    ;; the GNU GPLv3 (http://www.gnu.org/licenses/license-list.html#GNUGPLv3),
    ;; or any future license endorsed by Mnemosyne LLC.
    ;;
    ;; A few files files carry an MIT/X11 license header.
    (license l:gpl3+)))

(define-public libtorrent
  (package
    (name "libtorrent")
    (version "0.13.6")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://rtorrent.net/downloads/libtorrent-"
                    version ".tar.gz"))
              (sha256
               (base32
                "012s1nwcvz5m5r4d2z9klgy2n34kpgn9kgwgzxm97zgdjs6a0f18"))))
    (build-system gnu-build-system)
    (inputs `(("openssl" ,openssl)
              ("zlib" ,zlib)))
    (native-inputs `(("pkg-config" ,pkg-config)
                     ("cppunit" ,cppunit)))
    (synopsis "BitTorrent library of rtorrent")
    (description
     "LibTorrent is a BitTorrent library used by and developed in parallel
with the BitTorrent client rtorrent.  It is written in C++ with emphasis on
speed and efficiency.")
    (home-page "https://github.com/rakshasa/libtorrent")
    (license l:gpl2+)))

(define-public rtorrent
  (package
    (name "rtorrent")
    (version "0.9.6")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://rtorrent.net/downloads/rtorrent-"
                    version ".tar.gz"))
              (sha256
               (base32
                "03jvzw9pi2mhcm913h8qg0qw9gwjqc6lhwynb1yz1y163x7w4s8y"))))
    (build-system gnu-build-system)
    (inputs `(("libtorrent" ,libtorrent)
              ("ncurses" ,ncurses)
              ("curl" ,curl)
              ("cyrus-sasl" ,cyrus-sasl)
              ("openssl" ,openssl)
              ("zlib" ,zlib)))
    (native-inputs `(("pkg-config" ,pkg-config)
                     ("cppunit" ,cppunit)))
    (synopsis "BitTorrent client with ncurses interface")
    (description
     "rTorrent is a BitTorrent client with an ncurses interface.  It supports
full encryption, DHT, PEX, and Magnet Links.  It can also be controlled via
XML-RPC over SCGI.")
    (home-page "https://github.com/rakshasa/rtorrent")
    (license l:gpl2+)))

(define-public transmission-remote-cli
  (package
    (name "transmission-remote-cli")
    (version "1.7.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/fagga/"
                                  "transmission-remote-cli/archive/v"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1y0hkpcjf6jw9xig8yf484hbhy63nip0pkchx401yxj81m25l4z9"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2 ; only supports Python 2
       #:tests? #f ; no test suite
       #:phases (modify-phases %standard-phases
                  ;; The software is just a Python script that must be
                  ;; copied into place.
                  (delete 'build)
                  (replace 'install
                    (lambda* (#:key outputs #:allow-other-keys)
                      (let* ((out (assoc-ref outputs "out"))
                             (bin (string-append out "/bin"))
                             (man (string-append out "/share/man/man1"))
                             ;; FIXME install zsh completions
                             (completions (string-append out "/etc/bash_completion.d")))
                        (install-file "transmission-remote-cli" bin)
                        (install-file "transmission-remote-cli.1" man)
                        (install-file
                          (string-append
                            "completion/bash/"
                            "transmission-remote-cli-bash-completion.sh")
                          completions)))))))
    (synopsis "Console client for the Transmission BitTorrent daemon")
    (description "Transmission-remote-cli is a console client, with a curses
interface, for the Transmission BitTorrent daemon.")
    (home-page "https://github.com/fagga/transmission-remote-cli")
    (license l:gpl3+)))

(define-public aria2
  (package
    (name "aria2")
    (version "1.25.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/tatsuhiro-t/aria2/"
                                  "releases/download/release-" version "/"
                                  name "-" version ".tar.xz"))
              (sha256
               (base32
                "0d8drwc5m5ps4bw63iq2gng36gyc2vadzixbynk1dj6gfr6fp2gz"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags '("--enable-libaria2")
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'delete-socket-tests
           (lambda _
             (substitute* "test/LpdMessageDispatcherTest.cc"
               (("CPPUNIT_TEST_SUITE_REGISTRATION\\(LpdMessageDispatcherTest\\);" text)
                (string-append "// " text)))
             (substitute* "test/LpdMessageReceiverTest.cc"
               (("CPPUNIT_TEST_SUITE_REGISTRATION\\(LpdMessageReceiverTest\\);" text)
                (string-append "// " text))))))))
    (native-inputs
     `(("cppunit" ,cppunit) ; for the tests
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("c-ares" ,c-ares)
       ("gnutls" ,gnutls)
       ("gmp" ,gmp)
       ("libssh2" ,libssh2)
       ("libxml2" ,libxml2)
       ("nettle" ,nettle)
       ("sqlite" ,sqlite)
       ("zlib" ,zlib)))
    (home-page "https://aria2.github.io/")
    (synopsis "Utility for parallel downloading files")
    (description
      "Aria2 is a lightweight, multi-protocol & multi-source command-line
download utility.  It supports HTTP/HTTPS, FTP, SFTP, BitTorrent and Metalink.
Aria2 can be manipulated via built-in JSON-RPC and XML-RPC interfaces.")
    (license l:gpl2+)))
