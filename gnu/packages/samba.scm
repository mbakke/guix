;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Adonay "adfeno" Felipe Nogueira <https://libreplanet.org/wiki/User:Adfeno> <adfeno@openmailbox.org>
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

(define-module (gnu packages samba)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix licenses)
  #:use-module (gnu packages acl)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages cups)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages popt)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages openldap)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages python))

(define-public iniparser
  (package
    (name "iniparser")
    (version "4.0")
    (source (origin
             (method url-fetch)
             (uri (string-append "https://github.com/ndevilla/iniparser/archive/v"
                                 version ".tar.gz"))
             (file-name (string-append name "-" version ".tar.gz"))
             (sha256
              (base32
               "1flj7srvh2hp9ls96qz922bklyhw7f27mmn23b16839zpdjddfz0"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (substitute* '("Makefile" "test/Makefile")
               (("/usr/lib")
                (string-append (assoc-ref outputs "out") "/lib"))
               (("\\?= gcc") "= gcc"))))
         (replace 'build
           (lambda _
             (and (zero? (system* "make" "libiniparser.so"))
                         (symlink "libiniparser.so.0" "libiniparser.so"))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out  (assoc-ref outputs "out"))
                    (lib  (string-append out "/lib"))
                    (inc  (string-append out "/include"))
                    (doc  (string-append out "/share/doc"))
                    (html (string-append doc "/html")))
               (define (copy dir)
                 (lambda (file)
                   (copy-file file
                              (string-append dir "/"
                                             (basename file)))))
               (mkdir-p lib)
               (for-each (copy lib)
                         (find-files "." "^lib.*\\.(so\\.|a)"))
               (with-directory-excursion lib
                 (symlink "libiniparser.so.0" "libiniparser.so"))
               (mkdir-p inc)
               (for-each (copy inc)
                         (find-files "src" "\\.h$"))
               (mkdir-p html)
               (for-each (copy html)
                         (find-files "html" ".*"))
               (for-each (copy doc)
                         '("AUTHORS" "INSTALL" "LICENSE" "README.md"))))))))
    (home-page "http://ndevilla.free.fr/iniparser")
    (synopsis "Standalone ini file parsing library")
    (description
     "iniparser is a free stand-alone `ini' file parsing library (Windows
configuration files).  It is written in portable ANSI C and should compile
anywhere.")
    (license x11)))

(define-public samba
  (package
    (name "samba")
    (version "4.5.3")
    (source (origin
             (method url-fetch)
             (uri (string-append "https://download.samba.org/pub/samba/stable/"
                                 "samba-" version ".tar.gz"))
             (sha256
              (base32
               "1jif95684swssqwp9v3i2r08cn3r2iddf6ly68db4wmvl5ac8vgh"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           ;; samba uses a custom configuration script that runs waf.
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out    (assoc-ref outputs "out"))
                    (libdir (string-append out "/lib")))
               (zero? (system*
                       "./configure"
                       "--enable-fhs"
                       ;; XXX: heimdal not packaged.
                       "--bundled-libraries=com_err"
                       (string-append "--prefix=" out)
		       "--sysconfdir=/etc"
                       ;; Install public and private libraries into
                       ;; a single directory to avoid RPATH issues.
                       (string-append "--libdir=" libdir)
                       (string-append "--with-privatelibdir=" libdir))))))
	 (add-before 'install 'disable-etc-samba-directory-creation
           (lambda _
             (substitute* "dynconfig/wscript"
               (("bld\\.INSTALL_DIRS\\(\"\",[[:blank:]]{1,}\"\\$\\{CONFIGDIR\\}[[:blank:]]{1,}")
                "bld.INSTALL_DIRS(\"\", \"")))))
       ;; XXX: The test infrastructure attempts to set password with
       ;; smbpasswd, which fails with "smbpasswd -L can only be used by root."
       ;; So disable tests until there's a workaround.
       #:tests? #f))
    (inputs                                   ; TODO: Add missing dependencies
     `(("acl" ,acl)
       ("cups" ,cups)
       ;; ("gamin" ,gamin)
       ("gnutls" ,gnutls)
       ("iniparser" ,iniparser)
       ("libaio" ,libaio)
       ("ldb" ,ldb)
       ("linux-pam" ,linux-pam)
       ("openldap" ,openldap)
       ("popt" ,popt)
       ("readline" ,readline)
       ("talloc" ,talloc)
       ("tevent" ,tevent)
       ("tdb" ,tdb)))
    (native-inputs
     `(("perl" ,perl)
       ("pkg-config" ,pkg-config)
       ("python" ,python-2))) ; incompatible with Python 3
    (home-page "https://www.samba.org/")
    (synopsis
     "The standard Windows interoperability suite of programs for GNU and Unix")
    (description
     "Since 1992, Samba has provided secure, stable and fast file and print
services for all clients using the SMB/CIFS protocol, such as all versions of
DOS and Windows, OS/2, GNU/Linux and many others.

Samba is an important component to seamlessly integrate Linux/Unix Servers and
Desktops into Active Directory environments using the winbind daemon.")
    (license gpl3+)))

(define-public talloc
  (package
    (name "talloc")
    (version "2.1.8")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://www.samba.org/ftp/talloc/talloc-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0c3ihyb0jd8mhvi7gg2mr5w1zl2habx6jlkbyxzyckad2q8lkl92"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             ;; test_magic_differs.sh has syntax error, and is not in the right
             ;; place where wscript expected.
             ;; Skip the test.
             (substitute* "wscript"
               (("magic_ret = .*") "magic_ret = 0\n"))
             ;; talloc uses a custom configuration script that runs a
             ;; python script called 'waf'.
             (setenv "CONFIG_SHELL" (which "sh"))
             (let ((out (assoc-ref outputs "out")))
               (zero? (system* "./configure"
                               (string-append "--prefix=" out)))))))))
    (inputs
     `(("python" ,python-2)))
    (home-page "http://talloc.samba.org")
    (synopsis "Hierarchical, reference counted memory pool system")
    (description
     "Talloc is a hierarchical, reference counted memory pool system with
destructors.  It is the core memory allocator used in Samba.")
    (license gpl3+))) ;; The bundled "replace" library uses LGPL3.

(define-public tevent
  (package
    (name "tevent")
    (version "0.9.31")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://www.samba.org/ftp/tevent/tevent-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1z1bij9gccps34q8zakr1k7k3gpqs25jas20x1hch16qd8jz44sa"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           ;; tevent uses a custom configuration script that runs waf.
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (zero? (system* "./configure"
                               (string-append "--prefix=" out)
                               "--bundled-libraries=NONE"))))))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python" ,python-2)))
    (propagated-inputs
     `(("talloc" ,talloc))) ; required by tevent.pc
    (synopsis "Event system library")
    (home-page "https://tevent.samba.org/")
    (description
     "Tevent is an event system based on the talloc memory management library.
It is the core event system used in Samba.  The low level tevent has support for
many event types, including timers, signals, and the classic file descriptor events.")
    (license lgpl3+)))

(define-public ldb
  (package
    (name "ldb")
    (version "1.1.27")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://www.samba.org/ftp/ldb/ldb-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1b1mkl5p8swb67s9aswavhzswlib34hpgsv66zgns009paf2df6d"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           ;; ldb use a custom configuration script that runs waf.
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (zero? (system* "./configure"
                               (string-append "--prefix=" out)
                               (string-append "--with-modulesdir=" out
                                              "/lib/ldb/modules")
                               "--bundled-libraries=NONE"))))))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python" ,python-2)))
    (propagated-inputs
     ;; ldb.pc refers to all these.
     `(("talloc" ,talloc)
       ("tdb" ,tdb)))
    (inputs
     `(("popt" ,popt)
       ("tevent" ,tevent)))
    (synopsis "LDAP-like embedded database")
    (home-page "https://ldb.samba.org/")
    (description
     "Ldb is a LDAP-like embedded database built on top of TDB.  What ldb does
is provide a fast database with an LDAP-like API designed to be used within an
application.  In some ways it can be seen as a intermediate solution between
key-value pair databases and a real LDAP database.")
    (license lgpl3+)))

(define-public ppp
  (package
    (name "ppp")
    (version "2.4.7")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://www.samba.org/ftp/ppp/ppp-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0c7vrjxl52pdwi4ckrvfjr08b31lfpgwf3pp0cqy76a77vfs7q02"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ; no check target
       #:make-flags '("CC=gcc")
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'patch-Makefile
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((libc    (assoc-ref inputs "libc"))
                   (libpcap (assoc-ref inputs "libpcap")))
               (substitute* "pppd/Makefile.linux"
                 (("/usr/include/crypt\\.h")
                  (string-append libc "/include/crypt.h"))
                 (("/usr/include/pcap-bpf.h")
                  (string-append libpcap "/include/pcap-bpf.h")))))))))
    (inputs
     `(("libpcap" ,libpcap)))
    (synopsis "Implementation of the Point-to-Point Protocol")
    (home-page "https://ppp.samba.org/")
    (description
     "The Point-to-Point Protocol (PPP) provides a standard way to establish
a network connection over a serial link.  At present, this package supports IP
and IPV6 and the protocols layered above them, such as TCP and UDP.")
    ;; pppd, pppstats and pppdump are under BSD-style notices.
    ;; some of the pppd plugins are GPL'd.
    ;; chat is public domain.
    (license (list bsd-3 bsd-4 gpl2+ public-domain))))
