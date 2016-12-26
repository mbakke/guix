;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014 Ian Denhardt <ian@zenhack.net>
;;; Copyright © 2013, 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2015 David Thompson <davet@gnu.org>
;;; Copyright © 2015, 2016 Leo Famulari <leo@famulari.name>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 ng0 <ng0@we.make.ritual.n0.is>
;;; Copyright © 2016 Hartmut Goebel <h.goebel@crazy-compilers.com>
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

(define-module (gnu packages tls)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system perl)
  #:use-module (guix build-system python)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages libbsd)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages libidn)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages nettle)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages base))

(define-public libtasn1
  (package
    (name "libtasn1")
    (version "4.9")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/libtasn1/libtasn1-"
                          version ".tar.gz"))
      (sha256
       (base32
        "0869cp6jx7cajgv6cnddsh3vc7bimmdkdjn80y1jpb4iss7plvsg"))))
    (build-system gnu-build-system)
    (native-inputs `(("perl" ,perl)))
    (home-page "http://www.gnu.org/software/libtasn1/")
    (synopsis "ASN.1 library")
    (description
     "GNU libtasn1 is a library implementing the ASN.1 notation.  It is used
for transmitting machine-neutral encodings of data objects in computer
networking, allowing for formal validation of data according to some
specifications.")
    (license license:lgpl2.0+)))

(define-public asn1c
  (package
    (name "asn1c")
    (version "0.9.27")
    (source (origin
      (method url-fetch)
      (uri (string-append "https://lionet.info/soft/asn1c-"
                          version ".tar.gz"))
      (sha256
       (base32
        "17nvn2kzvlryasr9dzqg6gs27b9lvqpval0k31pb64bjqbhn8pq2"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("perl" ,perl)))
    (home-page "https://lionet.info/asn1c")
    (synopsis "ASN.1 to C compiler")
    (description "The ASN.1 to C compiler takes ASN.1 module
files and generates C++ compatible C source code.  That code can be
used to serialize the native C structures into compact and unambiguous
BER/XER/PER-based data files, and deserialize the files back.

Various ASN.1 based formats are widely used in the industry, such as to encode
the X.509 certificates employed in the HTTPS handshake, to exchange control
data between mobile phones and cellular networks, to car-to-car communication
in intelligent transportation networks.")
    (license license:bsd-2)))

(define-public p11-kit
  (package
    (name "p11-kit")
    (version "0.23.2")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://p11-glue.freedesktop.org/releases/p11-kit-"
                          version ".tar.gz"))
      (sha256
       (base32
        "1w7szm190phlkg7qx05ychlj2dbvkgkhx9gw6dx4d5rw62l6wwms"))
      (modules '((guix build utils))) ; for substitute*
      (snippet
        '(begin
           ;; Drop one test that fails, also when trying to compile manually.
           ;; Reported upstream at
           ;; https://bugs.freedesktop.org/show_bug.cgi?id=89027
           (substitute* "Makefile.in"
             (("test-module\\$\\(EXEEXT\\) ") ""))))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("libffi" ,libffi)
       ("libtasn1" ,libtasn1)))
    (arguments
     `(#:configure-flags '("--without-trust-paths")))
    (home-page "http://p11-glue.freedesktop.org/p11-kit.html")
    (synopsis "PKCS#11 library")
    (description
     "p11-kit provides a way to load and enumerate PKCS#11 modules.  It
provides a standard configuration setup for installing PKCS#11 modules
in such a way that they are discoverable.  It also solves problems with
coordinating the use of PKCS#11 by different components or libraries
living in the same process.")
    (license license:bsd-3)))

(define-public gnutls
  (package
    (name "gnutls")
    (version "3.5.4")
    (source (origin
             (method url-fetch)
             (uri
              ;; Note: Releases are no longer on ftp.gnu.org since the
              ;; schism (after version 3.1.5).
              (string-append "mirror://gnupg/gnutls/v"
                             (version-major+minor version)
                             "/gnutls-" version ".tar.xz"))
             (sha256
              (base32
               "1sx8p7v452s9m854r2c5pvcd1k15a3caiv5h35fhrxz0691h2f2f"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags
       (list (string-append "--with-guile-site-dir="
                            (assoc-ref %outputs "out")
                            "/share/guile/site/2.0")
             ;; GnuTLS doesn't consult any environment variables to specify
             ;; the location of the system-wide trust store.  Instead it has a
             ;; configure-time option.  Unless specified, its configure script
             ;; attempts to auto-detect the location by looking for common
             ;; places in the file system, none of which are present in our
             ;; chroot build environment.  If not found, then no default trust
             ;; store is used, so each program has to provide its own
             ;; fallback, and users have to configure each program
             ;; independently.  This seems suboptimal.
             "--with-default-trust-store-dir=/etc/ssl/certs"

             ;; FIXME: Temporarily disable p11-kit support since it is not
             ;; working on mips64el.
             "--without-p11-kit")

       #:phases (modify-phases %standard-phases
                  (add-after
                   'install 'move-doc
                   (lambda* (#:key outputs #:allow-other-keys)
                     ;; Copy the 4.1 MiB of section 3 man pages to "doc".
                     (let* ((out    (assoc-ref outputs "out"))
                            (doc    (assoc-ref outputs "doc"))
                            (mandir (string-append doc "/share/man/man3"))
                            (oldman (string-append out "/share/man/man3")))
                       (mkdir-p mandir)
                       (copy-recursively oldman mandir)
                       (delete-file-recursively oldman)
                       #t))))))
    (outputs '("out"                              ;4.4 MiB
               "debug"
               "doc"))                            ;4.1 MiB of man pages
    (native-inputs
     `(("net-tools" ,net-tools)
       ("pkg-config" ,pkg-config)
       ("which" ,which)))
    (inputs
     `(("guile" ,guile-2.0)
       ("perl" ,perl)))
    (propagated-inputs
     ;; These are all in the 'Requires.private' field of gnutls.pc.
     `(("libtasn1" ,libtasn1)
       ("libidn" ,libidn)
       ("nettle" ,nettle)
       ("zlib" ,zlib)))
    (home-page "https://www.gnu.org/software/gnutls/")
    (synopsis "Transport layer security library")
    (description
     "GnuTLS is a secure communications library implementing the SSL, TLS
and DTLS protocols.  It is provided in the form of a C library to support the
protocols, as well as to parse and write X.5009, PKCS 12, OpenPGP and other
required structures.")
    (license license:lgpl2.1+)
    (properties '((ftp-server . "ftp.gnutls.org")
                  (ftp-directory . "/gcrypt/gnutls")))))

(define-public openssl
  (package
   (name "openssl")
   (version "1.0.2j")
   (source (origin
             (method url-fetch)
             (uri (list (string-append "ftp://ftp.openssl.org/source/"
                                       name "-" version ".tar.gz")
                        (string-append "ftp://ftp.openssl.org/source/old/"
                                       (string-trim-right version char-set:letter)
                                       "/" name "-" version ".tar.gz")))
             (sha256
              (base32
               "0cf4ar97ijfc7mg35zdgpad6x8ivkdx9qii6mz35khi1ps9g5bz7"))
             (patches (search-patches "openssl-runpath.patch"
                                      "openssl-c-rehash-in.patch"))))
   (build-system gnu-build-system)
   (outputs '("out"
              "doc"                               ;1.5MiB of man3 pages
              "static"))                          ;6MiB of .a files
   (native-inputs `(("perl" ,perl)))
   (arguments
    `(#:disallowed-references (,perl)
      #:parallel-build? #f
      #:parallel-tests? #f
      #:test-target "test"

      ;; Changes to OpenSSL sometimes cause Perl to "sneak in" to the closure,
      ;; so we explicitly disallow it here.
      #:disallowed-references ,(list (canonical-package perl))
      #:phases
      (modify-phases %standard-phases
        (add-before
         'configure 'patch-Makefile.org
         (lambda* (#:key outputs #:allow-other-keys)
           ;; The default MANDIR is some unusual place.  Fix that.
           (let ((out (assoc-ref outputs "out")))
             (patch-makefile-SHELL "Makefile.org")
             (substitute* "Makefile.org"
               (("^MANDIR[[:blank:]]*=.*$")
                (string-append "MANDIR = " out "/share/man\n")))
             #t)))
        (replace
         'configure
         (lambda* (#:key outputs #:allow-other-keys)
           (let ((out (assoc-ref outputs "out")))
             (zero?
              (system* "./config"
                       "shared"                   ;build shared libraries
                       "--libdir=lib"

                       ;; The default for this catch-all directory is
                       ;; PREFIX/ssl.  Change that to something more
                       ;; conventional.
                       (string-append "--openssldir=" out
                                      "/share/openssl-" ,version)

                       (string-append "--prefix=" out)

                       ;; XXX FIXME: Work around a code generation bug in GCC
                       ;; 4.9.3 on ARM when compiled with -mfpu=neon.  See:
                       ;; <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66917>
                       ,@(if (and (not (%current-target-system))
                                  (string-prefix? "armhf" (%current-system)))
                             '("-mfpu=vfpv3")
                             '()))))))
        (add-after
         'install 'make-libraries-writable
         (lambda* (#:key outputs #:allow-other-keys)
           ;; Make libraries writable so that 'strip' does its job.
           (let ((out (assoc-ref outputs "out")))
             (for-each (lambda (file)
                         (chmod file #o644))
                       (find-files (string-append out "/lib")
                                   "\\.so"))
             #t)))
        (add-after 'install 'move-static-libraries
          (lambda* (#:key outputs #:allow-other-keys)
            ;; Move static libraries to the "static" output.
            (let* ((out    (assoc-ref outputs "out"))
                   (lib    (string-append out "/lib"))
                   (static (assoc-ref outputs "static"))
                   (slib   (string-append static "/lib")))
              (mkdir-p slib)
              (for-each (lambda (file)
                          (install-file file slib)
                          (delete-file file))
                        (find-files lib "\\.a$"))
              #t)))
        (add-after 'install 'move-man3-pages
          (lambda* (#:key outputs #:allow-other-keys)
            ;; Move section 3 man pages to "doc".
            (let* ((out    (assoc-ref outputs "out"))
                   (man3   (string-append out "/share/man/man3"))
                   (doc    (assoc-ref outputs "doc"))
                   (target (string-append doc "/share/man/man3")))
              (mkdir-p target)
              (for-each (lambda (file)
                          (rename-file file
                                       (string-append target "/"
                                                      (basename file))))
                        (find-files man3))
              (delete-file-recursively man3)
              #t)))
        (add-before
         'patch-source-shebangs 'patch-tests
         (lambda* (#:key inputs native-inputs #:allow-other-keys)
           (let ((bash (assoc-ref (or native-inputs inputs) "bash")))
             (substitute* (find-files "test" ".*")
               (("/bin/sh")
                (string-append bash "/bin/bash"))
               (("/bin/rm")
                "rm"))
             #t)))
        (add-after
         'install 'remove-miscellany
         (lambda* (#:key outputs #:allow-other-keys)
           ;; The 'misc' directory contains random undocumented shell and Perl
           ;; scripts.  Remove them to avoid retaining a reference on Perl.
           (let ((out (assoc-ref outputs "out")))
             (delete-file-recursively (string-append out "/share/openssl-"
                                                     ,version "/misc"))
             #t))))))
   (native-search-paths
    ;; FIXME: These two variables must designate a single file or directory
    ;; and are not actually "search paths."  In practice it works OK in user
    ;; profiles because there's always just one item that matches the
    ;; specification.
    (list (search-path-specification
           (variable "SSL_CERT_DIR")
           (files '("etc/ssl/certs")))
          (search-path-specification
           (variable "SSL_CERT_FILE")
           (files '("etc/ssl/certs/ca-certificates.crt")))))
   (synopsis "SSL/TLS implementation")
   (description
    "OpenSSL is an implementation of SSL/TLS.")
   (license license:openssl)
   (home-page "http://www.openssl.org/")))

(define-public openssl-next
  (package
    (inherit openssl)
    (name "openssl")
    (version "1.1.0c")
    (source (origin
             (method url-fetch)
             (uri (list (string-append "ftp://ftp.openssl.org/source/"
                                       name "-" version ".tar.gz")
                        (string-append "ftp://ftp.openssl.org/source/old/"
                                       (string-trim-right version char-set:letter)
                                       "/" name "-" version ".tar.gz")))
              (patches (search-patches "openssl-1.1.0-c-rehash-in.patch"))
              (sha256
               (base32
                "1xfn5ydl14myd9wgxm4nxy5a42cpp1g12ijf3g9m4mz0l90n8hzw"))))
    (outputs '("out"
               "doc"        ;1.3MiB of man3 pages
               "static"))   ; 5.5MiB of .a files
    (arguments
     (substitute-keyword-arguments (package-arguments openssl)
       ((#:phases phases)
        `(modify-phases ,phases
           (delete 'patch-tests)          ; These two phases are not needed by
           (delete 'patch-Makefile.org)   ; OpenSSL 1.1.0.

           ;; Override configure phase since -rpath is now a configure option.
           (replace 'configure
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out"))
                      (lib (string-append out "/lib")))
                 (zero?
                  (system* "./config"
                           "shared"                   ;build shared libraries
                           "--libdir=lib"

                           ;; The default for this catch-all directory is
                           ;; PREFIX/ssl.  Change that to something more
                           ;; conventional.
                           (string-append "--openssldir=" out
                                          "/share/openssl-" ,version)

                           (string-append "--prefix=" out)
                           (string-append "-Wl,-rpath," lib)

                           ;; XXX FIXME: Work around a code generation bug in GCC
                           ;; 4.9.3 on ARM when compiled with -mfpu=neon.  See:
                           ;; <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66917>
                           ,@(if (and (not (%current-target-system))
                                      (string-prefix? "armhf" (%current-system)))
                                 '("-mfpu=vfpv3")
                                 '()))))))

           ;; XXX: Duplicate this phase to make sure 'version' evaluates
           ;; in the current scope and not the inherited one.
           (replace 'remove-miscellany
             (lambda* (#:key outputs #:allow-other-keys)
               ;; The 'misc' directory contains random undocumented shell and Perl
               ;; scripts.  Remove them to avoid retaining a reference on Perl.
               (let ((out (assoc-ref outputs "out")))
                 (delete-file-recursively (string-append out "/share/openssl-"
                                                         ,version "/misc"))
                 #t)))))))))

(define-public libressl
  (package
    (name "libressl")
    (version "2.5.0")
    (source
     (origin
      (method url-fetch)
      (uri (string-append
             "http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-"
             version ".tar.gz"))
      (sha256
       (base32
        "1bkfvapi4z826slycmicvs7hwgk4l82gd8w6nqvznldbammvyll6"))))
    (build-system gnu-build-system)
    (native-search-paths
      ;; FIXME: These two variables must designate a single file or directory
      ;; and are not actually "search paths."  In practice it works OK in
      ;; user profiles because there's always just one item that matches the
      ;; specification.
     (list (search-path-specification
            (variable "SSL_CERT_DIR")
            (files '("etc/ssl/certs")))
           (search-path-specification
            (variable "SSL_CERT_FILE")
            (files '("etc/ssl/certs/ca-certificates.crt")))))
    (home-page "http://www.libressl.org/")
    (synopsis "SSL/TLS implementation")
    (description "LibreSSL is a version of the TLS/crypto stack forked
from OpenSSL in 2014, with the goals of modernizing the codebase, improving
security, and applying best practice development processes.")
    ;; Files taken from OpenSSL keep their license, others are under various
    ;; non-copyleft licenses.
    (license (list license:openssl
                   (license:non-copyleft
                     "file://COPYING"
                     "See COPYING in the distribution.")))))

(define-public python-acme
  (package
    (name "python-acme")
    (version "0.9.3")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "acme" version))
      (sha256
        (base32
         "16a02bb0apnk1bm68bcabdmmwd6rnvnjzanrmcb46bpbapwz3vx6"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'install 'docs
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (man (string-append out "/share/man/man1"))
                    (info (string-append out "/info")))
               (and (zero? (system* "make" "-C" "docs" "man" "info"))
                    (install-file "docs/_build/texinfo/acme-python.info" info)
                    (install-file "docs/_build/man/acme-python.1" man)
                    #t)))))))
    ;; TODO: Add optional inputs for testing.
    (native-inputs
     `(("python-mock" ,python-mock)
       ;; For documentation
       ("python-sphinx" ,python-sphinx)
       ("python-sphinxcontrib-programoutput" ,python-sphinxcontrib-programoutput)
       ("python-sphinx-rtd-theme" ,python-sphinx-rtd-theme)
       ("texinfo" ,texinfo)))
    (propagated-inputs
     `(("python-ndg-httpsclient" ,python-ndg-httpsclient)
       ("python-werkzeug" ,python-werkzeug)
       ("python-six" ,python-six)
       ("python-requests" ,python-requests)
       ("python-pytz" ,python-pytz)
       ("python-pyrfc3339" ,python-pyrfc3339)
       ("python-pyasn1" ,python-pyasn1)
       ("python-cryptography" ,python-cryptography)
       ("python-pyopenssl" ,python-pyopenssl)))
    (home-page "https://github.com/letsencrypt/letsencrypt")
    (synopsis "ACME protocol implementation in Python")
    (description "ACME protocol implementation in Python")
    (license license:asl2.0)))

(define-public python2-acme
  (package-with-python2 python-acme))

(define-public certbot
  (package
    (name "certbot")
    (version "0.9.3")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri name version))
              (sha256
               (base32
                "1c7k4lfq5j78d1rvrwrb9082ngwibz92cwkf4kazaa9b76w9q538"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         (add-after 'build 'docs
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (man1 (string-append out "/share/man/man1"))
                    (man7 (string-append out "/share/man/man7"))
                    (info (string-append out "/info")))
               (and
                 (zero? (system* "make" "-C" "docs" "man" "info"))
                 (install-file "docs/_build/texinfo/Certbot.info" info)
                 (install-file "docs/_build/man/certbot.1" man1)
                 (install-file "docs/_build/man/certbot.7" man7)
                 #t)))))))
    ;; TODO: Add optional inputs for testing.
    (native-inputs
     `(("python2-nose" ,python2-nose)
       ("python2-mock" ,python2-mock)
       ;; For documentation
       ("python2-sphinx" ,python2-sphinx)
       ("python2-sphinx-rtd-theme" ,python2-sphinx-rtd-theme)
       ("python2-sphinx-repoze-autointerface" ,python2-sphinx-repoze-autointerface)
       ("python2-sphinxcontrib-programoutput" ,python2-sphinxcontrib-programoutput)
       ("texinfo" ,texinfo)))
    (propagated-inputs
     `(("python2-acme" ,python2-acme)
       ("python2-zope-interface" ,python2-zope-interface)
       ("python2-pythondialog" ,python2-pythondialog)
       ("python2-pyrfc3339" ,python2-pyrfc3339)
       ("python2-pyopenssl" ,python2-pyopenssl)
       ("python2-configobj" ,python2-configobj)
       ("python2-configargparse" ,python2-configargparse)
       ("python2-zope-component" ,python2-zope-component)
       ("python2-parsedatetime" ,python2-parsedatetime)
       ("python2-six" ,python2-six)
       ("python2-psutil" ,python2-psutil)
       ("python2-requests" ,python2-requests)
       ("python2-pytz" ,python2-pytz)))
    (synopsis "Let's Encrypt client by the Electronic Frontier Foundation")
    (description "Tool to automatically receive and install X.509 certificates
to enable TLS on servers.  The client will interoperate with the Let’s Encrypt CA which
will be issuing browser-trusted certificates for free.")
    (home-page "https://certbot.eff.org/")
    (license license:asl2.0)))

(define-public letsencrypt
  (package (inherit certbot)
    (name "letsencrypt")
    (properties `((superseded . ,certbot)))))

(define-public perl-net-ssleay
  (package
    (name "perl-net-ssleay")
    (version "1.68")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/M/MI/MIKEM/"
                                  "Net-SSLeay-" version ".tar.gz"))
              (sha256
               (base32
                "1m2wwzhjwsg0drlhp9w12fl6bsgj69v8gdz72jqrqll3qr7f408p"))))
    (build-system perl-build-system)
    (native-inputs
     `(("patch" ,patch)
       ("patch/disable-ede-test"
        ,(search-patch "perl-net-ssleay-disable-ede-test.patch"))))
    (inputs `(("openssl" ,openssl)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after
          'unpack 'apply-patch
          (lambda* (#:key inputs #:allow-other-keys)
            ;; XXX We apply this patch here instead of in the 'origin' because
            ;; this package's build system fails badly when the source file
            ;; times are zeroed.
            ;; XXX Try removing this patch for perl-net-ssleay > 1.68
            (zero? (system* "patch" "--force" "-p1" "-i"
                            (assoc-ref inputs "patch/disable-ede-test")))))
         (add-before
          'configure 'set-ssl-prefix
          (lambda* (#:key inputs #:allow-other-keys)
            (setenv "OPENSSL_PREFIX" (assoc-ref inputs "openssl"))
            #t)))))
    (synopsis "Perl extension for using OpenSSL")
    (description
     "This module offers some high level convenience functions for accessing
web pages on SSL servers (for symmetry, the same API is offered for accessing
http servers, too), an sslcat() function for writing your own clients, and
finally access to the SSL api of the SSLeay/OpenSSL package so you can write
servers or clients for more complicated applications.")
    (license (package-license perl))
    (home-page "http://search.cpan.org/~mikem/Net-SSLeay-1.66/")))

(define-public perl-crypt-openssl-rsa
 (package
  (name "perl-crypt-openssl-rsa")
  (version "0.28")
  (source
    (origin
      (method url-fetch)
      (uri (string-append
             "mirror://cpan/authors/id/P/PE/PERLER/Crypt-OpenSSL-RSA-"
             version
             ".tar.gz"))
      (sha256
        (base32
          "1gnpvv09b2gpifwdzc5jnhama3d1a4c39lzj9hcaicsb8rvzjmsk"))))
  (build-system perl-build-system)
  (inputs
    `(("perl-crypt-openssl-bignum" ,perl-crypt-openssl-bignum)
      ("perl-crypt-openssl-random" ,perl-crypt-openssl-random)
      ("openssl" ,openssl)))
  (arguments perl-crypt-arguments)
  (home-page
    "http://search.cpan.org/dist/Crypt-OpenSSL-RSA")
  (synopsis
    "RSA encoding and decoding, using the openSSL libraries")
  (description "Crypt::OpenSSL::RSA does RSA encoding and decoding (using the
OpenSSL libraries).")
  (license (package-license perl))))

(define perl-crypt-arguments
   `(#:phases (modify-phases %standard-phases
      (add-before 'configure 'patch-Makefile.PL
        (lambda* (#:key inputs #:allow-other-keys)
          (substitute* "Makefile.PL"
            (("'LIBS'.*=>.*") (string-append "'LIBS' => ['-L"
                                             (assoc-ref inputs "openssl")
                                             "/lib -lcrypto'],")))
          #t)))))

(define-public perl-crypt-openssl-bignum
 (package
  (name "perl-crypt-openssl-bignum")
  (version "0.06")
  (source
    (origin
      (method url-fetch)
      (uri (string-append
             "mirror://cpan/authors/id/K/KM/KMX/Crypt-OpenSSL-Bignum-"
             version
             ".tar.gz"))
      (sha256
        (base32
          "05yzrdglrrzp191krf77zrwfkmzrfwrsrx1vyskbj94522lszk67"))))
  (build-system perl-build-system)
  (inputs `(("openssl" ,openssl)))
  (arguments perl-crypt-arguments)
  (home-page
    "http://search.cpan.org/dist/Crypt-OpenSSL-Bignum")
  (synopsis
    "OpenSSL's multiprecision integer arithmetic in Perl")
  (description "Crypt::OpenSSL::Bignum provides multiprecision integer
arithmetic in Perl.")
  ;; At your option either gpl1+ or the Artistic License
  (license (package-license perl))))

(define-public perl-crypt-openssl-random
 (package
  (name "perl-crypt-openssl-random")
  (version "0.11")
  (source
    (origin
      (method url-fetch)
      (uri (string-append
             "mirror://cpan/authors/id/R/RU/RURBAN/Crypt-OpenSSL-Random-"
             version
             ".tar.gz"))
      (sha256
        (base32
          "0yjcabkibrkafywvdkmd1xpi6br48skyk3l15ni176wvlg38335v"))))
  (build-system perl-build-system)
  (inputs `(("openssl" ,openssl)))
  (arguments perl-crypt-arguments)
  (home-page
    "http://search.cpan.org/dist/Crypt-OpenSSL-Random")
  (synopsis
    "OpenSSL/LibreSSL pseudo-random number generator access")
  (description "Crypt::OpenSSL::Random is a OpenSSL/LibreSSL pseudo-random
number generator")
  (license (package-license perl))))

(define-public acme-client
  (package
    (name "acme-client")
    (version "0.1.15")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://kristaps.bsd.lv/" name "/"
                                  "snapshots/" name "-portable-"
                                  version ".tgz"))
              (sha256
               (base32
                "07p723391whrswl4rir0l1k03l457sjscnj0cfaxr8mfnkx4y3wi"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ; no test suite
       #:make-flags
       (list "CC=gcc"
             (string-append "PREFIX=" (assoc-ref %outputs "out")))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-paths
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((pem (string-append (assoc-ref inputs "libressl")
                                       "/etc/ssl/cert.pem")))
               (substitute* "http.c"
                 (("/etc/ssl/cert.pem") pem))
               #t)))
         (delete 'configure)))) ; no './configure' script
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("libbsd" ,libbsd)
       ("libressl" ,libressl)))
    (synopsis "Let's Encrypt client by the OpenBSD project")
    (description "acme-client is a Let's Encrypt client implemented in C.  It
uses a modular design, and attempts to secure itself by dropping privileges and
operating in a chroot where possible.  acme-client is developed on OpenBSD and
then ported to the GNU / Linux environment.")
    (home-page "https://kristaps.bsd.lv/acme-client/")
    ;; acme-client is distributed under the ISC license, but the files 'jsmn.h'
    ;; and 'jsmn.c' are distributed under the Expat license.
    (license (list license:isc license:expat))))
