;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2013 Aljosha Papsch <misc@rpapsch.de>
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015 Taylan Ulrich Bayırlı/Kammer <taylanbayirli@gmail.com>
;;; Copyright © 2015, 2016 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2015 Eric Dvorsak <eric@dvorsak.fr>
;;; Copyright © 2016 Sou Bunnbu <iyzsong@gmail.com>
;;; Copyright © 2016 Jelle Licht <jlicht@fsfe.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Rene Saavedra <rennes@openmailbox.org>
;;; Copyright © 2016 Ben Woodcroft <donttrustben@gmail.com>
;;; Copyright © 2016 Clément Lassieur <clement@lassieur.org>
;;; Copyright © 2016 ng0 <ng0@we.make.ritual.n0.is>
;;; Copyright © 2016 Arun Isaac <arunisaac@systemreboot.net>
;;; Copyright © 2016 Tobias Geerinckx-Rice <me@tobias.gr>
;;; Copyright © 2016 Bake Timmons <b3timmons@speedymail.org>
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

(define-module (gnu packages web)
  #:use-module (ice-9 match)
  #:use-module ((guix licenses) #:prefix l:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix cvs-download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system glib-or-gtk)
  #:use-module (guix build-system perl)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system r)
  #:use-module (guix build-system trivial)
  #:use-module (guix build-system python)
  #:use-module (gnu packages)
  #:use-module (gnu packages apr)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages docbook)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages cyrus-sasl)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages mit-krb5)
  #:use-module (gnu packages gd)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages gperf)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages image)
  #:use-module (gnu packages lua)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages base)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages python)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages valgrind)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages textutils)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages statistics))

(define-public httpd
  (package
    (name "httpd")
    (version "2.4.23")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://apache/httpd/httpd-"
                                 version ".tar.bz2"))
             (sha256
              (base32
               "0n2yx3gjlpr4kgqx845fj6amnmg25r2l6a7rzab5hxnpmar985hc"))
             (patches (search-patches "httpd-CVE-2016-8740.patch"))
             (patch-flags '("-p0"))))
    (build-system gnu-build-system)
    (native-inputs `(("pcre" ,pcre "bin")))       ;for 'pcre-config'
    (inputs `(("apr" ,apr)
              ("apr-util" ,apr-util)
              ("openssl" ,openssl)
              ("perl" ,perl))) ; needed to run bin/apxs
    (arguments
     `(#:test-target "test"
       #:configure-flags (list "--enable-rewrite"
                               "--enable-userdir"
                               "--enable-vhost-alias"
                               "--enable-ssl"
                               "--enable-mime-magic"
                               (string-append "--sysconfdir="
                                              (assoc-ref %outputs "out")
                                              "/etc/httpd"))))
    (synopsis "Featureful HTTP server")
    (description
     "The Apache HTTP Server Project is a collaborative software development
effort aimed at creating a robust, commercial-grade, featureful, and
freely-available source code implementation of an HTTP (Web) server.  The
project is jointly managed by a group of volunteers located around the world,
using the Internet and the Web to communicate, plan, and develop the server
and its related documentation.")
    (license l:asl2.0)
    (home-page "https://httpd.apache.org/")))

(define-public nginx
  (package
    (name "nginx")
    (version "1.11.6")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://nginx.org/download/nginx-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1gc5phrzm2hbpvryaya6rlvasa00vjips4hv5q1rqbcfa6xsnlri"))))
    (build-system gnu-build-system)
    (inputs `(("pcre" ,pcre)
              ("openssl" ,openssl)
              ("zlib" ,zlib)))
    (arguments
     `(#:tests? #f                      ; no test target
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'patch-/bin/sh
           (lambda _
             (substitute* "auto/feature"
               (("/bin/sh") (which "bash")))
             #t))
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((flags
                    (list (string-append "--prefix=" (assoc-ref outputs "out"))
                          "--with-http_ssl_module"
                          "--with-pcre-jit"
                          "--with-debug"
                          ;; Even when not cross-building, we pass the
                          ;; --crossbuild option to avoid customizing for the
                          ;; kernel version on the build machine.
                          ,(let ((system "Linux")    ; uname -s
                                 (release "2.6.32")  ; uname -r
                                 ;; uname -m
                                 (machine (match (or (%current-target-system)
                                                     (%current-system))
                                            ("x86_64-linux"   "x86_64")
                                            ("i686-linux"     "i686")
                                            ("mips64el-linux" "mips64")
                                            ;; Prevent errors when querying
                                            ;; this package on unsupported
                                            ;; platforms, e.g. when running
                                            ;; "guix package --search="
                                            (_                "UNSUPPORTED"))))
                             (string-append "--crossbuild="
                                            system ":" release ":" machine)))))
               (setenv "CC" "gcc")
               (format #t "environment variable `CC' set to `gcc'~%")
               (format #t "configure flags: ~s~%" flags)
               (zero? (apply system* "./configure" flags)))))
         (add-after 'install 'fix-root-dirs
           (lambda* (#:key outputs #:allow-other-keys)
             ;; 'make install' puts things in strange places, so we need to
             ;; clean it up ourselves.
             (let* ((out (assoc-ref outputs "out"))
                    (share (string-append out "/share/nginx")))
               ;; This directory is empty, so get rid of it.
               (rmdir (string-append out "/logs"))
               ;; Example configuration and HTML files belong in
               ;; /share.
               (mkdir-p share)
               (rename-file (string-append out "/conf")
                            (string-append share "/conf"))
               (rename-file (string-append out "/html")
                            (string-append share "/html"))))))))
    (home-page "https://nginx.org")
    (synopsis "HTTP and reverse proxy server")
    (description
     "Nginx (\"engine X\") is a high-performance web and reverse proxy server
created by Igor Sysoev.  It can be used both as a standalone web server
and as a proxy to reduce the load on back-end HTTP or mail servers.")
    ;; Almost all of nginx is distributed under the bsd-2 license.
    ;; The exceptions are:
    ;;   * The 'nginx-http-push' module is covered by the expat license.
    ;;   * The 'nginx-development-kit' module is mostly covered by bsd-3,
    ;;     except for two source files which are bsd-4 licensed.
    (license (list l:bsd-2 l:expat l:bsd-3 l:bsd-4))))

(define-public fcgi
  (package
    (name "fcgi")
    (version "2.4.0")
    (source
     (origin
       (method url-fetch)
       ;; Upstream has disappeared
       (uri (string-append "https://sources.archlinux.org/other/packages/fcgi/"
                           "fcgi-" version ".tar.gz"))
       (sha256
        (base32
         "1f857wnl1d6jfrgfgfpz3zdaj8fch3vr13mnpcpvy8bang34bz36"))
       (patches (search-patches "fcgi-2.4.0-poll.patch"
                                "fcgi-2.4.0-gcc44-fixes.patch"))))
    (build-system gnu-build-system)
    ;; Parallel building is not supported.
    (arguments `(#:parallel-build? #f))
    (home-page "http://www.fastcgi.com")
    (synopsis "Language-independent, high-performant extension to CGI")
    (description "FastCGI is a language independent, scalable extension to CGI
that provides high performance without the limitations of server specific
APIs.")
    ;; This package is released under the Open Market License, a variant of
    ;; the Expat license, incompatible with the GPL.
    (license (l:non-copyleft "file://LICENSE.TERMS"))))

(define-public fcgiwrap
  (package
    (name "fcgiwrap")
    (version "1.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/gnosek/fcgiwrap/"
                           "archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "07y6s4mm86cv7p1ljz94sxnqa89y9amn3vzwsnbq5hrl4vdy0zac"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; no tests included
       #:make-flags (list "CC=gcc")
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'bootstrap
           (lambda _
             (zero? (system* "autoreconf" "-vif")))))))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("fcgi" ,fcgi)))
    (home-page "https://nginx.localdomain.pl/wiki/FcgiWrap")
    (synopsis "Simple server for running CGI applications over FastCGI")
    (description "Fcgiwrap is a simple server for running CGI applications
over FastCGI.  It hopes to provide clean CGI support to Nginx (and other web
servers that may need it).")
    (license l:expat)))

(define-public starman
  (package
    (name "starman")
    (version "0.4014")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/M/MI/MIYAGAWA/"
                           "Starman-" version ".tar.gz"))
       (sha256
        (base32
         "1sbb5rb3vs82rlh1fjkgkcmj5pj62b4y9si4ihh45sl9m8c2qxx5"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-libwww" ,perl-libwww)
       ("perl-module-build-tiny" ,perl-module-build-tiny)
       ("perl-test-requires" ,perl-test-requires)))
    (propagated-inputs
     `(("perl-data-dump" ,perl-data-dump)
       ("perl-http-date" ,perl-http-date)
       ("perl-http-message" ,perl-http-message)
       ("perl-http-parser-xs" ,perl-http-parser-xs)
       ("perl-net-server" ,perl-net-server)
       ("perl-plack" ,perl-plack)
       ("perl-test-tcp" ,perl-test-tcp)))
    (home-page "http://search.cpan.org/dist/Starman")
    (synopsis "PSGI/Plack web server")
    (description "Starman is a PSGI perl web server that has unique features
such as high performance, preforking, signal support, superdaemon awareness,
and UNIX socket support.")
    (license (package-license perl))))

(define-public jansson
  (package
    (name "jansson")
    (version "2.9")
    (source (origin
             (method url-fetch)
             (uri
              (string-append "http://www.digip.org/jansson/releases/jansson-"
                             version ".tar.gz"))
             (sha256
              (base32
               "19fjgfwjfj99rqa3kf96x5rssj88siazggksgrikd6h4r9sd1l0a"))))
    (build-system gnu-build-system)
    (home-page "http://www.digip.org/jansson/")
    (synopsis "JSON C library")
    (description
     "Jansson is a C library for encoding, decoding and manipulating JSON
data.")
    (license l:expat)))

(define-public json-c
  (package
    (name "json-c")
    (version "0.12.1")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "https://s3.amazonaws.com/json-c_releases/releases/json-c-"
                   version ".tar.gz"))
             (sha256
              (base32
               "08qibrq29a5v7g23wi5icy6l4fbfw90h9ccps6vq0bcklx8n84ra"))
             (modules '((guix build utils)))
             (snippet
              '(begin
                 ;; Somehow 'config.h.in' is older than
                 ;; 'aclocal.m4', which would trigger a rule to
                 ;; run 'autoheader'.
                 (set-file-time "config.h.in"
                                (stat "aclocal.m4"))

                 ;; Don't try to build with -Werror.
                 (substitute* (find-files "." "Makefile\\.in")
                   (("-Werror") ""))))))
    (build-system gnu-build-system)
    (arguments '(#:parallel-build? #f
                 #:parallel-tests? #f))
    (home-page "https://github.com/json-c/json-c/wiki")
    (synopsis "JSON implementation in C")
    (description
     "JSON-C implements a reference counting object model that allows you to
easily construct JSON objects in C, output them as JSON formatted strings and
parse JSON formatted strings back into the C representation of JSON objects.")
    (license l:x11)))

(define-public krona-tools
  (package
   (name "krona-tools")
   (version "2.7")
   (source (origin
             (method url-fetch)
             (uri (string-append
                   "https://github.com/marbl/Krona/releases/download/v"
                   version "/KronaTools-" version ".tar"))
             (sha256
              (base32
               "0wvgllcqscsfb4xc09y3fqhx8i38pmr4w55vjs5y79wx56n710iq"))))
   (build-system perl-build-system)
   (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; There is no configure or build steps.
         (delete 'configure)
         (delete 'build)
         ;; Install script "install.pl" expects the build directory to remain
         ;; after installation, creating symlinks etc., so re-implement it
         ;; here.
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((bin   (string-append (assoc-ref outputs "out") "/bin"))
                   (perl  (string-append (assoc-ref outputs "out")
                                         "/lib/perl5/site_perl/krona-tools/lib")))
               (mkdir-p bin)
               (for-each
                (lambda (script)
                  (let* ((executable (string-append "scripts/" script ".pl")))
                    ;; Prefix executables with 'kt' as install script does.
                    (copy-file executable (string-append bin "/kt" script))))
                '("ClassifyBLAST"
                  "GetContigMagnitudes"
                  "GetLCA"
                  "GetTaxIDFromAcc"
                  "GetTaxInfo"
                  "ImportBLAST"
                  "ImportDiskUsage"
                  "ImportEC"
                  "ImportFCP"
                  "ImportGalaxy"
                  "ImportKrona"
                  "ImportMETAREP-BLAST"
                  "ImportMETAREP-EC"
                  "ImportMGRAST"
                  "ImportPhymmBL"
                  "ImportRDP"
                  "ImportRDPComparison"
                  "ImportTaxonomy"
                  "ImportText"
                  "ImportXML"))
               (for-each 
                (lambda (directory)
                  (copy-recursively directory
                                    (string-append perl "/../" directory)))
                (list "data" "img" "taxonomy" "src"))
               (install-file "lib/KronaTools.pm" perl))))
         (add-after 'install 'wrap-program
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (path (getenv "PERL5LIB")))
               (for-each
                (lambda (executable)
                  (wrap-program executable
                    `("PERL5LIB" ":" prefix
                      (,(string-append out "/lib/perl5/site_perl/krona-tools/lib")))))
                (find-files (string-append out "/bin/") ".*")))))
         (delete 'check)
         (add-after 'wrap-program 'check
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (with-directory-excursion "data"
               (zero? (system* (string-append (assoc-ref outputs "out") "/bin/ktImportText")
                               "ec.tsv"))))))))
   (inputs
    `(("perl" ,perl)))
   (home-page "https://github.com/marbl/Krona/wiki")
   (synopsis "Hierarchical data exploration with zoomable HTML5 pie charts")
   (description
    "Krona is a flexible tool for exploring the relative proportions of
hierarchical data, such as metagenomic classifications, using a radial,
space-filling display.  It is implemented using HTML5 and JavaScript, allowing
charts to be explored locally or served over the Internet, requiring only a
current version of any major web browser.")
   (license l:bsd-3)))

(define-public rapidjson
  (package
    (name "rapidjson")
    (version "1.0.2")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "https://github.com/miloyip/rapidjson/archive/v"
                   version ".tar.gz"))
             (file-name (string-append name "-" version ".tar.gz"))
             (sha256
              (base32
               "0rl6s0vg5y1dhh9vfl1lqay3sxf69sxjh0czxrjmasn7ng91wwf3"))
             (modules '((guix build utils)))
             (snippet
              ;; Building with GCC 4.8 with -Werror was fine, but 4.9.3
              ;; complains in new ways, so turn of -Werror.
              '(substitute* (find-files "." "^CMakeLists\\.txt$")
                 (("-Werror") "")))))
    (build-system cmake-build-system)
    (home-page "https://github.com/miloyip/rapidjson")
    (synopsis "JSON parser/generator for C++ with both SAX/DOM style API")
    (description
     "RapidJSON is a fast JSON parser/generator for C++ with both SAX/DOM
style API.")
    (license l:expat)))

(define-public libyajl
  (package
    (name "libyajl")
    (version "2.1.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/lloyd/yajl/"
                                  "archive/" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0nmcqpaiq4pv7dymyg3n3jsd57yhp5npxl26a1hzw3m3lmj37drz"))))
    (build-system cmake-build-system)
    (home-page "https://lloyd.github.io/yajl/")
    (synopsis "C library for parsing JSON")
    (description
     "Yet Another JSON Library (YAJL) is a small event-driven (SAX-style) JSON
parser written in ANSI C and a small validating JSON generator.")
    (license l:isc)))

(define-public libwebsockets
  (package
    (name "libwebsockets")
    (version "1.3")
    (source (origin
              ;; The project does not publish tarballs, so we have to take
              ;; things from Git.
              (method git-fetch)
              (uri (git-reference
                    (url "git://git.libwebsockets.org/libwebsockets")
                    (commit (string-append "v" version
                                           "-chrome37-firefox30"))))
              (sha256
               (base32
                "12fqh2d2098mgf0ls19p9lzibpsqhv7mc5rn1yvrbfnazmcr40g4"))
              (file-name (string-append name "-" version))))

    (build-system cmake-build-system)
    (arguments
     ;; XXX: The thing lacks a 'make test' target, because CMakeLists.txt
     ;; doesn't use 'add_test', and it's unclear how to run the test suite.
     '(#:tests? #f))

    (native-inputs `(("perl" ,perl)))             ; to build the HTML doc
    (inputs `(("zlib" ,zlib)
              ("openssl" ,openssl)))
    (synopsis "WebSockets library written in C")
    (description
     "Libwebsockets is a library that allows C programs to establish client
and server WebSockets connections---a protocol layered above HTTP that allows
for efficient socket-like bidirectional reliable communication channels.")
    (home-page "http://libwebsockets.org/")

    ;; This is LGPLv2.1-only with extra exceptions specified in 'LICENSE'.
    (license l:lgpl2.1)))

(define-public libpsl
  (package
    (name "libpsl")
    (version "0.16.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/rockdaboot/libpsl/"
                                  "releases/download/libpsl-" version
                                  "/libpsl-" version ".tar.gz"))
              (sha256
               (base32
                "1srrd0iyz9p5xgl8q0hrzqg7p8cl9ar0cdb8f54hls4kllf3f80l"))))
    (build-system gnu-build-system)
    (inputs
     `(("icu4c" ,icu4c)
       ("python-2" ,python-2)))
    (home-page "https://github.com/rockdaboot/libpsl")
    (synopsis "C library for the Publix Suffix List")
    (description
     "A \"public suffix\" is a domain name under which Internet users can
directly register own names.

Browsers and other web clients can use it to avoid privacy-leaking
\"supercookies\", avoid privacy-leaking \"super domain\" certificates, domain
highlighting parts of the domain in a user interface, and sorting domain lists
by site.

Libpsl has built-in PSL data for fast access, allows to load PSL data from
files, checks if a given domain is a public suffix, provides immediate cookie
domain verification, finds the longest public part of a given domain, finds
the shortest private part of a given domain, works with international
domains (UTF-8 and IDNA2008 Punycode), is thread-safe, and handles IDNA2008
UTS#46.")
    (license l:x11)))

(define-public tidy
  (package
    (name "tidy")
    (version "20091223")
    (source (origin
              (method cvs-fetch)
              (uri (cvs-reference
                    (root-directory
                     ":pserver:anonymous@tidy.cvs.sourceforge.net:/cvsroot/tidy")
                    (module "tidy")
                    (revision "2009-12-23")))
              (sha256
               (base32
                "14dsnmirjcrvwsffqp3as70qr6bbfaig2fv3zvs5g7005jrsbvpb"))
              (patches (search-patches "tidy-CVE-2015-5522+5523.patch"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (modify-phases %standard-phases
                  (add-after 'unpack 'bootstrap
                    (lambda* (#:key inputs #:allow-other-keys)
                      ;; configure.in and Makefile.am aren't in the root of the
                      ;; source tree.
                      (copy-recursively "build/gnuauto" ".")
                      (setenv "AUTOMAKE" "automake --foreign")
                      (zero? (system* "autoreconf" "-vfi")))))))
    (native-inputs
     `(("automake" ,automake)
       ("autoconf" ,autoconf)
       ("libtool" ,libtool)))
    (synopsis "HTML validator and tidier")
    (description "HTML Tidy is a command-line tool and C library that can be
used to validate and fix HTML data.")
    (home-page "http://tidy.sourceforge.net/")
    (license (l:x11-style "file:///include/tidy.h"))))

(define-public tinyproxy
  (package
    (name "tinyproxy")
    (version "1.8.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/tinyproxy/tinyproxy/"
                                  "releases/download/" version "/tinyproxy-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "002hi97687czhfkwsjkr174yvlp10224qi6gd5s53z230bgls7x4"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags
       (list
        ;; For the log file, etc.
        "--localstatedir=/var")
       #:phases
       (alist-cons-before
        'build 'pre-build
        (lambda* (#:key inputs #:allow-other-keys #:rest args)
          ;; Uncommenting the next two lines may assist in debugging
          ;; (substitute* "docs/man5/Makefile" (("a2x") "a2x -v"))
          ;; (setenv "XML_DEBUG_CATALOG" "1")
          #t)
        %standard-phases)))
    ;; All of the below are used to generate the documentation
    ;; (Should they be propagated inputs of asciidoc ??)
    (native-inputs `(("asciidoc" ,asciidoc)
                     ("libxml2" ,libxml2)
                     ("docbook-xml" ,docbook-xml)
                     ("docbook-xsl" ,docbook-xsl)
                     ("libxslt" ,libxslt)))
    (home-page "https://tinyproxy.github.io/")
    (synopsis "Light-weight HTTP/HTTPS proxy daemon")
    (description "Tinyproxy is a light-weight HTTP/HTTPS proxy
daemon.  Designed from the ground up to be fast and yet small, it is an ideal
solution for use cases such as embedded deployments where a full featured HTTP
proxy is required, but the system resources for a larger proxy are
unavailable.")
    (license l:gpl2+)))

(define-public polipo
  (package
    (name "polipo")
    (version "1.1.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "http://www.pps.univ-paris-diderot.fr/~jch/software/files/polipo/polipo-"
             version ".tar.gz"))
       (sha256
        (base32
         "05g09sg9qkkhnc2mxldm1w1xkxzs2ylybkjzs28w8ydbjc3pand2"))))
    (native-inputs `(("texinfo" ,texinfo)))
    (build-system gnu-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (delete 'configure))
       #:make-flags (let ((out (assoc-ref %outputs "out")))
                      (list (string-append "PREFIX=" out)
                            (string-append "LOCAL_ROOT="
                                           out "/share/polipo/www")
                            "CC=gcc"))
       ;; No 'check' target.
       #:tests? #f))
    (home-page "http://www.pps.univ-paris-diderot.fr/~jch/software/polipo/")
    (synopsis "Small caching web proxy")
    (description
     "Polipo is a small caching web proxy (web cache, HTTP proxy, and proxy
server).  It was primarily designed to be used by one person or a small group
of people.")
    (license l:expat)))

(define-public wwwoffle
  (package
    (name "wwwoffle")
    (version "2.9j")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://www.gedanken.org.uk/software/"
                                  "wwwoffle/download/wwwoffle-"
                                  version ".tgz"))
              (sha256
               (base32
                "1ihil1xq9dp21hf108khxbw6f3baq0w5c0j3af038y6lkmad4vdi"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags '("--with-gnutls")
       #:tests? #f))                         ; no test target
    (native-inputs `(("flex" ,flex)))
    (inputs `(("gnutls" ,gnutls)
              ("libcrypt", libgcrypt)))
    (home-page "https://www.gedanken.org.uk/software/wwwoffle/")
    (synopsis "Caching web proxy optimized for intermittent internet links")
    (description "WWWOFFLE is a proxy web server that is especially good for
intermittent internet links.  It can cache HTTP, HTTPS, FTP, and finger
protocols, and supports browsing and requesting pages while offline, indexing,
modifying pages and incoming and outgoing headers, monitoring pages for
changes, and much more.")
    (license l:gpl2+)))

(define-public libyaml
  (package
    (name "libyaml")
    (version "0.1.6")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "http://pyyaml.org/download/libyaml/yaml-"
             version ".tar.gz"))
       (patches (search-patches "libyaml-CVE-2014-9130.patch"))
       (sha256
        (base32
         "0j9731s5zjb8mjx7wzf6vh7bsqi38ay564x6s9nri2nh9cdrg9kx"))))
    (build-system gnu-build-system)
    (home-page "http://pyyaml.org/wiki/LibYAML")
    (synopsis "YAML 1.1 parser and emitter written in C")
    (description
     "LibYAML is a YAML 1.1 parser and emitter written in C.")
    (license l:expat)))

(define-public libquvi-scripts
  (package
    (name "libquvi-scripts")
    (version "0.4.21")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "mirror://sourceforge/quvi/" (version-major+minor version) "/"
             name "/" name "-" version ".tar.xz"))
       (sha256
        (base32 "0d0giry6bb57pnidymvdl7i5x9bq3ljk3g4bs294hcr5mj3cq0kw"))))
    (build-system gnu-build-system)
    (home-page "http://quvi.sourceforge.net/")
    (synopsis "Media stream URL parser")
    (description "This package contains support scripts called by libquvi to
parse media stream properties.")
    (license l:lgpl2.1+)))

(define-public libquvi
  (package
    (name "libquvi")
    (version "0.4.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "mirror://sourceforge/quvi/" (version-major+minor version) "/" name "/"
             name "-" version ".tar.xz"))
       (sha256
        (base32 "00x9gbmzc5cns0gnfag0hsphcr3cb33vbbb9s7ppvvd6bxz2z1mm"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)))
    (inputs
     `(("curl" ,curl)
       ("cyrus-sasl" ,cyrus-sasl)
       ("libquvi-scripts" ,libquvi-scripts)
       ("lua" ,lua-5.1)
       ("openssl" ,openssl)
       ("zlib" ,zlib)))
    (arguments
     ;; Lua provides no .pc file, so add CFLAGS/LIBS manually.
     '(#:configure-flags
       (let ((lua (assoc-ref %build-inputs "lua")))
         (list
          (string-append "liblua_CFLAGS=-I" lua "/include")
          (string-append "liblua_LIBS=-L" lua "/libs -llua")))))
    (home-page "http://quvi.sourceforge.net/")
    (synopsis "Media stream URL parser")
    (description "libquvi is a library with a C API for parsing media stream
URLs and extracting their actual media files.")
    (license l:lgpl2.1+)))

(define-public quvi
  (package
    (name "quvi")
    (version "0.4.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "mirror://sourceforge/" name "/"  (version-major+minor version)
             "/" name "/" name "-" version ".tar.xz"))
       (sha256
        (base32 "09lhl6dv5zpryasx7yjslfrcdcqlsbwapvd5lg7w6sm5x5n3k8ci"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)))
    (inputs
     `(("curl" ,curl)
       ("libquvi" ,libquvi)))
    (home-page "http://quvi.sourceforge.net/")
    (synopsis "Media stream URL parser")
    (description "quvi is a command-line-tool suite to extract media files
from streaming URLs.  It is a command-line wrapper for the libquvi library.")
    (license l:lgpl2.1+)))

(define-public serf
  (package
    (name "serf")
    (version "1.3.8")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://archive.apache.org/dist/serf/serf-"
                           version ".tar.bz2"))
       (sha256
        (base32 "14155g48gamcv5s0828bzij6vr14nqmbndwq8j8f9g6vcph0nl70"))
       (patches (search-patches "serf-comment-style-fix.patch"
                                "serf-deflate-buckets-test-fix.patch"))
       (patch-flags '("-p0"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("scons" ,scons)
       ("python" ,python-2)))
    (propagated-inputs
     `(("apr" ,apr)
       ("apr-util" ,apr-util)
       ("openssl" ,openssl)))
    (inputs
     `(;; TODO: Fix build with gss.
       ;;("gss" ,gss)
       ("zlib" ,zlib)))
    (arguments
     `(#:phases
       ;; TODO: Add scons-build-system and use it here.
       (modify-phases %standard-phases
         (delete 'configure)
         (add-after 'unpack 'scons-propagate-environment
                    (lambda _
                      ;; By design, SCons does not, by default, propagate
                      ;; environment variables to subprocesses.  See:
                      ;; <http://comments.gmane.org/gmane.linux.distributions.nixos/4969>
                      ;; Here, we modify the SConstruct file to arrange for
                      ;; environment variables to be propagated.
                      (substitute* "SConstruct"
                        (("^env = Environment\\(")
                         "env = Environment(ENV=os.environ, "))))
         (replace 'build
                  (lambda* (#:key inputs outputs #:allow-other-keys)
                    (let ((out      (assoc-ref outputs "out"))
                          (apr      (assoc-ref inputs "apr"))
                          (apr-util (assoc-ref inputs "apr-util"))
                          (openssl  (assoc-ref inputs "openssl"))
                          ;;(gss      (assoc-ref inputs "gss"))
                          (zlib     (assoc-ref inputs "zlib")))
                      (zero? (system* "scons"
                                      (string-append "APR=" apr)
                                      (string-append "APU=" apr-util)
                                      (string-append "OPENSSL=" openssl)
                                      ;;(string-append "GSSAPI=" gss)
                                      (string-append "ZLIB=" zlib)
                                      (string-append "PREFIX=" out))))))
         (replace 'check   (lambda _ (zero? (system* "scons" "check"))))
         (replace 'install (lambda _ (zero? (system* "scons" "install")))))))
    (home-page "https://serf.apache.org/")
    (synopsis "High-performance asynchronous HTTP client library")
    (description
     "serf is a C-based HTTP client library built upon the Apache Portable
Runtime (APR) library.  It multiplexes connections, running the read/write
communication asynchronously.  Memory copies and transformations are kept to a
minimum to provide high performance operation.")
    ;; Most of the code is covered by the Apache License, Version 2.0, but the
    ;; bundled CuTest framework uses a different non-copyleft license.
    (license (list l:asl2.0 (l:non-copyleft "file://test/CuTest-README.txt")))))

(define-public sassc
  ;; libsass must be statically linked and it isn't included in the sassc
  ;; release tarballs, hence this odd package recipe.
  (let* ((version "3.2.5")
         (libsass
          (origin
            (method url-fetch)
            (uri (string-append
                  "https://github.com/sass/libsass/archive/"
                  version ".tar.gz"))
            (file-name (string-append "libsass-" version ".tar.gz"))
            (sha256
             (base32
              "1x25k6p1s1yzsdpzb7bzh8japilmi1mk3z96q66pycbinj9z9is4")))))
    (package
      (name "sassc")
      (version version)
      (source (origin
                (method url-fetch)
                (uri (string-append "https://github.com/sass/sassc/archive/"
                                    version ".tar.gz"))
                (file-name (string-append "sassc-" version ".tar.gz"))
                (sha256
                 (base32
                  "1xf3w75w840rj0nx375rxi7mcv1ngqqq8p3zrzjlyx8jfpnldmv5"))))
      (build-system gnu-build-system)
      (arguments
       `(#:make-flags '("CC=gcc")
         #:test-target "test"
         #:phases
         (modify-phases %standard-phases
           (delete 'configure)
           (add-after 'unpack 'unpack-libsass-and-set-path
             (lambda* (#:key inputs #:allow-other-keys)
               (and (zero? (system* "tar" "xvf" (assoc-ref inputs "libsass")))
                    (begin
                      (setenv "SASS_LIBSASS_PATH"
                              (string-append (getcwd) "/libsass-" ,version))
                      #t))))
           (replace 'install ; no install target
             (lambda* (#:key outputs #:allow-other-keys)
               (let ((bin (string-append (assoc-ref outputs "out") "/bin")))
                 (mkdir-p bin)
                 (copy-file "bin/sassc" (string-append bin "/sassc"))
                 #t))))))
      (inputs
       `(("libsass" ,libsass)))
      (synopsis "CSS pre-processor")
      (description "SassC is a compiler written in C for the CSS pre-processor
language known as SASS.")
      (home-page "http://sass-lang.com/libsass")
      (license l:expat))))


(define-public perl-apache-logformat-compiler
  (package
    (name "perl-apache-logformat-compiler")
    (version "0.33")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/K/KA/KAZEBURO/"
                           "Apache-LogFormat-Compiler-" version ".tar.gz"))
       (sha256
        (base32
         "17blk3zhp05azgypn25ydxf3d7fyfgr9bxyiv7xkchhqma96vwqv"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-http-message" ,perl-http-message)
       ("perl-module-build" ,perl-module-build)
       ("perl-test-mocktime" ,perl-test-mocktime)
       ("perl-try-tiny" ,perl-try-tiny)
       ("perl-uri" ,perl-uri)))
    (propagated-inputs
     `(("perl-posix-strftime-compiler" ,perl-posix-strftime-compiler)))
    (arguments `(#:tests? #f))          ;TODO: Timezone test failures
    (home-page "http://search.cpan.org/dist/Apache-LogFormat-Compiler")
    (synopsis "Compile a log format string to perl-code")
    (description "This module provides methods to compile a log format string
to perl-code, for faster generation of access_log lines.")
    (license (package-license perl))))

(define-public perl-authen-sasl
  (package
    (name "perl-authen-sasl")
    (version "2.16")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/G/GB/GBARR/"
                           "Authen-SASL-" version ".tar.gz"))
       (sha256
        (base32
         "02afhlrdq5hh5g8b32fa79fqq5i76qzwfqqvfi9zi57h31szl536"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-digest-hmac" ,perl-digest-hmac)
       ("perl-gssapi" ,perl-gssapi)))
    (home-page "http://search.cpan.org/dist/Authen-SASL")
    (synopsis "SASL authentication framework")
    (description "Authen::SASL provides an SASL authentication framework.")
    (license (package-license perl))))

(define-public perl-catalyst-action-renderview
  (package
    (name "perl-catalyst-action-renderview")
    (version "0.16")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/B/BO/BOBTFISH/"
                           "Catalyst-Action-RenderView-"
                           version ".tar.gz"))
       (sha256
        (base32
         "0j1rrld13cjk7ks92b5hv3xw4rfm2lvmksb4rlzd8mx0a0wj0rc5"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-http-request-ascgi" ,perl-http-request-ascgi)))
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-data-visitor" ,perl-data-visitor)
       ("perl-mro-compat" ,perl-mro-compat)))
    (home-page "http://search.cpan.org/dist/Catalyst-Action-RenderView")
    (synopsis "Sensible default Catalyst action")
    (description "This Catalyst action implements a sensible default end
action, which will forward to the first available view.")
    (license (package-license perl))))

(define-public perl-catalyst-action-rest
  (package
    (name "perl-catalyst-action-rest")
    (version "1.20")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/J/JJ/JJNAPIORK/"
                                  "Catalyst-Action-REST-" version ".tar.gz"))
              (sha256
               (base32
                "1mpa64p61f3dp24xnhdraswch4sqj5vyv1iivcvvh5h0xi0haiy0"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-requires" ,perl-test-requires)))
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-class-inspector" ,perl-class-inspector)
       ("perl-config-general" ,perl-config-general)
       ("perl-cpanel-json-xs" ,perl-cpanel-json-xs)
       ("perl-libwww" ,perl-libwww)
       ("perl-moose" ,perl-moose)
       ("perl-mro-compat" ,perl-mro-compat)
       ("perl-namespace-autoclean" ,perl-namespace-autoclean)
       ("perl-params-validate" ,perl-params-validate)
       ("perl-uri-find" ,perl-uri-find)
       ("perl-xml-simple" ,perl-xml-simple)))
    (home-page "http://search.cpan.org/dist/Catalyst-Action-REST")
    (synopsis "Automated REST Method Dispatching")
    (description "This Action handles doing automatic method dispatching for
REST requests.  It takes a normal Catalyst action, and changes the dispatch to
append an underscore and method name.  First it will try dispatching to an
action with the generated name, and failing that it will try to dispatch to a
regular method.")
    (license (package-license perl))))

(define-public perl-catalyst-authentication-store-dbix-class
  (package
    (name "perl-catalyst-authentication-store-dbix-class")
    (version "0.1506")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/I/IL/ILMARI/"
                           "Catalyst-Authentication-Store-DBIx-Class-"
                           version ".tar.gz"))
       (sha256
        (base32
         "0i5ja7690fs9nhxcij6lw51j804sm8s06m5mvk1n8pi8jljrymvw"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-catalyst-plugin-authorization-roles"
        ,perl-catalyst-plugin-authorization-roles)
       ("perl-catalyst-plugin-session-state-cookie"
        ,perl-catalyst-plugin-session-state-cookie)
       ("perl-dbd-sqlite" ,perl-dbd-sqlite)
       ("perl-test-www-mechanize-catalyst" ,perl-test-www-mechanize-catalyst)))
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-catalyst-plugin-authentication"
        ,perl-catalyst-plugin-authentication)
       ("perl-dbix-class" ,perl-dbix-class)
       ("perl-catalyst-model-dbic-schema" ,perl-catalyst-model-dbic-schema)))
    (home-page
     "http://search.cpan.org/dist/Catalyst-Authentication-Store-DBIx-Class")
    (synopsis "Storage class for Catalyst authentication using DBIx::Class")
    (description "The Catalyst::Authentication::Store::DBIx::Class class
provides access to authentication information stored in a database via
DBIx::Class.")
    (license (package-license perl))))

(define-public perl-catalyst-component-instancepercontext
  (package
    (name "perl-catalyst-component-instancepercontext")
    (version "0.001001")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/G/GR/GRODITI/"
                           "Catalyst-Component-InstancePerContext-"
                           version ".tar.gz"))
       (sha256
        (base32
         "0wfj4vnn2cvk6jh62amwlg050p37fcwdgrn9amcz24z6w4qgjqvz"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-moose" ,perl-moose)))
    (home-page
     "http://search.cpan.org/dist/Catalyst-Component-InstancePerContext")
    (synopsis "Create only one instance of Moose component per context")
    (description "Catalyst::Component::InstancePerContext returns a new
instance of a component on each request.")
    (license (package-license perl))))

(define-public perl-catalyst-devel
  (package
    (name "perl-catalyst-devel")
    (version "1.39")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/I/IL/ILMARI/"
                           "Catalyst-Devel-" version ".tar.gz"))
       (sha256
        (base32
         "12m50bbkggjmpxihv3wnvr0g2qng0zwhlzi5ygppjz8wh2x73qxw"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-fatal" ,perl-test-fatal)))
    (propagated-inputs
     `(("perl-catalyst-action-renderview" ,perl-catalyst-action-renderview)
       ("perl-catalyst-plugin-configloader" ,perl-catalyst-plugin-configloader)
       ("perl-catalyst-plugin-static-simple" ,perl-catalyst-plugin-static-simple)
       ("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-config-general" ,perl-config-general)
       ("perl-file-changenotify" ,perl-file-changenotify)
       ("perl-file-copy-recursive" ,perl-file-copy-recursive)
       ("perl-file-sharedir" ,perl-file-sharedir)
       ("perl-module-install" ,perl-module-install)
       ("perl-moose" ,perl-moose)
       ("perl-moosex-emulate-class-accessor-fast"
        ,perl-moosex-emulate-class-accessor-fast)
       ("perl-namespace-autoclean" ,perl-namespace-autoclean)
       ("perl-namespace-clean" ,perl-namespace-clean)
       ("perl-path-class" ,perl-path-class)
       ("perl-template-toolkit" ,perl-template-toolkit)))
    (home-page "http://search.cpan.org/dist/Catalyst-Devel")
    (synopsis "Catalyst Development Tools")
    (description "The Catalyst-Devel distribution includes a variety of
modules useful for the development of Catalyst applications, but not required
to run them.  Catalyst-Devel includes the Catalyst::Helper system, which
autogenerates scripts and tests; Module::Install::Catalyst, a Module::Install
extension for Catalyst; and requirements for a variety of development-related
modules.")
    (license (package-license perl))))

(define-public perl-catalyst-dispatchtype-regex
  (package
    (name "perl-catalyst-dispatchtype-regex")
    (version "5.90035")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/M/MG/MGRIMES/"
                           "Catalyst-DispatchType-Regex-" version ".tar.gz"))
       (sha256
        (base32
         "06jq1lmpq88rmp9zik5gqczg234xac0hiyc3l698iif7zsgcyb80"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-module-build" ,perl-module-build) ;needs Module::Build >= 0.4004
       ("perl-namespace-autoclean" ,perl-namespace-autoclean)
       ("perl-catalyst-runtime" ,perl-catalyst-runtime)))
    (propagated-inputs
     `(("perl-moose" ,perl-moose)
       ("perl-text-simpletable" ,perl-text-simpletable)))
    (home-page "http://search.cpan.org/dist/Catalyst-DispatchType-Regex")
    (synopsis "Regex DispatchType for Catalyst")
    (description "Dispatch type managing path-matching behaviour using
regexes.  Regex dispatch types have been deprecated and removed from Catalyst
core.  It is recommend that you use Chained methods or other techniques
instead.  As part of the refactoring, the dispatch priority of Regex vs Regexp
vs LocalRegex vs LocalRegexp may have changed.  Priority is now influenced by
when the dispatch type is first seen in your application.")
    (license (package-license perl))))

(define-public perl-catalyst-model-dbic-schema
  (package
  (name "perl-catalyst-model-dbic-schema")
  (version "0.65")
  (source
    (origin
      (method url-fetch)
      (uri (string-append "mirror://cpan/authors/id/G/GB/GBJK/"
                          "Catalyst-Model-DBIC-Schema-"
                          version ".tar.gz"))
      (sha256
        (base32
          "1spfjcjc0b9dv3k2gbanqj1m1cqzyxb32p76dhdwizzpbvpi3a96"))))
  (build-system perl-build-system)
  (native-inputs
   `(("perl-dbd-sqlite" ,perl-dbd-sqlite)
     ("perl-test-exception" ,perl-test-exception)
     ("perl-test-requires" ,perl-test-requires)))
  (propagated-inputs
   `(("perl-carp-clan" ,perl-carp-clan)
     ("perl-catalyst-component-instancepercontext"
      ,perl-catalyst-component-instancepercontext)
     ("perl-catalyst-runtime" ,perl-catalyst-runtime)
     ("perl-catalystx-component-traits" ,perl-catalystx-component-traits)
     ("perl-dbix-class" ,perl-dbix-class)
     ("perl-dbix-class-cursor-cached" ,perl-dbix-class-cursor-cached)
     ("perl-dbix-class-schema-loader" ,perl-dbix-class-schema-loader)
     ("perl-hash-merge" ,perl-hash-merge)
     ("perl-list-moreutils" ,perl-list-moreutils)
     ("perl-module-runtime" ,perl-module-runtime)
     ("perl-moose" ,perl-moose)
     ("perl-moosex-markasmethods" ,perl-moosex-markasmethods)
     ("perl-moosex-nonmoose" ,perl-moosex-nonmoose)
     ("perl-moosex-types" ,perl-moosex-types)
     ("perl-moosex-types-loadableclass" ,perl-moosex-types-loadableclass)
     ("perl-namespace-autoclean" ,perl-namespace-autoclean)
     ("perl-namespace-clean" ,perl-namespace-clean)
     ("perl-tie-ixhash" ,perl-tie-ixhash)
     ("perl-try-tiny" ,perl-try-tiny)))
  (home-page "http://search.cpan.org/dist/Catalyst-Model-DBIC-Schema")
  (synopsis "DBIx::Class::Schema Model Class")
  (description "This is a Catalyst Model for DBIx::Class::Schema-based
Models.")
  (license (package-license perl))))

(define-public perl-catalyst-plugin-accesslog
  (package
    (name "perl-catalyst-plugin-accesslog")
    (version "1.10")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/A/AR/ARODLAND/"
                           "Catalyst-Plugin-AccessLog-" version ".tar.gz"))
       (sha256
        (base32
         "0811rj45q4v2y8wka3wb9d5m4vbyhcmkvddf2wz4x69awzjbhgc7"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-datetime" ,perl-datetime)
       ("perl-moose" ,perl-moose)
       ("perl-namespace-autoclean" ,perl-namespace-autoclean)))
    (home-page "http://search.cpan.org/dist/Catalyst-Plugin-AccessLog")
    (synopsis "Request logging from within Catalyst")
    (description "This Catalyst plugin enables you to create \"access logs\"
from within a Catalyst application instead of requiring a webserver to do it
for you.  It will work even with Catalyst debug logging turned off.")
    (license (package-license perl))))

(define-public perl-catalyst-plugin-authentication
  (package
    (name "perl-catalyst-plugin-authentication")
    (version "0.10023")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/B/BO/BOBTFISH/"
                           "Catalyst-Plugin-Authentication-"
                           version ".tar.gz"))
       (sha256
        (base32
         "0v6hb4r1wv3djrnqvnjcn3xx1scgqzx8nyjdg9lfc1ybvamrl0rn"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-catalyst-plugin-session" ,perl-catalyst-plugin-session)
       ("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-class-inspector" ,perl-class-inspector)
       ("perl-moose" ,perl-moose)
       ("perl-moosex-emulate-class-accessor-fast"
        ,perl-moosex-emulate-class-accessor-fast)
       ("perl-mro-compat" ,perl-mro-compat)
       ("perl-namespace-autoclean" ,perl-namespace-autoclean)
       ("perl-string-rewriteprefix" ,perl-string-rewriteprefix)
       ("perl-test-exception" ,perl-test-exception)
       ("perl-try-tiny" ,perl-try-tiny)))
    (home-page "http://search.cpan.org/dist/Catalyst-Plugin-Authentication")
    (synopsis "Infrastructure plugin for the Catalyst authentication framework")
    (description "The authentication plugin provides generic user support for
Catalyst apps.  It is the basis for both authentication (checking the user is
who they claim to be), and authorization (allowing the user to do what the
system authorises them to do).")
    (license (package-license perl))))

(define-public perl-catalyst-plugin-authorization-roles
  (package
    (name "perl-catalyst-plugin-authorization-roles")
    (version "0.09")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/B/BO/BOBTFISH/"
                           "Catalyst-Plugin-Authorization-Roles-"
                           version ".tar.gz"))
       (sha256
        (base32
         "0l83lkwmq0lngwh8b1rv3r719pn8w1gdbyhjqm74rnd0wbjl8h7f"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-exception" ,perl-test-exception)))
    (propagated-inputs
     `(("perl-catalyst-plugin-authentication"
        ,perl-catalyst-plugin-authentication)
       ("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-set-object" ,perl-set-object)
       ("perl-universal-isa" ,perl-universal-isa)))
    (home-page
     "http://search.cpan.org/dist/Catalyst-Plugin-Authorization-Roles")
    (synopsis "Role-based authorization for Catalyst")
    (description "Catalyst::Plugin::Authorization::Roles provides role-based
authorization for Catalyst based on Catalyst::Plugin::Authentication.")
    (license (package-license perl))))

(define-public perl-catalyst-plugin-captcha
  (package
    (name "perl-catalyst-plugin-captcha")
    (version "0.04")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/D/DI/DIEGOK/"
                           "Catalyst-Plugin-Captcha-" version ".tar.gz"))
       (sha256
        (base32
         "0llyj3v5nx9cx46jdbbvxf1lc9s9cxq5ml22xmx3wkb201r5qgaa"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-catalyst-plugin-session" ,perl-catalyst-plugin-session)
       ("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-gd-securityimage" ,perl-gd-securityimage)
       ("perl-http-date" ,perl-http-date)))
    (home-page "http://search.cpan.org/dist/Catalyst-Plugin-Captcha")
    (synopsis "Captchas for Catalyst")
    (description "This plugin creates and validates Captcha images for
Catalyst.")
    (license (package-license perl))))

(define-public perl-catalyst-plugin-configloader
  (package
    (name "perl-catalyst-plugin-configloader")
    (version "0.34")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/B/BO/BOBTFISH/"
                           "Catalyst-Plugin-ConfigLoader-"
                           version ".tar.gz"))
       (sha256
        (base32
         "19j7p4v7mbx6wrmpvmrnd974apx7hdl2s095ga3b9zcbdrl77h5q"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-path-class" ,perl-path-class)))
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-config-any" ,perl-config-any)
       ("perl-data-visitor" ,perl-data-visitor)
       ("perl-mro-compat" ,perl-mro-compat)))
    (home-page "http://search.cpan.org/dist/Catalyst-Plugin-ConfigLoader")
    (synopsis "Load config files of various types")
    (description "This module will attempt to load find and load configuration
files of various types.  Currently it supports YAML, JSON, XML, INI and Perl
formats.")
    (license (package-license perl))))

(define-public perl-catalyst-plugin-session
  (package
    (name "perl-catalyst-plugin-session")
    (version "0.40")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/J/JJ/JJNAPIORK/"
                           "Catalyst-Plugin-Session-" version ".tar.gz"))
       (sha256
        (base32
         "171vi9xcl775scjaw4fcfdmqvz0rb1nr0xxg2gb3ng6bjzpslhgv"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-deep" ,perl-test-deep)
       ("perl-test-exception" ,perl-test-exception)))
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-moose" ,perl-moose)
       ("perl-moosex-emulate-class-accessor-fast"
        ,perl-moosex-emulate-class-accessor-fast)
       ("perl-mro-compat" ,perl-mro-compat)
       ("perl-namespace-clean" ,perl-namespace-clean)
       ("perl-object-signature" ,perl-object-signature)
       ("perl-test-www-mechanize-psgi" ,perl-test-www-mechanize-psgi)))
    (home-page "http://search.cpan.org/dist/Catalyst-Plugin-Session")
    (synopsis "Catalyst generic session plugin")
    (description "This plugin links the two pieces required for session
management in web applications together: the state, and the store.")
    (license (package-license perl))))

(define-public perl-catalyst-plugin-session-state-cookie
  (package
    (name "perl-catalyst-plugin-session-state-cookie")
    (version "0.17")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/M/MS/MSTROUT/"
                           "Catalyst-Plugin-Session-State-Cookie-"
                           version ".tar.gz"))
       (sha256
        (base32
         "1rvxbfnpf9x2pc2zgpazlcgdlr2dijmxgmcs0m5nazs0w6xikssb"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-catalyst-plugin-session" ,perl-catalyst-plugin-session)
       ("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-moose" ,perl-moose)
       ("perl-mro-compat" ,perl-mro-compat)
       ("perl-namespace-autoclean" ,perl-namespace-autoclean)))
    (home-page
     "http://search.cpan.org/dist/Catalyst-Plugin-Session-State-Cookie")
    (synopsis "Maintain session IDs using cookies")
    (description "In order for Catalyst::Plugin::Session to work, the session
ID needs to be stored on the client, and the session data needs to be stored
on the server.  This plugin stores the session ID on the client using the
cookie mechanism.")
    (license (package-license perl))))

(define-public perl-catalyst-plugin-session-store-fastmmap
  (package
    (name "perl-catalyst-plugin-session-store-fastmmap")
    (version "0.16")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/B/BO/BOBTFISH/"
                           "Catalyst-Plugin-Session-Store-FastMmap-"
                           version ".tar.gz"))
       (sha256
        (base32
         "0x3j6zv3wr41jlwr6yb2jpmcx019ibyn11y8653ffnwhpzbpzsxs"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-cache-fastmmap" ,perl-cache-fastmmap)
       ("perl-catalyst-plugin-session" ,perl-catalyst-plugin-session)
       ("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-moosex-emulate-class-accessor-fast"
        ,perl-moosex-emulate-class-accessor-fast)
       ("perl-mro-compat" ,perl-mro-compat)
       ("perl-path-class" ,perl-path-class)))
    (home-page
     "http://search.cpan.org/dist/Catalyst-Plugin-Session-Store-FastMmap")
    (synopsis "FastMmap session storage backend")
    (description "Catalyst::Plugin::Session::Store::FastMmap is a fast session
storage plugin for Catalyst that uses an mmap'ed file to act as a shared
memory interprocess cache.  It is based on Cache::FastMmap.")
    (license (package-license perl))))

(define-public perl-catalyst-plugin-stacktrace
  (package
    (name "perl-catalyst-plugin-stacktrace")
    (version "0.12")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/B/BO/BOBTFISH/"
                           "Catalyst-Plugin-StackTrace-" version ".tar.gz"))
       (sha256
        (base32
         "1b2ksz74cpigxqzf63rddar3vfmnbpwpdcbs11v0ml89pb8ar79j"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-devel-stacktrace" ,perl-devel-stacktrace)
       ("perl-mro-compat" ,perl-mro-compat)))
    (home-page "http://search.cpan.org/dist/Catalyst-Plugin-StackTrace")
    (synopsis "Stack trace on the Catalyst debug screen")
    (description "This plugin enhances the standard Catalyst debug screen by
including a stack trace of your application up to the point where the error
occurred.  Each stack frame is displayed along with the package name, line
number, file name, and code context surrounding the line number.")
    (license (package-license perl))))

(define-public perl-catalyst-plugin-static-simple
  (package
    (name "perl-catalyst-plugin-static-simple")
    (version "0.33")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/J/JJ/JJNAPIORK/"
                           "Catalyst-Plugin-Static-Simple-" version ".tar.gz"))
       (sha256
        (base32
         "1h8f12bhzh0ssq9gs8r9g3hqn8zn2k0q944vc1vm8j81bns16msy"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-mime-types" ,perl-mime-types)
       ("perl-moose" ,perl-moose)
       ("perl-moosex-types" ,perl-moosex-types)
       ("perl-namespace-autoclean" ,perl-namespace-autoclean)))
    (home-page "http://search.cpan.org/dist/Catalyst-Plugin-Static-Simple")
    (synopsis "Simple serving of static pages")
    (description "The Static::Simple plugin is designed to make serving static
content in your application during development quick and easy, without
requiring a single line of code from you.  This plugin detects static files by
looking at the file extension in the URL (such as .css or .png or .js).  The
plugin uses the lightweight MIME::Types module to map file extensions to
IANA-registered MIME types, and will serve your static files with the correct
MIME type directly to the browser, without being processed through Catalyst.")
    (license (package-license perl))))

(define-public perl-catalyst-runtime
  (package
    (name "perl-catalyst-runtime")
    (version "5.90082")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/J/JJ/JJNAPIORK/"
                           "Catalyst-Runtime-" version ".tar.gz"))
       (sha256
        (base32
         "1gs70nq4rikpq6siwds9disb1z03vwjzf979xi9kf7saa1drfncs"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-fatal" ,perl-test-fatal)))
    (propagated-inputs
     `(("perl-cgi-simple" ,perl-cgi-simple)
       ("perl-cgi-struct" ,perl-cgi-struct)
       ("perl-class-c3-adopt-next" ,perl-class-c3-adopt-next)
       ("perl-class-data-inheritable" ,perl-class-data-inheritable)
       ("perl-class-date" ,perl-class-date)
       ("perl-class-load" ,perl-class-load)
       ("perl-data-dump" ,perl-data-dump)
       ("perl-http-body" ,perl-http-body)
       ("perl-http-message" ,perl-http-message)
       ("perl-http-request-ascgi" ,perl-http-request-ascgi)
       ("perl-io-stringy" ,perl-io-stringy)
       ("perl-json-maybexs" ,perl-json-maybexs)
       ("perl-libwww" ,perl-libwww)
       ("perl-module-pluggable" ,perl-module-pluggable)
       ("perl-moose" ,perl-moose)
       ("perl-moosex-emulate-class-accessor-fast"
        ,perl-moosex-emulate-class-accessor-fast)
       ("perl-moosex-getopt" ,perl-moosex-getopt)
       ("perl-moosex-methodattributes" ,perl-moosex-methodattributes)
       ("perl-moosex-role-withoverloading" ,perl-moosex-role-withoverloading)
       ("perl-namespace-autoclean" ,perl-namespace-autoclean)
       ("perl-namespace-clean" ,perl-namespace-clean)
       ("perl-path-class" ,perl-path-class)
       ("perl-plack" ,perl-plack)
       ("perl-plack-middleware-fixmissingbodyinredirect"
        ,perl-plack-middleware-fixmissingbodyinredirect)
       ("perl-plack-middleware-methodoverride"
        ,perl-plack-middleware-methodoverride)
       ("perl-plack-middleware-removeredundantbody"
        ,perl-plack-middleware-removeredundantbody)
       ("perl-plack-middleware-reverseproxy"
        ,perl-plack-middleware-reverseproxy)
       ("perl-plack-test-externalserver" ,perl-plack-test-externalserver)
       ("perl-safe-isa" ,perl-safe-isa)
       ("perl-string-rewriteprefix" ,perl-string-rewriteprefix)
       ("perl-text-simpletable" ,perl-text-simpletable)
       ("perl-tree-simple" ,perl-tree-simple)
       ("perl-tree-simple-visitorfactory" ,perl-tree-simple-visitorfactory)
       ("perl-try-tiny" ,perl-try-tiny)
       ("perl-uri" ,perl-uri)
       ("perl-uri-ws" ,perl-uri-ws)))
    (home-page "http://search.cpan.org/dist/Catalyst-Runtime")
    (synopsis "The Catalyst Framework Runtime")
    (description "Catalyst is a modern framework for making web applications.
It is designed to make it easy to manage the various tasks you need to do to
run an application on the web, either by doing them itself, or by letting you
\"plug in\" existing Perl modules that do what you need.")
    (license (package-license perl))))

(define-public perl-catalyst-traitfor-request-proxybase
  (package
    (name "perl-catalyst-traitfor-request-proxybase")
    (version "0.000005")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/B/BO/BOBTFISH/"
                           "Catalyst-TraitFor-Request-ProxyBase-"
                           version ".tar.gz"))
       (sha256
        (base32
         "02kir63d5cs2ipj3fn1qlmmx3gqi1xqzrxfr4pv5vjhjgsm0zgx7"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-catalystx-roleapplicator" ,perl-catalystx-roleapplicator)
       ("perl-http-message" ,perl-http-message)))
    (propagated-inputs
     `(("perl-moose" ,perl-moose)
       ("perl-namespace-autoclean" ,perl-namespace-autoclean)
       ("perl-uri" ,perl-uri)))
    (home-page
     "http://search.cpan.org/dist/Catalyst-TraitFor-Request-ProxyBase")
    (synopsis "Replace request base with value passed by HTTP proxy")
    (description "This module is a Moose::Role which allows you more
flexibility in your application's deployment configurations when deployed
behind a proxy.  Using this module, the request base ($c->req->base) is
replaced with the contents of the X-Request-Base header.")
    (license (package-license perl))))

(define-public perl-catalyst-view-download
  (package
    (name "perl-catalyst-view-download")
    (version "0.09")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/G/GA/GAUDEON/"
                           "Catalyst-View-Download-" version ".tar.gz"))
       (sha256
        (base32
         "1qgq6y9iwfbhbkbgpw9czang2ami6z8jk1zlagrzdisy4igqzkvs"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-test-simple" ,perl-test-simple)
       ("perl-test-www-mechanize-catalyst" ,perl-test-www-mechanize-catalyst)
       ("perl-text-csv" ,perl-text-csv)
       ("perl-xml-simple" ,perl-xml-simple)))
    (home-page "http://search.cpan.org/dist/Catalyst-View-Download")
    (synopsis "Download data in many formats")
    (description "The purpose of this module is to provide a method for
downloading data into many supportable formats.  For example, downloading a
table based report in a variety of formats (CSV, HTML, etc.).")
    (license (package-license perl))))

(define-public perl-catalyst-view-json
  (package
    (name "perl-catalyst-view-json")
    (version "0.36")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/J/JJ/JJNAPIORK/"
                           "Catalyst-View-JSON-" version ".tar.gz"))
       (sha256
        (base32
         "0x943j1n2r0zqanyzdrs1xsnn8ayn2wqskn7h144xcqa6v6gcisl"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-yaml" ,perl-yaml)))
    (inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-json-maybexs" ,perl-json-maybexs)
       ("perl-mro-compat" ,perl-mro-compat)))
    (home-page "http://search.cpan.org/dist/Catalyst-View-JSON")
    (synopsis "Catalyst JSON view")
    (description "Catalyst::View::JSON is a Catalyst View handler that returns
stash data in JSON format.")
    (license (package-license perl))))

(define-public perl-catalyst-view-tt
  (package
    (name "perl-catalyst-view-tt")
    (version "0.44")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/E/ET/ETHER/"
                           "Catalyst-View-TT-" version ".tar.gz"))
     (sha256
      (base32
       "06d1zg4nbb6kcyjbnyxrkf8z4zlscxr8650d94f7187jygfl8rvh"))))
  (build-system perl-build-system)
  (propagated-inputs
   `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
     ("perl-class-accessor" ,perl-class-accessor)
     ("perl-data-dump" ,perl-data-dump)
     ("perl-mro-compat" ,perl-mro-compat)
     ("perl-path-class" ,perl-path-class)
     ("perl-template-timer" ,perl-template-timer)
     ("perl-template-toolkit" ,perl-template-toolkit)))
  (home-page "http://search.cpan.org/dist/Catalyst-View-TT")
  (synopsis "Template View Class")
  (description "This module is a Catalyst view class for the Template
Toolkit.")
  (license (package-license perl))))

(define-public perl-catalystx-component-traits
  (package
    (name "perl-catalystx-component-traits")
    (version "0.19")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/R/RK/RKITOVER/"
                           "CatalystX-Component-Traits-" version ".tar.gz"))
       (sha256
        (base32
         "0iq4ci8m6g2c4g01fvdl568y7pjz28f3widk986v3pyhr7ll8j88"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-moose" ,perl-moose)
       ("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-moosex-methodattributes" ,perl-moosex-methodattributes)))
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-class-load" ,perl-class-load)
       ("perl-moose" ,perl-moose)
       ("perl-moosex-traits-pluggable" ,perl-moosex-traits-pluggable)
       ("perl-namespace-autoclean" ,perl-namespace-autoclean)
       ("perl-list-moreutils" ,perl-list-moreutils)))
    (home-page "http://search.cpan.org/dist/CatalystX-Component-Traits")
    (synopsis "Trait Loading and Resolution for Catalyst Components")
    (description "Adds a \"COMPONENT\" in Catalyst::Component method to your
Catalyst component base class that reads the optional \"traits\" parameter
from app and component config and instantiates the component subclass with
those traits using \"new_with_traits\" in MooseX::Traits from
MooseX::Traits::Pluggable.")
    (license (package-license perl))))

(define-public perl-catalystx-roleapplicator
  (package
    (name "perl-catalystx-roleapplicator")
    (version "0.005")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/H/HD/HDP/"
                           "CatalystX-RoleApplicator-" version ".tar.gz"))
       (sha256
        (base32
         "0vwaapxn8g5hs2xp63c4dwv9jmapmji4272fakssvgc9frklg3p2"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-moose" ,perl-moose)
       ("perl-moosex-relatedclassroles" ,perl-moosex-relatedclassroles)))
    (home-page "http://search.cpan.org/dist/CatalystX-RoleApplicator")
    (synopsis "Apply roles to Catalyst classes")
    (description "CatalystX::RoleApplicator applies roles to Catalyst
application classes.")
    (license (package-license perl))))

(define-public perl-catalystx-script-server-starman
  (package
    (name "perl-catalystx-script-server-starman")
    (version "0.02")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/A/AB/ABRAXXA/"
                           "CatalystX-Script-Server-Starman-"
                           version ".tar.gz"))
       (sha256
        (base32
         "0h02mpkc4cmi3jpvcd7iw7xyzx55bqvvl1qkf967gqkvpklm0qx5"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-www-mechanize-catalyst" ,perl-test-www-mechanize-catalyst)))
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-moose" ,perl-moose)
       ("perl-namespace-autoclean" ,perl-namespace-autoclean)
       ("starman" ,starman)))
    (home-page "http://search.cpan.org/dist/CatalystX-Script-Server-Starman")
    (synopsis "Catalyst development server with Starman")
    (description "This module provides a Catalyst extension to replace the
development server with Starman.")
    (license (package-license perl))))

(define-public perl-cgi
  (package
    (name "perl-cgi")
    (version "4.35")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/L/LE/LEEJO/"
                           "CGI-" version ".tar.gz"))
       (sha256
        (base32
         "07gwnlc7vq58fjwmfsrv0hfyirqqdrpjhf89caq34rjrkz2wsd0b"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-deep" ,perl-test-deep)
       ("perl-test-nowarnings" ,perl-test-nowarnings)
       ("perl-test-warn" ,perl-test-warn)))
    (propagated-inputs
     `(("perl-html-parser" ,perl-html-parser)))
    (home-page "http://search.cpan.org/dist/CGI")
    (synopsis "Handle Common Gateway Interface requests and responses")
    (description "CGI.pm is a stable, complete and mature solution for
processing and preparing HTTP requests and responses.  Major features include
processing form submissions, file uploads, reading and writing cookies, query
string generation and manipulation, and processing and preparing HTTP
headers.")
    (license (package-license perl))))

(define-public perl-cgi-simple
  (package
    (name "perl-cgi-simple")
    (version "1.115")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/S/SZ/SZABGAB/"
                           "CGI-Simple-" version ".tar.gz"))
       (sha256
        (base32
         "1nkyb1m1g5r47xykflf68dplanih5p15njv82frbgbsms34kp1sg"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-module-build" ,perl-module-build)
       ("perl-io-stringy" ,perl-io-stringy))) ;for IO::Scalar
    (home-page "http://search.cpan.org/dist/CGI-Simple")
    (synopsis "CGI interface that is CGI.pm compliant")
    (description "CGI::Simple provides a relatively lightweight drop in
replacement for CGI.pm.  It shares an identical OO interface to CGI.pm for
parameter parsing, file upload, cookie handling and header generation.")
    (license (package-license perl))))

(define-public perl-cgi-struct
  (package
    (name "perl-cgi-struct")
    (version "1.21")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/F/FU/FULLERMD/"
                           "CGI-Struct-" version ".tar.gz"))
       (sha256
        (base32
         "0v4xq2qpryr7i6jngw1wpn8yr2kiib10yxp4aih90vfdznkqsgfi"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-deep" ,perl-test-deep)))
    (home-page "http://search.cpan.org/dist/CGI-Struct")
    (synopsis "Build structures from CGI data")
    (description "This is a module for building structured data from CGI
inputs, in a manner reminiscent of how PHP does.")
    (license l:bsd-2)))

(define-public perl-datetime-format-http
  (package
    (name "perl-datetime-format-http")
    (version "0.42")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/C/CK/CKRAS/"
                           "DateTime-Format-HTTP-" version ".tar.gz"))
       (sha256
        (base32
         "0h6qqdg1yzqkdxp7hqlp0qa7d1y64nilgimxs79dys2ryjfpcknh"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-module-build" ,perl-module-build)))
    (propagated-inputs
     `(("perl-datetime" ,perl-datetime)
       ("perl-http-date" ,perl-http-date)))
    (home-page "http://search.cpan.org/dist/DateTime-Format-HTTP")
    (synopsis "Date conversion routines")
    (description "This module provides functions that deal with the date
formats used by the HTTP protocol.")
    (license (package-license perl))))

(define-public perl-digest-md5-file
  (package
    (name "perl-digest-md5-file")
    (version "0.08")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/D/DM/DMUEY/"
                           "Digest-MD5-File-" version ".tar.gz"))
       (sha256
        (base32
         "060jzf45dlwysw5wsm7av1wvpl06xgk415kwwpvv89r6wda3md5d"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-libwww" ,perl-libwww)))
    (home-page "http://search.cpan.org/dist/Digest-MD5-File")
    (synopsis "MD5 sums for files and urls")
    (description "Digest::MD5::File is a Perl extension for getting MD5 sums
for files and urls.")
    (license (package-license perl))))

(define-public perl-encode-locale
  (package
    (name "perl-encode-locale")
    (version "1.05")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/G/GA/GAAS/Encode-Locale-"
                   version ".tar.gz"))
             (sha256
              (base32
               "1h8fvcdg3n20c2yp7107yhdkkx78534s9hnvn7ps8hpmf4ks0vqp"))))
    (build-system perl-build-system)
    (license (package-license perl))
    (synopsis "Perl locale encoding determination")
    (description
     "The POSIX locale system is used to specify both the language
conventions requested by the user and the preferred character set to
consume and output.  The Encode::Locale module looks up the charset and
encoding (called a CODESET in the locale jargon) and arranges for the
Encode module to know this encoding under the name \"locale\".  It means
bytes obtained from the environment can be converted to Unicode strings
by calling Encode::encode(locale => $bytes) and converted back again
with Encode::decode(locale => $string).")
    (home-page "http://search.cpan.org/~gaas/Encode-Locale/")))

(define-public perl-feed-find
  (package
    (name "perl-feed-find")
    (version "0.07")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/B/BT/BTROTT/"
                                  "Feed-Find-" version ".tar.gz"))
              (sha256
               (base32
                "0sa33cm8ww55cymnl8j7b5yspi2y5xkkkgqqa4h6fs3wdqylz600"))))
    (build-system perl-build-system)
    (arguments
     ;; Tests expect to query files at http://stupidfool.org/perl/feeds/
     `(#:tests? #f))
    (inputs
     `(("perl-class-errorhandler" ,perl-class-errorhandler)
       ("perl-html-parser" ,perl-html-parser)
       ("perl-libwww" ,perl-libwww)
       ("perl-uri" ,perl-uri)))
    (home-page "http://search.cpan.org/dist/Feed-Find")
    (synopsis "Syndication feed auto-discovery")
    (description "@code{Feed::Find} implements feed auto-discovery for finding
syndication feeds, given a URI.  It will discover the following feed formats:
RSS 0.91, RSS 1.0, RSS 2.0, Atom.")
    (license (package-license perl))))

(define-public perl-file-listing
  (package
    (name "perl-file-listing")
    (version "6.04")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/G/GA/GAAS/File-Listing-"
                   version ".tar.gz"))
             (sha256
              (base32
               "1xcwjlnxaiwwpn41a5yi6nz95ywh3szq5chdxiwj36kqsvy5000y"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-http-date" ,perl-http-date)))
    (license (package-license perl))
    (synopsis "Perl directory listing parser")
    (description
     "The File::Listing module exports a single function called parse_dir(),
which can be used to parse directory listings.")
    (home-page "http://search.cpan.org/~gaas/File-Listing/")))

(define-public perl-finance-quote
  (package
   (name "perl-finance-quote")
   (version "1.38")
   (source
    (origin
      (method url-fetch)
      (uri (string-append "https://cpan.metacpan.org/authors/id/E/EC/ECOCODE/"
                          "Finance-Quote-" version ".tar.gz"))
      (sha256
       (base32
        "0zhqb27y4vdxn476s2kwm9zl2f970yjcyyybnjm9b406krr2fm59"))
      (patches (search-patches
                "perl-finance-quote-unuse-mozilla-ca.patch"))))
   (build-system perl-build-system)
   (propagated-inputs
    `(("perl-cgi" ,perl-cgi)
      ("perl-datetime" ,perl-datetime)
      ("perl-html-parser" ,perl-html-parser)
      ("perl-html-tableextract" ,perl-html-tableextract)
      ("perl-html-tree" ,perl-html-tree)
      ("perl-http-cookies" ,perl-http-cookies)
      ("perl-http-message" ,perl-http-message)
      ("perl-json" ,perl-json)
      ("perl-libwww" ,perl-libwww)
      ("perl-lwp-protocol-https" ,perl-lwp-protocol-https)
      ("perl-uri" ,perl-uri)))
   (home-page "http://search.cpan.org/dist/Finance-Quote")
   (synopsis "Stock and mutual fund quotes")
   (description
    "Finance::Quote gets stock quotes from various internet sources, including
Yahoo! Finance, Fidelity Investments, and the Australian Stock Exchange.")
   (license l:gpl2)))

(define-public perl-gssapi
  (package
    (name "perl-gssapi")
    (version "0.28")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/A/AG/AGROLMS/"
                           "GSSAPI-" version ".tar.gz"))
       (sha256
        (base32
         "1mkhwxjjlhr58pd770i9gnf7zy7jj092iv6jfbnb8bvnc5xjr3vx"))))
    (build-system perl-build-system)
    (inputs `(("gssapi" ,mit-krb5)))
    (arguments
     `(#:make-maker-flags
       `(,(string-append "--gssapiimpl=" (assoc-ref %build-inputs "gssapi")))))
    (home-page "http://search.cpan.org/dist/GSSAPI")
    (synopsis "Perl extension providing access to the GSSAPIv2 library")
    (description "This is a Perl extension for using GSSAPI C bindings as
described in RFC 2744.")
    (license (package-license perl))))

(define-public perl-html-element-extended
  (package
    (name "perl-html-element-extended")
    (version "1.18")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/M/MS/MSISK/"
                           "HTML-Element-Extended-" version ".tar.gz"))
       (sha256
        (base32
         "0axknss8c368r5i082yhkfj8mq0w4nglfrpcxcayyzzj13qimvzk"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-html-tree" ,perl-html-tree)))
    (home-page "http://search.cpan.org/dist/HTML-Element-Extended")
    (synopsis "Manipulate tables of HTML::Element")
    (description
     "HTML::Element::Extended is a Perl extension for manipulating a table
composed of HTML::Element style components.")
    (license (package-license perl))))

(define-public perl-html-form
  (package
    (name "perl-html-form")
    (version "6.03")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/G/GA/GAAS/"
                           "HTML-Form-" version ".tar.gz"))
       (sha256
        (base32
         "0dpwr7yz6hjc3bcqgcbdzjjk9l58ycdjmbam9nfcmm85y2a1vh38"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-html-parser" ,perl-html-parser)
       ("perl-html-tagset" ,perl-html-tagset)
       ("perl-http-message" ,perl-http-message)
       ("perl-lwp-mediatypes" ,perl-lwp-mediatypes)
       ("perl-uri" ,perl-uri)))
    (home-page "http://search.cpan.org/dist/HTML-Form")
    (synopsis "Perl class representing an HTML form element")
    (description "Objects of the HTML::Form class represents a single HTML
<form> ... </form> instance.")
    (license (package-license perl))))

(define-public perl-html-lint
  (package
    (name "perl-html-lint")
    (version "2.20")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/P/PE/PETDANCE/"
                           "HTML-Lint-" version ".tar.gz"))
       (sha256
        (base32
         "15vrqjnlb0f8rib1kqdf4islqy6i33h08wy7b1bkgd550p7lfjwk"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-html-parser" ,perl-html-parser)
       ("perl-html-tagset" ,perl-html-tagset)
       ("perl-libwww" ,perl-libwww)))
    (home-page "http://search.cpan.org/dist/HTML-Lint")
    (synopsis "Check for HTML errors in a string or file")
    (description "HTML::Lint is a pure-Perl HTML parser and checker for
syntactic legitmacy.")
    (license l:artistic2.0)))

(define-public perl-html-tableextract
  (package
    (name "perl-html-tableextract")
    (version "2.13")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://cpan.metacpan.org/authors/id/M/MS/MSISK/"
                           "HTML-TableExtract-" version ".tar.gz"))
       (sha256
        (base32
         "01jimmss3q68a89696wmclvqwb2ybz6xgabpnbp6mm6jcni82z8a"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-html-element-extended" ,perl-html-element-extended)
       ("perl-html-parser" ,perl-html-parser)))
    (home-page "http://search.cpan.org/dist/HTML-TableExtract")
    (synopsis "Extract contents from HTML tables")
    (description
     "HTML::TableExtract is a Perl module for extracting the content contained
in tables within an HTML document, either as text or encoded element trees.")
    (license (package-license perl))))

(define-public perl-html-tree
  (package
    (name "perl-html-tree")
    (version "5.03")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/C/CJ/CJM/"
                           "HTML-Tree-" version ".tar.gz"))
       (sha256
        (base32
         "13qlqbpixw470gnck0xgny8hyjj576m8y24bba2p9ai2lvy76vbx"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-module-build" ,perl-module-build)
       ("perl-test-fatal" ,perl-test-fatal)))
    (propagated-inputs
     `(("perl-html-parser" ,perl-html-parser)
       ("perl-html-tagset" ,perl-html-tagset)
       ("perl-libwww" ,perl-libwww)))
    (home-page "http://search.cpan.org/dist/HTML-Tree")
    (synopsis "Work with HTML in a DOM-like tree structure")
    (description "This distribution contains a suite of modules for
representing, creating, and extracting information from HTML syntax trees.")
    (license (package-license perl))))

(define-public perl-html-parser
  (package
    (name "perl-html-parser")
    (version "3.72")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/G/GA/GAAS/HTML-Parser-"
                   version ".tar.gz"))
             (sha256
              (base32
               "12v05ywlnsi9lc17z32k9jxx3sj1viy7y1wpl7n4az76v7hwfa7c"))))
    (build-system perl-build-system)
    (inputs
     `(("perl-html-tagset" ,perl-html-tagset)
       ("perl-http-message" ,perl-http-message)))
    (license (package-license perl))
    (synopsis "Perl HTML parser class")
    (description
     "Objects of the HTML::Parser class will recognize markup and separate
it from plain text (alias data content) in HTML documents.  As different
kinds of markup and text are recognized, the corresponding event handlers
are invoked.")
    (home-page "http://search.cpan.org/~gaas/HTML-Parser/")))

(define-public perl-html-tagset
  (package
    (name "perl-html-tagset")
    (version "3.20")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/P/PE/PETDANCE/HTML-Tagset-"
                   version ".tar.gz"))
             (sha256
              (base32
               "1qh8249wgr4v9vgghq77zh1d2zs176bir223a8gh3k9nksn7vcdd"))))
    (build-system perl-build-system)
    (license (package-license perl))
    (synopsis "Perl data tables useful in parsing HTML")
    (description
     "The HTML::Tagset module contains several data tables useful in various
kinds of HTML parsing operations.")
    (home-page "http://search.cpan.org/dist/HTML-Tagset/")))

(define-public perl-html-template
  (package
    (name "perl-html-template")
    (version "2.95")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/W/WO/WONKO/"
                                  "HTML-Template-" version ".tar.gz"))
              (sha256
               (base32
                "07ahpfgidxsw2yb7y8i7bbr8s64aq6qgq832h9jswmksxbd0l43q"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-cgi" ,perl-cgi)))
    (home-page "http://search.cpan.org/dist/HTML-Template")
    (synopsis "HTML-like templates")
    (description
     "This module attempts to make using HTML templates simple and natural.
It extends standard HTML with a few new HTML-esque tags: @code{<TMPL_VAR>},
@code{<TMPL_LOOP>}, @code{<TMPL_INCLUDE>}, @code{<TMPL_IF>},
@code{<TMPL_ELSE>} and @code{<TMPL_UNLESS>}.  The file written with HTML and
these new tags is called a template.  Using this module you fill in the values
for the variables, loops and branches declared in the template.  This allows
you to separate design from the data.")
    (license (package-license perl))))

(define-public perl-http-body
  (package
    (name "perl-http-body")
    (version "1.22")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/G/GE/GETTY/"
                           "HTTP-Body-" version ".tar.gz"))
       (sha256
        (base32
         "15vj488i62mdp4ps9k77h39prj70i7anb6b0j8nm7l9vbdc2q3gw"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-deep" ,perl-test-deep)))
    (propagated-inputs
     `(("perl-file-temp" ,perl-file-temp)
       ("perl-http-message" ,perl-http-message))) ;For HTTP::Headers
    (home-page "http://search.cpan.org/dist/HTTP-Body")
    (synopsis "HTTP Body Parser")
    (description "HTTP::Body parses chunks of HTTP POST data and supports
application/octet-stream, application/json, application/x-www-form-urlencoded,
and multipart/form-data.")
    (license (package-license perl))))

(define-public perl-http-cookiejar
  (package
    (name "perl-http-cookiejar")
    (version "0.008")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/D/DA/DAGOLDEN/"
                           "HTTP-CookieJar-" version ".tar.gz"))
       (sha256
        (base32
         "0rfw6avcralggs7bf7n86flvhaahxjnqzvpwszp0sk4z4wwy01wm"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-deep" ,perl-test-deep)
       ("perl-test-requires" ,perl-test-requires)
       ("perl-time-mock" ,perl-time-mock)
       ("perl-uri" ,perl-uri)))
    (inputs
     `(("perl-time-local" ,perl-time-local)
       ("perl-http-date" ,perl-http-date)))
    (home-page "http://search.cpan.org/dist/HTTP-CookieJar")
    (synopsis "Minimalist HTTP user agent cookie jar")
    (description "This module implements a minimalist HTTP user agent cookie
jar in conformance with RFC 6265 <http://tools.ietf.org/html/rfc6265>.")
    (license l:asl2.0)))

(define-public perl-http-cookies
  (package
    (name "perl-http-cookies")
    (version "6.01")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/G/GA/GAAS/HTTP-Cookies-"
                   version ".tar.gz"))
             (sha256
              (base32
               "087bqmg22dg3vj7gssh3pcsh9y1scimkbl5h1kc8jqyfhgisvlzm"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-http-message" ,perl-http-message)))
    (license (package-license perl))
    (synopsis "Perl HTTP cookie jars")
    (description
     "The HTTP::Cookies class is for objects that represent a cookie jar,
that is, a database of all the HTTP cookies that a given LWP::UserAgent
object knows about.")
    (home-page "http://search.cpan.org/~gaas/HTTP-Cookies/")))

(define-public perl-http-daemon
  (package
    (name "perl-http-daemon")
    (version "6.01")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/G/GA/GAAS/HTTP-Daemon-"
                   version ".tar.gz"))
             (sha256
              (base32
               "1hmd2isrkilf0q0nkxms1q64kikjmcw9imbvrjgky6kh89vqdza3"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-http-message" ,perl-http-message)
       ("perl-lwp-mediatypes" ,perl-lwp-mediatypes)))
    (license (package-license perl))
    (synopsis "Perl simple http server class")
    (description
     "Instances of the HTTP::Daemon class are HTTP/1.1 servers that listen
on a socket for incoming requests.  The HTTP::Daemon is a subclass of
IO::Socket::INET, so you can perform socket operations directly on it too.")
    (home-page "http://search.cpan.org/~gaas/HTTP-Daemon/")))

(define-public perl-http-date
  (package
    (name "perl-http-date")
    (version "6.02")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/G/GA/GAAS/HTTP-Date-"
                   version ".tar.gz"))
             (sha256
              (base32
               "0cz357kafhhzw7w59iyi0wvhw7rlh5g1lh38230ckw7rl0fr9fg8"))))
    (build-system perl-build-system)
    (license (package-license perl))
    (synopsis "Perl date conversion routines")
    (description
     "The HTTP::Date module provides functions that deal with date formats
used by the HTTP protocol (and then some more).")
    (home-page "http://search.cpan.org/~gaas/HTTP-Date/")))

(define-public perl-http-message
  (package
    (name "perl-http-message")
    (version "6.11")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/E/ET/ETHER/HTTP-Message-"
                   version ".tar.gz"))
             (sha256
              (base32
               "06yq6cjx4vzl4if4ykap77xsrrd8aa7ish90k7cqi8g6g83nicz7"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-encode-locale" ,perl-encode-locale)
       ("perl-http-date" ,perl-http-date)
       ("perl-io-html" ,perl-io-html)
       ("perl-lwp-mediatypes" ,perl-lwp-mediatypes)
       ("perl-uri" ,perl-uri)))
    (license (package-license perl))
    (synopsis "Perl HTTP style message")
    (description
     "An HTTP::Message object contains some headers and a content body.")
    (home-page "http://search.cpan.org/~ether/HTTP-Message/")))

(define-public perl-http-negotiate
  (package
    (name "perl-http-negotiate")
    (version "6.01")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/G/GA/GAAS/HTTP-Negotiate-"
                   version ".tar.gz"))
             (sha256
              (base32
               "05p053vjs5g91v5cmjnny7a3xzddz5k7vnjw81wfh01ilqg9qwhw"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-http-message" ,perl-http-message)))
    (license (package-license perl))
    (synopsis "Perl http content negotiation")
    (description
     "The HTTP::Negotiate module provides a complete implementation of the
HTTP content negotiation algorithm specified in
draft-ietf-http-v11-spec-00.ps chapter 12.  Content negotiation allows for
the selection of a preferred content representation based upon attributes
of the negotiable variants and the value of the various Accept* header
fields in the request.")
    (home-page "http://search.cpan.org/~gaas/HTTP-Negotiate/")))

(define-public perl-http-parser
  (package
    (name "perl-http-parser")
    (version "0.06")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/E/ED/EDECA/"
                           "HTTP-Parser-" version ".tar.gz"))
       (sha256
        (base32
         "0idwq3jk595xil65lmxz128ha7s3r2n5zknisddpgwnqrghs3igq"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-http-message" ,perl-http-message)
       ("perl-uri" ,perl-uri)))
    (home-page "http://search.cpan.org/dist/HTTP-Parser")
    (synopsis "Parse HTTP/1.1 requests")
    (description "This is an HTTP request parser.  It takes chunks of text as
received and returns a 'hint' as to what is required, or returns the
HTTP::Request when a complete request has been read.  HTTP/1.1 chunking is
supported.")
    (license (package-license perl))))

(define-public perl-http-parser-xs
  (package
    (name "perl-http-parser-xs")
    (version "0.17")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/K/KA/KAZUHO/"
                           "HTTP-Parser-XS-" version ".tar.gz"))
       (sha256
        (base32
         "02d84xq1mm53c7jl33qyb7v5w4372vydp74z6qj0vc96wcrnhkkr"))))
    (build-system perl-build-system)
    (home-page "http://search.cpan.org/dist/HTTP-Parser-XS")
    (synopsis "Fast HTTP request parser")
    (description "HTTP::Parser::XS is a fast, primitive HTTP request/response
parser.")
    (license (package-license perl))))

(define-public perl-http-request-ascgi
  (package
    (name "perl-http-request-ascgi")
    (version "1.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/F/FL/FLORA/"
                           "HTTP-Request-AsCGI-" version ".tar.gz"))
       (sha256
        (base32
         "1smwmiarwcgq7vjdblnb6ldi2x1s5sk5p15p7xvm5byiqq3znnwl"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-class-accessor" ,perl-class-accessor)
       ("perl-http-message" ,perl-http-message)))
    (home-page "http://search.cpan.org/dist/HTTP-Request-AsCGI")
    (synopsis "Set up a CGI environment from an HTTP::Request")
    (description "This module provides a convenient way to set up a CGI
environment from an HTTP::Request.")
    (license (package-license perl))))

(define-public perl-http-server-simple
  (package
    (name "perl-http-server-simple")
    (version "0.51")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/B/BP/BPS/"
                           "HTTP-Server-Simple-" version ".tar.gz"))
       (sha256
        (base32
         "1yvd2g57z2kq00q5i3zzfi15k98qgbif3vghjsda6v612agmrp5r"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-cgi" ,perl-cgi)))
    (arguments
     ;; See the discussion of a related tests issue at
     ;; https://lists.gnu.org/archive/html/guix-devel/2015-01/msg00346.html
     `(#:tests? #f))
    (home-page "http://search.cpan.org/dist/HTTP-Server-Simple")
    (synopsis "Lightweight HTTP server")
    (description "HTTP::Server::Simple is a simple standalone HTTP daemon with
no non-core module dependencies.  It can be used for building a standalone
http-based UI to your existing tools.")
    (license (package-license perl))))

(define-public perl-http-tiny
  (package
    (name "perl-http-tiny")
    (version "0.070")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/D/DA/DAGOLDEN/"
                           "HTTP-Tiny-" version ".tar.gz"))
       (sha256
        (base32
         "0cvp5yqrni6qydpsa8fpkbm82zfwmy9js8jsvyj8gs3dx78qbwvl"))))
    (build-system perl-build-system)
    (inputs
     `(("perl-http-cookiejar" ,perl-http-cookiejar)
       ("perl-io-socket-ip" ,perl-io-socket-ip)
       ("perl-io-socket-ssl" ,perl-io-socket-ssl)
       ("perl-mozilla-ca" ,perl-mozilla-ca)
       ("perl-net-ssleay" ,perl-net-ssleay)))
    (home-page "http://search.cpan.org/dist/HTTP-Tiny")
    (synopsis "HTTP/1.1 client")
    (description "This is a very simple HTTP/1.1 client, designed for doing
simple requests without the overhead of a large framework like LWP::UserAgent.
It supports proxies and redirection.  It also correctly resumes after EINTR.")
    (license (package-license perl))))

(define-public perl-io-html
  (package
    (name "perl-io-html")
    (version "1.00")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/C/CJ/CJM/IO-HTML-"
                   version ".tar.gz"))
             (sha256
              (base32
               "06nj3a0xgp5jxwxx6ayglfk2v7npf5a7gwkqsjlkapjkybarzqh4"))))
    (build-system perl-build-system)
    (license (package-license perl))
    (synopsis "Perl module to open an HTML file with automatic charset detection")
    (description
     "IO::HTML provides an easy way to open a file containing HTML while
automatically determining its encoding.  It uses the HTML5 encoding sniffing
algorithm specified in section 8.2.2.1 of the draft standard.")
    (home-page "http://search.cpan.org/~cjm/IO-HTML/")))

(define-public perl-io-socket-ip
  (package
    (name "perl-io-socket-ip")
    (version "0.36")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/P/PE/PEVANS/"
                           "IO-Socket-IP-" version ".tar.gz"))
       (sha256
        (base32
         "0ky20hmln6waipzqikizyw04vpszf70fgpshz7ib8zv8480ri456"))))
    (build-system perl-build-system)
    (native-inputs `(("perl-module-build" ,perl-module-build)))
    (home-page "http://search.cpan.org/dist/IO-Socket-IP")
    (synopsis "Family-neutral IP socket supporting both IPv4 and IPv6")
    (description "This module provides a protocol-independent way to use IPv4
and IPv6 sockets, intended as a replacement for IO::Socket::INET.")
    (license (package-license perl))))

(define-public perl-io-socket-ssl
  (package
    (name "perl-io-socket-ssl")
    (version "2.038")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/S/SU/SULLR/"
                                  "IO-Socket-SSL-" version ".tar.gz"))
              (sha256
               (base32
                "11fiifxyvn7njc9p52wgygyw24jz7rh7gnz2ikjphr4l4x9f03rx"))
              (patches (search-patches
                        "perl-io-socket-ssl-openssl-1.0.2f-fix.patch"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-net-ssleay" ,perl-net-ssleay)
       ;; for IDN support
       ("perl-uri" ,perl-uri)))
    (synopsis "Nearly transparent SSL encapsulation for IO::Socket::INET")
    (description
     "IO::Socket::SSL makes using SSL/TLS much easier by wrapping the
necessary functionality into the familiar IO::Socket interface and providing
secure defaults whenever possible.  This way existing applications can be made
SSL-aware without much effort, at least if you do blocking I/O and don't use
select or poll.")
    (license (package-license perl))
    (home-page "https://github.com/noxxi/p5-io-socket-ssl")))

(define-public perl-libwww
  (package
    (name "perl-libwww")
    (version "6.15")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/E/ET/ETHER/libwww-perl-"
                   version ".tar.gz"))
             (sha256
              (base32
               "08l3mpgcvm4ipn1zggymqgk402apf35xyds43i8c07hvq92rsd3g"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-encode-locale" ,perl-encode-locale)
       ("perl-file-listing" ,perl-file-listing)
       ("perl-html-parser" ,perl-html-parser)
       ("perl-http-cookies" ,perl-http-cookies)
       ("perl-http-daemon" ,perl-http-daemon)
       ("perl-http-date" ,perl-http-date)
       ("perl-http-message" ,perl-http-message)
       ("perl-http-negotiate" ,perl-http-negotiate)
       ("perl-net-http" ,perl-net-http)
       ("perl-uri" ,perl-uri)
       ("perl-www-robotrules" ,perl-www-robotrules)))
    (license (package-license perl))
    (synopsis "Perl modules for the WWW")
    (description
     "The libwww-perl collection is a set of Perl modules which provides a
simple and consistent application programming interface to the
World-Wide Web.  The main focus of the library is to provide classes
and functions that allow you to write WWW clients.  The library also
contains modules that are of more general use and even classes that
help you implement simple HTTP servers.")
    (home-page "http://search.cpan.org/dist/libwww-perl/")))

(define-public perl-lwp-mediatypes
  (package
    (name "perl-lwp-mediatypes")
    (version "6.02")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/G/GA/GAAS/LWP-MediaTypes-"
                   version ".tar.gz"))
             (sha256
              (base32
               "0xmnblp962qy02akah30sji8bxrqcyqlff2w95l199ghql60ny8q"))))
    (build-system perl-build-system)
    (license (package-license perl))
    (synopsis "Perl module to guess the media type for a file or a URL")
    (description
     "The LWP::MediaTypes module provides functions for handling media (also
known as MIME) types and encodings.  The mapping from file extensions to
media types is defined by the media.types file.  If the ~/.media.types file
exists it is used instead.")
    (home-page "http://search.cpan.org/~gaas/LWP-MediaTypes/")))

(define-public perl-lwp-protocol-https
  (package
    (name "perl-lwp-protocol-https")
    (version "6.06")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/M/MS/MSCHILLI/"
                           "LWP-Protocol-https-" version ".tar.gz"))
       (sha256
        (base32
         "1vxdjqj4bwq56m9h1bqqwkk3c6jr76f2zqzvwa26yjng3p686v5q"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-io-socket-ssl" ,perl-io-socket-ssl)
       ("perl-libwww" ,perl-libwww)
       ;; Users should instead make sure SSL_ca_path is set properly.
       ;; ("perl-mozilla-ca" ,perl-mozilla-ca)
       ("perl-net-http" ,perl-net-http)))
    (home-page "http://search.cpan.org/dist/LWP-Protocol-https")
    (synopsis "HTTPS support for LWP::UserAgent")
    (description "The LWP::Protocol::https module provides support for using
https schemed URLs with LWP.")
    (license (package-license perl))))

(define-public perl-lwp-useragent-determined
  (package
    (name "perl-lwp-useragent-determined")
    (version "1.07")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/A/AL/ALEXMV/"
                           "LWP-UserAgent-Determined-" version ".tar.gz"))
       (sha256
        (base32
         "0lyvbpjng7yfvyha9rp2y2c6liz5hhplmd2grc8jlsfkih7dbn06"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-libwww" ,perl-libwww)))
    (home-page "http://search.cpan.org/dist/LWP-UserAgent-Determined")
    (synopsis "Virtual browser that retries errors")
    (description "LWP::UserAgent::Determined works just like LWP::UserAgent,
except that when you use it to get a web page but run into a
possibly-temporary error (like a DNS lookup timeout), it'll wait a few seconds
and retry a few times.")
    (license (package-license perl))))

(define-public perl-net-amazon-s3
  (package
    (name "perl-net-amazon-s3")
    (version "0.60")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/P/PF/PFIG/"
                           "Net-Amazon-S3-" version ".tar.gz"))
       (sha256
        (base32
         "10dcsq4s2kc9cb1vccx17r187c81drirc3s1hbxh3rb8489kg2b2"))
       (patches (search-patches
                 "perl-net-amazon-s3-moose-warning.patch"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-libwww" ,perl-libwww)
       ("perl-test-exception" ,perl-test-exception)))
    (propagated-inputs
     `(("perl-data-stream-bulk" ,perl-data-stream-bulk)
       ("perl-datetime-format-http" ,perl-datetime-format-http)
       ("perl-digest-hmac" ,perl-digest-hmac)
       ("perl-digest-md5-file" ,perl-digest-md5-file)
       ("perl-file-find-rule" ,perl-file-find-rule)
       ("perl-http-date" ,perl-http-date)
       ("perl-http-message" ,perl-http-message)
       ("perl-lwp-useragent-determined" ,perl-lwp-useragent-determined)
       ("perl-mime-types" ,perl-mime-types)
       ("perl-moose" ,perl-moose)
       ("perl-moosex-strictconstructor" ,perl-moosex-strictconstructor)
       ("perl-moosex-types-datetime-morecoercions"
        ,perl-moosex-types-datetime-morecoercions)
       ("perl-path-class" ,perl-path-class)
       ("perl-regexp-common" ,perl-regexp-common)
       ("perl-term-encoding" ,perl-term-encoding)
       ("perl-term-progressbar-simple" ,perl-term-progressbar-simple)
       ("perl-uri" ,perl-uri)
       ("perl-xml-libxml" ,perl-xml-libxml)))
    (home-page "http://search.cpan.org/dist/Net-Amazon-S3")
    (synopsis "Perl interface to Amazon S3")
    (description "This module provides a Perlish interface to Amazon S3.")
    (license (package-license perl))))

(define-public perl-net-http
  (package
    (name "perl-net-http")
    (version "6.07")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/M/MS/MSCHILLI/Net-HTTP-"
                   version ".tar.gz"))
             (sha256
              (base32
               "0r034hhci0yqbrkrh1gv6vi5g3i0kpd1k84z62nk02asb8rf0ccz"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-io-socket-ssl" ,perl-io-socket-ssl)
       ("perl-uri" ,perl-uri)))
    (license (package-license perl))
    (synopsis "Perl low-level HTTP connection (client)")
    (description
     "The Net::HTTP class is a low-level HTTP client.  An instance of the
Net::HTTP class represents a connection to an HTTP server.  The HTTP protocol
is described in RFC 2616.  The Net::HTTP class supports HTTP/1.0 and
HTTP/1.1.")
    (home-page "http://search.cpan.org/dist/Net-HTTP")))

(define-public perl-net-server
  (package
    (name "perl-net-server")
    (version "2.008")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/R/RH/RHANDOM/"
                           "Net-Server-" version ".tar.gz"))
       (sha256
        (base32
         "182gfikn7r40kmm3d35m2qc6r8g0y1j8gxbn9ffaawf8xmm0a889"))))
    (build-system perl-build-system)
    (home-page "http://search.cpan.org/dist/Net-Server")
    (synopsis "Extensible Perl server engine")
    (description "Net::Server is an extensible, generic Perl server engine.
It attempts to be a generic server as in Net::Daemon and NetServer::Generic.
It includes with it the ability to run as an inetd
process (Net::Server::INET), a single connection server (Net::Server or
Net::Server::Single), a forking server (Net::Server::Fork), a preforking
server which maintains a constant number of preforked
children (Net::Server::PreForkSimple), or as a managed preforking server which
maintains the number of children based on server load (Net::Server::PreFork).
In all but the inetd type, the server provides the ability to connect to one
or to multiple server ports.")
    (license (package-license perl))))

(define-public perl-net-smtp-ssl
  (package
    (name "perl-net-smtp-ssl")
    (version "1.03")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/R/RJ/RJBS/"
                           "Net-SMTP-SSL-" version ".tar.gz"))
       (sha256
        (base32
         "05y94mb1vdw32mvwb0cp2h4ggh32f8j8nwwfjb8kjwxvfkfhyp9h"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-io-socket-ssl" ,perl-io-socket-ssl)))
    (home-page "http://search.cpan.org/dist/Net-SMTP-SSL")
    (synopsis "SSL support for Net::SMTP")
    (description "SSL support for Net::SMTP.")
    (license (package-license perl))))

(define-public perl-plack
  (package
    (name "perl-plack")
    (version "1.0033")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/M/MI/MIYAGAWA/"
                           "Plack-" version ".tar.gz"))
       (sha256
        (base32
         "081jg0xddzpg2anmqi9i6d7vs6c8z7k557bf8xl6vgb3h95pin5w"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-requires" ,perl-test-requires)
       ("perl-file-sharedir-install" ,perl-file-sharedir-install)))
    (propagated-inputs
     `(("perl-apache-logformat-compiler" ,perl-apache-logformat-compiler)
       ("perl-devel-stacktrace" ,perl-devel-stacktrace)
       ("perl-devel-stacktrace-ashtml" ,perl-devel-stacktrace-ashtml)
       ("perl-file-sharedir" ,perl-file-sharedir)
       ("perl-hash-multivalue" ,perl-hash-multivalue)
       ("perl-http-body" ,perl-http-body)
       ("perl-http-message" ,perl-http-message)
       ("perl-http-tiny" ,perl-http-tiny)
       ("perl-libwww" ,perl-libwww)
       ("perl-stream-buffered" ,perl-stream-buffered)
       ("perl-test-tcp" ,perl-test-tcp)
       ("perl-try-tiny" ,perl-try-tiny)
       ("perl-uri" ,perl-uri)))
    (home-page "http://search.cpan.org/dist/Plack")
    (synopsis "Perl Superglue for Web frameworks and servers (PSGI toolkit)")
    (description "Plack is a set of tools for using the PSGI stack.  It
contains middleware components, a reference server, and utilities for Web
application frameworks.  Plack is like Ruby's Rack or Python's Paste for
WSGI.")
    (license (package-license perl))))

(define-public perl-plack-middleware-fixmissingbodyinredirect
  (package
    (name "perl-plack-middleware-fixmissingbodyinredirect")
    (version "0.12")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/S/SW/SWEETKID/"
                           "Plack-Middleware-FixMissingBodyInRedirect-"
                           version ".tar.gz"))
       (sha256
        (base32
         "14dkrmccq7a5vpymx5dv8032gfcvhsw2i6v5sh3c4ym5ymlx08kc"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-html-parser" ,perl-html-parser) ;for HTML::Entities
       ("perl-http-message" ,perl-http-message)
       ("perl-plack" ,perl-plack)))     ;for Plack::Test
    (home-page
     "http://search.cpan.org/dist/Plack-Middleware-FixMissingBodyInRedirect")
    (synopsis "Plack::Middleware which sets body for redirect response")
    (description "This module sets the body in redirect response, if it's not
already set.")
    (license (package-license perl))))

(define-public perl-plack-middleware-methodoverride
  (package
    (name "perl-plack-middleware-methodoverride")
    (version "0.11")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/D/DW/DWHEELER/"
                           "Plack-Middleware-MethodOverride-"
                           version ".tar.gz"))
       (sha256
        (base32
         "1hb8dx7i4vs74n0p737wrvpdnnw6argxrjpr6kj6432zabp8325z"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-module-build" ,perl-module-build)))
    (propagated-inputs
     `(("perl-plack" ,perl-plack)))
    (home-page "http://search.cpan.org/dist/Plack-Middleware-MethodOverride")
    (synopsis "Override REST methods to Plack apps via POST")
    (description "This middleware allows for POST requests that pretend to be
something else: by adding either a header named X-HTTP-Method-Override to the
request, or a query parameter named x-tunneled-method to the URI, the client
can say what method it actually meant.")
    (license (package-license perl))))

(define-public perl-plack-middleware-removeredundantbody
  (package
    (name "perl-plack-middleware-removeredundantbody")
    (version "0.05")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/S/SW/SWEETKID/"
                           "Plack-Middleware-RemoveRedundantBody-"
                           version ".tar.gz"))
       (sha256
        (base32
         "1n3wm0zi8dnk54jx937asl951lslj3jvw0fry4jpzsibg4f6wrx0"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-plack" ,perl-plack)))
    (home-page
     "http://search.cpan.org/dist/Plack-Middleware-RemoveRedundantBody")
    (synopsis "Plack::Middleware which removes body for HTTP response")
    (description "This module removes the body in an HTTP response if it's not
required.")
    (license (package-license perl))))

(define-public perl-plack-middleware-reverseproxy
  (package
    (name "perl-plack-middleware-reverseproxy")
    (version "0.15")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/M/MI/MIYAGAWA/"
                           "Plack-Middleware-ReverseProxy-"
                           version ".tar.gz"))
       (sha256
        (base32
         "1zmsccdy6wr5hxzj07r1nsmaymyibk87p95z0wzknjw10lwmqs9f"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-plack" ,perl-plack)))
    (home-page "http://search.cpan.org/dist/Plack-Middleware-ReverseProxy")
    (synopsis "Supports app to run as a reverse proxy backend")
    (description "Plack::Middleware::ReverseProxy resets some HTTP headers,
which are changed by reverse-proxy.  You can specify the reverse proxy address
and stop fake requests using 'enable_if' directive in your app.psgi.")
    (license (package-license perl))))

(define-public perl-plack-test-externalserver
  (package
    (name "perl-plack-test-externalserver")
    (version "0.01")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/F/FL/FLORA/"
                           "Plack-Test-ExternalServer-" version ".tar.gz"))
       (sha256
        (base32
         "1dbg1p3rgvvbkkpvca5jlc2mzx8iqyiybk88al93pvbca65h1g7h"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-plack" ,perl-plack)))
    (home-page "http://search.cpan.org/dist/Plack-Test-ExternalServer")
    (synopsis "Run HTTP tests on external live servers")
    (description "This module allows your to run your Plack::Test tests
against an external server instead of just against a local application through
either mocked HTTP or a locally spawned server.")
    (license (package-license perl))))

(define-public perl-test-tcp
  (package
    (name "perl-test-tcp")
    (version "2.06")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/T/TO/TOKUHIROM/"
                           "Test-TCP-" version ".tar.gz"))
       (sha256
        (base32
         "0acjwm21y2an4f3fasci9qa0isakh9cgp74fk0bzcdi506xmcjbi"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-test-sharedfork" ,perl-test-sharedfork)))
    (arguments `(#:tests? #f))          ;related to signaling in t/05_sigint.t
    (home-page "http://search.cpan.org/dist/Test-TCP")
    (synopsis "Testing TCP programs")
    (description "Test::TCP is test utilities for TCP/IP programs.")
    (license (package-license perl))))

(define-public perl-test-www-mechanize
  (package
    (name "perl-test-www-mechanize")
    (version "1.44")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/P/PE/PETDANCE/"
                           "Test-WWW-Mechanize-" version ".tar.gz"))
       (sha256
        (base32
         "062pj242vsc73bw11jqpap92ax9wzc9f2m4xhyp1wzrwkfchpl2q"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-exception" ,perl-test-exception)))
    (propagated-inputs
     `(("perl-carp-assert-more" ,perl-carp-assert-more)
       ("perl-html-form" ,perl-html-form)
       ("perl-html-lint" ,perl-html-lint)
       ("perl-html-tree" ,perl-html-tree)
       ("perl-http-server-simple" ,perl-http-server-simple)
       ("perl-libwww" ,perl-libwww)
       ("perl-test-longstring" ,perl-test-longstring)
       ("perl-www-mechanize" ,perl-www-mechanize)))
    (home-page "http://search.cpan.org/dist/Test-WWW-Mechanize")
    (synopsis "Testing-specific WWW::Mechanize subclass")
    (description "Test::WWW::Mechanize is a subclass of the Perl module
WWW::Mechanize that incorporates features for web application testing.")
    (license l:artistic2.0)))

(define-public perl-test-www-mechanize-catalyst
  (package
    (name "perl-test-www-mechanize-catalyst")
    (version "0.60")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/J/JJ/JJNAPIORK/"
                           "Test-WWW-Mechanize-Catalyst-" version ".tar.gz"))
       (sha256
        (base32
         "0nhhfrrai3ndziz873vpa1j0vljjnib4wqafd6yyvkf58ad7v0lv"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-catalyst-plugin-session" ,perl-catalyst-plugin-session)
       ("perl-catalyst-plugin-session-state-cookie"
        ,perl-catalyst-plugin-session-state-cookie)
       ("perl-test-exception" ,perl-test-exception)
       ("perl-test-pod" ,perl-test-pod)
       ("perl-test-utf8" ,perl-test-utf8)))
    (propagated-inputs
     `(("perl-catalyst-runtime" ,perl-catalyst-runtime)
       ("perl-class-load" ,perl-class-load)
       ("perl-libwww" ,perl-libwww)
       ("perl-moose" ,perl-moose)
       ("perl-namespace-clean" ,perl-namespace-clean)
       ("perl-test-www-mechanize" ,perl-test-www-mechanize)
       ("perl-www-mechanize" ,perl-www-mechanize)))
    (home-page "http://search.cpan.org/dist/Test-WWW-Mechanize-Catalyst")
    (synopsis "Test::WWW::Mechanize for Catalyst")
    (description "The Test::WWW::Mechanize::Catalyst module meshes the
Test::WWW:Mechanize module and the Catalyst web application framework to allow
testing of Catalyst applications without needing to start up a web server.")
    (license (package-license perl))))

(define-public perl-test-www-mechanize-psgi
  (package
    (name "perl-test-www-mechanize-psgi")
    (version "0.35")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/L/LB/LBROCARD/"
                           "Test-WWW-Mechanize-PSGI-" version ".tar.gz"))
       (sha256
        (base32
         "1hih8s49zf38bisvhnhzrrj0zwyiivkrbs7nmmdqm1qqy27wv7pc"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-pod" ,perl-test-pod)))
    (propagated-inputs
     `(("perl-plack" ,perl-plack)
       ("perl-test-www-mechanize" ,perl-test-www-mechanize)))
    (home-page "http://search.cpan.org/dist/Test-WWW-Mechanize-PSGI")
    (synopsis "Test PSGI programs using WWW::Mechanize")
    (description "PSGI is a specification to decouple web server environments
from web application framework code.  Test::WWW::Mechanize is a subclass of
WWW::Mechanize that incorporates features for web application testing.  The
Test::WWW::Mechanize::PSGI module meshes the two to allow easy testing of PSGI
applications.")
    (license (package-license perl))))

(define-public perl-uri
  (package
    (name "perl-uri")
    (version "1.71")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://cpan/authors/id/E/ET/ETHER/"
                                 "URI-" version ".tar.gz"))
             (sha256
              (base32
               "05a1ck1bhvqkkk690xhsxf7276dnagk96qkh2jy4prrrgw6wm3lw"))))
    (build-system perl-build-system)
    (license (package-license perl))
    (synopsis "Perl Uniform Resource Identifiers (absolute and relative)")
    (description
     "The URI module implements the URI class.  Objects of this class
represent \"Uniform Resource Identifier references\" as specified in RFC 2396
and updated by RFC 2732.")
    (home-page "http://search.cpan.org/dist/URI/")))

(define-public perl-uri-fetch
  (package
    (name "perl-uri-fetch")
    (version "0.13")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/N/NE/NEILB/"
                                  "URI-Fetch-" version ".tar.gz"))
              (sha256
               (base32
                "0rw6xiqm70s218aii9id3hf8j3pz6n22xnwd8v9m1ff2bnh63c0d"))))
    (build-system perl-build-system)
    (arguments
     `(#:tests? #f)) ; Tests require internet connection to succeed
    (inputs
     `(("perl-class-errorhandler" ,perl-class-errorhandler)
       ("perl-libwww" ,perl-libwww)
       ("perl-uri" ,perl-uri)))
    (home-page "http://search.cpan.org/dist/URI-Fetch")
    (synopsis "Smart URI fetching/caching")
    (description "@code{URI::Fetch} is a smart client for fetching HTTP pages,
notably syndication feeds (RSS, Atom, and others), in an intelligent, bandwidth-
and time-saving way.")
    (license (package-license perl))))

(define-public perl-uri-find
  (package
    (name "perl-uri-find")
    (version "20140709")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/M/MS/MSCHWERN/"
                           "URI-Find-" version ".tar.gz"))
       (sha256
        (base32
         "0czc4h182s7sx3k123m7qlg7yybnwxgh369hap3c3b6xgrglrhy0"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-module-build" ,perl-module-build)))
    (propagated-inputs
     `(("perl-uri" ,perl-uri)))
    (home-page "http://search.cpan.org/dist/URI-Find")
    (synopsis "Find URIs in arbitrary text")
    (description "This module finds URIs and URLs (according to what URI.pm
considers a URI) in plain text.  It only finds URIs which include a
scheme (http:// or the like), for something a bit less strict, consider
URI::Find::Schemeless.  For a command-line interface, urifind is provided.")
    (license (package-license perl))))

(define-public perl-uri-ws
  (package
    (name "perl-uri-ws")
    (version "0.03")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/P/PL/PLICEASE/"
                           "URI-ws-" version ".tar.gz"))
       (sha256
        (base32
         "1vs1wm80sq685944g1l4a0fxcbccc00c0f9648yabdmcf90hwsvf"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-uri" ,perl-uri)))
    (home-page "http://search.cpan.org/dist/URI-ws")
    (synopsis "WebSocket support for URI package")
    (description "With this module, the URI package provides the same set of
methods for WebSocket URIs as it does for HTTP URIs.")
    (license (package-license perl))))

(define-public perl-uri-template
  (package
    (name "perl-uri-template")
    (version "0.22")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/B/BR/BRICAS/URI-Template-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "08kjjb4c0v9gqfrfnj1wkivylxl05finn11ra64dj136fhmnyrbg"))))
    (build-system perl-build-system)
    (inputs
     `(("perl-uri" ,perl-uri)))
    (native-inputs
     `(("perl-test-pod-coverage" ,perl-test-pod-coverage)
       ("perl-test-pod" ,perl-test-pod)
       ("perl-json" ,perl-json)))
    (home-page "http://search.cpan.org/dist/URI-Template")
    (synopsis "Object for handling URI templates")
    (description "This perl module provides a wrapper around URI templates as described in
RFC 6570.")
    (license (package-license perl))))

(define-public perl-www-curl
  (package
    (name "perl-www-curl")
    (version "4.17")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://cpan/authors/id/S/SZ/SZBALINT/WWW-Curl-"
                    version".tar.gz"))
              (patches (search-patches "perl-www-curl-remove-symbol.patch"))
              (sha256
               (base32
                "1fmp9aib1kaps9vhs4dwxn7b15kgnlz9f714bxvqsd1j1q8spzsj"))))
    (build-system perl-build-system)
    (arguments
     '(#:tests? #f))                        ;XXX: tests require network access
    (inputs `(("curl" ,curl)))
    (synopsis "Perl extension interface for libcurl")
    (description
     "This is a Perl extension interface for the libcurl file downloading
library.")
    (license (package-license perl))
    (home-page "http://search.cpan.org/~szbalint/WWW-Curl-4.17/lib/WWW/Curl.pm")))

(define-public perl-www-mechanize
  (package
    (name "perl-www-mechanize")
    (version "1.73")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/E/ET/ETHER/"
                           "WWW-Mechanize-" version ".tar.gz"))
       (sha256
        (base32
         "1zrw8aadhwy48q51x2z2rqlkwf17bya4j4h3hy89mw783j96rmg9"))))
    (build-system perl-build-system)
    (native-inputs                      ;only for tests
     `(("perl-cgi" ,perl-cgi)))
    (propagated-inputs
     `(("perl-html-form" ,perl-html-form)
       ("perl-html-parser" ,perl-html-parser)
       ("perl-http-message" ,perl-http-message)
       ("perl-http-server-simple" ,perl-http-server-simple)
       ("perl-libwww" ,perl-libwww)
       ("perl-test-warn" ,perl-test-warn)
       ("perl-uri" ,perl-uri)))
    (home-page "http://search.cpan.org/dist/WWW-Mechanize")
    (synopsis "Web browsing in a Perl object")
    (description "WWW::Mechanize is a Perl module for stateful programmatic
web browsing, used for automating interaction with websites.")
    (license (package-license perl))))

(define-public perl-www-opensearch
  (package
    (name "perl-www-opensearch")
    (version "0.17")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/B/BR/BRICAS/"
                                  "WWW-OpenSearch-" version ".tar.gz"))
              (sha256
               (base32
                "1yxplx1q1qk2fvnzqrbk01lz26fy1lyhay51a3ky7q3jgh9p01rb"))))
    (build-system perl-build-system)
    (arguments
     `(#:tests? #f)) ; Tests require further modules to be packaged
    (inputs
     `(("perl-data-page" ,perl-data-page)
       ("perl-libwww" ,perl-libwww)
       ("perl-uri" ,perl-uri)
       ("perl-uri-template" ,perl-uri-template)
       ("perl-xml-feed" ,perl-xml-feed)
       ("perl-xml-libxml" ,perl-xml-libxml)))
    (home-page "http://search.cpan.org/dist/WWW-OpenSearch")
    (synopsis "Search A9 OpenSearch compatible engines")
    (description
     "@code{WWW::OpenSearch} is a module to search @url{A9's OpenSearch,
http://opensearch.a9.com} compatible search engines.")
    (license (package-license perl))))

(define-public perl-www-robotrules
  (package
    (name "perl-www-robotrules")
    (version "6.02")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/G/GA/GAAS/WWW-RobotRules-"
                   version ".tar.gz"))
             (sha256
              (base32
               "07m50dp5n5jxv3m93i55qvnd67a6g7cvbvlik115kmc8lbkh5da6"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-uri" ,perl-uri)))
    (license (package-license perl))
    (synopsis "Perl database of robots.txt-derived permissions")
    (description
     "The WWW::RobotRules module parses /robots.txt files as specified in
\"A Standard for Robot Exclusion\", at
<http://www.robotstxt.org/wc/norobots.html>.  Webmasters can use the
/robots.txt file to forbid conforming robots from accessing parts of
their web site.")
    (home-page "http://search.cpan.org/~gaas/WWW-RobotRules/")))

(define-public python-feedparser
  (package
    (name "python-feedparser")
    (version "5.2.1")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "feedparser" version ".tar.bz2"))
       (sha256
        (base32
         "00hb4qg2am06g81mygfi1jsbx8830024jm45g6qp9g8fr6am91yf"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f))
    (home-page
     "https://github.com/kurtmckee/feedparser")
    (synopsis "Parse feeds in Python")
    (description
     "Universal feed parser which handles RSS 0.9x, RSS 1.0, RSS 2.0,
CDF, Atom 0.3, and Atom 1.0 feeds.")
    (license (list l:bsd-2 ; source code
                   l:freebsd-doc)))) ; documentation

(define-public python2-feedparser
  (package-with-python2 python-feedparser))

(define-public r-httpuv
  (package
    (name "r-httpuv")
    (version "1.3.3")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "httpuv" version))
              (sha256
               (base32
                "0aibs0hf38n8f6xxx4g2i2lzd6l5h92m5pscx2z834sdvhnladxv"))))
    (build-system r-build-system)
    (native-inputs `(("r-rcpp" ,r-rcpp)))
    (home-page "https://github.com/rstudio/httpuv")
    (synopsis "HTTP and WebSocket server library for R")
    (description
     "The httpuv package provides low-level socket and protocol support for
handling HTTP and WebSocket requests directly from within R.  It is primarily
intended as a building block for other packages, rather than making it
particularly easy to create complete web applications using httpuv alone.")
    ;; This package includes third-party code that was originally released
    ;; under various non-copyleft licenses.  Full licensing information can be
    ;; obtained here: https://github.com/rstudio/httpuv/blob/master/LICENSE
    (license l:gpl3+)))

(define-public r-jsonlite
  (package
    (name "r-jsonlite")
    (version "1.1")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "jsonlite" version))
              (sha256
               (base32
                "0mrfzh0mxxrhqdmxai434wvyd7skkw28vxr7pyls19yrg941g6r3"))))
    (build-system r-build-system)
    (home-page "http://arxiv.org/abs/1403.2805")
    (synopsis "Robust, high performance JSON parser and generator for R")
    (description
     "The jsonlite package provides a fast JSON parser and generator optimized
for statistical data and the web.  It offers flexible, robust, high
performance tools for working with JSON in R and is particularly powerful for
building pipelines and interacting with a web API.  In addition to converting
JSON data from/to R objects, jsonlite contains functions to stream, validate,
and prettify JSON data.  The unit tests included with the package verify that
all edge cases are encoded and decoded consistently for use with dynamic data
in systems and applications.")
    (license l:expat)))

(define-public r-servr
  (package
    (name "r-servr")
    (version "0.4")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "servr" version))
              (sha256
               (base32
                "1fkqf5ynd1g0932qwv5nr70bw42m8vxpc9rhi0qxmdamwqcw8qjn"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-httpuv" ,r-httpuv)
       ("r-jsonlite" ,r-jsonlite)
       ("r-mime" ,r-mime)))
    (native-inputs
     `(("r-rcpp" ,r-rcpp)))
    (home-page "https://github.com/yihui/servr")
    (synopsis "Simple HTTP server to serve static files or dynamic documents")
    (description
     "Servr provides an HTTP server in R to serve static files, or dynamic
documents that can be converted to HTML files (e.g., R Markdown) under a given
directory.")
    (license l:expat)))

(define-public r-htmltools
  (package
    (name "r-htmltools")
    (version "0.3.5")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "htmltools" version))
              (sha256
               (base32
                "0j9bf80grd6gwh7116m575pycv87c0wcwkxsz3gzzfs4aw3pxyr9"))))
    (build-system r-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; See https://github.com/rstudio/htmltools/pull/68
         ;; The resource files are in the store and have mode 444.  After
         ;; copying the files R fails to remove them again because it doesn't
         ;; have write access to them.
         (add-after 'unpack 'copy-files-without-mode
           (lambda _
             (substitute* "R/html_dependency.R"
               (("file.copy\\(from, to, " prefix)
                (string-append prefix
                               "copy.mode = FALSE, ")))
             #t)))))
    (propagated-inputs
     `(("r-digest" ,r-digest)
       ("r-rcpp" ,r-rcpp)))
    (home-page "http://cran.r-project.org/web/packages/htmltools")
    (synopsis "R tools for HTML")
    (description
     "This package provides tools for HTML generation and output in R.")
    (license l:expat)))

(define-public r-htmlwidgets
  (package
    (name "r-htmlwidgets")
    (version "0.7")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "htmlwidgets" version))
              (sha256
               (base32
                "1xh8aiaci5hi3r67ym7r37hm89m9vzywk292avnmaj125kq7w1d0"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-htmltools" ,r-htmltools)
       ("r-jsonlite" ,r-jsonlite)
       ("r-yaml" ,r-yaml)))
    (home-page "https://github.com/ramnathv/htmlwidgets")
    (synopsis "HTML Widgets for R")
    (description
     "HTML widgets is a framework for creating HTML widgets that render in
various contexts including the R console, R Markdown documents, and Shiny web
applications.")
    (license l:expat)))

(define-public r-htmltable
  (package
    (name "r-htmltable")
    (version "1.7")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "htmlTable" version))
       (sha256
        (base32
         "0x2f2hrbhvm53zqwn0ny9wxbk34nwf6zww8cx4bjy5ax15asdllm"))))
    (properties `((upstream-name . "htmlTable")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-knitr" ,r-knitr)
       ("r-magrittr" ,r-magrittr)
       ("r-stringr" ,r-stringr)))
    (home-page "http://gforge.se/packages/")
    (synopsis "Advanced tables for Markdown/HTML")
    (description
     "This package provides functions to build tables with advanced layout
elements such as row spanners, column spanners, table spanners, zebra
striping, and more.  While allowing advanced layout, the underlying
CSS-structure is simple in order to maximize compatibility with word
processors such as LibreOffice.  The package also contains a few text
formatting functions that help outputting text compatible with HTML or
LaTeX.")
    (license l:gpl3+)))

(define-public r-curl
  (package
    (name "r-curl")
    (version "2.2")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "curl" version))
              (sha256
               (base32
                "0hyvyjzf5ja7kfhzmlfgp86hg1lxrriiwbnr6pxabwwslswj3cmj"))))
    (build-system r-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; The environment variable CURL_CA_BUNDLE is only respected when
         ;; running Windows, so we disable the platform checks.
         ;; This can be removed once the libcurl has been patched.
         (add-after 'unpack 'allow-CURL_CA_BUNDLE
           (lambda _
             (substitute* "R/onload.R"
               (("if \\(!grepl\\(\"mingw\".*")
                "if (FALSE)\n"))
             (substitute* "src/handle.c"
               (("#ifdef _WIN32") "#if 1"))
             #t)))))
    (inputs
     `(("libcurl" ,curl)))
    (home-page "https://github.com/jeroenooms/curl")
    (synopsis "HTTP client for R")
    (description
     "The @code{curl()} and @code{curl_download()} functions provide highly
configurable drop-in replacements for base @code{url()} and
@code{download.file()} with better performance, support for encryption, gzip
compression, authentication, and other @code{libcurl} goodies.  The core of
the package implements a framework for performing fully customized requests
where data can be processed either in memory, on disk, or streaming via the
callback or connection interfaces.")
    (license l:expat)))

(define-public r-hwriter
  (package
    (name "r-hwriter")
    (version "1.3.2")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "hwriter" version))
       (sha256
        (base32
         "0arjsz854rfkfqhgvpqbm9lfni97dcjs66isdsfvwfd2wz932dbb"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/hwriter")
    (synopsis "Output R objects in HTML format")
    (description
     "This package provides easy-to-use and versatile functions to output R
objects in HTML format.")
    (license l:lgpl2.1+)))

(define-public r-rjson
  (package
    (name "r-rjson")
    (version "0.2.15")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "rjson" version))
       (sha256
        (base32
         "1vzjyvf57k1fjizlk28rby65y5lsww5qnfvgnhln74qwda7hvl3p"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/rjson")
    (synopsis "JSON library for R")
    (description
     "This package provides functions to convert R objects into JSON objects
and vice-versa.")
    (license l:gpl2+)))

(define-public gumbo-parser
  (package
    (name "gumbo-parser")
    (version "0.10.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/google/"
                                  "gumbo-parser/archive/v" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1bgg2kbj311pqdzw2v33za7k66g1rv44kkvvnz2gnpaasi9k0ii8"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; tests require bundling googletest sources
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'bootstrap
          (lambda _ (zero? (system* "sh" "autogen.sh")))))))
    ;; The release tarball lacks the generated files.
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)))
    (home-page "https://github.com/google/gumbo-parser")
    (synopsis "HTML5 parsing library")
    (description
     "Gumbo is an implementation of the HTML5 parsing algorithm implemented as
a pure C99 library.")
    (license l:asl2.0)))

(define-public uwsgi
  (package
    (name "uwsgi")
    (version "2.0.12")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://projects.unbit.it/downloads/uwsgi-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "02g46dnw5j1iw8fsq392bxbk8d21b9pdgb3ypcinv3b4jzdm2srh"))))
    (build-system gnu-build-system)
    (outputs '("out" "python"))
    (arguments
     '(;; XXX: The 'check' target runs cppcheck to do static code analysis.
       ;;      But there is no obvious way to run the real tests.
       #:tests? #f
       #:phases
       (modify-phases %standard-phases
         (replace 'configure
           ;; Configuration is done by writing an ini file.
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out       (assoc-ref outputs "out"))
                    (bindir    (string-append out "/bin"))
                    (plugindir (string-append out "/lib/uwsgi")))
               ;; The build phase outputs files to these directories directly.
               (mkdir-p bindir)
               (mkdir-p plugindir)
               ;; XXX: Enable other plugins.
               (call-with-output-file "buildconf/guix.ini"
                 (lambda (port)
                   (format port "[uwsgi]
yaml = libyaml
bin_name = ~a/uwsgi
plugin_dir = ~a

inherit = base
plugins = cgi,python
embedded_plugins =
" bindir plugindir))))
             (setenv "PROFILE" "guix")
             #t))
         (replace 'install
           ;; Move plugins into their own output.
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out           (assoc-ref outputs "out"))
                    (plugindir     (string-append out "/lib/uwsgi"))
                    (python-plugin (string-append
                                    plugindir "/python_plugin.so")))
               (install-file python-plugin
                             (string-append
                              (assoc-ref outputs "python") "/lib/uwsgi"))
               (delete-file python-plugin)
               #t))))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python" ,python-wrapper)))
    (inputs
     `(("jansson" ,jansson)
       ("libxml2" ,libxml2)
       ("libyaml" ,libyaml)
       ("openssl" ,openssl)
       ("pcre" ,pcre)
       ("zlib" ,zlib)
       ;; For plugins.
       ("python" ,python)))
    (home-page "https://uwsgi-docs.readthedocs.org/")
    (synopsis "Application container server")
    (description
     "uWSGI presents a complete stack for networked/clustered web applications,
implementing message/object passing, caching, RPC and process management.
It uses the uwsgi protocol for all the networking/interprocess communications.")
    (license l:gpl2+))) ; with linking exception

(define-public jq
  (package
    (name "jq")
    (version "1.5")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/stedolan/" name
                                  "/releases/download/" name "-" version
                                  "/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "0g29kyz4ykasdcrb0zmbrp2jqs9kv1wz9swx849i2d1ncknbzln4"))
              ;; This patch has been pushed and the vulnerability will be
              ;; fixed in the next release after 1.5.
              ;; https://github.com/stedolan/jq/issues/995
              (patches (search-patches "jq-CVE-2015-8863.patch"))))
    (inputs
     `(("oniguruma" ,oniguruma)))
    (native-inputs
     `(;; TODO fix gems to generate documentation
       ;;("ruby" ,ruby)
       ;;("bundler" ,bundler)
       ("valgrind" ,valgrind)))
    (build-system gnu-build-system)
    (home-page "http://stedolan.github.io/jq/")
    (synopsis "Command-line JSON processor")
    (description "jq is like sed for JSON data – you can use it to slice and
filter and map and transform structured data with the same ease that sed, awk,
grep and friends let you play with text.  It is written in portable C.  jq can
mangle the data format that you have into the one that you want with very
little effort, and the program to do so is often shorter and simpler than
you'd expect.")
    (license (list l:expat l:cc-by3.0))))

(define-public uhttpmock
  (package
    (name "uhttpmock")
    (version "0.5.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://tecnocode.co.uk/downloads/uhttpmock/"
                           name "-" version ".tar.xz"))
       (sha256
        (base32
         "0vniyx341pnnmvxmqacc49k0g7h9a9nhknfslidrqmxj5lm1ini6"))))
    (build-system glib-or-gtk-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'use-empty-ssl-cert-file
           (lambda _
             ;; Search for ca-certificates.crt files
             ;; during the check phase.
             (setenv "SSL_CERT_FILE" "/dev/null")
             #t)))))
    (native-inputs
     `(("gobject-introspection" ,gobject-introspection)
       ;; For check phase.
       ("glib-networking" ,glib-networking)
       ("gsettings-desktop-schemas" ,gsettings-desktop-schemas)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("libsoup" ,libsoup)))
    (home-page "https://gitlab.com/groups/uhttpmock")
    (synopsis "Library for mocking web service APIs which use HTTP or HTTPS")
    (description
     "Uhttpmock is a project for mocking web service APIs which use HTTP or
HTTPS.  It provides a library, libuhttpmock, which implements recording and
playback of HTTP request/response traces.")
    (license l:lgpl2.1+)))

(define-public woof
  (package
    (name "woof")
    (version "2012-05-31")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://www.home.unix-ag.org/simon/woof-"
                    version ".py"))
              (sha256
               (base32
                "0wjmjhpg6xlid33yi59j47q2qadz20sijrqsjahj30vngz856hyq"))))
    (build-system trivial-build-system)
    (arguments
     '(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (let* ((source (assoc-ref %build-inputs "source"))
                (out    (assoc-ref %outputs "out"))
                (bin    (string-append out "/bin"))
                (python (assoc-ref %build-inputs "python")))
           (mkdir-p bin)
           (with-directory-excursion bin
             (copy-file source "woof")
             (patch-shebang "woof" (list (string-append python "/bin")))
             (chmod "woof" #o555))
           #t))))
    (inputs `(("python" ,python-2)))
    (home-page "http://www.home.unix-ag.org/simon/woof.html")
    (synopsis "Single file web server")
    (description "Woof (Web Offer One File) is a small simple web server that
can easily be invoked on a single file.  Your partner can access the file with
tools they trust (e.g. wget).")
    (license l:gpl2+)))

(define-public netsurf
  (package
    (name "netsurf")
    (version "3.5")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://download.netsurf-browser.org/"
                           "netsurf/releases/source-full/netsurf-all-"
                           version ".tar.gz"))
       (sha256
        (base32
         "1vdldzcv42wykajmw8vbql0f1yd44gbx30kywfrrh2x3064ly609"))
       (modules '((guix build utils)))
       (snippet
        '(begin
           (substitute* "Makefile"
             ;; Do not clobber PKG_CONFIG_PATH from the environment
             (("PKG_CONFIG_PATH = \\$")
              "PKG_CONFIG_PATH := $(PKG_CONFIG_PATH):$")
             ;; Honor make variables
             (("shell cc") "shell $(CC)"))))
       (patches (search-patches "netsurf-about.patch"))))
    (build-system glib-or-gtk-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("perl" ,perl)
       ("perl-html-parser" ,perl-html-parser)
       ("flex" ,flex)
       ("bison" ,bison)))
    (inputs
     `(("gtk+" ,gtk+-2)
       ("gperf" ,gperf)
       ("curl" ,curl)
       ("openssl" ,openssl)
       ("libpng" ,libpng)
       ("libjpeg" ,libjpeg)
       ("expat" ,expat)))
    (arguments
     `(#:make-flags `("CC=gcc" "BUILD_CC=gcc"
                      ,(string-append "PREFIX=" %output))
       #:parallel-build? #f         ;parallel builds not supported
       #:tests? #f                  ;no way to easily run from release tarball
       #:modules ((ice-9 rdelim)
                  (ice-9 match)
                  (srfi srfi-1)
                  (sxml simple)
                  ,@%glib-or-gtk-build-system-modules)
       #:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda _
             (call-with-output-file "netsurf/Makefile.config"
               (lambda (port)
                 (format port "~
                         NETSURF_GTK_RESOURCES := $(PREFIX)/share/netsurf/~@
                         ")))
             #t))
         (add-after 'build 'adjust-welcome
           (lambda _
             ;; First, fix some unended tags and simple substitutions
             (substitute* "netsurf/gtk/res/welcome.html"
               (("<(img|input)([^>]*)>" _ tag contents)
                (string-append "<" tag contents " />"))
               (("Licence") "License") ;prefer GNU spelling
               ((" open source") ", free software")
               (("web&nbsp;site") "website")
               ;; Prefer privacy-respecting default search engine
               (("www.google.co.uk") "www.duckduckgo.com/html")
               (("Google Search") "DuckDuckGo Search")
               (("name=\"btnG\"") ""))
             ;; Remove default links so it doesn't seem we're endorsing them
             (with-atomic-file-replacement "netsurf/gtk/res/welcome.html"
               (lambda (in out)
                 ;; Leave the DOCTYPE header as is
                 (display (read-line in 'concat) out)
                 (sxml->xml
                  (let rec ((sxml (xml->sxml in)))
                    ;; We'd like to use sxml-match here, but it can't
                    ;; match against generic tag symbols...
                    (match sxml
                      (`(div (@ (class "links")) . ,rest)
                       '())
                      ((x ...)
                       (map rec x))
                      (x x)))
                  out)))
             #t))
         (add-after 'install 'install-more
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (desktop (string-append out "/share/applications/"
                                            "netsurf.desktop")))
               (mkdir-p (dirname desktop))
               (copy-file "netsurf/gtk/res/netsurf-gtk.desktop"
                          desktop)
               (substitute* desktop
                 (("netsurf-gtk") (string-append out "/bin/netsurf"))
                 (("netsurf.png") (string-append out "/share/netsurf/"
                                                 "netsurf.xpm")))
               (install-file "netsurf/Docs/netsurf-gtk.1"
                             (string-append out "/share/man/man1/"))
               #t))))))
    (home-page "https://www.netsurf-browser.org")
    (synopsis "Web browser")
    (description
     "NetSurf is a lightweight web browser that has its own layout and
rendering engine entirely written from scratch.  It is small and capable of
handling many of the web standards in use today.")
    (license l:gpl2+)))

(define-public surfraw
  (package
    (name "surfraw")
    (version "2.2.9")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://surfraw.alioth.debian.org/dist/"
                                  name "-" version ".tar.gz"))
              (sha256
               (base32
                "1fy4ph5h9kp0jzj1m6pfylxnnmgdk0mmdppw76z9jhna4jndk5xa"))))
    (build-system gnu-build-system)
    (inputs
     `(("perl" ,perl)
       ("perl-www-opensearch" ,perl-www-opensearch)
       ("perl-html-parser" ,perl-html-parser)
       ("perl-libwww" ,perl-libwww)))
    (synopsis "Unix command line interface to the www")
    (description "Surfraw (Shell Users' Revolutionary Front Rage Against the Web)
provides a unix command line interface to a variety of popular www search engines
and similar services.")
    (home-page "https://surfraw.alioth.debian.org/")
    (license l:public-domain)))

(define-public darkhttpd
  (package
    (name "darkhttpd")
    (version "1.12")
    (source
     (origin
       ;; The darkhttpd release tarball URL fails to download with a
       ;; 'TLS warning alert'. Download from the darkhttpd git repo
       ;; until the problem has been fixed upstream.
       (method git-fetch)
       (uri (git-reference
             (url (string-append "https://unix4lyfe.org/git/darkhttpd"))
             (commit "41b68476c35270f47dcd2ddebe27cbcd87e43d41")))
       (sha256
        (base32
         "0wi8dfgj4ic0fsy4dszl69xgxdxlwxz4c30vsw2i2dpnczgjm04k"))
       (file-name (string-append name "-" version "-checkout"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags '("CC=gcc")
       #:tests? #f ; No test suite
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (install-file "darkhttpd"
                           (string-append (assoc-ref outputs "out")
                                          "/bin"))
             #t)))))
    (synopsis "Simple static web server")
    (description "darkhttpd is a simple static web server.  It is
standalone and does not need inetd or ucspi-tcp.  It does not need any
config files---you only have to specify the www root.")
    (home-page "https://unix4lyfe.org/darkhttpd/")
    (license l:isc)))

(define-public goaccess
  (package
    (name "goaccess")
    (version "1.0.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://tar.goaccess.io/goaccess-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1w84y61f3ldg2f28q6qlyr1scn3mcx0bsbq3i5xi5w193wh3xa2q"))
              (modules '((guix build utils)))
              (snippet
               '(substitute* "src/error.h"
                  (("__DATE__") "\"1970-01-01\"")
                  (("__TIME__") "\"00:00:00\"")))))
    (build-system gnu-build-system)
    (inputs
     ;; TODO: Add dependency on geoip-tools.
     `(("glib" ,glib)
       ("ncurses" ,ncurses)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "https://goaccess.io")
    (synopsis "Analyze Web server logs in real time")
    (description
     "GoAccess is a real-time web log analyzer and interactive viewer that
runs in a terminal or through your browser.  It provides fast and valuable
HTTP statistics for system administrators that require a visual server report
on the fly.")
    (license l:x11)))

(define-public httptunnel
  (package
    (name "httptunnel")
    (version "3.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://www.nocrew.org/software/httptunnel/"
                           name "-" version ".tar.gz"))
       (sha256
        (base32
         "0mn5s6p68n32xzadz6ds5i6bp44dyxzkq68r1yljlv470jr84bql"))
       (modules '((guix build utils)))
       (snippet
        ;; Remove non-free IETF RFC documentation.
        '(delete-file-recursively "doc"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; The default configure phase tries to pass environment variables as
         ;; command-line arguments, which confuses the ./configure script.
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out")))
               (setenv "CONFIG_SHELL" (which "bash"))
               (zero? (system* "./configure"
                               (string-append "--prefix=" out)))))))))
    (home-page "http://www.nocrew.org/software/httptunnel.html")
    (synopsis "Tunnel data connections through HTTP requests")
    (description "httptunnel creates a bidirectional virtual data connection
tunnelled through HTTP (HyperText Transfer Protocol) requests.  This can be
useful for users behind restrictive firewalls.  As long as Web traffic is
allowed, even through a HTTP-only proxy, httptunnel can be combined with other
tools like SSH (Secure Shell) to reach the outside world.")
    (license l:gpl2+)))
