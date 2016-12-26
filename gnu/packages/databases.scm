;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2012, 2014, 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2013 Cyril Roelandt <tipecaml@gmail.com>
;;; Copyright © 2014, 2016 David Thompson <davet@gnu.org>
;;; Copyright © 2014, 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2015 Sou Bunnbu <iyzsong@gmail.com>
;;; Copyright © 2015 Leo Famulari <leo@famulari.name>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 ng0 <ng0@we.make.ritual.n0.is>
;;; Copyright © 2016 Roel Janssen <roel@gnu.org>
;;; Copyright © 2016 David Craven <david@craven.ch>
;;; Copyright © 2016 Jan Nieuwenhuizen <janneke@gnu.org>
;;; Copyright © 2016 Andy Patterson <ajpatter@uwaterloo.ca>
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

(define-module (gnu packages databases)
  #:use-module (gnu packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages avahi)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages boost)
  #:use-module (gnu packages crypto)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages language)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages tcl)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages emacs)
  #:use-module (gnu packages check)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages cyrus-sasl)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages python)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages rdf)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages jemalloc)
  #:use-module ((guix licenses)
                #:select (gpl2 gpl3 gpl3+ lgpl2.1+ lgpl3+ x11-style non-copyleft
                          bsd-2 bsd-3 public-domain))
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system perl)
  #:use-module (guix build-system python)
  #:use-module (guix build-system cmake)
  #:use-module (guix utils)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match))

(define-public 4store
  (package
    (name "4store")
    (version "1.1.6")
    (source (origin
      (method url-fetch)
      (uri (string-append "https://github.com/garlik/4store/archive/v"
                          version ".tar.gz"))
      (file-name (string-append name "-" version ".tar.gz"))
      (sha256
       (base32 "004fmcf1w75zhc1x3zc6kc97j4jqn2v5nhk6yb3z3cpfrhzi9j50"))
      (patches (list (search-patch "4store-fix-buildsystem.patch")))))
    (build-system gnu-build-system)
    (native-inputs
     `(("perl" ,perl)
       ("python" ,python-2)
       ("autoconf" ,autoconf)
       ("automake" ,automake)
       ("gettext" ,gettext-minimal)
       ("libtool" ,libtool)
       ("pcre" ,pcre "bin")                       ;for 'pcre-config'
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("glib" ,glib)
       ("rasqal" ,rasqal)
       ("libxml2" ,libxml2)
       ("raptor2" ,raptor2)
       ("readline" ,readline)
       ("avahi" ,avahi)
       ("cyrus-sasl" ,cyrus-sasl)
       ("openssl" ,openssl)
       ("util-linux" ,util-linux)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'configure 'generate-configure
           (lambda _
             (zero? (system* "./autogen.sh")))))))
    ;; http://www.4store.org has been down for a while now.
    (home-page "https://github.com/garlik/4store")
    (synopsis "Clustered RDF storage and query engine")
    (description "4store is a RDF/SPARQL store written in C, supporting
either single machines or networked clusters.")
      (license gpl3+)))

(define-public gdbm
  (package
    (name "gdbm")
    (version "1.12")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/gdbm/gdbm-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1smwz4x5qa4js0zf1w3asq6z7mh20zlgwbh2bk5dczw6xrk22yyr"))))
    (arguments `(#:configure-flags '("--enable-libgdbm-compat")))
    (build-system gnu-build-system)
    (home-page "http://www.gnu.org/software/gdbm/")
    (synopsis
     "Hash library of database functions compatible with traditional dbm")
    (description
     "GDBM is a library for manipulating hashed databases.  It is used to
store key/value pairs in a file in a manner similar to the Unix dbm library
and provides interfaces to the traditional file format.")
    (license gpl3+)))

(define-public bdb
  (package
    (name "bdb")
    (version "6.2.23")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://download.oracle.com/berkeley-db/db-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1isxx4jfmnh913jzhp8hhfngbk6dsg46f4kjpvvc56maj64jqqa7"))))
    (build-system gnu-build-system)
    (outputs '("out"                             ; programs, libraries, headers
               "doc"))                           ; 94 MiB of HTML docs
    (arguments
     '(#:tests? #f                            ; no check target available
       #:disallowed-references ("doc")
       #:phases
       (alist-replace
        'configure
        (lambda* (#:key outputs #:allow-other-keys)
          (let ((out (assoc-ref outputs "out"))
                (doc (assoc-ref outputs "doc")))
            ;; '--docdir' is not honored, so we need to patch.
            (substitute* "dist/Makefile.in"
              (("docdir[[:blank:]]*=.*")
               (string-append "docdir = " doc "/share/doc/bdb")))

            (zero?
             (system* "./dist/configure"
                      (string-append "--prefix=" out)
                      (string-append "CONFIG_SHELL=" (which "bash"))
                      (string-append "SHELL=" (which "bash"))

                      ;; Remove 7 MiB of .a files.
                      "--disable-static"

                      ;; The compatibility mode is needed by some packages,
                      ;; notably iproute2.
                      "--enable-compat185"

                      ;; The following flag is needed so that the inclusion
                      ;; of db_cxx.h into C++ files works; it leads to
                      ;; HAVE_CXX_STDHEADERS being defined in db_cxx.h.
                      "--enable-cxx"))))
                 %standard-phases)))
    (synopsis "Berkeley database")
    (description
     "Berkeley DB is an embeddable database allowing developers the choice of
SQL, Key/Value, XML/XQuery or Java Object storage for their data model.")
    (license (non-copyleft "file://LICENSE"
                           "See LICENSE in the distribution."))
    (home-page
     "http://www.oracle.com/us/products/database/berkeley-db/overview/index.html")))

(define-public bdb-5.3
  (package (inherit bdb)
    (name "bdb")
    (version "5.3.28")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://download.oracle.com/berkeley-db/db-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0a1n5hbl7027fbz5lm0vp0zzfp1hmxnz14wx3zl9563h83br5ag0"))))))

(define-public mysql
  (package
    (name "mysql")
    (version "5.7.16")
    (source (origin
             (method url-fetch)
             (uri (list (string-append
                          "http://dev.mysql.com/get/Downloads/MySQL-"
                          (version-major+minor version) "/"
                          name "-" version ".tar.gz")
                        (string-append
                          "http://downloads.mysql.com/archives/get/file/"
                          name "-" version ".tar.gz")))
             (sha256
              (base32
               "198qhd9bdm0fnpp307mgby2aar92yzya0937kxi7bcpdfjcvada9"))))
    (build-system cmake-build-system)
    (arguments
     `(#:configure-flags
       '("-DBUILD_CONFIG=mysql_release"
         "-DWITH_SSL=system"
         "-DWITH_ZLIB=system"
         "-DDEFAULT_CHARSET=utf8"
         "-DDEFAULT_COLLATION=utf8_general_ci"
         "-DMYSQL_DATADIR=/var/lib/mysql"
         "-DMYSQL_UNIX_ADDR=/run/mysqld/mysqld.sock"
         "-DINSTALL_INFODIR=share/mysql/docs"
         "-DINSTALL_MANDIR=share/man"
         "-DINSTALL_PLUGINDIR=lib/mysql/plugin"
         "-DINSTALL_SCRIPTDIR=bin"
         "-DINSTALL_INCLUDEDIR=include/mysql"
         "-DINSTALL_DOCREADMEDIR=share/mysql/docs"
         "-DINSTALL_SUPPORTFILESDIR=share/mysql"
         "-DINSTALL_MYSQLSHAREDIR=share/mysql"
         "-DINSTALL_DOCDIR=share/mysql/docs"
         "-DINSTALL_SHAREDIR=share/mysql"
         ;; Get rid of test data.
         "-DINSTALL_MYSQLTESTDIR="
         "-DINSTALL_SQLBENCHDIR=")
       #:phases (modify-phases %standard-phases
                  (add-after
                   'unpack 'patch-boost-version
                   (lambda _
                     ;; Mysql wants boost-1.59.0 specifically
                     (substitute* "cmake/boost.cmake"
                       (("59")
                        ,(match (string-split (package-version boost) #\.)
                           ((_ minor . _) minor))))))
                  (add-after
                   'install 'remove-extra-binaries
                   (lambda* (#:key outputs #:allow-other-keys)
                     (let ((out (assoc-ref outputs "out")))
                       ;; Remove the 3 *_embedded files, which weigh in at
                       ;; 14 MiB each.
                       (for-each delete-file
                                 (find-files (string-append out "/bin")
                                             "_embedded$"))
                       #t))))))
    (native-inputs
     `(("bison" ,bison)
       ("perl" ,perl)))
    (inputs
     `(("boost" ,boost)
       ("libaio" ,libaio)
       ("ncurses" ,ncurses)
       ("openssl" ,openssl)
       ("zlib" ,zlib)))
    (home-page "http://www.mysql.com/")
    (synopsis "Fast, easy to use, and popular database")
    (description
     "MySQL is a fast, reliable, and easy to use relational database
management system that supports the standardized Structured Query
Language.")
    (license gpl2)))

(define-public mariadb
  (package
    (name "mariadb")
    (version "10.1.19")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://downloads.mariadb.org/f/"
                                  name "-" version "/source/"
                                  name "-" version ".tar.gz"))
              (sha256
               (base32
                "108s4mimdbmgmmn5pcr9a405j70cyny9adzv49s75lg22krp74sv"))))
    (build-system cmake-build-system)
    (arguments
     '(#:configure-flags
       '("-DBUILD_CONFIG=mysql_release"
         "-DDEFAULT_CHARSET=utf8"
         "-DDEFAULT_COLLATION=utf8_general_ci"
         "-DMYSQL_DATADIR=/var/lib/mysql"
         "-DMYSQL_UNIX_ADDR=/run/mysqld/mysqld.sock"
         "-DINSTALL_INFODIR=share/mysql/docs"
         "-DINSTALL_MANDIR=share/man"
         "-DINSTALL_PLUGINDIR=lib/mysql/plugin"
         "-DINSTALL_SCRIPTDIR=bin"
         "-DINSTALL_INCLUDEDIR=include/mysql"
         "-DINSTALL_DOCREADMEDIR=share/mysql/docs"
         "-DINSTALL_SUPPORTFILESDIR=share/mysql/support-files"
         "-DINSTALL_MYSQLSHAREDIR=share/mysql"
         "-DINSTALL_DOCDIR=share/mysql/docs"
         "-DINSTALL_SHAREDIR=share/mysql")
       #:phases
       (modify-phases %standard-phases
         (add-before
          'configure 'pre-configure
          (lambda _
            (setenv "CONFIG_SHELL" (which "sh"))
            #t))
         (add-after
          'install 'post-install
          (lambda* (#:key outputs #:allow-other-keys)
            (let* ((out     (assoc-ref outputs "out"))
                   (test    (assoc-ref outputs "test")))
              (substitute* (string-append out "/bin/mysql_install_db")
                (("basedir=\"\"")
                 (string-append "basedir=\"" out "\"")))
              ;; Remove unneeded files for testing.
              (with-directory-excursion out
                (for-each delete-file-recursively
                          '("data" "mysql-test" "sql-bench"
                            "share/man/man1/mysql-test-run.pl.1")))))))))
    (native-inputs
     `(("bison" ,bison)
       ("perl" ,perl)))
    (inputs
     `(("jemalloc" ,jemalloc)
       ("libaio" ,libaio)
       ("libxml2" ,libxml2)
       ("ncurses" ,ncurses)
       ("openssl" ,openssl)
       ("pcre" ,pcre)
       ("zlib" ,zlib)))
    (home-page "https://mariadb.org/")
    (synopsis "SQL database server")
    (description
     "MariaDB is a multi-user and multi-threaded SQL database server, designed
as a drop-in replacement of MySQL.")
    (license gpl2)))

(define-public postgresql
  (package
    (name "postgresql")
    (version "9.5.5")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://ftp.postgresql.org/pub/source/v"
                                  version "/postgresql-" version ".tar.bz2"))
              (sha256
               (base32
                "157kf6mdazmxfmd11f0akya2xcz6sfgprn7yqc26dpklps855ih2"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'configure 'patch-/bin/sh
                     (lambda _
                       ;; Refer to the actual shell.
                       (substitute* '("src/bin/pg_ctl/pg_ctl.c"
                                      "src/bin/psql/command.c")
                         (("/bin/sh") (which "sh")))
                       #t)))))
    (inputs
     `(("readline" ,readline)
       ("zlib" ,zlib)))
    (home-page "https://www.postgresql.org/")
    (synopsis "Powerful object-relational database system")
    (description
     "PostgreSQL is a powerful object-relational database system.  It is fully
ACID compliant, has full support for foreign keys, joins, views, triggers, and
stored procedures (in multiple languages).  It includes most SQL:2008 data
types, including INTEGER, NUMERIC, BOOLEAN, CHAR, VARCHAR, DATE, INTERVAL, and
TIMESTAMP.  It also supports storage of binary large objects, including
pictures, sounds, or video.")
    (license (x11-style "file://COPYRIGHT"))))

(define-public recutils
  (package
    (name "recutils")
    (version "1.7")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/recutils/recutils-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0cdwa4094x3yx7vn98xykvnlp9rngvd58d19vs3vh5hrvggccg93"))))
    (build-system gnu-build-system)

    ;; Running tests in parallel leads to test failures and crashes in
    ;; torture/utils.
    (arguments '(#:parallel-tests? #f
                 #:configure-flags
                 (list (string-append "--with-bash-headers="
                                      (assoc-ref %build-inputs "bash:include")
                                      "/include/bash"))

                 #:phases (modify-phases %standard-phases
                            (add-before 'build 'set-bash4.4-header-location
                              (lambda _
                                (substitute* "bash/Makefile.in"
                                  ;; Adjust the header search path for Bash
                                  ;; 4.4 in accordance with 'bash.pc'.
                                  (("AM_CPPFLAGS = (.*)$" _ rest)
                                   (string-append "AM_CPPFLAGS = "
                                                  "-I$(BASH_HEADERS)/include "
                                                  rest))

                                  ;; Install to PREFIX/lib/bash to match Bash
                                  ;; 4.4's search path.
                                  (("^libdir = .*$")
                                   "libdir = @libdir@/bash\n"))
                                #t)))))

    (native-inputs `(("emacs" ,emacs-minimal)
                     ("bc" ,bc)
                     ("bash:include" ,bash "include")
                     ("libuuid" ,util-linux)))

    ;; TODO: Add more optional inputs.
    (inputs `(("curl" ,curl)
              ("libgcrypt" ,libgcrypt)
              ("check" ,check)))
    (synopsis "Manipulate plain text files as databases")
    (description
     "GNU Recutils is a set of tools and libraries for creating and
manipulating text-based, human-editable databases.  Despite being text-based,
databases created with Recutils carry all of the expected features such as
unique fields, primary keys, time stamps and more.  Many different field
types are supported, as is encryption.")
    (license gpl3+)
    (home-page "http://www.gnu.org/software/recutils/")))

(define-public sparql-query
  (package
    (name "sparql-query")
    (version "1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/tialaramex/"
                                  name "/archive/" version ".tar.gz"))
              (sha256
               (base32 "0yq3k20472rv8npcc420q9ab6idy584g5y0q501d360k5q0ggr8w"))
              (file-name (string-append name "-" version ".tar.gz"))))
    (build-system gnu-build-system)
    (inputs
     `(("readline" ,readline)
       ("ncurses" ,ncurses)
       ("glib" ,glib)
       ("libxml2" ,libxml2)
       ("curl" ,curl)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (arguments
     `(#:make-flags '("CC=gcc")
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         ;; The Makefile uses git to obtain versioning information. This phase
         ;; substitutes the git invocation with the package version.
         (add-after 'unpack 'remove-git-dependency
           (lambda _
             (substitute* "Makefile"
               (("^gitrev :=.*$")
                (string-append "gitrev = \"v" ,version "\"")))))
         ;; The install phase of the Makefile assumes $PREFIX/usr/local/bin.
         ;; This replacement does the same thing, except for using $PREFIX/bin
         ;; instead.
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin")))
               (install-file "sparql-query" bin)
               (system* "ln" "--symbolic"
                        (string-append bin "/sparql-query")
                        (string-append bin "/sparql-update")))))
         (replace 'check
           (lambda* (#:key make-flags #:allow-other-keys)
             (and
              (zero? (apply system* "make" `(,@make-flags "scan-test")))
              (zero? (system "./scan-test"))))))))
    (home-page "https://github.com/tialaramex/sparql-query/")
    (synopsis "Command-line tool for accessing SPARQL endpoints over HTTP")
    (description "Sparql-query is a command-line tool for accessing SPARQL
endpoints over HTTP.  It has been intentionally designed to 'feel' similar to
tools for interrogating SQL databases.  For example, you can enter a query over
several lines, using a semi-colon at the end of a line to indicate the end of
your query.  It also supports readline so that you can more easily recall and
edit previous queries, even across sessions.  It can be used non-interactively,
for example from a shell script.")
    ;; Some files (like scan-sparql.c) contain a GPLv3+ license header, while
    ;; others (like sparql-query.c) contain a GPLv2+ license header.
    (license (list gpl3+))))

(define-public sqlite
  (package
   (name "sqlite")
   (version "3.14.1")
   (source (origin
            (method url-fetch)
            ;; TODO: Download from sqlite.org once this bug :
            ;; http://lists.gnu.org/archive/html/bug-guile/2013-01/msg00027.html
            ;; has been fixed.
            (uri (let ((numeric-version
                        (match (string-split version #\.)
                          ((first-digit other-digits ...)
                           (string-append first-digit
                                          (string-pad-right
                                           (string-concatenate
                                            (map (cut string-pad <> 2 #\0)
                                                 other-digits))
                                           6 #\0))))))
                   (list
                    (string-append
                     "https://fossies.org/linux/misc/sqlite-autoconf-"
                     numeric-version ".tar.gz")
                    (string-append
                     "http://distfiles.gentoo.org/distfiles/"
                     "/sqlite-autoconf-" numeric-version ".tar.gz"))

                   ;; XXX: As of 2015-09-08, SourceForge is squatting the URL
                   ;; below, returning 200 and showing an advertising page.
                   ;; (string-append
                   ;;  "mirror://sourceforge/sqlite.mirror/SQLite%20" version
                   ;;  "/sqlite-autoconf-" numeric-version ".tar.gz")
                   ))
            (sha256
             (base32
              "19j73j44akqgc6m82wm98yvnmm3mfzmfqr8mp3n7n080d53q4wdw"))))
   (build-system gnu-build-system)
   (inputs `(("readline" ,readline)))
   (arguments
    `(#:configure-flags
      ;; Add -DSQLITE_SECURE_DELETE, -DSQLITE_ENABLE_UNLOCK_NOTIFY and
      ;; -DSQLITE_ENABLE_DBSTAT_VTAB to CFLAGS.  GNU Icecat will refuse
      ;; to use the system SQLite unless these options are enabled.
      (list (string-append "CFLAGS=-O2 -DSQLITE_SECURE_DELETE "
                           "-DSQLITE_ENABLE_UNLOCK_NOTIFY "
                           "-DSQLITE_ENABLE_DBSTAT_VTAB"))))
   (home-page "http://www.sqlite.org/")
   (synopsis "The SQLite database management system")
   (description
    "SQLite is a software library that implements a self-contained, serverless,
zero-configuration, transactional SQL database engine.  SQLite is the most
widely deployed SQL database engine in the world.  The source code for SQLite
is in the public domain.")
   (license public-domain)))

(define-public sqlite-3.15.1
  (package (inherit sqlite)
           (version "3.15.1")
           (source (origin
                     (method url-fetch)
                     (uri (let ((numeric-version
                                 (match (string-split version #\.)
                                   ((first-digit other-digits ...)
                                    (string-append first-digit
                                                   (string-pad-right
                                                    (string-concatenate
                                                     (map (cut string-pad <> 2 #\0)
                                                          other-digits))
                                                    6 #\0))))))
                            (string-append "https://sqlite.org/2016/sqlite-autoconf-"
                                           numeric-version ".tar.gz")))
                     (sha256
                      (base32
                       "1ig2d9jzzixiifmgqsl6kjcvy17jwxby3s24gfnc5qvyd6vqkyjx"))))))

(define-public tdb
  (package
    (name "tdb")
    (version "1.3.11")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://www.samba.org/ftp/tdb/tdb-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0i1l38h0vyck6zkcj4fn2l03spadlmyr1qa1xpdp9dy2ccbm3s1r"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               ;; The 'configure' script is a wrapper for Waf and
               ;; doesn't recognize things like '--enable-fast-install'.
               (zero? (system* "./configure"
                               (string-append "--prefix=" out)))))))))
    (native-inputs
     `(;; TODO: Build the documentation.
       ;; ("docbook-xsl" ,docbook-xsl)
       ;; ("libxml2" ,libxml2)
       ;; ("libxslt" ,libxslt)
       ("python" ,python-2)))                     ;for the Waf build system
    (home-page "https://tdb.samba.org/")
    (synopsis "Trivial database")
    (description
     "TDB is a Trivial Database.  In concept, it is very much like GDBM,
and BSD's DB except that it allows multiple simultaneous writers and uses
locking internally to keep writers from trampling on each other.  TDB is also
extremely small.")
    (license lgpl3+)))

(define-public perl-dbi
  (package
    (name "perl-dbi")
    (version "1.636")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://cpan/authors/id/T/TI/TIMB/DBI-"
                    version ".tar.gz"))
              (sha256
               (base32
                "0v37vnr5p0bx396cj0lb5kb69jbryq2mspp602hbgd04gklxqzcg"))))
    (build-system perl-build-system)
    (synopsis "Database independent interface for Perl")
    (description "This package provides an database interface for Perl.")
    (home-page "http://search.cpan.org/dist/DBI")
    (license (package-license perl))))

(define-public perl-dbix-class
  (package
    (name "perl-dbix-class")
    (version "0.082840")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/R/RI/RIBASUSHI/"
                           "DBIx-Class-" version ".tar.gz"))
       (sha256
        (base32
         "1vw1f756g8m5hq11nqf5dk2cw2y4mqq91ca5p75fn5g3fp8syja0"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-dbd-sqlite" ,perl-dbd-sqlite)
       ("perl-file-temp" ,perl-file-temp)
       ("perl-package-stash" ,perl-package-stash)
       ("perl-test-deep" ,perl-test-deep)
       ("perl-test-exception" ,perl-test-exception)
       ("perl-test-warn" ,perl-test-warn)))
    (propagated-inputs
     `(("perl-class-accessor-grouped" ,perl-class-accessor-grouped)
       ("perl-class-c3-componentised" ,perl-class-c3-componentised)
       ("perl-class-inspector" ,perl-class-inspector)
       ("perl-config-any" ,perl-config-any)
       ("perl-context-preserve" ,perl-context-preserve)
       ("perl-data-dumper-concise" ,perl-data-dumper-concise)
       ("perl-data-page" ,perl-data-page)
       ("perl-dbi" ,perl-dbi)
       ("perl-devel-globaldestruction" ,perl-devel-globaldestruction)
       ("perl-hash-merge" ,perl-hash-merge)
       ("perl-module-find" ,perl-module-find)
       ("perl-moo" ,perl-moo)
       ("perl-mro-compat" ,perl-mro-compat)
       ("perl-namespace-clean" ,perl-namespace-clean)
       ("perl-path-class" ,perl-path-class)
       ("perl-scalar-list-utils" ,perl-scalar-list-utils)
       ("perl-scope-guard" ,perl-scope-guard)
       ("perl-sql-abstract" ,perl-sql-abstract)
       ("perl-sub-name" ,perl-sub-name)
       ("perl-text-balanced" ,perl-text-balanced)
       ("perl-try-tiny" ,perl-try-tiny)))
    (home-page "http://search.cpan.org/dist/DBIx-Class")
    (synopsis "Extensible and flexible object <-> relational mapper")
    (description "An SQL to OO mapper with an object API inspired by
Class::DBI (with a compatibility layer as a springboard for porting) and a
resultset API that allows abstract encapsulation of database operations.  It
aims to make representing queries in your code as perl-ish as possible while
still providing access to as many of the capabilities of the database as
possible, including retrieving related records from multiple tables in a
single query, \"JOIN\", \"LEFT JOIN\", \"COUNT\", \"DISTINCT\", \"GROUP BY\",
\"ORDER BY\" and \"HAVING\" support.")
    (license (package-license perl))))

(define-public perl-dbix-class-cursor-cached
  (package
    (name "perl-dbix-class-cursor-cached")
    (version "1.001004")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/A/AR/ARCANEZ/"
                           "DBIx-Class-Cursor-Cached-" version ".tar.gz"))
       (sha256
        (base32
         "09b2jahn2x12qm4f7qm1jzsxbz7qn1czp6a3fnl5l2i3l4r5421p"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-cache-cache" ,perl-cache-cache)
       ("perl-dbd-sqlite" ,perl-dbd-sqlite)))
    (propagated-inputs
     `(("perl-carp-clan" ,perl-carp-clan)
       ("perl-dbix-class" ,perl-dbix-class)))
    (home-page "http://search.cpan.org/dist/DBIx-Class-Cursor-Cached")
    (synopsis "Cursor with built-in caching support")
    (description "DBIx::Class::Cursor::Cached provides a cursor class with
built-in caching support.")
    (license (package-license perl))))

(define-public perl-dbix-class-introspectablem2m
  (package
    (name "perl-dbix-class-introspectablem2m")
    (version "0.001002")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/I/IL/ILMARI/"
                           "DBIx-Class-IntrospectableM2M-" version ".tar.gz"))
       (sha256
        (base32
         "1w47rh2241iy5x3a9bqsyd5kdp9sk43dksr99frzv4qn4jsazfn6"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-dbix-class" ,perl-dbix-class)))
    (home-page "http://search.cpan.org/dist/DBIx-Class-IntrospectableM2M")
    (synopsis "Introspect many-to-many relationships")
    (description "Because the many-to-many relationships are not real
relationships, they can not be introspected with DBIx::Class.  Many-to-many
relationships are actually just a collection of convenience methods installed
to bridge two relationships.  This DBIx::Class component can be used to store
all relevant information about these non-relationships so they can later be
introspected and examined.")
    (license (package-license perl))))

(define-public perl-dbix-class-schema-loader
  (package
    (name "perl-dbix-class-schema-loader")
    (version "0.07046")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/I/IL/ILMARI/"
                           "DBIx-Class-Schema-Loader-" version ".tar.gz"))
       (sha256
        (base32
         "08cgn0dx42y9xsxas9np7s55a7qmy4kf6sfmx0jmk4hryvbapml3"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-config-any" ,perl-config-any)
       ("perl-config-general" ,perl-config-general)
       ("perl-dbd-sqlite" ,perl-dbd-sqlite)
       ("perl-dbix-class-introspectablem2m" ,perl-dbix-class-introspectablem2m)
       ("perl-moose" ,perl-moose)
       ("perl-moosex-markasmethods" ,perl-moosex-markasmethods)
       ("perl-moosex-nonmoose" ,perl-moosex-nonmoose)
       ("perl-namespace-autoclean" ,perl-namespace-autoclean)
       ("perl-test-deep" ,perl-test-deep)
       ("perl-test-differences" ,perl-test-differences)
       ("perl-test-exception" ,perl-test-exception)
       ("perl-test-pod" ,perl-test-pod)
       ("perl-test-warn" ,perl-test-warn)))
    (propagated-inputs
     `(("perl-class-unload" ,perl-class-unload)
       ("perl-class-inspector" ,perl-class-inspector)
       ("perl-class-accessor-grouped" ,perl-class-accessor-grouped)
       ("perl-class-c3-componentised" ,perl-class-c3-componentised)
       ("perl-carp-clan" ,perl-carp-clan)
       ("perl-data-dump" ,perl-data-dump)
       ("perl-dbix-class" ,perl-dbix-class)
       ("perl-hash-merge" ,perl-hash-merge)
       ("perl-list-moreutils" ,perl-list-moreutils)
       ("perl-lingua-en-inflect-phrase" ,perl-lingua-en-inflect-phrase)
       ("perl-lingua-en-inflect-number" ,perl-lingua-en-inflect-number)
       ("perl-lingua-en-tagger" ,perl-lingua-en-tagger)
       ("perl-namespace-clean" ,perl-namespace-clean)
       ("perl-mro-compat" ,perl-mro-compat)
       ("perl-scope-guard" ,perl-scope-guard)
       ("perl-string-camelcase" ,perl-string-camelcase)
       ("perl-string-toidentifier-en" ,perl-string-toidentifier-en)
       ("perl-sub-name" ,perl-sub-name)
       ("perl-try-tiny" ,perl-try-tiny)))
    (arguments `(#:tests? #f))          ;TODO: t/20invocations.t fails
    (home-page "http://search.cpan.org/dist/DBIx-Class-Schema-Loader")
    (synopsis "Create a DBIx::Class::Schema based on a database")
    (description "DBIx::Class::Schema::Loader automates the definition of a
DBIx::Class::Schema by scanning database table definitions and setting up the
columns, primary keys, unique constraints and relationships.")
    (license (package-license perl))))

(define-public perl-dbd-pg
  (package
    (name "perl-dbd-pg")
    (version "3.5.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/T/TU/TURNSTEP/"
                           "DBD-Pg-" version ".tar.gz"))
       (sha256
        (base32
         "0z0kf1kjgbi5f6nr63i2fnrx7629d9lvxg1q8sficwb3zdf1ggzx"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-dbi" ,perl-dbi)))
    (propagated-inputs
     `(("perl-dbi" ,perl-dbi)
       ("postgresql" ,postgresql)))
    (home-page "http://search.cpan.org/dist/DBD-Pg")
    (synopsis "DBI PostgreSQL interface")
    (description "This package provides a PostgreSQL driver for the Perl5
@dfn{Database Interface} (DBI).")
    (license (package-license perl))))

(define-public perl-dbd-mysql
  (package
    (name "perl-dbd-mysql")
    (version "4.041")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/M/MI/MICHIELB/"
                           "DBD-mysql-" version ".tar.gz"))
       (sha256
        (base32
         "0h4h6zwzj8fwh9ljb8svnsa0a3ch4p10hp59kpdibdb4qh8xwxs7"))))
    (build-system perl-build-system)
    ;; Tests require running MySQL server
    (arguments `(#:tests? #f))
    (propagated-inputs
     `(("perl-dbi" ,perl-dbi)
       ("mysql" ,mysql)))
    (home-page "http://search.cpan.org/dist/DBD-mysql")
    (synopsis "DBI MySQL interface")
    (description "This package provides a MySQL driver for the Perl5
@dfn{Database Interface} (DBI).")
    (license (package-license perl))))

(define-public perl-dbd-sqlite
  (package
    (name "perl-dbd-sqlite")
    (version "1.52")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://cpan/authors/id/I/IS/ISHIGAKI/DBD-SQLite-"
                    version ".tar.gz"))
              (sha256
               (base32
                "0kimb2qr1rh07yylbbfybwcizpmy61ck667amypn4clmkfg0knm6"))))
    (build-system perl-build-system)
    (inputs `(("sqlite" ,sqlite)))
    (propagated-inputs `(("perl-dbi" ,perl-dbi)))
    (synopsis "SQlite interface for Perl")
    (description "DBD::SQLite is a Perl DBI driver for SQLite, that includes
the entire thing in the distribution.  So in order to get a fast transaction
capable RDBMS working for your Perl project you simply have to install this
module, and nothing else.")
    (license (package-license perl))
    (home-page "http://search.cpan.org/~ishigaki/DBD-SQLite/lib/DBD/SQLite.pm")))

(define-public perl-sql-abstract
  (package
    (name "perl-sql-abstract")
    (version "1.81")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/R/RI/RIBASUSHI/"
                           "SQL-Abstract-" version ".tar.gz"))
       (sha256
        (base32
         "17sgwq3mvqjhv3b77cnvrq60xgp8harjhlnvpwmxc914rqc5ckaz"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-deep" ,perl-test-deep)
       ("perl-test-exception" ,perl-test-exception)
       ("perl-test-warn" ,perl-test-warn)))
    (propagated-inputs
     `(("perl-hash-merge" ,perl-hash-merge)
       ("perl-moo" ,perl-moo)
       ("perl-mro-compat" ,perl-mro-compat)
       ("perl-text-balanced" ,perl-text-balanced)))
    (home-page "http://search.cpan.org/dist/SQL-Abstract")
    (synopsis "Generate SQL from Perl data structures")
    (description "This module was inspired by the excellent DBIx::Abstract.
While based on the concepts used by DBIx::Abstract, the concepts used have
been modified to make the SQL easier to generate from Perl data structures.
The underlying idea is for this module to do what you mean, based on the data
structures you provide it, so that you don't have to modify your code every
time your data changes.")
    (license (package-license perl))))

(define-public perl-sql-splitstatement
  (package
    (name "perl-sql-splitstatement")
    (version "1.00020")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/E/EM/EMAZEP/"
                           "SQL-SplitStatement-" version ".tar.gz"))
       (sha256
        (base32
         "0bqg45k4c9qkb2ypynlwhpvzsl4ssfagmsalys18s5c79ps30z7p"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-test-exception" ,perl-test-exception)))
    (propagated-inputs
     `(("perl-class-accessor" ,perl-class-accessor)
       ("perl-list-moreutils" ,perl-list-moreutils)
       ("perl-regexp-common" ,perl-regexp-common)
       ("perl-sql-tokenizer" ,perl-sql-tokenizer)))
    (home-page "http://search.cpan.org/dist/SQL-SplitStatement")
    (synopsis "Split SQL code into atomic statements")
    (description "This module tries to split any SQL code, even including
non-standard extensions, into the atomic statements it is composed of.")
    (license (package-license perl))))

(define-public perl-sql-tokenizer
  (package
    (name "perl-sql-tokenizer")
    (version "0.24")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/I/IZ/IZUT/"
                           "SQL-Tokenizer-" version ".tar.gz"))
       (sha256
        (base32
         "1qa2dfbzdlr5qqdam9yn78z5w3al5r8577x06qan8wv58ay6ka7s"))))
    (build-system perl-build-system)
    (home-page "http://search.cpan.org/dist/SQL-Tokenizer")
    (synopsis "SQL tokenizer")
    (description "SQL::Tokenizer is a tokenizer for SQL queries.  It does not
claim to be a parser or query verifier.  It just creates sane tokens from a
valid SQL query.")
    (license (package-license perl))))

(define-public unixodbc
  (package
   (name "unixodbc")
   (version "2.3.4")
   (source (origin
            (method url-fetch)
            (uri
             (string-append
              "ftp://ftp.unixodbc.org/pub/unixODBC/unixODBC-"
              version ".tar.gz"))
            (sha256
             (base32 "0f8y88rcc2akjvjv5y66yx7k0ms9h1s0vbcfy25j93didflhj59f"))))
   (build-system gnu-build-system)
   (synopsis "Data source abstraction library")
   (description "Unixodbc is a library providing an API with which to access
data sources.  Data sources include SQL Servers and any software with an ODBC
Driver.")
   (license lgpl2.1+)
   ;; COPYING contains copy of lgpl2.1 - but copyright notices just say "LGPL"
   (home-page "http://www.unixodbc.org")))

(define-public unqlite
  (package
    (name "unqlite")
    (version "1.1.6")
    (source (origin
              (method url-fetch)
              ;; Contains bug fixes against the official release, and has an
              ;; autotooled build system.
              (uri (string-append "https://github.com/aidin36/tocc/releases/"
                                  "download/v1.0.0/"
                                  "unqlite-unofficial-" version ".tar.gz"))
              (sha256
               (base32
                "1sbpvhg15gadq0mpcy16q7k3rkg4b4dicpnn5xifpkpn02sqik3s"))))
    (build-system gnu-build-system)
    (arguments `(#:tests? #f))          ;No check target
    (home-page "http://www.unqlite.org")
    (synopsis "In-memory key/value and document store")
    (description
     "UnQLite is an in-process software library which implements a
self-contained, serverless, zero-configuration, transactional NoSQL
database engine.  UnQLite is a document store database similar to
MongoDB, Redis, CouchDB, etc. as well as a standard Key/Value store
similar to BerkeleyDB, LevelDB, etc.")
    (license bsd-2)))

(define-public redis
  (package
    (name "redis")
    (version "3.2.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://download.redis.io/releases/redis-"
                                  version".tar.gz"))
              (sha256
               (base32
                "1wb9jd692a0y52bkkxr6815kk4g039mirjdrvqx24265lv2l5l1a"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ; tests related to master/slave and replication fail
       #:phases (modify-phases %standard-phases
                  (delete 'configure))
       #:make-flags `("CC=gcc"
                      "MALLOC=libc"
                      "LDFLAGS=-ldl"
                      ,(string-append "PREFIX="
                                      (assoc-ref %outputs "out")))))
    (synopsis "Key-value cache and store")
    (description "Redis is an advanced key-value cache and store.  Redis
supports many data structures including strings, hashes, lists, sets, sorted
sets, bitmaps and hyperloglogs.")
    (home-page "http://redis.io/")
    (license bsd-3)))

(define-public kyotocabinet
  (package
    (name "kyotocabinet")
    (version "1.2.76")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://fallabs.com/kyotocabinet/pkg/"
                                  name "-" version ".tar.gz"))
              (sha256
               (base32
                "0g6js20x7vnpq4p8ghbw3mh9wpqksya9vwhzdx6dnlf354zjsal1"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags
       (list
        (string-append "LDFLAGS=-Wl,-rpath="
                       (assoc-ref %outputs "out") "/lib"))))
    (inputs `(("zlib" ,zlib)))
    (home-page "http://fallabs.com/kyotocabinet/")
    (synopsis
     "Kyoto Cabinet is a modern implementation of the DBM database")
    (description
     "Kyoto Cabinet is a standalone file-based database that supports Hash
and B+ Tree data storage models.  It is a fast key-value lightweight
database and supports many programming languages.  It is a NoSQL database.")
    (license gpl3+)))

(define-public wiredtiger
  (package
    (name "wiredtiger")
    (version "2.8.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://source.wiredtiger.com/releases/wiredtiger-"
                    version ".tar.bz2"))
              (sha256
               (base32
                "1qh7y5paisdxq19jgg81ld7i32lz920n5k30hdpxnr8ll9c4hgjr"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags '("--enable-lz4" "--enable-zlib")
       #:phases
       (modify-phases %standard-phases
         (add-before 'check 'disable-test/fops
           (lambda _
             ;; XXX: timed out after 3600 seconds of silence
             (substitute* "Makefile"
               (("test/fops") ""))
             #t)))))
    (inputs
     `(("lz4" ,lz4)
       ("zlib" ,zlib)))
    (home-page "http://source.wiredtiger.com/")
    (synopsis "NoSQL data engine")
    (description
     "WiredTiger is an extensible platform for data management.  It supports
row-oriented storage (where all columns of a row are stored together),
column-oriented storage (where columns are stored in groups, allowing for
more efficient access and storage of column subsets) and log-structured merge
trees (LSM), for sustained throughput under random insert workloads.")
    (license gpl3) ; or GPL-2
    ;; configure.ac: WiredTiger requires a 64-bit build.
    (supported-systems '("x86_64-linux" "mips64el-linux"))))

(define-public perl-db-file
 (package
  (name "perl-db-file")
  (version "1.838")
  (source
    (origin
      (method url-fetch)
      (uri (string-append
             "mirror://cpan/authors/id/P/PM/PMQS/DB_File-"
             version
             ".tar.gz"))
      (sha256
        (base32
          "0yp5d5zr8dk9g6xdh7ygi5bq63q7nxvhd58dk2i3ki4nb7yv2yh9"))))
  (build-system perl-build-system)
  (inputs `(("bdb" ,bdb)))
  (native-inputs `(("perl-test-pod" ,perl-test-pod)))
  (arguments
     `(#:phases (modify-phases %standard-phases
                  (add-before
                   'configure 'modify-config.in
                   (lambda* (#:key inputs #:allow-other-keys)
                     (substitute* "config.in"
                       (("/usr/local/BerkeleyDB") (assoc-ref inputs "bdb")))
                     #t)))))
  (home-page "http://search.cpan.org/dist/DB_File")
  (synopsis
    "Perl5 access to Berkeley DB version 1.x")
  (description
    "The DB::File module provides Perl bindings to the Berkeley DB version 1.x.")
  (license (package-license perl))))

(define-public lmdb
  (package
    (name "lmdb")
    (version "0.9.18")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/LMDB/lmdb/archive/"
                                  "LMDB_" version ".tar.gz"))
              (sha256
               (base32
                "12crvzxky8in99ibh22k4ppmkgqs28yy3v7yy944za7fsrqv8dfx"))))
    (build-system gnu-build-system)
    (arguments
     `(#:test-target "test"
       #:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (chdir (string-append
               (getenv "PWD") "/lmdb-LMDB_" ,version "/libraries/liblmdb"))
             (substitute* "Makefile"
               (("/usr/local") (assoc-ref outputs "out")))
            #t)))))
    (home-page "https://symas.com/products/lightning-memory-mapped-database")
    (synopsis "Lightning memory-mapped database library")
    (description "Lightning memory-mapped database library.")
    (license license:openldap2.8)))

(define-public libpqxx
  (package
    (name "libpqxx")
    (version "4.0.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://pqxx.org/download/software/libpqxx/"
                    name "-" version ".tar.gz"))
              (sha256
               (base32
                "0f6wxspp6rx12fkasanb0z2g2gc8dhcfwnxagx8wwqbpg6ifsz09"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("python" ,python-2)))
    (inputs `(("postgresql" ,postgresql)))
    (arguments
     `(#:tests? #f)) ; # FAIL:  1
    (synopsis "C++ connector for PostgreSQL")
    (description
     "Libpqxx is a C++ library to enable user programs to communicate with the
PostgreSQL database back-end.  The database back-end can be local or it may be
on another machine, accessed via TCP/IP.")
    (home-page "http://pqxx.org/")
    (license license:bsd-3)))

(define-public python-peewee
  (package
    (name "python-peewee")
    (version "2.8.3")
      (source
        (origin
        (method url-fetch)
        (uri (pypi-uri "peewee" version))
        (sha256
         (base32
          "1605bk11s7aap2q4qyba93rx7yfh8b11kk0cqi08z8klx2iar8yd"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f)) ; Fails to import test data
    (native-inputs
     `(("python-cython" ,python-cython)))
    (home-page "https://github.com/coleifer/peewee/")
    (synopsis "Small object-relational mapping utility")
    (description
     "Peewee is a simple and small ORM (object-relation mapping) tool.  Peewee
handles converting between pythonic values and those used by databases, so you
can use Python types in your code without having to worry.  It has built-in
support for sqlite, mysql and postgresql.  If you already have a database, you
can autogenerate peewee models using @code{pwiz}, a model generator.")
    (license license:expat)))

(define-public python2-peewee
  (package-with-python2 python-peewee))

(define-public sqlcipher
  (package
    (name "sqlcipher")
    (version "3.3.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/sqlcipher/" name
                           "/archive/v" version ".tar.gz"))
       (sha256
        (base32 "1gv58dlbpzrmznly52yqbxgvii0ib88zr3aszla1bsypwjr6flff"))
       (file-name (string-append name "-" version ".tar.gz"))))
    (build-system gnu-build-system)
    (inputs
     `(("libcrypto" ,openssl)
       ("libtcl8.6" ,tcl))) ; required for running the tests
    (native-inputs
     `(("tcl" ,tcl)))
    (arguments
     '(#:configure-flags
       '("--enable-tempstore=yes"
         "CFLAGS=-DSQLITE_HAS_CODEC -DSQLITE_ENABLE_FTS3"
         "LDFLAGS=-lcrypto -ltcl8.6"
         "--disable-tcl")
       ;; tests cannot be run from the Makefile
       ;; see: <https://github.com/sqlcipher/sqlcipher/issues/172>
       #:test-target "testfixture"
       #:phases
       (modify-phases %standard-phases
         (add-before 'check 'build-test-runner
           (assoc-ref %standard-phases 'check))
         (replace 'check
           (lambda _
             (zero?
              (system* "./testfixture" "test/crypto.test")))))))
    (home-page "https://www.zetetic.net/sqlcipher/")
    (synopsis
     "Library providing transparent encryption of SQLite database files")
    (description "SQLCipher is an implementation of SQLite, extended to
provide transparent 256-bit AES encryption of database files.  Pages are
encrypted before being written to disk and are decrypted when read back.  It’s
well suited for protecting embedded application databases and for mobile
development.")
    ;; The source files
    ;; src/{crypto.c,crypto_impl.c,crypto.h,crypto_cc.c,crypto_libtomcrypt.c},
    ;; src/{crypto_openssl.c,sqlcipher.h}, tool/crypto-speedtest.tcl,
    ;; test/crypto.test are licensed under a 3-clause BSD license. All other
    ;; source files are in the public domain.
    (license (list license:public-domain license:bsd-3))))
