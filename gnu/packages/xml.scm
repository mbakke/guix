;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013, 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2015 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2015 Sou Bunnbu <iyzsong@gmail.com>
;;; Copyright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015, 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2015 Raimon Grau <raimonster@gmail.com>
;;; Copyright © 2016 Mathieu Lirzin <mthl@gnu.org>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
;;; Copyright © 2016 Ben Woodcroft <donttrustben@gmail.com>
;;; Copyright © 2016 Jan Nieuwenhuizen <janneke@gnu.org>
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

(define-module (gnu packages xml)
  #:use-module (gnu packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages python)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages web)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system perl)
  #:use-module (guix build-system python)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages pkg-config))

(define-public expat
  (package
    (name "expat")
    (version "2.2.0")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://sourceforge/expat/expat/"
                                 version "/expat-" version ".tar.bz2"))
             (patches
               (search-patches "expat-CVE-2016-0718-fix-regression.patch"))
             (sha256
              (base32
               "1zq4lnwjlw8s9mmachwfvfjf2x3lk24jm41746ykhdcvs7r0zrfr"))))
    (build-system gnu-build-system)
    (home-page "http://www.libexpat.org/")
    (synopsis "Stream-oriented XML parser library written in C")
    (description
     "Expat is an XML parser library written in C.  It is a
stream-oriented parser in which an application registers handlers for
things the parser might find in the XML document (like start tags).")
    (license license:expat)))

(define-public libxml2
  (package
    (name "libxml2")
    (replacement libxml2/fixed)
    (version "2.9.4")
    (source (origin
             (method url-fetch)
             (uri (string-append "ftp://xmlsoft.org/libxml2/libxml2-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "0g336cr0bw6dax1q48bblphmchgihx9p1pjmxdnrd6sh3qci3fgz"))))
    (build-system gnu-build-system)
    (home-page "http://www.xmlsoft.org/")
    (synopsis "C parser for XML")
    (propagated-inputs `(("zlib" ,zlib))) ; libxml2.la says '-lz'.
    (native-inputs `(("perl" ,perl)))
    ;; $XML_CATALOG_FILES lists 'catalog.xml' files found in under the 'xml'
    ;; sub-directory of any given package.
    (native-search-paths (list (search-path-specification
                                (variable "XML_CATALOG_FILES")
                                (separator " ")
                                (files '("xml"))
                                (file-pattern "^catalog\\.xml$")
                                (file-type 'regular))))
    (search-paths native-search-paths)
    (description
     "Libxml2 is the XML C parser and toolkit developed for the Gnome
project (but it is usable outside of the Gnome platform).")
    (license license:x11)))

(define libxml2/fixed
  (package
    (inherit libxml2)
    (source
      (origin
        (inherit (package-source libxml2))
        (patches (search-patches "libxml2-CVE-2016-4658.patch"
                                 "libxml2-CVE-2016-5131.patch"))))))

(define-public python-libxml2
  (package (inherit libxml2)
    (name "python-libxml2")
    (replacement #f)
    (build-system python-build-system)
    (arguments
     `(;; XXX: Tests are specified in 'Makefile.am', but not in 'setup.py'.
       #:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-before
          'build 'configure
          (lambda* (#:key inputs #:allow-other-keys)
            (chdir "python")
            (let ((glibc   (assoc-ref inputs ,(if (%current-target-system)
                                                  "cross-libc" "libc")))
                  (libxml2 (assoc-ref inputs "libxml2")))
              (substitute* "setup.py"
                ;; For 'libxml2/libxml/tree.h'.
                (("ROOT = r'/usr'")
                 (format #f "ROOT = r'~a'" libxml2))
                ;; For 'iconv.h'.
                (("/opt/include")
                 (string-append glibc "/include")))))))))
    (inputs `(("libxml2" ,libxml2)))
    (synopsis "Python bindings for the libxml2 library")))

(define-public python2-libxml2
  (package-with-python2 python-libxml2))

(define-public libxslt
  (package
    (name "libxslt")
    (replacement libxslt/fixed)
    (version "1.1.29")
    (source (origin
             (method url-fetch)
             (uri (string-append "ftp://xmlsoft.org/libxslt/libxslt-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "1klh81xbm9ppzgqk339097i39b7fnpmlj8lzn8bpczl3aww6x5xm"))
             (patches (search-patches "libxslt-generated-ids.patch"))))
    (build-system gnu-build-system)
    (home-page "http://xmlsoft.org/XSLT/index.html")
    (synopsis "C library for applying XSLT stylesheets to XML documents")
    (inputs `(("libgcrypt" ,libgcrypt)
              ("libxml2" ,libxml2)
              ("python" ,python-minimal-wrapper)
              ("zlib" ,zlib)))
    (description
     "Libxslt is an XSLT C library developed for the GNOME project.  It is
based on libxml for XML parsing, tree manipulation and XPath support.")
    (license license:x11)))

(define libxslt/fixed
  (package
    (inherit libxslt)
    (name "libxslt")
    (source (origin
              (inherit (package-source libxslt))
              (patches (search-patches "libxslt-CVE-2016-4738.patch"))))))

(define-public perl-graph-readwrite
  (package
    (name "perl-graph-readwrite")
    (version "2.09")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "mirror://cpan/authors/id/N/NE/NEILB/Graph-ReadWrite-"
             version
             ".tar.gz"))
       (sha256
        (base32
         "0jlsg64pmy6ka5q5gy851nnyfgjzvhyxc576bhns3vi2x5ng07mh"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-graph" ,perl-graph)
       ("perl-parse-yapp" ,perl-parse-yapp)
       ("perl-xml-parser" ,perl-xml-parser)
       ("perl-xml-writer" ,perl-xml-writer)))
    (home-page "http://search.cpan.org/dist/Graph-ReadWrite")
    (synopsis "Modules for reading and writing directed graphs")
    (description "This is a collection of perl classes for reading and writing
directed graphs in a variety of file formats.  The graphs are represented in
Perl using Jarkko Hietaniemi's @code{Graph} classes.

There are two base classes. @code{Graph::Reader} is the base class for classes
which read a graph file and create an instance of the Graph class.
@code{Graph::Writer} is the base class for classes which take an instance of
the @code{Graph} class and write it out in a specific file format.")
    (license (package-license perl))))

(define-public perl-xml-atom
  (package
    (name "perl-xml-atom")
    (version "0.41")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/M/MI/MIYAGAWA/"
                                  "XML-Atom-" version ".tar.gz"))
              (sha256
               (base32
                "17lnkb9ymrhk2z642bhj5i2bv3q1da3kpp2lvsl0yhqshk3wdjj8"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-datetime" ,perl-datetime)
       ;; TODO package: perl-datetime-format-atom
       ("perl-xml-xpath" ,perl-xml-xpath)))
    (inputs
     `(("perl-class-data-inheritable" ,perl-class-data-inheritable)
       ("perl-datetime" ,perl-datetime)
       ("perl-datetime-timezone" ,perl-datetime-timezone)
       ("perl-digest-sha1" ,perl-digest-sha1)
       ("perl-libwww" ,perl-libwww)
       ("perl-uri" ,perl-uri)
       ("perl-xml-libxml" ,perl-xml-libxml)
       ("perl-xml-xpath" ,perl-xml-xpath)))
    (home-page "http://search.cpan.org/dist/XML-Atom")
    (synopsis "Atom feed and API implementation")
    (description
     "Atom is a syndication, API, and archiving format for weblogs and other data.
@code{XML::Atom} implements the feed format as well as a client for the API.")
    (license (package-license perl))))

(define-public perl-xml-parser
  (package
    (name "perl-xml-parser")
    (version "2.44")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/T/TO/TODDR/XML-Parser-"
                   version ".tar.gz"))
             (sha256
              (base32
               "05ij0g6bfn27iaggxf8nl5rhlwx6f6p6xmdav6rjcly3x5zd1s8s"))))
    (build-system perl-build-system)
    (arguments `(#:make-maker-flags
                 (let ((expat (assoc-ref %build-inputs "expat")))
                   (list (string-append "EXPATLIBPATH=" expat "/lib")
                         (string-append "EXPATINCPATH=" expat "/include")))))
    (inputs `(("expat" ,expat)))
    (license (package-license perl))
    (synopsis "Perl bindings to the Expat XML parsing library")
    (description
     "This module provides ways to parse XML documents.  It is built on top of
XML::Parser::Expat, which is a lower level interface to James Clark's expat
library.  Each call to one of the parsing methods creates a new instance of
XML::Parser::Expat which is then used to parse the document.  Expat options
may be provided when the XML::Parser object is created.  These options are
then passed on to the Expat object on each parse call.  They can also be given
as extra arguments to the parse methods, in which case they override options
given at XML::Parser creation time.")
    (home-page "http://search.cpan.org/dist/XML-Parser")))

(define-public perl-libxml
  (package
    (name "perl-libxml")
    (version "0.08")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/K/KM/KMACLEOD/libxml-perl-"
                   version ".tar.gz"))
             (sha256
              (base32
               "1jy9af0ljyzj7wakqli0437zb2vrbplqj4xhab7bfj2xgfdhawa5"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-xml-parser" ,perl-xml-parser)))
    (license (package-license perl))
    (synopsis "Perl SAX parser using XML::Parser")
    (description
     "XML::Parser::PerlSAX is a PerlSAX parser using the XML::Parser
module.")
    (home-page "http://search.cpan.org/~kmacleod/libxml-perl/lib/XML/Parser/PerlSAX.pm")))

(define-public perl-xml-libxml
  (package
    (name "perl-xml-libxml")
    (version "2.0128")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/S/SH/SHLOMIF/"
                           "XML-LibXML-" version ".tar.gz"))
       (sha256
        (base32
         "0awgd2gjzy7kn38bqblsigikzl81xsi561phkz9f9b9v3x2vmrr6"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-xml-namespacesupport" ,perl-xml-namespacesupport)
       ("perl-xml-sax" ,perl-xml-sax)))
    (inputs
     `(("libxml2" ,libxml2)))
    (home-page "http://search.cpan.org/dist/XML-LibXML")
    (synopsis "Perl interface to libxml2")
    (description "This module implements a Perl interface to the libxml2
library which provides interfaces for parsing and manipulating XML files.  This
module allows Perl programmers to make use of the highly capable validating
XML parser and the high performance DOM implementation.")
    (license (package-license perl))))

(define-public perl-xml-libxml-simple
  (package
    (name "perl-xml-libxml-simple")
    (version "0.97")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/M/MA/MARKOV/"
                                  "XML-LibXML-Simple-" version ".tar.gz"))
              (sha256
               (base32
                "1g8nlk3zdz2cclxf7azvsb3jfxmvy6ml8wmj774k4qjqcsqmzk0w"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-file-slurp-tiny" ,perl-file-slurp-tiny)
       ("perl-xml-libxml" ,perl-xml-libxml)))
    (home-page "http://search.cpan.org/dist/XML-LibXML-Simple")
    (synopsis "XML::LibXML based XML::Simple clone")
    (description
     "This package provides the same API as @code{XML::Simple} but is based on
@code{XML::LibXML}.")
    (license (package-license perl))))

(define-public perl-xml-libxslt
  (package
    (name "perl-xml-libxslt")
    (version "1.95")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/S/SH/SHLOMIF/"
                           "XML-LibXSLT-" version ".tar.gz"))
       (sha256
        (base32
         "0dggycql18kfxzkb1kw3yc7gslxlrrgyyn2r2ygsylycb89j3jpi"))))
    (build-system perl-build-system)
    (inputs
     `(("libxslt" ,libxslt)))
    (propagated-inputs
     `(("perl-xml-libxml" ,perl-xml-libxml)))
    (home-page "http://search.cpan.org/dist/XML-LibXSLT")
    (synopsis "Perl bindings to GNOME libxslt library")
    (description "This Perl module is an interface to the GNOME project's
libxslt library.")
    (license (package-license perl))))

(define-public perl-xml-namespacesupport
  (package
    (name "perl-xml-namespacesupport")
    (version "1.11")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/P/PE/PERIGRIN/"
                           "XML-NamespaceSupport-" version ".tar.gz"))
       (sha256
        (base32
         "1sklgcldl3w6gn706vx1cgz6pm4y5lfgsjxnfqyk20pilgq530bd"))))
    (build-system perl-build-system)
    (home-page "http://search.cpan.org/dist/XML-NamespaceSupport")
    (synopsis "XML namespace support class")
    (description "This module offers a simple to process namespaced XML
names (unames) from within any application that may need them.  It also helps
maintain a prefix to namespace URI map, and provides a number of basic
checks.")
    (license (package-license perl))))

(define-public perl-xml-rss
  (package
    (name "perl-xml-rss")
    (version "1.59")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/S/SH/SHLOMIF/"
                                  "XML-RSS-" version ".tar.gz"))
              (sha256
               (base32
                "0v6vfizn2psy6av057kp7fv3z3y73s6b3w56jm3zr6hlq48llsx2"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-module-build" ,perl-module-build)
       ("perl-test-manifest" ,perl-test-manifest)
       ("perl-test-differences" ,perl-test-differences)
       ("perl-test-pod" ,perl-test-pod)
       ("perl-test-pod-coverage" ,perl-test-pod-coverage)))
    ;; XXX: The test which uses this modules does not run, even when it is included
    ;; it is ignored. ("perl-test-trailingspace" ,perl-test-trailingspace)
    (inputs
     `(("perl-datetime" ,perl-datetime)
       ("perl-datetime-format-mail" ,perl-datetime-format-mail)
       ("perl-datetime-format-w3cdtf" ,perl-datetime-format-w3cdtf)
       ("perl-html-parser" ,perl-html-parser)
       ("perl-xml-parser" ,perl-xml-parser)))
    (home-page "http://search.cpan.org/dist/XML-RSS")
    (synopsis "Creates and updates RSS files")
    (description
     "This module provides a basic framework for creating and maintaining
RDF Site Summary (RSS) files.  This distribution also contains many examples
that allow you to generate HTML from an RSS, convert between 0.9, 0.91, and
1.0 version, and more.")
    (license (package-license perl))))

(define-public perl-xml-sax
  (package
    (name "perl-xml-sax")
    (version "0.99")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/G/GR/GRANTM/"
                           "XML-SAX-" version ".tar.gz"))
       (sha256
        (base32
         "115dypb50w1l94y3iwihv5nkixbsv1cxiqkd93y4rk5n6s74pc1j"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-xml-namespacesupport" ,perl-xml-namespacesupport)
       ("perl-xml-sax-base" ,perl-xml-sax-base)))
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (add-before
                   'install 'augment-path
                   ;; The install target tries to load the newly-installed
                   ;; XML::SAX module, but can't find it, so we need to tell
                   ;; perl where to look.
                   (lambda* (#:key outputs #:allow-other-keys)
                     (setenv "PERL5LIB"
                             (string-append (getenv "PERL5LIB") ":"
                                            (assoc-ref outputs "out")
                                            "/lib/perl5/site_perl")))))))
    (home-page "http://search.cpan.org/dist/XML-SAX")
    (synopsis "Perl API for XML")
    (description "XML::SAX consists of several framework classes for using and
building Perl SAX2 XML parsers, filters, and drivers.")
    (license (package-license perl))))

(define-public perl-xml-sax-base
  (package
    (name "perl-xml-sax-base")
    (version "1.08")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://cpan/authors/id/G/GR/GRANTM/"
                           "XML-SAX-Base-" version ".tar.gz"))
       (sha256
        (base32
         "17i161rq1ngjlk0c8vdkrkkc56y1pf51k1g54y28py0micqp0qk6"))))
    (build-system perl-build-system)
    (home-page "http://search.cpan.org/dist/XML-SAX-Base")
    (synopsis "Base class for SAX Drivers and Filters")
    (description "This module has a very simple task - to be a base class for
PerlSAX drivers and filters.  It's default behaviour is to pass the input
directly to the output unchanged.  It can be useful to use this module as a
base class so you don't have to, for example, implement the characters()
callback.")
    (license (package-license perl))))

(define-public perl-xml-simple
  (package
    (name "perl-xml-simple")
    (version "2.22")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/G/GR/GRANTM/XML-Simple-"
                   version ".tar.gz"))
             (sha256
              (base32
               "0jgbk30jizafpl7078jhw1di1yh08gf8d85dsvjllr595vr0widr"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-xml-parser" ,perl-xml-parser)
       ("perl-xml-sax" ,perl-xml-sax)))
    (license (package-license perl))
    (synopsis "Perl module for easy reading/writing of XML files")
    (description
     "The XML::Simple module provides a simple API layer on top of an
underlying XML parsing module (either XML::Parser or one of the SAX2
parser modules).")
    (home-page "http://search.cpan.org/dist/XML-Simple")))

(define-public perl-xml-regexp
  (package
    (name "perl-xml-regexp")
    (version "0.04")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/T/TJ/TJMATHER/XML-RegExp-"
                   version ".tar.gz"))
             (sha256
              (base32
               "0m7wj00a2kik7wj0azhs1zagwazqh3hlz4255n75q21nc04r06fz"))))
    (build-system perl-build-system)
    (inputs
     `(("perl-xml-parser" ,perl-xml-parser)))
    (license (package-license perl))
    (synopsis "Perl regular expressions for XML tokens")
    (description
     "XML::RegExp contains regular expressions for the following XML tokens:
BaseChar, Ideographic, Letter, Digit, Extender, CombiningChar, NameChar,
EntityRef, CharRef, Reference, Name, NmToken, and AttValue.")
    (home-page "http://search.cpan.org/~tjmather/XML-RegExp/lib/XML/RegExp.pm")))

(define-public perl-xml-dom
  (package
    (name "perl-xml-dom")
    (version "1.46")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://cpan/authors/id/T/TJ/TJMATHER/XML-DOM-"
                   version ".tar.gz"))
             (sha256
              (base32
               "0phpkc4li43m2g44hdcvyxzy9pymqwlqhh5hwp2xc0cv8l5lp8lb"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-libwww" ,perl-libwww)
       ("perl-libxml" ,perl-libxml)
       ("perl-xml-parser" ,perl-xml-parser)
       ("perl-xml-regexp" ,perl-xml-regexp)))
    (license (package-license perl))
    (synopsis
     "Perl module for building DOM Level 1 compliant document structures")
    (description
     "This module extends the XML::Parser module by Clark Cooper.  The
XML::Parser module is built on top of XML::Parser::Expat, which is a lower
level interface to James Clark's expat library.  XML::DOM::Parser is derived
from XML::Parser.  It parses XML strings or files and builds a data structure
that conforms to the API of the Document Object Model.")
    (home-page "http://search.cpan.org/~tjmather/XML-DOM-1.44/lib/XML/DOM.pm")))

(define-public perl-xml-compile-tester
  (package
    (name "perl-xml-compile-tester")
    (version "0.90")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/M/MA/MARKOV/"
                                  "XML-Compile-Tester-" version ".tar.gz"))
              (sha256
               (base32
                "1bcl8x8cyacqv9yjp97aq9qq85sy8wv78kd8c16yd9yw3by4cpp1"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-log-report" ,perl-log-report)
       ("perl-test-deep" ,perl-test-deep)))
    (home-page "http://search.cpan.org/dist/XML-Compile-Tester")
    (synopsis "XML::Compile related regression testing")
    (description
     "The @code{XML::Compile} module suite has extensive regression testing.
This module provide functions which simplify writing tests for
@code{XML::Compile} related distributions.")
    (license (package-license perl))))

(define-public perl-xml-compile
  (package
    (name "perl-xml-compile")
    (version "1.54")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/M/MA/MARKOV/"
                                  "XML-Compile-" version ".tar.gz"))
              (sha256
               (base32
                "1hp41960bpqxvv1samv9hc0ghhmvs3i16r4rfl9yp54lp6jhsr2c"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-log-report" ,perl-log-report)
       ("perl-xml-compile-tester" ,perl-xml-compile-tester)
       ("perl-xml-libxml" ,perl-xml-libxml)
       ("perl-test-deep" ,perl-test-deep)))
    (home-page "http://search.cpan.org/dist/XML-Compile")
    (synopsis "Compilation-based XML processing")
    (description
     "@code{XML::Compile} can be used to translate a Perl data-structure into
XML or XML into a Perl data-structure, both directions under rigid control by
a schema.")
    (license (package-license perl))))

(define-public perl-xml-compile-cache
  (package
    (name "perl-xml-compile-cache")
    (version "1.05")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/M/MA/MARKOV/"
                                  "XML-Compile-Cache-" version ".tar.gz"))
              (sha256
               (base32
                "0xbwlszhi9hg8sxm5ylglm2qvnb689i595p913awrj2g4mp9yfsw"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-log-report" ,perl-log-report)
       ("perl-xml-compile" ,perl-xml-compile)
       ("perl-xml-compile-tester" ,perl-xml-compile-tester)
       ("perl-xml-libxml-simple" ,perl-xml-libxml-simple)))
    (home-page "http://search.cpan.org/dist/XML-Compile-Cache")
    (synopsis "Cache compiled XML translators")
    (description
     "This package provides methods to cache compiled XML translators.")
    (license (package-license perl))))

(define-public perl-xml-compile-soap
  (package
    (name "perl-xml-compile-soap")
    (version "3.20")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/M/MA/MARKOV/"
                                  "XML-Compile-SOAP-" version ".tar.gz"))
              (sha256
               (base32
                "0qplb77qr97pc9yis51jmphl9gbq9xyf8abldpxkwvdn6iqlbgx5"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-file-slurp-tiny" ,perl-file-slurp-tiny)
       ("perl-libwww" ,perl-libwww)
       ("perl-log-report" ,perl-log-report)
       ("perl-xml-compile" ,perl-xml-compile)
       ("perl-xml-compile-cache" ,perl-xml-compile-cache)
       ("perl-xml-compile-tester" ,perl-xml-compile-tester)))
    (home-page "http://search.cpan.org/dist/XML-Compile-SOAP")
    (synopsis "Base-class for SOAP implementations")
    (description
     "This module provides a class to handle the SOAP protocol.  The first
implementation is @url{SOAP1.1,
http://www.w3.org/TR/2000/NOTE-SOAP-20000508/}, which is still most often
used.")
    (license (package-license perl))))

(define-public perl-xml-compile-wsdl11
  (package
    (name "perl-xml-compile-wsdl11")
    (version "3.05")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/M/MA/MARKOV/"
                                  "XML-Compile-WSDL11-" version ".tar.gz"))
              (sha256
               (base32
                "1a50in1qrbzx3924wvrhgfm5fcxz5cd95f3z9z2xgln27q1zssc4"))))
    (build-system perl-build-system)
    (propagated-inputs
     `(("perl-log-report" ,perl-log-report)
       ("perl-xml-compile" ,perl-xml-compile)
       ("perl-xml-compile-cache" ,perl-xml-compile-cache)
       ("perl-xml-compile-soap" ,perl-xml-compile-soap)))
    (home-page "http://search.cpan.org/dist/XML-Compile-WSDL11")
    (synopsis "Create SOAP messages defined by WSDL 1.1")
    (description
     "This module understands WSDL version 1.1.  A WSDL file defines a set of
messages to be send and received over SOAP connections.  This involves
encoding of the message to be send into XML, sending the message to the
server, collect the answer, and finally decoding the XML to Perl.")
    (license (package-license perl))))

(define-public perl-xml-feed
  (package
    (name "perl-xml-feed")
    (version "0.53")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/D/DA/DAVECROSS/"
                                  "XML-Feed-" version ".tar.gz"))
              (sha256
               (base32
                "07b165g6wk8kqwpl49r3n0kag6p2nrkyp3ch0h8qyxb6nrnkkq7c"))))
    (build-system perl-build-system)
    (arguments
     `(#:tests? #f)) ; Tests require internet connection
    (native-inputs
     `(("perl-module-build" ,perl-module-build)
       ("perl-uri" ,perl-uri)
       ("perl-class-data-inheritable" ,perl-class-data-inheritable)))
    (inputs
     `(("perl-class-errorhandler" ,perl-class-errorhandler)
       ("perl-datetime" ,perl-datetime)
       ("perl-datetime-format-mail" ,perl-datetime-format-mail)
       ("perl-datetime-format-w3cdtf" ,perl-datetime-format-w3cdtf)
       ("perl-feed-find" ,perl-feed-find)
       ("perl-html-parser" ,perl-html-parser)
       ("perl-libwww-perl" ,perl-libwww)
       ("perl-module-pluggable" ,perl-module-pluggable)
       ("perl-uri-fetch" ,perl-uri-fetch)
       ("perl-xml-atom" ,perl-xml-atom)
       ("perl-xml-libxml" ,perl-xml-libxml)
       ("perl-xml-rss" ,perl-xml-rss)))
    (home-page "http://search.cpan.org/dist/XML-Feed")
    (synopsis "XML Syndication Feed Support")
    (description "@code{XML::Feed} is a syndication feed parser for both RSS and
Atom feeds.  It also implements feed auto-discovery for finding feeds, given a URI.
@code{XML::Feed} supports the following syndication feed formats:
RSS 0.91, RSS 1.0, RSS 2.0, Atom")
    (license (package-license perl))))

(define-public perl-xml-xpath
  (package
    (name "perl-xml-xpath")
    (version "1.40")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cpan/authors/id/M/MA/MANWAR/"
                                  "XML-XPath-" version ".tar.gz"))
              (sha256
               (base32
                "07pa0bl42jka8mj7jshjynx8vpfh8b4cdyiv4zlkqvkqz98nzxib"))))
    (build-system perl-build-system)
    (native-inputs
     `(("perl-path-tiny" ,perl-path-tiny)))
    (inputs
     `(("perl-xml-parser" ,perl-xml-parser)))
    (home-page "http://search.cpan.org/dist/XML-XPath")
    (synopsis "Parse and evaluate XPath statements")
    (description
     "This module aims to comply exactly to the @url{XPath specification,
https://www.w3.org/TR/xpath} and yet allow extensions to be added in
the form of functions.")
    (license (package-license perl))))

(define-public pugixml
  (package
    (name "pugixml")
    (version "1.7")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://github.com/zeux/pugixml/releases/download/v"
                          version "/pugixml-" version ".tar.gz"))
      (sha256
       (base32
        "1jpml475kbhs1aqwa48g2cbfxlrb9qp115m2j9yryxhxyr30vqgv"))))
    (build-system cmake-build-system)
    (arguments
     `(#:tests? #f
       #:out-of-source? #f
       #:phases (modify-phases %standard-phases
                  (add-before
                   'configure 'chdir
                   (lambda _
                     (chdir "scripts")
                     #t)))))
    (home-page "http://pugixml.org")
    (synopsis "Light-weight, simple and fast XML parser for C++ with XPath support")
    (description
     "pugixml is a C++ XML processing library, which consists of a DOM-like
interface with rich traversal/modification capabilities, a fast XML parser
which constructs the DOM tree from an XML file/buffer, and an XPath 1.0
implementation for complex data-driven tree queries.  Full Unicode support is
also available, with Unicode interface variants and conversions between
different Unicode encodings which happen automatically during
parsing/saving.")
    (license license:expat)))

(define-public python-pyxb
  (package
    (name "python-pyxb")
    (version "1.2.5")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "PyXB" version))
              (sha256
               (base32
                "0rzzwibfqa28gxgcxx4cybx1qcg0g6fand06ykj3gz7z5kp653sf"))))
    (build-system python-build-system)
    (home-page "http://pyxb.sourceforge.net/")
    (synopsis "Python XML Schema Bindings")
    (description
     "PyXB (\"pixbee\") is a pure Python package that generates Python source
code for classes that correspond to data structures defined by XMLSchema.")
    (license (list license:asl2.0    ; Most files.
                   license:expat     ; pyxb/utils/six.py
                   license:gpl2      ; bundled jquery in doc is dual MIT/GPL2
                   license:psfl))))  ; pyxb/utils/activestate.py

(define-public python2-pyxb
  (package-with-python2 python-pyxb))

(define-public xmlto
  (package
    (name "xmlto")
    (version "0.0.28")
    (source
     (origin
      (method url-fetch)
      (uri (string-append
            "https://fedorahosted.org/releases/x/m/xmlto/xmlto-"
            version ".tar.bz2"))
      (sha256
       (base32
        "0xhj8b2pwp4vhl9y16v3dpxpsakkflfamr191mprzsspg4xdyc0i"))))
    (build-system gnu-build-system)
    (arguments
     ;; Make sure the reference to util-linux's 'getopt' is kept in 'xmlto'.
     '(#:configure-flags (list (string-append "GETOPT="
                                              (assoc-ref %build-inputs
                                                         "util-linux")
                                              "/bin/getopt"))))
    (inputs
     `(("util-linux" ,util-linux)                 ; for 'getopt'
       ("libxml2" ,libxml2)                       ; for 'xmllint'
       ("libxslt" ,libxslt)))                     ; for 'xsltproc'
    (home-page "http://cyberelk.net/tim/software/xmlto/")
    (synopsis "Front-end to an XSL toolchain")
    (description
     "Xmlto is a front-end to an XSL toolchain.  It chooses an appropriate
stylesheet for the conversion you want and applies it using an external
XSL-T processor.  It also performs any necessary post-processing.")
    (license license:gpl2+)))

(define-public xmlsec
  (package
    (name "xmlsec")
    (version "1.2.20")
    (source (origin
             (method url-fetch)
             (uri (string-append "https://www.aleksey.com/xmlsec/download/"
                                 name "1-" version ".tar.gz"))
             (sha256
              (base32
               "01bkbv2y3x8d1sf4dcln1x3y2jyj391s3208d9a2ndhglly5j89j"))))
    (build-system gnu-build-system)
    (propagated-inputs ; according to xmlsec1.pc
     `(("libxml2" ,libxml2)
       ("libxslt" ,libxslt)))
    (inputs
     `(("gnutls" ,gnutls)
       ("libgcrypt" ,libgcrypt)
       ("libltdl" ,libltdl)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://www.libexpat.org/")
    (synopsis "XML Security Library")
    (description
     "The XML Security Library is a C library based on Libxml2.  It
supports XML security standards such as XML Signature, XML Encryption,
Canonical XML (part of Libxml2) and Exclusive Canonical XML (part of
Libxml2).")
    (license (license:x11-style "file://COPYING"
                                "See 'COPYING' in the distribution."))))

(define-public minixml
  (package
    (name "minixml")
    (version "2.9")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.msweet.org/files/project3/mxml-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "14pzhlfidj5v1qbxy7a59yn4jz9pnjrs2zwalz228jsq7ijm9vfd"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f))  ;no "check" target
    (home-page "http://www.minixml.org/")
    (synopsis "Small XML parsing library")
    (description
     "Mini-XML is a small C library to read and write XML files and strings in
UTF-8 and UTF-16 encoding.")
    ;; LGPL 2.0+ with additional exceptions for static linking
    (license license:lgpl2.0+)))

;; TinyXML is an unmaintained piece of software, so the patches and build
;; system massaging have no upstream potential.
(define-public tinyxml
  (package
    (name "tinyxml")
    (version "2.6.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/tinyxml/tinyxml/"
                                  version "/tinyxml_"
                                  (string-join (string-split version #\.) "_")
                                  ".tar.gz"))
              (sha256
               (base32
                "14smciid19lvkxqznfig77jxn5s4iq3jpb47vh5a6zcaqp7gvg8m"))
              (patches (search-patches "tinyxml-use-stl.patch"))))
    (build-system gnu-build-system)
    ;; This library is missing *a lot* of the steps to make it usable, so we
    ;; have to add them here, like every other distro must do.
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (add-after 'build 'build-shared-library
           (lambda _
             (zero? (system* "g++" "-Wall" "-O2" "-shared" "-fpic"
                             "tinyxml.cpp" "tinyxmlerror.cpp"
                             "tinyxmlparser.cpp" "tinystr.cpp"
                             "-o" "libtinyxml.so"))))
         (replace 'check
           (lambda _ (zero? (system "./xmltest"))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (include (string-append out "/include"))
                    (lib (string-append out "/lib"))
                    (pkgconfig (string-append out "/lib/pkgconfig"))
                    (doc (string-append out "/share/doc")))
               ;; Install libs and headers.
               (install-file "libtinyxml.so" lib)
               (install-file "tinystr.h" include)
               (install-file "tinyxml.h" include)
               ;; Generate and install pkg-config file.
               (mkdir-p pkgconfig)
               ;; Software such as Kodi expect this file to be present, but
               ;; it's not provided in the source code.
               (call-with-output-file (string-append pkgconfig "/tinyxml.pc")
                 (lambda (port)
                   (format port "prefix=~a
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include

Name: TinyXML
Description: A simple, small, C++ XML parser
Version: ~a
Libs: -L${libdir} -ltinyxml
Cflags: -I${includedir}
"
                           out ,version)))
               ;; Install docs.
               (mkdir-p doc)
               (copy-recursively "docs" (string-append doc "tinyxml"))
               #t))))))
    (synopsis "Small XML parser for C++")
    (description "TinyXML is a small and simple XML parsing library for the
C++ programming language.")
    (home-page "http://www.grinninglizard.com/tinyxml/index.html")
    (license license:zlib)))

(define-public tinyxml2
  (package
    (name "tinyxml2")
    (version "4.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/leethomason/tinyxml2/archive/"
                           version ".tar.gz"))
       (sha256
       (base32
        "083z4r4khcndxi9k840lcr48sqxvar4gpsnf749xfdn1bkr8xcql"))))
    (build-system cmake-build-system)
    (arguments
     `(#:tests? #f))    ; no tests
    (synopsis "Small XML parser for C++")
    (description "TinyXML2 is a small and simple XML parsing library for the
C++ programming language.")
    (home-page "http://www.grinninglizard.com/tinyxml2/")
    (license license:zlib)))

(define-public xmlstarlet
 (package
   (name "xmlstarlet")
   (version "1.6.1")
   (source
    (origin
      (method url-fetch)
      (uri (string-append "mirror://sourceforge/xmlstar/xmlstarlet/"
                          version "/xmlstarlet-" version ".tar.gz"))
      (sha256
       (base32
        "1jp737nvfcf6wyb54fla868yrr39kcbijijmjpyk4lrpyg23in0m"))))
   (build-system gnu-build-system)
   (inputs
    `(("libxslt" ,libxslt)
      ("libxml2" ,libxml2)))
   (home-page "http://xmlstar.sourceforge.net/")
   (synopsis "Command line XML toolkit")
   (description "XMLStarlet is a set of command line utilities which can be
used to transform, query, validate, and edit XML documents.  XPath is used to
match and extract data, and elements can be added, deleted or modified using
XSLT and EXSLT.")
   (license license:x11)))

(define-public xlsx2csv
  (package
    (name "xlsx2csv")
    (version "0.7.2")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "https://github.com/dilshod/"
                   name "/archive/release/" version ".tar.gz"))
             (file-name (string-append name "-" version ".tar.gz"))
             (sha256
              (base32
               "1gpn6kaa7l1ai8c9zx2j3acf04bvxq79pni8jjfjrk01smjbyyql"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2 ; Use python-2 for the test script.
       #:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (substitute* "test/run"
               ;; Run tests with `python' only
               (("^(PYTHON_VERSIONS = ).*" all m) (string-append m "['']")))
             (zero? (system* "test/run")))))))
    (home-page "https://github.com/dilshod/xlsx2csv")
    (synopsis "XLSX to CSV converter")
    (description
     "Xlsx2csv is a program to convert Microsoft Excel 2007 XML (XLSX and
XLSM) format spreadsheets into plaintext @dfn{comma separated values} (CSV)
files.  It is designed to be fast and to handle large input files.")
    (license license:gpl2+)))
