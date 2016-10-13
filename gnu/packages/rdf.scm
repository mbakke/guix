;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
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

(define-module (gnu packages rdf)
  #:use-module ((guix licenses)
                #:select (non-copyleft isc gpl2 lgpl2.1 lgpl2.1+))
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system python)
  #:use-module (guix build-system waf)
  #:use-module (gnu packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages boost)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages cyrus-sasl)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages qt)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages xml))

(define-public raptor2
  (package
    (name "raptor2")
    (version "2.0.15")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://download.librdf.org/source/" name
                                 "-" version ".tar.gz"))
             (sha256
              (base32
               "1vc02im4mpc28zxzgli68k6j0dakh0k3s389bm436yvqajxg19xd"))))
    (build-system gnu-build-system)
    (inputs
     `(("curl" ,curl)
       ("libxml2" ,libxml2)
       ("libxslt" ,libxslt)
       ("zlib" ,zlib)))
    (arguments
     `(#:parallel-tests? #f))
    (home-page "http://librdf.org/raptor/")
    (synopsis "RDF syntax library")
    (description "Raptor is a C library providing a set of parsers and
serialisers that generate Resource Description Framework (RDF) triples
by parsing syntaxes or serialise the triples into a syntax.  The supported
parsing syntaxes are RDF/XML, N-Quads, N-Triples 1.0 and 1.1, TRiG,
Turtle 2008 and 2013, RDFa 1.0 and 1.1, RSS tag soup including all versions
of RSS, Atom 1.0 and 0.3, GRDDL and microformats for HTML, XHTML and
XML.  The serialising syntaxes are RDF/XML (regular, abbreviated, XMP),
Turtle 2013, N-Quads, N-Triples 1.1, Atom 1.0, RSS 1.0, GraphViz DOT,
HTML and JSON.")
    (license lgpl2.1+))) ; or any choice of gpl2+ or asl2.0

(define-public clucene
  (package
    (name "clucene")
    (version "2.3.3.4")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://sourceforge/clucene/"
                                 "clucene-core-unstable/2.3/clucene-core-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "1arffdwivig88kkx685pldr784njm0249k0rb1f1plwavlrw9zfx"))
             (patches (search-patches "clucene-pkgconfig.patch"
                                      "clucene-contribs-lib.patch"))))
    (build-system cmake-build-system)
    (inputs
     `(("boost" ,boost) ; could also use bundled copy
       ("zlib" ,zlib)))
    (arguments
     `(#:test-target "cl_test"
       #:configure-flags '("-DBUILD_CONTRIBS_LIB=ON")
       #:tests? #f)) ; Tests do not compile, as TestIndexSearcher.cpp uses
                     ; undeclared usleep. After fixing this, one needs to run
                     ; "make test" in addition to "make cl_test", then
                     ; SimpleTest fails.
                     ; Notice that the library appears to be unmaintained
                     ; with no reaction to bug reports.
    (home-page "http://clucene.sourceforge.net/")
    (synopsis "C text indexing and searching library")
    (description "CLucene is a high-performance, scalable, cross platform,
full-featured indexing and searching API.  It is a port of the very popular
Java Lucene text search engine API to C++.")
    (license lgpl2.1)))

(define-public lrdf
  (package
    (name "lrdf")
    (version "0.5.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/swh/LRDF/archive/"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "18p2flb2sv2hq6w2qkd29z9c7knnwqr3f12i2srshlzx6vwkm05s"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (alist-cons-after
                 'remove-out-of-tree-references 'autoreconf
                 (lambda _
                   (zero? (system* "autoreconf" "-vfi")))
                 (alist-cons-after
                  'unpack 'remove-out-of-tree-references
                  (lambda _
                    ;; remove symlinks to files in /usr/
                    (delete-file-recursively "m4")
                    (for-each delete-file '("config.guess"
                                            "config.sub"
                                            "depcomp"
                                            "install-sh"
                                            "ltmain.sh"
                                            "missing"))
                    ;; remove_test depends on an out-of-tree RDF file
                    (substitute* "examples/Makefile.am"
                      (("instances_test remove_test") "instances_test")
                      (("\\$\\(TESTS\\) remove_test") "$(TESTS)")))
                  %standard-phases))))
    (inputs
     `(("raptor" ,raptor2)
       ("cyrus-sasl" ,cyrus-sasl)
       ("openssl" ,openssl)
       ("zlib" ,zlib)))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)
       ("pkg-config" ,pkg-config)))
    (home-page "https://github.com/swh/LRDF")
    (synopsis "Lightweight RDF library for accessing LADSPA plugin metadata")
    (description
     "LRDF is a library to make it easy to manipulate RDF files describing
LADSPA plugins.  It can also be used for general RDF manipulation.  It can
read RDF/XLM and N3 files and export N3 files, and it also has a light
taxonomic inference capability.")
    (license gpl2)))

(define-public rasqal
  (package
    (name "rasqal")
    (version "0.9.33")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://download.librdf.org/source/" name
                                 "-" version ".tar.gz"))
             (sha256
              (base32
               "0z6rrwn4jsagvarg8d5zf0j352kjgi33py39jqd29gbhcnncj939"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("perl" ,perl)
       ("perl-xml-dom" ,perl-xml-dom) ; for the tests
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("libgcrypt" ,libgcrypt)
       ("libxml2" ,libxml2)
       ("mpfr" ,mpfr)
       ("pcre" ,pcre)
       ("util-linux" ,util-linux)))
    (propagated-inputs
     `(("raptor2" ,raptor2))) ; stipulated by rasqal.pc
    (arguments
     `(#:parallel-tests? #f
       ; test failure reported upstream, see
       ; http://bugs.librdf.org/mantis/view.php?id=571
       #:tests? #f))
    (home-page "http://librdf.org/rasqal/")
    (synopsis "RDF query library")
    (description "Rasqal is a C library that handles Resource Description
Framework (RDF) query language syntaxes, query construction and execution
of queries returning results as bindings, boolean, RDF graphs/triples or
syntaxes.  The supported query languages are SPARQL Query 1.0,
SPARQL Query 1.1, SPARQL Update 1.1 (no executing) and the Experimental
SPARQL extensions (LAQRS).  Rasqal can write binding query results in the
SPARQL XML, SPARQL JSON, CSV, TSV, HTML, ASCII tables, RDF/XML and
Turtle/N3 and read them in SPARQL XML, RDF/XML and Turtle/N3.")
    (license lgpl2.1+))) ; or any choice of gpl2+ or asl2.0

(define-public redland
  (package
    (name "redland")
    (version "1.0.17")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://download.librdf.org/source/" name
                                 "-" version ".tar.gz"))
             (sha256
              (base32
               "109n0kp39p966dpiasad2bb7q66rwbcb9avjvimw28chnpvlf66y"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("perl" ,perl) ; needed for installation
       ("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("rasqal" ,rasqal))) ; in Requires.private field of .pc
    (inputs
     `(("bdb" ,bdb)))
    (home-page "http://librdf.org/")
    (synopsis "RDF library")
    (description "The Redland RDF Library (librdf) provides the RDF API
and triple stores.")
    (license lgpl2.1+))) ; or any choice of gpl2+ or asl2.0

(define-public serd
  (package
    (name "serd")
    (version "0.22.0")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://download.drobilla.net/serd-"
                                 version
                                 ".tar.bz2"))
             (sha256
              (base32
               "1lmgca2s6r7ysakcld2lrj06bgn0pr45c51b47k3apxpnj3h40vv"))))
    (build-system waf-build-system)
    (arguments
     `(#:tests? #f ; no check target
       #:phases
       (modify-phases %standard-phases
         (add-before
          'configure 'set-ldflags
          (lambda* (#:key outputs #:allow-other-keys)
            (setenv "LDFLAGS"
                    (string-append "-Wl,-rpath="
                                   (assoc-ref outputs "out") "/lib")))))))
    (home-page "http://drobilla.net/software/serd/")
    (synopsis "Library for RDF syntax supporting Turtle and NTriples")
    (description
     "Serd is a lightweight C library for RDF syntax which supports reading
and writing Turtle and NTriples.  Serd is not intended to be a swiss-army
knife of RDF syntax, but rather is suited to resource limited or performance
critical applications (e.g. converting many gigabytes of NTriples to Turtle),
or situations where a simple reader/writer with minimal dependencies is
ideal (e.g. in LV2 implementations or embedded applications).")
    (license isc)))

(define-public sord
  (package
    (name "sord")
    (version "0.14.0")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://download.drobilla.net/sord-"
                                 version
                                 ".tar.bz2"))
             (sha256
              (base32
               "16piw1s3l95cf9x3rdcplp9l52k2lxq8drwg2q50ygm4avndhmkn"))))
    (build-system waf-build-system)
    (arguments
     `(#:tests? #f ; no check target
       #:phases
       (modify-phases %standard-phases
         (add-before
          'configure 'set-ldflags
          (lambda* (#:key outputs #:allow-other-keys)
            (setenv "LDFLAGS"
                    (string-append "-Wl,-rpath="
                                   (assoc-ref outputs "out") "/lib")))))))
    (inputs
     `(("serd" ,serd)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://drobilla.net/software/sord/")
    (synopsis "C library for storing RDF data in memory")
    (description
     "Sord is a lightweight C library for storing RDF data in memory.")
    (license isc)))

(define-public python-rdflib
  (package
    (name "python-rdflib")
    (version "4.1.2")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
              "https://pypi.python.org/packages/source/r/rdflib/rdflib-"
              version
              ".tar.gz"))
        (patches
          ;; The patch has no effect under Python 3.
          (search-patches "python2-rdflib-drop-sparqlwrapper.patch"))
        (sha256
          (base32
            "0kvaf332cqbi47rqzlpdx4mbkvw12mkrzkj8n9l19wk713d4py9w"))))
    (build-system python-build-system)
    (propagated-inputs
      `(("python-html5lib" ,python-html5lib)
        ("python-isodate" ,python-isodate)
        ("python-pyparsing" ,python-pyparsing)))
    (home-page "https://github.com/RDFLib/rdflib")
    (synopsis
      "Python RDF library")
    (description
      "RDFLib is a Python library for working with RDF, a simple yet
powerful language for representing information.")
    (license (non-copyleft "file://LICENSE"
                        "See LICENSE in the distribution."))))

(define-public python2-rdflib
  (let ((base (package-with-python2 python-rdflib)))
    (package
      (inherit base)
      (inputs
        (append (package-inputs base)
                `(("python2-nose" ,python2-nose))))
      (arguments
        `(#:python ,python-2
          #:tests? #f))))) ; 3 tests fail, also outside Guix
