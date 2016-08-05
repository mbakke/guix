;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2016 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2016 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2016 Roel Janssen <roel@gnu.org>
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

(define-module (gnu packages documentation)
  #:use-module (guix licenses)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system cmake)
  #:use-module (gnu packages)
  #:use-module (gnu packages python)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages docbook)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages graphviz)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages xml)
  #:autoload   (gnu packages zip) (unzip))

(define-public asciidoc
  (package
    (name "asciidoc")
    (version "8.6.9")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/asciidoc/asciidoc/"
                                  version "/asciidoc-" version ".tar.gz"))
              (sha256
               (base32
                "1w71nk527lq504njmaf0vzr93pgahkgzzxzglrq6bay8cw2rvnvq"))))
    (build-system gnu-build-system)
    (arguments '(#:tests? #f))                    ; no 'check' target
    (inputs `(("python" ,python-2)))
    (home-page "http://www.methods.co.nz/asciidoc/")
    (synopsis "Text-based document generation system")
    (description
     "AsciiDoc is a text document format for writing notes, documentation,
articles, books, ebooks, slideshows, web pages, man pages and blogs.
AsciiDoc files can be translated to many formats including HTML, PDF,
EPUB, man page.

AsciiDoc is highly configurable: both the AsciiDoc source file syntax and
the backend output markups (which can be almost any type of SGML/XML
markup) can be customized and extended by the user.")
    (license gpl2+)))

(define-public doxygen
  (package
    (name "doxygen")
    (version "1.8.11")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://ftp.stack.nl/pub/users/dimitri/"
                                 name "-" version ".src.tar.gz"))
             (sha256
              (base32
               "0ja02pm3fpfhc5dkry00kq8mn141cqvdqqpmms373ncbwi38pl35"))
             (patches (search-patches "doxygen-test.patch"))))
    (build-system cmake-build-system)
    (native-inputs
     `(("bison" ,bison)
       ("flex" ,flex)
       ("libxml2" ,libxml2) ; provides xmllint for the tests
       ("python" ,python-2))) ; for creating the documentation
    (arguments
     `(#:test-target "tests"))
    (home-page "http://www.stack.nl/~dimitri/doxygen/")
    (synopsis "Generate documentation from annotated sources")
    (description "Doxygen is the de facto standard tool for generating
documentation from annotated C++ sources, but it also supports other popular
programming languages such as C, Objective-C, C#, PHP, Java, Python,
IDL (Corba, Microsoft, and UNO/OpenOffice flavors), Fortran, VHDL, Tcl,
and to some extent D.")
    (license gpl3+)))

(define-public doc++
  (package
    (name "doc++")
    (version "3.4.10")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://sourceforge.net/projects/docpp/"
                                  "files/doc++-" version ".tar.gz"))
              (sha256
               (base32
                "0i37zlxl8g352s4hzpdx0657k5x3czh3xcsfr27irc708gb277pn"))
              (patches (search-patches "doc++-include-directives.patch"
                                       "doc++-segfault-fix.patch"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("flex" ,flex)
       ("gettext" ,gnu-gettext)))
    (home-page "http://docpp.sourceforge.net/")
    (synopsis "Documentation system for C, C++, IDL, and Java")
    (description
     "DOC++ is a documentation system for C, C++, IDL, and Java.  It can
generate both TeX output for high-quality hardcopies or HTML output for online
brwosing.  The documentation is extracted directly from the C/C++/IDL source
or Java class files.")
    (license gpl2+)))

(define-public scrollkeeper
  (package
    (name "scrollkeeper")
    (version "0.3.14")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/scrollkeeper/scrollkeeper/"
                           version "/scrollkeeper-" version ".tar.gz"))
       (sha256
        (base32 "1bfxwxc1ngh11v36z899sz9qam366r050fhkyb5adv65lb1x62sa"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags
       (list (string-append "--with-xml-catalog="
                            (assoc-ref %build-inputs "docbook-xml")
                            "/xml/dtd/docbook/catalog.xml"))))
    (inputs
     `(("perl" ,perl)
       ("libxml2" ,libxml2)
       ("libxslt" ,libxslt)
       ;; The configure script checks for either version 4.2 or 4.1.2.
       ("docbook-xml" ,docbook-xml-4.2)))
    (native-inputs
     `(("intltool" ,intltool)))
    (home-page "http://scrollkeeper.sourceforge.net/")
    (synopsis "Open Documentation Cataloging Project")
    (description "ScrollKeeper is a cataloging system for documentation on open
systems.  It manages documentation metadata as specified by the Open Source
Metadata Framework and provides a simple API to allow help browsers to find,
sort, and search the document catalog.  It will also be able to communicate
with catalog servers on the Net to search for documents which are not on the
local system.")
    (license lgpl2.1+)))
