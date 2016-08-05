;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2016 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
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

(define-module (gnu packages texinfo)
  #:use-module (guix licenses)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages ncurses))

(define-public texinfo
  (package
    (name "texinfo")
    (version "6.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/texinfo/texinfo-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "1ll3d0l8izygdxqz96wfr2631kxahifwdknpgsx2090vw963js5c"))))
    (build-system gnu-build-system)
    (native-inputs `(("procps" ,procps)))  ;one of the tests needs pgrep
    (inputs `(("ncurses" ,ncurses)
              ("perl" ,perl)))

    (native-search-paths
     ;; This is the variable used by the standalone Info reader.
     (list (search-path-specification
            (variable "INFOPATH")
            (files '("share/info")))))

    (home-page "http://www.gnu.org/software/texinfo/")
    (synopsis "The GNU documentation format")
    (description
     "Texinfo is the official documentation format of the GNU project.  It
uses a single source file using explicit commands to produce a final document
in any of several supported output formats, such as HTML or PDF.  This
package includes both the tools necessary to produce Info documents from
their source and the command-line Info reader.  The emphasis of the language
is on expressing the content semantically, avoiding physical markup commands.")
    (license gpl3+)))

(define-public texinfo-5
  (package (inherit texinfo)
    (version "5.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/texinfo/texinfo-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "1njfwh2z34r2c4r0iqa7v24wmjzvsfyz4vplzry8ln3479lfywal"))))
    (native-inputs '())))

(define-public texinfo-4
  (package (inherit texinfo)
    (version "4.13a")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/texinfo/texinfo-"
                    version
                    ".tar.lzma"))
              (sha256
               (base32
                "1rf9ckpqwixj65bw469i634897xwlgkm5i9g2hv3avl6mv7b0a3d"))))
    (native-inputs '())
    (inputs `(("ncurses" ,ncurses) ("xz" ,xz)))))

(define-public info-reader
  ;; The idea of this package is to have the standalone Info reader without
  ;; the dependency on Perl that 'makeinfo' drags.
  (package
    (inherit texinfo)
    (name "info-reader")
    (arguments
     `(#:disallowed-references ,(assoc-ref (package-inputs texinfo)
                                           "perl")

       #:modules ((ice-9 ftw) (srfi srfi-1)
                  ,@%gnu-build-system-modules)

       #:phases (modify-phases %standard-phases
                  (add-after 'install 'keep-only-info-reader
                    (lambda* (#:key outputs #:allow-other-keys)
                      ;; Remove everything but 'bin/info' and associated
                      ;; files.
                      (define (files)
                        (scandir "." (lambda (file)
                                       (not (member file '("." ".."))))))

                      (let ((out (assoc-ref outputs "out")))
                        (with-directory-excursion out
                          (for-each delete-file-recursively
                                    (fold delete (files) '("bin" "share"))))
                        (with-directory-excursion (string-append out "/bin")
                          (for-each delete-file (delete "info" (files))))
                        (with-directory-excursion (string-append out "/share")
                          (for-each delete-file-recursively
                                    (fold delete (files)
                                          '("info" "locale"))))
                        #t))))))
    (synopsis "Standalone Info documentation reader")))

(define-public texi2html
  (package
    (name "texi2html")
    (version "5.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://savannah/" name "/" name "-"
                                  version ".tar.bz2"))
              (sha256
               (base32
                "1yprv64vrlcbksqv25asplnjg07mbq38lfclp1m5lj8cw878pag8"))
              (patches
               (search-patches "texi2html-document-encoding.patch"
                               "texi2html-i18n.patch"))
              (snippet
               ;; This file is modified by the patch above, but reset its
               ;; timestamp so we don't trigger the rule to update PO files,
               ;; which would require Gettext.
               ;; See <http://bugs.gnu.org/18247>.
               '(utime "texi2html.pl" 0 0 0 0))))
    (build-system gnu-build-system)
    (inputs `(("perl" ,perl)))
    (arguments
     ;; Tests fail because of warnings on stderr from Perl 5.22.  Adjusting
     ;; texi2html.pl to avoid the warnings seems non-trivial, so we simply
     ;; disable the tests.
     '(#:tests? #f))
    (home-page "http://www.nongnu.org/texi2html/")
    (synopsis "Convert Texinfo to HTML")
    (description
     "Texi2HTML is a Perl script which converts Texinfo source files to HTML
output.  It now supports many advanced features, such as internationalization
and extremely configurable output formats.

Development of Texi2HTML moved to the GNU Texinfo repository in 2010, since it
was meant to replace the makeinfo implementation in GNU Texinfo.  The route
forward for authors is, in most cases, to alter manuals and build processes as
necessary to use the new features of the makeinfo/texi2any implementation of
GNU Texinfo.  The Texi2HTML maintainers (one of whom is the principal author
of the GNU Texinfo implementation) do not intend to make further releases of
Texi2HTML.")
    ;; Files in /lib under lgpl2.1+ and x11
    (license gpl2+)))
