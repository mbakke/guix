;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2014 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Ricardo Wurmus <rekado@elephly.net>
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

(define-module (gnu packages gettext)
  #:use-module ((guix licenses) #:select (gpl2+ gpl3+))
  #:use-module (gnu packages)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system perl)
  #:use-module (gnu packages docbook)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages xml))

;; Use that name to avoid clashes with Guile's 'gettext' procedure.
;;
;; We used to resort to #:renamer on the user side, but that prevented
;; circular dependencies involving (gnu packages gettext).  This is because
;; 'resolve-interface' (as of Guile 2.0.9) iterates eagerly over the used
;; module when there's a #:renamer, and that module may be empty at that point
;; in case or circular dependencies.
(define-public gnu-gettext
  (package
    (name "gettext")
    (version "0.19.8")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/gettext/gettext-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "13ylc6n3hsk919c7xl0yyibc3pfddzb53avdykn4hmk8g6yzd91x"))))
    (build-system gnu-build-system)
    (outputs '("out"
               "doc"))                            ;8 MiB of HTML
    (inputs
     `(("expat" ,expat)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
        (add-before 'check 'patch-tests
         (lambda* (#:key inputs #:allow-other-keys)
           (let* ((bash (which "sh")))
             ;; Some of the files we're patching are
             ;; ISO-8859-1-encoded, so choose it as the default
             ;; encoding so the byte encoding is preserved.
             (with-fluids ((%default-port-encoding #f))
               (substitute*
                   (find-files "gettext-tools/tests"
                               "^(lang-sh|msg(exec|filter)-[0-9])")
                 (("#![[:blank:]]/bin/sh")
                  (format #f "#!~a" bash)))

               (substitute* (cons "gettext-tools/src/msginit.c"
                                  (find-files "gettext-tools/gnulib-tests"
                                              "posix_spawn"))
                 (("/bin/sh")
                  bash))

               (substitute* "gettext-tools/src/project-id"
                 (("/bin/pwd")
                  "pwd"))))))
        (add-before 'configure 'link-expat
         (lambda _
           ;; Gettext defaults to opening expat via dlopen on
           ;; "Linux".  Change to link directly.
           (substitute* "gettext-tools/configure"
             (("LIBEXPAT=\"-ldl\"") "LIBEXPAT=\"-ldl -lexpat\"")
             (("LTLIBEXPAT=\"-ldl\"") "LTLIBEXPAT=\"-ldl -lexpat\"")))))

       ;; When tests fail, we want to know the details.
       #:make-flags '("VERBOSE=yes")))
    (home-page "http://www.gnu.org/software/gettext/")
    (synopsis "Tools and documentation for translation")
    (description
     "GNU Gettext is a package providing a framework for translating the
textual output of programs into multiple languages.  It provides translators
with the means to create message catalogs, as well as an Emacs mode to work
with them, and a runtime library to load translated messages from the
catalogs.  Nearly all GNU packages use Gettext.")
    (license gpl3+)))                             ;some files are under GPLv2+

(define-public po4a
  (package
    (name "po4a")
    (version "0.47")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://alioth.debian.org/frs/download.php"
                                  "/file/4142/po4a-" version ".tar.gz"))
              (sha256
               (base32
                "01vm0750aq0h2lphrflv3wq9gz7y0py8frglfpacn58ivyvy242h"))))
    (build-system perl-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; FIXME: One test fails as we don't have SGMLS.pm
         (add-before 'check 'disable-sgml-test
          (lambda _
            (delete-file "t/20-sgml.t")
            #t))
         (add-after 'unpack 'fix-builder
          (lambda* (#:key inputs outputs #:allow-other-keys)
            (substitute* "Po4aBuilder.pm"
              ;; By default it tries to install into perl's manpath.
              (("my \\$mandir = .*$")
               (string-append "my $mandir = \"" (assoc-ref outputs "out")
                              "/share/man\";\n")))
            #t))
         (add-after 'install 'wrap-programs
          (lambda* (#:key outputs #:allow-other-keys)
            ;; Make sure all executables in "bin" find the Perl modules
            ;; provided by this package at runtime.
            (let* ((out  (assoc-ref outputs "out"))
                   (bin  (string-append out "/bin/"))
                   (path (string-append out "/lib/perl5/site_perl")))
              (for-each (lambda (file)
                          (wrap-program file
                            `("PERL5LIB" ":" prefix (,path))))
                        (find-files bin "\\.*$"))
              #t))))))
    (native-inputs
     `(("gettext" ,gnu-gettext)
       ("perl-module-build" ,perl-module-build)
       ("docbook-xsl" ,docbook-xsl)
       ("docbook-xml" ,docbook-xml) ;for tests
       ("texlive" ,texlive-minimal) ;for tests
       ("libxml2" ,libxml2)
       ("xsltproc" ,libxslt)))
    (home-page "http://po4a.alioth.debian.org/")
    (synopsis "Scripts to ease maintenance of translations")
    (description
     "The po4a (PO for anything) project goal is to ease translations (and
more interestingly, the maintenance of translations) using gettext tools on
areas where they were not expected like documentation.")
    (license gpl2+)))
