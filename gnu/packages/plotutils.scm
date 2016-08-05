;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2016 Nicolas Goaziou <mail@nicolasgoaziou.fr>
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

(define-module (gnu packages plotutils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages bdw-gc)
  #:use-module (gnu packages emacs)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages image)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages))

(define-public plotutils
  (package
    (name "plotutils")
    (version "2.6")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/plotutils/plotutils-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "1arkyizn5wbgvbh53aziv3s6lmd3wm9lqzkhxb3hijlp1y124hjg"))
             (patches (search-patches "plotutils-libpng-jmpbuf.patch"))
             (modules '((guix build utils)))
             (snippet
              ;; Force the use of libXaw7 instead of libXaw.  When not doing
              ;; that, libplot.la ends up containing just "-lXaw" (without
              ;; "-L/path/to/Xaw"), due to the fact that there is no
              ;; libXaw.la, which forces us to propagate libXaw.
              '(substitute* "configure"
                 (("-lXaw")
                  "-lXaw7")))))
    (build-system gnu-build-system)
    (inputs `(("libpng" ,libpng)
              ("libx11" ,libx11)
              ("libxt" ,libxt)
              ("libxaw" ,libxaw)))

    (home-page
     "http://www.gnu.org/software/plotutils/")
    (synopsis "Plotting utilities and library")
    (description
     "GNU Plotutils is a package for plotting and working with 2D graphics. 
It includes a library, \"libplot\", for C and C++ for exporting 2D vector
graphics in many file formats.  It also has support for 2D vector graphics
animations.  The package also contains command-line programs for plotting
scientific data.")
    (license license:gpl2+)))

(define-public guile-charting
  (package
    (name "guile-charting")
    (version "0.2.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://wingolog.org/pub/guile-charting/"
                                  "guile-charting-" version ".tar.gz"))
              (sha256
               (base32
                "0w5qiyv9v0ip5li22x762bm48g8xnw281w66iyw094zdw611pb2m"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  ;; Use the standard location for modules.
                  (substitute* "Makefile.in"
                    (("godir = .*$")
                     "godir = $(moddir)\n"))))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)))
    (inputs `(("guile" ,guile-2.0)))
    (propagated-inputs `(("guile-cairo" ,guile-cairo)))
    (home-page "http://wingolog.org/software/guile-charting/")
    (synopsis "Create charts and graphs in Guile")
    (description
     "Guile-Charting is a Guile Scheme library to create bar charts and graphs
using the Cairo drawing library.")
    (license license:lgpl2.1+)))

(define-public ploticus
  (package
    (name "ploticus")
    (version "2.42")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/ploticus/ploticus/"
                                  version "/ploticus242_src.tar.gz"))
              (sha256
               (base32
                "1c70cvfvgjh83hj1x21130wb9qfr2rc0x47cxy9kl805yjwy8a9z"))
              (modules '((guix build utils)))
              (snippet
               ;; Install binaries in the right place.
               '(substitute* "src/Makefile"
                  (("INSTALLBIN =.*$")
                   (string-append "INSTALLBIN = $(out)/bin"))))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f
       #:phases
       (modify-phases %standard-phases
         (replace 'configure (lambda _ (chdir "src")))
         (add-before 'install 'make-target-directories
                     (lambda* (#:key outputs #:allow-other-keys)
                       (let ((out (assoc-ref outputs "out")))
                         (mkdir-p (string-append out "/bin"))
                         #t)))
         (add-after 'install 'install-prefabs
                    (lambda* (#:key outputs #:allow-other-keys)
                      (let* ((out (assoc-ref outputs "out"))
                             (dir (string-append out
                                                 "/share/ploticus/prefabs"))
                             (bin (string-append out "/bin")))
                        (mkdir-p dir)

                        ;; Install "prefabs".
                        (for-each (lambda (file)
                                    (let ((target
                                           (string-append dir "/"
                                                          (basename file))))
                                      (copy-file file target)))
                                  (find-files "../prefabs" "."))

                        ;; Allow them to be found.
                        (wrap-program (string-append bin "/pl")
                          `("PLOTICUS_PREFABS" ":" = (,dir)))))))))
    (inputs
     `(("libpng" ,libpng)
       ("libx11" ,libx11)
       ("zlib" ,zlib)))
    (home-page "http://ploticus.sourceforge.net/")
    (synopsis "Command-line tool for producing plots and charts")
    (description
     "Ploticus is a non-interactive software package for producing plots,
charts, and graphics from data.  Ploticus is good for automated or
just-in-time graph generation, handles date and time data nicely, and has
basic statistical capabilities.  It allows significant user control over
colors, styles, options and details.")
    (license license:gpl2+)))

(define-public asymptote
  (package
    (name "asymptote")
    (version "2.38")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/asymptote/"
                                  version "/asymptote-" version ".src.tgz"))
              (sha256
               (base32
                "1dxwvq0xighqckkjkjva8s0igxfgy1j25z81pbwvlz6jzsrxpip9"))))
    (build-system gnu-build-system)
    ;; Note: The 'asy' binary retains a reference to docdir for use with its
    ;; "help" command in interactive mode, so adding a "doc" output is not
    ;; currently useful.
    (native-inputs
     `(("gs" ,ghostscript-gs)           ;For tests
       ("gs-2" ,ghostscript)             ;For dvipdfm
       ("texinfo" ,texinfo)             ;For generating documentation
       ("texlive" ,texlive)             ;For tests and documentation
       ("emacs" ,emacs-minimal)
       ("perl" ,perl)))
    (inputs
     `(("fftw" ,fftw)
       ("freeglut" ,freeglut)
       ("gsl" ,gsl)
       ("libgc" ,libgc)
       ("python" ,python-2)
       ("readline" ,readline)
       ("zlib" ,zlib)))
    (arguments
     `(#:modules ((guix build emacs-utils)
                  (guix build gnu-build-system)
                  (guix build utils)
                  (srfi srfi-26))
       #:imported-modules (,@%gnu-build-system-modules
                           (guix build emacs-utils))
       #:configure-flags
       (list (string-append "--enable-gc=" (assoc-ref %build-inputs "libgc"))
             (string-append "--with-latex="
                            (assoc-ref %outputs "out")
                            "/share/texmf/tex/latex")
             (string-append "--with-context="
                            (assoc-ref %outputs "out")
                            "/share/texmf/tex/context/third"))
       #:phases
       (modify-phases %standard-phases
         (add-before 'build 'patch-pdf-viewer
           (lambda _
             ;; Default to a free pdf viewer.
             (substitute* "settings.cc"
               (("defaultPDFViewer=\"acroread\"")
                "defaultPDFViewer=\"gv\""))
             #t))
         (add-before 'check 'set-HOME
           ;; Some tests require write access to $HOME, otherwise leading to
           ;; "failed to create directory /homeless-shelter/.asy" error.
           (lambda _
             (setenv "HOME" "/tmp")
             #t))
         (add-after 'install 'install-Emacs-data
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Install related Emacs libraries into an appropriate location.
             (let* ((out (assoc-ref outputs "out"))
                    (lisp-dir (string-append out "/share/emacs/site-lisp")))
               (for-each (cut install-file <> lisp-dir)
                         (find-files "." "\\.el$"))
               (emacs-generate-autoloads ,name lisp-dir))
             #t)))))
    (home-page "http://asymptote.sourceforge.net")
    (synopsis "Script-based vector graphics language")
    (description
     "Asymptote is a powerful descriptive vector graphics language for
technical drawing, inspired by MetaPost but with an improved C++-like syntax.
Asymptote provides for figures the same high-quality level of typesetting that
LaTeX does for scientific text.")
    ;; Most source files do not contain license statements, but the README
    ;; contains: "All source files in the Asymptote project, unless explicitly
    ;; noted otherwise, are released under version 3 (or later) of the GNU
    ;; Lesser General Public License"
    (license license:lgpl3+)))
