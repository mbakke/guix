;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014 Joshua Grant <tadni@riseup.net>
;;; Copyright © 2014 Alex Kost <alezost@gmail.com>
;;; Copyright © 2015 Sou Bunnbu <iyzsong@gmail.com>
;;; Copyright © 2015 Eric Dvorsak <eric@dvorsak.fr>
;;; Copyright © 2015 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015, 2016 Leo Famulari <leo@famulari.name>
;;; Copyright © 2016 ng0 <ng0@we.make.ritual.n0.is>
;;; Copyright © 2016 Jookia <166291@gmail.com>
;;; Copyright © 2016 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2016 Dmitry Nikolaev <cameltheman@gmail.com>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Marius Bakke <mbakke@fastmail.com>
;;; Copyright © 2016 Toni Reina <areina@riseup.net>
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

(define-module (gnu packages fonts)
  #:use-module (ice-9 regex)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (gnu packages base)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages zip))

(define-public font-inconsolata
  (package
    (name "font-inconsolata")
    (version "0.80")
    (source (origin
              (method url-fetch)
              (uri "http://www.levien.com/type/myfonts/Inconsolata.otf")
              (sha256
               (base32
                "06js6znbcf7swn8y3b8ki416bz96ay7d3yvddqnvi88lqhbfcq8m"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder (begin
                   (use-modules (guix build utils))
                   (let ((font-dir (string-append %output
                                                  "/share/fonts/opentype"))
                         (source (assoc-ref %build-inputs "source")))
                     (mkdir-p font-dir)
                     (copy-file source
                                (string-append font-dir "/" "inconsolata.otf"))))))
    (native-inputs `(("source" ,source)))
    (home-page "http://levien.com/type/myfonts/inconsolata.html")
    (synopsis "Monospace font")
    (description "A monospace font, designed for code listings and the like,
in print.  With attention to detail for high resolution rendering.")
    (license license:silofl1.1)))

(define-public font-ubuntu
  (package
    (name "font-ubuntu")
    (version "0.83")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://font.ubuntu.com/download/ubuntu-font-family-"
                    version ".zip"))
              (sha256
               (base32
                "0hjvq2x758dx0sfwqhzflns0ns035qm7h6ygskbx1svzg517sva5"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder (begin
                   (use-modules (guix build utils)
                                (srfi srfi-26))

                   (let ((PATH     (string-append (assoc-ref %build-inputs
                                                             "unzip")
                                                  "/bin"))
                         (font-dir (string-append %output
                                                  "/share/fonts/truetype"))
                         (doc-dir  (string-append %output "/share/doc/"
                                                  ,name "-" ,version)))
                     (setenv "PATH" PATH)
                     (system* "unzip" (assoc-ref %build-inputs "source"))

                     (mkdir-p font-dir)
                     (mkdir-p doc-dir)
                     (chdir (string-append "ubuntu-font-family-" ,version))
                     (for-each (lambda (ttf)
                                 (copy-file ttf
                                            (string-append font-dir "/" ttf)))
                               (find-files "." "\\.ttf$"))
                     (for-each (lambda (doc)
                                 (copy-file doc
                                            (string-append doc-dir "/" doc)))
                               (find-files "." "\\.txt$"))))))
    (native-inputs `(("source" ,source)
                     ("unzip" ,unzip)))
    (home-page "http://font.ubuntu.com/")
    (synopsis "The Ubuntu Font Family")
    (description "The Ubuntu Font Family is a unique, custom designed font
that has a very distinctive look and feel.  This package provides the
TrueType (TTF) files.")
    (license
     (license:non-copyleft
      "http://font.ubuntu.com/ufl/ubuntu-font-licence-1.0.txt"
      "Ubuntu Font License v1.0"))))

(define-public font-dejavu
  (package
    (name "font-dejavu")
    (version "2.37")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://sourceforge/dejavu/dejavu/"
                                 version "/dejavu-fonts-ttf-"
                                 version ".tar.bz2"))
             (sha256
              (base32
               "1mqpds24wfs5cmfhj57fsfs07mji2z8812i5c4pi5pbi738s977s"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder (begin
                   (use-modules (guix build utils))

                   (let ((tar      (string-append (assoc-ref %build-inputs
                                                             "tar")
                                                  "/bin/tar"))
                         (PATH     (string-append (assoc-ref %build-inputs
                                                             "bzip2")
                                                  "/bin"))
                         (font-dir (string-append
                                    %output "/share/fonts/truetype"))
                         (conf-dir (string-append
                                    %output "/share/fontconfig/conf.avail"))
                         (doc-dir  (string-append
                                    %output "/share/doc/" ,name "-" ,version)))
                     (setenv "PATH" PATH)
                     (system* tar "xvf" (assoc-ref %build-inputs "source"))

                     (mkdir-p font-dir)
                     (mkdir-p conf-dir)
                     (mkdir-p doc-dir)
                     (chdir (string-append "dejavu-fonts-ttf-" ,version))
                     (for-each (lambda (ttf)
                                 (copy-file ttf
                                            (string-append font-dir "/"
                                                           (basename ttf))))
                               (find-files "ttf" "\\.ttf$"))
                     (for-each (lambda (conf)
                                 (copy-file conf
                                            (string-append conf-dir "/"
                                                           (basename conf))))
                               (find-files "fontconfig" "\\.conf$"))
                     (for-each (lambda (doc)
                                 (copy-file doc
                                            (string-append doc-dir "/"
                                                           (basename doc))))
                               (find-files "." "\\.txt$|^[A-Z][A-Z]*$"))))))
    (native-inputs `(("source" ,source)
                     ("tar" ,tar)
                     ("bzip2" ,bzip2)))
    (home-page "http://dejavu-fonts.org/")
    (synopsis "Vera font family derivate with additional characters")
    (description "DejaVu provides an expanded version of the Vera font family
aiming for quality and broader Unicode coverage while retaining the original
Vera style.  DejaVu currently works towards conformance with the Multilingual
European Standards (MES-1 and MES-2) for Unicode coverage.  The DejaVu fonts
provide serif, sans and monospaced variants.")
    (license
     (license:x11-style
      "http://dejavu-fonts.org/"))))

(define-public font-bitstream-vera
  (package
    (name "font-bitstream-vera")
    (version "1.10")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnome/sources/ttf-bitstream-vera/"
                                 version "/ttf-bitstream-vera-"
                                 version ".tar.bz2"))
             (sha256
              (base32
               "1p3qs51x5327gnk71yq8cvmxc6wgx79sqxfvxcv80cdvgggjfnyv"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder (begin
                   (use-modules (guix build utils)
                                (srfi srfi-26))

                   (let ((tar      (string-append (assoc-ref %build-inputs
                                                             "tar")
                                                  "/bin/tar"))
                         (PATH     (string-append (assoc-ref %build-inputs
                                                             "bzip2")
                                                  "/bin"))
                         (font-dir (string-append %output
                                                  "/share/fonts/truetype"))
                         (doc-dir  (string-append %output "/share/doc/"
                                                  ,name "-" ,version)))
                     (setenv "PATH" PATH)
                     (system* tar "xvf" (assoc-ref %build-inputs "source"))

                     (mkdir-p font-dir)
                     (mkdir-p doc-dir)
                     (chdir (string-append "ttf-bitstream-vera-" ,version))
                     (for-each (lambda (ttf)
                                 (copy-file ttf
                                            (string-append font-dir "/" ttf)))
                               (find-files "." "\\.ttf$"))
                     (for-each (lambda (doc)
                                 (copy-file doc
                                            (string-append doc-dir "/" doc)))
                               (find-files "." "\\.TXT$"))))))
    (native-inputs `(("source" ,source)
                     ("tar" ,tar)
                     ("bzip2" ,bzip2)))
    (home-page "http://www.gnome.org/fonts/")
    (synopsis "Bitstream Vera sans-serif typeface")
    (description "Vera is a sans-serif typeface from Bitstream, Inc.  This
package provides the TrueType (TTF) files.")
    (license
     (license:x11-style
      "http://www.gnome.org/fonts/#Final_Bitstream_Vera_Fonts"))))

(define-public font-cantarell
  (package
    (name "font-abattis-cantarell")
    (version "0.0.24")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnome/sources/cantarell-fonts/"
                                  (version-major+minor version)
                                  "/cantarell-fonts-" version ".tar.xz"))
              (sha256
               (base32
                "0r4jnc2x9yncf40lixjb1pqgpq8rzbi2fz33pshlqzjgx2d69bcw"))))
    (build-system gnu-build-system)
    (home-page "https://wiki.gnome.org/Projects/CantarellFonts")
    (synopsis "Cantarell sans-serif typeface")
    (description "The Cantarell font family is a contemporary Humanist
sans-serif designed for on-screen reading.  It is used by GNOME@tie{}3.")
    (license license:silofl1.1)))

(define-public font-gnu-freefont-ttf
  (package
    (name "font-gnu-freefont-ttf")
    (version "20120503")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/freefont/freefont-src-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "0yk58blhcd4hm7nyincmqq4jrzjjk82wif2zmk1l3y2m4vif4qhd"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (delete 'configure)
                  (replace 'install
                   (lambda _
                     (let ((doc-dir  (string-append %output "/share/doc/"
                                                    ,name "-" ,version))
                           (font-dir (string-append %output
                                                    "/share/fonts/truetype")))
                       (mkdir-p doc-dir)
                       (substitute* "Makefile"
                         (("\\$\\(TMPDIR\\)") doc-dir)
                         (("sfd/\\*.ttf") ""))
                       (system* "make" "ttftar")
                       (mkdir-p font-dir)
                       (for-each (lambda (file)
                                   (copy-file file
                                              (string-append font-dir "/"
                                                             (basename file))))
                                 (filter
                                   (lambda (file) (string-suffix? "ttf" file))
                                   (find-files "." "")))))))
       #:test-target "tests"))
    ;; replace python 3 with python 2
    ;; python 3 support commits aren't yet released in 20120503
    ;; so freefont needs python 2 support in fontforge
    (native-inputs `(("fontforge" ,(package (inherit fontforge)
                                     (inputs `(("python-2" ,python-2)
                                     ,@(package-inputs fontforge)))))))
    (home-page "http://www.gnu.org/software/freefont/")
    (synopsis "Unicode-encoded outline fonts")
    (description
     "The GNU Freefont project aims to provide a set of free outline
 (PostScript Type0, TrueType, OpenType...) fonts covering the ISO
10646/Unicode UCS (Universal Character Set).")
    (license license:gpl3+)
    (properties '((upstream-name . "freefont")
                  (ftp-directory . "/gnu/freefont")))))

(define-public font-liberation
  (package
    (name "font-liberation")
    (version "2.00.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://fedorahosted.org/releases/l/i/"
                                  "liberation-fonts/liberation-fonts-ttf-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "010m4zfqan4w04b6bs9pm3gapn9hsb18bmwwgp2p6y6idj52g43q"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))

         (let ((tar      (string-append (assoc-ref %build-inputs "tar")
                                        "/bin/tar"))
               (PATH     (string-append (assoc-ref %build-inputs "gzip")
                                        "/bin"))
               (font-dir (string-append %output "/share/fonts/truetype"))
               (doc-dir  (string-append %output "/share/doc/" ,name)))
           (setenv "PATH" PATH)
           (system* tar "xvf" (assoc-ref %build-inputs "source"))
           (mkdir-p font-dir)
           (mkdir-p doc-dir)
           (chdir (string-append "liberation-fonts-ttf-" ,version))
           (for-each (lambda (ttf)
                       (copy-file ttf
                                  (string-append font-dir "/"
                                                 (basename ttf))))
                     (find-files "." "\\.ttf$"))
           (for-each (lambda (doc)
                       (copy-file doc
                                  (string-append doc-dir "/"
                                                 (basename doc))))
                     '("AUTHORS" "ChangeLog" "LICENSE" "README" "TODO"))))))
    (native-inputs
     `(("source" ,source)
       ("tar" ,tar)
       ("gzip" ,gzip)))
    (home-page "https://fedorahosted.org/liberation-fonts/")
    (synopsis
     "Fonts compatible with Arial, Times New Roman, and Courier New")
    (description
     "The Liberation font family aims at metric compatibility with
Arial, Times New Roman, and Courier New.

There are three sets:

- Sans (a substitute for Arial, Albany, Helvetica, Nimbus Sans L, and
Bitstream Vera Sans);

- Serif (a substitute for Times New Roman, Thorndale, Nimbus Roman, and
Bitstream Vera Serif);

- Mono (a substitute for Courier New, Cumberland, Courier, Nimbus Mono L,
and Bitstream Vera Sans Mono).

The Liberation Fonts are sponsored by Red Hat.")
    (license license:silofl1.1)))

(define-public font-terminus
  (package
    (name "font-terminus")
    (version "4.40")
    (source
      (origin
        (method url-fetch)
        (uri (string-append
               "mirror://sourceforge/terminus-font/terminus-font-"
               version
               "/terminus-font-"
               version
               ".tar.gz"))
        (sha256
         (base32
          "0487cyx5h1f0crbny5sg73a22gmym5vk1i7646gy7hgiscj2rxb4"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("perl" ,perl)
       ("bdftopcf" ,bdftopcf)
       ("font-util" ,font-util)
       ("mkfontdir" ,mkfontdir)))
    (arguments
     `(#:configure-flags (list
                          ;; install fonts into subdirectory of package output
                          ;; instead of font-util-?.?.?/share/fonts/X11
                          (string-append "--with-fontrootdir="
                                         %output "/share/fonts/X11"))
       #:tests? #f)) ;; No test target in tarball
    (home-page "http://terminus-font.sourceforge.net/")
    (synopsis "Simple bitmap programming font")
    (description "Terminus Font is a clean, fixed width bitmap font, designed
for long (8 and more hours per day) work with computers.")
    (license license:silofl1.1)))

(define-public font-adobe-source-han-sans
  (package
    (name "font-adobe-source-han-sans")
    (version "1.004")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/adobe-fonts/source-han-sans/archive/"
                    version "R.tar.gz"))
              (file-name (string-append "source-han-sans-" version "R.tar.gz"))
              (sha256
               (base32
                "1ssx0fw90sy6mj8fv8fv4dgzszpqwbmwpjnlx16g4pvaqzdmybbz"))))
    (outputs '("out"                 ; OpenType/CFF Collection (OTC), 121 MiB.
               "cn" "jp" "kr" "tw")) ; Region-specific Subset OpenType/CFF.
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (let ((tar  (string-append (assoc-ref %build-inputs
                                               "tar")
                                    "/bin/tar"))
               (PATH (string-append (assoc-ref %build-inputs
                                               "gzip")
                                    "/bin"))
               (install-opentype-fonts
                (lambda (fonts-dir out)
                  (copy-recursively fonts-dir
                                    (string-append (assoc-ref %outputs out)
                                                   "/share/fonts/opentype")))))
           (setenv "PATH" PATH)
           (system* tar "xvf" (assoc-ref %build-inputs "source"))
           (chdir (string-append "source-han-sans-" ,version "R"))
           (install-opentype-fonts "OTC" "out")
           (install-opentype-fonts "SubsetOTF/CN" "cn")
           (install-opentype-fonts "SubsetOTF/JP" "jp")
           (install-opentype-fonts "SubsetOTF/KR" "kr")
           (install-opentype-fonts "SubsetOTF/TW" "tw")
           (for-each delete-file (find-files %output "\\.zip$"))))))
    (native-inputs
     `(("gzip" ,gzip)
       ("tar" ,tar)))
    (home-page "https://github.com/adobe-fonts/source-han-sans")
    (synopsis "Pan-CJK fonts")
    (description
     "Source Han Sans is a sans serif Pan-CJK font family that is offered in
seven weights: ExtraLight, Light, Normal, Regular, Medium, Bold, and Heavy.
And in several OpenType/CFF-based deployment configurations to accommodate
various system requirements or limitations.  As the name suggests, Pan-CJK
fonts are intended to support the characters necessary to render or display
text in Simplified Chinese, Traditional Chinese, Japanese, and Korean.")
    (license license:silofl1.1)))

(define-public font-wqy-zenhei
  (package
    (name "font-wqy-zenhei")
    (version "0.9.45")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://sourceforge/wqy/wqy-zenhei/" version
                    "%20%28Fighting-state%20RC1%29/wqy-zenhei-"
                    version ".tar.gz"))
              (file-name (string-append "wqy-zenhei-" version ".tar.gz"))
              (sha256
               (base32
                "1mkmxq8g2hjcglb3zajfqj20r4r88l78ymsp2xyl5yav8w3f7dz4"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (let ((PATH (string-append (assoc-ref %build-inputs "tar")  "/bin:"
                                    (assoc-ref %build-inputs "gzip") "/bin"))
               (font-dir (string-append (assoc-ref %outputs "out")
                                        "/share/fonts/wenquanyi/")))
           (setenv "PATH" PATH)
           (mkdir-p font-dir)
           (system* "tar" "xvf" (assoc-ref %build-inputs "source"))
           (chdir "wqy-zenhei")
           (copy-file "wqy-zenhei.ttc"
                      (string-append font-dir "wqy-zenhei.ttc"))))))
    (native-inputs
     `(("gzip" ,gzip)
       ("tar" ,tar)))
    (home-page "http://wenq.org/wqy2/")
    (synopsis "CJK font")
    (description
     "WenQuanYi Zen Hei is a Hei-Ti style (sans-serif type) Chinese outline
font.  It is designed for general purpose text formatting and on-screen
display of Chinese characters and symbols from many other languages.
WenQuanYi Zen Hei provides a rather complete coverage to Chinese Hanzi glyphs,
including both simplified and traditional forms.  The total glyph number in
this font is over 35,000, including over 21,000 Chinese Hanzi.  This font has
full coverage to GBK(CP936) charset, CJK Unified Ideographs, as well as the
code-points needed for zh_cn, zh_sg, zh_tw, zh_hk, zh_mo, ja (Japanese) and
ko (Korean) locales for fontconfig.")
    ;; GPLv2 with font embedding exception
    (license license:gpl2)))

(define-public font-tex-gyre
  (package
    (name "font-tex-gyre")
    (version "2.005")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://www.gust.org.pl/projects/e-foundry/"
                           "tex-gyre/whole/tg-" version "otf.zip"))
       (sha256
        (base32
         "0kph9l3g7jb2bpmxdbdg5zl56wacmnvdvsdn7is1gc750sqvsn31"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))

         (let ((unzip    (string-append (assoc-ref %build-inputs "unzip")
                                        "/bin/unzip"))
               (font-dir (string-append %output "/share/fonts/opentype")))
           (mkdir-p font-dir)
           (system* unzip
                    (assoc-ref %build-inputs "source")
                    "-d" font-dir)))))
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page "http://www.gust.org.pl/projects/e-foundry/tex-gyre/")
    (synopsis "Remake of Ghostscript fonts")
    (description "The TeX Gyre collection of fonts is the result of an
extensive remake and extension of the freely available base PostScript fonts
distributed with Ghostscript version 4.00.  The collection contains the
following fonts in the OpenType format: Adventor, Bonum, Chorus, Cursor,
Heros, Pagella, Schola, Termes.")
    (license license:gfl1.0)))

(define-public font-anonymous-pro
  (package
    (name "font-anonymous-pro")
    (version "1.002")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://www.marksimonson.com/assets/content/fonts/"
                    "AnonymousPro-" version ".zip"))
              (sha256
               (base32
                "1asj6lykvxh46czbal7ymy2k861zlcdqpz8x3s5bbpqwlm3mhrl6"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (let ((unzip (string-append (assoc-ref %build-inputs "unzip")
                                     "/bin/unzip"))
               (font-dir (string-append %output "/share/fonts/truetype"))
               (doc-dir  (string-append %output "/share/doc/" ,name)))
           (system* unzip (assoc-ref %build-inputs "source"))
           (mkdir-p font-dir)
           (mkdir-p doc-dir)
           (chdir (string-append "AnonymousPro-" ,version ".001"))
           (for-each (lambda (ttf)
                       (copy-file ttf
                                  (string-append font-dir "/" ttf)))
                     (find-files "." "\\.ttf$"))
           (for-each (lambda (doc)
                       (copy-file doc
                                  (string-append doc-dir "/" doc)))
                     (find-files "." "\\.txt$"))))))
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page "http://www.marksimonson.com/fonts/view/anonymous-pro")
    (synopsis "Fixed-width fonts designed with coding in mind")
    (description "Anonymous Pro is a family of four fixed-width fonts designed
with coding in mind.  Anonymous Pro features an international, Unicode-based
character set, with support for most Western and Central European Latin-based
languages, plus Greek and Cyrillic.")
    (license license:silofl1.1)))

(define-public font-gnu-unifont
  (package
    (name "font-gnu-unifont")
    (version "9.0.06")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/unifont/unifont-" version "/unifont-"
                    version ".tar.gz"))
              (sha256
               (base32
                "0ybyraxi8pngibazfq4zlsqmg8kn5xlhvaiwnxb11znhfi61vi87"))))
    (build-system gnu-build-system)
    (outputs '("out" ; TrueType version
               "pcf" ; PCF (bitmap) version
               "psf" ; PSF (console) version
               "bin" ; Utilities to manipulate '.hex' format
               ))
    (arguments
     '(#:parallel-build? #f ; parallel build fails
       #:tests? #f          ; no check target
       #:phases
       (modify-phases %standard-phases
         (replace
          'configure
          (lambda _ (setenv "CC" "gcc") #t))
         (replace
          'install
          (lambda* (#:key outputs #:allow-other-keys)
            (let* ((ttf (string-append (assoc-ref outputs "out")
                                       "/share/fonts/truetype"))
                   (pcf (string-append (assoc-ref outputs "pcf")
                                       "/share/fonts/misc"))
                   (psf (string-append (assoc-ref outputs "psf")
                                       "/share/consolefonts"))
                   (bin (assoc-ref outputs "bin")))
              (system* "make"
                       (string-append "PREFIX=" bin)
                       (string-append "TTFDEST=" ttf)
                       (string-append "PCFDEST=" pcf)
                       (string-append "CONSOLEDEST=" psf)
                       "install")
              ;; Move Texinfo file to the right place.
              (mkdir (string-append bin "/share/info"))
              (rename-file (string-append bin "/share/unifont/unifont.info.gz")
                           (string-append bin "/share/info/unifont.info.gz"))
              #t))))))
    (inputs
     `(("perl" ,perl))) ; for utilities
    (synopsis
     "Large bitmap font covering Unicode's Basic Multilingual Plane")
    (description
     "GNU Unifont is a bitmap font covering essentially all of
Unicode's Basic Multilingual Plane.  The package also includes
utilities to ease adding new glyphs to the font.")
    (home-page "http://unifoundry.com/unifont.html")
    (license license:gpl2+)))

(define-public font-google-noto
  (package
    (name "font-google-noto")
    (version "20150929")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://noto-website-2.storage.googleapis.com/"
                                  "pkgs/Noto-hinted.zip"))
              (sha256
               (base32
                "13jhpqzhsqhyby8n0ksqg155a3jyaif3nzj9anzbq8s2gn1xjyd9"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder (begin
                   (use-modules (guix build utils)
                                (srfi srfi-26))

                   (let ((PATH     (string-append (assoc-ref %build-inputs
                                                             "unzip")
                                                  "/bin"))
                         (font-dir (string-append %output
                                                  "/share/fonts/truetype")))
                     (setenv "PATH" PATH)
                     (system* "unzip" (assoc-ref %build-inputs "source"))

                     (mkdir-p font-dir)
                     (for-each (lambda (ttf)
                                 (copy-file ttf
                                            (string-append font-dir "/" ttf)))
                               (find-files "." "\\.ttf$"))
                     (for-each (lambda (otf)
                                 (copy-file otf
                                            (string-append font-dir "/" otf)))
                               (find-files "." "\\.otf$"))))))
    (native-inputs `(("unzip" ,unzip)))
    (home-page "https://www.google.com/get/noto/")
    (synopsis "Fonts aimed to cover all languages")
    (description "Googe Noto Fonts is a family of fonts aimed to support all
languages with a consistent look and aesthetic.  It's goal is to have no Unicode
symbols unable to be displayed properly.")
    (license license:silofl1.1)))

(define-public font-un
  (package
    (name "font-un")
    (version "1.0.2-080608")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://kldp.net/unfonts/release/2607-"
                    "un-fonts-core-" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "13liaz2pmww3aqabm55la5npd08m1skh334ky7qfidxaz5s742iv"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))

         (let ((tar      (string-append (assoc-ref %build-inputs "tar")
                                        "/bin/tar"))
               (PATH     (string-append (assoc-ref %build-inputs "gzip")
                                        "/bin"))
               (font-dir (string-append %output "/share/fonts/truetype"))
               (doc-dir  (string-append %output "/share/doc/" ,name)))
           (setenv "PATH" PATH)
           (system* tar "xvf" (assoc-ref %build-inputs "source"))
           (mkdir-p font-dir)
           (mkdir-p doc-dir)
           (chdir (string-append "un-fonts"))
           (for-each (lambda (ttf)
                       (copy-file ttf
                                  (string-append font-dir "/"
                                                 (basename ttf))))
                     (find-files "." "\\.ttf$"))
           (for-each (lambda (doc)
                       (copy-file doc
                                  (string-append doc-dir "/"
                                                 (basename doc))))
                     '("COPYING" "README"))))))
    (native-inputs
     `(("tar" ,tar)
       ("gzip" ,gzip)))
    (home-page "https://kldp.net/projects/unfonts/")
    (synopsis "Collection of Korean fonts")
    (description
     "Un-fonts is a family of mainly Korean fonts.
It contains the following fonts and styles:

@enumerate
@item UnBatang, UnBatangBold: serif;
@item UnDotum, UnDotumBold: sans-serif;
@item UnGraphic, UnGraphicBold: sans-serif style;
@item UnDinaru, UnDinaruBold, UnDinaruLight;
@item UnPilgi, UnPilgiBold: script;
@item UnGungseo: cursive, brush-stroke.
@end enumerate\n")
    (license license:gpl2+)))

(define-public font-fantasque-sans
  (package
    (name "font-fantasque-sans")
    (version "1.7.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/belluzj/fantasque-sans/"
                           "archive/v" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "07fpy53k2x2nz5q61swkab6cfk9gw2kc4x4brsj6zjgbm16fap85"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("ttfautohint" ,ttfautohint)
       ("woff-tools" ,woff-tools)
       ("fontforge" ,fontforge)
       ("woff2" ,woff2)
       ("ttf2eot" ,ttf2eot)))
    (arguments
     `(#:tests? #f                 ;test target intended for visual inspection
       #:phases (modify-phases %standard-phases
                  (delete 'configure)   ;no configuration
                  (replace 'install
                    ;; 'make install' wants to install to ~/.fonts, install to
                    ;; output instead.
                    (lambda* (#:key outputs #:allow-other-keys)
                      (let* ((out (assoc-ref outputs "out"))
                             (font-dir (string-append out "/share/fonts"))
                             (truetype-dir (string-append font-dir "/truetype"))
                             (opentype-dir (string-append font-dir "/opentype"))
                             (webfonts-dir (string-append font-dir "/webfonts")))
                        (copy-recursively "OTF" opentype-dir)
                        (for-each (lambda (f) (install-file f truetype-dir))
                                  (find-files "." "\\.ttf$"))
                        (copy-recursively "Webfonts" webfonts-dir)
                        #t))))))
    (synopsis "Font family with a monospaced variant for programmers")
    (description
     "Fantasque Sans Mono is a programming font designed with functionality in
mind.  The font includes a bold version and a good italic version with new
glyph designs, not just an added slant.")
    (home-page "https://fontlibrary.org/en/font/fantasque-sans-mono")
    (license license:silofl1.1)))

(define-public font-hack
  (package
    (name "font-hack")
    (version "2.020")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/chrissimpkins/Hack/releases/download/v"
                    version "/Hack-v"
                    (string-replace-substring version "." "_")
                    "-ttf.zip"))
              (sha256
               (base32
                "16kkmc3psckw1b7k07ccn1gi5ymhlg9djh43nqjzg065g6p6d184"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder (begin
                   (use-modules (guix build utils)
                                (srfi srfi-26))

                   (let ((PATH     (string-append (assoc-ref %build-inputs
                                                             "unzip")
                                                  "/bin"))
                         (font-dir (string-append %output
                                                  "/share/fonts/truetype")))
                     (setenv "PATH" PATH)
                     (system* "unzip" (assoc-ref %build-inputs "source"))

                     (mkdir-p font-dir)
                     (for-each (lambda (ttf)
                                 (copy-file ttf
                                            (string-append font-dir "/" ttf)))
                               (find-files "." "\\.ttf$"))))))
    (native-inputs
     `(("source" ,source)
       ("unzip" ,unzip)))
    (home-page "https://sourcefoundry.org/hack/")
    (synopsis "Typeface designed for sourcecode")
    (description
     "Hack is designed to be a workhorse typeface for code, it expands upon
the Bitstream Vera & DejaVu projects, provides 1561 glyphs including
powerline support.")
    (license (license:x11-style
              "https://github.com/chrissimpkins/Hack/blob/master/LICENSE.md"
              "Hack Open Font License v2.0"))))

(define-public font-adobe-source-code-pro
  (package
    (name "font-adobe-source-code-pro")
    (version "2.030R-ro-1.050R-it")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/adobe-fonts/source-code-pro/archive/"
                    (regexp-substitute/global
                     ;; The upstream tag uses "/" between the roman and italic
                     ;; versions, so substitute our "-" separator here.
                     #f "R-ro-" version 'pre "R-ro/" 'post) ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0arhhsf3i7ss39ykn73d1j8k4n8vx7115xph6jwkd970p1cxvr54"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (let ((tar  (string-append (assoc-ref %build-inputs "tar")
                                    "/bin/tar"))
               (PATH (string-append (assoc-ref %build-inputs "gzip")
                                    "/bin"))
               (font-dir (string-append %output "/share/fonts/opentype")))
           (setenv "PATH" PATH)
           (mkdir-p font-dir)
           (zero? (system* tar "-C" font-dir "--strip-components=2"
                           "-xvf" (assoc-ref %build-inputs "source")
                           (string-append "source-code-pro-"
                                          ,version "/OTF")))))))
    (native-inputs
     `(("gzip" ,gzip)
       ("tar" ,tar)))
    (home-page "https://github.com/adobe-fonts/source-code-pro")
    (synopsis
     "Monospaced font family for user interface and coding environments")
    (description
     "Source Code Pro is a set of monospaced OpenType fonts that have been
designed to work well in user interface environments.")
    (license license:silofl1.1)))

(define-public font-fira-mono
  (package
    (name "font-fira-mono")
    (version "3.206")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://carrois.com/downloads/fira_mono_3_2/"
                                  "FiraMonoFonts"
                                  (string-replace-substring version "." "")
                                  ".zip"))
              (sha256
               (base32
                "1z65x0dw5dq6rs6p9wyfrir50rlh95vgzsxr8jcd40nqazw4jhpi"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (let ((unzip (string-append (assoc-ref %build-inputs "unzip")
                                     "/bin/unzip"))
               (font-dir (string-append %output "/share/fonts/opentype")))
           (mkdir-p font-dir)
           (system* unzip
                    "-j"
                    (assoc-ref %build-inputs "source")
                    "*.otf"
                    "-d" font-dir)))))
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page "http://mozilla.github.io/Fira/")
    (synopsis "Mozilla's monospace font")
    (description "This is the typeface used by Mozilla in Firefox OS.")
    (license license:silofl1.1)))
