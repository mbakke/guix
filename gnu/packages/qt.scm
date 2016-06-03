;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2015 Sou Bunnbu <iyzsong@gmail.com>
;;; Copyright © 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015, 2016 Efraim Flashner <efraim@flashner.co.il>
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

(define-module (gnu packages qt)
  #:use-module ((guix licenses) #:select (bsd-3 gpl2 gpl3 lgpl2.1 lgpl2.1+ lgpl3 x11-style))
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build utils)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system gnu)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (gnu packages)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages cups)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnuzilla)
  #:use-module (gnu packages gperf)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages image)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages pciutils)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages ruby)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages xml))

(define-public qt
  (package
    (name "qt")
    (version "5.5.1")
    (source (origin
             (method url-fetch)
             (uri
               (string-append
                 "http://download.qt.io/official_releases/qt/"
                 (version-major+minor version)
                 "/" version
                 "/single/qt-everywhere-opensource-src-"
                 version ".tar.xz"))
             (sha256
               (base32
                 "0615cn4n3n78v48lnmapqz2jizm2pzrjwvsjlnsf4awrsiiqw0kg"))
             (modules '((guix build utils)))
             (snippet
              '(begin
                ;; Remove qtwebengine, which relies on a bundled copy of
                ;; chromium. Not only does it fail compilation in qt 5.5:
                ;;    3rdparty/chromium/ui/gfx/codec/jpeg_codec.cc:362:10:
                ;;    error: cannot convert ‘bool’ to ‘boolean’ in return
                ;; it might also pose security problems.
                ;; Alternatively, we could use the "-skip qtwebengine"
                ;; configuration option.
                (delete-file-recursively "qtwebengine")
                ;; Remove one of the two bundled harfbuzz copies in addition
                ;; to passing "-system-harfbuzz".
                (delete-file-recursively "qtbase/src/3rdparty/harfbuzz-ng")
                ;; Remove the bundled sqlite copy in addition to
                ;; passing "-system-sqlite".
                (delete-file-recursively "qtbase/src/3rdparty/sqlite")))))
    (build-system gnu-build-system)
    (propagated-inputs
     `(("mesa" ,mesa)))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("dbus" ,dbus)
       ("cups" ,cups)
       ("expat" ,expat)
       ("fontconfig" ,fontconfig)
       ("freetype" ,freetype)
       ("glib" ,glib)
       ("harfbuzz" ,harfbuzz)
       ("icu4c" ,icu4c)
       ("libjpeg" ,libjpeg)
       ("libmng" ,libmng)
       ("libpci" ,pciutils)
       ("libpng" ,libpng)
       ("libx11" ,libx11)
       ("libxcomposite" ,libxcomposite)
       ("libxcursor" ,libxcursor)
       ("libxfixes" ,libxfixes)
       ("libxi" ,libxi)
       ("libxinerama" ,libxinerama)
       ("libxkbcommon" ,libxkbcommon)
       ("libxml2" ,libxml2)
       ("libxrandr" ,libxrandr)
       ("libxrender" ,libxrender)
       ("libxslt" ,libxslt)
       ("libxtst" ,libxtst)
       ("mtdev" ,mtdev)
       ("mysql" ,mysql)
       ("nss" ,nss)
       ("openssl" ,openssl)
       ("postgresql" ,postgresql)
       ("pulseaudio" ,pulseaudio)
       ("pcre" ,pcre)
       ("sqlite" ,sqlite)
       ("udev" ,eudev)
       ("unixodbc" ,unixodbc)
       ("xcb-util" ,xcb-util)
       ("xcb-util-image" ,xcb-util-image)
       ("xcb-util-keysyms" ,xcb-util-keysyms)
       ("xcb-util-renderutil" ,xcb-util-renderutil)
       ("xcb-util-wm" ,xcb-util-wm)
       ("zlib" ,zlib)))
    (native-inputs
     `(("bison" ,bison)
       ("flex" ,flex)
       ("gperf" ,gperf)
       ("perl" ,perl)
       ("pkg-config" ,pkg-config)
       ("python" ,python-2)
       ("ruby" ,ruby)
       ("which" ,(@ (gnu packages base) which))))
    (arguments
     `(;; FIXME: Disabling parallel building is a quick hack to avoid the
       ;; failure described in
       ;; https://lists.gnu.org/archive/html/guix-devel/2016-01/msg00837.html
       ;; A more structural fix is needed.
       #:parallel-build? #f
       #:phases
         (alist-replace
          'configure
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((out (assoc-ref outputs "out")))
              (substitute* '("configure" "qtbase/configure")
                (("/bin/pwd") (which "pwd")))
              (substitute* "qtbase/src/corelib/global/global.pri"
                (("/bin/ls") (which "ls")))
              ;; do not pass "--enable-fast-install", which makes the
              ;; configure process fail
              (zero? (system*
                      "./configure"
                      "-verbose"
                      "-prefix" out
                      "-opensource"
                      "-confirm-license"
                      ;; Most "-system-..." are automatic, but some use
                      ;; the bundled copy by default.
                      "-system-sqlite"
                      "-system-harfbuzz"
                      ;; explicitly link with openssl instead of dlopening it
                      "-openssl-linked"
                      ;; explicitly link with dbus instead of dlopening it
                      "-dbus-linked"
                      ;; drop special machine instructions not supported
                      ;; on all instances of the target
                      ,@(if (string-prefix? "x86_64"
                                            (or (%current-target-system)
                                                (%current-system)))
                            '()
                            '("-no-sse2"))
                      "-no-sse3"
                      "-no-ssse3"
                      "-no-sse4.1"
                      "-no-sse4.2"
                      "-no-avx"
                      "-no-avx2"
                      "-no-mips_dsp"
                      "-no-mips_dspr2"))))
          %standard-phases)))
    (home-page "http://qt-project.org/")
    (synopsis "Cross-platform GUI library")
    (description "Qt is a cross-platform application and UI framework for
developers using C++ or QML, a CSS & JavaScript like language.")
    (license lgpl2.1)

    ;; Qt 4: 'QBasicAtomicPointer' leads to build failures on MIPS;
    ;; see <http://hydra.gnu.org/build/112828>.
    ;; Qt 5: assembler error; see <http://hydra.gnu.org/build/112526>.
    (supported-systems (delete "mips64el-linux" %supported-systems))))

(define-public qt-4
  (package (inherit qt)
    (version "4.8.7")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://download.qt-project.org/official_releases/qt/"
                                 (string-copy version 0 (string-rindex version #\.))
                                 "/" version
                                 "/qt-everywhere-opensource-src-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "183fca7n7439nlhxyg1z7aky0izgbyll3iwakw4gwivy16aj5272"))
             (patches (search-patches "qt4-ldflags.patch"))
             (modules '((guix build utils)))
             (snippet
              ;; Remove webkit module, which is not built.
              '(delete-file-recursively "src/3rdparty/webkit"))))
    (inputs `(,@(alist-delete "harfbuzz"
                              (alist-delete "libjpeg" (package-inputs qt)))
              ("libjepg" ,libjpeg-8)
              ("libsm" ,libsm)))

    ;; Note: there are 37 MiB of examples and a '-exampledir' configure flags,
    ;; but we can't make them a separate output because "out" and "examples"
    ;; would refer to each other.
    (outputs '("out"                             ;112MiB core + 37MiB examples
               "doc"))                           ;280MiB of HTML + code
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace
          'configure
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((out (assoc-ref outputs "out"))
                  (doc (assoc-ref outputs "doc")))
              (substitute* '("configure")
                (("/bin/pwd") (which "pwd")))

              (zero? (system*
                      "./configure"
                      "-verbose"
                      "-prefix" out
                      ;; Note: Don't pass '-docdir' since 'qmake' and
                      ;; libQtCore would record its value, thereby defeating
                      ;; the whole point of having a separate output.
                      "-datadir" (string-append out "/share/qt-" ,version
                                                "/data")
                      "-importdir" (string-append out "/lib/qt-4"
                                                  "/imports")
                      "-plugindir" (string-append out "/lib/qt-4"
                                                  "/plugins")
                      "-translationdir" (string-append out "/share/qt-" ,version
                                                       "/translations")
                      "-demosdir"    (string-append out "/share/qt-" ,version
                                                    "/demos")
                      "-examplesdir" (string-append out "/share/qt-" ,version
                                                    "/examples")
                      "-opensource"
                      "-confirm-license"
                      ;; explicitly link with dbus instead of dlopening it
                      "-dbus-linked"
                      ;; Skip the webkit module; it fails to build on armhf
                      ;; and, apart from that, may pose security risks.
                      "-no-webkit"
                      ;; drop special machine instructions not supported
                      ;; on all instances of the target
                      ,@(if (string-prefix? "x86_64"
                                            (or (%current-target-system)
                                                (%current-system)))
                            '()
                            '("-no-mmx"
                              "-no-3dnow"
                              "-no-sse"
                              "-no-sse2"))
                      "-no-sse3"
                      "-no-ssse3"
                      "-no-sse4.1"
                      "-no-sse4.2"
                      "-no-avx")))))
         (add-after
          'install 'move-doc
          (lambda* (#:key outputs #:allow-other-keys)
            ;; Because of qt4-documentation-path.patch, documentation ends up
            ;; being installed in OUT.  Move it to the right place.
            (let* ((out    (assoc-ref outputs "out"))
                   (doc    (assoc-ref outputs "doc"))
                   (olddoc (string-append out "/doc"))
                   (docdir (string-append doc "/share/doc/qt-" ,version)))
              (mkdir-p (dirname docdir))

              ;; Note: We can't use 'rename-file' here because OUT and DOC are
              ;; different "devices" due to bind-mounts.
              (copy-recursively olddoc docdir)
              (delete-file-recursively olddoc)
              #t))))))))

(define-public qtbase
  (package
    (name "qtbase")
    (version "5.6.0")
    (source (origin
             (method url-fetch)
             (uri (string-append "https://download.qt.io/official_releases/qt/"
                                 (version-major+minor version) "/" version
                                 "/submodules/" name "-opensource-src-"
                                 version ".tar.xz"))
             (sha256
               (base32
                 "0ynnvcs5idivzldsq5ciqg9myg82b3l3906l4vjv54lyamf8mykf"))
             (modules '((guix build utils)))
             (snippet
              '(begin
                ;; Remove one of the two bundled harfbuzz copies in addition
                ;; to passing "-system-harfbuzz".
                (delete-file-recursively "src/3rdparty/harfbuzz-ng")
                ;; Remove the bundled sqlite copy in addition to
                ;; passing "-system-sqlite".
                (delete-file-recursively "src/3rdparty/sqlite")))))
    (build-system gnu-build-system)
    (propagated-inputs
     `(("mesa" ,mesa)))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("dbus" ,dbus)
       ("cups" ,cups)
       ("expat" ,expat)
       ("fontconfig" ,fontconfig)
       ("freetype" ,freetype)
       ("glib" ,glib)
       ("harfbuzz" ,harfbuzz)
       ("icu4c" ,icu4c)
       ("libjpeg" ,libjpeg)
       ("libmng" ,libmng)
       ("libpci" ,pciutils)
       ("libpng" ,libpng)
       ("libx11" ,libx11)
       ("libxcomposite" ,libxcomposite)
       ("libxcursor" ,libxcursor)
       ("libxfixes" ,libxfixes)
       ("libxi" ,libxi)
       ("libxinerama" ,libxinerama)
       ("libxkbcommon" ,libxkbcommon)
       ("libxml2" ,libxml2)
       ("libxrandr" ,libxrandr)
       ("libxrender" ,libxrender)
       ("libxslt" ,libxslt)
       ("libxtst" ,libxtst)
       ("mtdev" ,mtdev)
       ("mysql" ,mysql)
       ("nss" ,nss)
       ("openssl" ,openssl)
       ("postgresql" ,postgresql)
       ("pulseaudio" ,pulseaudio)
       ("pcre" ,pcre)
       ("sqlite" ,sqlite)
       ("udev" ,eudev)
       ("unixodbc" ,unixodbc)
       ("xcb-util" ,xcb-util)
       ("xcb-util-image" ,xcb-util-image)
       ("xcb-util-keysyms" ,xcb-util-keysyms)
       ("xcb-util-renderutil" ,xcb-util-renderutil)
       ("xcb-util-wm" ,xcb-util-wm)
       ("zlib" ,zlib)))
    (native-inputs
     `(("bison" ,bison)
       ("flex" ,flex)
       ("gperf" ,gperf)
       ("perl" ,perl)
       ("pkg-config" ,pkg-config)
       ("python" ,python-2)
       ("ruby" ,ruby)
       ("which" ,(@ (gnu packages base) which))))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'configure 'patch-bin-sh
           (lambda _
             (substitute* '("config.status"
                            "configure"
                            "mkspecs/features/qt_functions.prf"
                            "qmake/library/qmakebuiltins.cpp")
                          (("/bin/sh") (which "sh")))
             #t))
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (substitute* "configure"
                 (("/bin/pwd") (which "pwd")))
               (substitute* "src/corelib/global/global.pri"
                 (("/bin/ls") (which "ls")))
               ;; do not pass "--enable-fast-install", which makes the
               ;; configure process fail
               (zero? (system*
                       "./configure"
                       "-verbose"
                       "-prefix" out
                       "-opensource"
                       "-confirm-license"
                       ;; We don't want the examples in the 'out' output, but
                       ;; the easiest option is to just not build them.
                       ;; This also saves significant time while building.
                       "-nomake" "examples"
                       ;; Most "-system-..." are automatic, but some use
                       ;; the bundled copy by default.
                       "-system-sqlite"
                       "-system-harfbuzz"
                       ;; explicitly link with openssl instead of dlopening it
                       "-openssl-linked"
                       ;; explicitly link with dbus instead of dlopening it
                       "-dbus-linked"
                       ;; drop special machine instructions not supported
                       ;; on all instances of the target
                       ,@(if (string-prefix? "x86_64"
                                             (or (%current-target-system)
                                                 (%current-system)))
                             '()
                             '("-no-sse2"))
                       "-no-sse3"
                       "-no-ssse3"
                       "-no-sse4.1"
                       "-no-sse4.2"
                       "-no-avx"
                       "-no-avx2"
                       "-no-mips_dsp"
                       "-no-mips_dspr2"))))))))
    (home-page "https://www.qt.io/")
    (synopsis "Cross-platform GUI library")
    (description "Qt is a cross-platform application and UI framework for
developers using C++ or QML, a CSS & JavaScript like language.")
    (license (list lgpl2.1 lgpl3))))

(define-public qtsvg
  (package (inherit qtbase)
    (name "qtsvg")
    (version "5.6.0")
    (source (origin
             (method url-fetch)
             (uri (string-append "https://download.qt.io/official_releases/qt/"
                                 (version-major+minor version) "/" version
                                 "/submodules/" name "-opensource-src-"
                                 version ".tar.xz"))
             (sha256
              (base32
               "07v4bzxd31dhkhp52y4g2ii0sslmk48cqkkz32v41frqj4qrk1vr"))))
    (propagated-inputs `())
    (inputs
     `(("qtbase" ,qtbase)
       ,@(package-inputs qtbase)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda _
             (zero? (system* "qmake"
                             (string-append "PREFIX="
                                            (assoc-ref %outputs "out"))))))
         (add-before 'install 'fix-Makefiles
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let ((out    (assoc-ref outputs "out"))
                   (qtbase (assoc-ref inputs "qtbase")))
               (substitute* '("src/svg/Makefile"
                              "src/plugins/iconengines/svgiconengine/Makefile"
                              "src/plugins/imageformats/svg/Makefile")
                            (((string-append "INSTALL_ROOT)" qtbase))
                             (string-append "INSTALL_ROOT)" out)))))))))))

(define-public qtimageformats
  (package (inherit qtbase)
    (name "qtimageformats")
    (version "5.6.0")
    (source (origin
             (method url-fetch)
             (uri (string-append "https://download.qt.io/official_releases/qt/"
                                 (version-major+minor version) "/" version
                                 "/submodules/" name "-opensource-src-"
                                 version ".tar.xz"))
             (sha256
              (base32
               "1nmsh682idxl0642q7376r9qfxkx0736q9pl4jx179c9lrsl519c"))))
    (propagated-inputs `())
    (inputs
     `(("qtbase" ,qtbase)
       ,@(package-inputs qtbase)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda _
             (zero? (system* "qmake"
                             (string-append "PREFIX="
                                            (assoc-ref %outputs "out"))))))
         (add-before 'install 'fix-Makefiles
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let ((out    (assoc-ref outputs "out"))
                   (qtbase (assoc-ref inputs "qtbase")))
               (substitute* '("src/plugins/imageformats/tiff/Makefile"
                              "src/plugins/imageformats/wbmp/Makefile"
                              "src/plugins/imageformats/dds/Makefile"
                              "src/plugins/imageformats/tga/Makefile"
                              "src/plugins/imageformats/webp/Makefile"
                              "src/plugins/imageformats/icns/Makefile"
                              "src/plugins/imageformats/mng/Makefile")
                            (((string-append "INSTALL_ROOT)" qtbase))
                             (string-append "INSTALL_ROOT)" out)))))))))))

(define-public qjson
  (package
    (name "qjson")
    (version "0.8.1")
    (source (origin
             (method url-fetch)
             (uri (string-append "https://github.com/flavio/qjson/archive/"
                                 version ".tar.gz"))
             (file-name (string-append name "-" version ".tar.gz"))
             (sha256
              (base32
               "163fspi0xc705irv79qw861fmh68pjyla9vx3kqiq6xrdhb9834j"))))
    (build-system cmake-build-system)
    (inputs
     `(("qt" ,qt-4)))
    (arguments
     `(#:tests? #f)) ; no test target
    (home-page "http://qjson.sourceforge.net/")
    (synopsis "Qt-based library for handling JSON")
    (description "QJson is a Qt-based library that maps JSON data to QVariant
objects and vice versa.  JSON arrays are mapped to QVariantList instances,
while JSON objects are mapped to QVariantMap.")
    (license lgpl2.1+)))

(define-public python-sip
  (package
    (name "python-sip")
    (version "4.16.9")
    (source
      (origin
        (method url-fetch)
        (uri
          (string-append "mirror://sourceforge/pyqt/sip/"
                         "sip-" version "/sip-"
                         version ".tar.gz"))
        (sha256
         (base32
          "0m85dgm3g9s9h7s5sfxvcxi423vqxwq1vg5wnl5wl9kfasm77qfv"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("python" ,python-wrapper)))
    (arguments
     `(#:tests? #f ; no check target
       #:modules ((srfi srfi-1)
                  ,@%gnu-build-system-modules)
       #:phases
         (alist-replace
          'configure
          (lambda* (#:key inputs outputs #:allow-other-keys)
            (let* ((out (assoc-ref outputs "out"))
                   (bin (string-append out "/bin"))
                   (include (string-append out "/include"))
                   (python (assoc-ref inputs "python"))
                   (python-version
                     (last (string-split python #\-)))
                   (python-major+minor
                     (string-join
                       (take (string-split python-version #\.) 2)
                       "."))
                   (lib (string-append out "/lib/python"
                                       python-major+minor
                                       "/site-packages")))
              (zero?
                (system* "python" "configure.py"
                         "--bindir" bin
                          "--destdir" lib
                         "--incdir" include))))
          %standard-phases)))
    (home-page "http://www.riverbankcomputing.com/software/sip/intro")
    (synopsis "Python binding creator for C and C++ libraries")
    (description
     "SIP is a tool to create Python bindings for C and C++ libraries.  It
was originally developed to create PyQt, the Python bindings for the Qt
toolkit, but can be used to create bindings for any C or C++ library.

SIP comprises a code generator and a Python module.  The code generator
processes a set of specification files and generates C or C++ code, which
is then compiled to create the bindings extension module.  The SIP Python
module provides support functions to the automatically generated code.")
    ;; There is a choice between a python like license, gpl2 and gpl3.
    ;; For compatibility with pyqt, we need gpl3.
    (license gpl3)))

(define-public python2-sip
  (package (inherit python-sip)
    (name "python2-sip")
    (native-inputs
     `(("python" ,python-2)))))

(define-public python-pyqt
  (package
    (name "python-pyqt")
    (version "5.5")
    (source
      (origin
        (method url-fetch)
        (uri
          (string-append "mirror://sourceforge/pyqt/PyQt5/"
                         "PyQt-" version "/PyQt-gpl-"
                         version ".tar.gz"))
        (sha256
         (base32
          "056qmkv02wdcfblqdaxiswrgn4wa88sz22i1x58dpb1iniavplfd"))
       (patches (search-patches "pyqt-configure.patch"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("python-sip" ,python-sip)
       ("qt" ,qt))) ; for qmake
    (inputs
     `(("python" ,python-wrapper)))
    (arguments
     `(#:modules ((srfi srfi-1)
                  ,@%gnu-build-system-modules)
       #:phases
         (alist-replace
         'configure
         (lambda* (#:key inputs outputs #:allow-other-keys)
           (let* ((out (assoc-ref outputs "out"))
                  (bin (string-append out "/bin"))
                  (sip (string-append out "/share/sip"))
                  (plugins (string-append out "/plugins"))
                  (designer (string-append plugins "/designer"))
                  (qml (string-append plugins "/PyQt5"))
                  (python (assoc-ref inputs "python"))
                  (python-version
                    (last (string-split python #\-)))
                  (python-major+minor
                    (string-join
                      (take (string-split python-version #\.) 2)
                      "."))
                  (lib (string-append out "/lib/python"
                                      python-major+minor
                                      "/site-packages")))
             (zero? (system* "python" "configure.py"
                             "--confirm-license"
                             "--bindir" bin
                             "--destdir" lib
                             "--designer-plugindir" designer
                             "--qml-plugindir" qml
                             "--sipdir" sip))))
         %standard-phases)))
    (home-page "http://www.riverbankcomputing.com/software/pyqt/intro")
    (synopsis "Python bindings for Qt")
    (description
     "PyQt is a set of Python v2 and v3 bindings for the Qt application
framework.  The bindings are implemented as a set of Python modules and
contain over 620 classes.")
    (license gpl3)))

(define-public python2-pyqt
  (package (inherit python-pyqt)
    (name "python2-pyqt")
    (native-inputs
     `(("python-sip" ,python2-sip)
       ("qt" ,qt)))
    (inputs
     `(("python" ,python-2)))))

(define-public python-pyqt-4
  (package (inherit python-pyqt)
    (name "python-pyqt")
    (version "4.11.4")
    (source
      (origin
        (method url-fetch)
        (uri
          (string-append "mirror://sourceforge/pyqt/PyQt4/"
                         "PyQt-" version "/PyQt-x11-gpl-"
                         version ".tar.gz"))
        (sha256
         (base32
          "01zlviy5lq8g6db84wnvvpsrfnip9lbcpxagsyqa6as3jmsff7zw"))))
    (native-inputs
     `(("python-sip" ,python-sip)
       ("qt" ,qt-4)))
    (arguments
     `(#:tests? #f ; no check target
       #:modules ((srfi srfi-1)
                  ,@%gnu-build-system-modules)
       #:phases
         (alist-replace
         'configure
         (lambda* (#:key inputs outputs #:allow-other-keys)
           (let* ((out (assoc-ref outputs "out"))
                  (bin (string-append out "/bin"))
                  (sip (string-append out "/share/sip"))
                  (python (assoc-ref inputs "python"))
                  (python-version
                    (last (string-split python #\-)))
                  (python-major+minor
                    (string-join
                      (take (string-split python-version #\.) 2)
                      "."))
                  (lib (string-append out "/lib/python"
                                      python-major+minor
                                      "/site-packages")))
             (zero? (system* "python" "configure.py"
                             "--confirm-license"
                             "--bindir" bin
                             "--destdir" lib
                             "--sipdir" sip))))
         %standard-phases)))
    (license (list gpl2 gpl3)))) ; choice of either license

(define-public qtkeychain
  (package
    (name "qtkeychain")
    (version "0.6.2")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "https://github.com/frankosterfeld/qtkeychain/"
                            "archive/v" version ".tar.gz"))
        (file-name (string-append name "-" version ".tar.gz"))
        (sha256
         (base32 "0g76pa786mg0fxy52hrljw09dvi6kffk2ms42lxapvpy6j94a4xf"))))
    (build-system cmake-build-system)
    (inputs
     `(("qt" ,qt)))
    (arguments
     `(#:tests? #f ; No tests included
       #:phases
       (modify-phases %standard-phases
         (add-before
          'configure 'set-qt-trans-dir
           (lambda _
             (substitute* "CMakeLists.txt"
              (("\\$\\{qt_translations_dir\\}")
               "${CMAKE_INSTALL_PREFIX}/share/qt/translations")))))))
    (home-page "https://github.com/frankosterfeld/qtkeychain")
    (synopsis "Qt API to store passwords")
    (description
      "QtKeychain is a Qt library to store passwords and other secret data
securely.  It will not store any data unencrypted unless explicitly requested.")
    (license bsd-3)))
