;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Thomas Danckaert <post@thomasdanckaert.be>
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

(define-module (gnu packages kde)
  #:use-module (guix build-system cmake)
  #:use-module (guix download)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (gnu packages apr)
  #:use-module (gnu packages boost)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages kde-frameworks)
  #:use-module (gnu packages llvm)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages qt)
  #:use-module (gnu packages version-control))

(define-public kdevelop
  (package
    (name "kdevelop")
    (version "5.0.2")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "mirror://kde/stable/kdevelop"
                            "/" version "/src/kdevelop-"
                            version ".tar.xz"))
        (sha256
         (base32
          "0rl6csmzf14gf0r0mk7z2lj7cq8fggf5qmlbxq6j68vp2q0pj0cv"))))
    (build-system cmake-build-system)
    (native-inputs
     `(("extra-cmake-modules" ,extra-cmake-modules)
       ("pkg-config" ,pkg-config)
       ("qttools" ,qttools)))
    (inputs
     `(("kdevplatform" ,kdevplatform)
       ("kdevelop-pg-qt" ,kdevelop-pg-qt)
       ("qtbase" ,qtbase)
       ("qtdeclarative" ,qtdeclarative)
       ("qtquickcontrols" ,qtquickcontrols)
       ("qtwebkit" ,qtwebkit)
       ("karchive" ,karchive)
       ("kcmutils" ,kcmutils)
       ("kconfig" ,kconfig)
       ("kdeclarative" ,kdeclarative)
       ("kdoctools" ,kdoctools)
       ("kguiaddons" ,kguiaddons)
       ("ki18n" ,ki18n)
       ("kio" ,kio)
       ("kiconthemes" ,kiconthemes)
       ("kitemmodels" ,kitemmodels)
       ("kitemviews" ,kitemviews)
       ("kjobwidgets" ,kjobwidgets)
       ("knotifyconfig" ,knotifyconfig)
       ("knotifications" ,knotifications)
       ("kparts" ,kparts)
       ("kcrash" ,kcrash)
       ("knewstuff" ,knewstuff)
       ("krunner" ,krunner)
       ("kxmlgui" ,kxmlgui)
       ("libksysguard" ,libksysguard)
       ("threadweaver" ,threadweaver)
       ("ktexteditor" ,ktexteditor)
       ("kwindowsystem" ,kwindowsystem)
       ("plasma" ,plasma-framework)
       ("grantlee" ,grantlee)
       ("libepoxy" ,libepoxy)
       ("clang" ,clang)
       ("shared-mime-info" ,shared-mime-info)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (delete 'check) ;; there are some issues with the test suite
         (add-after 'install 'wrap-executable
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out  (assoc-ref outputs "out"))
                    (kdevplatform (assoc-ref inputs "kdevplatform"))
                    (kio (assoc-ref inputs "kio"))
                    (qtquickcontrols (assoc-ref inputs "qtquickcontrols"))
                    (qtdeclarative (assoc-ref inputs "qtdeclarative"))
                    (plugins "/lib/plugins")
                    (qml "/qml"))
               (wrap-program (string-append out "/bin/kdevelop")
                 `("QT_PLUGIN_PATH" ":" prefix
                   (,(string-append out plugins)
                    ,(string-append kdevplatform plugins)
                    ,(string-append kio plugins)))
                 `("QML2_IMPORT_PATH" ":" prefix
                   (,(string-append qtquickcontrols qml)
                    ,(string-append qtdeclarative qml))))))))))
    (home-page "https://kdevelop.org")
    (synopsis "IDE for C, C++, Python, Javascript and PHP")
    (description "The KDevelop IDE provides semantic syntax highlighting, as
well as code navigation and completion for C, C++ (using Clang/LLVM), QML,
JavaScript, Python and PHP.  It also integrates with a debugger, different
build systems (CMake, QMake, custom Makefiles) and version control
software (Git, Subversion, Mercurial, CVS and Bazaar).")
    (license license:lgpl2.1+)))

(define-public kdevelop-pg-qt
  (package
    (name "kdevelop-pg-qt")
    (version "2.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/KDE/kdevelop-pg-qt/archive/v"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32 "1av8plqz7hyhrd07avnmn6ryslqlarmxn0pw7swzvb6ddiqp59j4"))))
    (native-inputs
     `(("extra-cmake-modules" ,extra-cmake-modules)))
    (inputs
     `(("qtbase" ,qtbase)))
    (build-system cmake-build-system)
    (home-page "https://kde.org")
    (synopsis "Parser generator library for KDevplatform")
    (description "KDevelop-PG-Qt is the parser generator used in KDevplatform
for some KDevelop language plugins (Ruby, PHP, CSS...).")
    (license license:lgpl2.0+)))

(define-public kdevplatform
  (package
    (name "kdevplatform")
    (version "5.0.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/KDE/kdevplatform/archive/v"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1m8c0ixv91diyy9bvq53d4jik4zrnf7bix7clad4ywxnlpcs4ahr"))
              (file-name (string-append name "-" version ".tar.gz"))))
    (build-system cmake-build-system)
    (native-inputs
     `(("extra-cmake-modules" ,extra-cmake-modules)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("apr" ,apr)
       ("apr-util" ,apr-util)
       ("boost" ,boost)
       ("karchive" ,karchive)
       ("kconfigwidgets" ,kconfigwidgets)
       ("kcmutils" ,kcmutils)
       ("kiconthemes" ,kiconthemes)
       ("kdeclarative" ,kdeclarative)
       ("kdoctools" ,kdoctools)
       ("kguiaddons" ,kguiaddons)
       ("kinit" ,kinit)
       ("kitemmodels" ,kitemmodels)
       ("knewstuff" ,knewstuff)
       ("knotifications" ,knotifications)
       ("knotifyconfig" ,knotifyconfig)
       ("kwindowsystem" ,kwindowsystem)
       ("kio" ,kio)
       ("ki18n" ,ki18n)
       ("kparts" ,kparts)
       ("kservice" ,kservice)
       ("grantlee" ,grantlee)
       ("libkomparediff2" ,libkomparediff2)
       ("sonnet" ,sonnet)
       ("threadweaver" ,threadweaver)
       ("ktexteditor" ,ktexteditor)
       ("qtbase" ,qtbase)
       ("qtdeclarative" ,qtdeclarative)
       ("qtscript" ,qtscript)
       ("qtwebkit" ,qtwebkit)
       ("qtx11extras" ,qtx11extras)
       ("plasma" ,plasma-framework)
       ("subversion" ,subversion)
       ("zlib" ,zlib)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (delete 'check)
         (add-after 'install 'check ;; add-after 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (setenv "CTEST_OUTPUT_ON_FAILURE" "1")
               (setenv "QT_PLUGIN_PATH"
                       (string-append out "/lib/plugins:"
                                      (getenv "QT_PLUGIN_PATH")))
               (setenv "XDG_DATA_DIRS"
                       (string-append out "/share:"
                                      (getenv "XDG_DATA_DIRS")))
               (zero?
                (system* "ctest" "-R" ;; almost all tests require a display
                         "filteringstrategy|kdevvarlengtharray|kdevhash"))))))))
    (home-page "https://github.com/KDE/kdevplatform")
    (synopsis "Framework to build integrated development environments (IDEs)")
    (description "KDevPlatform is the basis of KDevelop and contains some
plugins, as well as code to create plugins, or complete applications.")
    (license license:gpl3+)))

(define-public libkomparediff2
  (package
    (name "libkomparediff2")
    (version "16.08.2")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "https://github.com/KDE/libkomparediff2/archive/v"
                            version ".tar.gz"))
        (file-name (string-append name "-" version ".tar.gz"))
        (sha256
         (base32
          "1lafifrwfxvn0jwhz67kwv7m38lm4syips3fq77rwcvfhmkiijmh"))))
    (native-inputs
     `(("extra-cmake-modules" ,extra-cmake-modules)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("kcodecs" ,kcodecs)
       ("kconfig" ,kconfig)
       ("kcoreaddons" ,kcoreaddons)
       ("ki18n" ,ki18n)
       ("kio" ,kio)
       ("kxmlgui" ,kxmlgui)
       ("qtbase" ,qtbase)))
    (build-system cmake-build-system)
    (home-page "https://kde.org")
    (synopsis "Library to compare files and strings, used in Kompare and KDevelop")
    (description "Libkomparediff2 is a library to work with diffs and patches,
used in KDE development tools Kompare and KDevelop.")

    ;; GPL, some files are also licensed under LGPL or BSD, see COPYING in the
    ;; source archive
    (license (list license:gpl2+ license:lgpl2.0+ license:bsd-3))))

(define-public libksysguard
  (package
    (name "libksysguard")
    (version "5.8.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://kde//stable/plasma/" version
                           "/libksysguard-" version ".tar.xz"))
       (sha256
        (base32
         "158n30wbpsgbw3axhhsc58hnwhwdd02j3zc9hhcybmnbkfl5c96l"))))
    (native-inputs
     `(("extra-cmake-modules" ,extra-cmake-modules)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("kconfigwidgets" ,kconfigwidgets)
       ("kiconthemes" ,kiconthemes)
       ("kwindowsystem" ,kwindowsystem)
       ("ki18n" ,ki18n)
       ("kauth" ,kauth)
       ("kcompletion" ,kcompletion)
       ("kconfig" ,kconfig)
       ("kcoreaddons" ,kcoreaddons)
       ("kwidgetsaddons" ,kwidgetsaddons)
       ("kservice" ,kservice)
       ("qtbase" ,qtbase)
       ("qtscript" ,qtscript)
       ("qtwebkit" ,qtwebkit)
       ("qtx11extras" ,qtx11extras)
       ("plasma" ,plasma-framework)
       ("zlib" ,zlib)))
    (build-system cmake-build-system)
    (arguments
     `(#:configure-flags
       `(,(string-append "-DKDE_INSTALL_DATADIR="
                         (assoc-ref %outputs "out") "/share"))
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'patch-cmakelists
           (lambda _
             (substitute* "processcore/CMakeLists.txt"
               (("KAUTH_HELPER_INSTALL_DIR") "KDE_INSTALL_LIBEXECDIR"))))
         (replace 'check
           (lambda _         ;other tests require a display and therefore fail
             (zero? (system* "ctest" "-R" "chronotest")))))))
    (home-page "https://www.kde.org/info/plasma-5.8.2.php")
    (synopsis "Network enabled task and system monitoring")
    (description "KSysGuard can obtain information on system load and
manage running processes.  It obtains this information by interacting
with a ksysguardd daemon, which may also run on a remote system.")
    (license license:gpl3+)))

(define-public qca
  (package
    (name "qca")
    (version "2.1.1")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "http://download.kde.org/stable/qca/" version
                            "/src/qca-" version ".tar.xz"))
        (sha256
         (base32
          "10z9icq28fww4qbzwra8d9z55ywbv74qk68nhiqfrydm21wkxplm"))))
    (build-system cmake-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("openssl" ,openssl)
       ("qtbase" ,qtbase)))
    (home-page "http://delta.affinix.com/qca/")
    (synopsis "Libraries for the Qt Cryptographic Architecture")
    (description "The Qt Cryptographic Architecture (QCA) provides a
straightforward and cross-platform API for a range of cryptographic features,
including SSL/TLS, X.509 certificates, SASL, OpenPGP, S/MIME CMS, and smart
cards.")
    (license license:lgpl2.1)))

(define-public snorenotify
  (package
    (name "snorenotify")
    (version "0.7.0")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "http://download.kde.org/stable/snorenotify/"
                            version "/src/snorenotify-" version ".tar.xz"))
        (sha256
         (base32
          "0jz6ivk90h7iwgyxar7xzzj8yvzn6s1my6cqs9bdnwqswfk1nhbd"))))
    (build-system cmake-build-system)
    (arguments
     `(#:tests? #f)) ; both tests fail, require display
    (inputs
     `(("extra-cmake-modules" ,extra-cmake-modules)
       ("qtbase" ,qtbase)
       ("qttools" ,qttools)))
    (home-page "https://techbase.kde.org/Projects/Snorenotify")
    (synopsis "Qt notification framework")
    (description "Snorenotify is a multi platform Qt notification framework.
Using a plugin system it is possible to create notifications with many
different notification systems.")
    (license license:lgpl3)))
