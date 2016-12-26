;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
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

(define-module (gnu packages java)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix utils)
  #:use-module (guix build-system ant)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages attr)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages certs)
  #:use-module (gnu packages cpio)
  #:use-module (gnu packages cups)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages gawk)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages gnuzilla) ;nss
  #:use-module (gnu packages ghostscript) ;lcms
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages image)
  #:use-module (gnu packages linux) ;alsa
  #:use-module (gnu packages wget)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages mit-krb5)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages zip)
  #:use-module (gnu packages texinfo)
  #:use-module ((srfi srfi-1) #:select (fold alist-delete))
  #:use-module (srfi srfi-11)
  #:use-module (ice-9 match))

(define-public java-swt
  (package
    (name "java-swt")
    (version "4.6")
    (source
     ;; The types of many variables and procedures differ in the sources
     ;; dependent on whether the target architecture is a 32-bit system or a
     ;; 64-bit system.  Instead of patching the sources on demand in a build
     ;; phase we download either the 32-bit archive (which mostly uses "int"
     ;; types) or the 64-bit archive (which mostly uses "long" types).
     (let ((hash32 "0jmx1h65wqxsyjzs64i2z6ryiynllxzm13cq90fky2qrzagcw1ir")
           (hash64 "0wnd01xssdq9pgx5xqh5lfiy3dmk60dzzqdxzdzf883h13692lgy")
           (file32 "x86")
           (file64 "x86_64"))
       (let-values (((hash file)
                     (match (or (%current-target-system) (%current-system))
                       ("x86_64-linux" (values hash64 file64))
                       (_              (values hash32 file32)))))
         (origin
           (method url-fetch)
           (uri (string-append
                 "http://ftp-stud.fht-esslingen.de/pub/Mirrors/"
                 "eclipse/eclipse/downloads/drops4/R-" version
                 "-201606061100/swt-" version "-gtk-linux-" file ".zip"))
           (sha256 (base32 hash))))))
    (build-system ant-build-system)
    (arguments
     `(#:jar-name "swt.jar"
       #:tests? #f ; no "check" target
       #:phases
       (modify-phases %standard-phases
         (replace 'unpack
           (lambda* (#:key source #:allow-other-keys)
             (and (mkdir "swt")
                  (zero? (system* "unzip" source "-d" "swt"))
                  (chdir "swt")
                  (mkdir "src")
                  (zero? (system* "unzip" "src.zip" "-d" "src")))))
         ;; The classpath contains invalid icecat jars.  Since we don't need
         ;; anything other than the JDK on the classpath, we can simply unset
         ;; it.
         (add-after 'configure 'unset-classpath
           (lambda _ (unsetenv "CLASSPATH") #t))
         (add-before 'build 'build-native
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let ((lib (string-append (assoc-ref outputs "out") "/lib")))
               ;; Build shared libraries.  Users of SWT have to set the system
               ;; property swt.library.path to the "lib" directory of this
               ;; package output.
               (mkdir-p lib)
               (setenv "OUTPUT_DIR" lib)
               (with-directory-excursion "src"
                 (zero? (system* "bash" "build.sh"))))))
         (add-after 'install 'install-native
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((lib (string-append (assoc-ref outputs "out") "/lib")))
               (for-each (lambda (file)
                           (install-file file lib))
                         (find-files "." "\\.so$"))
               #t))))))
    (inputs
     `(("xulrunner" ,icecat)
       ("gtk" ,gtk+-2)
       ("libxtst" ,libxtst)
       ("libxt" ,libxt)
       ("mesa" ,mesa)
       ("glu" ,glu)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("unzip" ,unzip)))
    (home-page "https://www.eclipse.org/swt/")
    (synopsis "Widget toolkit for Java")
    (description
     "SWT is a widget toolkit for Java designed to provide efficient, portable
access to the user-interface facilities of the operating systems on which it
is implemented.")
    ;; SWT code is licensed under EPL1.0
    ;; Gnome and Gtk+ bindings contain code licensed under LGPLv2.1
    ;; Cairo bindings contain code under MPL1.1
    ;; XULRunner 1.9 bindings contain code under MPL2.0
    (license (list
              license:epl1.0
              license:mpl1.1
              license:mpl2.0
              license:lgpl2.1+))))

(define-public clojure
  (let* ((remove-archives '(begin
                             (for-each delete-file
                                       (find-files "." ".*\\.(jar|zip)"))
                             #t))
         (submodule (lambda (prefix version hash)
                      (origin
                        (method url-fetch)
                        (uri (string-append "https://github.com/clojure/"
                                            prefix version ".tar.gz"))
                        (sha256 (base32 hash))
                        (modules '((guix build utils)))
                        (snippet remove-archives)))))
    (package
      (name "clojure")
      (version "1.8.0")
      (source
       (origin
         (method url-fetch)
         (uri
          (string-append "http://repo1.maven.org/maven2/org/clojure/clojure/"
                         version "/clojure-" version ".zip"))
         (sha256
          (base32 "1nip095fz5c492sw15skril60i1vd21ibg6szin4jcvyy3xr6cym"))
         (modules '((guix build utils)))
         (snippet remove-archives)))
      (build-system ant-build-system)
      (arguments
       `(#:modules ((guix build ant-build-system)
                    (guix build utils)
                    (ice-9 ftw)
                    (ice-9 regex)
                    (srfi srfi-1)
                    (srfi srfi-26))
         #:test-target "test"
         #:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'unpack-submodule-sources
             (lambda* (#:key inputs #:allow-other-keys)
               (for-each
                (lambda (name)
                  (mkdir-p name)
                  (with-directory-excursion name
                    (or (zero? (system* "tar"
                                        ;; Use xz for repacked tarball.
                                        "--xz"
                                        "--extract"
                                        "--verbose"
                                        "--file" (assoc-ref inputs name)
                                        "--strip-components=1"))
                        (error "failed to unpack tarball" name)))
                  (copy-recursively (string-append name "/src/main/clojure/")
                                    "src/clj/"))
                '("data-generators-src"
                  "java-classpath-src"
                  "test-check-src"
                  "test-generative-src"
                  "tools-namespace-src"
                  "tools-reader-src"))
               #t))
           ;; The javadoc target is not built by default.
           (add-after 'build 'build-doc
             (lambda _
               (zero? (system* "ant" "javadoc"))))
           ;; Needed since no install target is provided.
           (replace 'install
             (lambda* (#:key outputs #:allow-other-keys)
               (let ((java-dir (string-append (assoc-ref outputs "out")
                                              "/share/java/")))
                 ;; Install versioned to avoid collisions.
                 (install-file (string-append "clojure-" ,version ".jar")
                               java-dir)
                 #t)))
           ;; Needed since no install-doc target is provided.
           (add-after 'install 'install-doc
             (lambda* (#:key outputs #:allow-other-keys)
               (let ((doc-dir (string-append (assoc-ref outputs "out")
                                             "/share/doc/clojure-"
                                             ,version "/")))
                 (copy-recursively "doc/clojure" doc-dir)
                 (copy-recursively "target/javadoc/"
                                   (string-append doc-dir "javadoc/"))
                 (for-each (cut install-file <> doc-dir)
                           (filter (cut string-match
                                     ".*\\.(html|markdown|md|txt)"
                                     <>)
                                   (scandir "./")))
                 #t))))))
      ;; The native-inputs below are needed to run the tests.
      (native-inputs
       `(("data-generators-src"
          ,(submodule "data.generators/archive/data.generators-"
                      "0.1.2"
                      "0kki093jp4ckwxzfnw8ylflrfqs8b1i1wi9iapmwcsy328dmgzp1"))
         ("java-classpath-src"
          ,(submodule "java.classpath/archive/java.classpath-"
                      "0.2.3"
                      "0sjymly9xh1lkvwn5ygygpsfwz4dabblnlq0c9bx76rkvq62fyng"))
         ("test-check-src"
          ,(submodule "test.check/archive/test.check-"
                      "0.9.0"
                      "0p0mnyhr442bzkz0s4k5ra3i6l5lc7kp6ajaqkkyh4c2k5yck1md"))
         ("test-generative-src"
          ,(submodule "test.generative/archive/test.generative-"
                      "0.5.2"
                      "1pjafy1i7yblc7ixmcpfq1lfbyf3jaljvkgrajn70sws9xs7a9f8"))
         ("tools-namespace-src"
          ,(submodule "tools.namespace/archive/tools.namespace-"
                      "0.2.11"
                      "10baak8v0hnwz2hr33bavshm7y49mmn9zsyyms1dwjz45p5ymhy0"))
         ("tools-reader-src"
          ,(submodule "tools.reader/archive/tools.reader-"
                      "0.10.0"
                      "09i3lzbhr608h76mhdjm3932gg9xi8sflscla3c5f0v1nkc28cnr"))))
      (home-page "https://clojure.org/")
      (synopsis "Lisp dialect running on the JVM")
      (description "Clojure is a dynamic, general-purpose programming language,
combining the approachability and interactive development of a scripting
language with an efficient and robust infrastructure for multithreaded
programming.  Clojure is a compiled language, yet remains completely dynamic
– every feature supported by Clojure is supported at runtime.  Clojure
provides easy access to the Java frameworks, with optional type hints and type
inference, to ensure that calls to Java can avoid reflection.

Clojure is a dialect of Lisp, and shares with Lisp the code-as-data philosophy
and a powerful macro system.  Clojure is predominantly a functional programming
language, and features a rich set of immutable, persistent data structures.
When mutable state is needed, Clojure offers a software transactional memory
system and reactive Agent system that ensure clean, correct, multithreaded
designs.")
      ;; Clojure is licensed under EPL1.0
      ;; ASM bytecode manipulation library is licensed under BSD-3
      ;; Guava Murmur3 hash implementation is licensed under APL2.0
      ;; src/clj/repl.clj is licensed under CPL1.0
      ;;
      ;; See readme.html or readme.txt for details.
      (license (list license:epl1.0
                     license:bsd-3
                     license:asl2.0
                     license:cpl1.0)))))

(define-public ant
  (package
    (name "ant")
    (version "1.9.6")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://apache/ant/source/apache-ant-"
                                  version "-src.tar.gz"))
              (sha256
               (base32
                "1396wflczyxjxl603dhxjvd559f289lha9y2f04f71c7hapjl3am"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; no "check" target
       #:phases
       (alist-cons-after
        'unpack 'remove-scripts
        ;; Remove bat / cmd scripts for DOS as well as the antRun and runant
        ;; wrappers.
        (lambda _
          (for-each delete-file
                    (find-files "src/script"
                                "(.*\\.(bat|cmd)|runant.*|antRun.*)")))
        (alist-replace
         'build
         (lambda _
           (setenv "JAVA_HOME" (string-append (assoc-ref %build-inputs "gcj")
                                              "/lib/jvm"))
           ;; Disable tests to avoid dependency on hamcrest-core, which needs
           ;; Ant to build.  This is necessary in addition to disabling the
           ;; "check" phase, because the dependency on "test-jar" would always
           ;; result in the tests to be run.
           (substitute* "build.xml"
             (("depends=\"jars,test-jar\"") "depends=\"jars\""))
           (zero? (system* "bash" "bootstrap.sh"
                           (string-append "-Ddist.dir="
                                          (assoc-ref %outputs "out")))))
         (alist-delete
          'configure
          (alist-delete 'install %standard-phases))))))
    (native-inputs
     `(("gcj" ,gcj)))
    (home-page "http://ant.apache.org")
    (synopsis "Build tool for Java")
    (description
     "Ant is a platform-independent build tool for Java.  It is similar to
make but is implemented using the Java language, requires the Java platform,
and is best suited to building Java projects.  Ant uses XML to describe the
build process and its dependencies, whereas Make uses Makefile format.")
    (license license:asl2.0)))

(define-public icedtea-6
  (package
    (name "icedtea")
    (version "1.13.12")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://icedtea.wildebeest.org/download/source/icedtea6-"
                    version ".tar.xz"))
              (sha256
               (base32
                "1q5iqm3dzqj8w3dwj6qqhczkkrslrfhmn3110klfwq9kyi2nimj8"))
              (modules '((guix build utils)))
              (snippet
               '(substitute* "Makefile.in"
                  ;; link against libgcj to avoid linker error
                  (("-o native-ecj")
                   "-lgcj -o native-ecj")
                  ;; do not leak information about the build host
                  (("DISTRIBUTION_ID=\"\\$\\(DIST_ID\\)\"")
                   "DISTRIBUTION_ID=\"\\\"guix\\\"\"")))))
    (build-system gnu-build-system)
    (outputs '("out"   ; Java Runtime Environment
               "jdk"   ; Java Development Kit
               "doc")) ; all documentation
    (arguments
     `(;; There are many failing tests and many are known to fail upstream.
       ;;
       ;; * Hotspot VM tests:
       ;;   FAILED: compiler/7082949/Test7082949.java
       ;;   FAILED: compiler/7088020/Test7088020.java
       ;;   FAILED: runtime/6929067/Test6929067.sh
       ;;   FAILED: serviceability/sa/jmap-hashcode/Test8028623.java
       ;;   => Test results: passed: 161; failed: 4
       ;;
       ;; * langtools tests:
       ;;   FAILED: com/sun/javadoc/testHtmlDefinitionListTag/TestHtmlDefinitionListTag.java
       ;;   FAILED: tools/javac/6627362/T6627362.java
       ;;   FAILED: tools/javac/7003595/T7003595.java
       ;;   FAILED: tools/javac/7024568/T7024568.java
       ;;   FAILED: tools/javap/4111861/T4111861.java
       ;;   FAILED: tools/javap/ListTest.java
       ;;   FAILED: tools/javap/OptionTest.java
       ;;   FAILED: tools/javap/T4884240.java
       ;;   FAILED: tools/javap/T4975569.java
       ;;     --> fails because of insignificant whitespace differences
       ;;         in output of javap
       ;;   FAILED: tools/javap/T6868539.java
       ;;   => Test results: passed: 1,445; failed: 10
       ;;
       ;; * JDK tests:
       ;;   Tests are incomplete because of a segfault after this test:
       ;;     javax/crypto/spec/RC5ParameterSpec/RC5ParameterSpecEquals.java
       ;;   A bug report has already been filed upstream:
       ;;     http://icedtea.classpath.org/bugzilla/show_bug.cgi?id=2188
       ;;
       ;;   The tests require xvfb-run, a wrapper script around Xvfb, which
       ;;   has not been packaged yet.  Without it many AWT tests fail, so I
       ;;   made no attempts to make a list of failing JDK tests.  At least
       ;;   222 tests are failing of which at least 132 are AWT tests.
       #:tests? #f

       ;; The DSOs use $ORIGIN to refer to each other, but (guix build
       ;; gremlin) doesn't support it yet, so skip this phase.
       #:validate-runpath? #f

       #:modules ((guix build utils)
                  (guix build gnu-build-system)
                  (ice-9 popen)
                  (ice-9 rdelim)
                  (srfi srfi-19))

       #:configure-flags
       (let* ((gcjdir (assoc-ref %build-inputs "gcj"))
              (ecj    (string-append gcjdir "/share/java/ecj.jar"))
              (jdk    (string-append gcjdir "/lib/jvm/"))
              (gcj    (string-append gcjdir "/bin/gcj")))
         `("--enable-bootstrap"
           "--enable-nss"
           "--without-rhino"
           "--disable-downloading"
           "--disable-tests" ;they are run in the check phase instead
           "--with-openjdk-src-dir=./openjdk.src"
           ,(string-append "--with-javac=" jdk "/bin/javac")
           ,(string-append "--with-ecj-jar=" ecj)
           ,(string-append "--with-gcj=" gcj)
           ,(string-append "--with-jdk-home=" jdk)
           ,(string-append "--with-java=" jdk "/bin/java")))
       #:phases
       (modify-phases %standard-phases
         (replace 'unpack
           (lambda* (#:key source inputs #:allow-other-keys)
             (and (zero? (system* "tar" "xvf" source))
                  (begin
                    (chdir (string-append "icedtea6-" ,version))
                    (mkdir "openjdk.src")
                    (with-directory-excursion "openjdk.src"
                      (copy-file (assoc-ref inputs "openjdk6-src")
                                 "openjdk6-src.tar.xz")
                      (zero? (system* "tar" "xvf" "openjdk6-src.tar.xz")))))))
         (add-after 'unpack 'patch-patches
           (lambda _
             ;; shebang in patches so that they apply cleanly
             (substitute* '("patches/jtreg-jrunscript.patch"
                            "patches/hotspot/hs23/drop_unlicensed_test.patch")
               (("#!/bin/sh") (string-append "#!" (which "sh"))))
             #t))
         (add-after 'unpack 'patch-paths
           (lambda _
             ;; buildtree.make generates shell scripts, so we need to replace
             ;; the generated shebang
             (substitute* '("openjdk.src/hotspot/make/linux/makefiles/buildtree.make")
               (("/bin/sh") (which "bash")))

             (let ((corebin (string-append
                             (assoc-ref %build-inputs "coreutils") "/bin/"))
                   (binbin  (string-append
                             (assoc-ref %build-inputs "binutils") "/bin/"))
                   (grepbin (string-append
                             (assoc-ref %build-inputs "grep") "/bin/")))
               (substitute* '("openjdk.src/jdk/make/common/shared/Defs-linux.gmk"
                              "openjdk.src/corba/make/common/shared/Defs-linux.gmk")
                 (("UNIXCOMMAND_PATH  = /bin/")
                  (string-append "UNIXCOMMAND_PATH = " corebin))
                 (("USRBIN_PATH  = /usr/bin/")
                  (string-append "USRBIN_PATH = " corebin))
                 (("DEVTOOLS_PATH *= */usr/bin/")
                  (string-append "DEVTOOLS_PATH = " corebin))
                 (("COMPILER_PATH *= */usr/bin/")
                  (string-append "COMPILER_PATH = "
                                 (assoc-ref %build-inputs "gcc") "/bin/"))
                 (("DEF_OBJCOPY *=.*objcopy")
                  (string-append "DEF_OBJCOPY = " (which "objcopy"))))

               ;; fix path to alsa header
               (substitute* "openjdk.src/jdk/make/common/shared/Sanity.gmk"
                 (("ALSA_INCLUDE=/usr/include/alsa/version.h")
                  (string-append "ALSA_INCLUDE="
                                 (assoc-ref %build-inputs "alsa-lib")
                                 "/include/alsa/version.h")))

               ;; fix hard-coded utility paths
               (substitute* '("openjdk.src/jdk/make/common/shared/Defs-utils.gmk"
                              "openjdk.src/corba/make/common/shared/Defs-utils.gmk")
                 (("ECHO *=.*echo")
                  (string-append "ECHO = " (which "echo")))
                 (("^GREP *=.*grep")
                  (string-append "GREP = " (which "grep")))
                 (("EGREP *=.*egrep")
                  (string-append "EGREP = " (which "egrep")))
                 (("CPIO *=.*cpio")
                  (string-append "CPIO = " (which "cpio")))
                 (("READELF *=.*readelf")
                  (string-append "READELF = " (which "readelf")))
                 (("^ *AR *=.*ar")
                  (string-append "AR = " (which "ar")))
                 (("^ *TAR *=.*tar")
                  (string-append "TAR = " (which "tar")))
                 (("AS *=.*as")
                  (string-append "AS = " (which "as")))
                 (("LD *=.*ld")
                  (string-append "LD = " (which "ld")))
                 (("STRIP *=.*strip")
                  (string-append "STRIP = " (which "strip")))
                 (("NM *=.*nm")
                  (string-append "NM = " (which "nm")))
                 (("^SH *=.*sh")
                  (string-append "SH = " (which "bash")))
                 (("^FIND *=.*find")
                  (string-append "FIND = " (which "find")))
                 (("LDD *=.*ldd")
                  (string-append "LDD = " (which "ldd")))
                 (("NAWK *=.*(n|g)awk")
                  (string-append "NAWK = " (which "gawk")))
                 (("XARGS *=.*xargs")
                  (string-append "XARGS = " (which "xargs")))
                 (("UNZIP *=.*unzip")
                  (string-append "UNZIP = " (which "unzip")))
                 (("ZIPEXE *=.*zip")
                  (string-append "ZIPEXE = " (which "zip")))
                 (("SED *=.*sed")
                  (string-append "SED = " (which "sed"))))

               ;; Some of these timestamps cause problems as they are more than
               ;; 10 years ago, failing the build process.
               (substitute*
                   "openjdk.src/jdk/src/share/classes/java/util/CurrencyData.properties"
                 (("AZ=AZM;2005-12-31-20-00-00;AZN") "AZ=AZN")
                 (("MZ=MZM;2006-06-30-22-00-00;MZN") "MZ=MZN")
                 (("RO=ROL;2005-06-30-21-00-00;RON") "RO=RON")
                 (("TR=TRL;2004-12-31-22-00-00;TRY") "TR=TRY")))))
         (add-before 'configure 'set-additional-paths
           (lambda* (#:key inputs #:allow-other-keys)
             (let* ((gcjdir  (assoc-ref %build-inputs "gcj"))
                    (gcjlib  (string-append gcjdir "/lib"))
                    ;; Get target-specific include directory so that
                    ;; libgcj-config.h is found when compiling hotspot.
                    (gcjinclude (let* ((port (open-input-pipe "gcj -print-file-name=include"))
                                       (str  (read-line port)))
                                  (close-pipe port)
                                  str)))
               (setenv "CPATH"
                       (string-append gcjinclude ":"
                                      (assoc-ref %build-inputs "libxrender")
                                      "/include/X11/extensions" ":"
                                      (assoc-ref %build-inputs "libxtst")
                                      "/include/X11/extensions" ":"
                                      (assoc-ref %build-inputs "libxinerama")
                                      "/include/X11/extensions" ":"
                                      (or (getenv "CPATH") "")))
               (setenv "ALT_CUPS_HEADERS_PATH"
                       (string-append (assoc-ref %build-inputs "cups")
                                      "/include"))
               (setenv "ALT_FREETYPE_HEADERS_PATH"
                       (string-append (assoc-ref %build-inputs "freetype")
                                      "/include"))
               (setenv "ALT_FREETYPE_LIB_PATH"
                       (string-append (assoc-ref %build-inputs "freetype")
                                      "/lib")))))
         (add-before 'check 'fix-test-framework
           (lambda _
             ;; Fix PATH in test environment
             (substitute* "src/jtreg/com/sun/javatest/regtest/Main.java"
               (("PATH=/bin:/usr/bin")
                (string-append "PATH=" (getenv "PATH"))))
             (substitute* "src/jtreg/com/sun/javatest/util/SysEnv.java"
               (("/usr/bin/env") (which "env")))
             #t))
         (add-before 'check 'fix-hotspot-tests
           (lambda _
             (with-directory-excursion "openjdk.src/hotspot/test/"
               (substitute* "jprt.config"
                 (("PATH=\"\\$\\{path4sdk\\}\"")
                  (string-append "PATH=" (getenv "PATH")))
                 (("make=/usr/bin/make")
                  (string-append "make=" (which "make"))))
               (substitute* '("runtime/6626217/Test6626217.sh"
                              "runtime/7110720/Test7110720.sh")
                 (("/bin/rm") (which "rm"))
                 (("/bin/cp") (which "cp"))
                 (("/bin/mv") (which "mv"))))
             #t))
         (add-before 'check 'fix-jdk-tests
           (lambda _
             (with-directory-excursion "openjdk.src/jdk/test/"
               (substitute* "com/sun/jdi/JdbReadTwiceTest.sh"
                 (("/bin/pwd") (which "pwd")))
               (substitute* "com/sun/jdi/ShellScaffold.sh"
                 (("/bin/kill") (which "kill")))
               (substitute* "start-Xvfb.sh"
                 ;;(("/usr/bin/X11/Xvfb") (which "Xvfb"))
                 (("/usr/bin/nohup")    (which "nohup")))
               (substitute* "javax/security/auth/Subject/doAs/Test.sh"
                 (("/bin/rm") (which "rm")))
               (substitute* "tools/launcher/MultipleJRE.sh"
                 (("echo \"#!/bin/sh\"")
                  (string-append "echo \"#!" (which "rm") "\""))
                 (("/usr/bin/zip") (which "zip")))
               (substitute* "com/sun/jdi/OnThrowTest.java"
                 (("#!/bin/sh") (string-append "#!" (which "sh"))))
               (substitute* "java/lang/management/OperatingSystemMXBean/GetSystemLoadAverage.java"
                 (("/usr/bin/uptime") (which "uptime")))
               (substitute* "java/lang/ProcessBuilder/Basic.java"
                 (("/usr/bin/env") (which "env"))
                 (("/bin/false") (which "false"))
                 (("/bin/true") (which "true"))
                 (("/bin/cp") (which "cp"))
                 (("/bin/sh") (which "sh")))
               (substitute* "java/lang/ProcessBuilder/FeelingLucky.java"
                 (("/bin/sh") (which "sh")))
               (substitute* "java/lang/ProcessBuilder/Zombies.java"
                 (("/usr/bin/perl") (which "perl"))
                 (("/bin/ps") (which "ps"))
                 (("/bin/true") (which "true")))
               (substitute* "java/lang/Runtime/exec/ConcurrentRead.java"
                 (("/usr/bin/tee") (which "tee")))
               (substitute* "java/lang/Runtime/exec/ExecWithDir.java"
                 (("/bin/true") (which "true")))
               (substitute* "java/lang/Runtime/exec/ExecWithInput.java"
                 (("/bin/cat") (which "cat")))
               (substitute* "java/lang/Runtime/exec/ExitValue.java"
                 (("/bin/sh") (which "sh"))
                 (("/bin/true") (which "true"))
                 (("/bin/kill") (which "kill")))
               (substitute* "java/lang/Runtime/exec/LotsOfDestroys.java"
                 (("/usr/bin/echo") (which "echo")))
               (substitute* "java/lang/Runtime/exec/LotsOfOutput.java"
                 (("/usr/bin/cat") (which "cat")))
               (substitute* "java/lang/Runtime/exec/SleepyCat.java"
                 (("/bin/cat") (which "cat"))
                 (("/bin/sleep") (which "sleep"))
                 (("/bin/sh") (which "sh")))
               (substitute* "java/lang/Runtime/exec/StreamsSurviveDestroy.java"
                 (("/bin/cat") (which "cat")))
               (substitute* "java/rmi/activation/CommandEnvironment/SetChildEnv.java"
                 (("/bin/chmod") (which "chmod")))
               (substitute* "java/util/zip/ZipFile/Assortment.java"
                 (("/bin/sh") (which "sh"))))
             #t))
         (replace 'check
           (lambda _
             ;; The "make check-*" targets always return zero, so we need to
             ;; check for errors in the associated log files to determine
             ;; whether any tests have failed.
             (use-modules (ice-9 rdelim))
             (let* ((error-pattern (make-regexp "^(Error|FAILED):.*"))
                    (checker (lambda (port)
                               (let loop ()
                                 (let ((line (read-line port)))
                                   (cond
                                    ((eof-object? line) #t)
                                    ((regexp-exec error-pattern line) #f)
                                    (else (loop)))))))
                    (run-test (lambda (test)
                                (system* "make" test)
                                (call-with-input-file
                                    (string-append "test/" test ".log")
                                  checker))))
               (or #t ; skip tests
                   (and (run-test "check-hotspot")
                        (run-test "check-langtools")
                        (run-test "check-jdk"))))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((doc (string-append (assoc-ref outputs "doc")
                                       "/share/doc/icedtea"))
                   (jre (assoc-ref outputs "out"))
                   (jdk (assoc-ref outputs "jdk")))
               (copy-recursively "openjdk.build/docs" doc)
               (copy-recursively "openjdk.build/j2re-image" jre)
               (copy-recursively "openjdk.build/j2sdk-image" jdk))))
         ;; By default IcedTea only generates an empty keystore.  In order to
         ;; be able to use certificates in Java programs we need to generate a
         ;; keystore from a set of certificates.  For convenience we use the
         ;; certificates from the nss-certs package.
         (add-after 'install 'install-keystore
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((keystore  "cacerts")
                    (certs-dir (string-append (assoc-ref inputs "nss-certs")
                                              "/etc/ssl/certs"))
                    (keytool   (string-append (assoc-ref outputs "jdk")
                                              "/bin/keytool")))
               (define (extract-cert file target)
                 (call-with-input-file file
                   (lambda (in)
                     (call-with-output-file target
                       (lambda (out)
                         (let loop ((line (read-line in 'concat))
                                    (copying? #f))
                           (cond
                            ((eof-object? line) #t)
                            ((string-prefix? "-----BEGIN" line)
                             (display line out)
                             (loop (read-line in 'concat) #t))
                            ((string-prefix? "-----END" line)
                             (display line out)
                             #t)
                            (else
                             (when copying? (display line out))
                             (loop (read-line in 'concat) copying?)))))))))
               (define (import-cert cert)
                 (format #t "Importing certificate ~a\n" (basename cert))
                 (let ((temp "tmpcert"))
                   (extract-cert cert temp)
                   (let ((port (open-pipe* OPEN_WRITE keytool
                                           "-import"
                                           "-alias" (basename cert)
                                           "-keystore" keystore
                                           "-storepass" "changeit"
                                           "-file" temp)))
                     (display "yes\n" port)
                     (when (not (zero? (status:exit-val (close-pipe port))))
                       (error "failed to import" cert)))
                   (delete-file temp)))

               ;; This is necessary because the certificate directory contains
               ;; files with non-ASCII characters in their names.
               (setlocale LC_ALL "en_US.utf8")
               (setenv "LC_ALL" "en_US.utf8")

               (for-each import-cert (find-files certs-dir "\\.pem$"))
               (mkdir-p (string-append (assoc-ref outputs "out")
                                       "/lib/security"))
               (mkdir-p (string-append (assoc-ref outputs "jdk")
                                       "/jre/lib/security"))
               (install-file keystore
                             (string-append (assoc-ref outputs "out")
                                            "/lib/security"))
               (install-file keystore
                             (string-append (assoc-ref outputs "jdk")
                                            "/jre/lib/security"))
               #t))))))
    (native-inputs
     `(("ant" ,ant)
       ("alsa-lib" ,alsa-lib)
       ("attr" ,attr)
       ("autoconf" ,autoconf)
       ("automake" ,automake)
       ("coreutils" ,coreutils)
       ("diffutils" ,diffutils) ;for tests
       ("gawk" ,gawk)
       ("grep" ,grep)
       ("libtool" ,libtool)
       ("pkg-config" ,pkg-config)
       ("cups" ,cups)
       ("wget" ,wget)
       ("which" ,which)
       ("cpio" ,cpio)
       ("zip" ,zip)
       ("unzip" ,unzip)
       ("fastjar" ,fastjar)
       ("libxslt" ,libxslt) ;for xsltproc
       ("mit-krb5" ,mit-krb5)
       ("nss" ,nss)
       ("nss-certs" ,nss-certs)
       ("libx11" ,libx11)
       ("libxcomposite" ,libxcomposite)
       ("libxt" ,libxt)
       ("libxtst" ,libxtst)
       ("libxi" ,libxi)
       ("libxinerama" ,libxinerama)
       ("libxrender" ,libxrender)
       ("libjpeg" ,libjpeg)
       ("libpng" ,libpng)
       ("giflib" ,giflib)
       ("perl" ,perl)
       ("procps" ,procps) ;for "free", even though I'm not sure we should use it
       ("openjdk6-src"
        ,(origin
           (method url-fetch)
           (uri "https://java.net/downloads/openjdk6/openjdk-6-src-b40-22_aug_2016.tar.gz")
           (sha256
            (base32
             "01v4q7g9pa6w7m6yxply5yrin08jgv12fck665xnmp09bpxy8sa5"))))
       ("lcms" ,lcms)
       ("zlib" ,zlib)
       ("gtk" ,gtk+-2)
       ("fontconfig" ,fontconfig)
       ("freetype" ,freetype)
       ("gcj" ,gcj)))
    (home-page "http://icedtea.classpath.org")
    (synopsis "Java development kit")
    (description
     "The OpenJDK built with the IcedTea build harness.")
    ;; IcedTea is released under the GPL2 + Classpath exception, which is the
    ;; same license as both GNU Classpath and OpenJDK.
    (license license:gpl2+)))

(define-public icedtea-7
  (let* ((version "2.6.8")
         (drop (lambda (name hash)
                 (origin
                   (method url-fetch)
                   (uri (string-append
                         "http://icedtea.classpath.org/download/drops/"
                         "/icedtea7/" version "/" name ".tar.bz2"))
                   (sha256 (base32 hash))))))
    (package (inherit icedtea-6)
      (version version)
      (source (origin
                (method url-fetch)
                (uri (string-append
                      "http://icedtea.wildebeest.org/download/source/icedtea-"
                      version ".tar.xz"))
                (sha256
                 (base32
                  "0p95402viz6dnfkhhn18hrvm7wqfvij0xnxvp9nqj3aq3gzk0h45"))
                (modules '((guix build utils)))
                (snippet
                 '(substitute* "Makefile.in"
                    ;; link against libgcj to avoid linker error
                    (("-o native-ecj")
                     "-lgcj -o native-ecj")
                    ;; do not leak information about the build host
                    (("DISTRIBUTION_ID=\"\\$\\(DIST_ID\\)\"")
                     "DISTRIBUTION_ID=\"\\\"guix\\\"\"")))))
      (arguments
       `(;; There are many test failures.  Some are known to
         ;; fail upstream, others relate to not having an X
         ;; server running at test time, yet others are a
         ;; complete mystery to me.

         ;; hotspot:   passed: 241; failed: 45; error: 2
         ;; langtools: passed: 1,934; failed: 26
         ;; jdk:       unknown
         #:tests? #f
         ;; Apparently, the C locale is needed for some of the tests.
         #:locale "C"
         ,@(substitute-keyword-arguments (package-arguments icedtea-6)
             ((#:modules modules)
              `((ice-9 match)
                (srfi srfi-26)
                ,@modules))
             ((#:configure-flags flags)
              ;; TODO: package pcsc and sctp, and add to inputs
              `(append '("--disable-system-pcsc"
                         "--disable-system-sctp")
                       ,flags))
             ((#:phases phases)
              `(modify-phases ,phases
                 (replace 'unpack
                   (lambda* (#:key source inputs #:allow-other-keys)
                     (let ((target (string-append "icedtea-" ,version))
                           (unpack (lambda* (name #:optional dir)
                                     (let ((dir (or dir
                                                    (string-drop-right name 5))))
                                       (mkdir dir)
                                       (zero? (system* "tar" "xvf"
                                                       (assoc-ref inputs name)
                                                       "-C" dir
                                                       "--strip-components=1"))))))
                       (mkdir target)
                       (and
                        (zero? (system* "tar" "xvf" source
                                        "-C" target "--strip-components=1"))
                        (chdir target)
                        (unpack "openjdk-src" "openjdk.src")
                        (with-directory-excursion "openjdk.src"
                          (for-each unpack
                                    (filter (cut string-suffix? "-drop" <>)
                                            (map (match-lambda
                                                   ((name . _) name))
                                                 inputs))))
                        #t))))
                 (replace
                  'set-additional-paths
                  (lambda* (#:key inputs #:allow-other-keys)
                    (let (;; Get target-specific include directory so that
                          ;; libgcj-config.h is found when compiling hotspot.
                          (gcjinclude (let* ((port (open-input-pipe "gcj -print-file-name=include"))
                                             (str  (read-line port)))
                                        (close-pipe port)
                                        str)))
                      (substitute* "openjdk.src/jdk/make/common/shared/Sanity.gmk"
                        (("ALSA_INCLUDE=/usr/include/alsa/version.h")
                         (string-append "ALSA_INCLUDE="
                                        (assoc-ref inputs "alsa-lib")
                                        "/include/alsa/version.h")))
                      (setenv "CC" "gcc")
                      (setenv "CPATH"
                              (string-append gcjinclude ":"
                                             (assoc-ref inputs "libxcomposite")
                                             "/include/X11/extensions" ":"
                                             (assoc-ref inputs "libxrender")
                                             "/include/X11/extensions" ":"
                                             (assoc-ref inputs "libxtst")
                                             "/include/X11/extensions" ":"
                                             (assoc-ref inputs "libxinerama")
                                             "/include/X11/extensions" ":"
                                             (or (getenv "CPATH") "")))
                      (setenv "ALT_OBJCOPY" (which "objcopy"))
                      (setenv "ALT_CUPS_HEADERS_PATH"
                              (string-append (assoc-ref inputs "cups")
                                             "/include"))
                      (setenv "ALT_FREETYPE_HEADERS_PATH"
                              (string-append (assoc-ref inputs "freetype")
                                             "/include"))
                      (setenv "ALT_FREETYPE_LIB_PATH"
                              (string-append (assoc-ref inputs "freetype")
                                             "/lib")))))
                 (add-after
                  'unpack 'fix-x11-extension-include-path
                  (lambda* (#:key inputs #:allow-other-keys)
                    (substitute* "openjdk.src/jdk/make/sun/awt/mawt.gmk"
                      (((string-append "\\$\\(firstword \\$\\(wildcard "
                                       "\\$\\(OPENWIN_HOME\\)"
                                       "/include/X11/extensions\\).*$"))
                       (string-append (assoc-ref inputs "libxrender")
                                      "/include/X11/extensions"
                                      " -I" (assoc-ref inputs "libxtst")
                                      "/include/X11/extensions"
                                      " -I" (assoc-ref inputs "libxinerama")
                                      "/include/X11/extensions"))
                      (("\\$\\(wildcard /usr/include/X11/extensions\\)\\)") ""))
                    #t))
                 (replace
                  'fix-test-framework
                  (lambda _
                    ;; Fix PATH in test environment
                    (substitute* "test/jtreg/com/sun/javatest/regtest/Main.java"
                      (("PATH=/bin:/usr/bin")
                       (string-append "PATH=" (getenv "PATH"))))
                    (substitute* "test/jtreg/com/sun/javatest/util/SysEnv.java"
                      (("/usr/bin/env") (which "env")))
                    (substitute* "openjdk.src/hotspot/test/test_env.sh"
                      (("/bin/rm") (which "rm"))
                      (("/bin/cp") (which "cp"))
                      (("/bin/mv") (which "mv")))
                    #t))
                 (delete 'patch-patches))))))
      (native-inputs
       `(("openjdk-src"
          ,(drop "openjdk"
                 "1qscircx5z9rnyx4k6lzxbrl5q6f9shag962zl0f52cyrcma5gp6"))
         ("corba-drop"
          ,(drop "corba"
                 "0f25l1db5v9ib4v5wb32wjblb2zzx8f8qgr2g84yg26aq2m8swig"))
         ("jaxp-drop"
          ,(drop "jaxp"
                 "1z4i404i3rrf5zmch8z2rslqm7vs1wzjhvjf6kgkdvnrka7a86xs"))
         ("jaxws-drop"
          ,(drop "jaxws"
                 "06h49jgf76408j1qhhkksly8fbyw1wisyvgi1csvj2f63bkr6c3m"))
         ("jdk-drop"
          ,(drop "jdk"
                 "0qg76gjlnyrjskzz019fi47vqdxpa51sdhcyx4lsa25j5vsih4gc"))
         ("langtools-drop"
          ,(drop "langtools"
                 "04w82l34z83n8cd901bvmlrdk825nw5ijgny5cn1idnhplzcckh0"))
         ("hotspot-drop"
          ,(drop "hotspot"
                 "153i1panv3mzwh39dc8rxr9hj5920y86a4m8djxsk6qnyd4gamfa"))
         ,@(fold alist-delete (package-native-inputs icedtea-6)
                 '("openjdk6-src"))))
      (inputs
       `(("libxcomposite" ,libxcomposite)
         ,@(package-inputs icedtea-6))))))

(define-public icedtea-8
  (let* ((version "3.2.0")
         (drop (lambda (name hash)
                 (origin
                   (method url-fetch)
                   (uri (string-append
                         "http://icedtea.classpath.org/download/drops/"
                         "/icedtea8/" version "/" name ".tar.xz"))
                   (sha256 (base32 hash))))))
    (package (inherit icedtea-7)
      (version "3.2.0")
      (source (origin
                (method url-fetch)
                (uri (string-append
                      "http://icedtea.wildebeest.org/download/source/icedtea-"
                      version ".tar.xz"))
                (sha256
                 (base32
                  "104g2x5nhnqqvx6x29phx5vlrhlqy7qax83b9bqj1y619irrg8gj"))
                (modules '((guix build utils)))
                (snippet
                 '(substitute* "Makefile.am"
                    ;; do not leak information about the build host
                    (("DISTRIBUTION_ID=\"\\$\\(DIST_ID\\)\"")
                     "DISTRIBUTION_ID=\"\\\"guix\\\"\"")))))
      (arguments
       (substitute-keyword-arguments (package-arguments icedtea-7)
         ((#:configure-flags flags)
          `(let ((jdk (assoc-ref %build-inputs "jdk")))
             `(;;"--disable-bootstrap"
               "--enable-bootstrap"
               "--enable-nss"
               "--disable-downloading"
               "--disable-system-pcsc"
               "--disable-system-sctp"
               "--disable-tests"      ;they are run in the check phase instead
               "--with-openjdk-src-dir=./openjdk.src"
               ,(string-append "--with-jdk-home=" jdk))))
         ((#:phases phases)
          `(modify-phases ,phases
             (delete 'fix-x11-extension-include-path)
             (delete 'patch-paths)
             (delete 'set-additional-paths)
             (delete 'patch-patches)
             (add-after 'unpack 'patch-jni-libs
               ;; Hardcode dynamically loaded libraries.
               (lambda _
                 (let* ((library-path (search-path-as-string->list
                                       (getenv "LIBRARY_PATH")))
                        (find-library (lambda (name)
                                        (search-path
                                         library-path
                                         (string-append "lib" name ".so")))))
                   (for-each
                    (lambda (file)
                      (catch 'encoding-error
                        (lambda ()
                          (substitute* file
                            (("VERSIONED_JNI_LIB_NAME\\(\"(.*)\", \"(.*)\"\\)"
                              _ name version)
                             (format #f "\"~a\""  (find-library name)))
                            (("JNI_LIB_NAME\\(\"(.*)\"\\)" _ name)
                             (format #f "\"~a\"" (find-library name)))))
                        (lambda _
                          ;; Those are safe to skip.
                          (format (current-error-port)
                                  "warning: failed to substitute: ~a~%"
                                  file))))
                    (find-files "openjdk.src/jdk/src/solaris/native"
                                "\\.c|\\.h"))
                   #t)))
             ;; FIXME: This phase is needed but fails with this version of
             ;; IcedTea.
             (delete 'install-keystore)
             (replace 'install
               (lambda* (#:key outputs #:allow-other-keys)
                 (let ((doc (string-append (assoc-ref outputs "doc")
                                           "/share/doc/icedtea"))
                       (jre (assoc-ref outputs "out"))
                       (jdk (assoc-ref outputs "jdk")))
                   (copy-recursively "openjdk.build/docs" doc)
                   (copy-recursively "openjdk.build/images/j2re-image" jre)
                   (copy-recursively "openjdk.build/images/j2sdk-image" jdk)
                   #t)))))))
      (native-inputs
       `(("jdk" ,icedtea-7 "jdk")
         ("openjdk-src"
          ,(drop "openjdk"
                 "093r3vlmbdx78w9s6d8lv4q65i0s9wq6an6i2g2d1zaf0js4043c"))
         ("corba-drop"
          ,(drop "corba"
                 "11r3h9snnj7m5bqnzc5ryd85igdv7xlwzs0zy24p9ii6gsc0f9lh"))
         ("jaxp-drop"
          ,(drop "jaxp"
                 "1mp6ps15jk8v4nnvkmbvkk7g35icdjv7892q2a4f7b268yjcgmk1"))
         ("jaxws-drop"
          ,(drop "jaxws"
                 "1fb5hikzzx8292nhdbp0snqn66fwnnv4rkjsk1zsjvrv4z5vk18j"))
         ("jdk-drop"
          ,(drop "jdk"
                 "1if9c5grp0km7pyn4mhfwi2ynh3ix20l1fqbfcy68sl2py7psmcj"))
         ("langtools-drop"
          ,(drop "langtools"
                 "0kbah4h4pllk0gf50mp5f6720f5ci0ixqylccppb484hp95pblcl"))
         ("hotspot-drop"
          ,(drop "hotspot"
                 "1gqz9qqsi61838dj08s01sa51zlnkvrk3hy721211dhnmkvlzmwx"))
         ("nashorn-drop"
          ,(drop "nashorn"
                 "04697l95g6y6n5dvy55k2040c6qp5hfz16qaibwzs594m3gzwwjz"))
         ("shenandoah-drop"
          ,(drop "shenandoah"
                 "0k6h7jk5i98jnld2ivy4bhydmkzrp25c3l6gwhvczvrhn7mlbnfx"))
         ,@(fold alist-delete (package-native-inputs icedtea-7)
                 '("gcj" "openjdk-src" "corba-drop" "jaxp-drop" "jaxws-drop"
                   "jdk-drop" "langtools-drop" "hotspot-drop")))))))

(define-public icedtea icedtea-7)

(define-public java-xz
  (package
   (name "java-xz")
   (version "1.5")
   (source (origin
     (method url-fetch)
     (uri (string-append "http://tukaani.org/xz/xz-java-" version ".zip"))
     (sha256
      (base32
       "0x6vn9dp9kxk83x2fp3394n95dk8fx9yg8jns9371iqsn0vy8ih1"))))
   (build-system ant-build-system)
   (arguments
    `(#:tests? #f ; There are no tests to run.
      #:jar-name ,(string-append "xz-" version  ".jar")
      #:phases
      (modify-phases %standard-phases
        ;; The unpack phase enters the "maven" directory by accident.
        (add-after 'unpack 'chdir
          (lambda _ (chdir "..") #t)))))
   (native-inputs
    `(("unzip" ,unzip)))
   (home-page "http://tukaani.org/xz/java.html")
   (synopsis "Implementation of XZ data compression in pure Java")
   (description "This library aims to be a complete implementation of XZ data
compression in pure Java.  Single-threaded streamed compression and
decompression and random access decompression have been fully implemented.")
   (license license:public-domain)))

;; java-hamcrest-core uses qdox version 1.12.  We package this version instead
;; of the latest release.
(define-public java-qdox-1.12
  (package
    (name "java-qdox")
    (version "1.12.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://central.maven.org/maven2/"
                                  "com/thoughtworks/qdox/qdox/" version
                                  "/qdox-" version "-sources.jar"))
              (sha256
               (base32
                "0hlfbqq2avf5s26wxkksqmkdyk6zp9ggqn37c468m96mjv0n9xfl"))))
    (build-system ant-build-system)
    (arguments
     `(;; Tests require junit
       #:tests? #f
       #:jar-name "qdox.jar"
       #:phases
       (modify-phases %standard-phases
         (replace 'unpack
           (lambda* (#:key source #:allow-other-keys)
             (mkdir "src")
             (with-directory-excursion "src"
               (zero? (system* "jar" "-xf" source)))))
         ;; At this point we don't have junit, so we must remove the API
         ;; tests.
         (add-after 'unpack 'delete-tests
           (lambda _
             (delete-file-recursively "src/com/thoughtworks/qdox/junit")
             #t)))))
    (home-page "http://qdox.codehaus.org/")
    (synopsis "Parse definitions from Java source files")
    (description
     "QDox is a high speed, small footprint parser for extracting
class/interface/method definitions from source files complete with JavaDoc
@code{@@tags}.  It is designed to be used by active code generators or
documentation tools.")
    (license license:asl2.0)))

(define-public java-jarjar
  (package
    (name "java-jarjar")
    (version "1.4")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://storage.googleapis.com/google-code-archive-downloads/v2/"
                    "code.google.com/jarjar/jarjar-src-" version ".zip"))
              (sha256
               (base32
                "1v8irhni9cndcw1l1wxqgry013s2kpj0qqn57lj2ji28xjq8ndjl"))))
    (build-system ant-build-system)
    (arguments
     `(;; Tests require junit, which ultimately depends on this package.
       #:tests? #f
       #:build-target "jar"
       #:phases
       (modify-phases %standard-phases
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((target (string-append (assoc-ref outputs "out")
                                          "/share/java")))
               (install-file (string-append "dist/jarjar-" ,version ".jar")
                             target))
             #t)))))
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page "https://code.google.com/archive/p/jarjar/")
    (synopsis "Repackage Java libraries")
    (description
     "Jar Jar Links is a utility that makes it easy to repackage Java
libraries and embed them into your own distribution.  Jar Jar Links includes
an Ant task that extends the built-in @code{jar} task.")
    (license license:asl2.0)))

(define-public java-hamcrest-core
  (package
    (name "java-hamcrest-core")
    (version "1.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/hamcrest/JavaHamcrest/"
                                  "archive/hamcrest-java-" version ".tar.gz"))
              (sha256
               (base32
                "11g0s105fmwzijbv08lx8jlb521yravjmxnpgdx08fvg1kjivhva"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  ;; Delete bundled thirds-party jar archives.
                  (delete-file-recursively "lib")
                  #t))))
    (build-system ant-build-system)
    (arguments
     `(#:tests? #f ; Tests require junit
       #:make-flags (list (string-append "-Dversion=" ,version))
       #:build-target "core"
       #:phases
       (modify-phases %standard-phases
         ;; Disable unit tests, because they require junit, which requires
         ;; hamcrest-core.  We also give a fixed value to the "Built-Date"
         ;; attribute from the manifest for reproducibility.
         (add-before 'configure 'patch-build.xml
           (lambda _
             (substitute* "build.xml"
               (("unit-test, ") "")
               (("\\$\\{build.timestamp\\}") "guix"))
             #t))
         ;; Java's "getMethods()" returns methods in an unpredictable order.
         ;; To make the output of the generated code deterministic we must
         ;; sort the array of methods.
         (add-after 'unpack 'make-method-order-deterministic
           (lambda _
             (substitute* "hamcrest-generator/src/main/java/org/hamcrest/generator/ReflectiveFactoryReader.java"
               (("import java\\.util\\.Iterator;" line)
                (string-append line "\n"
                               "import java.util.Arrays; import java.util.Comparator;"))
               (("allMethods = cls\\.getMethods\\(\\);" line)
                (string-append "_" line
                               "
private Method[] getSortedMethods() {
  Arrays.sort(_allMethods, new Comparator<Method>() {
    @Override
    public int compare(Method a, Method b) {
      return a.toString().compareTo(b.toString());
    }
  });
  return _allMethods;
}

private Method[] allMethods = getSortedMethods();")))))
         (add-before 'build 'do-not-use-bundled-qdox
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "build.xml"
               (("lib/generator/qdox-1.12.jar")
                (string-append (assoc-ref inputs "java-qdox-1.12")
                               "/share/java/qdox.jar")))
             #t))
         ;; build.xml searches for .jar files in this directoy, which
         ;; we remove  from the source archive.
         (add-before 'build 'create-dummy-directories
           (lambda _
             (mkdir-p "lib/integration")
             #t))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (install-file (string-append "build/hamcrest-core-"
                                          ,version ".jar")
                           (string-append (assoc-ref outputs "out")
                                          "/share/java")))))))
    (native-inputs
     `(("java-qdox-1.12" ,java-qdox-1.12)
       ("java-jarjar" ,java-jarjar)))
    (home-page "http://hamcrest.org/")
    (synopsis "Library of matchers for building test expressions")
    (description
     "This package provides a library of matcher objects (also known as
constraints or predicates) allowing @code{match} rules to be defined
declaratively, to be used in other frameworks.  Typical scenarios include
testing frameworks, mocking libraries and UI validation rules.")
    (license license:bsd-2)))

(define-public java-junit
  (package
    (name "java-junit")
    (version "4.12")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/junit-team/junit/"
                                  "archive/r" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "090dn5v1vs0b3acyaqc0gjf6p8lmd2h24wfzsbq7sly6b214anws"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  ;; Delete bundled jar archives.
                  (delete-file-recursively "lib")
                  #t))))
    (build-system ant-build-system)
    (arguments
     `(#:tests? #f ; no tests
       #:jar-name "junit.jar"))
    (inputs
     `(("java-hamcrest-core" ,java-hamcrest-core)))
    (home-page "http://junit.org/")
    (synopsis "Test framework for Java")
    (description
     "JUnit is a simple framework to write repeatable tests for Java projects.
JUnit provides assertions for testing expected results, test fixtures for
sharing common test data, and test runners for running tests.")
    (license license:epl1.0)))
