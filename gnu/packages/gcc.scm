;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014, 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015 Andreas Enge <andreas@enge.fr>
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

(define-module (gnu packages gcc)
  #:use-module ((guix licenses)
                #:select (gpl3+ gpl2+ lgpl2.1+ lgpl2.0+ fdl1.3+))
  #:use-module (gnu packages)
  #:use-module (gnu packages bootstrap)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages dejagnu)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages docbook)
  #:use-module (gnu packages graphviz)
  #:use-module (gnu packages elf)
  #:use-module (gnu packages perl)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (guix utils)
  #:use-module (srfi srfi-1)
  #:use-module (ice-9 regex))

(define %gcc-infrastructure
  ;; Base URL for GCC's infrastructure.
  "mirror://gcc/infrastructure/")

(define (gcc-configure-flags-for-triplet target)
  "Return a list of additional GCC `configure' flags for TARGET, a GNU triplet.

The purpose of this procedure is to translate extended GNU triplets---e.g.,
where the OS part is overloaded to denote a specific ABI---into GCC
`configure' options.  We take extended GNU triplets that glibc recognizes."
  (cond ((string-match "^mips64el.*gnuabin?64$" target)
         ;; Triplets recognized by glibc as denoting the N64 ABI; see
         ;; ports/sysdeps/mips/preconfigure.
         '("--with-abi=64"))

        ((string-match "^arm.*-gnueabihf$" target)
         '("--with-arch=armv7-a"
           "--with-float=hard"
           "--with-mode=thumb"
           "--with-fpu=neon"))

        (else
         ;; TODO: Add `arm.*-gnueabi', etc.
         '())))

(define-public gcc-4.7
  (let* ((stripped? #t)      ;whether to strip the compiler, not the libraries
         (maybe-target-tools
          (lambda ()
            ;; Return the `_FOR_TARGET' variables that are needed when
            ;; cross-compiling GCC.
            (let ((target (%current-target-system)))
              (if target
                  (map (lambda (var tool)
                         (string-append (string-append var "_FOR_TARGET")
                                        "=" target "-" tool))
                       '("CC"  "CXX" "LD" "AR" "NM" "RANLIB" "STRIP")
                       '("gcc" "g++" "ld" "ar" "nm" "ranlib" "strip"))
                  '()))))
         (libdir
          (let ((base '(or (assoc-ref outputs "lib")
                           (assoc-ref outputs "out"))))
            (lambda ()
              ;; Return the directory that contains lib/libgcc_s.so et al.
              (if (%current-target-system)
                  `(string-append ,base "/" ,(%current-target-system))
                  base))))
         (configure-flags
          (lambda ()
            ;; This is terrible.  Since we have two levels of quasiquotation,
            ;; we have to do this convoluted thing just so we can insert the
            ;; contents of (maybe-target-tools).
            (list 'quasiquote
                  (append
                   '("--enable-plugin"
                     "--enable-languages=c,c++"
                     "--disable-multilib"
                     "--with-system-zlib"

                     ;; No pre-compiled libstdc++ headers, to save space.
                     "--disable-libstdcxx-pch"

                     "--with-local-prefix=/no-gcc-local-prefix"

                     ;; With a separate "lib" output, the build system
                     ;; incorrectly guesses GPLUSPLUS_INCLUDE_DIR, so force
                     ;; it.  (Don't use a versioned sub-directory, that's
                     ;; unnecessary.)
                     ,(string-append "--with-gxx-include-dir="
                                     (assoc-ref %outputs "out")
                                     "/include/c++")

                     ,(let ((libc (assoc-ref %build-inputs "libc")))
                        (if libc
                            (string-append "--with-native-system-header-dir=" libc
                                           "/include")
                            "--without-headers")))

                   ;; Pass the right options for the target triplet.
                   (let ((triplet
                          (or (%current-target-system)
                              (nix-system->gnu-triplet (%current-system)))))
                     (gcc-configure-flags-for-triplet triplet))

                   (maybe-target-tools))))))
    (package
      (name "gcc")
      (version "4.7.4")
      (source (origin
               (method url-fetch)
               (uri (string-append "mirror://gnu/gcc/gcc-"
                                   version "/gcc-" version ".tar.bz2"))
               (sha256
                (base32
                 "10k2k71kxgay283ylbbhhs51cl55zn2q38vj5pk4k950qdnirrlj"))))
      (build-system gnu-build-system)

      ;; Separate out the run-time support libraries because all the
      ;; dynamic-linked objects depend on it.
      (outputs '("out"                    ;commands, etc. (60+ MiB)
                 "lib"                    ;libgcc_s, libgomp, etc. (15+ MiB)
                 "debug"))                ;debug symbols of run-time libraries

      (inputs `(("gmp" ,gmp)
                ("mpfr" ,mpfr)
                ("mpc" ,mpc)
                ("isl" ,isl)
                ("cloog" ,cloog)
                ("libelf" ,libelf)
                ("zlib" ,zlib)))

      ;; GCC < 5 is one of the few packages that doesn't ship .info files.
      ;; Newer texinfos fail to build the manual, so we use an older one.
      (native-inputs `(("texinfo" ,texinfo-5)))

      (arguments
       `(#:out-of-source? #t
         #:configure-flags ,(configure-flags)
         #:make-flags
         ;; None of the flags below are needed when doing a Canadian cross.
         ;; TODO: Simplify this.
         ,(if (%current-target-system)
              (if stripped?
                  ''("CFLAGS=-g0 -O2")
                  ''())
              `(let* ((libc        (assoc-ref %build-inputs "libc"))
                      (libc-native (or (assoc-ref %build-inputs "libc-native")
                                       libc)))
                 `(,@(if libc
                         (list (string-append "LDFLAGS_FOR_TARGET="
                                              "-B" libc "/lib "
                                              "-Wl,-dynamic-linker "
                                              "-Wl," libc
                                              ,(glibc-dynamic-linker)))
                         '())

                   ;; Native programs like 'genhooks' also need that right.
                   ,(string-append "LDFLAGS="
                                   "-Wl,-rpath=" libc-native "/lib "
                                   "-Wl,-dynamic-linker "
                                   "-Wl," libc-native ,(glibc-dynamic-linker))
                   ,(string-append "BOOT_CFLAGS=-O2 "
                                   ,(if stripped? "-g0" "-g")))))

         #:tests? #f

         #:phases
         (alist-cons-before
          'configure 'pre-configure
          (lambda* (#:key inputs outputs #:allow-other-keys)
            (let ((libdir ,(libdir))
                  (libc   (assoc-ref inputs "libc")))
              (when libc
                ;; The following is not performed for `--without-headers'
                ;; cross-compiler builds.

                ;; Join multi-line definitions of GLIBC_DYNAMIC_LINKER* into a
                ;; single line, to allow the next step to work properly.
                (for-each
                 (lambda (x)
                   (substitute* (find-files "gcc/config"
                                            "^linux(64|-elf|-eabi)?\\.h$")
                     (("(#define GLIBC_DYNAMIC_LINKER.*)\\\\\n$" _ line)
                      line)))
                 '(1 2 3))

                ;; Fix the dynamic linker's file name.
                (substitute* (find-files "gcc/config"
                                         "^(linux|gnu)(64|-elf|-eabi)?\\.h$")
                  (("#define GLIBC_DYNAMIC_LINKER([^ ]*).*$" _ suffix)
                   (format #f "#define GLIBC_DYNAMIC_LINKER~a \"~a\"~%"
                           suffix
                           (string-append libc ,(glibc-dynamic-linker)))))

                ;; Tell where to find libstdc++, libc, and `?crt*.o', except
                ;; `crt{begin,end}.o', which come with GCC.
                (substitute* (find-files "gcc/config"
                                         "^gnu-user.*\\.h$")
                  (("#define GNU_USER_TARGET_LIB_SPEC (.*)$" _ suffix)
                   ;; Help libgcc_s.so be found (see also below.)  Always use
                   ;; '-lgcc_s' so that libgcc_s.so is always found by those
                   ;; programs that use 'pthread_cancel' (glibc dlopens
                   ;; libgcc_s.so when pthread_cancel support is needed, but
                   ;; having it in the application's RUNPATH isn't enough; see
                   ;; <http://sourceware.org/ml/libc-help/2013-11/msg00023.html>.)
                   ;;
                   ;; NOTE: The '-lgcc_s' added below needs to be removed in a
                   ;; later phase of %gcc-static.  If you change the string
                   ;; below, make sure to update the relevant code in
                   ;; %gcc-static package as needed.
                   (format #f "#define GNU_USER_TARGET_LIB_SPEC \
\"-L~a/lib %{!static:-rpath=~a/lib %{!static-libgcc:-rpath=~a/lib -lgcc_s}} \" ~a"
                           libc libc libdir suffix))
                  (("#define GNU_USER_TARGET_STARTFILE_SPEC.*$" line)
                   (format #f "#define STANDARD_STARTFILE_PREFIX_1 \"~a/lib\"
#define STANDARD_STARTFILE_PREFIX_2 \"\"
~a"
                           libc line))))

              ;; Don't retain a dependency on the build-time sed.
              (substitute* "fixincludes/fixincl.x"
                (("static char const sed_cmd_z\\[\\] =.*;")
                 "static char const sed_cmd_z[] = \"sed\";"))

              (when (file-exists? "libbacktrace")
                ;; GCC 4.8+ comes with libbacktrace.  By default it builds
                ;; with -Werror, which fails with a -Wcast-qual error in glibc
                ;; 2.21's stdlib-bsearch.h.  Remove -Werror.
                (substitute* "libbacktrace/configure"
                  (("WARN_FLAGS=(.*)-Werror" _ flags)
                   (string-append "WARN_FLAGS=" flags)))

                (when (file-exists? "libsanitizer/libbacktrace")
                  ;; Same in libsanitizer's bundled copy (!) found in 4.9+.
                  (substitute* "libsanitizer/libbacktrace/Makefile.in"
                    (("-Werror")
                     ""))))

              ;; Add a RUNPATH to libstdc++.so so that it finds libgcc_s.
              ;; See <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=32354>
              ;; and <http://bugs.gnu.org/20358>.
              (substitute* "libstdc++-v3/src/Makefile.in"
                (("^OPT_LDFLAGS = ")
                 "OPT_LDFLAGS = -Wl,-rpath=$(libdir) "))

              ;; Move libstdc++*-gdb.py to the "lib" output to avoid a
              ;; circularity between "out" and "lib".  (Note:
              ;; --with-python-dir is useless because it imposes $(prefix) as
              ;; the parent directory.)
              (substitute* "libstdc++-v3/python/Makefile.in"
                (("pythondir = .*$")
                 (string-append "pythondir = " libdir "/share"
                                "/gcc-$(gcc_version)/python\n")))

              ;; Avoid another circularity between the outputs: this #define
              ;; ends up in auto-host.h in the "lib" output, referring to
              ;; "out".  (This variable is used to augment cpp's search path,
              ;; but there's nothing useful to look for here.)
              (substitute* "gcc/config.in"
                (("PREFIX_INCLUDE_DIR")
                 "PREFIX_INCLUDE_DIR_isnt_necessary_here"))))

          (alist-cons-after
           'configure 'post-configure
           (lambda _
             ;; Don't store configure flags, to avoid retaining references to
             ;; build-time dependencies---e.g., `--with-ppl=/gnu/store/xxx'.
             (substitute* "Makefile"
               (("^TOPLEVEL_CONFIGURE_ARGUMENTS=(.*)$" _ rest)
                "TOPLEVEL_CONFIGURE_ARGUMENTS=\n")))
           %standard-phases))))

      (native-search-paths
       ;; Use the language-specific variables rather than 'CPATH' because they
       ;; are equivalent to '-isystem' whereas 'CPATH' is equivalent to '-I'.
       ;; The intent is to allow headers that are in the search path to be
       ;; treated as "system headers" (headers exempt from warnings) just like
       ;; the typical /usr/include headers on an FHS system.
       (list (search-path-specification
              (variable "C_INCLUDE_PATH")
              (files '("include")))
             (search-path-specification
              (variable "CPLUS_INCLUDE_PATH")
              (files '("include")))
             (search-path-specification
              (variable "LIBRARY_PATH")
              (files '("lib" "lib64")))))

      (properties `((gcc-libc . ,(assoc-ref inputs "libc"))))
      (synopsis "GNU Compiler Collection")
      (description
       "GCC is the GNU Compiler Collection.  It provides compiler front-ends
for several languages, including C, C++, Objective-C, Fortran, Java, Ada, and
Go.  It also includes runtime support libraries for these languages.")
      (license gpl3+)
      (home-page "http://gcc.gnu.org/"))))

(define-public gcc-4.8
  (package (inherit gcc-4.7)
    (version "4.8.5")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/gcc/gcc-"
                                  version "/gcc-" version ".tar.bz2"))
              (sha256
               (base32
                "08yggr18v373a1ihj0rg2vd6psnic42b518xcgp3r9k81xz1xyr2"))
              (patches (search-patches "gcc-arm-link-spec-fix.patch"))))))

(define-public gcc-4.9
  (package (inherit gcc-4.7)
    (version "4.9.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/gcc/gcc-"
                                  version "/gcc-" version ".tar.bz2"))
              (sha256
               (base32
                "14l06m7nvcvb0igkbip58x59w3nq6315k6jcz3wr9ch1rn9d44bc"))
              (patches (search-patches "gcc-arm-bug-71399.patch"
                                       "gcc-libvtv-runpath.patch"))))
    (native-inputs `(("texinfo" ,texinfo)))))

(define-public gcc-5
  ;; Note: GCC >= 5 ships with .info files but 'make install' fails to install
  ;; them in a VPATH build.
  (package (inherit gcc-4.9)
    (version "5.4.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/gcc/gcc-"
                                  version "/gcc-" version ".tar.bz2"))
              (sha256
               (base32
                "0fihlcy5hnksdxk0sn6bvgnyq8gfrgs8m794b1jxwd1dxinzg3b0"))
              (patches (search-patches "gcc-strmov-store-file-names.patch"
                                       "gcc-5.0-libvtv-runpath.patch"))))))

(define-public gcc-6
  (package
    (inherit gcc-5)
    (version "6.3.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/gcc/gcc-"
                                  version "/gcc-" version ".tar.bz2"))
              (sha256
               (base32
                "17xjz30jb65hcf714vn9gcxvrrji8j20xm7n33qg1ywhyzryfsph"))
              (patches (search-patches "gcc-strmov-store-file-names.patch"
                                       "gcc-5.0-libvtv-runpath.patch"))))))

;; Note: When changing the default gcc version, update
;;       the gcc-toolchain-* definitions accordingly.
(define-public gcc gcc-4.9)

(define-public (make-libstdc++ gcc)
  "Return a libstdc++ package based on GCC.  The primary use case is when
using compilers other than GCC."
  (package
    (inherit gcc)
    (name "libstdc++")
    (arguments
     `(#:out-of-source? #t
       #:phases (alist-cons-before
                 'configure 'chdir
                 (lambda _
                   (chdir "libstdc++-v3"))
                 %standard-phases)
       #:configure-flags `("--disable-libstdcxx-pch"
                           ,(string-append "--with-gxx-include-dir="
                                           (assoc-ref %outputs "out")
                                           "/include"))))
    (outputs '("out" "debug"))
    (inputs '())
    (native-inputs '())
    (propagated-inputs '())
    (synopsis "GNU C++ standard library")))

(define-public libstdc++-4.9
  (make-libstdc++ gcc-4.9))

(define (make-libiberty gcc)
  "Return a libiberty package based on GCC."
  (package
    (inherit gcc)
    (name "libiberty")
    (arguments
     `(#:out-of-source? #t
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'chdir
                     (lambda _
                       (chdir "libiberty")
                       #t))
         (replace
          'install
          (lambda* (#:key outputs #:allow-other-keys)
            (let* ((out     (assoc-ref outputs "out"))
                   (lib     (string-append out "/lib/"))
                   (include (string-append out "/include/")))
              (mkdir-p lib)
              (mkdir-p include)
              (copy-file "libiberty.a"
                         (string-append lib "libiberty.a"))
              (copy-file "../include/libiberty.h"
                         (string-append include "libiberty.h"))
              #t))))))
    (inputs '())
    (outputs '("out"))
    (native-inputs '())
    (propagated-inputs '())
    (synopsis "Collection of subroutines used by various GNU programs")))

(define-public libiberty
  (make-libiberty gcc))

(define* (custom-gcc gcc name languages
                     #:optional
                     (search-paths (package-native-search-paths gcc))
                     #:key (separate-lib-output? #t))
  "Return a custom version of GCC that supports LANGUAGES.  Use SEARCH-PATHS
as the 'native-search-paths' field."
  (package (inherit gcc)
    (name name)
    (outputs (if separate-lib-output?
                 (package-outputs gcc)
                 (delete "lib" (package-outputs gcc))))
    (native-search-paths search-paths)
    (arguments
     (substitute-keyword-arguments `(#:modules ((guix build gnu-build-system)
                                                (guix build utils)
                                                (ice-9 regex)
                                                (srfi srfi-1)
                                                (srfi srfi-26))
                                               ,@(package-arguments gcc))
       ((#:configure-flags flags)
        `(cons (string-append "--enable-languages="
                              ,(string-join languages ","))
               (remove (cut string-match "--enable-languages.*" <>)
                       ,flags)))
       ((#:phases phases)
        `(modify-phases ,phases
           (add-after 'install 'remove-broken-or-conflicting-files
             (lambda* (#:key outputs #:allow-other-keys)
               (for-each delete-file
                         (find-files (string-append (assoc-ref outputs "out") "/bin")
                                     ".*(c\\+\\+|cpp|g\\+\\+|gcov|gcc.*)"))
               #t))))))))

(define %generic-search-paths
  ;; This is the language-neutral search path for GCC.  Entries in $CPATH are
  ;; not considered "system headers", which means GCC can raise warnings for
  ;; issues in those headers.  'CPATH' is the only one that works for
  ;; front-ends not in the C family.
  (list (search-path-specification
         (variable "CPATH")
         (files '("include")))
        (search-path-specification
         (variable "LIBRARY_PATH")
         (files '("lib" "lib64")))))

(define-public gfortran-4.8
  (custom-gcc gcc-4.8 "gfortran" '("fortran")
              %generic-search-paths))

(define-public gfortran-4.9
  (custom-gcc gcc-4.9 "gfortran" '("fortran")
              %generic-search-paths))

(define-public gfortran
  (custom-gcc gcc "gfortran" '("fortran")
              %generic-search-paths))

(define-public gfortran-5
  (custom-gcc gcc-5 "gfortran" '("fortran")
              %generic-search-paths))

(define-public gccgo-4.9
  (custom-gcc gcc-4.9 "gccgo" '("go")
              %generic-search-paths
              ;; Suppress the separate "lib" output, because otherwise the
              ;; "lib" and "out" outputs would refer to each other, creating
              ;; a cyclic dependency.  <http://debbugs.gnu.org/18101>
              #:separate-lib-output? #f))

(define javac.in
  (origin
    (method url-fetch)
    (uri (string-append "http://sources.gentoo.org/cgi-bin/viewvc.cgi/"
                        "gentoo-x86/dev-java/gcj-jdk/files/javac.in?revision=1.1"))
    (file-name "javac.in")
    (sha256 (base32
              "1c3dk4z5yfj6ic2fn3lyxs27n6pmn2wy9k0r1s17lnkf1bzkrciv"))))

(define-public gcj
  (package (inherit gcc)
    (name "gcj")
    (version (package-version gcc))
    (inputs
     `(("fastjar" ,fastjar)
       ("perl" ,perl)
       ("javac.in" ,javac.in)
       ("ecj-bootstrap" ,ecj-bootstrap)
       ,@(package-inputs gcc)))
    (native-inputs
     `(("dejagnu" ,dejagnu)
       ,@(if (string-prefix? "armhf" (or (%current-system)
                                         (%current-target-system)))
             `(("arm-patch" ,(origin
                               (method url-fetch)
                               (uri (search-patch "gcj-arm-mode.patch"))
                               (sha256
                                (base32
                                 "1z15xs5yx6qinnb572swzxrn9f668sw7ga5280q3gznj1jyrynfn")))))
             '())
       ,@(package-native-inputs gcc)))
    (native-search-paths %generic-search-paths)

    ;; Suppress the separate "lib" output, because otherwise the
    ;; "lib" and "out" outputs would refer to each other, creating
    ;; a cyclic dependency.  <http://debbugs.gnu.org/18101>
    (outputs
     (delete "lib" (package-outputs gcc)))
    (arguments
     (substitute-keyword-arguments `(#:modules ((guix build gnu-build-system)
                                                (guix build utils)
                                                (ice-9 regex)
                                                (srfi srfi-1)
                                                (srfi srfi-26))
                                     #:test-target "check-target-libjava"
                                     ,@(package-arguments gcc))
       ((#:tests? _) #t)
       ((#:configure-flags flags)
        `(let ((ecj (assoc-ref %build-inputs "ecj-bootstrap")))
           `("--enable-java-home"
             "--enable-gjdoc"
             ,(string-append "--with-ecj-jar=" ecj)
             "--enable-languages=java"
             ,@(remove (cut string-match "--enable-languages.*" <>)
                       ,flags))))
       ((#:phases phases)
        `(modify-phases ,phases
           ;; Conditionally add phase to apply patch
           ,@(if (string-prefix? "armhf" (or (%current-system)
                                             (%current-target-system)))
                 `((add-after 'unpack 'apply-arm-patch
                     (lambda* (#:key inputs #:allow-other-keys)
                       (zero? (system* "patch" "-p1"
                                       "-i" (assoc-ref inputs "arm-patch"))))))
                 '())
           (add-after
            'unpack 'add-lib-output-to-rpath
            (lambda _
              (substitute* "libjava/Makefile.in"
                (("libgcj_bc_dummy_LINK = .* -shared" line)
                 (string-append line " -Wl,-rpath=$(libdir)"))
                (("libgcj(_bc)?_la_LDFLAGS =" ldflags _)
                 (string-append ldflags " -Wl,-rpath=$(libdir)")))))
           (add-after
            'unpack 'patch-testsuite
            ;; dejagnu-1.6 removes the 'absolute' command
            (lambda _
              ;; This test fails on armhf.  It seems harmless enough to disable it.
              (for-each delete-file '("libjava/testsuite/libjava.lang/Throw_2.java"
                                      "libjava/testsuite/libjava.lang/Throw_2.out"
                                      "libjava/testsuite/libjava.lang/Throw_2.jar"))
              (substitute* "libjava/testsuite/lib/libjava.exp"
                (("absolute") "file normalize"))
              #t))
           (add-after
            'install 'install-javac-and-javap-wrappers
            (lambda _
              (let* ((javac  (assoc-ref %build-inputs "javac.in"))
                     (ecj    (assoc-ref %build-inputs "ecj-bootstrap"))
                     (gcj    (assoc-ref %outputs "out"))
                     (gcjbin (string-append gcj "/bin/"))
                     (jvm    (string-append gcj "/lib/jvm/"))
                     (target (string-append jvm "/bin/javac")))

                (symlink (string-append gcjbin "jcf-dump")
                         (string-append jvm "/bin/javap"))

                (copy-file ecj (string-append gcj "/share/java/ecj.jar"))

                ;; Create javac wrapper from the template javac.in by
                ;; replacing the @VARIABLES@ with paths.
                (copy-file javac target)
                (patch-shebang target)
                (substitute* target
                  (("@JAVA@")
                   (string-append jvm "/bin/java"))
                  (("@ECJ_JAR@")
                   (string-append gcj "/share/java/ecj.jar"))
                  (("@RT_JAR@")
                   (string-append jvm "/jre/lib/rt.jar"))
                  (("@TOOLS_JAR@")
                   (string-append jvm "/lib/tools.jar")))
                (chmod target #o755)
                #t)))
           (add-after
            'install 'remove-broken-or-conflicting-files
            (lambda _
              (let ((out (assoc-ref %outputs "out")))
                (for-each
                 delete-file
                 (append (find-files (string-append out "/lib/jvm/jre/lib")
                                     "libjawt.so")
                         (find-files (string-append out "/bin")
                                     ".*(c\\+\\+|cpp|g\\+\\+|gcc.*)"))))
              #t))))))))

(define ecj-bootstrap
  (origin
    (method url-fetch)
    (uri "ftp://sourceware.org/pub/java/ecj-4.9.jar")
    (sha256
     (base32
      "1k9lgm3qamf6zy534pa2zwskr8mpiqrngbv1vw9j4y1ghrdyf1lm"))))

(define-public gcc-objc-4.8
  (custom-gcc gcc-4.8 "gcc-objc" '("objc")
              (list (search-path-specification
                     (variable "OBJC_INCLUDE_PATH")
                     (files '("include")))
                    (search-path-specification
                     (variable "LIBRARY_PATH")
                     (files '("lib" "lib64"))))))

(define-public gcc-objc-4.9
  (custom-gcc gcc-4.9 "gcc-objc" '("objc")
              (list (search-path-specification
                     (variable "OBJC_INCLUDE_PATH")
                     (files '("include")))
                    (search-path-specification
                     (variable "LIBRARY_PATH")
                     (files '("lib" "lib64"))))))

(define-public gcc-objc gcc-objc-4.9)

(define-public gcc-objc++-4.8
  (custom-gcc gcc-4.8 "gcc-objc++" '("obj-c++")
              (list (search-path-specification
                     (variable "OBJCPLUS_INCLUDE_PATH")
                     (files '("include")))
                    (search-path-specification
                     (variable "LIBRARY_PATH")
                     (files '("lib" "lib64"))))))

(define-public gcc-objc++-4.9
  (custom-gcc gcc-4.9 "gcc-objc++" '("obj-c++")
              (list (search-path-specification
                     (variable "OBJCPLUS_INCLUDE_PATH")
                     (files '("include")))
                    (search-path-specification
                     (variable "LIBRARY_PATH")
                     (files '("lib" "lib64"))))))

(define-public gcc-objc++ gcc-objc++-4.9)

(define (make-libstdc++-doc gcc)
  "Return a package with the libstdc++ documentation for GCC."
  (package
    (inherit gcc)
    (name "libstdc++-doc")
    (version (package-version gcc))
    (synopsis "GNU libstdc++ documentation")
    (outputs '("out"))
    (native-inputs `(("doxygen" ,doxygen)
                     ("texinfo" ,texinfo)
                     ("libxml2" ,libxml2)
                     ("libxslt" ,libxslt)
                     ("docbook-xml" ,docbook-xml)
                     ("docbook-xsl" ,docbook-xsl)
                     ("graphviz" ,graphviz))) ;for 'dot', invoked by 'doxygen'
    (inputs '())
    (propagated-inputs '())
    (arguments
     '(#:out-of-source? #t
       #:tests? #f                                ;it's just documentation
       #:phases (modify-phases %standard-phases
                  (add-before 'configure 'chdir
                              (lambda _
                                (chdir "libstdc++-v3")))
                  (add-before 'configure 'set-xsl-directory
                              (lambda* (#:key inputs #:allow-other-keys)
                                (let ((docbook (assoc-ref inputs "docbook-xsl")))
                                  (substitute* (find-files "doc"
                                                           "^Makefile\\.in$")
                                    (("@XSL_STYLE_DIR@")
                                     (string-append
                                      docbook "/xml/xsl/"
                                      (strip-store-file-name docbook)))))))
                  (replace 'build
                           (lambda _
                             ;; XXX: There's also a 'doc-info' target, but it
                             ;; relies on docbook2X, which itself relies on
                             ;; DocBook 4.1.2, which is not really usable
                             ;; (lacks a catalog.xml.)
                             (zero? (system* "make"
                                             "doc-html"
                                             "doc-man"))))
                  (replace 'install
                           (lambda* (#:key outputs #:allow-other-keys)
                             (let ((out (assoc-ref outputs "out")))
                               (zero? (system* "make"
                                               "doc-install-html"
                                               "doc-install-man"))))))))))

(define-public libstdc++-doc-4.9
  (make-libstdc++-doc gcc-4.9))

(define-public libstdc++-doc-5
  (make-libstdc++-doc gcc-5))

(define-public isl
  (package
    (name "isl")
    (version "0.11.1")
    (source (origin
             (method url-fetch)
             (uri (list (string-append
                         "http://isl.gforge.inria.fr/isl-"
                         version
                         ".tar.bz2")
                        (string-append %gcc-infrastructure
                                       name "-" version ".tar.gz")))
             (sha256
              (base32
               "13d9cqa5rzhbjq0xf0b2dyxag7pqa72xj9dhsa03m8ccr1a4npq9"))
             (patches (search-patches "isl-0.11.1-aarch64-support.patch"))))
    (build-system gnu-build-system)
    (inputs `(("gmp" ,gmp)))
    (home-page "http://isl.gforge.inria.fr/")
    (synopsis
     "Manipulating sets and relations of integer points \
bounded by linear constraints")
    (description
     "isl is a library for manipulating sets and relations of integer points
bounded by linear constraints.  Supported operations on sets include
intersection, union, set difference, emptiness check, convex hull, (integer)
affine hull, integer projection, computing the lexicographic minimum using
parametric integer programming, coalescing and parametric vertex
enumeration.  It also includes an ILP solver based on generalized basis
reduction, transitive closures on maps (which may encode infinite graphs),
dependence analysis and bounds on piecewise step-polynomials.")
    (license lgpl2.1+)))

(define-public cloog
  (package
    (name "cloog")
    (version "0.18.0")
    (source
     (origin
      (method url-fetch)
      (uri (list (string-append
                  "http://www.bastoul.net/cloog/pages/download/count.php3?url=cloog-"
                  version
                  ".tar.gz")
                 (string-append %gcc-infrastructure
                                name "-" version ".tar.gz")))
      (sha256
       (base32
        "0a12rwfwp22zd0nlld0xyql11cj390rrq1prw35yjsw8wzfshjhw"))
      (file-name (string-append name "-" version ".tar.gz"))))
    (build-system gnu-build-system)
    (inputs `(("gmp" ,gmp)
              ("isl" ,isl)))
    (arguments '(#:configure-flags '("--with-isl=system")))
    (home-page "http://www.cloog.org/")
    (synopsis "Library to generate code for scanning Z-polyhedra")
    (description
     "CLooG is a free software library to generate code for scanning
Z-polyhedra.  That is, it finds a code (e.g., in C, FORTRAN...) that
reaches each integral point of one or more parameterized polyhedra.
CLooG has been originally written to solve the code generation problem
for optimizing compilers based on the polytope model.  Nevertheless it
is used now in various area e.g., to build control automata for
high-level synthesis or to find the best polynomial approximation of a
function.  CLooG may help in any situation where scanning polyhedra
matters.  While the user has full control on generated code quality,
CLooG is designed to avoid control overhead and to produce a very
effective code.")
    (license gpl2+)))

(define-public gnu-c-manual
  (package
    (name "gnu-c-manual")
    (version "0.2.5")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/gnu-c-manual/gnu-c-manual-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1sfsj9256w18qzylgag2h5h377aq8in8929svblfnj9svfriqcys"))))
    (build-system gnu-build-system)
    (native-inputs `(("texinfo" ,texinfo)))
    (arguments
     '(#:phases (modify-phases %standard-phases
                  (delete 'configure)
                  (delete 'check)
                  (replace 'build
                           (lambda _
                             (zero? (system* "make"
                                             "gnu-c-manual.info"
                                             "gnu-c-manual.html"))))
                  (replace 'install
                           (lambda* (#:key outputs #:allow-other-keys)
                             (let* ((out (assoc-ref outputs "out"))
                                    (info (string-append out "/share/info"))
                                    (html (string-append
                                           out "/share/doc/gnu-c-manual")))
                               (mkdir-p info)
                               (mkdir-p html)

                               (for-each (lambda (file)
                                           (copy-file file
                                                      (string-append info "/"
                                                                     file)))
                                         (find-files "." "\\.info(-[0-9])?$"))
                               (for-each (lambda (file)
                                           (copy-file file
                                                      (string-append html "/"
                                                                     file)))
                                         (find-files "." "\\.html$"))
                               #t))))))
    (synopsis "Reference manual for the C programming language")
    (description
     "This is a reference manual for the C programming language, as
implemented by the GNU C Compiler (gcc).  As a reference, it is not intended
to be a tutorial of the language.  Rather, it outlines all of the constructs
of the language.  Library functions are not included.")
    (home-page "http://www.gnu.org/software/gnu-c-manual")
    (license fdl1.3+)))
