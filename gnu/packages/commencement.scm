;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2012 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2014, 2015 Mark H Weaver <mhw@netris.org>
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

(define-module (gnu packages commencement)
  #:use-module ((guix licenses)
                #:select (gpl3+ lgpl2.0+ public-domain))
  #:use-module (gnu packages bootstrap)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages m4)
  #:use-module (gnu packages file)
  #:use-module (gnu packages gawk)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages pkg-config)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (guix utils)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 vlist)
  #:use-module (ice-9 match))

;;; Commentary:
;;;
;;; This is the commencement, this is where things start.  Before the
;;; commencement, of course, there's the 'bootstrap' module, which provides us
;;; with the initial binaries.  This module uses those bootstrap binaries to
;;; actually build up the whole tool chain that make up the implicit inputs of
;;; 'gnu-build-system'.
;;;
;;; To avoid circular dependencies, this module should not be imported
;;; directly from anywhere.
;;;
;;; Code:

(define gnu-make-boot0
  (package-with-bootstrap-guile
   (package (inherit gnu-make)
     (name "make-boot0")
     (arguments
      `(#:guile ,%bootstrap-guile
        #:implicit-inputs? #f
        #:tests? #f                  ; cannot run "make check"
        ,@(substitute-keyword-arguments (package-arguments gnu-make)
            ((#:phases phases)
             `(alist-replace
               'build (lambda _
                        (zero? (system* "./build.sh")))
               (alist-replace
                'install (lambda* (#:key outputs #:allow-other-keys)
                           (let* ((out (assoc-ref outputs "out"))
                                  (bin (string-append out "/bin")))
                             (mkdir-p bin)
                             (copy-file "make"
                                        (string-append bin "/make"))))
                ,phases))))))
     (native-inputs '())                          ; no need for 'pkg-config'
     (inputs %bootstrap-inputs))))

(define diffutils-boot0
  (package-with-bootstrap-guile
   (let ((p (package-with-explicit-inputs diffutils
                                          `(("make" ,gnu-make-boot0)
                                            ,@%bootstrap-inputs)
                                          #:guile %bootstrap-guile)))
     (package (inherit p)
       (name "diffutils-boot0")
       (arguments `(#:tests? #f         ; the test suite needs diffutils
                    ,@(package-arguments p)))))))

(define findutils-boot0
  (package-with-bootstrap-guile
   (package-with-explicit-inputs (package
                                   (inherit findutils)
                                   (name "findutils-boot0"))
                                 `(("make" ,gnu-make-boot0)
                                   ("diffutils" ,diffutils-boot0) ; for tests
                                   ,@%bootstrap-inputs)
                                 (current-source-location)
                                 #:guile %bootstrap-guile)))

(define file-boot0
  (package-with-bootstrap-guile
   (package-with-explicit-inputs (package
                                   (inherit file)
                                   (name "file-boot0"))
                                 `(("make" ,gnu-make-boot0)
                                   ,@%bootstrap-inputs)
                                 (current-source-location)
                                 #:guile %bootstrap-guile)))


(define %boot0-inputs
  `(("make" ,gnu-make-boot0)
    ("diffutils" ,diffutils-boot0)
    ("findutils" ,findutils-boot0)
    ("file" ,file-boot0)
    ,@%bootstrap-inputs))

(define* (boot-triplet #:optional (system (%current-system)))
  ;; Return the triplet used to create the cross toolchain needed in the
  ;; first bootstrapping stage.
  (nix-system->gnu-triplet system "guix"))

;; Following Linux From Scratch, build a cross-toolchain in stage 0.  That
;; toolchain actually targets the same OS and arch, but it has the advantage
;; of being independent of the libc and tools in %BOOTSTRAP-INPUTS, since
;; GCC-BOOT0 (below) is built without any reference to the target libc.

(define binutils-boot0
  (package-with-bootstrap-guile
   (package (inherit binutils)
     (name "binutils-cross-boot0")
     (arguments
      `(#:guile ,%bootstrap-guile
        #:implicit-inputs? #f

        #:modules ((guix build gnu-build-system)
                   (guix build utils)
                   (ice-9 ftw))                    ; for 'scandir'
        #:phases (alist-cons-after
                  'install 'add-symlinks
                  (lambda* (#:key outputs #:allow-other-keys)
                    ;; The cross-gcc invokes 'as', 'ld', etc, without the
                    ;; triplet prefix, so add symlinks.
                    (let ((out (assoc-ref outputs "out"))
                          (triplet-prefix (string-append ,(boot-triplet) "-")))
                      (define (has-triplet-prefix? name)
                        (string-prefix? triplet-prefix name))
                      (define (remove-triplet-prefix name)
                        (substring name (string-length triplet-prefix)))
                      (with-directory-excursion (string-append out "/bin")
                        (for-each (lambda (name)
                                    (symlink name (remove-triplet-prefix name)))
                                  (scandir "." has-triplet-prefix?)))
                      #t))
                  %standard-phases)

        ,@(substitute-keyword-arguments (package-arguments binutils)
            ((#:configure-flags cf)
             `(cons ,(string-append "--target=" (boot-triplet))
                    ,cf)))))
     (inputs %boot0-inputs))))

(define gcc-boot0
  (package-with-bootstrap-guile
   (package (inherit gcc)
     (name "gcc-cross-boot0")
     (arguments
      `(#:guile ,%bootstrap-guile
        #:implicit-inputs? #f
        #:modules ((guix build gnu-build-system)
                   (guix build utils)
                   (ice-9 regex)
                   (srfi srfi-1)
                   (srfi srfi-26))
        ,@(substitute-keyword-arguments (package-arguments gcc)
            ((#:configure-flags flags)
             `(append (list ,(string-append "--target=" (boot-triplet))

                            ;; No libc yet.
                            "--without-headers"

                            ;; Disable features not needed at this stage.
                            "--disable-shared"
                            "--enable-languages=c,c++"

                            ;; libstdc++ cannot be built at this stage
                            ;; ("Link tests are not allowed after
                            ;; GCC_NO_EXECUTABLES.").
                            "--disable-libstdc++-v3"

                            "--disable-threads"
                            "--disable-libmudflap"
                            "--disable-libatomic"
                            "--disable-libsanitizer"
                            "--disable-libitm"
                            "--disable-libgomp"
                            "--disable-libcilkrts"
                            "--disable-libvtv"
                            "--disable-libssp"
                            "--disable-libquadmath"
                            "--disable-decimal-float")
                      (remove (cut string-match
                                "--(with-system-zlib|enable-languages.*)" <>)
                              ,flags)))
            ((#:phases phases)
             `(alist-cons-after
               'unpack 'unpack-gmp&co
               (lambda* (#:key inputs #:allow-other-keys)
                 (let ((gmp  (assoc-ref %build-inputs "gmp-source"))
                       (mpfr (assoc-ref %build-inputs "mpfr-source"))
                       (mpc  (assoc-ref %build-inputs "mpc-source")))

                   ;; To reduce the set of pre-built bootstrap inputs, build
                   ;; GMP & co. from GCC.
                   (for-each (lambda (source)
                               (or (zero? (system* "tar" "xvf" source))
                                   (error "failed to unpack tarball"
                                          source)))
                             (list gmp mpfr mpc))

                   ;; Create symlinks like `gmp' -> `gmp-x.y.z'.
                   ,@(map (lambda (lib)
                            ;; Drop trailing letters, as gmp-6.0.0a unpacks
                            ;; into gmp-6.0.0.
                            `(symlink ,(string-trim-right
                                        (package-full-name lib)
                                        char-set:letter)
                                      ,(package-name lib)))
                          (list gmp-6.0 mpfr mpc))))
               (alist-cons-after
                'install 'symlink-libgcc_eh
                (lambda* (#:key outputs #:allow-other-keys)
                  (let ((out (assoc-ref outputs "lib")))
                    ;; Glibc wants to link against libgcc_eh, so provide
                    ;; it.
                    (with-directory-excursion
                        (string-append out "/lib/gcc/"
                                       ,(boot-triplet)
                                       "/" ,(package-version gcc))
                      (symlink "libgcc.a" "libgcc_eh.a"))))
                ,phases))))))

     (inputs `(("gmp-source" ,(package-source gmp-6.0))
               ("mpfr-source" ,(package-source mpfr))
               ("mpc-source" ,(package-source mpc))
               ("binutils-cross" ,binutils-boot0)

               ;; Call it differently so that the builder can check whether
               ;; the "libc" input is #f.
               ("libc-native" ,@(assoc-ref %boot0-inputs "libc"))
               ,@(alist-delete "libc" %boot0-inputs)))

     ;; No need for Texinfo at this stage.
     (native-inputs (alist-delete "texinfo"
                                  (package-native-inputs gcc))))))

(define perl-boot0
  (let ((perl (package
                (inherit perl)
                (name "perl-boot0")
                (replacement #f)
                (arguments
                 ;; At the very least, this must not depend on GCC & co.
                 (let ((args `(#:disallowed-references
                               ,(list %bootstrap-binutils))))
                   (substitute-keyword-arguments (package-arguments perl)
                     ((#:phases phases)
                      `(modify-phases ,phases
                         ;; Pthread support is missing in the bootstrap compiler
                         ;; (broken spec file), so disable it.
                         (add-before 'configure 'disable-pthreads
                           (lambda _
                             (substitute* "Configure"
                               (("^libswanted=(.*)pthread" _ before)
                                (string-append "libswanted=" before)))))))))))))
    (package-with-bootstrap-guile
     (package-with-explicit-inputs perl
                                   %boot0-inputs
                                   (current-source-location)
                                   #:guile %bootstrap-guile))))

(define (linux-libre-headers-boot0)
  "Return Linux-Libre header files for the bootstrap environment."
  ;; Note: this is wrapped in a thunk to nicely handle circular dependencies
  ;; between (gnu packages linux) and this module.
  (package-with-bootstrap-guile
   (package (inherit linux-libre-headers)
     (arguments `(#:guile ,%bootstrap-guile
                  #:implicit-inputs? #f
                  ,@(package-arguments linux-libre-headers)))
     (native-inputs
      `(("perl" ,perl-boot0)
        ,@%boot0-inputs)))))

(define texinfo-boot0
  ;; Texinfo used to build libc's manual.
  ;; We build without ncurses because it fails to build at this stage, and
  ;; because we don't need the stand-alone Info reader.
  ;; Also, use %BOOT0-INPUTS to avoid building Perl once more.
  (let ((texinfo (package (inherit texinfo)
                   (native-inputs '())
                   (inputs `(("perl" ,perl-boot0)))

                   ;; Some of Texinfo 6.1's tests would fail with "Couldn't
                   ;; set UTF-8 character type in locale" but we don't have a
                   ;; UTF-8 locale at this stage, so skip them.
                   (arguments '(#:tests? #f)))))
    (package-with-bootstrap-guile
     (package-with-explicit-inputs texinfo %boot0-inputs
                                   (current-source-location)
                                   #:guile %bootstrap-guile))))

(define %boot1-inputs
  ;; 2nd stage inputs.
  `(("gcc" ,gcc-boot0)
    ("binutils-cross" ,binutils-boot0)
    ,@(alist-delete "binutils" %boot0-inputs)))

(define glibc-final-with-bootstrap-bash
  ;; The final libc, "cross-built".  If everything went well, the resulting
  ;; store path has no dependencies.  Actually, the really-final libc is
  ;; built just below; the only difference is that this one uses the
  ;; bootstrap Bash.
  (package-with-bootstrap-guile
   (package (inherit glibc)
     (name "glibc-intermediate")
     (arguments
      `(#:guile ,%bootstrap-guile
        #:implicit-inputs? #f

        ,@(substitute-keyword-arguments (package-arguments glibc)
            ((#:configure-flags flags)
             `(append (list ,(string-append "--host=" (boot-triplet))
                            ,(string-append "--build="
                                            (nix-system->gnu-triplet))

                            ;; Build Sun/ONC RPC support.  In particular,
                            ;; install rpc/*.h.
                            "--enable-obsolete-rpc")
                      ,flags))
            ((#:phases phases)
             `(alist-cons-before
               'configure 'pre-configure
               (lambda* (#:key inputs #:allow-other-keys)
                 ;; Don't clobber CPATH with the bootstrap libc.
                 (setenv "NATIVE_CPATH" (getenv "CPATH"))
                 (unsetenv "CPATH")

                 ;; 'rpcgen' needs native libc headers to be built.
                 (substitute* "sunrpc/Makefile"
                   (("sunrpc-CPPFLAGS =.*" all)
                    (string-append "CPATH = $(NATIVE_CPATH)\n"
                                   "export CPATH\n"
                                   all "\n"))))
               ,phases)))))
     (propagated-inputs `(("kernel-headers" ,(linux-libre-headers-boot0))))
     (native-inputs
      `(("texinfo" ,texinfo-boot0)
        ("perl" ,perl-boot0)))
     (inputs
      `(;; The boot inputs.  That includes the bootstrap libc.  We don't want
        ;; it in $CPATH, hence the 'pre-configure' phase above.
        ,@%boot1-inputs

        ;; A native GCC is needed to build `cross-rpcgen'.
        ("native-gcc" ,@(assoc-ref %boot0-inputs "gcc"))

        ;; Here, we use the bootstrap Bash, which is not satisfactory
        ;; because we don't want to depend on bootstrap tools.
        ("static-bash" ,@(assoc-ref %boot0-inputs "bash")))))))

(define (cross-gcc-wrapper gcc binutils glibc bash)
  "Return a wrapper for the pseudo-cross toolchain GCC/BINUTILS/GLIBC
that makes it available under the native tool names."
  (package (inherit gcc)
    (name (string-append (package-name gcc) "-wrapped"))
    (source #f)
    (build-system trivial-build-system)
    (outputs '("out"))
    (arguments
     `(#:guile ,%bootstrap-guile
       #:modules ((guix build utils))
       #:builder (begin
                   (use-modules (guix build utils))

                   (let* ((binutils (assoc-ref %build-inputs "binutils"))
                          (gcc      (assoc-ref %build-inputs "gcc"))
                          (libc     (assoc-ref %build-inputs "libc"))
                          (bash     (assoc-ref %build-inputs "bash"))
                          (out      (assoc-ref %outputs "out"))
                          (bindir   (string-append out "/bin"))
                          (triplet  ,(boot-triplet)))
                     (define (wrap-program program)
                       ;; GCC-BOOT0 is a libc-less cross-compiler, so it
                       ;; needs to be told where to find the crt files and
                       ;; the dynamic linker.
                       (call-with-output-file program
                         (lambda (p)
                           (format p "#!~a/bin/bash
exec ~a/bin/~a-~a -B~a/lib -Wl,-dynamic-linker -Wl,~a/~a \"$@\"~%"
                                   bash
                                   gcc triplet program
                                   libc libc
                                   ,(glibc-dynamic-linker))))

                       (chmod program #o555))

                     (mkdir-p bindir)
                     (with-directory-excursion bindir
                       (for-each (lambda (tool)
                                   (symlink (string-append binutils "/bin/"
                                                           triplet "-" tool)
                                            tool))
                                 '("ar" "ranlib"))
                       (for-each wrap-program '("gcc" "g++")))))))
    (native-inputs
     `(("binutils" ,binutils)
       ("gcc" ,gcc)
       ("libc" ,glibc)
       ("bash" ,bash)))
    (inputs '())))

(define bison-boot1
  ;; XXX: This Bison is needed to rebuild Bash's parser, which is modified by
  ;; its CVE patches.  Remove it when it's no longer needed.
  (let* ((m4    (package-with-bootstrap-guile
                 (package-with-explicit-inputs m4 %boot0-inputs
                                               (current-source-location)
                                               #:guile %bootstrap-guile)))
         (bison (package (inherit bison)
                  (propagated-inputs `(("m4" ,m4)))
                  (inputs '())                    ;remove Flex...
                  (arguments
                   '(#:tests? #f                  ;... and thus disable tests

                     ;; Zero timestamps in liby.a; this must be done
                     ;; explicitly here because the bootstrap Binutils don't
                     ;; do that (default is "cru".)
                     #:make-flags '("ARFLAGS=crD" "RANLIB=ranlib -D"
                                    "V=1"))))))
    (package
      (inherit (package-with-bootstrap-guile
                (package-with-explicit-inputs bison %boot0-inputs
                                              (current-source-location)
                                              #:guile %bootstrap-guile)))
      (native-inputs `(("perl" ,perl-boot0))))))

(define static-bash-for-glibc
  ;; A statically-linked Bash to be used by GLIBC-FINAL in system(3) & co.
  (let* ((gcc  (cross-gcc-wrapper gcc-boot0 binutils-boot0
                                  glibc-final-with-bootstrap-bash
                                  (car (assoc-ref %boot1-inputs "bash"))))
         (bash (package (inherit static-bash)
                 (arguments
                  `(#:guile ,%bootstrap-guile
                    ,@(package-arguments static-bash)))))
         (inputs `(("gcc" ,gcc)
                   ("libc" ,glibc-final-with-bootstrap-bash)
                   ,@(fold alist-delete %boot1-inputs
                           '("gcc" "libc")))))
    (package
      (inherit (package-with-bootstrap-guile
                (package-with-explicit-inputs bash inputs
                                              (current-source-location)
                                              #:guile %bootstrap-guile)))
      (native-inputs `(("bison" ,bison-boot1))))))

(define gettext-boot0
  ;; A minimal gettext used during bootstrap.
  (let ((gettext-minimal
         (package (inherit gnu-gettext)
           (name "gettext-boot0")
           (inputs '())                           ;zero dependencies
           (arguments
            (substitute-keyword-arguments
                `(#:tests? #f
                  ,@(package-arguments gnu-gettext))
              ((#:phases phases)
               `(modify-phases ,phases
                  ;; Build only the tools.
                  (add-after 'unpack 'chdir
                             (lambda _
                               (chdir "gettext-tools")))

                  ;; Some test programs require pthreads, which we don't have.
                  (add-before 'configure 'no-test-programs
                              (lambda _
                                (substitute* "tests/Makefile.in"
                                  (("^PROGRAMS =.*$")
                                   "PROGRAMS =\n"))
                                #t))

                  ;; Don't try to link against libexpat.
                  (delete 'link-expat)
                  (delete 'patch-tests))))))))
    (package-with-bootstrap-guile
     (package-with-explicit-inputs gettext-minimal
                                   %boot1-inputs
                                   (current-source-location)
                                   #:guile %bootstrap-guile))))

(define glibc-final
  ;; The final glibc, which embeds the statically-linked Bash built above.
  (package (inherit glibc-final-with-bootstrap-bash)
    (name "glibc")
    (inputs `(("static-bash" ,static-bash-for-glibc)
              ,@(alist-delete
                 "static-bash"
                 (package-inputs glibc-final-with-bootstrap-bash))))

    ;; This time we need 'msgfmt' to install all the libc.mo files.
    (native-inputs `(,@(package-native-inputs glibc-final-with-bootstrap-bash)
                     ("gettext" ,gettext-boot0)))

    ;; The final libc only refers to itself, but the 'debug' output contains
    ;; references to GCC-BOOT0 and to the Linux headers.  XXX: Would be great
    ;; if 'allowed-references' were per-output.
    (arguments
     `(#:allowed-references
       ,(cons* `(,gcc-boot0 "lib") (linux-libre-headers-boot0)
               static-bash-for-glibc
               (package-outputs glibc-final-with-bootstrap-bash))

       ,@(package-arguments glibc-final-with-bootstrap-bash)))))

(define gcc-boot0-wrapped
  ;; Make the cross-tools GCC-BOOT0 and BINUTILS-BOOT0 available under the
  ;; non-cross names.
  (cross-gcc-wrapper gcc-boot0 binutils-boot0 glibc-final
                     (car (assoc-ref %boot1-inputs "bash"))))

(define %boot2-inputs
  ;; 3rd stage inputs.
  `(("libc" ,glibc-final)
    ("gcc" ,gcc-boot0-wrapped)
    ,@(fold alist-delete %boot1-inputs '("libc" "gcc"))))

(define binutils-final
  (package-with-bootstrap-guile
   (package (inherit binutils)
     (arguments
      `(#:guile ,%bootstrap-guile
        #:implicit-inputs? #f
        #:allowed-references ("out" ,glibc-final)
        ,@(package-arguments binutils)))
     (inputs %boot2-inputs))))

(define libstdc++
  ;; Intermediate libstdc++ that will allow us to build the final GCC
  ;; (remember that GCC-BOOT0 cannot build libstdc++.)
  ;; TODO: Write in terms of 'make-libstdc++'.
  (package-with-bootstrap-guile
   (package (inherit gcc)
     (name "libstdc++")
     (arguments
      `(#:guile ,%bootstrap-guile
        #:implicit-inputs? #f
        #:allowed-references ("out")
        #:out-of-source? #t
        #:phases (alist-cons-before
                  'configure 'chdir
                  (lambda _
                    (chdir "libstdc++-v3"))
                  %standard-phases)
        #:configure-flags `("--disable-shared"
                            "--disable-libstdcxx-threads"
                            "--disable-libstdcxx-pch"
                            ,(string-append "--with-gxx-include-dir="
                                            (assoc-ref %outputs "out")
                                            "/include"
                                            ;; "/include/c++/"
                                            ;; ,(package-version gcc)
                                            ))))
     (outputs '("out"))
     (inputs %boot2-inputs)
     (native-inputs '())
     (propagated-inputs '())
     (synopsis "GNU C++ standard library (intermediate)"))))

(define zlib-final
  ;; Zlib used by GCC-FINAL.
  (package-with-bootstrap-guile
   (package
     (inherit zlib)
     (arguments
      `(#:guile ,%bootstrap-guile
        #:implicit-inputs? #f
        #:allowed-references ("out" ,glibc-final)
        ,@(package-arguments zlib)))
     (inputs %boot2-inputs))))

(define ld-wrapper-boot3
  ;; A linker wrapper that uses the bootstrap Guile.
  (make-ld-wrapper "ld-wrapper-boot3"
                   #:binutils binutils-final
                   #:guile %bootstrap-guile
                   #:bash (car (assoc-ref %boot2-inputs "bash"))))

(define gcc-final
  ;; The final GCC.
  (package (inherit gcc-boot0)
    (name "gcc")

    ;; XXX: Currently #:allowed-references applies to all the outputs but the
    ;; "debug" output contains disallowed references, notably
    ;; linux-libre-headers.  Disable the debugging output to work around that.
    (outputs (delete "debug" (package-outputs gcc-boot0)))

    (arguments
     `(#:guile ,%bootstrap-guile
       #:implicit-inputs? #f

       #:allowed-references ("out" "lib" ,zlib-final
                             ,glibc-final ,static-bash-for-glibc)

       ;; Things like libasan.so and libstdc++.so NEED ld.so for some
       ;; reason, but it is not in their RUNPATH.  This is a false
       ;; positive, so turn it off.
       #:validate-runpath? #f

       ;; Build again GMP & co. within GCC's build process, because it's hard
       ;; to do outside (because GCC-BOOT0 is a cross-compiler, and thus
       ;; doesn't honor $LIBRARY_PATH, which breaks `gnu-build-system'.)
       ,@(substitute-keyword-arguments (package-arguments gcc-boot0)
           ((#:configure-flags boot-flags)
            (let loop ((args (package-arguments gcc)))
              (match args
                ((#:configure-flags normal-flags _ ...)
                 normal-flags)
                ((_ rest ...)
                 (loop rest)))))
           ((#:make-flags flags)
            ;; Since $LIBRARY_PATH is not honored, add the relevant flags.
            `(let ((zlib (assoc-ref %build-inputs "zlib")))
               (map (lambda (flag)
                      (if (string-prefix? "LDFLAGS=" flag)
                          (string-append flag " -L"
                                         (assoc-ref %build-inputs "libstdc++")
                                         "/lib -L" zlib "/lib -Wl,-rpath="
                                         zlib "/lib")
                          flag))
                    ,flags)))
           ((#:phases phases)
            `(alist-delete 'symlink-libgcc_eh ,phases)))))

    ;; This time we want Texinfo, so we get the manual.  Add
    ;; STATIC-BASH-FOR-GLIBC so that it's used in the final shebangs of
    ;; scripts such as 'mkheaders' and 'fixinc.sh' (XXX: who cares about these
    ;; scripts?).
    (native-inputs `(("texinfo" ,texinfo-boot0)
                     ("static-bash" ,static-bash-for-glibc)
                     ,@(package-native-inputs gcc-boot0)))

    (inputs `(("gmp-source" ,(bootstrap-origin (package-source gmp-6.0)))
              ("mpfr-source" ,(package-source mpfr))
              ("mpc-source" ,(package-source mpc))
              ("ld-wrapper" ,ld-wrapper-boot3)
              ("binutils" ,binutils-final)
              ("libstdc++" ,libstdc++)
              ("zlib" ,zlib-final)
              ,@%boot2-inputs))))

(define %boot3-inputs
  ;; 4th stage inputs.
  `(("gcc" ,gcc-final)
    ("ld-wrapper" ,ld-wrapper-boot3)
    ,@(alist-delete "gcc" %boot2-inputs)))

(define bash-final
  ;; Link with `-static-libgcc' to make sure we don't retain a reference
  ;; to the bootstrap GCC.
  (package
    (inherit (package-with-bootstrap-guile
              (package-with-explicit-inputs (static-libgcc-package bash)
                                            %boot3-inputs
                                            (current-source-location)
                                            #:guile %bootstrap-guile)))
    (native-inputs `(("bison" ,bison-boot1)))))

(define %boot4-inputs
  ;; Now use the final Bash.
  `(("bash" ,bash-final)
    ,@(alist-delete "bash" %boot3-inputs)))

(define-public guile-final
  ;; This package must be public because other modules refer to it.  However,
  ;; mark it as hidden so that 'fold-packages' ignores it.
  (package-with-bootstrap-guile
   (package-with-explicit-inputs (hidden-package guile-2.0/fixed)
                                 %boot4-inputs
                                 (current-source-location)
                                 #:guile %bootstrap-guile)))

(define glibc-utf8-locales-final
  ;; Now that we have GUILE-FINAL, build the UTF-8 locales.  They are needed
  ;; by the build processes afterwards so their 'scm_to_locale_string' works
  ;; with the full range of Unicode codepoints (remember
  ;; 'scm_to_locale_string' is called every time a string is passed to a C
  ;; function.)
  (package
    (inherit glibc-utf8-locales)
    (inputs `(("glibc" ,glibc-final)
              ("gzip"
               ,(package-with-explicit-inputs gzip %boot4-inputs
                                              (current-source-location)
                                              #:guile %bootstrap-guile))))))

(define-public ld-wrapper
  ;; The final 'ld' wrapper, which uses the final Guile and Binutils.
  (package (inherit ld-wrapper-boot3)
    (name "ld-wrapper")
    (inputs `(("guile" ,guile-final)
              ("bash"  ,bash-final)
              ,@(fold alist-delete (package-inputs ld-wrapper-boot3)
                      '("guile" "bash"))))))

(define %boot5-inputs
  ;; Now with UTF-8 locales.  Remember that the bootstrap binaries were built
  ;; with an older libc, which cannot load the new locale format.  See
  ;; <https://lists.gnu.org/archive/html/guix-devel/2015-08/msg00737.html>.
  `(("locales" ,glibc-utf8-locales-final)
    ,@%boot4-inputs))

(define gnu-make-final
  ;; The final GNU Make, which uses the final Guile.
  (package-with-bootstrap-guile
   (package-with-explicit-inputs gnu-make
                                 `(("guile" ,guile-final)
                                   ,@%boot5-inputs)
                                 (current-source-location))))

(define coreutils-final
  ;; The final Coreutils.  Treat them specially because some packages, such as
  ;; Findutils, keep a reference to the Coreutils they were built with.
  (package-with-bootstrap-guile
   (package-with-explicit-inputs coreutils
                                 %boot5-inputs
                                 (current-source-location)

                                 ;; Use the final Guile, linked against the
                                 ;; final libc with working iconv, so that
                                 ;; 'substitute*' works well when touching
                                 ;; test files in Gettext.
                                 #:guile guile-final)))

(define grep-final
  ;; The final grep.  Gzip holds a reference to it (via zgrep), so it must be
  ;; built before gzip.
  (package-with-bootstrap-guile
   (package-with-explicit-inputs (package
                                   (inherit grep)
                                   (native-inputs `(("perl" ,perl-boot0))))
                                 %boot5-inputs
                                 (current-source-location)
                                 #:guile guile-final)))

(define %boot6-inputs
  ;; Now use the final Coreutils.
  `(("coreutils" ,coreutils-final)
    ("grep" ,grep-final)
    ,@%boot5-inputs))

(define-public %final-inputs
  ;; Final derivations used as implicit inputs by 'gnu-build-system'.  We
  ;; still use 'package-with-bootstrap-guile' so that the bootstrap tools are
  ;; used for origins that have patches, thereby avoiding circular
  ;; dependencies.
  (let ((finalize (compose package-with-bootstrap-guile
                           (cut package-with-explicit-inputs <> %boot6-inputs
                                (current-source-location)))))
    `(,@(map (match-lambda
              ((name package)
               (list name (finalize package))))
             `(("tar" ,tar)
               ("gzip" ,gzip)
               ("bzip2" ,bzip2)
               ("xz" ,xz)
               ("file" ,file)
               ("diffutils" ,diffutils)
               ("patch" ,patch)
               ("sed" ,sed)
               ("findutils" ,findutils)
               ("gawk" ,gawk)))
      ("grep" ,grep-final)
      ("coreutils" ,coreutils-final)
      ("make" ,gnu-make-final)
      ("bash" ,bash-final)
      ("ld-wrapper" ,ld-wrapper)
      ("binutils" ,binutils-final)
      ("gcc" ,gcc-final)
      ("libc" ,glibc-final)
      ("locales" ,glibc-utf8-locales-final))))

(define-public canonical-package
  (let ((name->package (fold (lambda (input result)
                               (match input
                                 ((_ package)
                                  (vhash-cons (package-full-name package)
                                              package result))))
                             vlist-null
                             `(("guile" ,guile-final)
                               ,@%final-inputs))))
    (lambda (package)
      "Return the 'canonical' variant of PACKAGE---i.e., if PACKAGE is one of
the implicit inputs of 'gnu-build-system', return that one, otherwise return
PACKAGE.

The goal is to avoid duplication in cases like GUILE-FINAL vs. GUILE-2.0,
COREUTILS-FINAL vs. COREUTILS, etc."
      ;; XXX: This doesn't handle dependencies of the final inputs, such as
      ;; libunistring, GMP, etc.
      (match (vhash-assoc (package-full-name package) name->package)
        ((_ . canon)
         ;; In general we want CANON, except if we're cross-compiling: CANON
         ;; uses explicit inputs, so it is "anchored" in the bootstrapped
         ;; process, with dependencies on things that cannot be
         ;; cross-compiled.
         (if (%current-target-system)
             package
             canon))
        (_ package)))))


;;;
;;; GCC toolchain.
;;;

(define (gcc-toolchain gcc)
  "Return a complete toolchain for GCC."
  (package
    (name "gcc-toolchain")
    (version (package-version gcc))
    (source #f)
    (build-system trivial-build-system)
    (arguments
     '(#:modules ((guix build union))
       #:builder (begin
                   (use-modules (ice-9 match)
                                (srfi srfi-26)
                                (guix build union))

                   (let ((out (assoc-ref %outputs "out")))

                     (match %build-inputs
                       (((names . directories) ...)
                        (union-build out directories)))

                     (union-build (assoc-ref %outputs "debug")
                                  (list (assoc-ref %build-inputs
                                                   "libc-debug")))))))

    (native-search-paths (package-native-search-paths gcc))
    (search-paths (package-search-paths gcc))

    (license (package-license gcc))
    (synopsis "Complete GCC tool chain for C/C++ development")
    (description
     "This package provides a complete GCC tool chain for C/C++ development to
be installed in user profiles.  This includes GCC, as well as libc (headers
and binaries, plus debugging symbols in the 'debug' output), and Binutils.")
    (home-page "http://gcc.gnu.org/")
    (outputs '("out" "debug"))

    ;; The main raison d'être of this "meta-package" is (1) to conveniently
    ;; install everything that we need, and (2) to make sure ld-wrapper comes
    ;; before Binutils' ld in the user's profile.
    (inputs `(("gcc" ,gcc)
              ("ld-wrapper" ,(car (assoc-ref %final-inputs "ld-wrapper")))
              ("binutils" ,binutils-final)
              ("libc" ,glibc-final)
              ("libc-debug" ,glibc-final "debug")))))

(define-public gcc-toolchain-4.8
  (gcc-toolchain gcc-4.8))

(define-public gcc-toolchain-4.9
  (gcc-toolchain gcc-final))

(define-public gcc-toolchain-5
  (gcc-toolchain gcc-5))

(define-public gcc-toolchain-6
  (gcc-toolchain gcc-6))

;;; commencement.scm ends here
