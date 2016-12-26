;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2016 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Dennis Mungai <dmngaie@gmail.com>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
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

(define-module (gnu packages llvm)
  #:use-module (guix packages)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system cmake)
  #:use-module (gnu packages)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages bootstrap)           ;glibc-dynamic-linker
  #:use-module (gnu packages compression)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages python)
  #:use-module (gnu packages xml))

(define-public llvm
  (package
    (name "llvm")
    (version "3.8.1")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "http://llvm.org/releases/"
                          version "/llvm-" version ".src.tar.xz"))
      (sha256
       (base32
        "1ybmnid4pw2hxn12ax5qa5kl1ldfns0njg8533y3mzslvd5cx0kf"))))
    (build-system cmake-build-system)
    (native-inputs
     `(("python" ,python-2) ;bytes->str conversion in clang>=3.7 needs python-2
       ("perl"   ,perl)))
    (inputs
     `(("libffi" ,libffi)))
    (propagated-inputs
     `(("zlib" ,zlib)))                 ;to use output from llvm-config
    (arguments
     `(#:configure-flags '("-DCMAKE_SKIP_BUILD_RPATH=FALSE"
                           "-DCMAKE_BUILD_WITH_INSTALL_RPATH=FALSE"
                           "-DBUILD_SHARED_LIBS:BOOL=TRUE"
                           "-DLLVM_ENABLE_FFI:BOOL=TRUE"
                           "-DLLVM_INSTALL_UTILS=ON") ; Needed for rustc.

       ;; Don't use '-g' during the build, to save space.
       #:build-type "Release"
       #:phases (modify-phases %standard-phases
                  (add-before 'build 'shared-lib-workaround
                    ;; Even with CMAKE_SKIP_BUILD_RPATH=FALSE, llvm-tblgen
                    ;; doesn't seem to get the correct rpath to be able to run
                    ;; from the build directory.  Set LD_LIBRARY_PATH as a
                    ;; workaround.
                    (lambda _
                      (setenv "LD_LIBRARY_PATH"
                              (string-append (getcwd) "/lib"))
                      #t)))))
    (home-page "http://www.llvm.org")
    (synopsis "Optimizing compiler infrastructure")
    (description
     "LLVM is a compiler infrastructure designed for compile-time, link-time,
runtime, and idle-time optimization of programs from arbitrary programming
languages.  It currently supports compilation of C and C++ programs, using
front-ends derived from GCC 4.0.1.  A new front-end for the C family of
languages is in development.  The compiler infrastructure includes mirror sets
of programming tools as well as libraries with equivalent functionality.")
    (license license:ncsa)))

(define-public llvm-with-rtti
  (package (inherit llvm)
    (name "llvm-with-rtti")
    (arguments
     (substitute-keyword-arguments (package-arguments llvm)
       ((#:configure-flags flags)
        `(append '("-DCMAKE_SKIP_BUILD_RPATH=FALSE"
                   "-DCMAKE_BUILD_WITH_INSTALL_RPATH=FALSE"
                   "-DLLVM_REQUIRES_RTTI=1")
                 ,flags))))))

(define (clang-runtime-from-llvm llvm hash)
  (package
    (name "clang-runtime")
    (version (package-version llvm))
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://llvm.org/releases/"
                           version "/compiler-rt-" version ".src.tar.xz"))
       (sha256 (base32 hash))))
    (build-system cmake-build-system)
    (native-inputs (package-native-inputs llvm))
    (inputs
     `(("llvm" ,llvm)))
    (arguments
     `(;; Don't use '-g' during the build to save space.
       #:build-type "Release"
       #:tests? #f))                    ; Tests require gtest
    (home-page "http://compiler-rt.llvm.org")
    (synopsis "Runtime library for Clang/LLVM")
    (description
     "The \"clang-runtime\" library provides the implementations of run-time
functions for C and C++ programs.  It also provides header files that allow C
and C++ source code to interface with the \"sanitization\" passes of the clang
compiler.  In LLVM this library is called \"compiler-rt\".")
    (license license:ncsa)

    ;; <http://compiler-rt.llvm.org/> doesn't list MIPS as supported.
    (supported-systems (delete "mips64el-linux" %supported-systems))))

(define* (clang-from-llvm llvm clang-runtime hash
                          #:key (patches '("clang-libc-search-path.patch")))
  (package
    (name "clang")
    (version (package-version llvm))
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://llvm.org/releases/"
                           version "/cfe-" version ".src.tar.xz"))
       (sha256 (base32 hash))
       (patches (map search-patch patches))))
    ;; Using cmake allows us to treat llvm as an external library.  There
    ;; doesn't seem to be any way to do this with clang's autotools-based
    ;; build system.
    (build-system cmake-build-system)
    (native-inputs (package-native-inputs llvm))
    (inputs
     `(("libxml2" ,libxml2)
       ("gcc-lib" ,gcc "lib")
       ,@(package-inputs llvm)))
    (propagated-inputs
     `(("llvm" ,llvm)
       ("clang-runtime" ,clang-runtime)))
    (arguments
     `(#:configure-flags
       (list "-DCLANG_INCLUDE_TESTS=True"

             ;; Find libgcc_s, crtbegin.o, and crtend.o.
             (string-append "-DGCC_INSTALL_PREFIX="
                            (assoc-ref %build-inputs "gcc-lib"))

             ;; Use a sane default include directory.
             (string-append "-DC_INCLUDE_DIRS="
                            (assoc-ref %build-inputs "libc")
                            "/include"))

       ;; Don't use '-g' during the build to save space.
       #:build-type "Release"

       #:phases (modify-phases %standard-phases
                  (add-after
                   'unpack 'set-glibc-file-names
                   (lambda* (#:key inputs #:allow-other-keys)
                     (let ((libc (assoc-ref inputs "libc"))
                           (compiler-rt (assoc-ref inputs "clang-runtime")))
                       (substitute* "lib/Driver/Tools.cpp"
                         ;; Patch the 'getLinuxDynamicLinker' function to that
                         ;; it uses the right dynamic linker file name.
                         (("/lib64/ld-linux-x86-64.so.2")
                          (string-append libc
                                         ,(glibc-dynamic-linker)))

                         ;; Link to libclang_rt files from clang-runtime.
                         (("TC\\.getDriver\\(\\)\\.ResourceDir")
                          (string-append "\"" compiler-rt "\"")))

                       ;; Same for libc's libdir, to allow crt1.o & co. to be
                       ;; found.
                       (substitute* "lib/Driver/ToolChains.cpp"
                         (("@GLIBC_LIBDIR@")
                          (string-append libc "/lib")))))))))

    ;; Clang supports the same environment variables as GCC.
    (native-search-paths
     (list (search-path-specification
            (variable "CPATH")
            (files '("include")))
           (search-path-specification
            (variable "LIBRARY_PATH")
            (files '("lib" "lib64")))))

    (home-page "http://clang.llvm.org")
    (synopsis "C language family frontend for LLVM")
    (description
     "Clang is a compiler front end for the C, C++, Objective-C and
Objective-C++ programming languages.  It uses LLVM as its back end.  The Clang
project includes the Clang front end, the Clang static analyzer, and several
code analysis tools.")
    (license license:ncsa)))

(define-public clang-runtime
  (clang-runtime-from-llvm
   llvm
   "0p0y85c7izndbpg2l816z7z7558axq11d5pwkm4h11sdw7d13w0d"))

(define-public clang
  (clang-from-llvm llvm clang-runtime
                   "1prc72xmkgx8wrzmrr337776676nhsp1qd3mw2bvb22bzdnq7lsc"
                   #:patches '("clang-3.8-libc-search-path.patch")))

(define-public llvm-3.7
  (package (inherit llvm)
    (version "3.7.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://llvm.org/releases/"
                           version "/llvm-" version ".src.tar.xz"))
       (sha256
        (base32
         "1masakdp9g2dan1yrazg7md5am2vacbkb3nahb3dchpc1knr8xxy"))))))

(define-public clang-runtime-3.7
  (clang-runtime-from-llvm
   llvm-3.7
   "10c1mz2q4bdq9bqfgr3dirc6hz1h3sq8573srd5q5lr7m7j6jiwx"))

(define-public clang-3.7
  (clang-from-llvm llvm-3.7 clang-runtime-3.7
                   "0x065d0w9b51xvdjxwfzjxng0gzpbx45fgiaxpap45ragi61dqjn"))

(define-public llvm-3.6
  (package (inherit llvm)
    (version "3.6.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://llvm.org/releases/"
                           version "/llvm-" version ".src.tar.xz"))
       (sha256
        (base32
         "153vcvj8gvgwakzr4j0kndc0b7wn91c2g1vy2vg24s6spxcc23gn"))))))

(define-public clang-runtime-3.6
  (clang-runtime-from-llvm
   llvm-3.6
   "11qx8d3pbfqjaj2x207pvlvzihbs1z2xbw4crpz7aid6h1yz6bqg"))

(define-public clang-3.6
  (clang-from-llvm llvm-3.6 clang-runtime-3.6
                   "1wwr8s6lzr324hv4s1k6na4j5zv6n9kdhi14s4kb9b13d93814df"))

(define-public llvm-3.5
  (package (inherit llvm)
    (version "3.5.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://llvm.org/releases/"
                           version "/llvm-" version ".src.tar.xz"))
       (sha256
        (base32
         "0xf5q17kkxsrm2gsi93h4pwlv663kji73r2g4asb97klsmb626a4"))))))

(define-public clang-runtime-3.5
  (clang-runtime-from-llvm
   llvm-3.5
   "1hsdnzzdr5kglz6fnv3lcsjs222zjsy14y8ax9dy6zqysanplbal"))

(define-public clang-3.5
  (clang-from-llvm llvm-3.5 clang-runtime-3.5
                   "0846h8vn3zlc00jkmvrmy88gc6ql6014c02l4jv78fpvfigmgssg"))

(define-public llvm-for-extempore
  (package (inherit llvm-3.7)
    (source
     (origin
       (inherit (package-source llvm-3.7))
       (patches (list (search-patch "llvm-for-extempore.patch")))))
    ;; Extempore refuses to build on architectures other than x86_64
    (supported-systems '("x86_64-linux"))))
