;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 John Darrington <jmd@gnu.org>
;;; Copyright © 2015 Taylan Ulrich Bayırlı/Kammer <taylanbayirli@gmail.com>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 Federico Beffa <beffa@fbengineering.ch>
;;; Copyright © 2016 ng0 <ng0@we.make.ritual.n0.is>
;;; Copyright © 2016 Andy Patterson <ajpatter@uwaterloo.ca>
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

(define-module (gnu packages lisp)
  #:use-module (gnu packages)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages m4)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages base)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages bdw-gc)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages libffcall)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages libsigsegv)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages ed)
  #:use-module (gnu packages m4)
  #:use-module (gnu packages version-control)
  #:use-module (ice-9 match))

(define-public gcl
  (package
    (name "gcl")
    (version "2.6.12")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/" name "/" name "-" version ".tar.gz"))
      (sha256
       (base32 "1s4hs2qbjqmn9h88l4xvsifq5c3dlc5s74lyb61rdi5grhdlkf4f"))))
    (build-system gnu-build-system)
    (arguments
     `(#:parallel-build? #f  ; The build system seems not to be thread safe.
       #:tests? #f  ; There does not seem to be make check or anything similar.
       #:configure-flags '("--enable-ansi") ; required for use by the maxima package
       #:phases (alist-cons-before
                'configure 'pre-conf
                (lambda _
                  ;; Patch bug when building readline support.  This bug was
                  ;; also observed by Debian
                  ;; https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=741819
                  (substitute* "o/gcl_readline.d"
                    (("rl_attempted_completion_function = \
\\(CPPFunction \\*\\)rl_completion;")
                      "rl_attempted_completion_function = rl_completion;"))
                  (substitute*
                      (append
                       '("pcl/impl/kcl/makefile.akcl"
                         "add-defs"
                         "unixport/makefile.dos"
                         "add-defs.bat"
                         "gcl-tk/makefile.prev"
                         "add-defs1")
                       (find-files "h" "\\.defs"))
                    (("SHELL=/bin/(ba)?sh")
                     (string-append "SHELL=" (which "bash")))))
                ;; drop strip phase to make maxima build, see
                ;; https://www.ma.utexas.edu/pipermail/maxima/2008/009769.html
                (alist-delete 'strip
                 %standard-phases))))
    (native-inputs
     `(("m4" ,m4)
       ("readline" ,readline)
       ("texinfo" ,texinfo)
       ("texlive" ,texlive)))
    (home-page "http://www.gnu.org/software/gcl")
    (synopsis "A Common Lisp implementation")
    (description "GCL is an implementation of the Common Lisp language.  It
features the ability to compile to native object code and to load native
object code modules directly into its lisp core.  It also features a
stratified garbage collection strategy, a source-level debugger and a built-in
interface to the Tk widget system.")
    (license license:lgpl2.0+)))

(define-public ecl
  (package
    (name "ecl")
    (version "16.1.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://common-lisp.net/project/ecl/static/files/release/"
             name "-" version ".tgz"))
       (sha256
        (base32 "16ab8qs3awvdxy8xs8jy82v8r04x4wr70l9l2j45vgag18d2nj1d"))))
    (build-system gnu-build-system)
    ;; src/configure uses 'which' to confirm the existence of 'gzip'.
    (native-inputs `(("which" ,which)))
    (inputs `(("gmp" ,gmp)
              ("libatomic-ops" ,libatomic-ops)
              ("libgc" ,libgc)
              ("libffi" ,libffi)))
    (arguments
     '(#:tests? #t
       #:make-flags `(,(string-append "ECL="
                                      (assoc-ref %outputs "out")
                                      "/bin/ecl"))
       #:parallel-tests? #f
       #:phases
       (modify-phases %standard-phases
         (delete 'check)
         (add-after 'install 'wrap
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((ecl (assoc-ref outputs "out"))
                    (input-path (lambda (lib path)
                                  (string-append
                                   (assoc-ref inputs lib) path)))
                    (libraries '("gmp" "libatomic-ops" "libgc" "libffi" "libc"))
                    (binaries  '("gcc" "ld-wrapper" "binutils"))
                    (library-directories
                     (map (lambda (lib) (input-path lib "/lib"))
                          libraries)))

               (wrap-program (string-append ecl "/bin/ecl")
                 `("PATH" prefix
                   ,(map (lambda (binary)
                           (input-path binary "/bin"))
                         binaries))
                 `("CPATH" suffix
                   ,(map (lambda (lib)
                           (input-path lib "/include"))
                         `("kernel-headers" ,@libraries)))
                 `("LIBRARY_PATH" suffix ,library-directories)
                 `("LD_LIBRARY_PATH" suffix ,library-directories)))))
         (add-after 'wrap 'check (assoc-ref %standard-phases 'check)))))
    (home-page "http://ecls.sourceforge.net/")
    (synopsis "Embeddable Common Lisp")
    (description "ECL is an implementation of the Common Lisp language as
defined by the ANSI X3J13 specification.  Its most relevant features are: a
bytecode compiler and interpreter, being able to compile Common Lisp with any
C/C++ compiler, being able to build standalone executables and libraries, and
supporting ASDF, Sockets, Gray streams, MOP, and other useful components.")
    ;; Note that the file "Copyright" points to some files and directories
    ;; which aren't under the lgpl2.0+ and instead contain many different,
    ;; non-copyleft licenses.
    (license license:lgpl2.0+)))

(define-public clisp
  (package
    (name "clisp")
    (version "2.49")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://gnu/clisp/release/" version
                           "/clisp-" version ".tar.gz"))
       (sha256
        (base32 "0rp82nqp5362isl9i34rwgg04cidz7izljd9d85pqcw1qr964bxx"))))
    (build-system gnu-build-system)
    (inputs `(("libffcall" ,libffcall)
              ("readline" ,readline)
              ("libsigsegv" ,libsigsegv)))
    (arguments
     '(;; XXX The custom configure script does not cope well when passed
       ;; --build=<triplet>.
       #:build #f
       #:phases
       (alist-cons-after
        'unpack 'patch-sh-and-pwd
        (lambda _
          ;; The package is very messy with its references to "/bin/sh" and
          ;; some other absolute paths to traditional tools.  These appear in
          ;; many places where our automatic patching misses them.  Therefore
          ;; we do the following, in this early (post-unpack) phase, to solve
          ;; the problem from its root.
          (substitute* (find-files "." "configure|Makefile")
            (("/bin/sh") "sh"))
          (substitute* '("src/clisp-link.in")
            (("/bin/pwd") "pwd")))
        (alist-cons-before
         'build 'chdir-to-source
         (lambda _
           ;; We are supposed to call make under the src sub-directory.
           (chdir "src"))
         %standard-phases))
       ;; Makefiles seem to have race conditions.
       #:parallel-build? #f))
    (home-page "http://www.clisp.org/")
    (synopsis "A Common Lisp implementation")
    (description
     "GNU CLISP is an implementation of ANSI Common Lisp.  Common Lisp is a
high-level, object-oriented functional programming language.  CLISP includes
an interpreter, a compiler, a debugger, and much more.")
    ;; Website says gpl2+, COPYRIGHT file says gpl2; actual source files have
    ;; a lot of gpl3+.  (Also some parts are under non-copyleft licenses, such
    ;; as CLX by Texas Instruments.)  In that case gpl3+ wins out.
    (license license:gpl3+)))

(define-public sbcl
  (package
    (name "sbcl")
    (version "1.3.7")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/sbcl/sbcl/" version "/sbcl-"
                           version "-source.tar.bz2"))
       (sha256
        (base32 "0fjdqnb2rsm2vi9794ywp27jr239ddvzc4xfr0dk49jd4v7p2kc5"))))
    (build-system gnu-build-system)
    (outputs '("out" "doc"))
    ;; Bootstrap with CLISP.
    (native-inputs
     `(("clisp" ,clisp)
       ("which" ,which)
       ("inetutils" ,inetutils)         ;for hostname(1)
       ("ed" ,ed)
       ("texlive" ,texlive)
       ("texinfo" ,texinfo)))
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (add-before 'build 'patch-unix-tool-paths
           (lambda* (#:key outputs inputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out"))
                   (bash (assoc-ref inputs "bash"))
                   (coreutils (assoc-ref inputs "coreutils"))
                   (ed (assoc-ref inputs "ed")))
               (define (quoted-path input path)
                 (string-append "\"" input path "\""))
               ;; Patch absolute paths in string literals.  Note that this
               ;; occurs in some .sh files too (which contain Lisp code).  Use
               ;; ISO-8859-1 because some of the files are ISO-8859-1 encoded.
               (with-fluids ((%default-port-encoding #f))
                 ;; The removed file is utf-16-be encoded, which gives substitute*
                 ;; trouble. It does not contain references to the listed programs.
                 (substitute* (delete
                               "./tests/data/compile-file-pos-utf16be.lisp"
                               (find-files "." "\\.(lisp|sh)$"))
                   (("\"/bin/sh\"") (quoted-path bash "/bin/sh"))
                   (("\"/usr/bin/env\"") (quoted-path coreutils "/usr/bin/env"))
                   (("\"/bin/cat\"") (quoted-path coreutils "/bin/cat"))
                   (("\"/bin/ed\"") (quoted-path ed "/bin/ed"))
                   (("\"/bin/echo\"") (quoted-path coreutils "/bin/echo"))
                   (("\"/bin/uname\"") (quoted-path coreutils "/bin/uname"))))
               ;; This one script has a non-string occurrence of /bin/sh.
               (substitute* '("tests/foreign.test.sh")
                 ;; Leave whitespace so we don't match the shebang.
                 ((" /bin/sh ") " sh "))
               ;; This file contains a module that can create executable files
               ;; which depend on the presence of SBCL.  It generates shell
               ;; scripts doing "exec sbcl ..." to achieve this.  We patch both
               ;; the shebang and the reference to "sbcl", tying the generated
               ;; executables to the exact SBCL package that generated them.
               (substitute* '("contrib/sb-executable/sb-executable.lisp")
                 (("/bin/sh") (string-append bash "/bin/sh"))
                 (("exec sbcl") (string-append "exec " out "/bin/sbcl")))
               ;; Disable some tests that fail in our build environment.
               (substitute* '("contrib/sb-bsd-sockets/tests.lisp")
                 ;; This requires /etc/protocols.
                 (("\\(deftest get-protocol-by-name/error" all)
                  (string-append "#+nil ;disabled by Guix\n" all)))
               (substitute* '("contrib/sb-posix/posix-tests.lisp")
                 ;; These assume some users/groups which we don't have.
                 (("\\(deftest pwent\\.[12]" all)
                  (string-append "#+nil ;disabled by Guix\n" all))
                 (("\\(deftest grent\\.[12]" all)
                  (string-append "#+nil ;disabled by Guix\n" all))))))
         (replace 'build
           (lambda* (#:key outputs #:allow-other-keys)
             (setenv "CC" "gcc")
             (zero? (system* "sh" "make.sh" "clisp"
                             (string-append "--prefix="
                                            (assoc-ref outputs "out"))))))
         (replace 'install
           (lambda _
             (zero? (system* "sh" "install.sh"))))
         (add-after 'build 'build-doc
           (lambda _
             (with-directory-excursion "doc/manual"
               (and  (zero? (system* "make" "info"))
                     (zero? (system* "make" "dist"))))))
         (add-after 'install 'install-doc
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (doc (assoc-ref outputs "doc"))
                    (old-doc-dir (string-append out "/share/doc"))
                    (new-doc/sbcl-dir (string-append doc "/share/doc/sbcl")))
               (rmdir (string-append old-doc-dir "/sbcl/html"))
               (mkdir-p new-doc/sbcl-dir)
               (copy-recursively (string-append old-doc-dir "/sbcl")
                                 new-doc/sbcl-dir)
               (delete-file-recursively old-doc-dir)
               #t))))
         ;; No 'check' target, though "make.sh" (build phase) runs tests.
         #:tests? #f))
    (home-page "http://www.sbcl.org/")
    (synopsis "Common Lisp implementation")
    (description "Steel Bank Common Lisp (SBCL) is a high performance Common
Lisp compiler.  In addition to the compiler and runtime system for ANSI Common
Lisp, it provides an interactive environment including a debugger, a
statistical profiler, a code coverage tool, and many other extensions.")
    ;; Public domain in jurisdictions that allow it, bsd-2 otherwise.  MIT
    ;; loop macro has its own license.  See COPYING file for further notes.
    (license (list license:public-domain license:bsd-2
                   (license:x11-style "file://src/code/loop.lisp")))))

(define-public ccl
  (package
    (name "ccl")
    (version "1.11")
    (source #f)
    (build-system gnu-build-system)
    ;; CCL consists of a "lisp kernel" and "heap image", both of which are
    ;; shipped in precompiled form in source tarballs.  The former is a C
    ;; program which we can rebuild from scratch, but the latter cannot be
    ;; generated without an already working copy of CCL, and is platform
    ;; dependent, so we need to fetch the correct tarball for the platform.
    (inputs
     `(("ccl"
        ,(origin
           (method url-fetch)
           (uri (string-append
                 "ftp://ftp.clozure.com/pub/release/" version
                 "/ccl-" version "-"
                 (match (%current-system)
                   ((or "i686-linux" "x86_64-linux") "linuxx86")
                   ("armhf-linux" "linuxarm")
                   ;; Prevent errors when querying this package on unsupported
                   ;; platforms, e.g. when running "guix package --search="
                   (_ "UNSUPPORTED"))
                 ".tar.gz"))
           (sha256
            (base32
             (match (%current-system)
               ((or "i686-linux" "x86_64-linux")
                "0w3dmj7q9kqyra3yrf1lxclnjz151yvf5s5q8ayllvmvqbl8bs08")
               ("armhf-linux"
                "1x487aaz2rqcb6k301sy2p39a1m4qdhg6z9p9fb76ssipqgr38b4")
               (_ ""))))))))
    (native-inputs
     `(("m4" ,m4)
       ("subversion" ,subversion)))
    (arguments
     `(#:tests? #f                      ;no 'check' target
       #:phases
       (alist-replace
        'unpack
        (lambda* (#:key inputs #:allow-other-keys)
          (and (zero? (system* "tar" "xzvf" (assoc-ref inputs "ccl")))
               (begin (chdir "ccl") #t)))
        (alist-delete
         'configure
         (alist-cons-before
          'build 'pre-build
          ;; Enter the source directory for the current platform's lisp
          ;; kernel, and run 'make clean' to remove the precompiled one.
          (lambda _
            (chdir (string-append
                    "lisp-kernel/"
                    ,(match (or (%current-target-system) (%current-system))
                       ("i686-linux"   "linuxx8632")
                       ("x86_64-linux" "linuxx8664")
                       ("armhf-linux"  "linuxarm")
                       ;; Prevent errors when querying this package
                       ;; on unsupported platforms, e.g. when running
                       ;; "guix package --search="
                       (_              "UNSUPPORTED"))))
            (substitute* '("Makefile")
              (("/bin/rm") "rm"))
            (setenv "CC" "gcc")
            (zero? (system* "make" "clean")))
          ;; XXX Do we need to recompile the heap image as well for Guix?
          ;; For now just use the one we already got in the tarball.
          (alist-replace
           'install
           (lambda* (#:key outputs inputs #:allow-other-keys)
             ;; The lisp kernel built by running 'make' in lisp-kernel/$system
             ;; is put back into the original directory, so go back.  The heap
             ;; image is there as well.
             (chdir "../..")
             (let* ((out (assoc-ref outputs "out"))
                    (libdir (string-append out "/lib/"))
                    (bindir (string-append out "/bin/"))
                    (wrapper (string-append bindir "ccl"))
                    (bash (assoc-ref inputs "bash"))
                    (kernel
                     ,(match (or (%current-target-system) (%current-system))
                        ("i686-linux"   "lx86cl")
                        ("x86_64-linux" "lx86cl64")
                        ("armhf-linux"  "armcl")
                        ;; Prevent errors when querying this package
                        ;; on unsupported platforms, e.g. when running
                        ;; "guix package --search="
                        (_              "UNSUPPORTED")))
                    (heap (string-append kernel ".image")))
               (mkdir-p libdir)
               (mkdir-p bindir)
               (copy-file kernel (string-append libdir kernel))
               (copy-file heap (string-append libdir heap))
               (with-output-to-file wrapper
                 (lambda ()
                   (display
                    (string-append
                     "#!" bash "/bin/sh\n"
                     "if [ -z \"$CCL_DEFAULT_DIRECTORY\" ]; then\n"
                     "    CCL_DEFAULT_DIRECTORY=" libdir "\n"
                     "fi\n"
                     "export CCL_DEFAULT_DIRECTORY\n"
                     "exec " libdir kernel "\n"))))
               (chmod wrapper #o755)))
           %standard-phases))))))
    (supported-systems '("i686-linux" "x86_64-linux" "armhf-linux"))
    (home-page "http://ccl.clozure.com/")
    (synopsis "Common Lisp implementation")
    (description "Clozure CL (often called CCL for short) is a Common Lisp
implementation featuring fast compilation speed, native threads, a precise,
generational, compacting garbage collector, and a convenient foreign-function
interface.")
    ;; See file doc/LICENSE for clarifications it makes regarding how the LGPL
    ;; applies to Lisp code according to them.
    (license (list license:lgpl2.1
                   license:clarified-artistic)))) ;TRIVIAL-LDAP package

(define-public lispf4
  (let ((commit "174d8764d2f9764e8f4794c2e3feada9f9c1f1ba"))
    (package
      (name "lispf4")
      (version (string-append "0.0.0-1" "-"
                              (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/blakemcbride/LISPF4.git")
                      (commit commit)))
                (file-name (string-append name "-" version))
                (sha256
                 (base32
                  "18k8kfn30za637y4bfbm9x3vv4psa3q8f7bi9h4h0qlb8rz8m92c"))))
      (build-system gnu-build-system)
      ;; 80 MB appended Documentation -> output:doc
      (outputs '("out" "doc"))
      (arguments
       `(#:make-flags
         '("-f" "Makefile.unx" "CC=gcc")
         ;; no check phase
         #:tests? #f
         #:phases
         (modify-phases %standard-phases
           (delete 'configure)
           (replace
            'install
            (lambda* (#:key outputs inputs #:allow-other-keys)
              (let* ((out (assoc-ref outputs "out"))
                     (bin (string-append out "/bin"))
                     (doc (string-append (assoc-ref outputs "doc")
                                         "/share/doc/lispf4")))
                (install-file "lispf4" bin)
                (install-file "SYSATOMS" bin)
                (install-file "BASIC.IMG" bin)
                (copy-recursively "Documentation" doc))
                #t)))))
      (synopsis "InterLisp interpreter")
      (description
       "LISPF4 is an InterLisp interpreter written in FORTRAN by Mats Nordstrom
in the early 80's.  It was converted to C by Blake McBride and supports much of
the InterLisp Standard.")
      (home-page "https://github.com/blakemcbride/LISPF4.git")
      (license license:expat))))
