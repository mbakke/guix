;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Taylan Ulrich Bayırlı/Kammer <taylanbayirli@gmail.com>
;;; Copyright © 2015, 2016 Federico Beffa <beffa@fbengineering.ch>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Jan Nieuwenhuizen <janneke@gnu.org>
;;; Copyright © 2016 ng0 <ng0@we.make.ritual.n0.is>
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

(define-module (gnu packages scheme)
  #:use-module (gnu packages)
  #:use-module ((guix licenses)
                #:select (gpl2+ lgpl2.0+ lgpl2.1+ asl2.0 bsd-3
                          cc-by-sa4.0))
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages m4)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages emacs)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages netpbm)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages base)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages avahi)
  #:use-module (gnu packages libphidget)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages image)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages gl)
  #:use-module (ice-9 match))

(define (mit-scheme-source-directory system version)
  (string-append "mit-scheme-"
                 (if (or (string-prefix? "x86_64" system)
                         (string-prefix? "i686" system))
                     ""
                     "c-")
                 version))

(define-public mit-scheme
  (package
    (name "mit-scheme")
    (version "9.2")
    (source #f)                                   ; see below
    (outputs '("out" "doc"))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f                                ; no "check" target
       #:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (srfi srfi-1))
       #:phases
       (modify-phases %standard-phases
         (replace 'unpack
           (lambda* (#:key inputs #:allow-other-keys)
             (and (zero? (system* "tar" "xzvf"
                                  (assoc-ref inputs "source")))
                  (chdir ,(mit-scheme-source-directory (%current-system)
                                                       version))
                  (begin
                    ;; Delete these dangling symlinks since they break
                    ;; `patch-shebangs'.
                    (for-each delete-file
                              (append '("src/lib/shim-config.scm")
                                      (find-files "src/lib/lib" "\\.so$")
                                      (find-files "src/lib" "^liarc-")
                                      (find-files "src/compiler" "^make\\.")))
                    (chdir "src")
                    #t))))
         (replace 'build
           (lambda* (#:key system outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (if (or (string-prefix? "x86_64" system)
                       (string-prefix? "i686" system))
                   (zero? (system* "make" "compile-microcode"))
                   (zero? (system* "./etc/make-liarc.sh"
                                   (string-append "--prefix=" out)))))))
         (add-after 'configure 'configure-doc
           (lambda* (#:key outputs inputs #:allow-other-keys)
             (with-directory-excursion "../doc"
               (let* ((out (assoc-ref outputs "out"))
                      (bash (assoc-ref inputs "bash"))
                      (bin/sh (string-append bash "/bin/sh")))
                 (system* bin/sh "./configure"
                          (string-append "--prefix=" out)
                          (string-append "SHELL=" bin/sh))
                 (substitute* '("Makefile" "make-common")
                   (("/lib/mit-scheme/doc")
                    (string-append "/share/doc/" ,name "-" ,version)))
                 #t))))
         (add-after 'build 'build-doc
           (lambda* _
             (with-directory-excursion "../doc"
               (zero? (system* "make")))))
         (add-after 'install 'install-doc
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (doc (assoc-ref outputs "doc"))
                    (old-doc-dir (string-append out "/share/doc"))
                    (new-doc/mit-scheme-dir
                     (string-append doc "/share/doc/" ,name "-" ,version)))
               (with-directory-excursion "../doc"
                 (for-each (lambda (target)
                             (system* "make" target))
                           '("install-config" "install-info-gz" "install-man"
                             "install-html" "install-pdf")))
               (mkdir-p new-doc/mit-scheme-dir)
               (copy-recursively
                (string-append old-doc-dir "/" ,name "-" ,version)
                new-doc/mit-scheme-dir)
               (delete-file-recursively old-doc-dir)
               #t))))))
    (native-inputs
     `(("texlive" ,texlive)
       ("texinfo" ,texinfo)
       ("m4" ,m4)))
    (inputs
     `(("libx11" ,libx11)

       ("source"

        ;; MIT/GNU Scheme is not bootstrappable, so it's recommended to
        ;; compile from the architecture-specific tarballs, which contain
        ;; pre-built binaries.  It leads to more efficient code than when
        ;; building the tarball that contains generated C code instead of
        ;; those binaries.
        ,(origin
          (method url-fetch)
          (uri (string-append "mirror://gnu/mit-scheme/stable.pkg/"
                              version "/mit-scheme-"
                              (match (%current-system)
                                ("x86_64-linux"
                                 (string-append version "-x86-64"))
                                ("i686-linux"
                                 (string-append version "-i386"))
                                (_
                                 (string-append "c-" version)))
                              ".tar.gz"))
          (sha256
           (match (%current-system)
             ("x86_64-linux"
              (base32
               "1skzxxhr0iq96bf0j5m7mvf3i4sppfyfa6gpqn34mwgkw1fx8274"))
             ("i686-linux"
              (base32
               "1fmlpnhf5a75db93phajh4ysbdgrgl72v45lk3kznriprl0a7jc6"))
             (_
              (base32
               "0w5ib5vsidihb4hb6fma3sp596ykr8izagm57axvgd6lqzwicsjg"))))))))

    ;; Fails to build on MIPS, see <http://bugs.gnu.org/18221>.
    (supported-systems (delete "mips64el-linux" %supported-systems))

    (home-page "http://www.gnu.org/software/mit-scheme/")
    (synopsis "A Scheme implementation with integrated editor and debugger")
    (description
     "GNU/MIT Scheme is an implementation of the Scheme programming
language.  It provides an interpreter, a compiler and a debugger.  It also
features an integrated Emacs-like editor and a large runtime library.")
    (license gpl2+)
    (properties '((ftp-directory . "/gnu/mit-scheme/stable.pkg")))))

(define-public bigloo
  (package
    (name "bigloo")
    (version "4.1a")
    (source (origin
             (method url-fetch)
             (uri (string-append "ftp://ftp-sop.inria.fr/indes/fp/Bigloo/bigloo"
                                 version ".tar.gz"))
             (sha256
              (base32
               "170q7nh08n4v20xl81fxb0xcdxphqqacfa643hsa8i2ar6pki04c"))
             (patches (search-patches "bigloo-gc-shebangs.patch"))))
    (build-system gnu-build-system)
    (arguments
     `(#:test-target "test"
       #:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)

             (substitute* "configure"
               (("^shell=.*$")
                (string-append "shell=" (which "bash") "\n")))

             ;; Since libgc's pthread redirects are used, we end up
             ;; using libgc symbols, so we must link against it.
             ;; Reported on 2013-06-25.
             (substitute* "api/pthread/src/Makefile"
               (("^EXTRALIBS[[:blank:]]*=(.*)$" _ value)
                (string-append "EXTRALIBS = "
                               (string-trim-right value)
                               " -l$(GCLIB)_fth-$(RELEASE)"
                               " -Wl,-rpath=" (assoc-ref outputs "out")
                               "/lib/bigloo/" ,version)))

             ;; Those variables are used by libgc's `configure'.
             (setenv "SHELL" (which "sh"))
             (setenv "CONFIG_SHELL" (which "sh"))

             ;; ... but they turned out to be overridden later, so work
             ;; around that.
             (substitute* (find-files "gc" "^configure-gc")
               (("sh=/bin/sh")
                (string-append "sh=" (which "sh"))))

             ;; The `configure' script doesn't understand options
             ;; of those of Autoconf.
             (let ((out (assoc-ref outputs "out")))
               (zero?
                (system* "./configure"
                         (string-append "--prefix=" out)
                         ;; FIXME: Currently fails, see
                         ;; <http://article.gmane.org/gmane.lisp.scheme.bigloo/6126>.
                         ;; "--customgc=no" ; use our libgc
                         (string-append"--mv=" (which "mv"))
                         (string-append "--rm=" (which "rm"))
                         (string-append "--ldflags=-Wl,-rpath="
                                        (assoc-ref outputs "out")
                                        "/lib/bigloo/" ,version))))))
         (add-after 'install 'install-emacs-modes
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (dir (string-append out "/share/emacs/site-lisp")))
               (zero? (system* "make" "-C" "bmacs" "all" "install"
                               (string-append "EMACSBRAND=emacs24")
                               (string-append "EMACSDIR=" dir)))))))))
    (inputs
     `(("emacs" ,emacs)                      ;UDE needs the X version of Emacs

       ;; Optional APIs for which Bigloo has bindings.
       ("avahi" ,avahi)
       ("libphidget" ,libphidget)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("gmp" ,gmp)))                             ; bigloo.h refers to gmp.h
    (home-page "http://www-sop.inria.fr/indes/fp/Bigloo/")
    (synopsis "Efficient Scheme compiler")
    (description
     "Bigloo is a Scheme implementation devoted to one goal: enabling
Scheme based programming style where C(++) is usually
required.  Bigloo attempts to make Scheme practical by offering
features usually presented by traditional programming languages
but not offered by Scheme and functional programming.  Bigloo
compiles Scheme modules.  It delivers small and fast stand alone
binary executables.  Bigloo enables full connections between
Scheme and C programs and between Scheme and Java programs.")
    (license gpl2+)))

(define-public hop
  (package
    (name "hop")
    (version "2.5.1")
    (source (origin
             (method url-fetch)
             (uri (string-append "ftp://ftp-sop.inria.fr/indes/fp/Hop/hop-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "1bvp7pc71bln5yvfj87s8750c6l53wjl6f8m12v62q9926adhwys"))
             (patches (search-patches "hop-linker-flags.patch"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (zero?
                (system* "./configure"
                         (string-append "--prefix=" out)
                         (string-append "--blflags="
                                        ;; user flags completely override useful
                                        ;; default flags, so repeat them here.
                                        "-copt \\$(CPICFLAGS) -L\\$(BUILDLIBDIR) "
                                        "-ldopt -Wl,-rpath," out "/lib")))))))
       #:tests? #f))                                ; no test suite
    (inputs `(("avahi" ,avahi)
              ("bigloo" ,bigloo)
              ("which" ,which)))
    (home-page "http://hop.inria.fr/")
    (synopsis "Multi-tier programming language for the Web 2.0")
    (description
     "HOP is a multi-tier programming language for the Web 2.0 and the
so-called diffuse Web.  It is designed for programming interactive web
applications in many fields such as multimedia (web galleries, music players,
...), ubiquitous and house automation (SmartPhones, personal appliance),
mashups, office (web agendas, mail clients, ...), etc.")
    (license gpl2+)))

(define-public chicken
  (package
    (name "chicken")
    (version "4.11.0")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://code.call-cc.org/releases/"
                                 version "/chicken-" version ".tar.gz"))
             (sha256
              (base32
               "12ddyiikqknpr8h6llsxbg2fz75xnayvcnsvr1cwv8xnjn7jpp73"))))
    (build-system gnu-build-system)
    (arguments
     `(#:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (srfi srfi-1))

       ;; No `configure' script; run "make check" after "make install" as
       ;; prescribed by README.
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (delete 'check)
         (add-after 'install 'check
           (assoc-ref %standard-phases 'check))
         (add-after 'unpack 'disable-broken-tests
           (lambda _
             ;; The port tests fail with this error:
             ;; Error: (line 294) invalid escape-sequence '\x o'
             (substitute* "tests/runtests.sh"
               (("\\$interpret -s port-tests\\.scm") ""))
             #t)))

       #:make-flags (let ((out (assoc-ref %outputs "out")))
                      (list "PLATFORM=linux"
                            (string-append "PREFIX=" out)
                            (string-append "VARDIR=" out "/var/lib")))

       ;; Parallel builds are not supported, as noted in README.
       #:parallel-build? #f))
    ;; One of the tests ("testing direct invocation can detect calls of too
    ;; many arguments...") times out when building with a more recent GCC.
    ;; The problem was reported here:
    ;; https://lists.gnu.org/archive/html/chicken-hackers/2015-04/msg00059.html
    (native-inputs
     `(("gcc" ,gcc-4.8)))
    (home-page "http://www.call-cc.org/")
    (synopsis "R5RS Scheme implementation that compiles native code via C")
    (description
     "CHICKEN is a compiler for the Scheme programming language.  CHICKEN
produces portable and efficient C, supports almost all of the R5RS Scheme
language standard, and includes many enhancements and extensions.")
    (license bsd-3)))

(define-public scheme48
  (package
    (name "scheme48")
    (version "1.9.2")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://s48.org/" version
                                 "/scheme48-" version ".tgz"))
             (sha256
              (base32
               "1x4xfm3lyz2piqcw1h01vbs1iq89zq7wrsfjgh3fxnlm1slj2jcw"))
             (patches (search-patches "scheme48-tests.patch"))))
    (build-system gnu-build-system)
    (home-page "http://s48.org/")
    (synopsis "Scheme implementation using a bytecode interpreter")
    (description
     "Scheme 48 is an implementation of Scheme based on a byte-code
interpreter and is designed to be used as a testbed for experiments in
implementation techniques and as an expository tool.")

    ;; Most files are BSD-3; see COPYING for the few exceptions.
    (license bsd-3)))

(define-public racket
  (package
    (name "racket")
    (version "6.6")
    (source (origin
             (method url-fetch)
             (uri (list (string-append "http://mirror.racket-lang.org/installers/"
                                       version "/racket-" version "-src.tgz")
                        (string-append
                         "http://mirror.informatik.uni-tuebingen.de/mirror/racket/"
                         version "/racket/racket-" version "-src-unix.tgz")))
             (sha256
              (base32
               "1kzdi1n6h6hmz8zd9k8r5a5yp2ryi4w3c2fjm1k6cqicn18cwaxz"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (alist-cons-before
        'configure 'pre-configure
        (lambda* (#:key inputs #:allow-other-keys)
          ;; Patch dynamically loaded libraries with their absolute paths.
          (let* ((library-path   (search-path-as-string->list
                                  (getenv "LIBRARY_PATH")))
                 (find-so        (lambda (soname)
                                   (search-path
                                    library-path
                                    (format #f "~a.so" soname))))
                 (patch-ffi-libs (lambda (file libs)
                                   (for-each
                                    (lambda (lib)
                                      (substitute* file
                                        (((format #f "\"~a\"" lib))
                                         (format #f "\"~a\"" (find-so lib)))))
                                    libs))))
            (substitute* "collects/db/private/sqlite3/ffi.rkt"
              (("ffi-lib sqlite-so")
               (format #f "ffi-lib \"~a\"" (find-so "libsqlite3"))))
            (substitute* "collects/openssl/libssl.rkt"
              (("ffi-lib libssl-so")
               (format #f "ffi-lib \"~a\"" (find-so "libssl"))))
            (substitute* "collects/openssl/libcrypto.rkt"
              (("ffi-lib libcrypto-so")
               (format #f "ffi-lib \"~a\"" (find-so "libcrypto"))))
            (substitute* "share/pkgs/math-lib/math/private/bigfloat/gmp.rkt"
              (("ffi-lib libgmp-so")
               (format #f "ffi-lib \"~a\"" (find-so "libgmp"))))
            (substitute* "share/pkgs/math-lib/math/private/bigfloat/mpfr.rkt"
              (("ffi-lib libmpfr-so")
               (format #f "ffi-lib \"~a\"" (find-so "libmpfr"))))
            (for-each
             (lambda (x) (apply patch-ffi-libs x))
             '(("share/pkgs/draw-lib/racket/draw/unsafe/cairo-lib.rkt"
                ("libfontconfig" "libcairo"))
               ("share/pkgs/draw-lib/racket/draw/unsafe/glib.rkt"
                ("libglib-2.0" "libgmodule-2.0" "libgobject-2.0"))
               ("share/pkgs/draw-lib/racket/draw/unsafe/jpeg.rkt"
                ("libjpeg"))
               ("share/pkgs/draw-lib/racket/draw/unsafe/pango.rkt"
                ("libpango-1.0" "libpangocairo-1.0"))
               ("share/pkgs/draw-lib/racket/draw/unsafe/png.rkt"
                ("libpng"))
               ("share/pkgs/db-lib/db/private/odbc/ffi.rkt"
                ("libodbc"))
               ("share/pkgs/gui-lib/mred/private/wx/gtk/x11.rkt"
                ("libX11"))
               ("share/pkgs/gui-lib/mred/private/wx/gtk/gsettings.rkt"
                ("libgio-2.0"))
               ("share/pkgs/gui-lib/mred/private/wx/gtk/gtk3.rkt"
                ("libgdk-3" "libgtk-3"))
               ("share/pkgs/gui-lib/mred/private/wx/gtk/unique.rkt"
                ("libunique-1.0"))
               ("share/pkgs/gui-lib/mred/private/wx/gtk/utils.rkt"
                ("libgdk-x11-2.0" "libgdk_pixbuf-2.0" "libgtk-x11-2.0"))
               ("share/pkgs/gui-lib/mred/private/wx/gtk/gl-context.rkt"
                ("libGL"))
               ("share/pkgs/sgl/gl.rkt"
                ("libGL" "libGLU")))))
          (chdir "src"))
        (alist-cons-after
         'unpack 'patch-/bin/sh
         (lambda _
           (substitute* "collects/racket/system.rkt"
             (("/bin/sh") (which "sh"))))
         %standard-phases))
       #:tests? #f                                ; XXX: how to run them?
       ))
    (inputs
     `(("libffi" ,libffi)
       ;; Hardcode dynamically loaded libraries for better functionality.
       ;; sqlite and libraries for `racket/draw' are needed to build the doc.
       ("cairo" ,cairo)
       ("fontconfig" ,fontconfig)
       ("glib" ,glib)
       ("glu" ,glu)
       ("gmp" ,gmp)
       ("gtk+" ,gtk+)  ; propagates gdk-pixbuf+svg
       ("libjpeg" ,libjpeg)
       ("libpng" ,libpng)
       ("libx11" ,libx11)
       ("mesa" ,mesa)
       ("mpfr" ,mpfr)
       ("openssl" ,openssl)
       ("pango" ,pango)
       ("sqlite" ,sqlite)
       ("unixodbc" ,unixodbc)))
    (home-page "http://racket-lang.org")
    (synopsis "Implementation of Scheme and related languages")
    (description
     "Racket is an implementation of the Scheme programming language (R5RS and
R6RS) and related languages, such as Typed Racket.  It features a compiler and
a virtual machine with just-in-time native compilation, as well as a large set
of libraries.")
    (license lgpl2.0+)))

(define-public gambit-c
  (package
    (name "gambit-c")
    (version "4.8.5")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "http://www.iro.umontreal.ca/~gambit/download/gambit/v"
             (version-major+minor version) "/source/gambit-v"
             (string-map (lambda (c) (if (char=? c #\.) #\_ c)) version)
             ".tgz"))
       (sha256
        (base32 "0xwmqzqvk83xyjz48vp36p5vj1415rl3pi3xq7y8i3p8s409a98b"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags
       ;; According to the ./configure script, this makes the build slower and
       ;; use >= 1 GB memory, but makes Gambit much faster.
       '("--enable-single-host")
       #:phases
       (modify-phases %standard-phases
         (add-before 'check 'fix-tests
           (lambda _
             (substitute* '("tests/makefile")
               ;; '-:' is how run-time options are set.  'tl' sets some terminal
               ;; option, which makes it fail in our build environment.  It
               ;; recommends using 'd-' as a solution, which sets the REPL
               ;; interaction channel to stdin/stdout.
               (("gsi -:tl") "gsi -:d-,tl"))
             #t)))))
    (home-page "http://www.iro.umontreal.ca/~gambit/")
    (synopsis "Efficient Scheme interpreter and compiler")
    (description
     "Gambit consists of two main programs: gsi, the Gambit Scheme
interpreter, and gsc, the Gambit Scheme compiler.  The interpreter contains
the complete execution and debugging environment.  The compiler is the
interpreter extended with the capability of generating executable files.  The
compiler can produce standalone executables or compiled modules which can be
loaded at run time.  Interpreted code and compiled code can be freely
mixed.")
    ;; Dual license.
    (license (list lgpl2.1+ asl2.0))))

(define-public chibi-scheme
  (package
    (name "chibi-scheme")
    (version "0.7.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/ashinn/chibi-scheme/archive/"
                           version ".tar.gz"))
       (sha256
        (base32 "16wppf4qzr0748iyp0m89gidsfgq9s6x3gw4xggym91waw4fh742"))
       (file-name (string-append "chibi-scheme-" version ".tar.gz"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (delete 'configure)
                  (add-before 'build 'set-cc
                    (lambda _
                      (setenv "CC" "gcc"))))
       #:make-flags (let ((out (assoc-ref %outputs "out")))
                      (list (string-append "PREFIX=" out)
                            (string-append "LDFLAGS=-Wl,-rpath=" out "/lib")))
       #:test-target "test"))
    (home-page "https://github.com/ashinn/chibi-scheme")
    (synopsis "Small embeddable Scheme implementation")
    (description
     "Chibi-Scheme is a very small library with no external dependencies
intended for use as an extension and scripting language in C programs.  In
addition to support for lightweight VM-based threads, each VM itself runs in
an isolated heap allowing multiple VMs to run simultaneously in different OS
threads.")
    (license bsd-3)))

(define-public scmutils
  (let ()
    (define (system-suffix)
      (cond
       ((string-prefix? "x86_64" (or (%current-target-system)
                                     (%current-system)))
        "x86-64")
       (else "i386")))

    (package
      (name "scmutils")
      (version "20140302")
      (source
       (origin
         (method url-fetch/tarbomb)
         (modules '((guix build utils)))
         (snippet
          ;; Remove binary code
          '(delete-file-recursively "scmutils/mit-scheme"))
         (file-name (string-append name "-" version ".tar.gz"))
         (uri (string-append "http://groups.csail.mit.edu/mac/users/gjs/6946"
                             "/scmutils-tarballs/" name "-" version
                             "-x86-64-gnu-linux.tar.gz"))
         (sha256
          (base32 "10cnbm7nh78m5mrl1di85s29gny81jb1am9zd9f9yx725xb6dnfg"))))
      (build-system gnu-build-system)
      (inputs
       `(("mit-scheme" ,mit-scheme)
         ("emacs" ,emacs-minimal)))
      (arguments
       `(#:tests? #f ;; no tests-suite
         #:modules ((guix build gnu-build-system)
                    (guix build utils)
                    (guix build emacs-utils))
         #:imported-modules (,@%gnu-build-system-modules
                             (guix build emacs-utils))
         #:phases
         (modify-phases %standard-phases
           (replace 'configure
                    ;; No standard build procedure is used. We set the correct
                    ;; runtime path in the custom build system.
                    (lambda* (#:key outputs #:allow-other-keys)
                      (let ((out (assoc-ref outputs "out")))
                        ;; Required to find .bci files at runtime.
                        (with-directory-excursion "scmutils"
                          (rename-file "src" "scmutils"))
                        (substitute* "scmutils/scmutils/load.scm"
                          (("/usr/local/scmutils/")
                           (string-append out "/lib/mit-scheme-"
                                          ,(system-suffix) "/")))
                        #t)))
           (replace 'build
                    ;; Compile the code and build a band.
                    (lambda* (#:key outputs #:allow-other-keys)
                      (let* ((out (assoc-ref outputs "out"))
                             (make-img (string-append
                                        "echo '(load \"load\") "
                                        "(disk-save \"edwin-mechanics.com\")'"
                                        "| mit-scheme")))
                        (with-directory-excursion "scmutils/scmutils"
                          (and (zero? (system "mit-scheme < compile.scm"))
                               (zero? (system make-img)))))))
           (add-before 'install 'fix-directory-names
                       ;; Correct directory names in the startup script.
                       (lambda* (#:key inputs outputs #:allow-other-keys)
                         (let* ((out (assoc-ref outputs "out"))
                                (scm-root (assoc-ref inputs "mit-scheme")))
                           (substitute* "bin/mechanics"
                             (("ROOT=\"\\$\\{SCMUTILS_ROOT:-/.*\\}\"")
                              (string-append
                               "ROOT=\"${SCMUTILS_ROOT:-" scm-root "}\"\n"
                               "LIB=\"${ROOT}/lib/mit-scheme-"
                               ,(system-suffix) ":"
                               out "/lib/mit-scheme-" ,(system-suffix) "\""))
                             (("EDWIN_INFO_DIRECTORY=.*\n") "")
                             (("SCHEME=.*\n")
                              (string-append "SCHEME=\"${ROOT}/bin/scheme "
                                             "--library ${LIB}\"\n"))
                             (("export EDWIN_INFO_DIRECTORY") ""))
                           #t)))
           (add-before 'install 'emacs-tags
                       ;; Generate Emacs's tags for easy reference to source
                       ;; code.
                       (lambda* (#:key inputs outputs #:allow-other-keys)
                         (with-directory-excursion "scmutils/scmutils"
                           (zero? (apply system* "etags"
                                         (find-files "." "\\.scm"))))))
           (replace 'install
                    ;; Copy files to the store.
                    (lambda* (#:key outputs #:allow-other-keys)
                      (define* (copy-files-to-directory files dir
                                                        #:optional (delete? #f))
                        (for-each (lambda (f)
                                    (copy-file f (string-append dir "/" f))
                                    (when delete? (delete-file f)))
                                  files))

                      (let* ((out (assoc-ref outputs "out"))
                             (bin (string-append out "/bin"))
                             (doc (string-append out "/share/doc/"
                                                 ,name "-" ,version))
                             (lib (string-append out "/lib/mit-scheme-"
                                                 ,(system-suffix)
                                                 "/scmutils")))
                        (for-each mkdir-p (list lib doc bin))
                        (with-directory-excursion "scmutils/scmutils"
                          (copy-files-to-directory '("COPYING" "LICENSE")
                                                   doc #t)
                          (for-each delete-file (find-files "." "\\.bin"))
                          (copy-files-to-directory '("edwin-mechanics.com")
                                                   (string-append lib "/..") #t)
                          (copy-recursively "." lib))
                        (with-directory-excursion "bin"
                          (copy-files-to-directory (find-files ".") bin))
                        (with-directory-excursion "scmutils/manual"
                          (copy-files-to-directory (find-files ".") doc))
                        #t)))
           (add-after 'install 'emacs-helpers
                      ;; Add convenience Emacs commands to easily load the
                      ;; Scmutils band in an MIT-Scheme buffer inside of Emacs
                      ;; and to easily load code tags.
                      (lambda* (#:key inputs outputs #:allow-other-keys)
                        (let* ((out (assoc-ref outputs "out"))
                               (mit-root (assoc-ref inputs "mit-scheme"))
                               (emacs-lisp-dir
                                (string-append out "/share/emacs/site-lisp"
                                               "/guix.d/" ,name "-" ,version))
                               (el-file (string-append emacs-lisp-dir
                                                       "/scmutils.el"))
                               (lib-relative-path
                                (string-append "/lib/mit-scheme-"
                                               ,(system-suffix))))
                          (mkdir-p emacs-lisp-dir)
                          (call-with-output-file el-file
                            (lambda (p)
                              (format p
                                      ";;;###autoload
(defun scmutils-load ()
  (interactive)
  (require 'xscheme)
  (let ((mit-root \"~a\")
    (scmutils \"~a\"))
    (run-scheme
     (concat mit-root \"/bin/scheme --library \"
          mit-root \"~a:\" scmutils \"~a\"
          \" --band edwin-mechanics.com\"
          \" --emacs\"))))

;;;###autoload
(defun scmutils-load-tags ()
  (interactive)
  (let ((scmutils \"~a\"))
    (visit-tags-table (concat scmutils \"/TAGS\"))))
"
                                      mit-root out
                                      lib-relative-path
                                      lib-relative-path
                                      (string-append out lib-relative-path
                                                     "/scmutils"))))
                          (emacs-generate-autoloads ,name emacs-lisp-dir)
                          (emacs-byte-compile-directory emacs-lisp-dir)
                          #t))))))
      (home-page
       "http://groups.csail.mit.edu/mac/users/gjs/6946/linux-install.htm")
      (synopsis "Scmutils library for MIT Scheme")
      (description "The Scmutils system is an integrated library of
procedures, embedded in the programming language Scheme, and intended to
support teaching and research in mathematical physics and electrical
engineering.")
      (license gpl2+))))

(define-public sicp
  (let ((commit "5b52db566968d28a89fbbaf338d207f01cc81cac"))
    (package
      (name "sicp")
      (version (string-append "20160220-1." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/sarabander/sicp")
                      (commit commit)))
                (sha256
                 (base32
                  "10h6h7szwlfbshwh18bnl2hvyddj5i7106l79s145l0sjjv15cxb"))
                (file-name (string-append name "-" version "-checkout"))))
      (build-system trivial-build-system)
      (native-inputs `(("gzip" ,gzip)
                       ("source" ,source)
                       ("texinfo" ,texinfo)))
      (arguments
       `(#:modules ((guix build utils)
                    (srfi srfi-1)
                    (srfi srfi-26))
         #:builder
         (begin
           (use-modules (guix build utils)
                        (srfi srfi-1)
                        (srfi srfi-26))
           (let ((gzip (assoc-ref %build-inputs "gzip"))
                 (source (assoc-ref %build-inputs "source"))
                 (texinfo (assoc-ref %build-inputs "texinfo"))
                 (info-dir (string-append %output "/share/info")))
             (setenv "PATH" (string-append gzip "/bin"
                                           ":" texinfo "/bin"))
             (mkdir-p info-dir)
             (and (zero?
                   (system* "makeinfo" "--output"
                            (string-append info-dir "/sicp.info")
                            (string-append source "/sicp-pocket.texi")))
                  (every zero?
                         (map (cut system* "gzip" "-9n" <>)
                              (find-files info-dir))))))))
      (home-page "http://sarabander.github.io/sicp")
      (synopsis "Structure and Interpretation of Computer Programs")
      (description "Structure and Interpretation of Computer Programs (SICP) is
a textbook aiming to teach the principles of computer programming.

Using Scheme, a dialect of the Lisp programming language, the book explains
core computer science concepts such as abstraction in programming,
metalinguistic abstraction, recursion, interpreters, and modular programming.")
      (license cc-by-sa4.0))))
