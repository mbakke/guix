;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Christopher Allan Webber <cwebber@dustycloud.org>
;;; Copyright © 2016 Alex Sassmannshausen <alex@pompo.co>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Erik Edrosa <erik.edrosa@gmail.com>
;;; Copyright © 2016 Eraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Alex Kost <alezost@gmail.com>
;;; Copyright © 2016 Adonay "adfeno" Felipe Nogueira <https://libreplanet.org/wiki/User:Adfeno> <adfeno@openmailbox.org>
;;; Copyright © 2016 Amirouche <amirouche@hypermove.net>
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

(define-module (gnu packages guile)
  #:use-module (guix licenses)
  #:use-module (gnu packages)
  #:use-module (gnu packages aspell)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages bdw-gc)
  #:use-module (gnu packages gawk)
  #:use-module (gnu packages gperf)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages libunistring)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages m4)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages ed)
  #:use-module (gnu packages base)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages man)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages python)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages sdl)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages image)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xorg)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (guix utils)
  #:use-module (ice-9 match))

;;; Commentary:
;;;
;;; GNU Guile, and modules and extensions.
;;;
;;; Code:

(define-public guile-1.8
  (package
   (name "guile")
   (version "1.8.8")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/guile/guile-" version
                                ".tar.gz"))
            (sha256
             (base32
              "0l200a0v7h8bh0cwz6v7hc13ds39cgqsmfrks55b1rbj5vniyiy3"))
            (patches (search-patches "guile-1.8-cpp-4.5.patch"))))
   (build-system gnu-build-system)
   (arguments '(#:configure-flags '("--disable-error-on-warning")

                ;; Insert a phase before `configure' to patch things up.
                #:phases (alist-cons-before
                           'configure
                           'patch-stuff
                           (lambda* (#:key outputs #:allow-other-keys)
                             ;; Add a call to `lt_dladdsearchdir' so that
                             ;; `libguile-readline.so' & co. are in the
                             ;; loader's search path.
                             (substitute* "libguile/dynl.c"
                               (("lt_dlinit.*$" match)
                                (format #f
                                        "  ~a~%  lt_dladdsearchdir(\"~a/lib\");~%"
                                        match
                                        (assoc-ref outputs "out"))))

                             ;; The usual /bin/sh...
                             (substitute* "ice-9/popen.scm"
                               (("/bin/sh") (which "sh"))))
                           %standard-phases)))
   (inputs `(("gawk" ,gawk)
             ("readline" ,readline)))

   ;; Since `guile-1.8.pc' has "Libs: ... -lgmp -lltdl", these must be
   ;; propagated.
   (propagated-inputs `(("gmp" ,gmp)
                        ("libltdl" ,libltdl)))

   ;; When cross-compiling, a native version of Guile itself is needed.
   (self-native-input? #t)

   (native-search-paths
    (list (search-path-specification
           (variable "GUILE_LOAD_PATH")
           (files '("share/guile/site")))))

   (synopsis "Scheme implementation intended especially for extensions")
   (description
    "Guile is the GNU Ubiquitous Intelligent Language for Extensions, the
official extension language of the GNU system.  It is an implementation of
the Scheme language which can be easily embedded in other applications to
provide a convenient means of extending the functionality of the application
without requiring the source code to be rewritten.")
   (home-page "http://www.gnu.org/software/guile/")
   (license lgpl2.0+)))

(define-public guile-2.0
  (package
   (name "guile")
   (version "2.0.12")
   (replacement guile-2.0.13)                 ;CVE-2016-8606 and CVE-2016-8605
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/guile/guile-" version
                                ".tar.xz"))
            (sha256
             (base32
              "1sdpjq0jf1h65w29q0zprj4x6kdp5jskkvbnlwphy9lvdxrqg0fy"))))
   (build-system gnu-build-system)
   (native-inputs `(("pkgconfig" ,pkg-config)))
   (inputs `(("libffi" ,libffi)
             ("readline" ,readline)
             ,@(libiconv-if-needed)
             ,@(if (target-mingw?) '() `(("bash" ,bash)))))
   (propagated-inputs
    `( ;; These ones aren't normally needed here, but since `libguile-2.0.la'
       ;; reads `-lltdl -lunistring', adding them here will add the needed
       ;; `-L' flags.  As for why the `.la' file lacks the `-L' flags, see
       ;; <http://thread.gmane.org/gmane.comp.lib.gnulib.bugs/18903>.
      ("libunistring" ,libunistring)

      ;; Depend on LIBLTDL, not LIBTOOL.  That way, we avoid some the extra
      ;; dependencies that LIBTOOL has, which is helpful during bootstrap.
      ("libltdl" ,libltdl)

      ;; The headers and/or `guile-2.0.pc' refer to these packages, so they
      ;; must be propagated.
      ("bdw-gc" ,libgc)
      ("gmp" ,gmp)))

   (self-native-input? #t)

   (outputs '("out" "debug"))

   (arguments
    `(#:configure-flags '("--disable-static")     ;saves 3MiB
      #:phases (alist-cons-before
                'configure 'pre-configure
                (lambda* (#:key inputs #:allow-other-keys)
                  ;; Tell (ice-9 popen) the file name of Bash.
                  (let ((bash (assoc-ref inputs "bash")))
                    (substitute* "module/ice-9/popen.scm"
                      ;; If bash is #f allow fallback for user to provide
                      ;; "bash" in PATH.  This happens when cross-building to
                      ;; MinGW for which we do not have Bash yet.
                      (("/bin/sh")
                       ,@(if (target-mingw?)
                             '((if bash
                                   (string-append bash "/bin/bash")
                                   "bash"))
                             '((string-append bash "/bin/bash")))))))
                %standard-phases)))

   (native-search-paths
    (list (search-path-specification
           (variable "GUILE_LOAD_PATH")
           (files '("share/guile/site/2.0")))
          (search-path-specification
           (variable "GUILE_LOAD_COMPILED_PATH")
           (files '("lib/guile/2.0/site-ccache"
                    "share/guile/site/2.0")))))

   (synopsis "Scheme implementation intended especially for extensions")
   (description
    "Guile is the GNU Ubiquitous Intelligent Language for Extensions, the
official extension language of the GNU system.  It is an implementation of
the Scheme language which can be easily embedded in other applications to
provide a convenient means of extending the functionality of the application
without requiring the source code to be rewritten.")
   (home-page "http://www.gnu.org/software/guile/")
   (license lgpl3+)))

(define-public guile-2.0/fixed
  ;; A package of Guile 2.0 that's rarely changed.  It is the one used
  ;; in the `base' module, and thus changing it entails a full rebuild.
  (package
    (inherit guile-2.0)
    (properties '((hidden? . #t)))          ;people should install 'guile-2.0'
    (replacement #f)))

(define guile-2.0.13
  (package
    (inherit guile-2.0)
    (version "2.0.13")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/guile/guile-" version
                                  ".tar.xz"))
              (sha256
               (base32
                "12yqkr974y91ylgw6jnmci2v90i90s7h9vxa4zk0sai8vjnz4i1p"))
              (patches (search-patches "guile-repl-server-test.patch"))))))

(define-public guile-next
  (package (inherit guile-2.0)
    (name "guile-next")
    (version "2.1.5")
    (replacement #f)
    (source (origin
              (method url-fetch)
              (uri (string-append "ftp://alpha.gnu.org/gnu/guile/guile-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "0r9y4hw17dlxahik4zsccfb2f3p2a07wqndfm251bgmam9hln6gi"))
              (modules '((guix build utils)))

              ;; Remove the pre-built object files.  Instead, build everything
              ;; from source, at the expense of significantly longer build
              ;; times (almost 3 hours on a 4-core Intel i5).
              (snippet '(for-each delete-file
                                  (find-files "prebuilt" "\\.go$")))))
    (synopsis "Snapshot of what will become version 2.2 of GNU Guile")
    (properties '((timeout . 72000)               ;20 hours
                  (upstream-name . "guile")
                  (ftp-server . "alpha.gnu.org")
                  (ftp-directory . "/gnu/guile")))
    (native-search-paths
     (list (search-path-specification
            (variable "GUILE_LOAD_PATH")
            (files '("share/guile/site/2.2")))
           (search-path-specification
            (variable "GUILE_LOAD_COMPILED_PATH")
            (files '("lib/guile/2.2/site-ccache"
                     "share/guile/site/2.2")))))))

(define (guile-2.2-package-name name)
  "Return NAME with a \"guile2.2-\" prefix instead of \"guile-\", when
applicable."
  (if (string-prefix? "guile-" name)
      (string-append "guile2.2-"
                     (string-drop name
                                  (string-length "guile-")))
      name))

(define package-for-guile-2.2
  ;; A procedure that rewrites the dependency tree of the given package to use
  ;; GUILE-NEXT instead of GUILE-2.0.
  (package-input-rewriting `((,guile-2.0 . ,guile-next))
                           guile-2.2-package-name))

(define-public guile-for-guile-emacs
  (package (inherit guile-next)
    (name "guile-for-guile-emacs")
    (version "20150510.d8d9a8d")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "git://git.hcoop.net/git/bpt/guile.git")
                    (commit "d8d9a8da05ec876acba81a559798eb5eeceb5a17")))
              (sha256
               (base32
                "00sprsshy16y8pxjy126hr2adqcvvzzz96hjyjwgg8swva1qh6b0"))))
    (arguments
     (substitute-keyword-arguments `(;; Tests aren't passing for now.
                                     ;; Obviously we should re-enable this!
                                     #:tests? #f
                                     ,@(package-arguments guile-next))
       ((#:phases phases)
        `(modify-phases ,phases
           (add-after 'unpack 'autogen
                      (lambda _
                        (zero? (system* "sh" "autogen.sh"))))
           (add-before 'autogen 'patch-/bin/sh
                       (lambda _
                         (substitute* "build-aux/git-version-gen"
                           (("#!/bin/sh") (string-append "#!" (which "sh"))))
                         #t))))))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)
       ("flex" ,flex)
       ("texinfo" ,texinfo)
       ("gettext" ,gettext-minimal)
       ,@(package-native-inputs guile-next)))
    ;; Same as in guile-2.0
    (native-search-paths
     (list (search-path-specification
            (variable "GUILE_LOAD_PATH")
            (files '("share/guile/site/2.0")))
           (search-path-specification
            (variable "GUILE_LOAD_COMPILED_PATH")
            (files '("lib/guile/2.0/site-ccache"
                     "share/guile/site/2.0")))))))


;;;
;;; Extensions.
;;;

(define-public artanis
  (package
    (name "artanis")
    (version "0.1.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "ftp://alpha.gnu.org/gnu/artanis/artanis-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "19m3ak12cqk8js9d2mdg11kh4fjsq8frfpd10qw75h0zpr5cywpp"))
              (patches (search-patches "artanis-fix-Makefile.in.patch"))))
    (build-system gnu-build-system)
    ;; TODO: Add guile-dbi and guile-dbd optional dependencies.
    (inputs `(("guile" ,guile-2.0)))
    (native-inputs `(("bash"       ,bash)         ;for the `source' builtin
                     ("pkgconfig"  ,pkg-config)
                     ("util-linux" ,util-linux))) ;for the `script' command
    (arguments
     '(#:make-flags
       ;; TODO: The documentation must be built with the `docs' target.
       (let* ((out (assoc-ref %outputs "out"))
              (dir (string-append out "/share/guile/site/2.0")))
         ;; Don't use (%site-dir) for site paths.
         (list (string-append "MOD_PATH=" dir)
               (string-append "MOD_COMPILED_PATH=" dir)))
       #:test-target "test"
       #:phases
       (modify-phases %standard-phases
         (add-before
          'install 'substitute-root-dir
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((out  (assoc-ref outputs "out")))
              (substitute* "Makefile"   ;ignore the execution of bash.bashrc
                ((" /etc/bash.bashrc") " /dev/null"))
              (substitute* "Makefile"   ;set the root of config files to OUT
                ((" /etc") (string-append " " out "/etc")))
              (mkdir-p (string-append out "/bin")) ;for the `art' executable
              #t))))))
    (synopsis "Web application framework written in Guile")
    (description "GNU Artanis is a web application framework written in Guile
Scheme.  A web application framework (WAF) is a software framework that is
designed to support the development of dynamic websites, web applications, web
services and web resources.  The framework aims to alleviate the overhead
associated with common activities performed in web development.  Artanis
provides several tools for web development: database access, templating
frameworks, session management, URL-remapping for RESTful, page caching, and
more.")
    (home-page "https://www.gnu.org/software/artanis/")
    (license (list gpl3+ lgpl3+))))     ;dual license

(define-public guile-reader
  (package
    (name "guile-reader")
    (version "0.6.1")
    (source  (origin
               (method url-fetch)
               (uri (string-append "mirror://savannah/guile-reader/guile-reader-"
                                   version ".tar.gz"))
               (sha256
                (base32
                 "020wz5w8z6g79nbqifg2n496wxwkcjzh8xizpv6mz0hczpl155ma"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkgconfig" ,pkg-config)
                     ("gperf" ,gperf)))
    (inputs `(("guile" ,guile-2.0)))
    (arguments `(#:configure-flags
                 (let ((out (assoc-ref %outputs "out")))
                   (list (string-append "--with-guilemoduledir="
                                        out "/share/guile/site/2.0")))))
    (synopsis "Framework for building readers for GNU Guile")
    (description
     "Guile-Reader is a simple framework for building readers for GNU Guile.

The idea is to make it easy to build procedures that extend Guile’s read
procedure.  Readers supporting various syntax variants can easily be written,
possibly by re-using existing “token readers” of a standard Scheme
readers.  For example, it is used to implement Skribilo’s R5RS-derived
document syntax.

Guile-Reader’s approach is similar to Common Lisp’s “read table”, but
hopefully more powerful and flexible (for instance, one may instantiate as
many readers as needed).")
    (home-page "http://www.nongnu.org/guile-reader/")
    (license gpl3+)))

(define-public guile-ncurses
  (package
    (name "guile-ncurses")
    (version "2.1")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/guile-ncurses/guile-ncurses-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "1h7rnq4g7xlxxybcb3vjq6nscm9zhlmfaxb7258c8ax7him4azg6"))))
    (build-system gnu-build-system)
    (inputs `(("ncurses" ,ncurses)
              ("guile" ,guile-2.0)))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (arguments
     '(#:configure-flags (list "--with-ncursesw"  ; Unicode support
                               "--with-gnu-filesystem-hierarchy")
       #:phases
       (modify-phases %standard-phases
         (add-before 'build 'fix-libguile-ncurses-file-name
           (lambda* (#:key outputs #:allow-other-keys)
             (and (zero? (system* "make" "install"
                                  "-C" "src/ncurses"
                                  "-j" (number->string
                                        (parallel-job-count))))
                  (let* ((out   (assoc-ref outputs "out"))
                         (dir   "src/ncurses")
                         (files (find-files dir ".scm")))
                    (substitute* files
                      (("\"libguile-ncurses\"")
                       (format #f "\"~a/lib/guile/2.0/libguile-ncurses\""
                               out)))
                    #t)))))))
    (home-page "https://www.gnu.org/software/guile-ncurses/")
    (synopsis "Guile bindings to ncurses")
    (description
     "guile-ncurses provides Guile language bindings for the ncurses
library.")
    (license lgpl3+)))

(define-public mcron
  (package
    (name "mcron")
    (version "1.0.8")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/mcron/mcron-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "0zparwgf01jgl1x53ik71ghabldq6zz18ha4dscps1i0qrzgap1b"))
             (patches (search-patches "mcron-install.patch"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)))
    (inputs `(("ed" ,ed) ("which" ,which) ("guile" ,guile-2.0)))
    (home-page "http://www.gnu.org/software/mcron/")
    (synopsis "Run jobs at scheduled times")
    (description
     "GNU Mcron is a complete replacement for Vixie cron.  It is used to run
tasks on a schedule, such as every hour or every Monday.  Mcron is written in
Guile, so its configuration can be written in Scheme; the original cron
format is also supported.")
    (license gpl3+)))

(define-public mcron2
  ;; This is mthl's mcron development branch, not yet merged in mcron.
  (let ((commit "31baff1a5187d8ddc89324cbe42dbeffc309c962"))
    (package
      (inherit mcron)
      (name "mcron2")
      (version (string-append (package-version mcron) "-0."
                              (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://notabug.org/mthl/mcron/")
                      (commit commit)))
                (sha256
                 (base32
                  "1h5wxy997hxi718hpx419c23q09939kbxrjbbq54lv0cgw1bb63z"))
                (file-name (string-append name "-" version "-checkout"))))
      (native-inputs
       `(("autoconf" ,autoconf)
         ("automake" ,automake)
         ("pkg-config" ,pkg-config)
         ("texinfo" ,texinfo)
         ("help2man" ,help2man)))
      (arguments
       `(#:modules ((ice-9 match) (ice-9 ftw)
                    ,@%gnu-build-system-modules)

         #:phases (modify-phases %standard-phases
                    (add-after 'unpack 'bootstrap
                      (lambda _
                        (zero? (system* "autoreconf" "-vfi"))))
                    (add-after 'install 'wrap-mcron
                      (lambda* (#:key outputs #:allow-other-keys)
                        ;; Wrap the 'mcron' command to refer to the right
                        ;; modules.
                        (let* ((out  (assoc-ref outputs "out"))
                               (bin  (string-append out "/bin"))
                               (site (string-append
                                      out "/share/guile/site")))
                          (match (scandir site)
                            (("." ".." version)
                             (let ((modules (string-append site "/" version)))
                               (wrap-program (string-append bin "/mcron")
                                 `("GUILE_LOAD_PATH" ":" prefix
                                   (,modules))
                                 `("GUILE_LOAD_COMPILED_PATH" ":" prefix
                                   (,modules)))
                               #t))))))))))))

(define-public guile-lib
  (package
    (name "guile-lib")
    (version "0.2.3")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://savannah/guile-lib/guile-lib-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "0pwdd52vakni1fabaiav8v0ad7xp3bx8x3brijbr1mpgamm9dxqc"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (modify-phases %standard-phases
                  (add-before 'configure 'patch-module-dir
                    (lambda _
                      (substitute* "src/Makefile.in"
                        (("^moddir = ([[:graph:]]+)")
                         "moddir = $(datadir)/guile/site/@GUILE_EFFECTIVE_VERSION@\n")
                        (("^godir = ([[:graph:]]+)")
                         "godir = \
$(libdir)/guile/@GUILE_EFFECTIVE_VERSION@/site-ccache\n"))
                      #t))
                  (replace 'check
                    (lambda _
                      ;; Work around a harmless test failure involving
                      ;; two-spaces-after-period rendering.
                      (zero? (system* "make" "check" ;"-C" "unit-tests"
                                      "XFAIL_TESTS=texinfo.serialize.scm")))))))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (inputs `(("guile" ,guile-2.0)))
    (home-page "http://www.nongnu.org/guile-lib/")
    (synopsis "Collection of useful Guile Scheme modules")
    (description
     "Guile-Lib is intended as an accumulation place for pure-scheme Guile
modules, allowing for people to cooperate integrating their generic Guile
modules into a coherent library.  Think \"a down-scaled, limited-scope CPAN
for Guile\".")

    ;; The whole is under GPLv3+, but some modules are under laxer
    ;; distribution terms such as LGPL and public domain.  See `COPYING' for
    ;; details.
    (license gpl3+)))

(define-public guile-json
  (package
    (name "guile-json")
    (version "0.5.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://savannah/guile-json/guile-json-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0l8a34l92nrdszy7ykycfvr8y0n0yi5qb3ccliycvpvf9mzk5n8d"))
              (modules '((guix build utils)))
              (snippet
               ;; Make sure everything goes under .../site/X.Y, like Guile's
               ;; search paths expects.
               '(begin
                  (substitute* "configure"
                    (("ac_subst_vars='")
                     "ac_subst_vars='GUILE_EFFECTIVE_VERSION\n"))
                  (substitute* '("Makefile.in" "json/Makefile.in")
                    (("moddir =.*/share/guile/site" all)
                     (string-append all "/@GUILE_EFFECTIVE_VERSION@")))))))
    (build-system gnu-build-system)
    (native-inputs `(("guile" ,guile-2.0)))
    (home-page "http://savannah.nongnu.org/projects/guile-json/")
    (synopsis "JSON module for Guile")
    (description
     "Guile-json supports parsing and building JSON documents according to the
http:://json.org specification.  These are the main features:
- Strictly complies to http://json.org specification.
- Build JSON documents programmatically via macros.
- Unicode support for strings.
- Allows JSON pretty printing.")
    (license lgpl3+)))

(define-public guile2.2-json
  (package-for-guile-2.2 guile-json))

(define-public guile-minikanren
  (package
    (name "guile-minikanren")
    (version "20150424.e844d85")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "https://github.com/ijp/minikanren.git")
                    (commit "e844d85512f8c055d3f96143ee506007389a25e3")))
              (file-name (string-append name "-" version "-checkout"))
              (sha256
               (base32
                "0r50jlpzi940jlmxyy3ddqqwmj5r12gb4bcv0ssini9v8km13xz6"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils)
                      (ice-9 match)
                      (ice-9 popen)
                      (ice-9 rdelim))

         (let* ((out (assoc-ref %outputs "out"))
                (guile (assoc-ref %build-inputs "guile"))
                (effective (read-line
                            (open-pipe* OPEN_READ
                                        (string-append guile "/bin/guile")
                                        "-c" "(display (effective-version))")))
                (module-dir (string-append out "/share/guile/site/"
                                           effective))
                (source (assoc-ref %build-inputs "source"))
                (doc (string-append out "/share/doc/guile-minikanren"))
                (scm-files '("minikanren.scm"
                             "minikanren/mkextraforms.scm"
                             "minikanren/mkprelude.scm"
                             "minikanren/mk.scm"))
                (guild (string-append (assoc-ref %build-inputs "guile")
                                      "/bin/guild")))
           ;; Make installation directories.
           (mkdir-p (string-append module-dir "/minikanren"))
           (mkdir-p doc)

           ;; Compile .scm files and install.
           (chdir source)
           (setenv "GUILE_AUTO_COMPILE" "0")
           (for-each (lambda (file)
                       (let* ((dest-file (string-append module-dir "/"
                                                        file))
                              (go-file (match (string-split file #\.)
                                         ((base _)
                                          (string-append module-dir "/"
                                                         base ".go")))))
                         ;; Install source module.
                         (copy-file file dest-file)
                         ;; Install compiled module.
                         (unless (zero? (system* guild "compile"
                                                 "-L" source
                                                 "-o" go-file
                                                 file))
                           (error (format #f "Failed to compile ~s to ~s!"
                                          file go-file)))))
                     scm-files)

           ;; Also copy over the README.
           (install-file "README.org" doc)
           #t))))
    (inputs
     `(("guile" ,guile-2.0)))
    (home-page "https://github.com/ijp/minikanren")
    (synopsis "MiniKanren declarative logic system, packaged for Guile")
    (description
     "MiniKanren is a relational programming extension to the Scheme
programming Language, written as a smaller version of Kanren suitable for
pedagogical purposes.  It is featured in the book, The Reasoned Schemer,
written by Dan Friedman, William Byrd, and Oleg Kiselyov.

This is Ian Price's r6rs packaged version of miniKanren, which deviates
slightly from miniKanren mainline.

See http://minikanren.org/ for more on miniKanren generally.")
    (license expat)))

(define-public guile2.2-minikanren
  (package-for-guile-2.2 guile-minikanren))

(define-public guile-irregex
  (package
    (name "guile-irregex")
    (version "0.9.6")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://synthcode.com/scheme/irregex/irregex-"
                    version ".tar.gz"))
              (sha256
               (base32
                "1ia3m7dp3lcxa048q0gqbiwwsyvn99baw6xkhb4bhhzn4k7bwyqq"))))
    (build-system gnu-build-system)
    (arguments
     `(#:modules ((guix build utils)
                  (ice-9 match)
                  (ice-9 rdelim)
                  (ice-9 popen)
                  (guix build gnu-build-system))
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (delete 'build)
         (delete 'check)
         (replace 'install
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (effective (read-line
                                (open-pipe* OPEN_READ
                                            "guile" "-c"
                                            "(display (effective-version))")))
                    (module-dir (string-append out "/share/guile/site/"
                                               effective))
                    (source (assoc-ref inputs "source"))
                    (doc (string-append out "/share/doc/guile-irregex/"))
                    (guild (string-append (assoc-ref %build-inputs "guile")
                                          "/bin/guild")))
               ;; Make installation directories.
               (mkdir-p (string-append module-dir "/rx/source"))
               (mkdir-p doc)

               ;; Compile .scm files and install.
               (setenv "GUILE_AUTO_COMPILE" "0")

               (for-each (lambda (copy-info)
                           (match copy-info
                             ((src-file dest-file-basis)
                              (let* ((dest-file (string-append
                                                 module-dir dest-file-basis
                                                 ".scm"))
                                     (go-file (string-append
                                               module-dir dest-file-basis
                                               ".go")))
                                ;; Install source module.
                                (copy-file src-file
                                           dest-file)
                                ;; Install compiled module.
                                (unless (zero? (system* guild "compile"
                                                        "-L" (getcwd)
                                                        "-o" go-file
                                                        src-file))
                                  (error (format #f "Failed to compile ~s to ~s!"
                                                 src-file dest-file)))))))
                         '(("irregex-guile.scm" "/rx/irregex")
                           ("irregex.scm" "/rx/source/irregex")
                           ;; Not really reachable via guile's packaging system,
                           ;; but nice to have around
                           ("irregex-utils.scm" "/rx/source/irregex-utils")))

               ;; Also copy over the README.
               (install-file "irregex.html" doc)
               #t))))))
    (inputs
     `(("guile" ,guile-2.0)))
    (home-page "http://synthcode.com/scheme/irregex")
    (synopsis "S-expression based regular expressions")
    (description
     "Irregex is an s-expression based alternative to your classic
string-based regular expressions.  It implements SRFI 115 and is deeply
inspired by the SCSH regular expression system.")
    (license bsd-3)))

(define-public guile2.2-irregex
  (package-for-guile-2.2 guile-irregex))

;; There are two guile-gdbm packages, one using the FFI and one with
;; direct C bindings, hence the verbose name.

(define-public guile-gdbm-ffi
  (package
    (name "guile-gdbm-ffi")
    (version "20120209.fa1d5b6")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "https://github.com/ijp/guile-gdbm.git")
                    (commit "fa1d5b6231d0e4d096687b378c025f2148c5f246")))
              (file-name (string-append name "-" version "-checkout"))
              (sha256
               (base32
                "1j8wrsw7v9w6qkl47xz0rdikg50v16nn6kbs3lgzcymjzpa7babj"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules
       ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils)
                      (system base compile))

         (let* ((out (assoc-ref %outputs "out"))
                (module-dir (string-append out "/share/guile/site/2.0"))
                (source (assoc-ref %build-inputs "source"))
                (doc (string-append out "/share/doc"))
                (guild (string-append (assoc-ref %build-inputs "guile")
                                      "/bin/guild"))
                (gdbm.scm-dest
                 (string-append module-dir "/gdbm.scm"))
                (gdbm.go-dest
                 (string-append module-dir "/gdbm.go")))
           ;; Make installation directories.
           (mkdir-p module-dir)
           (mkdir-p doc)

           ;; Switch directory for compiling and installing
           (chdir source)

           ;; copy the source
           (copy-file "gdbm.scm" gdbm.scm-dest)

           ;; Patch the FFI
           (substitute* gdbm.scm-dest
             (("\\(dynamic-link \"libgdbm\"\\)")
              (format #f "(dynamic-link \"~a/lib/libgdbm.so\")"
                      (assoc-ref %build-inputs "gdbm"))))

           ;; compile to the destination
           (compile-file gdbm.scm-dest
                         #:output-file gdbm.go-dest)))))
    (inputs
     `(("guile" ,guile-2.0)))
    (propagated-inputs
     `(("gdbm" ,gdbm)))
    (home-page "https://github.com/ijp/guile-gdbm")
    (synopsis "Guile bindings to the GDBM library via Guile's FFI")
    (description
     "Guile bindings to the GDBM key-value storage system, using
Guile's foreign function interface.")
    (license gpl3+)))

(define-public guile-sqlite3
  (let ((commit "607721fe1174a299e45d457acacf94eefb964071"))
    (package
      (name "guile-sqlite3")
      (version (string-append "0.0-0." (string-take commit 7)))

      ;; XXX: Gitorious being dead, this is not a reliable home page.
      (home-page "https://www.gitorious.org/guile-sqlite3/guile-sqlite3.git/")
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url home-page)
                      (commit commit)))
                (sha256
                 (base32
                  "09gaffhh5rawz5kdmqx2ahvj1ngvxddp469r18bmjz3sz8p0slj2"))
                (file-name (string-append name "-" version "-checkout"))
                (modules '((guix build utils)))
                (snippet
                 ;; Upgrade 'Makefile.am' to the current way of doing things.
                 '(substitute* "Makefile.am"
                    (("TESTS_ENVIRONMENT")
                     "TEST_LOG_COMPILER")))))

      (build-system gnu-build-system)
      (native-inputs
       `(("autoconf" ,autoconf)
         ("automake" ,automake)
         ("pkg-config" ,pkg-config)))
      (inputs
       `(("guile" ,guile-2.0)
         ("sqlite" ,sqlite)))
      (arguments
       '(#:phases (modify-phases %standard-phases
                    (add-before 'configure 'autoreconf
                      (lambda _
                        (zero? (system* "autoreconf" "-vfi"))))
                    (add-before 'build 'set-sqlite3-file-name
                      (lambda* (#:key inputs #:allow-other-keys)
                        (substitute* "sqlite3.scm"
                          (("\"libsqlite3\"")
                           (string-append "\"" (assoc-ref inputs "sqlite")
                                          "/lib/libsqlite3\"")))
                        #t)))))
      (synopsis "Access SQLite databases from Guile")
      (description
       "This package provides Guile bindings to the SQLite database system.")
      (license gpl3+))))

(define-public haunt
  (package
    (name "haunt")
    (version "0.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://files.dthompson.us/haunt/haunt-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1id83n8fs7jxys1d8jy70vylg8gzcvlw1y7hb41y3qxv5zi4671m"))))
    (build-system gnu-build-system)
    (arguments
     `(#:modules ((ice-9 match) (ice-9 ftw)
                  ,@%gnu-build-system-modules)

       #:phases (modify-phases %standard-phases
                  (add-after 'install 'wrap-haunt
                    (lambda* (#:key outputs #:allow-other-keys)
                      ;; Wrap the 'haunt' command to refer to the right
                      ;; modules.
                      (let* ((out  (assoc-ref outputs "out"))
                             (bin  (string-append out "/bin"))
                             (site (string-append
                                    out "/share/guile/site")))
                        (match (scandir site)
                          (("." ".." version)
                           (let ((modules (string-append site "/" version)))
                             (wrap-program (string-append bin "/haunt")
                               `("GUILE_LOAD_PATH" ":" prefix
                                 (,modules))
                               `("GUILE_LOAD_COMPILED_PATH" ":" prefix
                                 (,modules)))
                             #t)))))))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("texinfo" ,texinfo)))
    (inputs
     `(("guile" ,guile-2.0)))
    (propagated-inputs
     `(("guile-reader" ,guile-reader)))
    (synopsis "Functional static site generator")
    (description "Haunt is a static site generator written in Guile
Scheme.  Haunt features a functional build system and an extensible
interface for reading articles in any format.")
    (home-page "http://haunt.dthompson.us")
    (license gpl3+)))

(define-public guile-config
  (package
    (name "guile-config")
    (version "0.1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://alex.pompo.co/software/" name "-" version
                    ".tar.gz"))
              (sha256
               (base32
                "1b719bn192f9wg24rr0zx8jpmygsvyhfi35iy778pb5p392snrn8"))))
    (build-system gnu-build-system)
    (inputs
     `(("guile" ,guile-2.0)))
    (synopsis "Guile application configuration parsing library")
    (description
     "Guile Config is a library providing a declarative approach to
application configuration specification.  The library provides clean
configuration declaration forms, and processors that take care of:
configuration file creation; configuration file parsing; command-line
parameter parsing using getopt-long; basic GNU command-line parameter
generation (--help, --usage, --version); automatic output generation for the
above command-line parameters.")
    (home-page "https://github.com/a-sassmannshausen/guile-config")
    (license agpl3+)))

(define-public guile-redis
  (package
    (name "guile-redis")
    (version "0.1.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://savannah/guile-redis/guile-redis-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0vx6if6b4r3kwx64vzbs6vpc0cpcr85x11w9vkzq27gw8n7isv56"))
              (modules '((guix build utils)))
              (snippet
               ;; Make sure everything goes under .../site/X.Y, like Guile's
               ;; search paths expects.
               '(begin
                  (substitute* "configure"
                    (("ac_subst_vars='")
                     "ac_subst_vars='GUILE_EFFECTIVE_VERSION\n"))
                  (substitute* '("Makefile.in"
                                 "redis/Makefile.in"
                                 "redis/commands/Makefile.in")
                    (("moddir =.*/share/guile/site" all)
                     (string-append all "/@GUILE_EFFECTIVE_VERSION@")))))))
    (build-system gnu-build-system)
    (native-inputs
     `(("guile" ,guile-2.0)))
    (home-page "http://savannah.nongnu.org/projects/guile-redis/")
    (synopsis "Redis client library for Guile")
    (description "Guile-redis provides a Scheme interface to the Redis
key-value cache and store.")
    (license lgpl3+)))

(define-public guile2.2-redis
  (package-for-guile-2.2 guile-redis))

(define-public guile-wisp
  (package
    (name "guile-wisp")
    (version "0.9.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://bitbucket.org/ArneBab/"
                                  "wisp/downloads/wisp-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0y5fxacalkgbv9s71h58vdvm2h2ln3rk024dd0vszwcf953as5fq"))))
    (build-system gnu-build-system)
    (arguments
     `(#:modules ((system base compile)
                  ,@%gnu-build-system-modules)
       #:phases
       (modify-phases %standard-phases
         (add-before
          'configure 'substitute-before-config

          (lambda* (#:key inputs #:allow-other-keys)
            (let ((bash (assoc-ref inputs "bash")))
              ;; configure checks for guile-2.0, but ours is just named "guile" :)
              (substitute* "configure"
                (("guile-2.0") "guile"))
              ;; Puts together some test files with /bin/bash hardcoded
              (substitute* "Makefile.in"
                (("/bin/bash")
                 (string-append bash "/bin/bash") ))
              #t)))

         ;; auto compilation breaks, but if we set HOME to /tmp,
         ;; that works ok
         (add-before
          'check 'auto-compile-hacky-workaround
          (lambda _
            (setenv "HOME" "/tmp")
            #t))
         (replace
          'install
          (lambda* (#:key outputs inputs #:allow-other-keys)
            (let* ((out (assoc-ref outputs "out"))
                   (module-dir (string-append out "/share/guile/site/2.0"))
                   (language-dir
                    (string-append module-dir "/language/wisp"))
                   (guild (string-append (assoc-ref inputs "guile")
                                         "/bin/guild")))
              ;; Make installation directories.
              (mkdir-p module-dir)
              (mkdir-p language-dir)

              ;; copy the source
              (copy-file "wisp-scheme.scm"
                         (string-append module-dir "/wisp-scheme.scm"))
              (copy-file "language/wisp/spec.scm"
                         (string-append language-dir "/spec.scm"))

              ;; compile to the destination
              (compile-file "wisp-scheme.scm"
                            #:output-file (string-append
                                           module-dir "/wisp-scheme.go"))
              (compile-file "language/wisp/spec.scm"
                            #:output-file (string-append
                                           language-dir "/spec.go"))
              #t))))))
    (home-page "http://draketo.de/english/wisp")
    (inputs
     `(("guile" ,guile-2.0)
       ("python" ,python)))
    (synopsis "Whitespace to lisp syntax for Guile")
    (description "Wisp is a syntax for Guile which provides a Python-like
whitespace-significant language.  It may be easier on the eyes for some
users and in some situations.")
    (license gpl3+)))

(define-public guile-sly
  (package
    (name "guile-sly")
    (version "0.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://files.dthompson.us/sly/sly-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1svzlbz2vripmyq2kjh0rig16bsrnbkwbsm558pjln9l65mcl4qq"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags
       (list (string-append "--with-libfreeimage-prefix="
                            (assoc-ref %build-inputs "freeimage"))
             (string-append "--with-libgslcblas-prefix="
                            (assoc-ref %build-inputs "gsl")))))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("guile" ,guile-2.0)
       ("guile-sdl" ,guile-sdl)
       ("guile-opengl" ,guile-opengl)))
    (inputs
     `(("gsl" ,gsl)
       ("freeimage" ,freeimage)
       ("mesa" ,mesa)))
    (synopsis "2D/3D game engine for GNU Guile")
    (description "Sly is a 2D/3D game engine written in Guile Scheme.  Sly
features a functional reactive programming interface and live coding
capabilities.")
    (home-page "http://dthompson.us/pages/software/sly.html")
    (license gpl3+)))

(define-public g-wrap
  (package
    (name "g-wrap")
    (version "1.9.15")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://savannah/g-wrap/g-wrap-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0ak0bha37dfpj9kmyw1r8fj8nva639aw5xr66wr5gd3l1rqf5xhg"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("guile" ,guile-2.0)
       ("guile-lib" ,guile-lib)))
    (inputs
     `(("libffi" ,libffi)))
    (arguments
      `(#:phases
        (modify-phases %standard-phases
          (add-before 'configure 'pre-configure
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (substitute* (find-files "." "^Makefile.in$")
                  (("guilemoduledir =.*guile/site" all)
                   (string-append all "/2.0")))
                #t))))))
    (synopsis "Generate C bindings for Guile")
    (description "G-Wrap is a tool and Guile library for generating function
wrappers for inter-language calls.  It currently only supports generating Guile
wrappers for C functions.  Given a definition of the types and prototypes for
a given C interface, G-Wrap will automatically generate the C code that
provides access to that interface and its types from the Scheme level.")
    (home-page "http://www.nongnu.org/g-wrap/index.html")
    (license lgpl2.1+)))

(define-public guile-dbi
  (package
    (name "guile-dbi")
    (version "2.1.6")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://download.gna.org/guile-dbi/guile-dbi-"
                    version ".tar.gz"))
              (sha256
               (base32
                "116njrprhgrsv1qm904sp3b02rq01fx639r433d657gyhw3x159n"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags
       (list (string-append
              "--with-guile-site-dir=" %output "/share/guile/site/2.0"))
       #:phases
       (modify-phases %standard-phases
         (add-after 'install 'patch-extension-path
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out     (assoc-ref outputs "out"))
                    (dbi.scm (string-append
                              out "/share/guile/site/2.0/dbi/dbi.scm"))
                    (ext     (string-append out "/lib/libguile-dbi")))
               (substitute* dbi.scm (("libguile-dbi") ext))
               #t))))))
    (propagated-inputs
     `(("guile" ,guile-2.0)))
    (synopsis "Guile database abstraction layer")
    (home-page "http://home.gna.org/guile-dbi/guile-dbi.html")
    (description
     "guile-dbi is a library for Guile that provides a convenient interface to
SQL databases.  Database programming with guile-dbi is generic in that the same
programming interface is presented regardless of which database system is used.
It currently supports MySQL, Postgres and SQLite3.")
    (license gpl2+)))

(define-public guile-dbd-sqlite3
  (package
    (name "guile-dbd-sqlite3")
    (version "2.1.6")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://download.gna.org/guile-dbi/guile-dbd-sqlite3-"
                    version ".tar.gz"))
              (sha256
               (base32
                "0rg71jchxd2y8x496s8zmfmikr5g8zxi8zv2ar3f7a23pph92iw2"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("sqlite" ,sqlite)
       ("zlib" ,(@ (gnu packages compression) zlib))))
    (propagated-inputs
     `(("guile-dbi" ,guile-dbi)))
    (synopsis "Guile DBI driver for SQLite")
    (home-page "https://github.com/jkalbhenn/guile-dbd-sqlite3")
    (description
     "guile-dbi is a library for Guile that provides a convenient interface to
SQL databases.  This package implements the interface for SQLite.")
    (license gpl2+)))

(define-public guile-xosd
  (package
    (name "guile-xosd")
    (version "0.2.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/alezost/" name
                                  "/releases/download/v" version
                                  "/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "1ri5065c16kmgrf2pysn2ymxjqi5302lhpb07wkl1jr75ym8fn8p"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("guile" ,guile-2.0)
       ("libx11" ,libx11)
       ("libxext" ,libxext)
       ("libxinerama" ,libxinerama)
       ("xosd" ,xosd)))
    (home-page "https://github.com/alezost/guile-xosd")
    (synopsis "XOSD bindings for Guile")
    (description
     "Guile-XOSD provides Guile bindings for @code{libxosd},
@uref{http://sourceforge.net/projects/libxosd/, the X On Screen Display
library}.")
    (license gpl3+)))

(define-public guile-daemon
  (package
    (name "guile-daemon")
    (version "0.1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/alezost/" name
                                  "/releases/download/v" version
                                  "/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "0wsq9l6a4sijq4i1r3kcddfaznsak2jc5k59gzkhs5il5d2kn5yi"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("guile" ,guile-2.0)))
    (home-page "https://github.com/alezost/guile-daemon")
    (synopsis "Evaluate code in a running Guile process")
    (description
     "Guile-Daemon is a small Guile program that loads your initial
configuration file, and then reads and evaluates Guile expressions that
you send to a FIFO file.")
    (license gpl3+)))

(define-public guile-commonmark
  (package
    (name "guile-commonmark")
    (version "0.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/OrangeShark/" name
                                  "/releases/download/v" version
                                  "/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "12cb5fqvvgc87f5xp0ih5az305wnjia89l5jba83d0r2p8bfy0b0"))
              (modules '((guix build utils)))
              (snippet
               ;; Use the real effective version of Guile in directory names
               ;; instead of a hard-coded "/2.0".
               '(begin
                  (substitute* "configure"
                    (("ac_subst_vars='")
                     "ac_subst_vars='GUILE_EFFECTIVE_VERSION\n"))
                  (substitute* "Makefile.in"
                    (("/site/2.0")
                     "/site/@GUILE_EFFECTIVE_VERSION@"))))))
    (build-system gnu-build-system)
    (inputs
     `(("guile" ,guile-2.0)))
    (synopsis "CommonMark parser for Guile")
    (description
     "guile-commonmark is a library for parsing CommonMark, a fully specified
variant of Markdown.  The library is written in Guile Scheme and is designed
to transform a CommonMark document to SXML.  guile-commonmark tries to closely
follow the @uref{http://commonmark.org/, CommonMark spec}, the main difference
is no support for parsing block and inline level HTML.")
    (home-page "https://github.com/OrangeShark/guile-commonmark")
    (license lgpl3+)))

(define-public guile2.2-commonmark
  (package-for-guile-2.2 guile-commonmark))

(define-public guile-bytestructures
  (package
    (name "guile-bytestructures")
    (version "20160726.53127f6")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "https://github.com/TaylanUB/scheme-bytestructures")
                    (commit "53127f608caf64b34fa41c389b2743b546fbe9da")))
              (file-name (string-append name "-" version "-checkout"))
              (sha256
               (base32
                "0l4nx1vp9fkrgrgwjiycj7nx6wfjfd39rqamv4pmq7issi8mrywq"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils)
                      (ice-9 match)
                      (ice-9 popen)
                      (ice-9 rdelim))
         (let* ((out (assoc-ref %outputs "out"))
                (guile (assoc-ref %build-inputs "guile"))
                (effective (read-line
                            (open-pipe* OPEN_READ
                                        (string-append guile "/bin/guile")
                                        "-c" "(display (effective-version))")))
                (module-dir (string-append out "/share/guile/site/"
                                           effective))
                (source (assoc-ref %build-inputs "source"))
                (doc (string-append out "/share/doc/scheme-bytestructures"))
                (scm-files (filter (lambda (path)
                                     (not (string-prefix? "bytestructures/r7" path)))
                                   (with-directory-excursion source
                                     (find-files "bytestructures" "\\.scm$"))))
                (guild (string-append (assoc-ref %build-inputs "guile")
                                      "/bin/guild")))
           ;; Make installation directories.
           (mkdir-p doc)

           ;; Compile .scm files and install.
           (chdir source)
           (setenv "GUILE_AUTO_COMPILE" "0")
           (for-each (lambda (file)
                       (let* ((dest-file (string-append module-dir "/"
                                                        file))
                              (go-file (string-append module-dir "/"
                                                      (substring file 0
                                                                 (string-rindex file #\.))
                                                      ".go")))
                         ;; Install source module.
                         (mkdir-p (dirname dest-file))
                         (copy-file file dest-file)

                         ;; Install compiled module.
                         (mkdir-p (dirname go-file))
                         (unless (zero? (system* guild "compile"
                                                 "-L" source
                                                 "-o" go-file
                                                 file))
                           (error (format #f "Failed to compile ~s to ~s!"
                                          file go-file)))))
                     scm-files)

           ;; Also copy over the README.
           (install-file "README.md" doc)
           #t))))
    (inputs
     `(("guile" ,guile-2.0)))
    (home-page "https://github.com/TaylanUB/scheme-bytestructures")
    (synopsis "Structured access to bytevector contents for Guile")
    (description
     "Guile bytestructures offers a system imitating the type system
of the C programming language, to be used on bytevectors.  C's type
system works on raw memory, and Guile works on bytevectors which are
an abstraction over raw memory.  It's also more powerful than the C
type system, elevating types to first-class status.")
    (license gpl3+)))

(define-public guile-aspell
  (package
    (name "guile-aspell")
    (version "0.3")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://lonelycactus.com/tarball/guile_aspell-"
                    version ".tar.gz"))
              (sha256
               (base32
                "1wknn57x2qcsbn7zw6sbn1ma6fjsg8cvpnf78ak47s8jw6k6j75n"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags (list (string-append "--with-guilesitedir="
                                              (assoc-ref %outputs "out")
                                              "/share/guile/site/2.0"))
       #:phases (modify-phases %standard-phases
                  (add-before 'build 'set-libaspell-file-name
                    (lambda* (#:key inputs #:allow-other-keys)
                      (let ((aspell (assoc-ref inputs "aspell")))
                        (substitute* "aspell/aspell.scm"
                          (("\"libaspell\\.so\"")
                           (string-append "\"" aspell
                                          "/lib/libaspell\"")))
                        #t))))))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (inputs `(("guile" ,guile-2.0)
              ("aspell" ,aspell)))
    (home-page "https://github.com/spk121/guile-aspell")
    (synopsis "Spell-checking from Guile")
    (description
     "guile-aspell is a Guile Scheme library for comparing a string against a
dictionary and suggesting spelling corrections.")
    (license gpl3+)))

;;; guile.scm ends here
