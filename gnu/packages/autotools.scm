;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Mathieu Lirzin <mthl@openmailbox.org>
;;; Copyright © 2014 Manolis Fragkiskos Ragkousis <manolis837@gmail.com>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 David Thompson <davet@gnu.org>
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

(define-module (gnu packages autotools)
  #:use-module (guix licenses)
  #:use-module (gnu packages)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages m4)
  #:use-module (gnu packages bash)
  #:use-module (guix utils)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (ice-9 match)
  #:export (autoconf-wrapper))

(define-public autoconf
  (package
    (name "autoconf")
    (version "2.69")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/autoconf/autoconf-"
                          version ".tar.xz"))
      (sha256
       (base32
        "113nlmidxy9kjr45kg9x3ngar4951mvag1js2a3j8nxcz34wxsv4"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("perl" ,perl)
       ("m4" ,m4)))
    ;; XXX: testsuite: 209 and 279 failed. The latter is an impurity. It
    ;; should use our own "cpp" instead of "/lib/cpp".
    (arguments `(#:tests? #f))
    (home-page
     "http://www.gnu.org/software/autoconf/")
    (synopsis "Create source code configuration scripts")
    (description
     "Autoconf offers the developer a robust set of M4 macros which expand
into shell code to test the features of Unix-like systems and to adapt
automatically their software package to these systems.  The resulting shell
scripts are self-contained and portable, freeing the user from needing to
know anything about Autoconf or M4.")
    (license gpl3+))) ; some files are under GPLv2+

(define-public autoconf-2.68
  (package (inherit autoconf)
    (version "2.68")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/autoconf/autoconf-"
                          version ".tar.xz"))
      (sha256
       (base32
        "1fjm21k2na07f3vasf288a0zx66lbv0hd3l9bvv3q8p62s3pg569"))))))

(define-public autoconf-2.64
  ;; As of GDB 7.8, GDB is still developed using this version of Autoconf.
  (package (inherit autoconf)
    (version "2.64")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/autoconf/autoconf-"
                          version ".tar.xz"))
      (sha256
       (base32
        "0j3jdjpf5ly39dlp0bg70h72nzqr059k0x8iqxvaxf106chpgn9j"))))))


(define* (autoconf-wrapper #:optional (autoconf autoconf))
  "Return an wrapper around AUTOCONF that generates `configure' scripts that
use our own Bash instead of /bin/sh in shebangs.  For that reason, it should
only be used internally---users should not end up distributing `configure'
files with a system-specific shebang."
  (package (inherit autoconf)
    (name (string-append (package-name autoconf) "-wrapper"))
    (build-system trivial-build-system)
    (inputs `(("guile"
               ;; XXX: Kludge to hide the circular dependency.
               ,(module-ref (resolve-interface '(gnu packages guile))
                            'guile-2.0))
              ("autoconf" ,autoconf)
              ("bash" ,bash)))
    (arguments
     '(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (let* ((out      (assoc-ref %outputs "out"))
                (bin      (string-append out "/bin"))
                (autoconf (string-append
                           (assoc-ref %build-inputs "autoconf")
                           "/bin/autoconf"))
                (guile    (string-append
                           (assoc-ref %build-inputs "guile")
                           "/bin/guile"))
                (sh       (string-append
                           (assoc-ref %build-inputs "bash")
                           "/bin/sh"))
                (modules  ((compose dirname dirname dirname)
                           (search-path %load-path
                                        "guix/build/utils.scm"))))
           (mkdir-p bin)

           ;; Symlink all the binaries but `autoconf'.
           (with-directory-excursion bin
             (for-each (lambda (file)
                         (unless (string=? (basename file) "autoconf")
                           (symlink file (basename file))))
                       (find-files (dirname autoconf) ".*")))

           ;; Add an `autoconf' binary that wraps the real one.
           (call-with-output-file (string-append bin "/autoconf")
             (lambda (port)
               ;; Shamefully, Guile can be used in shebangs only if a
               ;; single argument is passed (-ds); otherwise it gets
               ;; them all as a single argument and fails to parse them.
               (format port "#!~a
export GUILE_LOAD_PATH=\"~a\"
export GUILE_LOAD_COMPILED_PATH=\"~a\"
exec ~a --no-auto-compile \"$0\" \"$@\"
!#~%"
                       sh modules modules guile)
               (write
                `(begin
                   (use-modules (guix build utils))
                   (let ((result (apply system* ,autoconf
                                        (cdr (command-line)))))
                     (when (and (file-exists? "configure")
                                (not (file-exists? "/bin/sh")))
                       ;; Patch regardless of RESULT, because `autoconf
                       ;; -Werror' can both create a `configure' file and
                       ;; return a non-zero exit code.
                       (patch-shebang "configure"))
                     (exit (status:exit-val result))))
                port)))
           (chmod (string-append bin "/autoconf") #o555)))))))

(define-public autoconf-archive
  (package
    (name "autoconf-archive")
    (version "2016.03.20")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/autoconf-archive/autoconf-archive-"
                          version ".tar.xz"))
      (sha256
       (base32
        "0dz4fnc723jqn3by22ds5fys7g31apzm1r9allldvva0yvzjxyw8"))))
    (build-system gnu-build-system)
    (home-page "https://www.gnu.org/software/autoconf-archive")
    (synopsis "Collection of freely reusable Autoconf macros")
    (description
     "Autoconf Archive is a collection of over 450 new macros for Autoconf,
greatly expanding the domain of its functionality.  These macros have been
contributed as free software by the community.")
    (license gpl3+)))

(define-public autobuild
  (package
    (name "autobuild")
    (version "5.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://savannah/autobuild/autobuild-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0gv7g61ja9q9zg1m30k4snqwwy1kq7b4df6sb7d2qra7kbdq8af1"))))
    (build-system gnu-build-system)
    (inputs `(("perl" ,perl)))
    (synopsis "Process generated build logs")
    (description "Autobuild is a package that processes build logs generated
when building software.  Autobuild is primarily focused on packages using
Autoconf and Automake, but can be used with other build systems too.
Autobuild generates an HTML summary file, containing links to each build log.
The summary includes project name, version, build hostname, host type (cross
compile aware), date of build, and indication of success or failure.  The
output is indexed in many ways to simplify browsing.")
    (home-page "http://josefsson.org/autobuild/")
    (license gpl3+)))

(define-public automake
  (package
    (name "automake")
    (version "1.15")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/automake/automake-"
                                 version ".tar.xz"))
             (sha256
              (base32
               "0dl6vfi2lzz8alnklwxzfz624b95hb1ipjvd3mk177flmddcf24r"))
             (patches
              (search-patches "automake-regexp-syntax.patch"
                              "automake-skip-amhello-tests.patch"
                              "automake-test-gzip-warning.patch"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("autoconf" ,(autoconf-wrapper))
       ("perl" ,perl)))
    (native-search-paths
     (list (search-path-specification
            (variable "ACLOCAL_PATH")
            (files '("share/aclocal")))))
    (arguments
     '(#:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (srfi srfi-1)
                  (srfi srfi-26)
                  (rnrs io ports))
       #:phases (alist-cons-before
                 'patch-source-shebangs 'patch-tests-shebangs
                 (lambda _
                   (let ((sh (which "sh")))
                     (substitute* (find-files "t" "\\.(sh|tap)$")
                       (("#![[:blank:]]?/bin/sh")
                        (string-append "#!" sh)))

                     ;; Set these variables for all the `configure' runs
                     ;; that occur during the test suite.
                     (setenv "SHELL" sh)
                     (setenv "CONFIG_SHELL" sh)))

                 ;; Files like `install-sh', `mdate.sh', etc. must use
                 ;; #!/bin/sh, otherwise users could leak erroneous shebangs
                 ;; in the wild.  See <http://bugs.gnu.org/14201> for an
                 ;; example.
                 (alist-cons-after
                  'install 'unpatch-shebangs
                  (lambda* (#:key outputs #:allow-other-keys)
                    (let* ((out (assoc-ref outputs "out"))
                           (dir (string-append out "/share")))
                      (define (starts-with-shebang? file)
                        (equal? (call-with-input-file file
                                  (lambda (p)
                                    (list (get-u8 p) (get-u8 p))))
                                (map char->integer '(#\# #\!))))

                      (for-each (lambda (file)
                                  (when (and (starts-with-shebang? file)
                                             (executable-file? file))
                                    (format #t "restoring shebang on `~a'~%"
                                            file)
                                    (substitute* file
                                      (("^#!.*/bin/sh")
                                       "#!/bin/sh")
                                      (("^#!.*/bin/env(.*)$" _ args)
                                       (string-append "#!/usr/bin/env"
                                                      args)))))
                                (find-files dir ".*"))))
                  %standard-phases))))
    (home-page "http://www.gnu.org/software/automake/")
    (synopsis "Making GNU standards-compliant Makefiles")
    (description
     "Automake the part of the GNU build system for producing
standards-compliant Makefiles.  Build requirements are entered in an
intuitive format and then Automake works with Autoconf to produce a robust
Makefile, simplifying the entire process for the developer.")
    (license gpl2+)))                      ; some files are under GPLv3+

(define-public libtool
  (package
    (name "libtool")
    (version "2.4.6")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/libtool/libtool-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "0vxj52zm709125gwv9qqlw02silj8bnjnh4y07arrz60r31ai1vw"))
              (patches (search-patches "libtool-skip-tests2.patch"))))
    (build-system gnu-build-system)
    (propagated-inputs `(("m4" ,m4)))
    (native-inputs `(("m4" ,m4)
                     ("perl" ,perl)
                     ("automake" ,automake)      ;some tests rely on 'aclocal'
                     ("autoconf" ,(autoconf-wrapper)))) ;others on 'autom4te'

    (arguments
     `(;; Libltdl is provided as a separate package, so don't install it here.
       #:configure-flags '("--disable-ltdl-install")

       ;; XXX: There are test failures on mips64el-linux starting from 2.4.4:
       ;; <http://hydra.gnu.org/build/181662>.
       #:tests? ,(not (string-prefix? "mips64"
                                      (or (%current-target-system)
                                          (%current-system))))

       #:phases (alist-cons-before
                 'check 'pre-check
                 (lambda* (#:key inputs #:allow-other-keys)
                   ;; Run the test suite in parallel, if possible.
                   (setenv "TESTSUITEFLAGS"
                           (string-append
                            "-j"
                            (number->string (parallel-job-count))))

                   ;; Path references to /bin/sh.
                   (let ((bash (assoc-ref inputs "bash")))
                     (substitute* "tests/testsuite"
                       (("/bin/sh")
                        (string-append bash "/bin/bash")))))
                 %standard-phases)))
    (synopsis "Generic shared library support tools")
    (description
     "GNU Libtool helps in the creation and use of shared libraries, by
presenting a single consistent, portable interface that hides the usual
complexity of working with shared libraries across platforms.")
    (license gpl3+)
    (home-page "http://www.gnu.org/software/libtool/")))

(define-public libltdl
  ;; This is a libltdl package separate from the libtool package.  This is
  ;; useful because, unlike libtool, it has zero extra dependencies (making it
  ;; readily usable during bootstrap), and it builds very quickly since
  ;; Libtool's extensive test suite isn't run.
  (package
    (name "libltdl")
    (version "2.4.6")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/libtool/libtool-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "0vxj52zm709125gwv9qqlw02silj8bnjnh4y07arrz60r31ai1vw"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags '("--enable-ltdl-install") ;really install it
       #:phases (alist-cons-before
                 'configure 'change-directory
                 (lambda _
                   (chdir "libltdl"))
                 %standard-phases)))

    (synopsis "System-independent dlopen wrapper of GNU libtool")
    (description (package-description libtool))
    (home-page (package-home-page libtool))
    (license lgpl2.1+)))
