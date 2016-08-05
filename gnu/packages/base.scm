;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2012 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2014, 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014 Alex Kost <alezost@gmail.com>
;;; Copyright © 2014, 2015 Manolis Fragkiskos Ragkousis <manolis837@gmail.com>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Jan Nieuwenhuizen <janneke@gnu.org>
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

(define-module (gnu packages base)
  #:use-module ((guix licenses)
                #:select (gpl3+ lgpl2.0+ lgpl3+ public-domain))
  #:use-module (gnu packages)
  #:use-module (gnu packages acl)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages ed)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages hurd)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages gettext)
  #:use-module (guix utils)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (ice-9 match)
  #:export (glibc))

;;; Commentary:
;;;
;;; Base packages of the Guix-based GNU user-land software distribution.
;;;
;;; Code:

(define-public hello
  (package
    (name "hello")
    (version "2.10")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/hello/hello-" version
                                  ".tar.gz"))
              (sha256
               (base32
                "0ssi1wpaf7plaswqqjwigppsg5fyh99vdlb9kzl7c9lng89ndq1i"))))
    (build-system gnu-build-system)
    (synopsis "Hello, GNU world: An example GNU package")
    (description
     "GNU Hello prints the message \"Hello, world!\" and then exits.  It
serves as an example of standard GNU coding practices.  As such, it supports
command-line arguments, multiple languages, and so on.")
    (home-page "http://www.gnu.org/software/hello/")
    (license gpl3+)))

(define-public grep
  (package
   (name "grep")
   (version "2.25")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/grep/grep-"
                                version ".tar.xz"))
            (sha256
             (base32
              "0c38b67cnwchwzv4wq2gpz6smkhdxrac2hhssv8f0l04qnx867p2"))
            (patches (search-patches "grep-timing-sensitive-test.patch"))))
   (build-system gnu-build-system)
   (native-inputs `(("perl" ,perl)))             ;some of the tests require it
   (synopsis "Print lines matching a pattern")
   (description
     "grep is a tool for finding text inside files.  Text is found by
matching a pattern provided by the user in one or many files.  The pattern
may be provided as a basic or extended regular expression, or as fixed
strings.  By default, the matching text is simply printed to the screen,
however the output can be greatly customized to include, for example, line
numbers.  GNU grep offers many extensions over the standard utility,
including, for example, recursive directory searching.")
   (license gpl3+)
   (home-page "http://www.gnu.org/software/grep/")))

(define-public sed
  (package
   (name "sed")
   (version "4.2.2")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/sed/sed-" version
                                ".tar.bz2"))
            (sha256
             (base32
              "1myvrmh99jsvk7v3d7crm0gcrq51hmmm1r2kjyyci152in1x2j7h"))
            (patches (search-patches "sed-hurd-path-max.patch"))))
   (build-system gnu-build-system)
   (synopsis "Stream editor")
   (arguments
    (if (%current-target-system)
        '()
        `(#:phases (alist-cons-before
                    'patch-source-shebangs 'patch-test-suite
                    (lambda* (#:key inputs #:allow-other-keys)
                      (let ((bash (assoc-ref inputs "bash")))
                        (patch-makefile-SHELL "testsuite/Makefile.tests")
                        (substitute* '("testsuite/bsd.sh"
                                       "testsuite/bug-regex9.c")
                          (("/bin/sh")
                           (string-append bash "/bin/bash")))))
                    %standard-phases))))
   (description
    "Sed is a non-interactive, text stream editor.  It receives a text
input from a file or from standard input and it then applies a series of text
editing commands to the stream and prints its output to standard output.  It
is often used for substituting text patterns in a stream.  The GNU
implementation offers several extensions over the standard utility.")
   (license gpl3+)
   (home-page "http://www.gnu.org/software/sed/")))

(define-public tar
  (package
   (name "tar")
   (version "1.29")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/tar/tar-"
                                version ".tar.xz"))
            (sha256
             (base32
              "097hx7sbzp8qirl4m930lw84kn0wmxhmq7v1qpra3mrg0b8cyba0"))
            (patches (search-patches "tar-skip-unreliable-tests.patch"))))
   (build-system gnu-build-system)
   ;; Note: test suite requires ~1GiB of disk space.
   (arguments
    '(#:phases (modify-phases %standard-phases
                 (add-before 'build 'set-shell-file-name
                   (lambda* (#:key inputs #:allow-other-keys)
                     ;; Do not use "/bin/sh" to run programs.
                     (let ((bash (assoc-ref inputs "bash")))
                       (substitute* "src/system.c"
                         (("/bin/sh")
                          (string-append bash "/bin/sh")))
                       #t))))))

   ;; When cross-compiling, the 'set-shell-file-name' phase needs to be able
   ;; to refer to the target Bash.
   (inputs (if (%current-target-system)
               `(("bash" ,bash))
               '()))

   (synopsis "Managing tar archives")
   (description
    "Tar provides the ability to create tar archives, as well as the
ability to extract, update or list files in an existing archive.  It is
useful for combining many files into one larger file, while maintaining
directory structure and file information such as permissions and
creation/modification dates.  GNU tar offers many extensions over the
standard utility.")
   (license gpl3+)
   (home-page "http://www.gnu.org/software/tar/")))

(define-public patch
  (package
   (name "patch")
    (version "2.7.5")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/patch/patch-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "16d2r9kpivaak948mxzc0bai45mqfw73m113wrkmbffnalv1b5gx"))
              (patches (search-patches "patch-hurd-path-max.patch"))))
   (build-system gnu-build-system)
   (native-inputs `(("ed" ,ed)))
   (synopsis "Apply differences to originals, with optional backups")
   (description
    "Patch is a program that applies changes to files based on differences
laid out as by the program \"diff\".  The changes may be applied to one or more
files depending on the contents of the diff file.  It accepts several
different diff formats.  It may also be used to revert previously applied
differences.")
   (license gpl3+)
   (home-page "http://savannah.gnu.org/projects/patch/")))

(define-public diffutils
  (package
   (name "diffutils")
   (version "3.3")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/diffutils/diffutils-"
                                version ".tar.xz"))
            (sha256
             (base32
              "1761vymxbp4wb5rzjvabhdkskk95pghnn67464byvzb5mfl8jpm2"))))
   (build-system gnu-build-system)
   (synopsis "Comparing and merging files")
   (description
    "GNU Diffutils is a package containing tools for finding the
differences between files.  The \"diff\" command is used to show how two files
differ, while \"cmp\" shows the offsets and line numbers where they differ.
\"diff3\" allows you to compare three files.  Finally, \"sdiff\" offers an
interactive means to merge two files.")
   (license gpl3+)
   (home-page "http://www.gnu.org/software/diffutils/")))

(define-public findutils
  (package
   (name "findutils")
   (version "4.6.0")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/findutils/findutils-"
                                version ".tar.gz"))
            (sha256
             (base32
              "178nn4dl7wbcw499czikirnkniwnx36argdnqgz4ik9i6zvwkm6y"))
            (patches (search-patches "findutils-localstatedir.patch"
                                     "findutils-test-xargs.patch"))))
   (build-system gnu-build-system)
   (arguments
    `(#:configure-flags (list
                         ;; Tell 'updatedb' to write to /var.
                         "--localstatedir=/var"

                         ;; Work around cross-compilation failure.  See
                         ;; <http://savannah.gnu.org/bugs/?27299#comment1>.
                         ,@(if (%current-target-system)
                               '("gl_cv_func_wcwidth_works=yes")
                               '()))))
   (synopsis "Operating on files matching given criteria")
   (description
    "Findutils supplies the basic file directory searching utilities of the
GNU system.  It consists of two primary searching utilities: \"find\"
recursively searches for files in a directory according to given criteria and
\"locate\" lists files in a database that match a query.  Two auxiliary tools
are included: \"updatedb\" updates the file name database and \"xargs\" may be
used to apply commands with arbitrarily long arguments.")
   (license gpl3+)
   (home-page "http://www.gnu.org/software/findutils/")))

(define-public coreutils
  (package
   (name "coreutils")
   (version "8.25")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/coreutils/coreutils-"
                                version ".tar.xz"))
            (sha256
             (base32
              "11yfrnb94xzmvi4lhclkcmkqsbhww64wf234ya1aacjvg82prrii"))))
   (build-system gnu-build-system)
   (inputs `(("acl"  ,acl)                        ; TODO: add SELinux
             ("gmp"  ,gmp)                        ;bignums in 'expr', yay!

             ;; Drop the dependency on libcap when cross-compiling since it's
             ;; not quite cross-compilable.
             ,@(if (%current-target-system)
                   '()
                   `(("libcap" ,libcap)))))  ;capability support is 'ls', etc.
   (native-inputs
    ;; Perl is needed to run tests in native builds, and to run the bundled
    ;; copy of help2man.  However, don't pass it when cross-compiling since
    ;; that would lead it to try to run programs to get their '--help' output
    ;; for help2man.
    (if (%current-target-system)
        '()
        `(("perl" ,perl))))
   (outputs '("out" "debug"))
   (arguments
    `(#:parallel-build? #f            ; help2man may be called too early
      #:phases (alist-cons-before
                'build 'patch-shell-references
                (lambda* (#:key inputs #:allow-other-keys)
                  (let ((bash (assoc-ref inputs "bash")))
                    ;; 'split' uses either $SHELL or /bin/sh.  Set $SHELL so
                    ;; that tests pass, since /bin/sh isn't in the chroot.
                    (setenv "SHELL" (which "sh"))

                    (substitute* (find-files "gnulib-tests" "\\.c$")
                      (("/bin/sh")
                       (format #f "~a/bin/sh" bash)))
                    (substitute* (find-files "tests" "\\.sh$")
                      (("#!/bin/sh")
                       (format #f "#!~a/bin/sh" bash)))))
                %standard-phases)))
   (synopsis "Core GNU utilities (file, text, shell)")
   (description
    "GNU Coreutils includes all of the basic command-line tools that are
expected in a POSIX system.  These provide the basic file, shell and text
manipulation functions of the GNU system.  Most of these tools offer extended
functionality beyond that which is outlined in the POSIX standard.")
   (license gpl3+)
   (home-page "http://www.gnu.org/software/coreutils/")))

(define-public coreutils-minimal
  ;; Coreutils without its optional dependencies.
  (package
    (inherit coreutils)
    (name "coreutils-minimal")
    (outputs '("out"))
    (inputs '())))

(define-public gnu-make
  (package
   (name "make")
   (version "4.2")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/make/make-" version
                                ".tar.bz2"))
            (sha256
             (base32
              "0pv5rvz5pp4njxiz3syf786d2xp4j7gzddwjvgw5zmz55yvf6p2f"))
            (patches (search-patches "make-impure-dirs.patch"))))
   (build-system gnu-build-system)
   (native-inputs `(("pkg-config" ,pkg-config)))  ; to detect Guile
   (inputs `(("guile" ,guile-2.0)))
   (outputs '("out" "debug"))
   (arguments
    '(#:phases (alist-cons-before
                'build 'set-default-shell
                (lambda* (#:key inputs #:allow-other-keys)
                  ;; Change the default shell from /bin/sh.
                  (let ((bash (assoc-ref inputs "bash")))
                    (substitute* "job.c"
                      (("default_shell =.*$")
                       (format #f "default_shell = \"~a/bin/bash\";\n"
                               bash)))))
                %standard-phases)))
   (synopsis "Remake files automatically")
   (description
    "Make is a program that is used to control the production of
executables or other files from their source files.  The process is
controlled from a Makefile, in which the developer specifies how each file is
generated from its source.  It has powerful dependency resolution and the
ability to determine when files have to be regenerated after their sources
change.  GNU make offers many powerful extensions over the standard utility.")
   (license gpl3+)
   (home-page "http://www.gnu.org/software/make/")))

(define-public binutils
  (package
   (name "binutils")
   (version "2.25.1")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/binutils/binutils-"
                                version ".tar.bz2"))
            (sha256
             (base32
              "08lzmhidzc16af1zbx34f8cy4z7mzrswpdbhrb8shy3xxpflmcdm"))
            (patches (search-patches "binutils-ld-new-dtags.patch"
                                     "binutils-loongson-workaround.patch"))))
   (build-system gnu-build-system)

   ;; TODO: Add dependency on zlib + those for Gold.
   (arguments
    `(#:configure-flags '(;; Add `-static-libgcc' to not retain a dependency
                          ;; on GCC when bootstrapping.
                          "LDFLAGS=-static-libgcc"

                          ;; Don't search under /usr/lib & co.
                          "--with-lib-path=/no-ld-lib-path"

                          ;; Glibc 2.17 has a "comparison of unsigned
                          ;; expression >= 0 is always true" in wchar.h.
                          "--disable-werror"

                          ;; Install BFD.  It ends up in a hidden directory,
                          ;; but it's here.
                          "--enable-install-libbfd"

                          ;; Make sure 'ar' and 'ranlib' produce archives in a
                          ;; deterministic fashion.
                          "--enable-deterministic-archives")))

   (synopsis "Binary utilities: bfd gas gprof ld")
   (description
    "GNU Binutils is a collection of tools for working with binary files.
Perhaps the most notable are \"ld\", a linker, and \"as\", an assembler.
Other tools include programs to display binary profiling information, list
the strings in a binary file, and utilities for working with archives.  The
\"bfd\" library for working with executable and object formats is also
included.")
   (license gpl3+)
   (home-page "http://www.gnu.org/software/binutils/")))

(define* (make-ld-wrapper name #:key binutils
                          (guile (canonical-package guile-2.0))
                          (bash (canonical-package bash)) target
                          (guile-for-build guile))
  "Return a package called NAME that contains a wrapper for the 'ld' program
of BINUTILS, which adds '-rpath' flags to the actual 'ld' command line.  When
TARGET is not #f, make a wrapper for the cross-linker for TARGET, called
'TARGET-ld'.  The wrapper uses GUILE and BASH."
  (package
    (name name)
    (version "0")
    (source #f)
    (build-system trivial-build-system)
    (inputs `(("binutils" ,binutils)
              ("guile"    ,guile)
              ("bash"     ,bash)
              ("wrapper"  ,(search-path %load-path
                                        "gnu/packages/ld-wrapper.in"))))
    (arguments
     `(#:guile ,guile-for-build
       #:modules ((guix build utils))
       #:builder (begin
                   (use-modules (guix build utils)
                                (system base compile))

                   (let* ((out (assoc-ref %outputs "out"))
                          (bin (string-append out "/bin"))
                          (ld  ,(if target
                                    `(string-append bin "/" ,target "-ld")
                                    '(string-append bin "/ld")))
                          (go  (string-append ld ".go")))

                     (setvbuf (current-output-port) _IOLBF)
                     (format #t "building ~s/bin/ld wrapper in ~s~%"
                             (assoc-ref %build-inputs "binutils")
                             out)

                     (mkdir-p bin)
                     (copy-file (assoc-ref %build-inputs "wrapper") ld)
                     (substitute* ld
                       (("@SELF@")
                        ld)
                       (("@GUILE@")
                        (string-append (assoc-ref %build-inputs "guile")
                                       "/bin/guile"))
                       (("@BASH@")
                        (string-append (assoc-ref %build-inputs "bash")
                                       "/bin/bash"))
                       (("@LD@")
                        (string-append (assoc-ref %build-inputs "binutils")
                                       ,(if target
                                            (string-append "/bin/"
                                                           target "-ld")
                                            "/bin/ld"))))
                     (chmod ld #o555)
                     (compile-file ld #:output-file go)))))
    (synopsis "The linker wrapper")
    (description
     "The linker wrapper (or 'ld-wrapper') wraps the linker to add any
missing '-rpath' flags, and to detect any misuse of libraries outside of the
store.")
    (home-page "http://www.gnu.org/software/guix/")
    (license gpl3+)))

(export make-ld-wrapper)

(define-public glibc/linux
  (package
   (name "glibc")
   (version "2.23")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/glibc/glibc-"
                                version ".tar.xz"))
            (sha256
             (base32
              "1s8krs3y2n6pzav7ic59dz41alqalphv7vww4138ag30wh0fpvwl"))
            (snippet
             ;; Disable 'ldconfig' and /etc/ld.so.cache.  The latter is
             ;; required on LFS distros to avoid loading the distro's libc.so
             ;; instead of ours.
             '(substitute* "sysdeps/unix/sysv/linux/configure"
                (("use_ldconfig=yes")
                 "use_ldconfig=no")))
            (modules '((guix build utils)))
            (patches (search-patches "glibc-ldd-x86_64.patch"
                                     "glibc-versioned-locpath.patch"
                                     "glibc-o-largefile.patch"))))
   (build-system gnu-build-system)

   ;; Glibc's <limits.h> refers to <linux/limit.h>, for instance, so glibc
   ;; users should automatically pull Linux headers as well.
   (propagated-inputs `(("kernel-headers" ,linux-libre-headers)))

   (outputs '("out" "debug"))

   (arguments
    `(#:out-of-source? #t

      ;; In version 2.21, there a race in the 'elf' directory, see
      ;; <http://lists.gnu.org/archive/html/guix-devel/2015-02/msg00709.html>.
      #:parallel-build? #f

      ;; The libraries have an empty RUNPATH, but some, such as the versioned
      ;; libraries (libdl-2.23.so, etc.) have ld.so marked as NEEDED.  Since
      ;; these libraries are always going to be found anyway, just skip
      ;; RUNPATH checks.
      #:validate-runpath? #f

      #:configure-flags
      (list "--enable-add-ons"
            "--sysconfdir=/etc"

            ;; Installing a locale archive with all the locales is to
            ;; expensive (~100 MiB), so we rely on users to install the
            ;; locales they really want.
            ;;
            ;; Set the default locale path.  In practice, $LOCPATH may be
            ;; defined to point whatever locales users want.  However, setuid
            ;; binaries don't honor $LOCPATH, so they'll instead look into
            ;; $libc_cv_localedir; we choose /run/current-system/locale/X.Y,
            ;; with the idea that it is going to be populated by the sysadmin.
            ;; The "X.Y" sub-directory is because locale data formats are
            ;; incompatible across libc versions; see
            ;; <https://lists.gnu.org/archive/html/guix-devel/2015-08/msg00737.html>.
            ;;
            ;; `--localedir' is not honored, so work around it.
            ;; See <http://sourceware.org/ml/libc-alpha/2013-03/msg00093.html>.
            ;; FIXME: This hack no longer works on 2.23!
            (string-append "libc_cv_localedir=/run/current-system/locale/"
                           ,version)

            (string-append "--with-headers="
                           (assoc-ref ,(if (%current-target-system)
                                           '%build-target-inputs
                                           '%build-inputs)
                                      "kernel-headers")
                           "/include")

            ;; This is the default for most architectures as of GNU libc 2.21,
            ;; but we specify it explicitly for clarity and consistency.  See
            ;; "kernel-features.h" in the GNU libc for details.
            "--enable-kernel=2.6.32"

            ;; Use our Bash instead of /bin/sh.
            (string-append "BASH_SHELL="
                           (assoc-ref %build-inputs "bash")
                           "/bin/bash")

            ;; XXX: Work around "undefined reference to `__stack_chk_guard'".
            "libc_cv_ssp=no" "libc_cv_ssp_strong=no")

      #:tests? #f                                 ; XXX
      #:phases (modify-phases %standard-phases
                 (add-before
                  'configure 'pre-configure
                  (lambda* (#:key inputs native-inputs outputs
                                  #:allow-other-keys)
                    (let* ((out  (assoc-ref outputs "out"))
                           (bin  (string-append out "/bin"))
                           ;; FIXME: Normally we would look it up only in INPUTS
                           ;; but cross-base uses it as a native input.
                           (bash (or (assoc-ref inputs "static-bash")
                                     (assoc-ref native-inputs "static-bash"))))
                      ;; Install the rpc data base file under `$out/etc/rpc'.
                      ;; FIXME: Use installFlags = [ "sysconfdir=$(out)/etc" ];
                      (substitute* "sunrpc/Makefile"
                        (("^\\$\\(inst_sysconfdir\\)/rpc(.*)$" _ suffix)
                         (string-append out "/etc/rpc" suffix "\n"))
                        (("^install-others =.*$")
                         (string-append "install-others = " out "/etc/rpc\n")))

                      (substitute* "Makeconfig"
                        ;; According to
                        ;; <http://www.linuxfromscratch.org/lfs/view/stable/chapter05/glibc.html>,
                        ;; linking against libgcc_s is not needed with GCC
                        ;; 4.7.1.
                        ((" -lgcc_s") ""))

                      ;; Have `system' use that Bash.
                      (substitute* "sysdeps/posix/system.c"
                        (("#define[[:blank:]]+SHELL_PATH.*$")
                         (format #f "#define SHELL_PATH \"~a/bin/bash\"\n"
                                 bash)))

                      ;; Same for `popen'.
                      (substitute* "libio/iopopen.c"
                        (("/bin/sh")
                         (string-append bash "/bin/bash")))

                      ;; Same for the shell used by the 'exec' functions for
                      ;; scripts that lack a shebang.
                      (substitute* (find-files "." "^paths\\.h$")
                        (("#define[[:blank:]]+_PATH_BSHELL[[:blank:]].*$")
                         (string-append "#define _PATH_BSHELL \""
                                        bash "/bin/bash\"\n")))

                      ;; Nscd uses __DATE__ and __TIME__ to create a string to
                      ;; make sure the client and server come from the same
                      ;; libc.  Use something deterministic instead.
                      (substitute* "nscd/nscd_stat.c"
                        (("static const char compilation\\[21\\] =.*$")
                         (string-append
                          "static const char compilation[21] = \""
                          (string-take (basename out) 20) "\";\n")))

                      ;; Make sure we don't retain a reference to the
                      ;; bootstrap Perl.
                      (substitute* "malloc/mtrace.pl"
                        (("^#!.*")
                         ;; The shebang can be omitted, because there's the
                         ;; "bilingual" eval/exec magic at the top of the file.
                         "")
                        (("exec @PERL@")
                         "exec perl"))))))))

   (inputs `(("static-bash" ,static-bash)))

   ;; To build the manual, we need Texinfo and Perl.  Gettext is needed to
   ;; install the message catalogs, with 'msgfmt'.
   (native-inputs `(("texinfo" ,texinfo)
                    ("perl" ,perl)
                    ("gettext" ,gnu-gettext)))

   (native-search-paths
    ;; Search path for packages that provide locale data.  This is useful
    ;; primarily in build environments.  Use 'GUIX_LOCPATH' rather than
    ;; 'LOCPATH' to avoid interference with the host system's libc on foreign
    ;; distros.
    (list (search-path-specification
           (variable "GUIX_LOCPATH")
           (files '("lib/locale")))))

   (synopsis "The GNU C Library")
   (description
    "Any Unix-like operating system needs a C library: the library which
defines the \"system calls\" and other basic facilities such as open, malloc,
printf, exit...

The GNU C library is used as the C library in the GNU system and most systems
with the Linux kernel.")
   (license lgpl2.0+)
   (home-page "http://www.gnu.org/software/libc/")))

(define-public glibc/hurd
  ;; The Hurd's libc variant.
  (package (inherit glibc/linux)
    (name "glibc-hurd")
    (version "2.19")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://alpha.gnu.org/gnu/hurd/glibc-"
                                  version "-hurd+libpthread-20160518" ".tar.gz"))
              (sha256
               (base32
                "12zmdjviybpsdb2kq4cg98rds7909f0cc96fzdahdfrzlxx1q0px"))))

    ;; Libc provides <hurd.h>, which includes a bunch of Hurd and Mach headers,
    ;; so both should be propagated.
    (propagated-inputs `(("hurd-core-headers" ,hurd-core-headers)))
    (native-inputs
     `(,@(package-native-inputs glibc/linux)
       ("mig" ,mig)
       ("perl" ,perl)))

    (arguments
     (substitute-keyword-arguments (package-arguments glibc/linux)
       ((#:phases original-phases)
        ;; Add libmachuser.so and libhurduser.so to libc.so's search path.
        ;; See <http://lists.gnu.org/archive/html/bug-hurd/2015-07/msg00051.html>.
        `(alist-cons-after
          'install 'augment-libc.so
          (lambda* (#:key outputs #:allow-other-keys)
            (let* ((out (assoc-ref outputs "out")))
              (substitute* (string-append out "/lib/libc.so")
                (("/[^ ]+/lib/libc.so.0.3")
                 (string-append out "/lib/libc.so.0.3" " libmachuser.so" " libhurduser.so"))))
            #t)
          (alist-cons-after
           'pre-configure 'pre-configure-set-pwd
           (lambda _
             ;; Use the right 'pwd'.
             (substitute* "configure"
               (("/bin/pwd") "pwd")))
          ,original-phases)))
        ((#:configure-flags original-configure-flags)
        `(append (list "--host=i586-pc-gnu"

                       ;; We need this to get a working openpty() function.
                       "--enable-pt_chown"

                       ;; nscd fails to build for GNU/Hurd:
                       ;; <https://lists.gnu.org/archive/html/bug-hurd/2014-07/msg00006.html>.
                       ;; Disable it.
                       "--disable-nscd")
                 (filter (lambda (flag)
                           (not (string-prefix? "--enable-kernel=" flag)))
                         ,original-configure-flags)))))
    (synopsis "The GNU C Library (GNU Hurd variant)")
    (supported-systems %hurd-systems)))

(define* (glibc-for-target #:optional
                           (target (or (%current-target-system)
                                       (%current-system))))
  "Return the glibc for TARGET, GLIBC/LINUX for a Linux host or
GLIBC/HURD for a Hurd host"
  (match target
    ((or "i586-pc-gnu" "i586-gnu") glibc/hurd)
    (_ glibc/linux)))

(define-syntax glibc
  (identifier-syntax (glibc-for-target)))

(define-public glibc-2.22
  ;; The old libc, which we use mostly to build locale data in the old format
  ;; (which the new libc can cope with.)
  (package
    (inherit glibc)
    (version "2.22")
    (source (origin
              (inherit (package-source glibc))
              (uri (string-append "mirror://gnu/glibc/glibc-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "0j49682pm2nh4qbdw35bas82p1pgfnz4d2l7iwfyzvrvj0318wzb"))
              (patches (search-patches "glibc-ldd-x86_64.patch"))))
    (arguments
      (substitute-keyword-arguments (package-arguments glibc)
        ((#:phases phases)
         `(modify-phases ,phases
            (add-before 'configure 'fix-pwd
              (lambda _
                ;; Use `pwd' instead of `/bin/pwd' for glibc-2.21
                (substitute* "configure"
                  (("/bin/pwd") "pwd"))))))))))

(define-public glibc-2.21
  ;; The old libc, which we use mostly to build locale data in the old format
  ;; (which the new libc can cope with.)
  (package
    (inherit glibc-2.22)
    (version "2.21")
    (source (origin
              (inherit (package-source glibc))
              (uri (string-append "mirror://gnu/glibc/glibc-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "1f135546j34s9bfkydmx2nhh9vwxlx60jldi80zmsnln6wj3dsxf"))
              (patches (search-patches "glibc-ldd-x86_64.patch"))))))

(define-public glibc-locales
  (package
    (inherit glibc)
    (name "glibc-locales")
    (source (origin (inherit (package-source glibc))
                    (patches (cons (search-patch "glibc-locales.patch")
                                   (origin-patches (package-source glibc))))))
    (synopsis "All the locales supported by the GNU C Library")
    (description
     "This package provides all the locales supported by the GNU C Library,
more than 400 in total.  To use them set the 'LOCPATH' environment variable to
the 'share/locale' sub-directory of this package.")
    (outputs '("out"))                            ;110+ MiB
    (native-search-paths '())
    (arguments
     (let ((args `(#:tests? #f #:strip-binaries? #f
                   ,@(package-arguments glibc))))
       (substitute-keyword-arguments args
         ((#:phases phases)
          `(alist-replace
            'build
            (lambda* (#:key outputs #:allow-other-keys)
              (zero? (system* "make" "localedata/install-locales"
                              "-j" (number->string (parallel-job-count)))))
            (alist-delete 'install ,phases)))
         ((#:configure-flags flags)
          `(append ,flags
                   ;; Use $(libdir)/locale/X.Y as is the case by default.
                   (list (string-append "libc_cv_complocaledir="
                                        (assoc-ref %outputs "out")
                                        "/lib/locale/"
                                        ,(package-version glibc))))))))))

(define-public glibc-utf8-locales
  (package
    (name "glibc-utf8-locales")
    (version (package-version glibc))
    (source #f)
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder (begin
                   (use-modules (srfi srfi-1)
                                (guix build utils))

                   (let* ((libc      (assoc-ref %build-inputs "glibc"))
                          (gzip      (assoc-ref %build-inputs "gzip"))
                          (out       (assoc-ref %outputs "out"))
                          (localedir (string-append out "/lib/locale/"
                                                    ,version)))
                     ;; 'localedef' needs 'gzip'.
                     (setenv "PATH" (string-append libc "/bin:" gzip "/bin"))

                     (mkdir-p localedir)
                     (every (lambda (locale)
                              (define file
                                ;; Use the "normalized codeset" by
                                ;; default--e.g., "en_US.utf8".
                                (string-append localedir "/" locale ".utf8"))

                              (and (zero? (system* "localedef" "--no-archive"
                                                   "--prefix" localedir
                                                   "-i" locale
                                                   "-f" "UTF-8" file))
                                   (begin
                                     ;; For backward compatibility with Guix
                                     ;; <= 0.8.3, add "xx_YY.UTF-8".
                                     (symlink (string-append locale ".utf8")
                                              (string-append localedir "/"
                                                             locale ".UTF-8"))
                                     #t)))

                            ;; These are the locales commonly used for
                            ;; tests---e.g., in Guile's i18n tests.
                            '("de_DE" "el_GR" "en_US" "fr_FR" "tr_TR"))))))
    (inputs `(("glibc" ,glibc)
              ("gzip" ,gzip)))
    (synopsis "Small sample of UTF-8 locales")
    (description
     "This package provides a small sample of UTF-8 locales mostly useful in
test environments.")
    (home-page (package-home-page glibc))
    (license (package-license glibc))))

(define-public which
  (package
    (name "which")
    (version "2.21")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/which/which-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1bgafvy3ypbhhfznwjv1lxmd6mci3x1byilnnkc7gcr486wlb8pl"))))
    (build-system gnu-build-system)
    (home-page "https://gnu.org/software/which/")
    (synopsis "Find full path of shell commands")
    (description
     "The which program finds the location of executables in PATH, with a
variety of options.  It is an alternative to the shell \"type\" built-in
command.")
    (license gpl3+))) ; some files are under GPLv2+

(define-public glibc/hurd-headers
  (package (inherit glibc/hurd)
    (name "glibc-hurd-headers")
    (outputs '("out"))
    (propagated-inputs `(("gnumach-headers" ,gnumach-headers)
                         ("hurd-headers" ,hurd-headers)))
    (arguments
     (substitute-keyword-arguments (package-arguments glibc/hurd)
       ;; We just pass the flags really needed to build the headers.
       ((#:configure-flags _)
        `(list "--enable-add-ons"
               "--host=i586-pc-gnu"
               "--enable-obsolete-rpc"))
       ((#:phases _)
        '(alist-replace
          'install
          (lambda* (#:key outputs #:allow-other-keys)
            (and (zero? (system* "make" "install-headers"))

                 ;; Make an empty stubs.h to work around not being able to
                 ;; produce a valid stubs.h and causing the build to fail. See
                 ;; <http://lists.gnu.org/archive/html/guix-devel/2014-04/msg00233.html>.
                 (let ((out (assoc-ref outputs "out")))
                   (close-port
                    (open-output-file
                     (string-append out "/include/gnu/stubs.h"))))))

          ;; Nothing to build.
          (alist-delete
           'build

           (alist-cons-before
            'configure 'pre-configure
            (lambda _
              ;; Use the right 'pwd'.
              (substitute* "configure"
                (("/bin/pwd") "pwd")))
            %standard-phases))))))))

(define-public tzdata
  (package
    (name "tzdata")
    (version "2015g")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "http://www.iana.org/time-zones/repository/releases/tzdata"
                   version ".tar.gz"))
             (sha256
              (base32
               "0qb1awqrn3215zd2jikpqnmkzrxwfjf0d3dw2xmnk4c40yzws8xr"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f
       #:make-flags (let ((out (assoc-ref %outputs "out"))
                          (tmp (getenv "TMPDIR")))
                      (list (string-append "TOPDIR=" out)
                            (string-append "TZDIR=" out "/share/zoneinfo")

                            ;; Discard zic, dump, and tzselect, already
                            ;; provided by glibc.
                            (string-append "ETCDIR=" tmp "/etc")

                            ;; Likewise for the C library routines.
                            (string-append "LIBDIR=" tmp "/lib")
                            (string-append "MANDIR=" tmp "/man")

                            "AWK=awk"
                            "CC=gcc"))
       #:modules ((guix build utils)
                  (guix build gnu-build-system)
                  (srfi srfi-1))
       #:phases
       (alist-replace
        'unpack
        (lambda* (#:key source inputs #:allow-other-keys)
          (and (zero? (system* "tar" "xvf" source))
               (zero? (system* "tar" "xvf" (assoc-ref inputs "tzcode")))))
        (alist-cons-after
         'install 'post-install
         (lambda* (#:key outputs #:allow-other-keys)
           ;; Move data in the right place.
           (let ((out (assoc-ref outputs "out")))
             (copy-recursively (string-append out "/share/zoneinfo-posix")
                               (string-append out "/share/zoneinfo/posix"))
             (copy-recursively (string-append out "/share/zoneinfo-leaps")
                               (string-append out "/share/zoneinfo/right"))
             (delete-file-recursively (string-append out "/share/zoneinfo-posix"))
             (delete-file-recursively (string-append out "/share/zoneinfo-leaps"))))
         (alist-delete 'configure %standard-phases)))))
    (inputs `(("tzcode" ,(origin
                          (method url-fetch)
                          (uri (string-append
                                "http://www.iana.org/time-zones/repository/releases/tzcode"
                                version ".tar.gz"))
                          (sha256
                           (base32
                            "1i3y1kzjiz2j62c7vd4wf85983sqk9x9lg3473njvbdz4kph5r0q"))))))
    (home-page "http://www.iana.org/time-zones")
    (synopsis "Database of current and historical time zones")
    (description "The Time Zone Database (often called tz or zoneinfo)
contains code and data that represent the history of local time for many
representative locations around the globe.  It is updated periodically to
reflect changes made by political bodies to time zone boundaries, UTC offsets,
and daylight-saving rules.")
    (license public-domain)))

(define-public libiconv
  (package
    (name "libiconv")
    (version "1.14")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/libiconv/libiconv-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "04q6lgl3kglmmhw59igq1n7v3rp1rpkypl366cy1k1yn2znlvckj"))
              (modules '((guix build utils)))
              (snippet
               ;; Work around "declared gets" error on glibc systems (fixed by
               ;; Gnulib commit 66712c23388e93e5c518ebc8515140fa0c807348.)
               '(substitute* "srclib/stdio.in.h"
                  (("^#undef gets") "")
                  (("^_GL_WARN_ON_USE \\(gets.*") "")))))
    (build-system gnu-build-system)
    (synopsis "Character set conversion library")
    (description
     "libiconv provides an implementation of the iconv function for systems
that lack it.  iconv is used to convert between character encodings in a
program.  It supports a wide variety of different encodings.")
    (home-page "http://www.gnu.org/software/libiconv/")
    (license lgpl3+)))

(define-public (canonical-package package)
  ;; Avoid circular dependency by lazily resolving 'commencement'.
  (let* ((iface (resolve-interface '(gnu packages commencement)))
         (proc  (module-ref iface 'canonical-package)))
    (proc package)))

;;; base.scm ends here
