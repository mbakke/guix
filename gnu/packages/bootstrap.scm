;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu packages bootstrap)
  #:use-module (guix licenses)
  #:use-module (gnu packages)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module ((guix store) #:select (add-to-store add-text-to-store))
  #:use-module ((guix derivations) #:select (derivation))
  #:use-module ((guix utils) #:select (gnu-triplet->nix-system))
  #:use-module (guix combinators)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)
  #:export (bootstrap-origin
            package-with-bootstrap-guile
            glibc-dynamic-linker

            %bootstrap-guile
            %bootstrap-coreutils&co
            %bootstrap-binutils
            %bootstrap-gcc
            %bootstrap-glibc
            %bootstrap-inputs))

;;; Commentary:
;;;
;;; Pre-built packages that are used to bootstrap the
;;; distribution--i.e., to build all the core packages from scratch.
;;;
;;; Code:



;;;
;;; Helper procedures.
;;;

(define (bootstrap-origin source)
  "Return a variant of SOURCE, an <origin> instance, whose method uses
%BOOTSTRAP-GUILE to do its job."
  (define (boot fetch)
    (lambda* (url hash-algo hash
              #:optional name #:key system)
      (fetch url hash-algo hash name
             #:guile %bootstrap-guile
             #:system system)))

  (define %bootstrap-patch-inputs
    ;; Packages used when an <origin> has a non-empty 'patches' field.
    `(("tar"   ,%bootstrap-coreutils&co)
      ("xz"    ,%bootstrap-coreutils&co)
      ("bzip2" ,%bootstrap-coreutils&co)
      ("gzip"  ,%bootstrap-coreutils&co)
      ("patch" ,%bootstrap-coreutils&co)))

  (let ((orig-method (origin-method source)))
    (origin (inherit source)
      (method (cond ((eq? orig-method url-fetch)
                     (boot url-fetch))
                    (else orig-method)))
      (patch-guile %bootstrap-guile)
      (patch-inputs %bootstrap-patch-inputs)

      ;; Patches can be origins as well, so process them.
      (patches (map (match-lambda
                     ((? origin? patch)
                      (bootstrap-origin patch))
                     (patch patch))
                    (origin-patches source))))))

(define* (package-from-tarball name source program-to-test description
                               #:key snippet)
  "Return a package that correspond to the extraction of SOURCE.
PROGRAM-TO-TEST is a program to run after extraction of SOURCE, to
check whether everything is alright.  If SNIPPET is provided, it is
evaluated after extracting SOURCE.  SNIPPET should return true if
successful, or false to signal an error."
  (package
    (name name)
    (version "0")
    (build-system trivial-build-system)
    (arguments
     `(#:guile ,%bootstrap-guile
       #:modules ((guix build utils))
       #:builder
       (let ((out     (assoc-ref %outputs "out"))
             (tar     (assoc-ref %build-inputs "tar"))
             (xz      (assoc-ref %build-inputs "xz"))
             (tarball (assoc-ref %build-inputs "tarball")))
         (use-modules (guix build utils))

         (mkdir out)
         (copy-file tarball "binaries.tar.xz")
         (system* xz "-d" "binaries.tar.xz")
         (let ((builddir (getcwd)))
           (with-directory-excursion out
             (and (zero? (system* tar "xvf"
                                  (string-append builddir "/binaries.tar")))
                  ,@(if snippet (list snippet) '())
                  (zero? (system* (string-append "bin/" ,program-to-test)
                                  "--version"))))))))
    (inputs
     `(("tar" ,(search-bootstrap-binary "tar" (%current-system)))
       ("xz"  ,(search-bootstrap-binary "xz" (%current-system)))
       ("tarball" ,(bootstrap-origin (source (%current-system))))))
    (source #f)
    (synopsis description)
    (description description)
    (home-page #f)
    (license gpl3+)))

(define package-with-bootstrap-guile
  (memoize
   (lambda (p)
    "Return a variant of P such that all its origins are fetched with
%BOOTSTRAP-GUILE."
    (define rewritten-input
      (match-lambda
       ((name (? origin? o))
        `(,name ,(bootstrap-origin o)))
       ((name (? package? p) sub-drvs ...)
        `(,name ,(package-with-bootstrap-guile p) ,@sub-drvs))
       (x x)))

    (package (inherit p)
      (source (match (package-source p)
                ((? origin? o) (bootstrap-origin o))
                (s s)))
      (inputs (map rewritten-input
                   (package-inputs p)))
      (native-inputs (map rewritten-input
                          (package-native-inputs p)))
      (propagated-inputs (map rewritten-input
                              (package-propagated-inputs p)))
      (replacement (and=> (package-replacement p)
                          package-with-bootstrap-guile))))))

(define* (glibc-dynamic-linker
          #:optional (system (or (and=> (%current-target-system)
                                        gnu-triplet->nix-system)
                                 (%current-system))))
  "Return the name of Glibc's dynamic linker for SYSTEM."
  (cond ((string=? system "x86_64-linux") "/lib/ld-linux-x86-64.so.2")
        ((string=? system "i686-linux") "/lib/ld-linux.so.2")
        ((string=? system "armhf-linux") "/lib/ld-linux-armhf.so.3")
        ((string=? system "mips64el-linux") "/lib/ld.so.1")
        ((string=? system "i586-gnu") "/lib/ld.so.1")
        ((string=? system "i686-gnu") "/lib/ld.so.1")
        ((string=? system "aarch64-linux") "/lib/ld-linux-aarch64.so.1")

        ;; XXX: This one is used bare-bones, without a libc, so add a case
        ;; here just so we can keep going.
        ((string=? system "xtensa-elf") "no-ld.so")
        ((string=? system "avr") "no-ld.so")
        ((string=? system "i686-mingw") "no-ld.so")

        (else (error "dynamic linker name not known for this system"
                     system))))


;;;
;;; Bootstrap packages.
;;;

(define* (raw-build store name inputs
                    #:key outputs system search-paths
                    #:allow-other-keys)
  (define (->store file)
    (add-to-store store file #t "sha256"
                  (or (search-bootstrap-binary file
                                               system)
                      (error "bootstrap binary not found"
                             file system))))

  (let* ((tar   (->store "tar"))
         (xz    (->store "xz"))
         (mkdir (->store "mkdir"))
         (bash  (->store "bash"))
         (guile (->store (match system
                           ("armhf-linux"
                            "guile-2.0.11.tar.xz")
                           (_
                            "guile-2.0.9.tar.xz"))))
         ;; The following code, run by the bootstrap guile after it is
         ;; unpacked, creates a wrapper for itself to set its load path.
         ;; This replaces the previous non-portable method based on
         ;; reading the /proc/self/exe symlink.
         (make-guile-wrapper
          '(begin
             (use-modules (ice-9 match))
             (match (command-line)
               ((_ out bash)
                (let ((bin-dir    (string-append out "/bin"))
                      (guile      (string-append out "/bin/guile"))
                      (guile-real (string-append out "/bin/.guile-real"))
                      ;; We must avoid using a bare dollar sign in this code,
                      ;; because it would be interpreted by the shell.
                      (dollar     (string (integer->char 36))))
                  (chmod bin-dir #o755)
                  (rename-file guile guile-real)
                  (call-with-output-file guile
                    (lambda (p)
                      (format p "\
#!~a
export GUILE_SYSTEM_PATH=~a/share/guile/2.0
export GUILE_SYSTEM_COMPILED_PATH=~a/lib/guile/2.0/ccache
exec -a \"~a0\" ~a \"~a@\"\n"
                              bash out out dollar guile-real dollar)))
                  (chmod guile   #o555)
                  (chmod bin-dir #o555))))))
         (builder
          (add-text-to-store store
                             "build-bootstrap-guile.sh"
                             (format #f "
echo \"unpacking bootstrap Guile to '$out'...\"
~a $out
cd $out
~a -dc < ~a | ~a xv

# Use the bootstrap guile to create its own wrapper to set the load path.
GUILE_SYSTEM_PATH=$out/share/guile/2.0 \
GUILE_SYSTEM_COMPILED_PATH=$out/lib/guile/2.0/ccache \
$out/bin/guile -c ~s $out ~a

# Sanity check.
$out/bin/guile --version~%"
                                     mkdir xz guile tar
                                     (format #f "~s" make-guile-wrapper)
                                     bash)
                             (list mkdir xz guile tar bash))))
    (derivation store name
                bash `(,builder)
                #:system system
                #:inputs `((,bash) (,builder)))))

(define* (make-raw-bag name
                       #:key source inputs native-inputs outputs
                       system target)
  (bag
    (name name)
    (system system)
    (build-inputs inputs)
    (build raw-build)))

(define %bootstrap-guile
  ;; The Guile used to run the build scripts of the initial derivations.
  ;; It is just unpacked from a tarball containing a pre-built binary.
  ;; This is typically built using %GUILE-BOOTSTRAP-TARBALL below.
  ;;
  ;; XXX: Would need libc's `libnss_files2.so' for proper `getaddrinfo'
  ;; support (for /etc/services).
  (let ((raw (build-system
               (name 'raw)
               (description "Raw build system with direct store access")
               (lower make-raw-bag))))
   (package
     (name "guile-bootstrap")
     (version "2.0")
     (source #f)
     (build-system raw)
     (synopsis "Bootstrap Guile")
     (description "Pre-built Guile for bootstrapping purposes.")
     (home-page #f)
     (license lgpl3+))))

(define %bootstrap-base-urls
  ;; This is where the initial binaries come from.
  '("http://alpha.gnu.org/gnu/guix/bootstrap"
    "http://www.fdn.fr/~lcourtes/software/guix/packages"))

(define %bootstrap-coreutils&co
  (package-from-tarball "bootstrap-binaries"
                        (lambda (system)
                          (origin
                           (method url-fetch)
                           (uri (map (cut string-append <> "/" system
                                          (match system
                                            ("armhf-linux"
                                             "/20150101/static-binaries.tar.xz")
                                            (_
                                             "/20131110/static-binaries.tar.xz")))
                                     %bootstrap-base-urls))
                           (sha256
                            (match system
                              ("x86_64-linux"
                               (base32
                                "0c533p9dhczzcsa1117gmfq3pc8w362g4mx84ik36srpr7cx2bg4"))
                              ("i686-linux"
                               (base32
                                "0s5b3jb315n13m1k8095l0a5hfrsz8g0fv1b6riyc5hnxqyphlak"))
                              ("armhf-linux"
                               (base32
                                "0gf0fn2kbpxkjixkmx5f4z6hv6qpmgixl69zgg74dbsfdfj8jdv5"))
                              ("mips64el-linux"
                               (base32
                                "072y4wyfsj1bs80r6vbybbafy8ya4vfy7qj25dklwk97m6g71753"))))))
                        "fgrep"                    ; the program to test
                        "Bootstrap binaries of Coreutils, Awk, etc."
                        #:snippet
                        '(let ((path (list (string-append (getcwd) "/bin"))))
                           (chmod "bin" #o755)
                           (patch-shebang "bin/egrep" path)
                           (patch-shebang "bin/fgrep" path)
                           (chmod "bin" #o555)
                           #t)))

(define %bootstrap-binutils
  (package-from-tarball "binutils-bootstrap"
                        (lambda (system)
                          (origin
                           (method url-fetch)
                           (uri (map (cut string-append <> "/" system
                                          (match system
                                            ("armhf-linux"
                                             "/20150101/binutils-2.25.tar.xz")
                                            (_
                                             "/20131110/binutils-2.23.2.tar.xz")))
                                     %bootstrap-base-urls))
                           (sha256
                            (match system
                              ("x86_64-linux"
                               (base32
                                "1j5yivz7zkjqfsfmxzrrrffwyayjqyfxgpi89df0w4qziqs2dg20"))
                              ("i686-linux"
                               (base32
                                "14jgwf9gscd7l2pnz610b1zia06dvcm2qyzvni31b8zpgmcai2v9"))
                              ("armhf-linux"
                               (base32
                                "1v7dj6bzn6m36f20gw31l99xaabq4xrhrx3gwqkhhig0mdlmr69q"))
                              ("mips64el-linux"
                               (base32
                                "1x8kkhcxmfyzg1ddpz2pxs6fbdl6412r7x0nzbmi5n7mj8zw2gy7"))))))
                        "ld"                      ; the program to test
                        "Bootstrap binaries of the GNU Binutils"))

(define %bootstrap-glibc
  ;; The initial libc.
  (package
    (name "glibc-bootstrap")
    (version "0")
    (source #f)
    (build-system trivial-build-system)
    (arguments
     `(#:guile ,%bootstrap-guile
       #:modules ((guix build utils))
       #:builder
       (let ((out     (assoc-ref %outputs "out"))
             (tar     (assoc-ref %build-inputs "tar"))
             (xz      (assoc-ref %build-inputs "xz"))
             (tarball (assoc-ref %build-inputs "tarball")))
         (use-modules (guix build utils))

         (mkdir out)
         (copy-file tarball "binaries.tar.xz")
         (system* xz "-d" "binaries.tar.xz")
         (let ((builddir (getcwd)))
           (with-directory-excursion out
             (system* tar "xvf"
                      (string-append builddir
                                     "/binaries.tar"))
             (chmod "lib" #o755)

             ;; Patch libc.so so it refers to the right path.
             (substitute* "lib/libc.so"
               (("/[^ ]+/lib/(libc|ld)" _ prefix)
                (string-append out "/lib/" prefix))))))))
    (inputs
     `(("tar" ,(search-bootstrap-binary "tar" (%current-system)))
       ("xz"  ,(search-bootstrap-binary "xz" (%current-system)))
       ("tarball" ,(bootstrap-origin
                    (origin
                     (method url-fetch)
                     (uri (map (cut string-append <> "/" (%current-system)
                                    (match (%current-system)
                                      ("armhf-linux"
                                       "/20150101/glibc-2.20.tar.xz")
                                      (_
                                       "/20131110/glibc-2.18.tar.xz")))
                               %bootstrap-base-urls))
                     (sha256
                      (match (%current-system)
                        ("x86_64-linux"
                         (base32
                          "0jlqrgavvnplj1b083s20jj9iddr4lzfvwybw5xrcis9spbfzk7v"))
                        ("i686-linux"
                         (base32
                          "1hgrccw1zqdc7lvgivwa54d9l3zsim5pqm0dykxg0z522h6gr05w"))
                        ("armhf-linux"
                         (base32
                          "18cmgvpllqfpn6khsmivqib7ys8ymnq0hdzi3qp24prik0ykz8gn"))
                        ("mips64el-linux"
                         (base32
                          "0k97a3whzx3apsi9n2cbsrr79ad6lh00klxph9hw4fqyp1abkdsg")))))))))
    (synopsis "Bootstrap binaries and headers of the GNU C Library")
    (description synopsis)
    (home-page #f)
    (license lgpl2.1+)))

(define %bootstrap-gcc
  ;; The initial GCC.  Uses binaries from a tarball typically built by
  ;; %GCC-BOOTSTRAP-TARBALL.
  (package
    (name "gcc-bootstrap")
    (version "0")
    (source #f)
    (build-system trivial-build-system)
    (arguments
     `(#:guile ,%bootstrap-guile
       #:modules ((guix build utils))
       #:builder
       (let ((out     (assoc-ref %outputs "out"))
             (tar     (assoc-ref %build-inputs "tar"))
             (xz      (assoc-ref %build-inputs "xz"))
             (bash    (assoc-ref %build-inputs "bash"))
             (libc    (assoc-ref %build-inputs "libc"))
             (tarball (assoc-ref %build-inputs "tarball")))
         (use-modules (guix build utils)
                      (ice-9 popen))

         (mkdir out)
         (copy-file tarball "binaries.tar.xz")
         (system* xz "-d" "binaries.tar.xz")
         (let ((builddir (getcwd))
               (bindir   (string-append out "/bin")))
           (with-directory-excursion out
             (system* tar "xvf"
                      (string-append builddir "/binaries.tar")))

           (with-directory-excursion bindir
             (chmod "." #o755)
             (rename-file "gcc" ".gcc-wrapped")
             (call-with-output-file "gcc"
               (lambda (p)
                 (format p "#!~a
exec ~a/bin/.gcc-wrapped -B~a/lib \
     -Wl,-rpath -Wl,~a/lib \
     -Wl,-dynamic-linker -Wl,~a/~a \"$@\"~%"
                         bash
                         out libc libc libc
                         ,(glibc-dynamic-linker))))

             (chmod "gcc" #o555))))))
    (inputs
     `(("tar" ,(search-bootstrap-binary "tar" (%current-system)))
       ("xz"  ,(search-bootstrap-binary "xz" (%current-system)))
       ("bash" ,(search-bootstrap-binary "bash" (%current-system)))
       ("libc" ,%bootstrap-glibc)
       ("tarball" ,(bootstrap-origin
                    (origin
                     (method url-fetch)
                     (uri (map (cut string-append <> "/" (%current-system)
                                    (match (%current-system)
                                      ("armhf-linux"
                                       "/20150101/gcc-4.8.4.tar.xz")
                                      (_
                                       "/20131110/gcc-4.8.2.tar.xz")))
                               %bootstrap-base-urls))
                     (sha256
                      (match (%current-system)
                        ("x86_64-linux"
                         (base32
                          "17ga4m6195n4fnbzdkmik834znkhs53nkypp6557pl1ps7dgqbls"))
                        ("i686-linux"
                         (base32
                          "150c1arrf2k8vfy6dpxh59vcgs4p1bgiz2av5m19dynpks7rjnyw"))
                        ("armhf-linux"
                         (base32
                          "0ghz825yzp43fxw53kd6afm8nkz16f7dxi9xi40bfwc8x3nbbr8v"))
                        ("mips64el-linux"
                         (base32
                          "1m5miqkyng45l745n0sfafdpjkqv9225xf44jqkygwsipj2cv9ks")))))))))
    (native-search-paths
     (list (search-path-specification
            (variable "CPATH")
            (files '("include")))
           (search-path-specification
            (variable "LIBRARY_PATH")
            (files '("lib" "lib64")))))
    (synopsis "Bootstrap binaries of the GNU Compiler Collection")
    (description synopsis)
    (home-page #f)
    (license gpl3+)))

(define %bootstrap-inputs
  ;; The initial, pre-built inputs.  From now on, we can start building our
  ;; own packages.
  `(("libc" ,%bootstrap-glibc)
    ("gcc" ,%bootstrap-gcc)
    ("binutils" ,%bootstrap-binutils)
    ("coreutils&co" ,%bootstrap-coreutils&co)

    ;; In gnu-build-system.scm, we rely on the availability of Bash.
    ("bash" ,%bootstrap-coreutils&co)))

;;; bootstrap.scm ends here
