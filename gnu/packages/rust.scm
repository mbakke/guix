;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 David Craven <david@craven.ch>
;;; Copyright © 2016 Eric Le Bihan <eric.le.bihan.dev@free.fr>
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

(define-module (gnu packages rust)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bootstrap)
  #:use-module (gnu packages cmake)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages elf)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages jemalloc)
  #:use-module (gnu packages llvm)
  #:use-module (gnu packages python)
  #:use-module (gnu packages version-control)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (guix download)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-26))

;; Should be one less than the current released version.
(define %rust-bootstrap-binaries-version "1.12.1")

(define %rust-bootstrap-binaries
  (origin
    (method url-fetch)
    (uri (string-append
          "https://static.rust-lang.org/dist/"
          "rust-" %rust-bootstrap-binaries-version
          "-i686-unknown-linux-gnu.tar.gz"))
    (sha256
     (base32
      "1cvbx7bbhbn3w6pn64rp9fdp2n17rwzxgsnifncw5nqx9p8vksgd"))))

(define (increment-rust-version rust-version major patch)
  (match (string-split rust-version #\.)
    (("1" minor _)
     (string-append (number->string major) "."
                    (number->string (+ (string->number minor) 1)) "."
                    (number->string patch)))))

(define* (cargo-version rustc-version #:optional (patch 0))
  ;; Computes the cargo version that matches the rustc version.
  ;; https://github.com/rust-lang/cargo#Releases
  (increment-rust-version rustc-version 0 patch))

(define* (rustc-version bootstrap-version #:optional (patch 0))
  ;; Computes the rustc version that can be compiled from a given
  ;; other rustc version. The patch argument is for selecting
  ;; a stability or security fix. 1.11.0 -> 1.12.1 -> 1.13.0
  (increment-rust-version bootstrap-version 1 patch))

(define rustc-bootstrap
  (package
    (name "rustc-bootstrap")
    (version %rust-bootstrap-binaries-version)
    (source %rust-bootstrap-binaries)
    (build-system gnu-build-system)
    (native-inputs
     `(("patchelf" ,patchelf)))
    (inputs
     `(("gcc:lib" ,(canonical-package gcc) "lib")
       ("zlib" ,zlib)))
    (arguments
     `(#:tests? #f
       #:strip-binaries? #f
       #:system "i686-linux"
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (delete 'build)
         (replace 'install
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (gcc:lib (assoc-ref inputs "gcc:lib"))
                    (libc (assoc-ref inputs "libc"))
                    (zlib (assoc-ref inputs "zlib"))
                    (ld-so (string-append libc
                                          ,(glibc-dynamic-linker "i686-linux")))
                    (rpath (string-append out "/lib:" zlib "/lib:"
                                          libc "/lib:" gcc:lib "/lib"))
                    (rustc (string-append out "/bin/rustc"))
                    (rustdoc (string-append out "/bin/rustdoc")))
               (system* "bash" "install.sh"
                        (string-append "--prefix=" out)
                        (string-append "--components=rustc,"
                                       "rust-std-i686-unknown-linux-gnu"))
               (for-each (lambda (file)
                           (system* "patchelf" "--set-rpath" rpath file))
                         (cons* rustc rustdoc (find-files out "\\.so$")))
               (for-each (lambda (file)
                           (system* "patchelf" "--set-interpreter" ld-so file))
                         (list rustc rustdoc))))))))
    (supported-systems '("i686-linux" "x86_64-linux"))
    (home-page "https://www.rust-lang.org")
    (synopsis "Prebuilt rust compiler")
    (description "This package provides a pre-built @command{rustc} compiler,
which can in turn be used to build the final Rust compiler.")
    (license license:asl2.0)))

;; FIXME: Make private once cargo is packaged. Is currently used by the
;; cargo-build-system.
(define-public cargo-bootstrap
  (package
    (name "cargo-bootstrap")
    (version (cargo-version %rust-bootstrap-binaries-version))
    (source %rust-bootstrap-binaries)
    (build-system gnu-build-system)
    (native-inputs
     `(("patchelf" ,patchelf)))
    (inputs
     `(("gcc:lib" ,(canonical-package gcc) "lib")))
    (arguments
     `(#:tests? #f
       #:strip-binaries? #f
       #:system "i686-linux"
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (delete 'build)
         (replace 'install
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (gcc:lib (assoc-ref inputs "gcc:lib"))
                    (libc (assoc-ref inputs "libc"))
                    (ld-so (string-append libc
                                          ,(glibc-dynamic-linker "i686-linux")))
                    (rpath (string-append out "/lib:" libc "/lib:"
                                          gcc:lib "/lib"))
                    (cargo (string-append out "/bin/cargo")))
               (system* "bash" "install.sh"
                        (string-append "--prefix=" out)
                        "--components=cargo")
               (system* "patchelf"
                        "--set-interpreter" ld-so
                        "--set-rpath" rpath
                        cargo)))))))
    (supported-systems '("i686-linux" "x86_64-linux"))
    (home-page "https://www.rust-lang.org")
    (synopsis "Prebuilt cargo package manager")
    (description "This package provides a pre-built @command{cargo} package
manager, which is required to build itself.")
    (license license:asl2.0)))

(define rust-bootstrap
  (package
    (name "rust-bootstrap")
    (version %rust-bootstrap-binaries-version)
    (source #f)
    (build-system trivial-build-system)
    (propagated-inputs
     `(("rustc-bootstrap" ,rustc-bootstrap)
       ("cargo-bootstrap" ,cargo-bootstrap)
       ("gcc" ,(canonical-package gcc))))
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (let ((out (assoc-ref %outputs "out"))
               (gcc (assoc-ref %build-inputs "gcc")))
           (mkdir-p (string-append out "/bin"))
           ;; Rust requires a C toolchain for linking. The prebuilt
           ;; binaries expect a compiler called cc. Thus symlink gcc
           ;; to cc.
           (symlink (string-append gcc "/bin/gcc")
                    (string-append out "/bin/cc"))))))
    (home-page "https://www.rust-lang.org")
    (synopsis "Rust bootstrapping meta package")
    (description "Meta package for a rust environment. Provides pre-compiled
rustc-bootstrap and cargo-bootstrap packages.")
    (license license:asl2.0)))

(define-public rustc
  (package
    (name "rustc")
    (version (rustc-version %rust-bootstrap-binaries-version))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://static.rust-lang.org/dist/"
                    "rustc-" version "-src.tar.gz"))
              (sha256
               (base32
                "112h7qgbn8c7s5880vplpgy5n58sc8css32dq7z5wylpr9slgf7c"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("cmake" ,cmake)
       ("git" ,git)
       ("python-2" ,python-2)
       ("rust-bootstrap" ,rust-bootstrap)
       ("which" ,which)))
    (inputs
     `(("jemalloc" ,jemalloc)
       ("llvm" ,llvm)))
    (arguments
     ;; FIXME: Test failure with llvm 3.8; Update llvm.
     ;; https://github.com/rust-lang/rust/issues/36835
     `(#:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-configure
           (lambda _
             ;; Detect target CPU correctly.
             (substitute* "configure"
               (("/usr/bin/env") (which "env")))
             ;; Avoid curl as a build dependency.
             (substitute* "configure"
               (("probe_need CFG_CURL curl") ""))))
         (add-after 'unpack 'set-env
           (lambda _
             (setenv "SHELL" (which "sh"))
             (setenv "CONFIG_SHELL" (which "sh"))))
         (add-after 'unpack 'patch-lockfile-test
           (lambda _
             (substitute* "src/tools/tidy/src/main.rs"
               (("^.*cargo.*::check.*$") ""))))
         (replace 'configure
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (gcc (assoc-ref inputs "gcc"))
                    (python (assoc-ref inputs "python-2"))
                    (rustc (assoc-ref inputs "rustc-bootstrap"))
                    (llvm (assoc-ref inputs "llvm"))
                    (jemalloc (assoc-ref inputs "jemalloc"))
                    (flags (list
                            (string-append "--prefix=" out)
                            (string-append "--datadir=" out "/share")
                            (string-append "--infodir=" out "/share/info")
                            (string-append "--default-linker=" gcc "/bin/gcc")
                            (string-append "--default-ar=" gcc "/bin/ar")
                            (string-append "--python=" python "/bin/python2")
                            (string-append "--local-rust-root=" rustc)
                            (string-append "--llvm-root=" llvm)
                            (string-append "--jemalloc-root=" jemalloc "/lib")
                            "--release-channel=stable"
                            "--enable-rpath"
                            "--enable-local-rust"
                            ;;"--enable-rustbuild"
                            "--disable-manage-submodules")))
               ;; Rust uses a custom configure script (no autoconf).
               (zero? (apply system* "./configure" flags))))))))
    (synopsis "Compiler for the Rust progamming language")
    (description "Rust is a systems programming language that provides memory
safety and thread safety guarantees.")
    (home-page "https://www.rust-lang.org")
    ;; Dual licensed.
    (license (list license:asl2.0 license:expat))))
