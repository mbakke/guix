;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Theodoros Foradis <theodoros.for@openmailbox.org>
;;; Copyright © 2016 David Craven <david@craven.ch>
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

(define-module (gnu packages embedded)
  #:use-module (guix utils)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix svn-download)
  #:use-module (guix git-download)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (guix build utils)
  #:use-module (gnu packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages cross-base)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages gdb)
  #:use-module (gnu packages libftdi)
  #:use-module (gnu packages libusb)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages texinfo)
  #:use-module (srfi srfi-1))

;; We must not use the released GCC sources here, because the cross-compiler
;; does not produce working binaries.  Instead we take the very same SVN
;; revision from the branch that is used for a release of the "GCC ARM
;; embedded" project on launchpad.
;; See https://launchpadlibrarian.net/218827644/release.txt
(define-public gcc-arm-none-eabi-4.9
  (let ((xgcc (cross-gcc "arm-none-eabi"
                         (cross-binutils "arm-none-eabi")))
        (revision "1")
        (svn-revision 227977))
    (package (inherit xgcc)
      (version (string-append (package-version xgcc) "-"
                              revision "." (number->string svn-revision)))
      (source
       (origin
         (method svn-fetch)
         (uri (svn-reference
               (url "svn://gcc.gnu.org/svn/gcc/branches/ARM/embedded-4_9-branch/")
               (revision svn-revision)))
         (file-name (string-append "gcc-arm-embedded-" version "-checkout"))
         (sha256
          (base32
           "113r98kygy8rrjfv2pd3z6zlfzbj543pq7xyq8bgh72c608mmsbr"))

         ;; Remove the one patch that doesn't apply to this 4.9 snapshot (the
         ;; patch is for 4.9.4 and later but this svn snapshot is older).
         (patches (remove (lambda (patch)
                            (string=? (basename patch)
                                      "gcc-arm-bug-71399.patch"))
                          (origin-patches (package-source xgcc))))))
      (native-inputs
       `(("flex" ,flex)
         ,@(package-native-inputs xgcc)))
      (arguments
       (substitute-keyword-arguments (package-arguments xgcc)
         ((#:phases phases)
          `(modify-phases ,phases
             (add-after 'unpack 'fix-genmultilib
               (lambda _
                 (substitute* "gcc/genmultilib"
                   (("#!/bin/sh") (string-append "#!" (which "sh"))))
                 #t))))
         ((#:configure-flags flags)
          ;; The configure flags are largely identical to the flags used by the
          ;; "GCC ARM embedded" project.
          `(append (list "--enable-multilib"
                         "--with-newlib"
                         "--with-multilib-list=armv6-m,armv7-m,armv7e-m"
                         "--with-host-libstdcxx=-static-libgcc -Wl,-Bstatic,-lstdc++,-Bdynamic -lm"
                         "--enable-plugins"
                         "--disable-decimal-float"
                         "--disable-libffi"
                         "--disable-libgomp"
                         "--disable-libmudflap"
                         "--disable-libquadmath"
                         "--disable-libssp"
                         "--disable-libstdcxx-pch"
                         "--disable-nls"
                         "--disable-shared"
                         "--disable-threads"
                         "--disable-tls")
                   (delete "--disable-multilib" ,flags)))))
      (native-search-paths
       (list (search-path-specification
              (variable "CROSS_C_INCLUDE_PATH")
              (files '("arm-none-eabi/include")))
             (search-path-specification
              (variable "CROSS_CPLUS_INCLUDE_PATH")
              (files '("arm-none-eabi/include")))
             (search-path-specification
              (variable "CROSS_LIBRARY_PATH")
              (files '("arm-none-eabi/lib"))))))))

(define-public gcc-arm-none-eabi-6
  (package
    (inherit gcc-arm-none-eabi-4.9)
    (version (package-version gcc-6))
    (source (origin (inherit (package-source gcc-6))
                    (patches
                     (append
                      (origin-patches (package-source gcc-6))
                      (search-patches "gcc-6-cross-environment-variables.patch"
                                      "gcc-6-arm-none-eabi-multilib.patch")))))))

(define-public newlib-arm-none-eabi
  (package
    (name "newlib")
    (version "2.4.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "ftp://sourceware.org/pub/newlib/newlib-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "01i7qllwicf05vsvh39qj7qp5fdifpvvky0x95hjq39mbqiksnsl"))))
    (build-system gnu-build-system)
    (arguments
     `(#:out-of-source? #t
       ;; The configure flags are identical to the flags used by the "GCC ARM
       ;; embedded" project.
       #:configure-flags '("--target=arm-none-eabi"
                           "--enable-newlib-io-long-long"
                           "--enable-newlib-register-fini"
                           "--disable-newlib-supplied-syscalls"
                           "--disable-nls")
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-references-to-/bin/sh
           (lambda _
             (substitute* '("libgloss/arm/cpu-init/Makefile.in"
                            "libgloss/arm/Makefile.in"
                            "libgloss/libnosys/Makefile.in"
                            "libgloss/Makefile.in")
               (("/bin/sh") (which "sh")))
             #t)))))
    (native-inputs
     `(("xbinutils" ,(cross-binutils "arm-none-eabi"))
       ("xgcc" ,gcc-arm-none-eabi-4.9)
       ("texinfo" ,texinfo)))
    (home-page "http://www.sourceware.org/newlib/")
    (synopsis "C library for use on embedded systems")
    (description "Newlib is a C library intended for use on embedded
systems.  It is a conglomeration of several library parts that are easily
usable on embedded products.")
    (license (license:non-copyleft
              "https://www.sourceware.org/newlib/COPYING.NEWLIB"))))

(define-public newlib-nano-arm-none-eabi
  (package (inherit newlib-arm-none-eabi)
    (name "newlib-nano")
    (arguments
     (substitute-keyword-arguments (package-arguments newlib-arm-none-eabi)
       ;; The configure flags are identical to the flags used by the "GCC ARM
       ;; embedded" project.  They optimize newlib for use on small embedded
       ;; systems with limited memory.
       ((#:configure-flags flags)
        ''("--target=arm-none-eabi"
           "--enable-multilib"
           "--disable-newlib-supplied-syscalls"
           "--enable-newlib-reent-small"
           "--disable-newlib-fvwrite-in-streamio"
           "--disable-newlib-fseek-optimization"
           "--disable-newlib-wide-orient"
           "--enable-newlib-nano-malloc"
           "--disable-newlib-unbuf-stream-opt"
           "--enable-lite-exit"
           "--enable-newlib-global-atexit"
           "--enable-newlib-nano-formatted-io"
           "--disable-nls"))))
    (synopsis "Newlib variant for small systems with limited memory")))

(define (arm-none-eabi-toolchain xgcc newlib)
  "Produce a cross-compiler toolchain package with the compiler XGCC and the C
library variant NEWLIB."
  (let ((newlib-with-xgcc (package (inherit newlib)
                            (native-inputs
                             (alist-replace "xgcc" (list xgcc)
                                            (package-native-inputs newlib))))))
    (package
      (name (string-append "arm-none-eabi"
                           (if (string=? (package-name newlib-with-xgcc)
                                         "newlib-nano")
                               "-nano" "")
                           "-toolchain"))
      (version (package-version xgcc))
      (source #f)
      (build-system trivial-build-system)
      (arguments '(#:builder (mkdir %output)))
      (propagated-inputs
       `(("binutils" ,(cross-binutils "arm-none-eabi"))
         ("gcc" ,xgcc)
         ("newlib" ,newlib-with-xgcc)))
      (synopsis "Complete GCC tool chain for ARM bare metal development")
      (description "This package provides a complete GCC tool chain for ARM
bare metal development.  This includes the GCC arm-none-eabi cross compiler
and newlib (or newlib-nano) as the C library.  The supported programming
languages are C and C++.")
      (home-page (package-home-page xgcc))
      (license (package-license xgcc)))))

(define-public arm-none-eabi-toolchain-4.9
  (arm-none-eabi-toolchain gcc-arm-none-eabi-4.9
                           newlib-arm-none-eabi))

(define-public arm-none-eabi-nano-toolchain-4.9
  (arm-none-eabi-toolchain gcc-arm-none-eabi-4.9
                           newlib-nano-arm-none-eabi))

(define-public arm-none-eabi-toolchain-6
  (arm-none-eabi-toolchain gcc-arm-none-eabi-6
                           newlib-arm-none-eabi))

(define-public arm-none-eabi-nano-toolchain-6
  (arm-none-eabi-toolchain gcc-arm-none-eabi-6
                           newlib-nano-arm-none-eabi))

(define-public gdb-arm-none-eabi
  (package
    (inherit gdb)
    (name "gdb-arm-none-eabi")
    (arguments
     `(#:configure-flags '("--target=arm-none-eabi"
                           "--enable-multilib"
                           "--enable-interwork"
                           "--enable-languages=c,c++"
                           "--disable-nls")
     ,@(package-arguments gdb)))))

(define-public libjaylink
  ;; No release tarballs available.
  (let ((commit "faa2a433fdd3de211728f3da5921133214af9dd3")
        (revision "1"))
    (package
      (name "libjaylink")
      (version (string-append "0.1.0-" revision "."
                              (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "git://git.zapb.de/libjaylink.git")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "02crr56csz8whq3q4mrmdzzgwp5b0qvxm0fb18drclc3zj44yxl2"))))
      (build-system gnu-build-system)
      (native-inputs
       `(("autoconf" ,autoconf)
         ("automake" ,automake)
         ("libtool" ,libtool)
         ("pkg-config" ,pkg-config)))
      (inputs
       `(("libusb" ,libusb)))
      (arguments
       `(#:phases
         (modify-phases %standard-phases
           (add-before 'configure 'autoreconf
             (lambda _
               (zero? (system* "autoreconf" "-vfi")))))))
      (home-page "http://repo.or.cz/w/libjaylink.git")
      (synopsis "Library to interface Segger J-Link devices")
      (description "libjaylink is a shared library written in C to access
SEGGER J-Link and compatible devices.")
      (license license:gpl2+))))

(define-public jimtcl
  (package
    (name "jimtcl")
    (version "0.77")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/msteveb/jimtcl"
                    "/archive/" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1cmk3qscqckg70chjyimzxa2qcka4qac0j4wq908kiijp45cax08"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; Doesn't use autoconf.
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (zero? (system* "./configure"
                               (string-append "--prefix=" out)))))))))
    (home-page "http://jim.tcl.tk")
    (synopsis "Small footprint Tcl implementation")
    (description "Jim is a small footprint implementation of the Tcl programming
language.")
    (license license:bsd-2)))

(define-public openocd
  ;; FIXME: Use tarball release after nrf52 patch is merged.
  (let ((commit "674141e8a7a6413cb803d90c2a20150260015f81")
        (revision "1"))
    (package
      (name "openocd")
      (version (string-append "0.9.0-" revision "."
                              (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "git://git.code.sf.net/p/openocd/code.git")
                      (commit commit)))
                (sha256
                 (base32
                  "1i86jp0wawq78d73z8hp7q1pn7lmlvhjjr19f7299h4w40a5jf8j"))
                (file-name (string-append name "-" version "-checkout"))
                (patches
                 (search-patches "openocd-nrf52.patch"))))
      (build-system gnu-build-system)
      (native-inputs
       `(("autoconf" ,autoconf)
         ("automake" ,automake)
         ("libtool" ,libtool)
         ("pkg-config" ,pkg-config)))
      (inputs
       `(("hidapi" ,hidapi)
         ("jimtcl" ,jimtcl)
         ("libftdi" ,libftdi)
         ("libjaylink" ,libjaylink)
         ("libusb-compat" ,libusb-compat)))
      (arguments
       '(#:configure-flags
         (append (list "--disable-werror"
                       "--disable-internal-jimtcl"
                       "--disable-internal-libjaylink")
                 (map (lambda (programmer)
                        (string-append "--enable-" programmer))
                      '("amtjtagaccel" "armjtagew" "buspirate" "ftdi"
                        "gw16012" "jlink" "oocd_trace" "opendous" "osbdm"
                        "parport" "aice" "cmsis-dap" "dummy" "jtag_vpi"
                        "remote-bitbang" "rlink" "stlink" "ti-icdi" "ulink"
                        "usbprog" "vsllink" "usb-blaster-2" "usb_blaster"
                        "presto" "openjtag")))
         #:phases
         (modify-phases %standard-phases
           (add-before 'configure 'autoreconf
             (lambda _
               (zero? (system* "autoreconf" "-vfi")))))))
      (home-page "http://openocd.org")
      (synopsis "On-Chip Debugger")
      (description "OpenOCD provides on-chip programming and debugging support
with a layered architecture of JTAG interface and TAP support.")
      (license license:gpl2+))))
