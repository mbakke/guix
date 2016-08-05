;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Leo Famulari <leo@famulari.name>
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

(define-module (gnu packages grub)
  #:use-module (guix download)
  #:use-module (guix packages)
  #:use-module ((guix licenses) #:select (gpl3+))
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages disk)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages qemu)
  #:use-module (gnu packages man)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages cdrom)
  #:use-module (srfi srfi-1))

(define qemu-for-tests
  ;; Newer QEMU versions, such as 1.5.1, no longer support the 'shutdown'
  ;; instruction.  This leads to test hangs, as reported at
  ;; <https://bugs.launchpad.net/bugs/947597> and fixed at
  ;; <http://bzr.savannah.gnu.org/lh/grub/trunk/grub/revision/4828>.
  ;; Work around it by using an older QEMU.
  (package (inherit qemu-minimal)
    (version "1.3.1")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://wiki.qemu-project.org/download/qemu-"
                                 version ".tar.bz2"))
             (sha256
              (base32
               "1bqfrb5dlsxm8gxhkksz8qzi5fhj3xqhxyfwbqcphhcv1kpyfwip"))))

    ;; With recent GLib versions, we get a test failure:
    ;;   ERROR:tests/rtc-test.c:176:check_time: assertion failed (ABS(t - s) <= wiggle): (382597824 <= 2)
    ;; Simply disable the tests.
    (arguments `(#:tests? #f
                 ,@(package-arguments qemu-minimal)))

    ;; The manual fails to build with Texinfo 5.x.
    (native-inputs (alist-delete "texinfo" (package-native-inputs qemu)))))

(define unifont
  ;; GNU Unifont, <http://gnu.org/s/unifont>.
  ;; GRUB needs it for its graphical terminal, gfxterm.
  (origin
    (method url-fetch)
    (uri
     "http://unifoundry.com/pub/unifont-7.0.06/font-builds/unifont-7.0.06.bdf.gz")
    (sha256
     (base32
      "0p2vhnc18cnbmb39vq4m7hzv4mhnm2l0a2s7gx3ar277fwng3hys"))))

(define-public grub
  (package
    (name "grub")
    (version "2.02beta3")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "ftp://alpha.gnu.org/gnu/grub/grub-"
                   "2.02~beta3"
                   ".tar.xz"))
             (file-name (string-append name "-" version ".tar.xz"))
             (sha256
              (base32
               "18ddwnw0vxs7zigvah0g6a5z5vvlz0p8fjglxv1h59sjbrakvv1h"))))
    (build-system gnu-build-system)
    (arguments
     '(;; Two warnings: suggest braces, signed/unsigned comparison.
       #:configure-flags '("--disable-werror")
       #:phases (modify-phases %standard-phases
                  (add-after
                   'unpack 'patch-stuff
                   (lambda* (#:key inputs #:allow-other-keys)
                     (substitute* "grub-core/Makefile.in"
                       (("/bin/sh") (which "sh")))

                     ;; Make the font visible.
                     (copy-file (assoc-ref inputs "unifont") "unifont.bdf.gz")
                     (system* "gunzip" "unifont.bdf.gz")

                     ;; We hit an assertion failure in
                     ;; grub-core/tests/video_checksum.c, as reported at
                     ;; <https://lists.gnu.org/archive/html/grub-devel/2016-07/msg00026.html>.
                     ;; Disable this test for now.
                     (substitute* "tests/grub_func_test.in"
                       (("set -e") "exit 77\nset -e"))
                     #t)))))
    (inputs
     `(;; ("lvm2" ,lvm2)
       ("gettext" ,gnu-gettext)
       ("freetype" ,freetype)
       ;; ("libusb" ,libusb)
       ;; ("fuse" ,fuse)
       ("ncurses" ,ncurses)))
    (native-inputs
     `(("unifont" ,unifont)
       ("bison" ,bison)
       ("flex" ,flex)
       ("texinfo" ,texinfo)
       ("help2man" ,help2man)

       ;; Dependencies for the test suite.  The "real" QEMU is needed here,
       ;; because several targets are used.
       ("parted" ,parted)
       ("qemu" ,qemu-for-tests)
       ("xorriso" ,xorriso)))
    (home-page "http://www.gnu.org/software/grub/")
    (synopsis "GRand Unified Boot loader")
    (description
     "GRUB is a multiboot bootloader.  It is used for initially loading the
kernel of an operating system and then transferring control to it.  The kernel
then goes on to load the rest of the operating system.  As a multiboot
bootloader, GRUB handles the presence of multiple operating systems installed
on the same computer; upon booting the computer, the user is presented with a
menu to select one of the installed operating systems.")
    (license gpl3+)
    (properties '((cpe-name . "grub2")))))
