;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013, 2014, 2015, 2016 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2012 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2014, 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Federico Beffa <beffa@fbengineering.ch>
;;; Copyright © 2015 Taylan Ulrich Bayırlı/Kammer <taylanbayirli@gmail.com>
;;; Copyright © 2015, 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Christopher Allan Webber <cwebber@dustycloud.org>
;;; Copyright © 2016 Tobias Geerinckx-Rice <me@tobias.gr>
;;; Copyright © 2016 Alex Kost <alezost@gmail.com>
;;; Copyright © 2016 Raymond Nicholson <rain1@openmailbox.org>
;;; Copyright © 2016 Mathieu Lirzin <mthl@gnu.org>
;;; Copyright © 2016 Nicolas Goaziou <mail@nicolasgoaziou.fr>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 David Craven <david@craven.ch>
;;; Copyright © 2016 John Darrington <jmd@gnu.org>
;;; Copyright © 2016 Marius Bakke <mbakke@fastmail.com>
;;; Copyright © 2016 Rene Saavedra <rennes@openmailbox.org>
;;; Copyright © 2016 ng0 <ng0@libertad.pw>
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

(define-module (gnu packages linux)
  #:use-module (gnu packages)
  #:use-module (gnu packages acl)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages attr)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages calendar)
  #:use-module (gnu packages check)
  #:use-module (gnu packages crypto)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages docbook)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages elf)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages freedesktop)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnuzilla)
  #:use-module (gnu packages gperf)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages libusb)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pciutils)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages popt)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages rrdtool)
  #:use-module (gnu packages slang)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages video)
  #:use-module (gnu packages xiph)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xorg)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system python)
  #:use-module (guix build-system trivial)
  #:use-module (guix download)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-2)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match))

(define-public (system->linux-architecture arch)
  "Return the Linux architecture name for ARCH, a Guix system name such as
\"x86_64-linux\" or a target triplet such as \"arm-linux-gnueabihf\"."
  (let ((arch (car (string-split arch #\-))))
    (cond ((string=? arch "i686") "i386")
          ((string-prefix? "mips" arch) "mips")
          ((string-prefix? "arm" arch) "arm")
          ((string-prefix? "aarch64" arch) "arm64")
          (else arch))))

(define (linux-libre-urls version)
  "Return a list of URLs for Linux-Libre VERSION."
  (list (string-append
         "http://linux-libre.fsfla.org/pub/linux-libre/releases/"
         version "-gnu/linux-libre-" version "-gnu.tar.xz")

        ;; XXX: Work around <http://bugs.gnu.org/14851>.
        (string-append
         "ftp://alpha.gnu.org/gnu/guix/mirror/linux-libre-"
         version "-gnu.tar.xz")

        ;; Maybe this URL will become valid eventually.
        (string-append
         "mirror://gnu/linux-libre/" version "-gnu/linux-libre-"
         version "-gnu.tar.xz")))

(define-public linux-libre-headers
  (package
    (name "linux-libre-headers")
    (version "4.4.18")
    (source (origin
             (method url-fetch)
             (uri (linux-libre-urls version))
             (sha256
              (base32
               "0k8k17in7dkjd9d8zg3i8l1ax466dba6bxw28flxizzyq8znljps"))))
    (build-system gnu-build-system)
    (native-inputs `(("perl" ,perl)))
    (arguments
     `(#:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (srfi srfi-1))
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'build
           (lambda _
             (let ((arch ,(system->linux-architecture
                          (or (%current-target-system)
                              (%current-system)))))
               (setenv "ARCH" arch)
               (format #t "`ARCH' set to `~a'~%" (getenv "ARCH"))

               (and (zero? (system* "make" "defconfig"))
                    (zero? (system* "make" "mrproper" "headers_check"))))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (and (zero? (system* "make"
                                    (string-append "INSTALL_HDR_PATH=" out)
                                    "headers_install"))
                    (begin
                      (mkdir (string-append out "/include/config"))
                      (call-with-output-file
                          (string-append out
                                         "/include/config/kernel.release")
                        (lambda (p)
                          (format p "~a-default~%" ,version)))

                      ;; Remove the '.install' and '..install.cmd' files; the
                      ;; latter contains store paths, which pulls in bootstrap
                      ;; binaries in the build environment, and prevents bit
                      ;; reproducibility for the bootstrap binaries.
                      (for-each delete-file (find-files out "\\.install"))

                      #t))))))
       #:allowed-references ()
       #:tests? #f))
    (home-page "http://www.gnu.org/software/linux-libre")
    (synopsis "GNU Linux-Libre kernel headers")
    (description "Headers of the Linux-Libre kernel.")
    (license license:gpl2)))

(define %boot-logo-patch
  ;; Linux-Libre boot logo featuring Freedo and a gnu.
  (origin
    (method url-fetch)
    (uri (string-append "http://www.fsfla.org/svn/fsfla/software/linux-libre/"
                        "lemote/gnewsense/branches/3.16/100gnu+freedo.patch"))
    (sha256
     (base32
      "1hk9swxxc80bmn2zd2qr5ccrjrk28xkypwhl4z0qx4hbivj7qm06"))))

(define* (kernel-config arch #:key variant)
  "Return the absolute file name of the Linux-Libre build configuration file
for ARCH and optionally VARIANT, or #f if there is no such configuration."
  (let* ((name (string-append "linux-libre-"
                              (if variant (string-append variant "-") "")
                              (if (string=? "i386" arch) "i686" arch) ".conf"))
         (file (string-append "gnu/packages/" name)))
    (search-path %load-path file)))

(define %default-extra-linux-options
  `(;; https://lists.gnu.org/archive/html/guix-devel/2014-04/msg00039.html
    ("CONFIG_DEVPTS_MULTIPLE_INSTANCES" . #t)
    ;; Modules required for initrd:
    ("CONFIG_NET_9P" . m)
    ("CONFIG_NET_9P_VIRTIO" . m)
    ("CONFIG_VIRTIO_BLK" . m)
    ("CONFIG_VIRTIO_NET" . m)
    ("CONFIG_VIRTIO_PCI" . m)
    ("CONFIG_VIRTIO_BALLOON" . m)
    ("CONFIG_VIRTIO_MMIO" . m)
    ("CONFIG_FUSE_FS" . m)
    ("CONFIG_CIFS" . m)
    ("CONFIG_9P_FS" . m)))

(define (config->string options)
  (string-join (map (match-lambda
                      ((option . 'm)
                       (string-append option "=m"))
                      ((option . #t)
                       (string-append option "=y"))
                      ((option . #f)
                       (string-append option "=n")))
                    options)
               "\n"))

(define* (make-linux-libre version hash supported-systems
                           #:key
                           ;; A function that takes an arch and a variant.
                           ;; See kernel-config for an example.
                           (extra-version #f)
                           (configuration-file #f)
                           (defconfig "defconfig")
                           (extra-options %default-extra-linux-options)
                           (patches (list %boot-logo-patch)))
  (package
    (name (if extra-version
              (string-append "linux-libre-" extra-version)
              "linux-libre"))
    (version version)
    (source (origin
              (method url-fetch)
              (uri (linux-libre-urls version))
              (sha256 (base32 hash))
              (patches patches)))
    (supported-systems supported-systems)
    (build-system gnu-build-system)
    (native-inputs
     `(("perl" ,perl)
       ("bc" ,bc)
       ("openssl" ,openssl)
       ("kmod" ,kmod)
       ,@(match (and configuration-file
                     (configuration-file
                      (system->linux-architecture
                       (or (%current-target-system) (%current-system)))
                      #:variant (version-major+minor version)))
           (#f                                    ;no config for this platform
            '())
           ((? string? config)
            `(("kconfig" ,config))))))
    (arguments
     `(#:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (srfi srfi-1)
                  (ice-9 match))
       #:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key inputs native-inputs target #:allow-other-keys)
             ;; Avoid introducing timestamps
             (setenv "KCONFIG_NOTIMESTAMP" "1")
             (setenv "KBUILD_BUILD_TIMESTAMP" (getenv "SOURCE_DATE_EPOCH"))

             ;; Set ARCH and CROSS_COMPILE
             (let ((arch ,(system->linux-architecture
                           (or (%current-target-system)
                               (%current-system)))))
               (setenv "ARCH" arch)
               (format #t "`ARCH' set to `~a'~%" (getenv "ARCH"))

               (when target
                 (setenv "CROSS_COMPILE" (string-append target "-"))
                 (format #t "`CROSS_COMPILE' set to `~a'~%"
                         (getenv "CROSS_COMPILE"))))

             (setenv "EXTRA_VERSION" ,extra-version)

             (let ((build  (assoc-ref %standard-phases 'build))
                   (config (assoc-ref inputs "kconfig")))

               ;; Use a custom kernel configuration file or a default
               ;; configuration file.
               (if config
                   (begin
                     (copy-file config ".config")
                     (chmod ".config" #o666))
                   (system* "make" ,defconfig))

               ;; Appending works even when the option wasn't in the
               ;; file.  The last one prevails if duplicated.
               (let ((port (open-file ".config" "a"))
                     (extra-configuration ,(config->string extra-options)))
                 (display extra-configuration port)
                 (close-port port))

               (zero? (system* "make" "oldconfig")))))
         (replace 'install
           (lambda* (#:key inputs native-inputs outputs #:allow-other-keys)
             (let* ((out    (assoc-ref outputs "out"))
                    (moddir (string-append out "/lib/modules"))
                    (dtbdir (string-append out "/lib/dtbs"))
                    (kmod   (assoc-ref (or native-inputs inputs) "kmod")))
               ;; Install kernel image, kernel configuration and link map.
               (for-each (lambda (file) (install-file file out))
                         (find-files "." "^(\\.config|bzImage|zImage|vmlinuz|System\\.map)$"))
               ;; Install device tree files
               (for-each (lambda (file) (install-file file dtbdir))
                         (find-files "." "\\.dtb$"))
               ;; Install kernel modules
               (mkdir-p moddir)
               (zero? (system* "make"
                               (string-append "DEPMOD=" kmod "/bin/depmod")
                               (string-append "MODULE_DIR=" moddir)
                               (string-append "INSTALL_PATH=" out)
                               (string-append "INSTALL_MOD_PATH=" out)
                               "INSTALL_MOD_STRIP=1"
                               "modules_install"))))))
       #:tests? #f))
    (home-page "http://www.gnu.org/software/linux-libre/")
    (synopsis "100% free redistribution of a cleaned Linux kernel")
    (description
     "GNU Linux-Libre is a free (as in freedom) variant of the Linux kernel.
It has been modified to remove all non-free binary blobs.")
    (license license:gpl2)))

(define %intel-compatible-systems '("x86_64-linux" "i686-linux"))

(define-public linux-libre
  (make-linux-libre "4.8.15"
                    "0msgi44mh1ighfawysrzrljikwrapkvk418d6h0v45vj2i5rwln9"
                    %intel-compatible-systems
                    #:configuration-file kernel-config))

(define-public linux-libre-4.4
  (make-linux-libre "4.4.39"
                    "0aqi44xshib7lx9zjc0kj2v172ywa0iy2kb6z0whbiw3f841hv43"
                    %intel-compatible-systems
                    #:configuration-file kernel-config))

(define-public linux-libre-4.1
  (make-linux-libre "4.1.36"
                    "0wy7xpqjwn1aprbzrbqgjskcg8qj2mczkv3rcisxf8gcdifz61qh"
                    %intel-compatible-systems
                    #:configuration-file kernel-config))

;; Avoid rebuilding kernel variants when there is a minor version bump.
(define %linux-libre-version "4.8.15")
(define %linux-libre-hash "0msgi44mh1ighfawysrzrljikwrapkvk418d6h0v45vj2i5rwln9")

(define-public linux-libre-arm-generic
  (make-linux-libre %linux-libre-version
                    %linux-libre-hash
                    '("armhf-linux")
                    #:defconfig "multi_v7_defconfig"
                    #:extra-version "arm-generic"))


;;;
;;; Pluggable authentication modules (PAM).
;;;

(define-public linux-pam
  (package
    (name "linux-pam")
    (version "1.3.0")
    (source
     (origin
      (method url-fetch)
      (uri (string-append
            "http://www.linux-pam.org/library/"
            "Linux-PAM-" version ".tar.bz2"))
      (sha256
       (base32
        "1fyi04d5nsh8ivd0rn2y0z83ylgc0licz7kifbb6xxi2ylgfs6i4"))
      (patches (search-patches "linux-pam-no-setfsuid.patch"))))

    (build-system gnu-build-system)
    (native-inputs
     `(("flex" ,flex)

       ;; TODO: optional dependencies
       ;; ("libxcrypt" ,libxcrypt)
       ;; ("cracklib" ,cracklib)
       ))
    (arguments
     '(;; Most users, such as `shadow', expect the headers to be under
       ;; `security'.
       #:configure-flags (list (string-append "--includedir="
                                              (assoc-ref %outputs "out")
                                              "/include/security"))

       ;; XXX: Tests won't run in chroot, presumably because /etc/pam.d
       ;; isn't available.
       #:tests? #f))
    (home-page "http://www.linux-pam.org/")
    (synopsis "Pluggable authentication modules for Linux")
    (description
     "A *Free* project to implement OSF's RFC 86.0.
Pluggable authentication modules are small shared object files that can
be used through the PAM API to perform tasks, like authenticating a user
at login.  Local and dynamic reconfiguration are its key features.")
    (license license:bsd-3)))

(define-public linux-pam-1.2
  (package
    (inherit linux-pam)
    (version "1.2.1")
    (source
     (origin
      (method url-fetch)
      (uri (string-append
            "http://www.linux-pam.org/library/"
            "Linux-PAM-" version ".tar.bz2"))
      (sha256
       (base32
        "1n9lnf9gjs72kbj1g354v1xhi2j27aqaah15vykh7cnkq08i4arl"))
      (patches (search-patches "linux-pam-no-setfsuid.patch"))))))


;;;
;;; Miscellaneous.
;;;

(define-public psmisc
  (package
    (name "psmisc")
    (version "22.20")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://sourceforge/psmisc/psmisc/psmisc-"
                          version ".tar.gz"))
      (sha256
       (base32
        "052mfraykmxnavpi8s78aljx8w87hyvpx8mvzsgpjsjz73i28wmi"))))
    (build-system gnu-build-system)
    (inputs `(("ncurses" ,ncurses)))
    (home-page "http://psmisc.sourceforge.net/")
    (synopsis
     "Small utilities that use the proc file system")
    (description
     "This PSmisc package is a set of some small useful utilities that
use the proc file system.  We're not about changing the world, but
providing the system administrator with some help in common tasks.")
    (license license:gpl2+)))

(define-public util-linux
  (package
    (name "util-linux")
    (version "2.28.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://kernel.org/linux/utils/"
                                  name "/v" (version-major+minor version) "/"
                                  name "-" version ".tar.xz"))
              (sha256
               (base32
                "03xnaw3c7pavxvvh1vnimcr44hlhhf25whawiyv8dxsflfj4xkiy"))
              (patches (search-patches "util-linux-tests.patch"))
              (modules '((guix build utils)))
              (snippet
               ;; We take the 'logger' program from GNU Inetutils and 'kill'
               ;; from GNU Coreutils.
               '(begin
                  (substitute* "configure"
                    (("build_logger=yes") "build_logger=no")
                    (("build_kill=yes") "build_kill=no"))
                  #t))))
    (build-system gnu-build-system)
    (outputs '("out"
               "static"))      ; >2 MiB of static .a libraries
    (arguments
     `(#:configure-flags (list "--disable-use-tty-group"

                               ;; Install completions where our
                               ;; bash-completion package expects them.
                               (string-append "--with-bashcompletiondir="
                                              (assoc-ref %outputs "out")
                                              "/etc/bash_completion.d"))
       #:phases (modify-phases %standard-phases
                  (add-before
                   'build 'set-umount-file-name
                   (lambda* (#:key outputs #:allow-other-keys)
                     ;; Tell 'eject' the right file name of 'umount'.
                     (let ((out (assoc-ref outputs "out")))
                       (substitute* "sys-utils/eject.c"
                         (("\"/bin/umount\"")
                          (string-append "\"" out "/bin/umount\"")))
                       #t)))
                  (add-before
                   'check 'pre-check
                   (lambda* (#:key inputs outputs #:allow-other-keys)
                     (let ((out (assoc-ref outputs "out"))
                           (net (assoc-ref inputs "net-base")))
                       ;; Change the test to refer to the right file.
                       (substitute* "tests/ts/misc/mcookie"
                         (("/etc/services")
                          (string-append net "/etc/services")))
                       #t)))
                  (add-after
                   'install 'move-static-libraries
                   (lambda* (#:key outputs #:allow-other-keys)
                     (let ((out    (assoc-ref outputs "out"))
                           (static (assoc-ref outputs "static")))
                       (mkdir-p (string-append static "/lib"))
                       (with-directory-excursion out
                         (for-each (lambda (file)
                                     (rename-file file
                                                  (string-append static "/"
                                                                 file)))
                                   (find-files "lib" "\\.a$")))
                       #t))))))
    (inputs `(("zlib" ,zlib)
              ("ncurses" ,ncurses)))
    (native-inputs
     `(("perl" ,perl)
       ("net-base" ,net-base)))                   ;for tests
    (home-page "https://www.kernel.org/pub/linux/utils/util-linux/")
    (synopsis "Collection of utilities for the Linux kernel")
    (description "Util-linux is a diverse collection of Linux kernel
utilities.  It provides dmesg and includes tools for working with file systems,
block devices, UUIDs, TTYs, and many other tools.")

    ;; Note that util-linux doesn't use the same license for all the
    ;; code.  GPLv2+ is the default license for a code without an
    ;; explicitly defined license.
    (license (list license:gpl3+ license:gpl2+ license:gpl2 license:lgpl2.0+
                   license:bsd-4 license:public-domain))))

(define-public procps
  (package
    (name "procps")
    (version "3.3.12")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/procps-ng/Production/"
                                  "procps-ng-" version ".tar.xz"))
              (sha256
               (base32
                "1m57w6jmry84njd5sgk5afycbglql0al80grx027kwqqcfw5mmkf"))))
    (build-system gnu-build-system)
    (arguments
     '(#:modules ((guix build utils)
                  (guix build gnu-build-system)
                  (srfi srfi-1)
                  (srfi srfi-26))
       #:phases
       (modify-phases %standard-phases
         (add-before 'check 'disable-strtod-test
           (lambda _
             ;; Disable the 'strtod' test, which fails on 32-bit systems.
             ;; This is what upstream does:
             ;; <https://gitlab.com/procps-ng/procps/commit/100afbc1491be388f1429021ff65d969f4b1e08f>.
             (substitute* "Makefile"
               (("^(TESTS|check_PROGRAMS) = .*$" all)
                (string-append "# " all "\n")))
             #t))
         (add-after
          'install 'post-install
          ;; Remove commands and man pages redudant with
          ;; Coreutils.
          (lambda* (#:key outputs #:allow-other-keys)
            (let* ((out (assoc-ref outputs "out"))
                   (dup (append-map (cut find-files out <>)
                                    '("^kill" "^uptime"))))
              (for-each delete-file dup)
              #t))))))
    (inputs `(("ncurses" ,ncurses)))
    (home-page "https://gitlab.com/procps-ng/procps/")
    (synopsis "Utilities that give information about processes")
    (description
     "Procps is the package that has a bunch of small useful utilities
that give information about processes using the Linux /proc file system.
The package includes the programs ps, top, vmstat, w, kill, free,
slabtop, and skill.")
    (license license:gpl2)))

(define-public usbutils
  (package
    (name "usbutils")
    (version "008")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://kernel.org/linux/utils/usb/usbutils/"
                          "usbutils-" version ".tar.xz"))
      (sha256
       (base32
        "132clk14j4nm8crln2jymdbbc2vhzar2j2hnxyh05m79pbq1lx24"))))
    (build-system gnu-build-system)
    (inputs
     `(("libusb" ,libusb)
       ("eudev" ,eudev)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://www.linux-usb.org/")
    (synopsis
     "Tools for working with USB devices, such as lsusb")
    (description
     "Tools for working with USB devices, such as lsusb.")
    (license license:gpl2+)))

(define-public e2fsprogs
  (package
    (name "e2fsprogs")
    (version "1.42.13")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://kernel.org/linux/kernel/people/tytso/"
                   name "/v" version "/"
                   name "-" version ".tar.xz"))
             (sha256
              (base32
               "1ix0b83zgw5n0p2grh2961c6796m92yr2jqc2sbr23x3lfsp8r71"))
             (modules '((guix build utils)))
             (snippet
              '(substitute* "MCONFIG.in"
                 (("INSTALL_SYMLINK = /bin/sh")
                  "INSTALL_SYMLINK = sh")))))
    (build-system gnu-build-system)
    (inputs `(("util-linux" ,util-linux)))
    (native-inputs `(("pkg-config" ,pkg-config)
                     ("texinfo" ,texinfo)))     ;for the libext2fs Info manual
    (arguments
     '(;; Parallel building reliably yields a failure like this:
       ;; "make[2]: *** No rule to make target '../lib/libss.so', needed by
       ;; 'debugfs'.  Stop."
       #:parallel-build? #f
       ;; util-linux is the preferred source for some of the libraries and
       ;; commands, so disable them (see, e.g.,
       ;; <http://git.buildroot.net/buildroot/commit/?id=e1ffc2f791b33633>.)
       #:configure-flags '("--disable-libblkid"
                           "--disable-libuuid" "--disable-uuidd"
                           "--disable-fsck"

                           ;; Install libext2fs et al.
                           "--enable-elf-shlibs")

       #:make-flags (list (string-append "LDFLAGS=-Wl,-rpath="
                                         (assoc-ref %outputs "out")
                                         "/lib"))

       #:phases (alist-cons-before
                 'configure 'patch-shells
                 (lambda _
                   (substitute* "configure"
                     (("/bin/sh (.*)parse-types.sh" _ dir)
                      (string-append (which "sh") " " dir
                                     "parse-types.sh")))
                   (substitute* (find-files "." "^Makefile.in$")
                     (("#!/bin/sh")
                      (string-append "#!" (which "sh")))))
                 (alist-cons-after
                  'install 'install-libs
                  (lambda* (#:key outputs #:allow-other-keys)
                    (let* ((out (assoc-ref outputs "out"))
                           (lib (string-append out "/lib")))
                      (and (zero? (system* "make" "install-libs"))

                           ;; Make the .a writable so that 'strip' works.
                           ;; Failing to do that, due to debug symbols, we
                           ;; retain a reference to the final
                           ;; linux-libre-headers, which refer to the
                           ;; bootstrap binaries.
                           (let ((archives (find-files lib "\\.a$")))
                             (for-each (lambda (file)
                                         (chmod file #o666))
                                       archives)
                             #t))))
                  %standard-phases))

       ;; FIXME: Tests work by comparing the stdout/stderr of programs, that
       ;; they fail because we get an extra line that says "Can't check if
       ;; file system is mounted due to missing mtab file".
       #:tests? #f))
    (home-page "http://e2fsprogs.sourceforge.net/")
    (synopsis "Creating and checking ext2/ext3/ext4 file systems")
    (description
     "This package provides tools for manipulating ext2/ext3/ext4 file systems.")
    (license (list license:gpl2                   ;programs
                   license:lgpl2.0                ;libext2fs
                   license:x11))))                ;libuuid

(define e2fsprogs/static
  (static-package
   (package (inherit e2fsprogs)
            (arguments
             ;; Do not build shared libraries.
             (substitute-keyword-arguments (package-arguments e2fsprogs)
               ((#:configure-flags _)
                '(list "--disable-blkid"))
               ((#:make-flags _)
                '(list)))))))

(define-public e2fsck/static
  (package
    (name "e2fsck-static")
    (version (package-version e2fsprogs))
    (build-system trivial-build-system)
    (source #f)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils)
                      (ice-9 ftw)
                      (srfi srfi-26))

         (let ((source (string-append (assoc-ref %build-inputs "e2fsprogs")
                                      "/sbin"))
               (bin    (string-append (assoc-ref %outputs "out") "/sbin")))
           (mkdir-p bin)
           (with-directory-excursion bin
             (for-each (lambda (file)
                         (copy-file (string-append source "/" file)
                                    file)
                         (remove-store-references file)
                         (chmod file #o555))
                       (scandir source (cut string-prefix? "fsck." <>))))))))
    (inputs `(("e2fsprogs" ,e2fsprogs/static)))
    (synopsis "Statically-linked fsck.* commands from e2fsprogs")
    (description
     "This package provides statically-linked command of fsck.ext[234] taken
from the e2fsprogs package.  It is meant to be used in initrds.")
    (home-page (package-home-page e2fsprogs))
    (license (package-license e2fsprogs))))

(define-public extundelete
  (package
    (name "extundelete")
    (version "0.2.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/extundelete/"
                                  "extundelete/" version "/extundelete-"
                                  version ".tar.bz2"))
              (sha256
               (base32
                "1x0r7ylxlp9lbj3d7sqf6j2a222dwy2nfpff05jd6mkh4ihxvyd1"))))
    (build-system gnu-build-system)
    (inputs `(("e2fsprogs" ,e2fsprogs)))
    (home-page "http://extundelete.sourceforge.net/")
    (synopsis "Recover deleted files from ext2/3/4 partitions")
    (description
     "Extundelete is a set of tools that can recover deleted files from an
ext3 or ext4 partition.")
    (license license:gpl2)))

(define-public zerofree
  (package
    (name "zerofree")
    (version "1.0.3")
    (home-page "http://intgat.tigress.co.uk/rmy/uml/")
    (source (origin
              (method url-fetch)
              (uri (string-append home-page name "-" version
                                  ".tgz"))
              (sha256
               (base32
                "1xncw3dn2cp922ly42m96p6fh7jv8ysg6bwqbk5xvw701f3dmkrs"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (alist-replace
                 'install
                 (lambda* (#:key outputs #:allow-other-keys)
                   (let* ((out (assoc-ref outputs "out"))
                          (bin (string-append out "/bin")))
                     (mkdir-p bin)
                     (copy-file "zerofree"
                                (string-append bin "/zerofree"))
                     (chmod (string-append bin "/zerofree")
                            #o555)
                     #t))
                 (alist-delete 'configure %standard-phases))
       #:tests? #f))                              ;no tests
    (inputs `(("libext2fs" ,e2fsprogs)))
    (synopsis "Zero non-allocated regions in ext2/ext3/ext4 file systems")
    (description
     "The zerofree command scans the free blocks in an ext2 file system and
fills any non-zero blocks with zeroes.  This is a useful way to make disk
images more compressible.")
    (license license:gpl2)))

(define-public strace
  (package
    (name "strace")
    (version "4.7")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://sourceforge/strace/strace/" version
                                 "/strace-" version ".tar.xz"))
             (sha256
              (base32
               "158iwk0pl2mfw93m1843xb7a2zb8p6lh0qim07rca6f1ff4dk764"))))
    (build-system gnu-build-system)
    (native-inputs `(("perl" ,perl)))
    (home-page "http://strace.sourceforge.net/")
    (synopsis "System call tracer for Linux")
    (description
     "strace is a system call tracer, i.e. a debugging tool which prints out a
trace of all the system calls made by a another process/program.")
    (license license:bsd-3)))

(define-public ltrace
  (package
    (name "ltrace")
    (version "0.7.3")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://www.ltrace.org/ltrace_" version
                                 ".orig.tar.bz2"))
             (sha256
              (base32
               "00wmbdghqbz6x95m1mcdd3wd46l6hgcr4wggdp049dbifh3qqvqf"))))
    (build-system gnu-build-system)
    (inputs `(("libelf" ,libelf)))
    (arguments
     ;; Compilation uses -Werror by default, but it fails.
     '(#:configure-flags '("--disable-werror")))
    (home-page "http://www.ltrace.org/")
    (synopsis "Library call tracer for Linux")
    (description
     "ltrace intercepts and records dynamic library calls which are called by
an executed process and the signals received by that process.  It can also
intercept and print the system calls executed by the program.")
    (license license:gpl2+)))

(define-public alsa-lib
  (package
    (name "alsa-lib")
    (version "1.0.27.1")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "ftp://ftp.alsa-project.org/pub/lib/alsa-lib-"
                   version ".tar.bz2"))
             (sha256
              (base32
               "0fx057746dj7rjdi0jnvx2m9b0y1lgdkh1hks87d8w32xyihf3k9"))
             (patches (search-patches "alsa-lib-mips-atomic-fix.patch"))))
    (build-system gnu-build-system)
    (home-page "http://www.alsa-project.org/")
    (synopsis "The Advanced Linux Sound Architecture libraries")
    (description
     "The Advanced Linux Sound Architecture (ALSA) provides audio and
MIDI functionality to the Linux-based operating system.")
    (license license:lgpl2.1+)))

(define-public alsa-utils
  (package
    (name "alsa-utils")
    (version "1.1.3")
    (source (origin
             (method url-fetch)
             (uri (string-append "ftp://ftp.alsa-project.org/pub/utils/"
                                 name "-" version ".tar.bz2"))
             (sha256
              (base32
               "0z0nnqp1707bm02dys2d16m88lsg5nd26bqaf14rl3za9sjifwhj"))))
    (build-system gnu-build-system)
    (arguments
     ;; XXX: Disable man page creation until we have DocBook.
     '(#:configure-flags (list "--disable-xmlto"

                               ;; The udev rule is responsible for restoring
                               ;; the volume.
                               (string-append "--with-udev-rules-dir="
                                              (assoc-ref %outputs "out")
                                              "/lib/udev/rules.d"))
       #:phases
       (modify-phases %standard-phases
         (add-before
           'install 'pre-install
           (lambda _
             ;; Don't try to mkdir /var/lib/alsa.
             (substitute* "Makefile"
               (("\\$\\(MKDIR_P\\) .*ASOUND_STATE_DIR.*")
                "true\n"))
             #t)))))
    (inputs
     `(("libsamplerate" ,libsamplerate)
       ("ncurses" ,ncurses)
       ("alsa-lib" ,alsa-lib)
       ("xmlto" ,xmlto)
       ("gettext" ,gettext-minimal)))
    (home-page "http://www.alsa-project.org/")
    (synopsis "Utilities for the Advanced Linux Sound Architecture (ALSA)")
    (description
     "The Advanced Linux Sound Architecture (ALSA) provides audio and
MIDI functionality to the Linux-based operating system.")

    ;; This is mostly GPLv2+ but a few files such as 'alsactl.c' are
    ;; GPLv2-only.
    (license license:gpl2)))

(define-public alsa-plugins
  (package
    (name "alsa-plugins")
    (version "1.1.1")
    (source (origin
             (method url-fetch)
             (uri (string-append "ftp://ftp.alsa-project.org/pub/plugins/"
                                 name "-" version ".tar.bz2"))
             (sha256
              (base32
               "1w81z5jlwqhd1l2m7qrq69lc4k9dnrg1wn52jsl2hrf3hbhd394f"))))
    (build-system gnu-build-system)
    ;; TODO: Split libavcodec and speex if possible. It looks like they can not
    ;; be split, there are references to both in files.
    ;; TODO: Remove OSS related plugins, they add support to run native
    ;; ALSA applications on OSS however we do not offer OSS and OSS is
    ;; obsolete.
    (outputs '("out" "pulseaudio"))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'install 'split
           (lambda* (#:key inputs outputs #:allow-other-keys)
             ;; Distribute the binaries to the various outputs.
             (let* ((out (assoc-ref outputs "out"))
                    (pua (assoc-ref outputs "pulseaudio"))
                    (pualib (string-append pua "/lib/alsa-lib"))
                    (puaconf (string-append pua "/share/alsa/alsa.conf.d")))
               (mkdir-p puaconf)
               (mkdir-p pualib)
               (chdir (string-append out "/share"))
               (for-each (lambda (file)
                           (rename-file file (string-append puaconf "/" (basename file))))
                         (find-files out "\\.(conf|example)"))
               (for-each (lambda (file)
                           (rename-file file (string-append pualib "/" (basename file))))
                         (find-files out ".*pulse\\.(la|so)"))
               (chdir "..")
               ;; We have moved the files to output pulsaudio, the
               ;; directory is now empty.
               (delete-file-recursively (string-append out "/share"))
               #t))))))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("speex" ,speex) ; libspeexdsp resampling plugin
       ("libsamplerate" ,libsamplerate) ; libsamplerate resampling plugin
       ("ffmpeg" ,ffmpeg) ; libavcodec resampling plugin, a52 plugin
       ("pulseaudio" ,pulseaudio))) ; PulseAudio plugin
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://www.alsa-project.org/")
    (synopsis "Plugins for the Advanced Linux Sound Architecture (ALSA)")
    (description
     "The Advanced Linux Sound Architecture (ALSA) provides audio and
MIDI functionality to the Linux-based operating system.  This package enhances ALSA
by providing additional plugins which include: upmixing, downmixing, jackd and
pulseaudio support for native alsa applications, format conversion (s16 to a52), and
external rate conversion.")
    (license (list license:gpl2+
                   ;; `rate/rate_samplerate.c': LGPL v2.1 or later.
                   license:lgpl2.1+))))

(define-public iptables
  (package
    (name "iptables")
    (version "1.4.21")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "http://www.netfilter.org/projects/iptables/files/iptables-"
                   version ".tar.bz2"))
             (sha256
              (base32
               "1q6kg7sf0pgpq0qhab6sywl23cngxxfzc9zdzscsba8x09l4q02j"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f       ; no test suite
       #:configure-flags ; add $libdir to the RUNPATH of executables
       (list (string-append "LDFLAGS=-Wl,-rpath=" %output "/lib"))))
    (home-page "http://www.netfilter.org/projects/iptables/index.html")
    (synopsis "Program to configure the Linux IP packet filtering rules")
    (description
     "iptables is the userspace command line program used to configure the
Linux 2.4.x and later IPv4 packet filtering ruleset (firewall).  It is targeted at
system administrators.  Since Network Address Translation is also configured
from the packet filter ruleset, iptables is used for this, too.  The iptables
package also includes ip6tables.  ip6tables is used for configuring the IPv6
packet filter.")
    (license license:gpl2+)))

(define-public iproute
  (package
    (name "iproute2")
    (version "4.9.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://kernel.org/linux/utils/net/iproute2/iproute2-"
                    version ".tar.xz"))
              (sha256
               (base32
                "1i0n071hiqxw1gisngw2jln3kcp9sh47n6fj5hdwqrvp7w20zwy0"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f                                ; no test suite
       #:make-flags (let ((out (assoc-ref %outputs "out")))
                      (list "DESTDIR="
                            (string-append "BASH_COMPDIR=" out
                                           "/etc/bash_completion.d")
                            (string-append "LIBDIR=" out "/lib")
                            (string-append "SBINDIR=" out "/sbin")
                            (string-append "CONFDIR=" out "/etc")
                            (string-append "DOCDIR=" out "/share/doc/"
                                           ,name "-" ,version)
                            (string-append "MANDIR=" out "/share/man")))
       #:phases (modify-phases %standard-phases
                  (add-before 'install 'pre-install
                    (lambda _
                      ;; Don't attempt to create /var/lib/arpd.
                      (substitute* "Makefile"
                        (("^.*ARPDDIR.*$") "")))))))
    (inputs
     `(("iptables" ,iptables)
       ("db4" ,bdb)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("flex" ,flex)
       ("bison" ,bison)))
    (home-page
     "https://wiki.linuxfoundation.org/networking/iproute2")
    (synopsis
     "Utilities for controlling TCP/IP networking and traffic in Linux")
    (description
     "Iproute2 is a collection of utilities for controlling TCP/IP
networking and traffic with the Linux kernel.

Most network configuration manuals still refer to ifconfig and route as the
primary network configuration tools, but ifconfig is known to behave
inadequately in modern network environments.  They should be deprecated, but
most distros still include them.  Most network configuration systems make use
of ifconfig and thus provide a limited feature set.  The /etc/net project aims
to support most modern network technologies, as it doesn't use ifconfig and
allows a system administrator to make use of all iproute2 features, including
traffic control.

iproute2 is usually shipped in a package called iproute or iproute2 and
consists of several tools, of which the most important are ip and tc.  ip
controls IPv4 and IPv6 configuration and tc stands for traffic control.  Both
tools print detailed usage messages and are accompanied by a set of
manpages.")
    (license license:gpl2+)))

(define-public net-tools
  ;; XXX: This package is basically unmaintained, but it provides a few
  ;; commands not yet provided by Inetutils, such as 'route', so we have to
  ;; live with it.
  (package
    (name "net-tools")
    (version "1.60")
    (home-page "http://net-tools.sourceforge.net/")
    (source (origin
             (method url-fetch)
             (uri (list (string-append
                         "mirror://sourceforge/net-tools/net-tools-"
                         version ".tar.bz2")
                        (string-append
                         "http://distro.ibiblio.org/rootlinux/rootlinux-ports"
                         "/base/net-tools/net-tools-1.60.tar.bz2")))
             (sha256
              (base32
               "0yvxrzk0mzmspr7sa34hm1anw6sif39gyn85w4c5ywfn8inxvr3s"))
             (patches (search-patches "net-tools-bitrot.patch"))))
    (build-system gnu-build-system)
    (arguments
     '(#:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (srfi srfi-1)
                  (srfi srfi-26))
       #:phases (alist-cons-after
                 'unpack 'patch
                 (lambda* (#:key inputs #:allow-other-keys)
                   (define (apply-patch file)
                     (zero? (system* "patch" "-p1" "--force"
                                     "--input" file)))

                   (let ((patch.gz (assoc-ref inputs "patch")))
                     (format #t "applying Debian patch set '~a'...~%"
                             patch.gz)
                     (system (string-append "gunzip < " patch.gz " > the-patch"))
                     (and (apply-patch "the-patch")
                          (for-each apply-patch
                                    (find-files "debian/patches"
                                                "\\.patch")))))
                 (alist-replace
                  'configure
                  (lambda* (#:key outputs #:allow-other-keys)
                    (let ((out (assoc-ref outputs "out")))
                      (mkdir-p (string-append out "/bin"))
                      (mkdir-p (string-append out "/sbin"))

                      ;; Pretend we have everything...
                      (system "yes | make config")

                      ;; ... except for the things we don't have.
                      ;; HAVE_AFDECnet requires libdnet, which we don't have.
                      ;; HAVE_HWSTRIP and HAVE_HWTR require kernel headers
                      ;; that have been removed.
                      (substitute* '("config.make" "config.h")
                        (("^.*HAVE_(AFDECnet|HWSTRIP|HWTR)[ =]1.*$") ""))))
                  (alist-cons-after
                   'install 'remove-redundant-commands
                   (lambda* (#:key outputs #:allow-other-keys)
                     ;; Remove commands and man pages redundant with
                     ;; Inetutils.
                     (let* ((out (assoc-ref outputs "out"))
                            (dup (append-map (cut find-files out <>)
                                             '("^hostname"
                                               "^(yp|nis|dns)?domainname"))))
                       (for-each delete-file dup)
                       #t))
                   %standard-phases)))

       ;; Binaries that depend on libnet-tools.a don't declare that
       ;; dependency, making it parallel-unsafe.
       #:parallel-build? #f

       #:tests? #f                                ; no test suite
       #:make-flags (let ((out (assoc-ref %outputs "out")))
                      (list "CC=gcc"
                            (string-append "BASEDIR=" out)
                            (string-append "INSTALLNLSDIR=" out "/share/locale")
                            (string-append "mandir=/share/man")))))

    ;; Use the big Debian patch set (the thing does not even compile out of
    ;; the box.)
    (inputs `(("patch" ,(origin
                         (method url-fetch)
                         (uri
                          "http://ftp.de.debian.org/debian/pool/main/n/net-tools/net-tools_1.60-24.2.diff.gz")
                         (sha256
                          (base32
                           "0p93lsqx23v5fv4hpbrydmfvw1ha2rgqpn2zqbs2jhxkzhjc030p"))))))
    (native-inputs `(("gettext" ,gettext-minimal)))

    (synopsis "Tools for controlling the network subsystem in Linux")
    (description
     "This package includes the important tools for controlling the network
subsystem of the Linux kernel.  This includes arp, hostname, ifconfig,
netstat, rarp and route.  Additionally, this package contains utilities
relating to particular network hardware types (plipconfig, slattach) and
advanced aspects of IP configuration (iptunnel, ipmaddr).")
    (license license:gpl2+)))

(define-public libcap
  (package
    (name "libcap")
    (version "2.24")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://kernel.org/linux/libs/security/linux-privs/"
                   "libcap2/libcap-" version ".tar.xz"))
             (sha256
              (base32
               "0rbc9qbqs5bp9am9s9g83wxj5k4ixps2agy9dxr1v1fwg27mdr6f"))))
    (build-system gnu-build-system)
    (arguments '(#:phases
                 (modify-phases %standard-phases
                   (replace 'configure
                            ;; Add $libdir to the RUNPATH of executables.
                            (lambda _
                              (substitute* "Make.Rules"
                                (("LDFLAGS := #-g")
                                 (string-append "LDFLAGS := -Wl,-rpath="
                                                %output "/lib"))))))
                 #:tests? #f                      ; no 'check' target
                 #:make-flags (list "lib=lib"
                                    (string-append "prefix="
                                                   (assoc-ref %outputs "out"))
                                    "RAISE_SETFCAP=no")))
    (native-inputs `(("perl" ,perl)))
    (inputs `(("attr" ,attr)))
    (home-page "https://sites.google.com/site/fullycapable/")
    (synopsis "Library for working with POSIX capabilities")
    (description
     "Libcap2 provides a programming interface to POSIX capabilities on
Linux-based operating systems.")

    ;; License is BSD-3 or GPLv2, at the user's choice.
    (license license:gpl2)))

(define-public bridge-utils
  (package
    (name "bridge-utils")
    (version "1.5")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://sourceforge/bridge/bridge/"
                                 "bridge-utils-" version ".tar.gz"))
             (sha256
              (base32
               "12367cwqmi0yqphi6j8rkx97q8hw52yq2fx4k0xfclkcizxybya2"))))
    (build-system gnu-build-system)

    ;; The tarball lacks all the generated files.
    (native-inputs `(("autoconf" ,autoconf)
                     ("automake" ,automake)))
    (arguments
     '(#:phases (alist-cons-after
                 'unpack 'bootstrap
                 (lambda _
                   ;; Fix "field ‘ip6’ has incomplete type" errors.
                   (substitute* "libbridge/libbridge.h"
                     (("#include <linux/if_bridge.h>")
                      "#include <linux/in6.h>\n#include <linux/if_bridge.h>"))

                   ;; Ensure that the entire build fails if one of the
                   ;; sub-Makefiles fails.
                   (substitute* "Makefile.in"
                     (("\\$\\(MAKE\\) \\$\\(MFLAGS\\) -C \\$\\$x ;")
                      "$(MAKE) $(MFLAGS) -C $$x || exit 1;"))

                   (zero? (system* "autoreconf" "-vf")))
                 %standard-phases)
       #:tests? #f))                              ; no 'check' target

    (home-page
     "http://www.linuxfoundation.org/collaborate/workgroups/networking/bridge")
    (synopsis "Manipulate Ethernet bridges")
    (description
     "Utilities for Linux's Ethernet bridging facilities.  A bridge is a way
to connect two Ethernet segments together in a protocol independent way.
Packets are forwarded based on Ethernet address, rather than IP address (like
a router).  Since forwarding is done at Layer 2, all protocols can go
transparently through a bridge.")
    (license license:gpl2+)))

(define-public libnl
  (package
    (name "libnl")
    (version "3.2.25")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://www.infradead.org/~tgr/libnl/files/libnl-"
                    version ".tar.gz"))
              (sha256
               (base32
                "1icfrv8yihcb74as1gcgmp0wfpdq632q2zvbvqqvjms9cy87bswb"))))
    (build-system gnu-build-system)
    (native-inputs `(("flex" ,flex) ("bison" ,bison)))
    (home-page "http://www.infradead.org/~tgr/libnl/")
    (synopsis "NetLink protocol library suite")
    (description
     "The libnl suite is a collection of libraries providing APIs to netlink
protocol based Linux kernel interfaces.  Netlink is an IPC mechanism primarily
between the kernel and user space processes.  It was designed to be a more
flexible successor to ioctl to provide mainly networking related kernel
configuration and monitoring interfaces.")

    ;; Most files are LGPLv2.1-only, but some are GPLv2-only (like
    ;; 'nl-addr-add.c'), so the result is GPLv2-only.
    (license license:gpl2)))

(define-public iw
  (package
    (name "iw")
    (version "4.9")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://kernel.org/software/network/iw/iw-"
                    version ".tar.xz"))
              (sha256
               (base32
                "1klpvv98bnx1zm6aqalnri2vd7w80scmdaxr2qnblb6mz82whk1j"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)))
    (inputs `(("libnl" ,libnl)))
    (arguments
     `(#:make-flags (list (string-append "PREFIX=" (assoc-ref %outputs "out"))
                          "CC=gcc")
       #:phases (alist-delete 'configure %standard-phases)))
    (home-page "https://wireless.wiki.kernel.org/")
    (synopsis "Tool for configuring wireless devices")
    (description
     "iw is a new nl80211 based CLI configuration utility for wireless
devices.  It replaces @code{iwconfig}, which is deprecated.")
    (license license:isc)))

(define-public powertop
  (package
    (name "powertop")
    (version "2.8")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://01.org/sites/default/files/downloads/powertop/powertop-"
             version ".tar.gz"))
       (sha256
        (base32
         "0nlwazxbnn0k6q5f5b09wdhw0f194lpzkp3l7vxansqhfczmcyx8"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         ;; TODO: Patch some hardcoded "wlan0" in calibrate/calibrate.cpp to
         ;; allow calibrating the network interface in GuixSD.
         (add-after 'unpack 'patch-absolute-file-names
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((kmod (assoc-ref inputs "kmod")))
               (substitute* (find-files "src" "\\.cpp$")
                 ;; Give the right 'modprobe' file name so that essential
                 ;; modules such as msr.ko can be loaded.
                 (("/sbin/modprobe") (string-append kmod "/bin/modprobe"))
                 ;; These programs are only needed to calibrate, so using
                 ;; relative file names avoids adding extra inputs.  When they
                 ;; are missing powertop gracefully handles it.
                 (("/usr/bin/hcitool") "hcitool")
                 (("/usr/bin/xset") "xset")
                 (("/usr/sbin/hciconfig") "hciconfig"))
               #t))))))
    (inputs
     `(("kmod" ,kmod)
       ("libnl" ,libnl)
       ("ncurses" ,ncurses)
       ("pciutils" ,pciutils)
       ("zlib" ,zlib)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "https://01.org/powertop/")
    (synopsis "Analyze power consumption on Intel-based laptops")
    (description
     "PowerTOP is a Linux tool to diagnose issues with power consumption and
power management.  In addition to being a diagnostic tool, PowerTOP also has
an interactive mode where the user can experiment various power management
settings for cases where the operating system has not enabled these
settings.")
    (license license:gpl2)))

(define-public aumix
  (package
    (name "aumix")
    (version "2.9.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://www.jpj.net/~trevor/aumix/releases/aumix-"
                    version ".tar.bz2"))
              (sha256
               (base32
                "0a8fwyxnc5qdxff8sl2sfsbnvgh6pkij4yafiln0fxgg6bal7knj"))))
    (build-system gnu-build-system)
    (inputs `(("ncurses" ,ncurses)))
    (home-page "http://www.jpj.net/~trevor/aumix.html")
    (synopsis "Audio mixer for X and the console")
    (description
     "Aumix adjusts an audio mixer from X, the console, a terminal,
the command line or a script.")
    (license license:gpl2+)))

(define-public iotop
  (package
    (name "iotop")
    (version "0.6")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://guichaz.free.fr/iotop/files/iotop-"
                           version ".tar.gz"))
       (sha256 (base32
                "1kp8mqg2pbxq4xzpianypadfxcsyfgwcaqgqia6h9fsq6zyh4z0s"))))
    (build-system python-build-system)
    (arguments
     ;; The setup.py script expects python-2.
     `(#:python ,python-2
       ;; There are currently no checks in the package.
       #:tests? #f))
    (native-inputs `(("python" ,python-2)))
    (home-page "http://guichaz.free.fr/iotop/")
    (synopsis
     "Displays the IO activity of running processes")
    (description
     "Iotop is a Python program with a top like user interface to show the
processes currently causing I/O.")
    (license license:gpl2+)))

(define-public fuse
  (package
    (name "fuse")
    (version "2.9.6")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/libfuse/libfuse/releases/"
                                  "download/fuse-" version
                                  "/fuse-" version ".tar.gz"))
              (sha256
               (base32
                "0szi2vlsjxg03y4ji51jks34p269jqj5ify6l0ajsqq6f6y8pd0c"))))
    (build-system gnu-build-system)
    (inputs `(("util-linux" ,util-linux)))
    (arguments
     '(#:configure-flags (list (string-append "MOUNT_FUSE_PATH="
                                              (assoc-ref %outputs "out")
                                              "/sbin")
                               (string-append "INIT_D_PATH="
                                              (assoc-ref %outputs "out")
                                              "/etc/init.d")

                               ;; The rule makes /dev/fuse 666.
                               (string-append "UDEV_RULES_PATH="
                                              (assoc-ref %outputs "out")
                                              "/lib/udev/rules.d"))
      #:phases (alist-cons-before
                'build 'set-file-names
                (lambda* (#:key inputs #:allow-other-keys)
                  ;; libfuse calls out to mount(8) and umount(8).  Make sure
                  ;; it refers to the right ones.
                  (substitute* '("lib/mount_util.c" "util/mount_util.c")
                    (("/bin/(u?)mount" _ maybe-u)
                     (string-append (assoc-ref inputs "util-linux")
                                    "/bin/" maybe-u "mount")))
                  (substitute* '("util/mount.fuse.c")
                    (("/bin/sh")
                     (which "sh")))

                  ;; This hack leads libfuse to search for 'fusermount' in
                  ;; $PATH, where it may find a setuid-root binary, instead of
                  ;; trying solely $out/sbin/fusermount and failing because
                  ;; it's not setuid.
                  (substitute* "lib/Makefile"
                    (("-DFUSERMOUNT_DIR=[[:graph:]]+")
                     "-DFUSERMOUNT_DIR=\\\"/var/empty\\\"")))
                %standard-phases)))
    (home-page "https://github.com/libfuse/libfuse")
    (synopsis "Support file systems implemented in user space")
    (description
     "As a consequence of its monolithic design, file system code for Linux
normally goes into the kernel itself---which is not only a robustness issue,
but also an impediment to system extensibility.  FUSE, for \"file systems in
user space\", is a kernel module and user-space library that tries to address
part of this problem by allowing users to run file system implementations as
user-space processes.")
    (license (list license:lgpl2.1                ;library
                   license:gpl2+))))              ;command-line utilities

(define-public unionfs-fuse
  (package
    (name "unionfs-fuse")
    (version "0.26")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://podgorny.cz/unionfs-fuse/releases/unionfs-fuse-"
                    version ".tar.xz"))
              (sha256
               (base32
                "0qpnr4czgc62vsfnmv933w62nq3xwcbnvqch72qakfgca75rsp4d"))))
    (build-system cmake-build-system)
    (inputs `(("fuse" ,fuse)))
    (arguments '(#:tests? #f))                    ; no tests
    (home-page "http://podgorny.cz/moin/UnionFsFuse")
    (synopsis "User-space union file system")
    (description
     "UnionFS-FUSE is a flexible union file system implementation in user
space, using the FUSE library.  Mounting a union file system allows you to
\"aggregate\" the contents of several directories into a single mount point.
UnionFS-FUSE additionally supports copy-on-write.")
    (license license:bsd-3)))

(define fuse-static
  (package (inherit fuse)
    (name "fuse-static")
    (source (origin (inherit (package-source fuse))
              (modules '((guix build utils)))
              (snippet
               ;; Normally libfuse invokes mount(8) so that /etc/mtab is
               ;; updated.  Change calls to 'mtab_needs_update' to 0 so that
               ;; it doesn't do that, allowing us to remove the dependency on
               ;; util-linux (something that is useful in initrds.)
               '(substitute* '("lib/mount_util.c"
                               "util/mount_util.c")
                  (("mtab_needs_update[[:blank:]]*\\([a-z_]+\\)")
                   "0")
                  (("/bin/")
                   "")))))))

(define-public unionfs-fuse/static
  (package (inherit unionfs-fuse)
    (synopsis "User-space union file system (statically linked)")
    (name (string-append (package-name unionfs-fuse) "-static"))
    (source (origin (inherit (package-source unionfs-fuse))
              (modules '((guix build utils)))
              (snippet
               ;; Add -ldl to the libraries, because libfuse.a needs that.
               '(substitute* "src/CMakeLists.txt"
                  (("target_link_libraries(.*)\\)" _ libs)
                   (string-append "target_link_libraries"
                                  libs " dl)"))))))
    (arguments
     '(#:tests? #f
       #:configure-flags '("-DCMAKE_EXE_LINKER_FLAGS=-static")
       #:phases (alist-cons-after
                 'install 'post-install
                 (lambda* (#:key outputs #:allow-other-keys)
                   (let* ((out (assoc-ref outputs "out"))
                          (exe (string-append out "/bin/unionfs")))
                     ;; By default, 'unionfs' keeps references to
                     ;; $glibc/share/locale and similar stuff.  Remove them.
                     (remove-store-references exe)))
                 %standard-phases)))
    (inputs `(("fuse" ,fuse-static)))))

(define-public sshfs-fuse
  (package
    (name "sshfs-fuse")
    (version "2.8")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/libfuse/sshfs/releases/"
                                  "download/sshfs_" version
                                  "/sshfs-" version ".tar.gz"))
              (sha256
               (base32
                "08mdd4rs7yys7hmyig6i08qlid76p17xlvrh64k7wsrfs1s92s3z"))))
    (build-system gnu-build-system)
    (inputs
     `(("fuse" ,fuse)
       ("glib" ,glib)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://fuse.sourceforge.net/sshfs.html")
    (synopsis "Mount remote file systems over SSH")
    (description
     "This is a file system client based on the SSH File Transfer Protocol.
Since most SSH servers already support this protocol it is very easy to set
up: on the server side there's nothing to do; on the client side mounting the
file system is as easy as logging into the server with an SSH client.")
    (license license:gpl2+)))

(define-public numactl
  (package
    (name "numactl")
    (version "2.0.11")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "ftp://oss.sgi.com/www/projects/libnuma/download/numactl-"
                    version
                    ".tar.gz"))
              (sha256
               (base32
                "0qbqa9gac2vlahrngi553hws2mqgqdwv2lc69a3yx4gq6l90j325"))))
    (build-system gnu-build-system)
    (arguments
     '(;; There's a 'test' target, but it requires NUMA support in the kernel
       ;; to run, which we can't assume to have.
       #:tests? #f))

    ;; NUMA is apparently not supported on armhf, see
    ;; http://www.spinics.net/lists/linux-numa/msg01157.html
    (supported-systems (delete "armhf-linux" %supported-systems))
    (home-page "http://oss.sgi.com/projects/libnuma/")
    (synopsis "Tools for non-uniform memory access (NUMA) machines")
    (description
     "NUMA stands for Non-Uniform Memory Access, in other words a system whose
memory is not all in one place.  The numactl program allows you to run your
application program on specific CPU's and memory nodes.  It does this by
supplying a NUMA memory policy to the operating system before running your
program.

The package contains other commands, such as numademo, numastat and memhog.
The numademo command provides a quick overview of NUMA performance on your
system.")
    (license (list license:gpl2                   ;programs
                   license:lgpl2.1))))            ;library

(define-public kbd
  (package
    (name "kbd")
    (version "2.0.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://kernel.org/linux/utils/kbd/kbd-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "0ppv953gn2zylcagr4z6zg5y2x93dxrml29plypg6xgbq3hrv2bs"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  (substitute* "tests/Makefile.in"
                    ;; The '%: %.in' rule incorrectly uses @VERSION@.
                    (("@VERSION@")
                     "[@]VERSION[@]"))
                  (substitute* '("src/unicode_start" "src/unicode_stop")
                    ;; Assume the Coreutils are in $PATH.
                    (("/usr/bin/tty")
                     "tty"))))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-before 'build 'pre-build
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((gzip  (assoc-ref %build-inputs "gzip"))
                   (bzip2 (assoc-ref %build-inputs "bzip2")))
               (substitute* "src/libkeymap/findfile.c"
                 (("gzip")
                  (string-append gzip "/bin/gzip"))
                 (("bzip2")
                  (string-append bzip2 "/bin/bzip2"))))))
         (add-after 'install 'post-install
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Make sure these programs find their comrades.
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin")))
               (for-each (lambda (prog)
                           (wrap-program (string-append bin "/" prog)
                             `("PATH" ":" prefix (,bin))))
                         '("unicode_start" "unicode_stop"))))))))
    (inputs `(("check" ,check)
              ("gzip" ,gzip)
              ("bzip2" ,bzip2)
              ("pam" ,linux-pam)))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (home-page "ftp://ftp.kernel.org/pub/linux/utils/kbd/")
    (synopsis "Linux keyboard utilities and keyboard maps")
    (description
     "This package contains keytable files and keyboard utilities compatible
for systems using the Linux kernel.  This includes commands such as
'loadkeys', 'setfont', 'kbdinfo', and 'chvt'.")
    (license license:gpl2+)))

(define-public inotify-tools
  (package
    (name "inotify-tools")
    (version "3.13")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://sourceforge/inotify-tools/inotify-tools/"
                    version "/inotify-tools-" version ".tar.gz"))
              (sha256
               (base32
                "0icl4bx041axd5dvhg89kilfkysjj86hjakc7bk8n49cxjn4cha6"))))
    (build-system gnu-build-system)
    (home-page "http://inotify-tools.sourceforge.net/")
    (synopsis "Monitor file accesses")
    (description
     "The inotify-tools packages provides a C library and command-line tools
to use Linux' inotify mechanism, which allows file accesses to be monitored.")
    (license license:gpl2+)))

(define-public kmod
  (package
    (name "kmod")
    (version "23")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "mirror://kernel.org/linux/utils/kernel/kmod/"
                              "kmod-" version ".tar.xz"))
              (sha256
               (base32
                "0mc12sx06p8il1ym3hdmgxxb37apn9yv7xij26gddjdfkx8xa0yk"))
              (patches (search-patches "kmod-module-directory.patch"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("xz" ,xz)
       ("zlib" ,zlib)))
    (arguments
     `(#:tests? #f ; FIXME: Investigate test failures
       #:configure-flags '("--with-xz" "--with-zlib")
       #:phases (alist-cons-after
                 'install 'install-modprobe&co
                 (lambda* (#:key outputs #:allow-other-keys)
                   (let* ((out (assoc-ref outputs "out"))
                          (bin (string-append out "/bin")))
                     (for-each (lambda (tool)
                                 (symlink "kmod"
                                          (string-append bin "/" tool)))
                               '("insmod" "rmmod" "lsmod" "modprobe"
                                 "modinfo" "depmod"))))
                 %standard-phases)))
    (home-page "https://www.kernel.org/")
    (synopsis "Kernel module tools")
    (description "Kmod is a set of tools to handle common tasks with Linux
kernel modules like insert, remove, list, check properties, resolve
dependencies and aliases.

These tools are designed on top of libkmod, a library that is shipped with
kmod.  The aim is to be compatible with tools, configurations and indices
from the module-init-tools project.")
    (license license:gpl2+))) ; library under lgpl2.1+

(define-public eudev
  ;; The post-systemd fork, maintained by Gentoo.
  (package
    (name "eudev")
    (version "3.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://dev.gentoo.org/~blueness/eudev/eudev-"
                    version ".tar.gz"))
              (sha256
               (base32
                "099w62ncq78nxpxizf910mx18hc8x4qvzw3azjd00fir89wmyjnq"))
              (patches (search-patches "eudev-rules-directory.patch"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("perl" ,perl)
       ("gperf" ,gperf)))
    (inputs
     ;; When linked against libblkid, eudev can populate /dev/disk/by-label
     ;; and similar; it also installs the '60-persistent-storage.rules' file,
     ;; which contains the rules to do that.
     `(("util-linux" ,util-linux)                 ;for blkid
       ("kmod" ,kmod)))
    (home-page "https://wiki.gentoo.org/wiki/Project:Eudev")
    (synopsis "Userspace device management")
    (description "Udev is a daemon which dynamically creates and removes
device nodes from /dev/, handles hotplug events and loads drivers at boot
time.")
    (license license:gpl2+)))

(define-public lvm2
  (package
    (name "lvm2")
    (version "2.02.166")
    (source (origin
              (method url-fetch)
              (uri (string-append "ftp://sources.redhat.com/pub/lvm2/releases/LVM2."
                                  version ".tgz"))
              (sha256
               (base32
                "150v0mawd2swdvypcmkjd3h3s4n5i1220h6sxx94a8jvp1kb0871"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  (use-modules (guix build utils))

                  ;; Honor sysconfdir.
                  (substitute* "make.tmpl.in"
                    (("confdir = .*$")
                     "confdir = @sysconfdir@\n")
                    (("DEFAULT_SYS_DIR = @DEFAULT_SYS_DIR@")
                     "DEFAULT_SYS_DIR = @sysconfdir@"))))
              (patches (search-patches "lvm2-static-link.patch"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("procps" ,procps)))                       ;tests use 'pgrep'
    (inputs
     `(("udev" ,eudev)))
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-after 'configure 'set-makefile-shell
           (lambda _
             ;; Use 'sh', not 'bash', so that '. lib/utils.sh' works as
             ;; expected.
             (setenv "SHELL" (which "sh"))

             ;; Replace /bin/sh with the right file name.
             (patch-makefile-SHELL "make.tmpl")
             #t))
         (add-before 'strip 'make-objects-writable
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Make compiled objects writable so they can be stripped.
             (let ((out (assoc-ref outputs "out")))
               (for-each (lambda (file)
                           (chmod file #o755))
                         (append
                           (find-files (string-append out "/lib"))
                           (find-files (string-append out "/sbin"))))
               #t))))

       #:configure-flags (list (string-append "--sysconfdir="
                                              (assoc-ref %outputs "out")
                                              "/etc/lvm")
                               "--enable-udev_sync"
                               "--enable-udev_rules"

                               ;; Make sure programs such as 'dmsetup' can
                               ;; find libdevmapper.so.
                               (string-append "LDFLAGS=-Wl,-rpath="
                                              (assoc-ref %outputs "out")
                                              "/lib"))

       ;; The tests use 'mknod', which requires root access.
       #:tests? #f))
    (home-page "http://sourceware.org/lvm2/")
    (synopsis "Logical volume management for Linux")
    (description
     "LVM2 is the logical volume management tool set for Linux-based systems.
This package includes the user-space libraries and tools, including the device
mapper.  Kernel components are part of Linux-libre.")

    ;; Libraries (liblvm2, libdevmapper) are LGPLv2.1.
    ;; Command-line tools are GPLv2.
    (license (list license:gpl2 license:lgpl2.1))))

(define-public lvm2-static
  (package
    (inherit lvm2)
    (name "lvm2-static")

    ;; Propagate udev because libdevmapper.a depends on libudev.
    (inputs (alist-delete "udev" (package-inputs lvm2)))
    (propagated-inputs `(("udev" ,eudev)))

    (arguments
     (substitute-keyword-arguments (package-arguments lvm2)
       ((#:configure-flags flags '())
        ;; LVM2 doesn't use Libtool, hence the custom option.
        `(cons "--enable-static_link" ,flags))))
    (synopsis "Logical volume management for Linux (statically linked)")))

(define-public wireless-tools
  (package
    (name "wireless-tools")
    (version "30.pre9")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.hpl.hp.com/personal/Jean_Tourrilhes/Linux/wireless_tools."
                                  version ".tar.gz"))
              (sha256
               (base32
                "0qscyd44jmhs4k32ggp107hlym1pcyjzihiai48xs7xzib4wbndb"))
              (snippet
               '(begin
                  ;; Remove the older header files that are not free software.
                  (for-each (lambda (n)
                              (delete-file (format #f "wireless.~a.h" n)))
                            '(10 11 12 13 14 15 16 17 18 19 20))
                  #t))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags
       (list (string-append "PREFIX=" %output)
             (string-append "INSTALL_MAN=" %output "/share/man")
             (string-append "LDFLAGS=-Wl,-rpath=" %output "/lib")
             "BUILD_STATIC=")
       #:phases (modify-phases %standard-phases
                  (delete 'configure))
       #:tests? #f))
    (synopsis "Tools for manipulating Linux Wireless Extensions")
    (description "Wireless Tools are used to manipulate the now-deprecated
Linux Wireless Extensions; consider using 'iw' instead.  The Wireless
Extension was an interface allowing you to set Wireless LAN specific
parameters and get the specific stats.  It is deprecated in favor the nl80211
interface.")
    (home-page "http://www.hpl.hp.com/personal/Jean_Tourrilhes/Linux/Tools.html")
    ;; wireless.21.h and wireless.22.h are distributed under lgpl2.1+, the
    ;; other files are distributed under gpl2.
    (license (list license:gpl2 license:lgpl2.1+))))

(define-public crda
  (package
    (name "crda")
    (version "3.18")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://kernel.org/software/network/crda/"
                                  "crda-" version ".tar.xz"))
              (sha256
               (base32
                "1gydiqgb08d9gbx4l6gv98zg3pljc984m50hmn3ysxcbkxkvkz23"))
              (patches (search-patches "crda-optional-gcrypt.patch"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (modify-phases %standard-phases
                  (delete 'configure)
                  (add-before
                   'build 'no-werror-no-ldconfig
                   (lambda _
                     (substitute* "Makefile"
                       (("-Werror")  "")
                       (("ldconfig") "true"))
                     #t))
                  (add-before
                   'build 'set-regulator-db-file-name
                   (lambda* (#:key inputs #:allow-other-keys)
                     ;; Tell CRDA where to find our database.
                     (let ((regdb (assoc-ref inputs "wireless-regdb")))
                       (substitute* "crda.c"
                         (("\"/lib/crda/regulatory.bin\"")
                          (string-append "\"" regdb
                                         "/lib/crda/regulatory.bin\"")))
                       #t))))
       #:test-target "verify"
       #:make-flags (let ((out   (assoc-ref %outputs "out"))
                          (regdb (assoc-ref %build-inputs "wireless-regdb")))
                      (list "CC=gcc" "V=1"

                            ;; Disable signature-checking on 'regulatory.bin'.
                            ;; The reason is that this simplifies maintenance
                            ;; on our side (no need to manage a distro key
                            ;; pair), and we can guarantee integrity of
                            ;; 'regulatory.bin' by other means anyway, such as
                            ;; 'guix gc --verify'.  See
                            ;; <https://wireless.wiki.kernel.org/en/developers/regulatory/wireless-regdb>
                            ;; for a discssion.
                            "USE_OPENSSL=0"

                            (string-append "PREFIX=" out)
                            (string-append "SBINDIR=" out "/sbin/")
                            (string-append "UDEV_RULE_DIR="
                                           out "/lib/udev/rules.d")
                            (string-append "LDFLAGS=-Wl,-rpath="
                                           out "/lib -L.")
                            (string-append "REG_BIN=" regdb
                                           "/lib/crda/regulatory.bin")))))
    (native-inputs `(("pkg-config" ,pkg-config)
                     ("python" ,python-2)
                     ("wireless-regdb" ,wireless-regdb)))
    (inputs `(("libnl" ,libnl)))
    (home-page
     "https://wireless.wiki.kernel.org/en/developers/Regulatory/CRDA")
    (synopsis "Central regulatory domain agent (CRDA) for WiFi")
    (description
     "The Central Regulatory Domain Agent (CRDA) acts as the udev helper for
communication between the kernel Linux and user space for regulatory
compliance.")
    (license license:copyleft-next)))

(define-public wireless-regdb
  (package
    (name "wireless-regdb")
    (version "2016.06.10")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://kernel.org/software/network/wireless-regdb/"
                    "wireless-regdb-" version ".tar.xz"))
              (sha256
               (base32
                "1dxqy7a7zpzya30ff00s8k1qgrlndrwys99gc0r8yg0vab1z3vfg"))

              ;; We're building 'regulatory.bin' by ourselves.
              (snippet '(delete-file "regulatory.bin"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (modify-phases %standard-phases
                  (delete 'configure))

       ;; The 'all' target of the makefile depends on $(REGDB_CHANGED), which
       ;; is computed and can be equal to 'maintainer-clean'; when that
       ;; happens, we can end up deleting the 'regulatory.bin' file that we
       ;; just built.  Thus, build things sequentially.
       #:parallel-build? #f

       #:tests? #f                                ;no tests
       #:make-flags (let ((out (assoc-ref %outputs "out")))
                      (list (string-append "PREFIX=" out)
                            (string-append "LSB_ID=GuixSD")
                            (string-append "DISTRO_PUBKEY=/dev/null")
                            (string-append "DISTRO_PRIVKEY=/dev/null")
                            (string-append "REGDB_PUBKEY=/dev/null")

                            ;; Leave that empty so that db2bin.py doesn't try
                            ;; to sign 'regulatory.bin'.  This allows us to
                            ;; avoid managing a key pair for the whole distro.
                            (string-append "REGDB_PRIVKEY=")))))
    (native-inputs `(("python" ,python-2)))
    (home-page
     "https://wireless.wiki.kernel.org/en/developers/regulatory/wireless-regdb")
    (synopsis "Wireless regulatory database")
    (description
     "This package contains the wireless regulatory database Central
Regulatory Database Agent (CRDA) daemon.  The database contains information on
country-specific regulations for the wireless spectrum.")
    (license license:isc)))

(define-public lm-sensors
  (package
    (name "lm-sensors")
    (version "3.4.0")
    (source (origin
              (method url-fetch)
              (uri (list (string-append
                           "https://github.com/groeck/lm-sensors/archive/V"
                           (string-join (string-split version #\.) "-")
                           ".tar.gz")))
              (sha256
               (base32
                "0knb09s9lvx0wzfsaizx3xq58q6kllqf7nkbwvir0wkgn31c2d73"))
              (patches (search-patches "lm-sensors-hwmon-attrs.patch"))))
    (build-system gnu-build-system)
    (inputs `(("rrdtool" ,rrdtool)
              ("perl" ,perl)
              ("kmod" ,kmod)
              ("gnuplot" ,gnuplot)))
    (native-inputs `(("pkg-config" ,pkg-config)
                     ("flex" ,flex)
                     ("bison" ,bison)
                     ("which" ,which)))
    (arguments
     `(#:tests? #f  ; no 'check' target
       #:make-flags (list (string-append "PREFIX=" %output)
                          (string-append "ETCDIR=" %output "/etc")
                          (string-append "MANDIR=" %output "/share/man"))
       #:phases
       (alist-delete
        'configure
        (alist-cons-before
         'build 'patch-exec-paths
         (lambda* (#:key inputs outputs #:allow-other-keys)
           (substitute* "prog/detect/sensors-detect"
             (("`uname")
              (string-append "`" (assoc-ref inputs "coreutils")
                             "/bin/uname"))
             (("(`|\")modprobe" all open-quote)
              (string-append open-quote
                             (assoc-ref inputs "kmod")
                             "/bin/modprobe")))
           (substitute* '("prog/pwm/pwmconfig"
                          "prog/pwm/fancontrol")
             (("gnuplot")
              (string-append (assoc-ref inputs "gnuplot")
                             "/bin/gnuplot"))
             (("cat ")
              (string-append (assoc-ref inputs "coreutils")
                             "/bin/cat "))
             (("egrep ")
              (string-append (assoc-ref inputs "grep")
                             "/bin/egrep "))
             (("sed -e")
              (string-append (assoc-ref inputs "sed")
                             "/bin/sed -e"))
             (("cut -d")
              (string-append (assoc-ref inputs "coreutils")
                             "/bin/cut -d"))
             (("sleep ")
              (string-append (assoc-ref inputs "coreutils")
                             "/bin/sleep "))
             (("readlink -f")
              (string-append (assoc-ref inputs "coreutils")
                             "/bin/readlink -f"))))
         %standard-phases))))
    (home-page "http://jdelvare.nerim.net/devel.html#lmsensors")
    (synopsis "Utilities to read temperature/voltage/fan sensors")
    (description
     "Lm-sensors is a hardware health monitoring package for Linux.  It allows
you to access information from temperature, voltage, and fan speed sensors.
It works with most newer systems.")
    (license license:gpl2+)))

(define-public i2c-tools
  (package
    (name "i2c-tools")
    (version "3.1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://jdelvare.nerim.net/mirror/i2c-tools/i2c-tools-"
                    version ".tar.bz2"))
              (sha256
               (base32
                "000pvg995qy1b15ks59gd0klri55hb33kqpg5czy84hw1pbdgm0l"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f  ; no 'check' target
       #:make-flags (list (string-append "prefix=" %output)
                          "CC=gcc")
       ;; no configure script
       #:phases (alist-delete 'configure %standard-phases)))
    (inputs
     `(("perl" ,perl)))
    (home-page "http://jdelvare.nerim.net/devel.html#i2ctools")
    (synopsis "I2C tools for Linux")
    (description
     "The i2c-tools package contains a heterogeneous set of I2C tools for
Linux: a bus probing tool, a chip dumper, register-level SMBus access helpers,
EEPROM decoding scripts, EEPROM programming tools, and a python module for
SMBus access.")
    (license license:gpl2+)))

(define-public xsensors
  (package
    (name "xsensors")
    (version "0.70")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://www.linuxhardware.org/xsensors/xsensors-"
                    version ".tar.gz"))
              (sha256
               (base32
                "1siplsfgvcxamyqf44h71jx6jdfmvhfm7mh0y1q8ps4zs6pj2zwh"))))
    (build-system gnu-build-system)
    (inputs `(("lm-sensors" ,lm-sensors)
              ("gtk" ,gtk+-2)))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (arguments
     `(#:phases (alist-cons-before
                 'configure 'enable-deprecated
                 (lambda _
                   (substitute* "src/Makefile.in"
                     (("-DGDK_DISABLE_DEPRECATED") "")
                     (("-DGTK_DISABLE_DEPRECATED") "")))
                 (alist-cons-before
                  'configure 'remove-Werror
                  (lambda _
                    (substitute* '("configure" "src/Makefile.in")
                      (("-Werror") "")))
                  %standard-phases))))
    (home-page "http://www.linuxhardware.org/xsensors/")
    (synopsis "Hardware health information viewer")
    (description
     "Xsensors reads data from the libsensors library regarding hardware
health such as temperature, voltage and fan speed and displays the information
in a digital read-out.")
    (license license:gpl2+)))

(define-public perf
  (package
    (name "perf")
    (version (package-version linux-libre))
    (source (package-source linux-libre))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (alist-replace
                 'configure
                 (lambda* (#:key inputs #:allow-other-keys)
                   (setenv "SHELL_PATH" (which "bash"))
                   (chdir "tools/perf"))
                 %standard-phases)
       #:make-flags (list (string-append "DESTDIR="
                                         (assoc-ref %outputs "out"))
                          "WERROR=0"

                          ;; By default, 'config/Makefile' uses lib64 on
                          ;; x86_64.  Work around that.
                          "lib=lib")
       #:tests? #f))                              ;no tests
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("bison" ,bison)
       ("flex" ,flex)

       ;; There are build scripts written in these languages.
       ("perl" ,perl)
       ("python" ,python-2)))
    (inputs
     `(("slang" ,slang)                        ;for the interactive TUI
       ;; ("newt" ,newt)
       ("python" ,python-2)                    ;'perf' links against libpython
       ("elfutils" ,elfutils)

       ;; Documentation.
       ("libxml2" ,libxml2)                       ;for $XML_CATALOG_FILES
       ("libxslt" ,libxslt)
       ("docbook-xml" ,docbook-xml)
       ("docbook-xsl" ,docbook-xsl)
       ("xmlto" ,xmlto)
       ("asciidoc" ,asciidoc)))
    (home-page "https://perf.wiki.kernel.org/")
    (synopsis "Linux profiling with performance counters")
    (description
     "perf is a tool suite for profiling using hardware performance counters,
with support in the Linux kernel.  perf can instrument CPU performance
counters, tracepoints, kprobes, and uprobes (dynamic tracing).  It is capable
of lightweight profiling.  This package contains the user-land tools and in
particular the 'perf' command.")
    (license (package-license linux-libre))))

(define-public pflask
  (package
    (name "pflask")
    (version "0.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/ghedo/pflask/archive/v"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1g8fjj67dfkc2s0852l9vqi1pm61gp4rxbpzbzg780f5s5hd1fys"))))
    (build-system cmake-build-system)
    (arguments
     '(#:tests? #f)) ; no tests
    (home-page "http://ghedo.github.io/pflask/")
    (synopsis "Simple tool for creating Linux namespace containers")
    (description "pflask is a simple tool for creating Linux namespace
containers.  It can be used for running a command or even booting an OS inside
an isolated container, created with the help of Linux namespaces.  It is
similar in functionality to chroot, although pflask provides better isolation
thanks to the use of namespaces.")
    (license license:bsd-2)))

(define-public hdparm
  (package
    (name "hdparm")
    (version "9.45")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/" name "/" name "/"
                                  name "-" version ".tar.gz"))
              (sha256
               (base32
                "0sc6yf3k6sd7n6a2ig2my9fjlqpak3znlyw7jw4cz5d9asm1rc13"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags (let ((out (assoc-ref %outputs "out")))
                      (list (string-append "binprefix=" out)
                            (string-append "manprefix=" out)
                            "CC=gcc"))
       #:phases (alist-delete 'configure %standard-phases)
       #:tests? #f))  ; no test suite
    (home-page "http://sourceforge.net/projects/hdparm/")
    (synopsis "Tune hard disk parameters for high performance")
    (description
     "Get/set device parameters for Linux SATA/IDE drives.  It's primary use
is for enabling irq-unmasking and IDE multiple-mode.")
    (license (license:non-copyleft "file://LICENSE.TXT"))))

(define-public rfkill
  (package
    (name "rfkill")
    (version "0.5")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://kernel.org/software/network/"
                                  name "/" name "-" version ".tar.xz"))
              (sha256
               (base32
                "0snqj5h0y991lszbigbyyqb8swj0hxajc1vfqg2scfay44231bp0"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags (list "CC=gcc"
                          (string-append "PREFIX=" %output))
       #:phases (modify-phases %standard-phases
                  (delete 'configure))
       #:tests? #f))
    (home-page "https://wireless.wiki.kernel.org/en/users/Documentation/rfkill")
    (synopsis "Tool for enabling and disabling wireless devices")
    (description
     "rfkill is a simple tool for accessing the rfkill device interface,
which is used to enable and disable wireless networking devices, typically
WLAN, Bluetooth and mobile broadband.")
    (license (license:non-copyleft "file://COPYING"
                                   "See COPYING in the distribution."))))

(define-public acpi
  (package
    (name "acpi")
    (version "1.7")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/acpiclient/acpiclient/" 
                                  version "/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "01ahldvf0gc29dmbd5zi4rrnrw2i1ajnf30sx2vyaski3jv099fp"))))
    (build-system gnu-build-system)
    (home-page "http://acpiclient.sourceforge.net")
    (synopsis "Display information on ACPI devices")
    (description "@code{acpi} attempts to replicate the functionality of the
\"old\" @code{apm} command on ACPI systems, including battery and thermal
information.  It does not support ACPI suspending, only displays information
about ACPI devices.")
    (license license:gpl2+)))

(define-public acpid
  (package
    (name "acpid")
    (version "2.0.23")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/acpid2/acpid-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "1vl7c6vc724v4jwki17czgj6lnrknnj1a6llm8gkl32i2gnam5j3"))))
    (build-system gnu-build-system)
    (home-page "http://sourceforge.net/projects/acpid2/")
    (synopsis "Daemon for delivering ACPI events to user-space programs")
    (description
     "acpid is designed to notify user-space programs of Advanced
Configuration and Power Interface (ACPI) events.  acpid should be started
during the system boot, and will run as a background process.  When an ACPI
event is received from the kernel, acpid will examine the list of rules
specified in /etc/acpi/events and execute the rules that match the event.")
    (license license:gpl2+)))

(define-public sysfsutils
  (package
    (name "sysfsutils")
    (version "2.1.0")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append
         "mirror://sourceforge/linux-diag/sysfsutils/" version "/sysfsutils-"
         version ".tar.gz"))
       (sha256
        (base32 "12i0ip11xbfcjzxz4r10cvz7mbzgq1hfcdn97w6zz7sm3wndwrg8"))))
    (build-system gnu-build-system)
    (home-page "http://linux-diag.sourceforge.net/Sysfsutils.html")
    (synopsis "System utilities based on Linux sysfs")
    (description
     "These are a set of utilities built upon sysfs, a virtual file system in
Linux kernel versions 2.5+ that exposes a system's device tree.  The package
also contains the libsysfs library.")
    ;; The library is under lgpl2.1+ (all files say "or any later version").
    ;; The rest is mostly gpl2, with a few files indicating gpl2+.
    (license (list license:gpl2 license:gpl2+ license:lgpl2.1+))))

(define-public sysfsutils-1
  (package
    (inherit sysfsutils)
    (version "1.3.0")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append
         "mirror://sourceforge/linux-diag/sysfsutils/sysfsutils-" version
         "/sysfsutils-" version ".tar.gz"))
       (sha256
        (base32 "0kdhs07fm8263pxwd5blwn2x211cg4fk63fyf9ijcdkvzmwxrqq3"))
       (modules '((guix build utils)))
       (snippet
        '(begin
           (substitute* "Makefile.in"
             (("includedir = /usr/include/sysfs")
              "includedir = @includedir@"))
           (substitute* "configure"
             (("includedir='(\\$\\{prefix\\}/include)'" all orig)
              (string-append "includedir='" orig "/sysfs'")))))))
    (synopsis "System utilities based on Linux sysfs (version 1.x)")))

(define-public cpufrequtils
  (package
    (name "cpufrequtils")
    (version "0.3")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append
         "https://www.kernel.org/pub/linux/utils/kernel/cpufreq/cpufrequtils-"
         version ".tar.gz"))
       (sha256
        (base32 "0qfqv7nqmjfr3p0bwrdlxkiqwqr7vmx053cadaa548ybqbghxmvm"))
       (patches (search-patches "cpufrequtils-fix-aclocal.patch"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("sysfsutils" ,sysfsutils-1)))
    (arguments
     '(#:make-flags (list (string-append "LDFLAGS=-Wl,-rpath="
                                         (assoc-ref %outputs "out") "/lib"))))
    (home-page "https://www.kernel.org/pub/linux/utils/kernel/cpufreq/")
    (synopsis "Utilities to get and set CPU frequency on Linux")
    (description
     "The cpufrequtils suite contains utilities to retrieve CPU frequency
information, and set the CPU frequency if supported, using the cpufreq
capabilities of the Linux kernel.")
    (license license:gpl2)))

(define-public libraw1394
  (package
    (name "libraw1394")
    (version "2.1.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://kernel.org/linux/libs/ieee1394/"
                    name "-" version ".tar.xz"))
              (sha256
               (base32
                "0pm5b415j1qdzyw38wdv8h7ff4yx20831z1727mpsb6jc6bwdk03"))))
    (build-system gnu-build-system)
    (home-page "https://ieee1394.wiki.kernel.org/index.php/Main_Page")
    (synopsis "Interface library for the Linux IEEE1394 drivers")
    (description
     "Libraw1394 is the only supported interface to the kernel side raw1394 of
the Linux IEEE-1394 subsystem, which provides direct access to the connected
1394 buses to user space.  Through libraw1394/raw1394, applications can directly
send to and receive from other nodes without requiring a kernel driver for the
protocol in question.")
    (license license:lgpl2.1+)))

(define-public libavc1394
  (package
    (name "libavc1394")
    (version "0.5.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/libavc1394/libavc1394/"
                                  name "-" version ".tar.gz"))
              (sha256
               (base32
                "0lsv46jdqvdx5hx92v0z2cz3yh6212pz9gk0k3513sbaa04zzcbw"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("libraw1394" ,libraw1394))) ; required by libavc1394.pc
    (home-page "http://sourceforge.net/projects/libavc1394/")
    (synopsis "AV/C protocol library for IEEE 1394")
    (description
     "Libavc1394 is a programming interface to the AV/C specification from
the 1394 Trade Association.  AV/C stands for Audio/Video Control.")
    (license license:lgpl2.1+)))

(define-public libiec61883
  (package
    (name "libiec61883")
    (version "1.2.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://kernel.org/linux/libs/ieee1394/"
                    name "-" version ".tar.xz"))
              (sha256
               (base32
                "17ph458zya2l8dr2xwqnzy195qd9swrir31g78qkgb3g4xz2rq6i"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("libraw1394" ,libraw1394))) ; required by libiec61883.pc
    (home-page "https://ieee1394.wiki.kernel.org/index.php/Main_Page")
    (synopsis "Isochronous streaming media library for IEEE 1394")
    (description
     "The libiec61883 library provides a higher level API for streaming DV,
MPEG-2 and audio over Linux IEEE 1394.")
    (license license:lgpl2.1+)))

(define-public mdadm
  (package
    (name "mdadm")
    (version "3.4")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://kernel.org/linux/utils/raid/mdadm/mdadm-"
                    version ".tar.xz"))
              (sha256
               (base32
                "0248v9f28mrbwabl94ck22gfim29sqhkf70wrpfi52nk4x3bxl17"))))
    (build-system gnu-build-system)
    (inputs
     `(("udev" ,eudev)))
    (arguments
     `(#:make-flags (let ((out (assoc-ref %outputs "out")))
                      (list "INSTALL=install"
                            "CHECK_RUN_DIR=0"
                            ;; TODO: tell it where to find 'sendmail'
                            ;; (string-append "MAILCMD=" <???> "/sbin/sendmail")
                            (string-append "BINDIR=" out "/sbin")
                            (string-append "MANDIR=" out "/share/man")
                            (string-append "UDEVDIR=" out "/lib/udev")))
       #:phases (alist-cons-before
                 'build 'patch-program-paths
                 (lambda* (#:key inputs #:allow-other-keys)
                   (let ((coreutils (assoc-ref inputs "coreutils")))
                     (substitute* "udev-md-raid-arrays.rules"
                       (("/usr/bin/(readlink|basename)" all program)
                        (string-append coreutils "/bin/" program)))))
                 (alist-cons-before
                  'build 'remove-W-error
                  (lambda _
                    ;; We cannot build with -Werror on i686 due to a
                    ;; 'sign-compare' warning in util.c.
                    (substitute* "Makefile"
                      (("-Werror") ""))
                    #t)
                  (alist-delete 'configure %standard-phases)))
       ;;tests must be done as root
       #:tests? #f))
    (home-page "http://neil.brown.name/blog/mdadm")
    (synopsis "Tool for managing Linux Software RAID arrays")
    (description
     "mdadm is a tool for managing Linux Software RAID arrays.  It can create,
assemble, report on, and monitor arrays.  It can also move spares between raid
arrays when needed.")
    (license license:gpl2+)))

(define-public mdadm-static
  (package
    (inherit mdadm)
    (name "mdadm-static")
    (arguments
     (substitute-keyword-arguments (package-arguments mdadm)
       ((#:make-flags flags)
        `(cons "LDFLAGS = -static" ,flags))
       ((#:phases phases)
        `(modify-phases ,phases
           (add-after 'install 'remove-cruft
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out         (assoc-ref outputs "out"))
                      (precious?   (lambda (file)
                                     (member file '("." ".." "sbin"))))
                      (directories (scandir out (negate precious?))))
                 (with-directory-excursion out
                   (for-each delete-file-recursively directories)
                   (remove-store-references "sbin/mdadm")
                   (delete-file "sbin/mdmon")
                   #t))))))
       ((#:modules modules %gnu-build-system-modules)
        `((ice-9 ftw) ,@modules))
       ((#:strip-flags _ '())
        ''("--strip-all"))                        ;strip a few extra KiB
       ((#:allowed-references _ '("out"))
        '("out"))))                               ;refer only self
    (synopsis "Statically-linked 'mdadm' command for use in an initrd")))

(define-public libaio
  (package
    (name "libaio")
    (version "0.3.110")
    (source (origin
              (method url-fetch)
             (uri (list
                   (string-append "mirror://debian/pool/main/liba/libaio/"
                                  name "_" version ".orig.tar.gz")
                   (string-append "https://fedorahosted.org/releases/l/i/libaio/"
                                  name "-" version ".tar.gz")))
             (sha256
              (base32
               "0zjzfkwd1kdvq6zpawhzisv7qbq1ffs343i5fs9p498pcf7046g0"))))
    (build-system gnu-build-system)
    (arguments
     '(#:make-flags
       (list "CC=gcc" (string-append "prefix=" %output))
       #:test-target "partcheck" ; need root for a full 'check'
       #:phases
       (alist-delete 'configure %standard-phases))) ; no configure script
    (home-page "http://lse.sourceforge.net/io/aio.html")
    (synopsis "Linux-native asynchronous I/O access library")
    (description
     "This library enables userspace to use Linux kernel asynchronous I/O
system calls, important for the performance of databases and other advanced
applications.")
    (license license:lgpl2.1+)))

(define-public sbc
  (package
    (name "sbc")
    (version "1.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://www.kernel.org/pub/linux/bluetooth/"
                                  name "-" version ".tar.xz"))
              (sha256
               (base32
                "02ckd2z51z0h85qgv7x8vv8ybp5czm9if1z78411j53gaz7j4476"))))
    (build-system gnu-build-system)
    (inputs
     `(("libsndfile" ,libsndfile)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "https://www.kernel.org/pub/linux/bluetooth/")
    (synopsis "Bluetooth subband audio codec")
    (description
     "The SBC is a digital audio encoder and decoder used to transfer data to
Bluetooth audio output devices like headphones or loudspeakers.")
    (license license:gpl2+)))

(define-public bluez
  (package
    (name "bluez")
    (version "5.43")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://kernel.org/linux/bluetooth/bluez-"
                    version ".tar.xz"))
              (sha256
               (base32
                "05cdnpz0w2lwq2x5ba87q1h2wgb4lfnpbnbh6p7499hx59fw1j8n"))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags
       (let ((out (assoc-ref %outputs "out")))
         (list "--sysconfdir=/etc"
               "--localstatedir=/var"
               "--enable-library"
               "--disable-systemd"
               ;; Install dbus/udev files to the correct location.
               (string-append "--with-dbusconfdir=" out "/etc")
               (string-append "--with-udevdir=" out "/lib/udev")))
       #:phases
       (modify-phases %standard-phases
         (add-after 'install 'post-install
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out        (assoc-ref outputs "out"))
                    (servicedir (string-append out "/share/dbus-1/services"))
                    (service    "obexd/src/org.bluez.obex.service")
                    (rule       (string-append
                                 out "/lib/udev/rules.d/97-hid2hci.rules")))
               ;; Install the obex dbus service file.
               (substitute* service
                 (("/bin/false")
                  (string-append out "/libexec/bluetooth/obexd")))
               (install-file service servicedir)
               ;; Fix paths in the udev rule.
               (substitute* rule
                 (("hid2hci --method")
                  (string-append out "/lib/udev/hid2hci --method"))
                 (("/sbin/udevadm")
                  (string-append (assoc-ref inputs "eudev") "/bin/udevadm")))
               #t))))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("gettext" ,gettext-minimal)))
    (inputs
     `(("glib" ,glib)
       ("dbus" ,dbus)
       ("eudev" ,eudev)
       ("libical" ,libical)
       ("readline" ,readline)))
    (home-page "http://www.bluez.org/")
    (synopsis "Linux Bluetooth protocol stack")
    (description
     "BlueZ provides support for the core Bluetooth layers and protocols.  It
is flexible, efficient and uses a modular implementation.")
    (license license:gpl2+)))

(define-public fuse-exfat
  (package
    (name "fuse-exfat")
    (version "1.2.5")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/relan/exfat/releases/download/v"
                    version "/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "1i0sh0s6wnm4dqxli3drva871wgbbm57qjf592vnswna9hc6bvim"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("fuse" ,fuse)))
    (home-page "https://github.com/relan/exfat")
    (synopsis "Mount exFAT file systems")
    (description
     "This package provides a FUSE-based file system that provides read and
write access to exFAT devices.")
    (license license:gpl2+)))

(define-public gpm
  (package
    (name "gpm")
    (version "1.20.7")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://www.nico.schottelius.org/software/gpm/archives/gpm-"
                    version ".tar.bz2"))
              (sha256
               (base32
                "13d426a8h403ckpc8zyf7s2p5rql0lqbg2bv0454x0pvgbfbf4gh"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (modify-phases %standard-phases
                  (add-before 'configure 'bootstrap
                    (lambda _
                      ;; The tarball was not generated with 'make dist' so we
                      ;; need to bootstrap things ourselves.
                      (and (zero? (system* "./autogen.sh"))
                           (begin
                             (patch-makefile-SHELL "Makefile.include.in")
                             #t)))))

       ;; Make sure programs find libgpm.so.
       #:configure-flags (list (string-append "LDFLAGS=-Wl,-rpath="
                                              (assoc-ref %outputs "out")
                                              "/lib"))))
    (native-inputs
     `(("texinfo" ,texinfo)
       ("bison" ,bison)
       ("flex" ,flex)
       ("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)))
    (home-page "http://www.nico.schottelius.org/software/gpm/")
    (synopsis "Mouse support for the Linux console")
    (description
     "The GPM (general-purpose mouse) daemon is a mouse server for
applications running on the Linux console.  It allows users to select items
and copy/paste text in the console and in xterm.")
    (license license:gpl2+)))

(define-public btrfs-progs
  (package
    (name "btrfs-progs")
    (version "4.9")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://kernel.org/linux/kernel/"
                                  "people/kdave/btrfs-progs/"
                                  "btrfs-progs-v" version ".tar.xz"))
              (sha256
               (base32
                "18y88avadn4wb3xmczd6pfcjr7ik62dw4phk6fmkms2j8vmvl9z2"))))
    (build-system gnu-build-system)
    (outputs '("out"
               "static"))      ; static versions of binaries in "out" (~16MiB!)
    (arguments
     '(#:phases (modify-phases %standard-phases
                 (add-after 'build 'build-static
                   (lambda _ (zero? (system* "make" "static"))))
                 (add-after 'install 'install-static
                   (let ((staticbin (string-append (assoc-ref %outputs "static")
                                                  "/bin")))
                     (lambda _
                       (zero? (system* "make"
                                       (string-append "bindir=" staticbin)
                                       "install-static"))))))
       #:test-target "test"
       #:parallel-tests? #f)) ; tests fail when run in parallel
    (inputs `(("e2fsprogs" ,e2fsprogs)
              ("libblkid" ,util-linux)
              ("libblkid:static" ,util-linux "static")
              ("libuuid" ,util-linux)
              ("libuuid:static" ,util-linux "static")
              ("zlib" ,zlib)
              ("lzo" ,lzo)))
    (native-inputs `(("pkg-config" ,pkg-config)
                     ("asciidoc" ,asciidoc)
                     ("xmlto" ,xmlto)
                     ;; For building documentation.
                     ("libxml2" ,libxml2)
                     ("docbook-xml" ,docbook-xml)
                     ("docbook-xsl" ,docbook-xsl)
                     ;; For tests.
                     ("which" ,which)))
    (home-page "https://btrfs.wiki.kernel.org/")
    (synopsis "Create and manage btrfs copy-on-write file systems")
    (description "Btrfs is a copy-on-write (CoW) file system for Linux aimed at
implementing advanced features while focusing on fault tolerance, repair and
easy administration.")
    ;; GPL2+: crc32.c, radix-tree.c, raid6.c, rbtree.c.
    ;; GPL2: Everything else.
    (license (list license:gpl2 license:gpl2+))))

(define-public freefall
  (package
    (name "freefall")
    (version (package-version linux-libre))
    (source (package-source linux-libre))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (modify-phases %standard-phases
                  (add-after 'unpack 'enter-subdirectory
                    (lambda _
                      (chdir "tools/laptop/freefall")))
                  (delete 'configure)
                  (add-before 'build 'increase-timeout
                    (lambda _
                      ;; The default of 2 seconds is too low: it assumes an
                      ;; open lid and AC power without actually checking.
                      (substitute* "freefall.c"
                        (("alarm\\(2\\)") "alarm(5)")))))
       #:make-flags (list (string-append "PREFIX="
                                         (assoc-ref %outputs "out")))
       #:tests? #f)) ;no tests
    (home-page (package-home-page linux-libre))
    (synopsis "Free-fall protection for spinning laptop hard drives")
    (description
     "Prevents shock damage to the internal spinning hard drive(s) of some
HP and Dell laptops.  When sudden movement is detected, all input/output
operations on the drive are suspended and its heads are parked on the ramp,
where they are less likely to cause damage to the spinning disc.  Requires a
drive that supports the ATA/ATAPI-7 IDLE IMMEDIATE command with unload
feature, and a laptop with an accelerometer.  It has no effect on SSDs.")
    (license license:gpl2)))

(define-public thinkfan
  (package
    (name "thinkfan")
    (version "0.9.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/thinkfan/"
                                  "/thinkfan-" version ".tar.gz"))
              (sha256
               (base32
                "0nz4c48f0i0dljpk5y33c188dnnwg8gz82s4grfl8l64jr4n675n"))
              (modules '((guix build utils)))
              ;; Fix erroneous man page location in Makefile leading to
              ;; a compilation failure.
              (snippet
               '(substitute* "CMakeLists.txt"
                  (("thinkfan\\.1") "src/thinkfan.1")))))
    (build-system cmake-build-system)
    (arguments
     `(#:modules ((guix build cmake-build-system)
                  (guix build utils)
                  (srfi srfi-26))
       #:tests? #f                      ;no test target
       #:configure-flags
       ;; Enable reading temperatures from hard disks via S.M.A.R.T.
       `("-DUSE_ATASMART:BOOL=ON")
       #:phases
       (modify-phases %standard-phases
         ;; Install scripts for various foreign init systems. Also fix
         ;; hard-coded path for daemon.
         (add-after 'install 'install-rc-scripts
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out"))
                   (files (find-files
                           (string-append "../thinkfan-" ,version "/rcscripts")
                           ".*")))
               (substitute* files
                 (("/usr/sbin/(\\$NAME|thinkfan)" _ name)
                  (string-append out "/sbin/" name)))
               (for-each (cute install-file <>
                               (string-append out "/share/thinkfan"))
                         files))
             #t)))))
    (inputs
     `(("libatasmart" ,libatasmart)))
    (home-page "http://thinkfan.sourceforge.net/")
    (synopsis "Simple fan control program")
    (description
     "Thinkfan is a simple fan control program.  It reads temperatures,
checks them against configured limits and switches to appropriate (also
pre-configured) fan level.  It requires a working @code{thinkpad_acpi} or any
other @code{hwmon} driver that enables temperature reading and fan control
from userspace.")
    (license license:gpl3+)))

(define-public ntfs-3g
  (package
    (name "ntfs-3g")
    (version "2016.2.22")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://tuxera.com/opensource/"
                                  "ntfs-3g_ntfsprogs-" version ".tgz"))
              (sha256
               (base32
                "180y5y09h30ryf2vim8j30a2npwz1iv9ly5yjmh3wjdkwh2jrdyp"))
              (modules '((guix build utils)))
              (snippet
               ;; Install under $prefix.
               '(substitute* '("src/Makefile.in" "ntfsprogs/Makefile.in")
                  (("/sbin")
                   "@sbindir@")))))
    (build-system gnu-build-system)
    (inputs `(("util-linux" ,util-linux)
              ("fuse" ,fuse)))                    ;libuuid
    (native-inputs `(("pkg-config" ,pkg-config)))
    (arguments
     '(#:configure-flags (list "--exec-prefix=${prefix}"
                               "--with-fuse=external" ;use our own FUSE
                               "--enable-mount-helper"
                               "--enable-posix-acls"
                               "--enable-xattr-mappings")))
    (home-page "http://www.tuxera.com/community/open-source-ntfs-3g/")
    (synopsis "Read-write access to NTFS file systems")
    (description
     "NTFS-3G provides read-write access to NTFS file systems, which are
commonly found on Microsoft Windows.  It is implemented as a FUSE file system.
The package provides additional NTFS tools.")
    (license license:gpl2+)))

(define-public rng-tools
  (package
    (name "rng-tools")
    (version "5")
    (source (origin
              (method url-fetch)
              (uri (string-append
                "http://downloads.sourceforge.net/sourceforge/gkernel/"
                "rng-tools-" version ".tar.gz"))
              (sha256
               (base32
                "13h7lc8wl9khhvkr0i3bl5j9bapf8anhqis1lcnwxg1vc2v058b0"))))
    (build-system gnu-build-system)
    (synopsis "Random number generator daemon")
    (description
     "Monitor a hardware random number generator, and supply entropy
from that to the system kernel's @file{/dev/random} machinery.")
    (home-page "http://sourceforge.net/projects/gkernel")
    ;; The source package is offered under the GPL2+, but the files
    ;; 'rngd_rdrand.c' and 'rdrand_asm.S' are only available under the GPL2.
    (license (list license:gpl2 license:gpl2+))))

(define-public cpupower
  (package
    (name "cpupower")
    (version (package-version linux-libre))
    (source (package-source linux-libre))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (modify-phases %standard-phases
                  (add-after 'unpack 'enter-subdirectory
                    (lambda _
                      (chdir "tools/power/cpupower")))
                  (delete 'configure)
                  (add-before 'build 'fix-makefiles
                    (lambda _
                      (substitute* "Makefile"
                        (("/usr/") "/")
                        (("/bin/(install|pwd)" _ command) command))
                      (substitute* "bench/Makefile"
                        (("\\$\\(CC\\) -o") "$(CC) $(LDFLAGS) -o")))))
       #:make-flags (let ((out (assoc-ref %outputs "out")))
                      (list (string-append "DESTDIR=" out)
                            (string-append "LDFLAGS=-Wl,-rpath=" out "/lib")
                            "docdir=/share/doc/cpupower"
                            "confdir=$(docdir)/examples"
                            ;; The Makefile recommends the following changes
                            "DEBUG=false"
                            "PACKAGE_BUGREPORT=bug-guix@gnu.org"))
       #:tests? #f)) ;no tests
    (native-inputs `(("gettext" ,gettext-minimal)))
    (inputs `(("pciutils" ,pciutils)))
    (home-page (package-home-page linux-libre))
    (synopsis "CPU frequency and voltage scaling tools for Linux")
    (description
     "cpupower is a set of user-space tools that use the cpufreq feature of the
Linux kernel to retrieve and control processor features related to power saving,
such as frequency and voltage scaling.")
    (license license:gpl2)))

(define-public haveged
  (package
    (name "haveged")
    (version "1.9.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://www.issihosts.com/haveged/haveged-"
                           version ".tar.gz"))
       (sha256
        (base32
         "059pxlfd4l5dqhd6r3lynzfz4wby2f17294fy17pi9j2jpnn68ww"))))
    (build-system gnu-build-system)
    (home-page "http://www.issihosts.com/haveged")
    (synopsis "Entropy source for the Linux random number generator")
    (description
     "haveged generates an unpredictable stream of random numbers for use by
Linux's @file{/dev/random} and @file{/dev/urandom} devices.  The kernel's
standard mechanisms for filling the entropy pool may not be sufficient for
systems with high needs or limited user interaction, such as headless servers.
@command{haveged} runs as a privileged daemon, harvesting randomness from the
indirect effects of hardware events on hidden processor state using the HArdware
Volatile Entropy Gathering and Expansion (HAVEGE) algorithm.  It tunes itself to
its environment and provides the same built-in test suite for the output stream
as used on certified hardware security devices.")
    (license (list (license:non-copyleft "file://nist/mconf.h")
                   (license:non-copyleft "file://nist/packtest.c")
                   license:public-domain        ; nist/dfft.c
                   license:gpl3+))))            ; everything else

(define-public ecryptfs-utils
  (package
    (name "ecryptfs-utils")
    (version "111")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://launchpad.net/ecryptfs/trunk/"
                           version "/+download/ecryptfs-utils_"
                           version ".orig.tar.gz"))
       (sha256
        (base32
         "0zwq19siiwf09h7lwa7n7mgmrr8cxifp45lmwgcfr8c1gviv6b0i"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags (list "--disable-pywrap")))
    (native-inputs
     `(("intltool" ,intltool)
       ("perl" ,perl)                   ; for pod2man
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("keyutils" ,keyutils)
       ("linux-pam" ,linux-pam)
       ("nss" ,nss)))
    (home-page "http://ecryptfs.org/")
    (synopsis "eCryptfs cryptographic file system utilities")
    (description
     "eCryptfs is a POSIX-compliant stacked cryptographic file system for Linux.
Each file's cryptographic meta-data is stored inside the file itself, along
with the encrypted contents.  This allows individual encrypted files to be
copied between hosts and still be decrypted with the proper key.  eCryptfs is a
native Linux file system, and has been part of the Linux kernel since version
2.6.19.  This package contains the userland utilities to manage it.")
    ;; The files src/key_mod/ecryptfs_key_mod_{openssl,pkcs11_helper,tspi}.c
    ;; grant additional permission to link with OpenSSL.
    (license license:gpl2+)))

(define-public libnfsidmap
  (package
    (name "libnfsidmap")
    (version "0.25")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "http://www.citi.umich.edu/projects/nfsv4/linux/"
                   name "/" name "-" version ".tar.gz"))
             (sha256
              (base32
               "1kzgwxzh83qi97rblcm9qj80cdvnv8kml2plz0q103j0hifj8vb5"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags (list
                          (string-append "--with-pluginpath="
                                         (assoc-ref %outputs "out")
                                         "/lib/libnfsidmap"))))
    (home-page
     "http://www.citi.umich.edu/projects/nfsv4/crossrealm/libnfsidmap_config.html")
    (synopsis
     "NFSv4 support library for name/ID mapping")
    (description "Libnfsidmap is a library holding mulitiple methods of
mapping names to ids and visa versa, mainly for NFSv4.  It provides an
extensible array of mapping functions, currently consisting of two choices:
the default @code{nsswitch} and the experimental @code{umich_ldap}.")
    (license (license:non-copyleft "file://COPYING"
                                   "See COPYING in the distribution."))))

(define-public module-init-tools
  (package
    (name "module-init-tools")
    (version "3.16")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "mirror://kernel.org/linux/utils/kernel/module-init-tools/"
                   "module-init-tools-" version ".tar.bz2"))
             (sha256
              (base32
               "0jxnz9ahfic79rp93l5wxcbgh4pkv85mwnjlbv1gz3jawv5cvwp1"))
             (patches (search-patches "module-init-tools-moduledir.patch"))))
    (build-system gnu-build-system)
    (arguments
     ;; FIXME: The upstream tarball lacks man pages, and building them would
     ;; require DocBook & co.  We used to use Gentoo's pre-built man pages,
     ;; but they vanished.  In the meantime, fake it.
     '(#:phases (alist-cons-before
                 'configure 'fake-docbook
                 (lambda _
                   (substitute* "Makefile.in"
                     (("^DOCBOOKTOMAN.*$")
                      "DOCBOOKTOMAN = true\n")))
                 %standard-phases)))
    (home-page "http://www.kernel.org/pub/linux/utils/kernel/module-init-tools/")
    (synopsis "Tools for loading and managing Linux kernel modules")
    (description
     "Tools for loading and managing Linux kernel modules, such as `modprobe',
`insmod', `lsmod', and more.")
    (license license:gpl2+)))

(define-public mcelog
  (package
    (name "mcelog")
    (version "146")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://git.kernel.org/cgit/utils/cpu/mce/"
                                  "mcelog.git/snapshot/v" version ".tar.gz"))
              (sha256
               (base32
                "0jjx4q1mfa380319cqz86nw5wv6jnbpvq2r8n0dyh87mhvrgb4wi"))
              (file-name (string-append name "-" version ".tar.gz"))
              (modules '((guix build utils)))
              (snippet
               ;; The snapshots lack a .git directory, breaking ‘git describe’.
               `(substitute* "Makefile"
                  (("\"unknown\"") (string-append "\"v" ,version "\""))))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (delete 'configure))  ; no configure script
       #:make-flags (let ((out (assoc-ref %outputs "out")))
                      (list "CC=gcc"
                            (string-append "prefix=" out)
                            (string-append "DOCDIR=" out "/share/doc/mcelog")
                            "etcprefix=$(DOCDIR)/examples"))
       ;; The tests will only run as root on certain supported CPU models.
       #:tests? #f))
    (supported-systems (list "i686-linux" "x86_64-linux"))
    (home-page "http://mcelog.org/")
    (synopsis "Machine check monitor for x86 Linux systems")
    (description
     "The mcelog daemon is required by the Linux kernel to log memory, I/O, CPU,
and other hardware errors on x86 systems.  It can also perform user-defined
tasks, such as bringing bad pages off-line, when configurable error thresholds
are exceeded.")
    (license license:gpl2)))

(define-public mtd-utils
  (package
    (name "mtd-utils")
    (version "1.5.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "ftp://ftp.infradead.org/pub/mtd-utils/"
                    "mtd-utils-" version ".tar.bz2"))
              (sha256
               (base32
                "007lhsd8yb34l899r4m37whhzdw815cz4fnjbpnblfha524p7dax"))))
    (inputs
     `(("acl" ,acl)
       ("libuuid" ,util-linux)
       ("lzo", lzo)
       ("zlib" ,zlib)))
    (build-system gnu-build-system)
    (arguments
     `(#:test-target "tests"
       #:make-flags (list (string-append "PREFIX=" (assoc-ref %outputs "out")))
       #:phases (modify-phases %standard-phases
                  (delete 'configure))))
    (synopsis "MTD Flash Storage Utilities")
    (description "This package provides utilities for testing, partitioning, etc
of flash storage.")
    (home-page "http://www.linux-mtd.infradead.org/")
    (license
      (list license:gpl2 ; Almost everything is gpl2 or gpl2+
            license:mpl1.1 ; All ftl* files
            license:expat)))) ; libiniparser

(define-public libseccomp
  (package
    (name "libseccomp")
    (version "2.3.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/seccomp/libseccomp/"
                                  "releases/download/v" version
                                  "/libseccomp-" version ".tar.gz"))
              (sha256
               (base32
                "0asnlkzqms520r0dra08dzcz5hh6hs7lkajfw9wij3vrd0hxsnzz"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("which" ,which)))
    (synopsis "Interface to Linux's seccomp syscall filtering mechanism")
    (description "The libseccomp library provides an easy to use, platform
independent, interface to the Linux Kernel's syscall filtering mechanism.  The
libseccomp API is designed to abstract away the underlying BPF based syscall
filter language and present a more conventional function-call based filtering
interface that should be familiar to, and easily adopted by, application
developers.")
    (home-page "https://github.com/seccomp/libseccomp")
    (license license:lgpl2.1)))

(define-public radeontop
  (package
    (name "radeontop")
    (version "0.9")
    (home-page "https://github.com/clbr/radeontop/")
    (source (origin
              (method url-fetch)
              (uri (string-append home-page "/archive/v" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "07fnimn6wwablmdjw0av11hk9a6xilbryh09izq4b2ic4b8md2p7"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  ;; getver.sh uses ‘git --describe’, isn't worth an extra git
                  ;; dependency, and doesn't even work on release(!) tarballs.
                  (add-after 'unpack 'report-correct-version
                    (lambda _ (substitute* "getver.sh"
                                (("ver=unknown")
                                 (string-append "ver=" ,version)))))
                  (delete 'configure))  ; no configure script
       #:make-flags (list "CC=gcc"
                          (string-append "PREFIX=" %output))
       #:tests? #f))                    ; no tests
    (native-inputs
     `(("gettext" ,gettext-minimal)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("libdrm" ,libdrm)
       ("libpciaccess" ,libpciaccess)
       ("ncurses" ,ncurses)))
    (synopsis "Usage monitor for AMD Radeon graphics")
    (description "RadeonTop monitors resource consumption on supported AMD
Radeon Graphics Processing Units (GPUs), either in real time as bar graphs on
a terminal or saved to a file for further processing.  It measures both the
activity of the GPU as a whole, which is also accurate during OpenCL
computations, as well as separate component statistics that are only meaningful
under OpenGL graphics workloads.")
    (license license:gpl3)))

(define-public efivar
  (package
    (name "efivar")
    (version "30")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/rhinstaller/" name
                                  "/releases/download/" version "/" name
                                  "-" version ".tar.bz2"))
              (sha256
               (base32
                "12qjnm44yi55ffqxjpgrxy82s89yjziy84w2rfjjknsd8flj0mqz"))))
    (build-system gnu-build-system)
    (arguments
     `(;; Tests require a UEFI system and is not detected in the chroot.
       #:tests? #f
       #:make-flags (list (string-append "prefix=" %output)
                          (string-append "libdir=" %output "/lib")
                          (string-append "LDFLAGS=-Wl,-rpath=" %output "/lib"))
       #:phases
       (modify-phases %standard-phases
         (delete 'configure))))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("popt" ,popt)))
    (home-page "https://github.com/rhinstaller/efivar")
    (synopsis "Tool and library to manipulate EFI variables")
    (description "This package provides a library and a command line
interface to the variable facility of UEFI boot firmware.")
    (license license:lgpl2.1+)))

(define-public efibootmgr
  (package
    (name "efibootmgr")
    (version "14")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/rhinstaller/" name
                                  "/releases/download/" version "/" name
                                  "-" version ".tar.bz2"))
              (sha256
               (base32
                "1n3sydvpr6yl040hhf460k7mrxby7laqd9dqs6pq0js1hijc2zip"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; No tests.
       #:make-flags (list (string-append "prefix=" %output)
                          (string-append "libdir=" %output "/lib")
                          ;; Override CFLAGS to add efivar include directory.
                          (string-append "CFLAGS=-O2 -g -flto -I"
                                         (assoc-ref %build-inputs "efivar")
                                         "/include/efivar"))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'branding
           ;; Replace default loader path with something more familiar.
           (lambda _
             (substitute* "src/efibootmgr.c"
               (("EFI\\\\\\\\redhat") ; Matches 'EFI\\redhat'.
                "EFI\\\\gnu"))
             #t))
         (delete 'configure))))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("efivar" ,efivar)
       ("popt" ,popt)))
    (home-page "https://github.com/rhinstaller/efibootmgr")
    (synopsis "Modify the Extensible Firmware Interface (EFI) boot manager")
    (description
     "@code{efibootmgr} is a user-space application to modify the Intel
Extensible Firmware Interface (EFI) Boot Manager.  This application can
create and destroy boot entries, change the boot order, change the next
running boot option, and more.")
    (license license:gpl2+)))
