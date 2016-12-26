;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
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

(define-module (gnu packages qemu)
  #:use-module (gnu packages)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages attr)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages check)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages cyrus-sasl)
  #:use-module (gnu packages disk)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages image)
  #:use-module (gnu packages libusb)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages polkit)
  #:use-module (gnu packages python)
  #:use-module (gnu packages sdl)
  #:use-module (gnu packages spice)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages web)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xml)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system python)
  #:use-module (guix download)
  #:use-module ((guix licenses) #:select (gpl2 gpl2+ lgpl2.1+))
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (srfi srfi-1))

(define (qemu-patch commit file-name sha256)
  "Return an origin for COMMIT."
  (origin
    (method url-fetch)
    (uri (string-append
          "http://git.qemu.org/?p=qemu.git;a=commitdiff_plain;h="
          commit))
    (sha256 sha256)
    (file-name file-name)))

(define-public qemu
  (package
    (name "qemu")
    (version "2.8.0")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://wiki.qemu-project.org/download/qemu-"
                                 version ".tar.bz2"))
             (sha256
              (base32
               "0qjy3rcrn89n42y5iz60kgr0rrl29hpnj8mq2yvbc1wrcizmvzfs"))))
    (build-system gnu-build-system)
    (arguments
     '(;; Running tests in parallel can occasionally lead to failures, like:
       ;; boot_sector_test: assertion failed (signature == SIGNATURE): (0x00000000 == 0x0000dead)
       #:parallel-tests? #f

       #:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key inputs outputs (configure-flags '())
                           #:allow-other-keys)
             ;; The `configure' script doesn't understand some of the
             ;; GNU options.  Thus, add a new phase that's compatible.
             (let ((out (assoc-ref outputs "out")))
               (setenv "SHELL" (which "bash"))

               ;; While we're at it, patch for tests.
               (substitute* "tests/libqtest.c"
                 (("/bin/sh") (which "sh")))

               ;; The binaries need to be linked against -lrt.
               (setenv "LDFLAGS" "-lrt")
               (zero?
                (apply system*
                       `("./configure"
                         ,(string-append "--cc=" (which "gcc"))
                         ;; Some architectures insist on using HOST_CC
                         ,(string-append "--host-cc=" (which "gcc"))
                         "--disable-debug-info" ; save build space
                         "--enable-virtfs"      ; just to be sure
                         ,(string-append "--prefix=" out)
                         ,@configure-flags))))))
         (add-after 'install 'install-info
           (lambda* (#:key inputs outputs #:allow-other-keys)
             ;; Install the Info manual, unless Texinfo is missing.
             (or (not (assoc-ref inputs "texinfo"))
                 (let ((out (assoc-ref outputs "out")))
                   (and (zero? (system* "make" "info"))
                        (let ((infodir (string-append out "/share/info")))
                          (for-each (lambda (info)
                                      (install-file info infodir))
                                    (find-files "." "\\.info"))
                          #t))))))
         (add-before 'check 'make-gtester-verbose
           (lambda _
             ;; Make GTester verbose to facilitate investigation upon failure.
             (setenv "V" "1") #t))
         (add-before 'check 'disable-test-qga
           (lambda _
             (substitute* "tests/Makefile.include"
               ;; Comment out the test-qga test, which needs /sys and
               ;; fails within the build environment.
               (("check-unit-.* tests/test-qga" all)
                (string-append "# " all)))
             #t)))))
    (inputs                                       ; TODO: Add optional inputs.
     `(("alsa-lib" ,alsa-lib)
       ("attr" ,attr)
       ("glib" ,glib)
       ;; ("libaio" ,libaio)
       ("libattr" ,attr)
       ("libcap" ,libcap)           ; virtfs support requires libcap & libattr
       ("libjpeg" ,libjpeg-8)
       ("libpng" ,libpng)
       ("libusb" ,libusb)                         ;USB pass-through support
       ("mesa" ,mesa)
       ("ncurses" ,ncurses)
       ;; ("pciutils" ,pciutils)
       ("pixman" ,pixman)
       ("sdl" ,sdl)
       ("spice" ,spice)
       ("util-linux" ,util-linux)
       ;; ("vde2" ,vde2)
       ("virglrenderer" ,virglrenderer)
       ("zlib" ,zlib)))
    (native-inputs `(("glib:bin" ,glib "bin") ; gtester, etc.
                     ("perl" ,perl)
                     ("pkg-config" ,pkg-config)
                     ("python" ,python-2) ; incompatible with Python 3 according to error message
                     ("texinfo" ,texinfo)))
    (home-page "http://www.qemu-project.org")
    (synopsis "Machine emulator and virtualizer")
    (description
     "QEMU is a generic machine emulator and virtualizer.

When used as a machine emulator, QEMU can run OSes and programs made for one
machine (e.g. an ARM board) on a different machine---e.g., your own PC.  By
using dynamic translation, it achieves very good performance.

When used as a virtualizer, QEMU achieves near native performances by
executing the guest code directly on the host CPU.  QEMU supports
virtualization when executing under the Xen hypervisor or using
the KVM kernel module in Linux.  When using KVM, QEMU can virtualize x86,
server and embedded PowerPC, and S390 guests.")

    ;; Many files are GPLv2+, but some are GPLv2-only---e.g., `memory.c'.
    (license gpl2)

    ;; Several tests fail on MIPS; see <http://hydra.gnu.org/build/117914>.
    (supported-systems (delete "mips64el-linux" %supported-systems))))

(define-public qemu-minimal
  ;; QEMU without GUI support.
  (package (inherit qemu)
    (name "qemu-minimal")
    (synopsis "Machine emulator and virtualizer (without GUI)")
    (arguments
     `(#:configure-flags
       ;; Restrict to the targets supported by Guix.
       '("--target-list=i386-softmmu,x86_64-softmmu,mips64el-softmmu,arm-softmmu")
       ,@(package-arguments qemu)))

    ;; Remove dependencies on optional libraries, notably GUI libraries.
    (inputs (fold alist-delete (package-inputs qemu)
                  '("libusb" "mesa" "sdl" "spice" "virglrenderer")))))

(define-public libosinfo
  (package
    (name "libosinfo")
    (version "0.3.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://fedorahosted.org/releases/l/i/libosinfo/libosinfo-"
                           version ".tar.gz"))
       (sha256
        (base32
         "151qrzmafxww5yfamrr7phk8217xmihfhazpb597vdv87na75cjh"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'copy-ids
           (lambda* (#:key inputs #:allow-other-keys)
             (copy-file (assoc-ref inputs "pci.ids") "data/pci.ids")
             (copy-file (assoc-ref inputs "usb.ids") "data/usb.ids")
             #t)))))
    (inputs
     `(("libsoup" ,libsoup)
       ("libxml2" ,libxml2)
       ("libxslt" ,libxslt)
       ("gobject-introspection" ,gobject-introspection)))
    (native-inputs
     `(("check" ,check)
       ("glib" ,glib "bin")  ; glib-mkenums, etc.
       ("gtk-doc" ,gtk-doc)
       ("vala" ,vala)
       ("intltool" ,intltool)
       ("pkg-config" ,pkg-config)
       ("pci.ids"
        ,(origin
           (method url-fetch)
           (uri "https://raw.githubusercontent.com/pciutils/pciids/f9477789526f9d380bc57aa92e357c521738d5dd/pci.ids")
           (sha256
            (base32
             "0g6dbwlamagxqxvng67xng3w2x56c0np4md1v1p1jn32qw518az0"))))
       ("usb.ids"
        ,(origin
           (method url-fetch)
           (uri "http://linux-usb.cvs.sourceforge.net/viewvc/linux-usb/htdocs/usb.ids?revision=1.539")
           (sha256
            (base32
             "0w9ila7662lzpx416lqy69zx6gfwq2xiigwd5fdyqcrg3dj07m80"))))))
    (home-page "https://libosinfo.org/")
    (synopsis "Operating system information database")
    (description "libosinfo is a GObject based library API for managing
information about operating systems, hypervisors and the (virtual) hardware
devices they can support.  It includes a database containing device metadata
and provides APIs to match/identify optimal devices for deploying an operating
system on a hypervisor.  Via GObject Introspection, the API is available in
all common programming languages.  Vala bindings are also provided.")
    ;; The library files are released under LGPLv2.1 or later; the source
    ;; files in the "tools" directory are released under GPLv2+.
    (license (list lgpl2.1+ gpl2+))))

(define-public libvirt
  (package
    (name "libvirt")
    (version "2.1.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://libvirt.org/sources/libvirt-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "0sriasjc573c519yqw1hcfb3qqjcsm9hm8vayw0anwkl6di9ay8s"))))
    (build-system gnu-build-system)
    (arguments
     `(;; FAIL: virshtest
       ;; FAIL: virfirewalltest
       ;; FAIL: virkmodtest
       ;; FAIL: virnetsockettest
       ;; FAIL: networkxml2firewalltest
       ;; FAIL: nwfilterebiptablestest
       ;; FAIL: nwfilterxml2firewalltest
       ;; Times out after PASS: virsh-vcpupin
       #:tests? #f
       #:configure-flags
       (list "--with-polkit"
             "--localstatedir=/var")
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-tests
           (lambda _
             (substitute* '("tests/commandtest.c"
                            "gnulib/tests/test-posix_spawn1.c"
                            "gnulib/tests/test-posix_spawn2.c")
               (("/bin/sh") (which "sh")))
             #t))
         (add-after 'unpack 'do-not-mkdir-in-/var
           ;; Since the localstatedir should be /var at runtime, we must
           ;; prevent writing to /var at installation time.
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out           (assoc-ref outputs "out"))
                    (localstatedir (string-append out "/var")))
               (substitute* '("src/Makefile.in"
                              "daemon/Makefile.in")
                 (("\\$\\(DESTDIR\\)\\$\\(localstatedir)") localstatedir)))
             #t)))))
    (inputs
     `(("libxml2" ,libxml2)
       ("gnutls" ,gnutls)
       ("dbus" ,dbus)
       ("qemu" ,qemu)
       ("polkit" ,polkit)
       ("libpcap" ,libpcap)
       ("libnl" ,libnl)
       ("libuuid" ,util-linux)
       ("lvm2" ,lvm2) ; for libdevmapper
       ("curl" ,curl)
       ("openssl" ,openssl)
       ("cyrus-sasl" ,cyrus-sasl)
       ("perl" ,perl)
       ("python" ,python-2)
       ("libyajl" ,libyajl)
       ("audit" ,audit)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://libvirt.org")
    (synopsis "Simple API for virtualization")
    (description "Libvirt is a C toolkit to interact with the virtualization
capabilities of recent versions of Linux.  The library aims at providing long
term stable C API initially for the Xen paravirtualization but should be able
to integrate other virtualization mechanisms if needed.")
    (license lgpl2.1+)))

(define-public libvirt-glib
  (package
    (name "libvirt-glib")
    (version "0.2.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "ftp://libvirt.org/libvirt/glib/"
                                  "libvirt-glib-" version ".tar.gz"))
              (sha256
               (base32
                "1pahj8qa7k2307sd57rwqwq1hijya02v0sxk91hl3cw48niimcf3"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-tests
           (lambda _
             (substitute* "tests/test-events.c"
               (("/bin/true") (which "true")))
             #t)))))
    (inputs
     `(("libxml2" ,libxml2)
       ("libvirt" ,libvirt)
       ("gobject-introspection" ,gobject-introspection)
       ("glib" ,glib)
       ("openssl" ,openssl)
       ("cyrus-sasl" ,cyrus-sasl)
       ("lvm2" ,lvm2) ; for libdevmapper
       ("libyajl" ,libyajl)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("intltool" ,intltool)
       ("glib" ,glib "bin")
       ("vala" ,vala)))
    (home-page "http://libvirt.org")
    (synopsis "GLib wrapper around libvirt")
    (description "libvirt-glib wraps the libvirt library to provide a
high-level object-oriented API better suited for glib-based applications, via
three libraries:

@enumerate
@item libvirt-glib - GLib main loop integration & misc helper APIs
@item libvirt-gconfig - GObjects for manipulating libvirt XML documents
@item libvirt-gobject - GObjects for managing libvirt objects
@end enumerate
")
    (license lgpl2.1+)))

(define-public python-libvirt
  (package
    (name "python-libvirt")
    (version "2.0.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "libvirt-python" version))
              (sha256
               (base32
                "0h0x5lpsx97bvw20pzfcsdmmivximddq4qmn8fk0n55dqv0wn5kq"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-nosetests-path
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "setup.py"
               (("sys.executable, \"/usr/bin/nosetests\"")
                (string-append "\"" (which "bash") "\", \""
                               (which "nosetests") "\"")))
             #t)))))
    (inputs
     `(("libvirt" ,libvirt)))
    (propagated-inputs
     `(("python-lxml" ,python-lxml)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("python-nose" ,python-nose)))
    (home-page "http://libvirt.org")
    (synopsis "Python bindings to libvirt")
    (description "This package provides Python bindings to the libvirt
virtualization library.")
    (license lgpl2.1+)))

(define-public python2-libvirt
  (package-with-python2 python-libvirt))

(define-public virt-manager
  (package
    (name "virt-manager")
    (version "1.4.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://virt-manager.org/download/sources"
                                  "/virt-manager/virt-manager-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1jnawqjmcqd2db78ngx05x7cxxn3iy1sb4qfgbwcn045qh6a8cdz"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:use-setuptools? #f ; Uses custom distutils 'install' command.
       ;; Some of the tests seem to require network access to install virtual
       ;; machines.
       #:tests? #f
       #:modules ((ice-9 match)
                  (srfi srfi-26)
                  (guix build python-build-system)
                  (guix build utils))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-setup
           (lambda* (#:key outputs #:allow-other-keys)
             (substitute* "virtcli/cliconfig.py"
               (("/usr") (assoc-ref outputs "out")))
             #t))
         (add-before 'wrap 'wrap-with-GI_TYPELIB_PATH
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((bin       (string-append (assoc-ref outputs "out") "/bin"))
                    (bin-files (find-files bin ".*"))
                    (paths     (map (match-lambda
                                      ((output . directory)
                                       (let* ((girepodir (string-append
                                                          directory
                                                          "/lib/girepository-1.0")))
                                         (if (file-exists? girepodir)
                                             girepodir #f))))
                                    inputs)))
               (for-each (lambda (file)
                           (format #t "wrapping ~a\n" file)
                           (wrap-program file
                             `("GI_TYPELIB_PATH" ":" prefix
                               ,(filter identity paths))))
                         bin-files))
             #t)))))
    (inputs
     `(("gtk+" ,gtk+)
       ("libvirt" ,libvirt)
       ("libvirt-glib" ,libvirt-glib)
       ("libosinfo" ,libosinfo)
       ("gobject-introspection" ,gobject-introspection)
       ("python2-libvirt" ,python2-libvirt)
       ("python2-requests" ,python2-requests)
       ("python2-ipaddr" ,python2-ipaddr)
       ("python2-pygobject" ,python2-pygobject)
       ("python2-libxml2" ,python2-libxml2)))
    ;; virt-manager searches for qemu-img or kvm-img in the PATH.
    (propagated-inputs
     `(("qemu" ,qemu)))
    (native-inputs
     `(("glib" ,glib "bin")             ; glib-compile-schemas.
       ("gtk+" ,gtk+ "bin")             ; gtk-update-icon-cache
       ("perl" ,perl)                   ; pod2man
       ("intltool" ,intltool)))
    (home-page "https://virt-manager.org/")
    (synopsis "Manage virtual machines")
    (description
     "The virt-manager application is a desktop user interface for managing
virtual machines through libvirt.  It primarily targets KVM VMs, but also
manages Xen and LXC (Linux containers).  It presents a summary view of running
domains, their live performance and resource utilization statistics.")
    (license gpl2+)))
