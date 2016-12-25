;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015, 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Danny Milosavljevic <dannym@scratchpost.org>
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

(define-module (gnu packages cups)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages avahi)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages libusb)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages python)
  #:use-module (gnu packages scanner)
  #:use-module (gnu packages image)
  #:use-module (gnu packages fonts) ;font-dejavu
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages pdf)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages tls))

;; Delay to avoid module circularity problems.
(define ghostscript/cups
  (delay
    (package (inherit ghostscript)
      (name "ghostscript-with-cups")
      (inputs `(("cups" ,cups-minimal)
                ,@(package-inputs ghostscript))))))

(define-public cups-filters
  (package
    (name "cups-filters")
    (version "1.13.1")
    (source(origin
              (method url-fetch)
              (uri
               (string-append "http://openprinting.org/download/cups-filters/"
                              "cups-filters-" version ".tar.xz"))
              (sha256
               (base32
                "0s7hylp2lcvc1vrqpywpv7lspkrh4xf7cyi4nbg10cf38rshj474"))
              (modules '((guix build utils)))
              (snippet
               ;; install backends, banners and filters to cups-filters output
               ;; directory, not the cups server directory
               '(begin
                  (substitute* "Makefile.in"
                    (("CUPS_DATADIR = @CUPS_DATADIR@")
                     "CUPS_DATADIR = $(PREFIX)/share/cups")
                    (("pkgcupsserverrootdir = \\$\\(CUPS_SERVERROOT\\)")
                     "pkgcupsserverrootdir = $(PREFIX)")
                    ;; Choose standard directories notably so that binaries are
                    ;; stripped.
                    (("pkgbackenddir = \\$\\(CUPS_SERVERBIN\\)/backend")
                     "pkgbackenddir = $(PREFIX)/lib/cups/backend")
                    (("pkgfilterdir = \\$\\(CUPS_SERVERBIN\\)/filter")
                     "pkgfilterdir = $(PREFIX)/lib/cups/filter"))
                  ;; Find bannertopdf data such as the print test page in our
                  ;; output directory, not CUPS's prefix.
                  (substitute* "configure"
                    (("\\{CUPS_DATADIR\\}/data")
                     "{prefix}/share/cups/data"))))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags (list (string-append "PREFIX=" %output))
       #:configure-flags
       `("--disable-driverless" ; TODO: enable this
         ,(string-append "--with-test-font-path="
                         (assoc-ref %build-inputs "font-dejavu")
                         "/share/fonts/truetype/DejaVuSans.ttf")
         ,(string-append "--with-gs-path="
                         (assoc-ref %build-inputs "ghostscript")
                         "/bin/gsc")
         ,(string-append "--with-shell="
                         (assoc-ref %build-inputs "bash")
                         "/bin/bash")
         ,(string-append "--with-rcdir="
                         (assoc-ref %outputs "out") "/etc/rc.d"))))
    (native-inputs
     `(("glib" ,glib "bin") ; for gdbus-codegen
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("avahi"        ,avahi)
       ("fontconfig"   ,fontconfig)
       ("freetype"     ,freetype)
       ("font-dejavu"  ,font-dejavu) ; also needed by test suite
       ("ghostscript"  ,(force ghostscript/cups))
       ("ijs"          ,ijs)
       ("dbus"         ,dbus)
       ("lcms"         ,lcms)
       ("libjpeg"      ,libjpeg)
       ("libpng"       ,libpng)
       ("libtiff"      ,libtiff)
       ("mupdf"        ,mupdf)
       ("glib"         ,glib)
       ("qpdf"         ,qpdf)
       ("poppler"      ,poppler)
       ("cups-minimal" ,cups-minimal)))
    (home-page "https://wiki.linuxfoundation.org/openprinting/cups-filters")
    (synopsis "OpenPrinting CUPS filters and backends")
    (description
     "Contains backends, filters, and other software that was once part of the
core CUPS distribution but is no longer maintained by Apple Inc.  In addition
it contains additional filters developed independently of Apple, especially
filters for the PDF-centric printing workflow introduced by OpenPrinting.")
    ;; Different filters and backends have different licenses; see COPYING for
    ;; details
    (license (list license:gpl2
                   license:gpl2+
                   license:gpl3
                   license:gpl3+
                   license:lgpl2.0+
                   license:expat))))

;; CUPS on non-MacOS systems requires cups-filters.  Since cups-filters also
;; depends on CUPS libraries and binaries, cups-minimal has been added to
;; satisfy this dependency.
(define-public cups-minimal
  (package
    (name "cups-minimal")
    (version "2.2.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/apple/cups/releases/download/v"
                           version "/cups-" version "-source.tar.gz"))
       (sha256
        (base32
         "1m8rwhbk0l8n19iwm51r2569jj15d0x6mpqhfig0bk3pm4577f43"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags
       '("--disable-launchd"
         "--disable-systemd"
         "--disable-avahi"
         "--disable-dnssd")
       ;; Seven tests fail, mostly because of files that are provided by the
       ;; cups-filters package.
       #:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'patch-makedefs
           (lambda _
             (substitute* "Makedefs.in"
               (("INITDIR.*=.*@INITDIR@") "INITDIR = @prefix@/@INITDIR@")
               (("/bin/sh") (which "sh")))))
         (add-before 'build 'patch-tests
           (lambda _
             (substitute* "test/ippserver.c"
               (("#  else /\\* HAVE_AVAHI \\*/")
                "#elif defined(HAVE_AVAHI)")))))))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("zlib"  ,zlib)
       ("gnutls" ,gnutls)))
    (home-page "https://www.cups.org")
    (synopsis "The Common Unix Printing System")
    (description
     "CUPS is a printing system that uses the Internet Printing
Protocol (IPP).  It provides System V and BSD command-line interfaces, as well
as a Web interface and a C programming interface to manage printers and print
jobs.  It supports printing to both local (parallel, serial, USB) and
networked printers, and printers can be shared from one computer to another.
Internally, CUPS uses PostScript Printer Description (PPD) files to describe
printer capabilities and features and a wide variety of generic and
device-specific programs to convert and print many types of files.")
    (license license:gpl2)))

(define-public cups
  (package (inherit cups-minimal)
    (name "cups")
    (arguments
     `(;; Three tests fail:
       ;; * two tests in ipp-1.1.test related to "RFC 2911 section 3.2.6:
       ;;   Get-Jobs Operation"
       ;; * test of number of error/warning messages, probably related to a
       ;;   missing font.
       #:tests? #f
       #:configure-flags
       '("--disable-launchd"
         "--disable-systemd")
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'patch-makedefs
           (lambda _
             (substitute* "Makedefs.in"
               (("INITDIR.*=.*@INITDIR@") "INITDIR = @prefix@/@INITDIR@")
               (("/bin/sh") (which "sh")))))
         (add-before 'check 'patch-tests
           (lambda _
             (let ((filters (assoc-ref %build-inputs "cups-filters"))
                   (catpath (string-append
                             (assoc-ref %build-inputs "coreutils") "/bin/"))
                   (testdir (string-append (getcwd) "/tmp/")))
               (mkdir testdir)
               (substitute* "test/run-stp-tests.sh"
                 ((" *BASE=/tmp/") (string-append "BASE=" testdir))

                 ;; allow installation of filters from output dir and from
                 ;; cups-filters
                 (("for dir in /usr/libexec/cups/filter /usr/lib/cups/filter")
                  (string-append
                   "for dir in "
                   (assoc-ref %outputs "out") "/lib/cups/filter "
                   filters "/lib/cups/filter"))

                 ;; check for charsets in cups-filters output
                 (("/usr/share/cups/charsets")
                  (string-append filters "/share/cups/charsets"))

                 ;; install additional required filters
                 (("instfilter texttopdf texttopdf pdf")
                  (string-append
                   "instfilter texttopdf texttopdf pdf;"
                   "instfilter imagetoraster imagetoraster raster;"
                   "instfilter gstoraster gstoraster raster;"
                   "instfilter urftopdf urftopdf pdf;"
                   "instfilter rastertopdf rastertopdf pdf;"
                   "instfilter pstopdf pstopdf pdf"))

                 ;; specify location of lpstat binary
                 (("description=\"`lpstat -l")
                  "description=\"`../systemv/lpstat -l")

                 ;; patch shebangs of embedded scripts
                 (("#!/bin/sh") (string-append "#!" (which "sh")))

                 ;; also link mime definitions from cups-filters
                 ;; to enable the additional filters for the test suite
                 (("ln -s \\$root/conf/mime\\.types")
                  (string-append
                   "ln -s " filters
                   "/share/cups/mime/cupsfilters.types $BASE/share/mime; "
                   "ln -s $root/conf/mime.types"))
                 (("ln -s \\$root/conf/mime\\.convs")
                  (string-append
                   "ln -s " filters
                   "/share/cups/mime/cupsfilters.convs $BASE/share/mime; "
                   "ln -s $root/conf/mime.convs")))

               ;; fix search path for "cat"
               (substitute* "cups/testfile.c"
                 (("cupsFileFind\\(\"cat\", \"/bin\"")
                  (string-append "cupsFileFind(\"cat\", \"" catpath "\""))
                 (("cupsFileFind\\(\"cat\", \"/bin:/usr/bin\"")
                  (string-append "cupsFileFind(\"cat\", \"" catpath "\""))))))
         (add-after 'install 'install-cups-filters-symlinks
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out"))
                   (cups-filters (assoc-ref inputs "cups-filters")))
               ;; charsets
               (symlink
                (string-append cups-filters "/share/cups/charsets")
                (string-append out "/share/charsets"))

               ;; mime types, driver file, ppds
               (for-each
                (lambda (f)
                  (symlink (string-append cups-filters f)
                           (string-append out f)))
                '("/share/cups/mime/cupsfilters.types"
                  "/share/cups/mime/cupsfilters.convs"
                  "/share/cups/drv/cupsfilters.drv"
                  "/share/ppd"))

               ;; filters
               (for-each
                (lambda (f)
                  (symlink f
                           (string-append out "/lib/cups/filter" (basename f))))
                (find-files (string-append cups-filters "/lib/cups/filter")))

               ;; backends
               (for-each
                (lambda (f)
                  (symlink (string-append cups-filters f)
                           (string-append out "/lib/cups/backend/"
                                          (basename f))))
                '("/lib/cups/backend/parallel"
                  "/lib/cups/backend/serial"))

               ;; banners
               (let ((banners "/share/cups/banners"))
                 (delete-file-recursively (string-append out banners))
                 (symlink (string-append cups-filters banners)
                          (string-append out banners)))

               ;; assorted data
               (let ((data "/share/cups/data"))
                 (delete-file-recursively (string-append out data))
                 (symlink (string-append cups-filters data)
                          (string-append out data)))))))))
    (inputs
     `(("avahi" ,avahi)
       ("gnutls" ,gnutls)
       ("cups-filters" ,cups-filters)
       ("zlib"  ,zlib)))))

(define-public hplip
  (package
    (name "hplip")
    (version "3.16.11")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/hplip/hplip/" version
                                  "/hplip-" version ".tar.gz"))
              (sha256
               (base32
                "094vkyr0rjng72m13dgr824cdl7q20x23qjxzih4w7l9njn0rqpn"))))
    (build-system gnu-build-system)
    (home-page "http://hplipopensource.com/")
    (synopsis "HP Printer Drivers")
    (description "Hewlett-Packard Printer Drivers and PPDs.")

    ;; The 'COPYING' file lists directories where each of these 3 licenses
    ;; applies.
    (license (list license:gpl2+ license:bsd-3 license:expat))

    ;; TODO install apparmor profile files eventually.
    (arguments
     `(#:configure-flags
       `("--disable-network-build"
         ,(string-append "--prefix=" (assoc-ref %outputs "out"))
         ,(string-append "--sysconfdir=" (assoc-ref %outputs "out") "/etc")
         ;; Disable until mime.types merging works (FIXME).
         "--disable-fax-build"
         "--enable-hpcups-install"
         "--enable-new-hpcups"
         "--enable-cups_ppd_install"
         "--enable-cups_drv_install"
         ;; TODO add foomatic drv install eventually.
         ;; TODO --enable-policykit eventually.
         ,(string-append "--with-cupsfilterdir="
                         (assoc-ref %outputs "out") "/lib/cups/filter")
         ,(string-append "--with-cupsbackenddir="
                         (assoc-ref %outputs "out") "/lib/cups/backend")
         ,(string-append "--with-icondir="
                         (assoc-ref %outputs "out") "/share/applications")
         ,(string-append "--with-systraydir="
                         (assoc-ref %outputs "out") "/etc/xdg"))

       #:imported-modules ((guix build python-build-system)
                           ,@%gnu-build-system-modules)
       #:modules ((guix build gnu-build-system)
                  (guix build utils)
                  ((guix build python-build-system) #:prefix python:))

       #:phases (modify-phases %standard-phases
                  (add-after 'unpack 'fix-hard-coded-file-names
                    (lambda* (#:key inputs outputs #:allow-other-keys)
                      (let ((out (assoc-ref outputs "out"))
                            ;; FIXME: use merged ppds (I think actually only
                            ;; drvs need to be merged).
                            (cupsdir (assoc-ref inputs "cups-minimal")))
                        (substitute* "base/g.py"
                          (("'/usr/share;[^']*'")
                           (string-append "'" cupsdir "/share'"))
                          (("'/etc/hp/hplip.conf'")
                           (string-append "'" out
                                          "/etc/hp/hplip.conf" "'")))

                        (substitute* "Makefile.in"
                          (("[[:blank:]]check-plugin\\.py[[:blank:]]") " ")
                          ;; FIXME Use beginning-of-word in regexp.
                          (("[[:blank:]]plugin\\.py[[:blank:]]") " ")
                          (("/usr/include/libusb-1.0")
                           (string-append (assoc-ref inputs "libusb")
                                          "/include/libusb-1.0"))
                          (("^\tinstall-dist_hplip_stateDATA")
                           ;; Remove dependencies on
                           ;; 'install-dist_hplip_stateDATA' so we don't bail
                           ;; out while trying to create /var/lib/hplip.
                           "\t")
                          (("hplip_confdir = /etc/hp")
                           ;; This is only used for installing the default config.
                           (string-append "hplip_confdir = " out
                                          "/etc/hp"))
                          (("halpredir = /usr/share/hal/fdi/preprobe/10osvendor")
                           ;; Note: We don't use hal.
                           (string-append "halpredir = " out
                                          "/share/hal/fdi/preprobe/10osvendor"))
                          (("rulesdir = /etc/udev/rules.d")
                           ;; udev rules will be merged by base service.
                           (string-append "rulesdir = " out
                                          "/lib/udev/rules.d"))
                          (("rulessystemdir = /usr/lib/systemd/system")
                           ;; We don't use systemd.
                           (string-append "rulessystemdir = " out
                                          "/lib/systemd/system"))
                          (("/etc/sane.d")
                           (string-append out "/etc/sane.d"))))))

                  ;; Wrap bin/* so that the Python libs are found.
                  (add-after 'install 'wrap-binaries
                    (assoc-ref python:%standard-phases 'wrap)))))

    ;; Python3 support is available starting from hplip@3.15.2.
    (inputs `(("libjpeg" ,libjpeg)
              ("cups-minimal" ,cups-minimal)
              ("libusb" ,libusb)
              ("sane-backends" ,sane-backends)
              ("dbus" ,dbus)
              ("python-wrapper" ,python-wrapper)
              ("python" ,python)
              ;; TODO: Make hp-setup find python-dbus.
              ("python-dbus" ,python-dbus)))
    (native-inputs `(("pkg-config" ,pkg-config)))))
