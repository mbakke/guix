;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2015 Mathieu Lirzin <mthl@gnu.org>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 Tobias Geerinckx-Rice <me@tobias.gr>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Jan Nieuwenhuizen <janneke@gnu.org>
;;; Copyright © 2016 Roel Janssen <roel@gnu.org>
;;; Copyright © 2016 Marius Bakke <mbakke@fastmail.com>
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

(define-module (gnu packages disk)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (gnu packages)
  #:use-module (gnu packages base)
  #:use-module (gnu packages docbook)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages popt)
  #:use-module (gnu packages python)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages xml))

(define-public parted
  (package
    (name "parted")
    (version "3.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/parted/parted-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "1r3qpg3bhz37mgvp9chsaa3k0csby3vayfvz8ggsqz194af5i2w5"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after
          'unpack 'fix-locales-and-python
          (lambda* (#:key inputs #:allow-other-keys)
            (substitute* "tests/t0251-gpt-unicode.sh"
              (("C.UTF-8") "en_US.utf8")) ;not in Glibc locales
            (substitute* "tests/msdos-overlap"
              (("/usr/bin/python") (which "python"))))))))
    (inputs
     `(("lvm2" ,lvm2)
       ("readline" ,readline)
       ("util-linux" ,util-linux)))
    (native-inputs
     `(("gettext" ,gettext-minimal)
       ;; For the tests.
       ("perl" ,perl)
       ("python" ,python-2)))
    (home-page "https://www.gnu.org/software/parted/")
    (synopsis "Disk partition editor")
    (description
     "GNU Parted is a package for creating and manipulating disk partition
tables.  It includes a library and command-line utility.")
    (license license:gpl3+)))

(define-public fdisk
  (package
    (name "fdisk")
    (version "2.0.0a")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/fdisk/gnufdisk-"
                          version ".tar.gz"))
      (sha256
       (base32
        "04nd7civ561x2lwcmxhsqbprml3178jfc58fy1v7hzqg5k4nbhy3"))))
    (build-system gnu-build-system)
    (inputs
     `(("gettext" ,gettext-minimal)
       ("guile" ,guile-1.8)
       ("util-linux" ,util-linux)
       ("parted" ,parted)))
    (home-page "https://www.gnu.org/software/fdisk/")
    (synopsis "Low-level disk partitioning and formatting")
    (description
     "GNU fdisk provides a GNU version of the common disk partitioning tool
fdisk.  fdisk is used for the creation and manipulation of disk partition
tables, and it understands a variety of different formats.")
    (license license:gpl3+)))

(define-public gptfdisk
  (package
    (name "gptfdisk")
    (version "1.0.1")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://sourceforge/gptfdisk/gptfdisk/"
                          version "/" name "-" version ".tar.gz"))
      (sha256
       (base32
        "1izazbyv5n2d81qdym77i8mg9m870hiydmq4d0s51npx5vp8lk46"))))
    (build-system gnu-build-system)
    (inputs
     `(("gettext" ,gettext-minimal)
       ("ncurses" ,ncurses)
       ("popt" ,popt)
       ("util-linux" ,util-linux))) ; libuuid
    (arguments
     `(#:test-target "test"
       #:phases
       (modify-phases %standard-phases
         ;; no configure script
         (delete 'configure)
         ;; no install target
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((bin (string-append (assoc-ref outputs "out") "/bin")))
               (install-file "gdisk" bin)
               (install-file "sgdisk" bin)
               (install-file "cgdisk" bin)
               (install-file "fixparts" bin)))))))
    (home-page "http://www.rodsbooks.com/gdisk/")
    (synopsis "Low-level GPT disk partitioning and formatting")
    (description "GPT fdisk (aka gdisk) is a text-mode partitioning tool that
works on Globally Unique Identifier (GUID) Partition Table (GPT) disks, rather
than on the more common (through 2009) Master Boot Record (MBR) partition
tables.")
    (license license:gpl2)))

(define-public ddrescue
  (package
    (name "ddrescue")
    (version "1.21")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/ddrescue/ddrescue-"
                          version ".tar.lz"))
      (sha256
       (base32
        "1b71hb42lh33y9843nd1mxlwkk9qh9ajvnz6ivzd1jq9lav4x7ph"))))
    (build-system gnu-build-system)
    (home-page "http://www.gnu.org/software/ddrescue/ddrescue.html")
    (synopsis "Data recovery utility")
    (native-inputs `(("lzip" ,lzip)))
    (description
     "GNU ddrescue is a fully automated data recovery tool.  It copies data
from one file to another, working to rescue data in case of read errors.  The
program also includes a tool for manipulating its log files, which are used
to recover data more efficiently by only reading the necessary blocks.")
    (license license:gpl3+)))

(define-public dosfstools
  (package
    (name "dosfstools")
    (version "4.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/" name "/" name
                           "/releases/download/v" version "/"
                           name "-" version ".tar.xz"))
       (sha256
        (base32
         "1bvxbv1w6vhbx0nx7ygp700wq5k2hjv0hm7w0kz1x7amaf4p6dwh"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags (list (string-append "PREFIX=" %output)
                          "CC=gcc")
       #:tests? #f))  ;no tests
    (home-page "https://github.com/dosfstools/dosfstools")
    (synopsis "Utilities for making and checking MS-DOS FAT file systems")
    (description
     "The dosfstools package includes the mkfs.fat and fsck.fat utilities,
which respectively make and check MS-DOS FAT file systems.")
    (license license:gpl3+)))

(define dosfstools/static
  (static-package
   (package (inherit dosfstools))))

(define-public fatfsck/static
  (package
    (name "fatfsck-static")
    (version (package-version dosfstools))
    (build-system trivial-build-system)
    (source #f)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (let ((src (string-append (assoc-ref %build-inputs "dosfstools")
                                   "/sbin"))
               (exe "fsck.fat")
               (bin (string-append (assoc-ref %outputs "out") "/sbin")))
           (mkdir-p bin)
           (with-directory-excursion bin
             (copy-file (string-append src "/" exe) exe)
             (remove-store-references exe)
             (chmod exe #o555)
             ;; Add fsck.vfat symlink to match the Linux driver name.
             (symlink exe "fsck.vfat")
             #t)))))
    (inputs `(("dosfstools" ,dosfstools/static)))
    (home-page (package-home-page dosfstools))
    (synopsis "Statically linked fsck.fat from dosfstools")
    (description "This package provides a statically-linked @command{fsck.fat}
and a @command{fsck.vfat} compatibility symlink for use in an initrd.")
    (license (package-license dosfstools))))

(define-public sdparm
  (package
    (name "sdparm")
    (version "1.09")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://sg.danny.cz/sg/p/"
                           name "-" version ".tar.xz"))
       (sha256
        (base32
         "0jakqyjwi72zqjzss04bally0xl0lc4710mx8da08vpmir1hfphg"))))
    (build-system gnu-build-system)
    (home-page "http://sg.danny.cz/sg/sdparm.html")
    (synopsis "Provide access to SCSI device parameters")
    (description
     "Sdparm reads and modifies SCSI device parameters.  These devices can be
SCSI disks, in which case the role of @command{sdparm} is similar to its
namesake: the @command{hdparm} utility originally designed for ATA disks.
However, @command{sdparm} can be used to access parameters on any device that
uses a SCSI command set.  Such devices include CD/DVD drives (irrespective of
transport), SCSI and ATAPI tape drives, and SCSI enclosures.  This utility can
also send commands associated with starting and stopping the media, loading
and unloading removable media and some other housekeeping functions.")
    (license license:bsd-3)))

(define-public idle3-tools
  (package
    (name "idle3-tools")
    (version "0.9.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/idle3-tools/idle3-tools-"
                           version ".tgz"))
       (sha256
        (base32
         "00ia7xq9yldxyl9gz0mr4xa568nav14p0fnv82f2rbbkg060cy4p"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ;no test suite
       #:phases
       (modify-phases %standard-phases
         (delete 'configure))
       #:make-flags (list "CC=gcc"
                          (string-append "manprefix=")
                          (string-append "DESTDIR="
                                         (assoc-ref %outputs "out")))))
    (home-page "http://idle3-tools.sourceforge.net")
    (synopsis "Change or disable Western Digital hard drives' Idle3 timer")
    (description
     "Idle3-tools provides a utility to get, set, or disable the Idle3 timer
present in many Western Digital hard drives.  This timer is part of the
\"IntelliPark\" feature that stops the disk when not in use.  Unfortunately,
the default timer setting is not well suited to Linux or other *nix systems,
and can dramatically shorten the lifespan of the drive if left unchecked.")
    (license license:gpl3+)))

(define-public gparted
  (package
    (name "gparted")
    (version "0.27.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/gparted/gparted/gparted-"
                           version "/gparted-" version ".tar.gz"))
       (sha256
        (base32 "1gg7k63jd6128mmzciwqmgixqhyqnninimaqyvjbx1hv0q6gd310"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; Tests require a network connection.
       #:configure-flags '("--disable-scrollkeeper")))
    (inputs
     `(("util-linux" ,util-linux)
       ("parted" ,parted)
       ("glib" ,glib)
       ("gtkmm" ,gtkmm-2)
       ("libxml2" ,libxml2)
       ("libxslt" ,libxslt)
       ("gnome-doc-utils" ,gnome-doc-utils)
       ("docbook-xml" ,docbook-xml-4.2)
       ("python" ,python-2)
       ("python-libxml2" ,python2-libxml2)
       ("which" ,which)))
    (native-inputs
     `(("intltool" ,intltool)
       ("pkg-config" ,pkg-config)))
    (home-page "https://sourceforge.net/projects/gparted/")
    (synopsis "Partition editor to graphically manage disk partitions")
    (description "GParted is a GNOME partition editor for creating,
reorganizing, and deleting disk partitions.  It uses libparted from the parted
project to detect and manipulate partition tables.  Optional file system tools
permit managing file systems not included in libparted.")
    ;; The home page says GPLv2, but the source code says GPLv2+.
    (license license:gpl2+)))
