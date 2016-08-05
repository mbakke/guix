;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014 Manolis Fragkiskos Ragkousis <manolis837@gmail.com>
;;; Copyright © 2016 Hartmut Goebel <h.goebel@crazy-compilers.com>
;;; Copyright © 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu packages flashing-tools)
  #:use-module (guix licenses)
  #:use-module (guix download)
  #:use-module (guix packages)
  #:use-module (gnu packages)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages elf)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages libusb)
  #:use-module (gnu packages libftdi)
  #:use-module (gnu packages pciutils)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages admin))

(define-public flashrom
  (package
    (name "flashrom")
    (version "0.9.7")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://download.flashrom.org/releases/flashrom-"
                    version ".tar.bz2"))
              (sha256
               (base32
                "1s9pc4yls2s1gcg2ar4q75nym2z5v6lxq36bl6lq26br00nj2mas"))
              (patches (search-patches "flashrom-use-libftdi1.patch"))))
    (build-system gnu-build-system)
    (inputs `(("dmidecode" ,dmidecode)
              ("pciutils" ,pciutils)
              ("libusb" ,libusb)
              ("libftdi" ,libftdi)))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (arguments
     '(#:make-flags (list "CC=gcc" (string-append "PREFIX=" %output))
       #:tests? #f   ; no 'check' target
       #:phases
       (alist-delete
        'configure
        (alist-cons-before
         'build 'patch-exec-paths
         (lambda* (#:key inputs #:allow-other-keys)
           (substitute* "dmi.c"
             (("\"dmidecode\"")
              (format #f "~S"
                      (string-append (assoc-ref inputs "dmidecode")
                                     "/sbin/dmidecode")))))
         %standard-phases))))
    (home-page "http://flashrom.org/")
    (synopsis "Identify, read, write, erase, and verify ROM/flash chips")
    (description
     "flashrom is a utility for identifying, reading, writing,
verifying and erasing flash chips.  It is designed to flash
BIOS/EFI/coreboot/firmware/optionROM images on mainboards,
network/graphics/storage controller cards, and various other
programmer devices.")
    (license gpl2)))

(define-public avrdude
  (package
    (name "avrdude")
    (version "6.1")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://savannah/avrdude/avrdude-"
                          version ".tar.gz"))
      (sha256
       (base32
        "0frxg0q09nrm95z7ymzddx7ysl77ilfbdix1m81d9jjpiv5bm64y"))))
    (build-system gnu-build-system)
    (inputs
     `(("libelf" ,libelf)
       ("libusb" ,libusb-compat)
       ("libftdi" ,libftdi)))
    (native-inputs
     `(("bison" ,bison)
       ("flex" ,flex)))
    (home-page "http://www.nongnu.org/avrdude/")
    (synopsis "AVR downloader and uploader")
    (description
     "AVRDUDE is a utility to download/upload/manipulate the ROM and
EEPROM contents of AVR microcontrollers using the in-system programming
technique (ISP).")
    (license gpl2+)))

(define-public dfu-programmer
  (package
    (name "dfu-programmer")
    (version "0.7.2")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://sourceforge/dfu-programmer/dfu-programmer/"
                          version "/dfu-programmer-" version ".tar.gz"))
      (sha256
       (base32
        "15gr99y1z9vbvhrkd25zqhnzhg6zjmaam3vfjzf2mazd39mx7d0x"))
      (patches (search-patches "dfu-programmer-fix-libusb.patch"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("libusb" ,libusb)))
    (home-page "http://dfu-programmer.github.io/")
    (synopsis "Device firmware update programmer for Atmel chips")
    (description
     "Dfu-programmer is a multi-platform command-line programmer for
Atmel (8051, AVR, XMEGA & AVR32) chips with a USB bootloader supporting
ISP.")
    (license gpl2+)))

(define-public dfu-util
  (package
    (name "dfu-util")
    (version "0.9")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://dfu-util.sourceforge.net/releases/dfu-util-"
                    version ".tar.gz"))
              (sha256
               (base32
                "0czq73m92ngf30asdzrfkzraag95hlrr74imbanqq25kdim8qhin"))))
    (build-system gnu-build-system)
    (inputs
     `(("libusb" ,libusb)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (synopsis "Host side of the USB Device Firmware Upgrade (DFU) protocol")
    (description
     "The DFU (Universal Serial Bus Device Firmware Upgrade) protocol is
intended to download and upload firmware to devices connected over USB.  It
ranges from small devices like micro-controller boards up to mobile phones.
With dfu-util you are able to download firmware to your device or upload
firmware from it.")
    (home-page "http://dfu-util.sourceforge.net/")
    (license gpl2+)))

(define-public teensy-loader-cli
  ;; The repo does not tag versions nor does it use releases, but a commit
  ;; message says "Importing 2.1", while the sourcce still says "2.0". So pin
  ;; to a fixed commit.
  (let ((commit "f289b7a2e5627464044249f0e5742830e052e360"))
    (package
      (name "teensy-loader-cli")
      (version (string-append "2.1-1." (string-take commit 7)))
      (source
       (origin
         (method url-fetch)
         (uri (string-append "https://github.com/PaulStoffregen/"
                             "teensy_loader_cli/archive/" commit ".tar.gz"))
         (sha256 (base32 "17wqc2q4fa473cy7f5m2yiyb9nq0qw7xal2kzrxzaikgm9rabsw8"))
         (file-name (string-append "teensy-loader-cli-" version ".tar.gz" ))
         (modules '((guix build utils)))
         (snippet
          `(begin
             ;; Remove example flash files and teensy rebooter flash binaries.
             (for-each delete-file (find-files "." "\\.(elf|hex)$"))
             ;; Fix the version
             (substitute* "teensy_loader_cli.c"
               (("Teensy Loader, Command Line, Version 2.0\\\\n")
                (string-append "Teensy Loader, Command Line, " ,version "\\n")))
             #t))
       (patches (search-patches "teensy-loader-cli-help.patch"))))
      (build-system gnu-build-system)
      (arguments
       '(#:tests? #f ;; Makefile has no test target
         #:make-flags (list "CC=gcc" (string-append "PREFIX=" %output))
         #:phases
         (modify-phases %standard-phases
           (delete 'configure)
           (replace 'install
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out"))
                      (bin (string-append out "/bin")))
                 (install-file "teensy_loader_cli" bin)
                 #t))))))
      (inputs
       `(("libusb-compat" ,libusb-compat)))
      (synopsis "Command line firmware uploader for Teensy development boards")
      (description
       "The Teensy loader program communicates with your Teensy board when the
HalfKay bootloader is running, so you can upload new programs and run them.

You need to add the udev rules to make the Teensy update available for
non-root users.")
      (home-page "https://www.pjrc.com/teensy/loader_cli.html")
      (license gpl3))))
