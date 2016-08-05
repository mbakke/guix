;;; GNU Guix --- Functional package management for GNU
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

(define-module (gnu tests install)
  #:use-module (gnu)
  #:use-module (gnu tests)
  #:use-module (gnu tests base)
  #:use-module (gnu system)
  #:use-module (gnu system install)
  #:use-module (gnu system vm)
  #:use-module ((gnu build vm) #:select (qemu-command))
  #:use-module (gnu packages qemu)
  #:use-module (gnu packages package-management)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix packages)
  #:use-module (guix grafts)
  #:use-module (guix gexp)
  #:use-module (guix utils)
  #:export (%test-installed-os
            %test-encrypted-os))

;;; Commentary:
;;;
;;; Test the installation of GuixSD using the documented approach at the
;;; command line.
;;;
;;; Code:

(define-os-with-source (%minimal-os %minimal-os-source)
  ;; The OS we want to install.
  (use-modules (gnu) (gnu tests) (srfi srfi-1))

  (operating-system
    (host-name "liberigilo")
    (timezone "Europe/Paris")
    (locale "en_US.UTF-8")

    (bootloader (grub-configuration (device "/dev/vdb")))
    (kernel-arguments '("console=ttyS0"))
    (file-systems (cons (file-system
                          (device "my-root")
                          (title 'label)
                          (mount-point "/")
                          (type "ext4"))
                        %base-file-systems))
    (users (cons (user-account
                  (name "alice")
                  (comment "Bob's sister")
                  (group "users")
                  (supplementary-groups '("wheel" "audio" "video"))
                  (home-directory "/home/alice"))
                 %base-user-accounts))
    (services (cons (service marionette-service-type
                             (marionette-configuration
                              (imported-modules '((gnu services herd)
                                                  (guix combinators)))))
                    %base-services))))

(define (operating-system-with-current-guix os)
  "Return a variant of OS that uses the current Guix."
  (operating-system
    (inherit os)
    (services (modify-services (operating-system-user-services os)
                (guix-service-type config =>
                                   (guix-configuration
                                    (inherit config)
                                    (guix (current-guix))))))))

(define (operating-system-with-gc-roots os roots)
  "Return a variant of OS where ROOTS are registered as GC roots."
  (operating-system
    (inherit os)
    (services (cons (service gc-root-service-type roots)
                    (operating-system-user-services os)))))


(define MiB (expt 2 20))

(define %simple-installation-script
  ;; Shell script of a simple installation.
  "\
. /etc/profile
set -e -x
guix --version

export GUIX_BUILD_OPTIONS=--no-grafts
guix build isc-dhcp
parted --script /dev/vdb mklabel gpt \\
  mkpart primary ext2 1M 3M \\
  mkpart primary ext2 3M 1G \\
  set 1 boot on \\
  set 1 bios_grub on
mkfs.ext4 -L my-root /dev/vdb2
mount /dev/vdb2 /mnt
df -h /mnt
herd start cow-store /mnt
mkdir /mnt/etc
cp /etc/target-config.scm /mnt/etc/config.scm
guix system init /mnt/etc/config.scm /mnt --no-substitutes
sync
reboot\n")

(define* (run-install target-os target-os-source
                      #:key
                      (script %simple-installation-script)
                      (os (marionette-operating-system
                           ;; Since the image has no network access, use the
                           ;; current Guix so the store items we need are in
                           ;; the image.
                           (operating-system
                             (inherit (operating-system-with-current-guix
                                       installation-os))
                             (kernel-arguments '("console=ttyS0")))
                           #:imported-modules '((gnu services herd)
                                                (guix combinators))))
                      (target-size (* 1200 MiB)))
  "Run SCRIPT (a shell script following the GuixSD installation procedure) in
OS to install TARGET-OS.  Return a VM image of TARGET-SIZE bytes containing
the installed system."

  (mlet* %store-monad ((_      (set-grafting #f))
                       (system (current-system))
                       (target (operating-system-derivation target-os))

                       ;; Since the installation system has no network access,
                       ;; we cheat a little bit by adding TARGET to its GC
                       ;; roots.  This way, we know 'guix system init' will
                       ;; succeed.
                       (image  (system-disk-image
                                (operating-system-with-gc-roots
                                 os (list target))
                                #:disk-image-size (* 1500 MiB))))
    (define install
      (with-imported-modules '((guix build utils)
                               (gnu build marionette))
        #~(begin
            (use-modules (guix build utils)
                         (gnu build marionette))

            (set-path-environment-variable "PATH" '("bin")
                                           (list #$qemu-minimal))

            (system* "qemu-img" "create" "-f" "qcow2"
                     #$output #$(number->string target-size))

            (define marionette
              (make-marionette
               (cons (which #$(qemu-command system))
                     (cons* "-no-reboot" "-m" "800"
                            "-drive"
                            (string-append "file=" #$image
                                           ",if=virtio,readonly")
                            "-drive"
                            (string-append "file=" #$output ",if=virtio")
                            (if (file-exists? "/dev/kvm")
                                '("-enable-kvm")
                                '())))))

            (pk 'uname (marionette-eval '(uname) marionette))

            ;; Wait for tty1.
            (marionette-eval '(begin
                                (use-modules (gnu services herd))
                                (start 'term-tty1))
                             marionette)

            (marionette-eval '(call-with-output-file "/etc/target-config.scm"
                                (lambda (port)
                                  (write '#$target-os-source port)))
                             marionette)

            (exit (marionette-eval '(zero? (system #$script))
                                   marionette)))))

    (gexp->derivation "installation" install)))

(define (qemu-command/writable-image image)
  "Return as a monadic value the command to run QEMU on a writable copy of
IMAGE, a disk image."
  (mlet %store-monad ((system (current-system)))
    (return #~(let ((image #$image))
                ;; First we need a writable copy of the image.
                (format #t "copying image '~a'...~%" image)
                (copy-file image "disk.img")
                (chmod "disk.img" #o644)
                `(,(string-append #$qemu-minimal "/bin/"
                                  #$(qemu-command system))
                  ,@(if (file-exists? "/dev/kvm")
                        '("-enable-kvm")
                        '())
                  "-no-reboot" "-m" "256"
                  "-drive" "file=disk.img,if=virtio")))))


(define %test-installed-os
  (system-test
   (name "installed-os")
   (description
    "Test basic functionality of an OS installed like one would do by hand.
This test is expensive in terms of CPU and storage usage since we need to
build (current-guix) and then store a couple of full system images.")
   (value
    (mlet* %store-monad ((image   (run-install %minimal-os %minimal-os-source))
                         (command (qemu-command/writable-image image)))
      (run-basic-test %minimal-os command
                      "installed-os")))))


(define-os-with-source (%encrypted-root-os %encrypted-root-os-source)
  ;; The OS we want to install.
  (use-modules (gnu) (gnu tests) (srfi srfi-1))

  (operating-system
    (host-name "liberigilo")
    (timezone "Europe/Paris")
    (locale "en_US.UTF-8")

    (bootloader (grub-configuration (device "/dev/vdb")))
    (kernel-arguments '("console=ttyS0"))
    (file-systems (cons (file-system
                          (device "/dev/mapper/the-root-device")
                          (title 'device)
                          (mount-point "/")
                          (type "ext4"))
                        %base-file-systems))
    (mapped-devices (list (mapped-device
                           (source "REPLACE-WITH-LUKS-UUID")
                           (target "the-root-device")
                           (type luks-device-mapping))))
    (users (cons (user-account
                  (name "charlie")
                  (group "users")
                  (home-directory "/home/charlie")
                  (supplementary-groups '("wheel" "audio" "video")))
                 %base-user-accounts))
    (services (cons (service marionette-service-type
                             (marionette-configuration
                              (imported-modules '((gnu services herd)
                                                  (guix combinators)))))
                    %base-services))))

(define %encrypted-root-installation-script
  ;; Shell script of a simple installation.
  "\
. /etc/profile
set -e -x
guix --version

export GUIX_BUILD_OPTIONS=--no-grafts
ls -l /run/current-system/gc-roots
parted --script /dev/vdb mklabel gpt \\
  mkpart primary ext2 1M 3M \\
  mkpart primary ext2 3M 1G \\
  set 1 boot on \\
  set 1 bios_grub on
echo -n thepassphrase | cryptsetup luksFormat -q /dev/vdb2 -
echo -n thepassphrase | \\
  cryptsetup open --type luks --key-file - /dev/vdb2 the-root-device
mkfs.ext4 -L my-root /dev/mapper/the-root-device
mount LABEL=my-root /mnt
herd start cow-store /mnt
mkdir /mnt/etc
cp /etc/target-config.scm /mnt/etc/config.scm
cat /mnt/etc/config
luks_uuid=`cryptsetup luksUUID /dev/vdb2`
sed -i /mnt/etc/config.scm \\
    -e \"s/\\\"REPLACE-WITH-LUKS-UUID\\\"/(uuid \\\"$luks_uuid\\\")/g\"
guix system build /mnt/etc/config.scm
guix system init /mnt/etc/config.scm /mnt --no-substitutes
sync
reboot\n")

(define %test-encrypted-os
  (system-test
   (name "encrypted-root-os")
   (description
    "Test basic functionality of an OS installed like one would do by hand.
This test is expensive in terms of CPU and storage usage since we need to
build (current-guix) and then store a couple of full system images.")
   (value
    (mlet* %store-monad ((image   (run-install %encrypted-root-os
                                               %encrypted-root-os-source
                                               #:script
                                               %encrypted-root-installation-script))
                         (command (qemu-command/writable-image image)))
      (run-basic-test %encrypted-root-os command "encrypted-root-os")))))

;;; install.scm ends here
