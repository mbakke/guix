;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Christopher Allan Webber <cwebber@dustycloud.org>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
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

(define-module (gnu system vm)
  #:use-module (guix config)
  #:use-module (guix store)
  #:use-module (guix gexp)
  #:use-module (guix derivations)
  #:use-module (guix packages)
  #:use-module (guix monads)
  #:use-module (guix records)

  #:use-module ((gnu build vm)
                #:select (qemu-command))
  #:use-module (gnu packages base)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages gawk)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages less)
  #:use-module (gnu packages qemu)
  #:use-module (gnu packages disk)
  #:use-module (gnu packages zile)
  #:use-module (gnu packages grub)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages package-management)
  #:use-module ((gnu packages make-bootstrap)
                #:select (%guile-static-stripped))
  #:use-module (gnu packages admin)

  #:use-module (gnu system shadow)
  #:use-module (gnu system pam)
  #:use-module (gnu system linux-initrd)
  #:use-module (gnu system grub)
  #:use-module (gnu system file-systems)
  #:use-module (gnu system)
  #:use-module (gnu services)

  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)

  #:export (expression->derivation-in-linux-vm
            qemu-image
            virtualized-operating-system
            system-qemu-image

            system-qemu-image/shared-store
            system-qemu-image/shared-store-script
            system-disk-image))


;;; Commentary:
;;;
;;; Tools to evaluate build expressions within virtual machines.
;;;
;;; Code:

(define %linux-vm-file-systems
  ;; File systems mounted for 'derivation-in-linux-vm'.  The store and /xchg
  ;; directory are shared with the host over 9p.
  (list (file-system
          (mount-point (%store-prefix))
          (device "store")
          (type "9p")
          (needed-for-boot? #t)
          (options "trans=virtio")
          (check? #f))
        (file-system
          (mount-point "/xchg")
          (device "xchg")
          (type "9p")
          (needed-for-boot? #t)
          (options "trans=virtio")
          (check? #f))))

(define %vm-module-closure
  ;; The closure of (gnu build vm), roughly.
  ;; FIXME: Compute it automatically.
  '((gnu build vm)
    (gnu build install)
    (gnu build linux-boot)
    (gnu build linux-modules)
    (gnu build file-systems)
    (guix elf)
    (guix records)
    (guix build utils)
    (guix build syscalls)
    (guix build bournish)
    (guix build store-copy)))

(define* (expression->derivation-in-linux-vm name exp
                                             #:key
                                             (system (%current-system))
                                             (linux linux-libre)
                                             initrd
                                             (qemu qemu-minimal)
                                             (env-vars '())
                                             (guile-for-build
                                              (%guile-for-build))

                                             (make-disk-image? #f)
                                             (references-graphs #f)
                                             (memory-size 256)
                                             (disk-image-format "qcow2")
                                             (disk-image-size
                                              (* 100 (expt 2 20))))
  "Evaluate EXP in a QEMU virtual machine running LINUX with INITRD (a
derivation).  In the virtual machine, EXP has access to all its inputs from the
store; it should put its output files in the `/xchg' directory, which is
copied to the derivation's output when the VM terminates.  The virtual machine
runs with MEMORY-SIZE MiB of memory.

When MAKE-DISK-IMAGE? is true, then create a QEMU disk image of type
DISK-IMAGE-FORMAT (e.g., 'qcow2' or 'raw'), of DISK-IMAGE-SIZE bytes and
return it.

When REFERENCES-GRAPHS is true, it must be a list of file name/store path
pairs, as for `derivation'.  The files containing the reference graphs are
made available under the /xchg CIFS share."
  (mlet* %store-monad
      ((user-builder (gexp->file "builder-in-linux-vm" exp))
       (loader       (gexp->file "linux-vm-loader"
                                 #~(primitive-load #$user-builder)))
       (coreutils -> (canonical-package coreutils))
       (initrd       (if initrd                   ; use the default initrd?
                         (return initrd)
                         (base-initrd %linux-vm-file-systems
                                      #:linux linux
                                      #:virtio? #t
                                      #:qemu-networking? #t))))

    (define builder
      ;; Code that launches the VM that evaluates EXP.
      (with-imported-modules %vm-module-closure
        #~(begin
            (use-modules (guix build utils)
                         (gnu build vm))

            (let ((inputs  '#$(list qemu coreutils))
                  (linux   (string-append #$linux "/bzImage"))
                  (initrd  (string-append #$initrd "/initrd"))
                  (loader  #$loader)
                  (graphs  '#$(match references-graphs
                                (((graph-files . _) ...) graph-files)
                                (_ #f))))

              (set-path-environment-variable "PATH" '("bin") inputs)

              (load-in-linux-vm loader
                                #:output #$output
                                #:linux linux #:initrd initrd
                                #:memory-size #$memory-size
                                #:make-disk-image? #$make-disk-image?
                                #:disk-image-format #$disk-image-format
                                #:disk-image-size #$disk-image-size
                                #:references-graphs graphs)))))

    (gexp->derivation name builder
                      ;; TODO: Require the "kvm" feature.
                      #:system system
                      #:env-vars env-vars
                      #:guile-for-build guile-for-build
                      #:references-graphs references-graphs)))

(define* (qemu-image #:key
                     (name "qemu-image")
                     (system (%current-system))
                     (qemu qemu-minimal)
                     (disk-image-size (* 100 (expt 2 20)))
                     (disk-image-format "qcow2")
                     (file-system-type "ext4")
                     file-system-label
                     os-derivation
                     grub-configuration
                     (register-closures? #t)
                     (inputs '())
                     copy-inputs?)
  "Return a bootable, stand-alone QEMU image of type DISK-IMAGE-FORMAT (e.g.,
'qcow2' or 'raw'), with a root partition of type FILE-SYSTEM-TYPE.
Optionally, FILE-SYSTEM-LABEL can be specified as the volume name for the root
partition.  The returned image is a full disk image that runs OS-DERIVATION,
with a GRUB installation that uses GRUB-CONFIGURATION as its configuration
file (GRUB-CONFIGURATION must be the name of a file in the VM.)

INPUTS is a list of inputs (as for packages).  When COPY-INPUTS? is true, copy
all of INPUTS into the image being built.  When REGISTER-CLOSURES? is true,
register INPUTS in the store database of the image so that Guix can be used in
the image."
  (expression->derivation-in-linux-vm
   name
   (with-imported-modules %vm-module-closure
     #~(begin
         (use-modules (gnu build vm)
                      (guix build utils))

         (let ((inputs
                '#$(append (list qemu parted grub e2fsprogs)
                           (map canonical-package
                                (list sed grep coreutils findutils gawk))
                           (if register-closures? (list guix) '())))

               ;; This variable is unused but allows us to add INPUTS-TO-COPY
               ;; as inputs.
               (to-register
                '#$(map (match-lambda
                          ((name thing) thing)
                          ((name thing output) `(,thing ,output)))
                        inputs)))

           (set-path-environment-variable "PATH" '("bin" "sbin") inputs)

           (let* ((graphs     '#$(match inputs
                                   (((names . _) ...)
                                    names)))
                  (initialize (root-partition-initializer
                               #:closures graphs
                               #:copy-closures? #$copy-inputs?
                               #:register-closures? #$register-closures?
                               #:system-directory #$os-derivation))
                  (partitions (list (partition
                                     (size #$(- disk-image-size
                                                (* 10 (expt 2 20))))
                                     (label #$file-system-label)
                                     (file-system #$file-system-type)
                                     (bootable? #t)
                                     (initializer initialize)))))
             (initialize-hard-disk "/dev/vda"
                                   #:partitions partitions
                                   #:grub.cfg #$grub-configuration)
             (reboot)))))
   #:system system
   #:make-disk-image? #t
   #:disk-image-size disk-image-size
   #:disk-image-format disk-image-format
   #:references-graphs inputs))


;;;
;;; VM and disk images.
;;;

(define* (system-disk-image os
                            #:key
                            (name "disk-image")
                            (file-system-type "ext4")
                            (disk-image-size (* 900 (expt 2 20)))
                            (volatile? #t))
  "Return the derivation of a disk image of DISK-IMAGE-SIZE bytes of the
system described by OS.  Said image can be copied on a USB stick as is.  When
VOLATILE? is true, the root file system is made volatile; this is useful
to USB sticks meant to be read-only."
  (define root-label
    ;; Volume name of the root file system.  Since we don't know which device
    ;; will hold it, we use the volume name to find it (using the UUID would
    ;; be even better, but somewhat less convenient.)
    "gnu-disk-image")

  (define file-systems-to-keep
    (remove (lambda (fs)
              (string=? (file-system-mount-point fs) "/"))
            (operating-system-file-systems os)))

  (let ((os (operating-system (inherit os)
              ;; Since this is meant to be used on real hardware, don't
              ;; install QEMU networking or anything like that.  Assume USB
              ;; mass storage devices (usb-storage.ko) are available.
              (initrd (lambda (file-systems . rest)
                        (apply base-initrd file-systems
                               #:volatile-root? #t
                               rest)))

              ;; Force our own root file system.
              (file-systems (cons (file-system
                                    (mount-point "/")
                                    (device root-label)
                                    (title 'label)
                                    (type file-system-type))
                                  file-systems-to-keep)))))

    (mlet* %store-monad ((os-drv   (operating-system-derivation os))
                         (grub.cfg (operating-system-grub.cfg os)))
      (qemu-image #:name name
                  #:os-derivation os-drv
                  #:grub-configuration grub.cfg
                  #:disk-image-size disk-image-size
                  #:disk-image-format "raw"
                  #:file-system-type file-system-type
                  #:file-system-label root-label
                  #:copy-inputs? #t
                  #:register-closures? #t
                  #:inputs `(("system" ,os-drv)
                             ("grub.cfg" ,grub.cfg))))))

(define* (system-qemu-image os
                            #:key
                            (file-system-type "ext4")
                            (disk-image-size (* 900 (expt 2 20))))
  "Return the derivation of a freestanding QEMU image of DISK-IMAGE-SIZE bytes
of the GNU system as described by OS."
  (define file-systems-to-keep
    ;; Keep only file systems other than root and not normally bound to real
    ;; devices.
    (remove (lambda (fs)
              (let ((target (file-system-mount-point fs))
                    (source (file-system-device fs)))
                (or (string=? target "/")
                    (string-prefix? "/dev/" source))))
            (operating-system-file-systems os)))

  (let ((os (operating-system (inherit os)
              ;; Use an initrd with the whole QEMU shebang.
              (initrd (lambda (file-systems . rest)
                        (apply base-initrd file-systems
                               #:virtio? #t
                               #:qemu-networking? #t
                               rest)))

              ;; Force our own root file system.
              (file-systems (cons (file-system
                                    (mount-point "/")
                                    (device "/dev/sda1")
                                    (type file-system-type))
                                  file-systems-to-keep)))))
    (mlet* %store-monad
        ((os-drv      (operating-system-derivation os))
         (grub.cfg    (operating-system-grub.cfg os)))
      (qemu-image  #:os-derivation os-drv
                   #:grub-configuration grub.cfg
                   #:disk-image-size disk-image-size
                   #:file-system-type file-system-type
                   #:inputs `(("system" ,os-drv)
                              ("grub.cfg" ,grub.cfg))
                   #:copy-inputs? #t))))


;;;
;;; VMs that share file systems with the host.
;;;

(define (file-system->mount-tag fs)
  "Return a 9p mount tag for host file system FS."
  ;; QEMU mount tags cannot contain slashes and cannot start with '_'.
  ;; Compute an identifier that corresponds to the rules.
  (string-append "TAG"
                 (string-map (match-lambda
                              (#\/ #\_)
                              (chr chr))
                             fs)))

(define (mapping->file-system mapping)
  "Return a 9p file system that realizes MAPPING."
  (match mapping
    (($ <file-system-mapping> source target writable?)
     (file-system
       (mount-point target)
       (device (file-system->mount-tag source))
       (type "9p")
       (flags (if writable? '() '(read-only)))
       (options (string-append "trans=virtio"))
       (check? #f)
       (create-mount-point? #t)))))

(define (virtualized-operating-system os mappings)
  "Return an operating system based on OS suitable for use in a virtualized
environment with the store shared with the host.  MAPPINGS is a list of
<file-system-mapping> to realize in the virtualized OS."
  (define user-file-systems
    ;; Remove file systems that conflict with those added below, or that are
    ;; normally bound to real devices.
    (remove (lambda (fs)
              (let ((target (file-system-mount-point fs))
                    (source (file-system-device fs)))
                (or (string=? target (%store-prefix))
                    (string=? target "/")
                    (and (eq? 'device (file-system-title fs))
                         (string-prefix? "/dev/" source)))))
            (operating-system-file-systems os)))

  (operating-system (inherit os)
    (initrd (lambda (file-systems . rest)
              (apply base-initrd file-systems
                     #:volatile-root? #t
                     #:virtio? #t
                     #:qemu-networking? #t
                     rest)))

    ;; Disable swap.
    (swap-devices '())

    (file-systems (cons* (file-system
                           (mount-point "/")
                           (device "/dev/vda1")
                           (type "ext4"))

                         (file-system (inherit
                                       (mapping->file-system %store-mapping))
                            (needed-for-boot? #t))

                         (append (map mapping->file-system mappings)
                                 user-file-systems)))))

(define* (system-qemu-image/shared-store
          os
          #:key
          full-boot?
          (disk-image-size (* (if full-boot? 500 30) (expt 2 20))))
  "Return a derivation that builds a QEMU image of OS that shares its store
with the host.

When FULL-BOOT? is true, return an image that does a complete boot sequence,
bootloaded included; thus, make a disk image that contains everything the
bootloader refers to: OS kernel, initrd, bootloader data, etc."
  (mlet* %store-monad ((os-drv   (operating-system-derivation os))
                       (grub.cfg (operating-system-grub.cfg os)))
    ;; XXX: When FULL-BOOT? is true, we end up creating an image that contains
    ;; GRUB.CFG and all its dependencies, including the output of OS-DRV.
    ;; This is more than needed (we only need the kernel, initrd, GRUB for its
    ;; font, and the background image), but it's hard to filter that.
    (qemu-image #:os-derivation os-drv
                #:grub-configuration grub.cfg
                #:disk-image-size disk-image-size
                #:inputs (if full-boot?
                             `(("grub.cfg" ,grub.cfg))
                             '())

                ;; XXX: Passing #t here is too slow, so let it off by default.
                #:register-closures? #f
                #:copy-inputs? full-boot?)))

(define* (common-qemu-options image shared-fs)
  "Return the a string-value gexp with the common QEMU options to boot IMAGE,
with '-virtfs' options for the host file systems listed in SHARED-FS."
  (define (virtfs-option fs)
    #~(string-append "-virtfs local,path=\"" #$fs
                     "\",security_model=none,mount_tag=\""
                     #$(file-system->mount-tag fs)
                     "\" "))

  #~(string-append
     ;; Only enable kvm if we see /dev/kvm exists.
     ;; This allows users without hardware virtualization to still use these
     ;; commands.
     #$(if (file-exists? "/dev/kvm")
           " -enable-kvm "
           "")
     " -no-reboot -net nic,model=virtio \
  " #$@(map virtfs-option shared-fs) " \
  -net user \
  -vga std \
  -drive file=" #$image
  ",if=virtio,cache=writeback,werror=report,readonly \
  -m 256"))

(define* (system-qemu-image/shared-store-script os
                                                #:key
                                                (qemu qemu)
                                                (graphic? #t)
                                                (mappings '())
                                                full-boot?
                                                (disk-image-size
                                                 (* (if full-boot? 500 30)
                                                    (expt 2 20))))
  "Return a derivation that builds a script to run a virtual machine image of
OS that shares its store with the host.

MAPPINGS is a list of <file-system-mapping> specifying mapping of host file
systems into the guest.

When FULL-BOOT? is true, the returned script runs everything starting from the
bootloader; otherwise it directly starts the operating system kernel.  The
DISK-IMAGE-SIZE parameter specifies the size in bytes of the root disk image;
it is mostly useful when FULL-BOOT?  is true."
  (mlet* %store-monad ((os ->  (virtualized-operating-system os mappings))
                       (os-drv (operating-system-derivation os))
                       (image  (system-qemu-image/shared-store
                                os
                                #:full-boot? full-boot?
                                #:disk-image-size disk-image-size)))
    (define builder
      #~(call-with-output-file #$output
          (lambda (port)
            (display
             (string-append "#!" #$bash "/bin/sh
exec " #$qemu "/bin/" #$(qemu-command (%current-system))

#$@(if full-boot?
       #~()
       #~(" -kernel " #$(operating-system-kernel os) "/bzImage \
            -initrd " #$os-drv "/initrd \
            -append \"" #$(if graphic? "" "console=ttyS0 ")
            "--system=" #$os-drv " --load=" #$os-drv "/boot --root=/dev/vda1 "
            (string-join (list #+@(operating-system-kernel-arguments os))) "\" "))
#$(common-qemu-options image
                       (map file-system-mapping-source
                            (cons %store-mapping mappings)))
" \"$@\"\n")
             port)
            (chmod port #o555))))

    (gexp->derivation "run-vm.sh" builder)))

;;; vm.scm ends here
