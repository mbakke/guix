;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu system file-systems)
  #:use-module (ice-9 match)
  #:use-module (guix records)
  #:use-module (guix store)
  #:use-module ((gnu build file-systems)
                #:select (string->uuid uuid->string))
  #:re-export (string->uuid
               uuid->string)
  #:export (<file-system>
            file-system
            file-system?
            file-system-device
            file-system-title
            file-system-mount-point
            file-system-type
            file-system-needed-for-boot?
            file-system-flags
            file-system-options
            file-system-mount?
            file-system-check?
            file-system-create-mount-point?
            file-system-dependencies

            file-system->spec
            specification->file-system-mapping
            uuid

            %fuse-control-file-system
            %binary-format-file-system
            %shared-memory-file-system
            %pseudo-terminal-file-system
            %immutable-store
            %control-groups
            %elogind-file-systems

            %base-file-systems
            %container-file-systems

            <file-system-mapping>
            file-system-mapping
            file-system-mapping?
            file-system-mapping-source
            file-system-mapping-target
            file-system-mapping-writable?

            %store-mapping))

;;; Commentary:
;;;
;;; Declaring file systems to be mounted.
;;;
;;; Code:

;; File system declaration.
(define-record-type* <file-system> file-system
  make-file-system
  file-system?
  (device           file-system-device)           ; string
  (title            file-system-title             ; 'device | 'label | 'uuid
                    (default 'device))
  (mount-point      file-system-mount-point)      ; string
  (type             file-system-type)             ; string
  (flags            file-system-flags             ; list of symbols
                    (default '()))
  (options          file-system-options           ; string or #f
                    (default #f))
  (mount?           file-system-mount?            ; Boolean
                    (default #t))
  (needed-for-boot? %file-system-needed-for-boot? ; Boolean
                    (default #f))
  (check?           file-system-check?            ; Boolean
                    (default #t))
  (create-mount-point? file-system-create-mount-point? ; Boolean
                       (default #f))
  (dependencies     file-system-dependencies      ; list of <file-system>
                    (default '())))               ; or <mapped-device>

(define-inlinable (file-system-needed-for-boot? fs)
  "Return true if FS has the 'needed-for-boot?' flag set, or if it's the root
file system."
  (or (%file-system-needed-for-boot? fs)
      (string=? "/" (file-system-mount-point fs))))

(define (file-system->spec fs)
  "Return a list corresponding to file-system FS that can be passed to the
initrd code."
  (match fs
    (($ <file-system> device title mount-point type flags options _ _ check?)
     (list device title mount-point type flags options check?))))

(define (specification->file-system-mapping spec writable?)
  "Read the SPEC and return the corresponding <file-system-mapping>.  SPEC is
a string of the form \"SOURCE\" or \"SOURCE=TARGET\".  The former specifies
that SOURCE from the host should be mounted at SOURCE in the other system.
The latter format specifies that SOURCE from the host should be mounted at
TARGET in the other system."
  (let ((index (string-index spec #\=)))
    (if index
        (file-system-mapping
         (source (substring spec 0 index))
         (target (substring spec (+ 1 index)))
         (writable? writable?))
        (file-system-mapping
         (source spec)
         (target spec)
         (writable? writable?)))))

(define-syntax uuid
  (lambda (s)
    "Return the bytevector corresponding to the given UUID representation."
    (syntax-case s ()
      ((_ str)
       (string? (syntax->datum #'str))
       ;; A literal string: do the conversion at expansion time.
       (let ((bv (string->uuid (syntax->datum #'str))))
         (unless bv
           (syntax-violation 'uuid "invalid UUID" s))
         (datum->syntax #'str bv)))
      ((_ str)
       #'(string->uuid str)))))


;;;
;;; Common file systems.
;;;

(define %fuse-control-file-system
  ;; Control file system for Linux' file systems in user-space (FUSE).
  (file-system
    (device "fusectl")
    (mount-point "/sys/fs/fuse/connections")
    (type "fusectl")
    (check? #f)))

(define %binary-format-file-system
  ;; Support for arbitrary executable binary format.
  (file-system
    (device "binfmt_misc")
    (mount-point "/proc/sys/fs/binfmt_misc")
    (type "binfmt_misc")
    (check? #f)))

(define %tty-gid
  ;; ID of the 'tty' group.  Allocate it statically to make it easy to refer
  ;; to it from here and from the 'tty' group definitions.
  996)

(define %pseudo-terminal-file-system
  ;; The pseudo-terminal file system.  It needs to be mounted so that
  ;; statfs(2) returns DEVPTS_SUPER_MAGIC like libc's getpt(3) expects (and
  ;; thus openpty(3) and its users, such as xterm.)
  (file-system
    (device "none")
    (mount-point "/dev/pts")
    (type "devpts")
    (check? #f)
    (needed-for-boot? #f)
    (create-mount-point? #t)
    (options (string-append "gid=" (number->string %tty-gid) ",mode=620"))))

(define %shared-memory-file-system
  ;; Shared memory.
  (file-system
    (device "tmpfs")
    (mount-point "/dev/shm")
    (type "tmpfs")
    (check? #f)
    (flags '(no-suid no-dev))
    (options "size=50%")                         ;TODO: make size configurable
    (create-mount-point? #t)))

(define %immutable-store
  ;; Read-only store to avoid users or daemons accidentally modifying it.
  ;; 'guix-daemon' has provisions to remount it read-write in its own name
  ;; space.
  (file-system
    (device (%store-prefix))
    (mount-point (%store-prefix))
    (type "none")
    (check? #f)
    (flags '(read-only bind-mount))))

(define %control-groups
  (let ((parent (file-system
                  (device "cgroup")
                  (mount-point "/sys/fs/cgroup")
                  (type "tmpfs")
                  (check? #f))))
    (cons parent
          (map (lambda (subsystem)
                 (file-system
                   (device "cgroup")
                   (mount-point (string-append "/sys/fs/cgroup/" subsystem))
                   (type "cgroup")
                   (check? #f)
                   (options subsystem)
                   (create-mount-point? #t)

                   ;; This must be mounted after, and unmounted before the
                   ;; parent directory.
                   (dependencies (list parent))))
               '("cpuset" "cpu" "cpuacct" "memory" "devices" "freezer"
                 "blkio" "perf_event" "hugetlb")))))

(define %elogind-file-systems
  ;; We don't use systemd, but these file systems are needed for elogind,
  ;; which was extracted from systemd.
  (list (file-system
          (device "none")
          (mount-point "/run/systemd")
          (type "tmpfs")
          (check? #f)
          (flags '(no-suid no-dev no-exec))
          (options "mode=0755")
          (create-mount-point? #t))
        (file-system
          (device "none")
          (mount-point "/run/user")
          (type "tmpfs")
          (check? #f)
          (flags '(no-suid no-dev no-exec))
          (options "mode=0755")
          (create-mount-point? #t))
        ;; Elogind uses cgroups to organize processes, allowing it to map PIDs
        ;; to sessions.  Elogind's cgroup hierarchy isn't associated with any
        ;; resource controller ("subsystem").
        (file-system
          (device "cgroup")
          (mount-point "/sys/fs/cgroup/elogind")
          (type "cgroup")
          (check? #f)
          (options "none,name=elogind")
          (create-mount-point? #t)
          (dependencies (list (car %control-groups))))))

(define %base-file-systems
  ;; List of basic file systems to be mounted.  Note that /proc and /sys are
  ;; currently mounted by the initrd.
  (append (list %pseudo-terminal-file-system
                %shared-memory-file-system
                %immutable-store)
          %elogind-file-systems
          %control-groups))

;; File systems for Linux containers differ from %base-file-systems in that
;; they impose additional restrictions such as no-exec or need different
;; options to function properly.
;;
;; The file system flags and options conform to the libcontainer
;; specification:
;; https://github.com/docker/libcontainer/blob/master/SPEC.md#filesystem
(define %container-file-systems
  (list
   ;; Pseudo-terminal file system.
   (file-system
     (device "none")
     (mount-point "/dev/pts")
     (type "devpts")
     (flags '(no-exec no-suid))
     (needed-for-boot? #t)
     (create-mount-point? #t)
     (check? #f)
     (options "newinstance,ptmxmode=0666,mode=620"))
   ;; Shared memory file system.
   (file-system
     (device "tmpfs")
     (mount-point "/dev/shm")
     (type "tmpfs")
     (flags '(no-exec no-suid no-dev))
     (options "mode=1777,size=65536k")
     (needed-for-boot? #t)
     (create-mount-point? #t)
     (check? #f))
   ;; Message queue file system.
   (file-system
     (device "mqueue")
     (mount-point "/dev/mqueue")
     (type "mqueue")
     (flags '(no-exec no-suid no-dev))
     (needed-for-boot? #t)
     (create-mount-point? #t)
     (check? #f))))


;;;
;;; Shared file systems, for VMs/containers.
;;;

;; Mapping of host file system SOURCE to mount point TARGET in the guest.
(define-record-type* <file-system-mapping> file-system-mapping
  make-file-system-mapping
  file-system-mapping?
  (source    file-system-mapping-source)          ;string
  (target    file-system-mapping-target)          ;string
  (writable? file-system-mapping-writable?        ;Boolean
             (default #f)))

(define %store-mapping
  ;; Mapping of the host's store into the guest.
  (file-system-mapping
   (source (%store-prefix))
   (target (%store-prefix))
   (writable? #f)))

;;; file-systems.scm ends here
