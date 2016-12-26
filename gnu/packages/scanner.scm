;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 John Darrington <jmd@gnu.org>
;;; Copyright © 2015 Andy Wingo <wingo@igalia.com>
;;; Copyright © 2016 Andy Patterson <ajpatter@uwaterloo.ca>
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

(define-module (gnu packages scanner)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages libusb)
  #:use-module ((guix licenses)
                #:prefix licence:))

(define-public sane-backends-minimal
  (package
    (name "sane-backends-minimal")
    (version "1.0.25")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "https://alioth.debian.org/frs/download.php/file/4146/"
                   "sane-backends-" version ".tar.gz"))
             (sha256
              (base32
               "0b3fvhrxl4l82bf3v0j47ypjv6a0k5lqbgknrq1agpmjca6vmmx4"))
             (modules '((guix build utils)))
             (snippet
              ;; Generated HTML files and udev rules normally embed a
              ;; timestamp.  Work around that to build things reproducibly.
              '(substitute* "tools/sane-desc.c"
                 (("asctime \\(localtime \\(&current_time\\)\\)")
                  "\"1970-01-01\"")))))
    (build-system gnu-build-system)
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("libusb-compat" ,libusb-compat)))
    (arguments
     `(#:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'disable-backends
           (lambda _
             (setenv "BACKENDS" " ")
             #t))
         (add-after
          'install 'install-udev-rules
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((out (assoc-ref outputs "out")))
              (mkdir-p (string-append out "/lib/udev/rules.d"))
              (copy-file "tools/udev/libsane.rules"
                         (string-append out
                                        "/lib/udev/rules.d/"
                                        "60-libsane.rules"))))))))
    ;; It would seem that tests are not maintained - fails with
    ;; the following:
    ;;
    ;; < This page was last updated on Wed Jul 31 07:52:48 2013
    ;; <  by sane-desc 3.5 from sane-backends 1.0.24git
    ;; ---
    ;; > This page was last updated on Sun Oct 19 15:41:39 2014
    ;; >  by sane-desc 3.5 from sane-backends 1.0.24
    ;; **** File generated for html-backends-split mode is different from reference
    ;; Makefile:501: recipe for target 'check.local' failed
    (home-page "http://www.sane-project.org")
    (synopsis
     "Raster image scanner library and drivers, without scanner support")
    (description "SANE stands for \"Scanner Access Now Easy\" and is an API
proving access to any raster image scanner hardware (flatbed scanner,
hand-held scanner, video- and still-cameras, frame-grabbers, etc.).  The
package contains the library, but no drivers.")
    (license licence:gpl2+))) ; plus linking exception

;; This variant links in the hpaio backend, provided by hplip, which adds
;; support for HP scanners whose backends are not maintained by
;; 'sane-backends'. It also builds all of those backends.
(define-public sane-backends
  (package
    (inherit sane-backends-minimal)
    (name "sane-backends")
    (inputs
     `(("hplip" ,(@ (gnu packages cups) hplip))
       ,@(package-inputs sane-backends-minimal)))
    (arguments
     (substitute-keyword-arguments (package-arguments sane-backends-minimal)
       ((#:phases phases)
        `(modify-phases ,phases
           (delete 'disable-backends)
           (add-after 'unpack 'add-backends
             (lambda _
               (substitute* "backend/dll.conf.in"
                 (("hp5590" all) (format #f "~a~%~a" all "hpaio")))
               #t))
           (add-after 'install 'install-hpaio
             (lambda* (#:key inputs outputs #:allow-other-keys)
               (define hplip (string-append (assoc-ref inputs "hplip")
                                            "/lib/sane"))
               (define out (string-append (assoc-ref outputs "out")
                                          "/lib/sane"))
               (for-each
                (lambda (file)
                  (symlink file (string-append out "/" (basename file))))
                (find-files hplip))
               #t))))))
    (synopsis
     "Raster image scanner library and drivers, with scanner support")
    (description "SANE stands for \"Scanner Access Now Easy\" and is an API
proving access to any raster image scanner hardware (flatbed scanner,
hand-held scanner, video- and still-cameras, frame-grabbers, etc.).  The
package contains the library and drivers.")))
