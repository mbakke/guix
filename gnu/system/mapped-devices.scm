;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Andreas Enge <andreas@enge.fr>
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

(define-module (gnu system mapped-devices)
  #:use-module (guix gexp)
  #:use-module (guix records)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:autoload   (gnu packages cryptsetup) (cryptsetup)
  #:autoload   (gnu packages linux) (mdadm)
  #:use-module (srfi srfi-1)
  #:use-module (ice-9 match)
  #:export (mapped-device
            mapped-device?
            mapped-device-source
            mapped-device-target
            mapped-device-type

            mapped-device-kind
            mapped-device-kind?
            mapped-device-kind-open
            mapped-device-kind-close

            device-mapping-service-type
            device-mapping-service

            luks-device-mapping
            raid-device-mapping))

;;; Commentary:
;;;
;;; This module supports "device mapping", a concept implemented by Linux's
;;; device-mapper.
;;;
;;; Code:

(define-record-type* <mapped-device> mapped-device
  make-mapped-device
  mapped-device?
  (source    mapped-device-source)                ;string
  (target    mapped-device-target)                ;string
  (type      mapped-device-type))                 ;<mapped-device-kind>

(define-record-type* <mapped-device-type> mapped-device-kind
  make-mapped-device-kind
  mapped-device-kind?
  (open      mapped-device-kind-open)             ;source target -> gexp
  (close     mapped-device-kind-close             ;source target -> gexp
             (default (const #~(const #f)))))


;;;
;;; Device mapping as a Shepherd service.
;;;

(define device-mapping-service-type
  (shepherd-service-type
   'device-mapping
   (match-lambda
     (($ <mapped-device> source target
                         ($ <mapped-device-type> open close))
      (shepherd-service
       (provision (list (symbol-append 'device-mapping- (string->symbol target))))
       (requirement '(udev))
       (documentation "Map a device node using Linux's device mapper.")
       (start #~(lambda () #$(open source target)))
       (stop #~(lambda _ (not #$(close source target))))
       (respawn? #f)

       ;; Add the modules needed by LUKS-DEVICE-MAPPING.
       ;; FIXME: This info should be propagated via gexps.
       (modules `((rnrs bytevectors)              ;bytevector?
                  ((gnu build file-systems)
                   #:select (find-partition-by-luks-uuid))
                  ,@%default-modules)))))))

(define (device-mapping-service mapped-device)
  "Return a service that sets up @var{mapped-device}."
  (service device-mapping-service-type mapped-device))


;;;
;;; Common device mappings.
;;;

(define (open-luks-device source target)
  "Return a gexp that maps SOURCE to TARGET as a LUKS device, using
'cryptsetup'."
  (with-imported-modules '((gnu build file-systems)
                           (guix build bournish))
    #~(let ((source #$source))
        (zero? (system* (string-append #$cryptsetup "/sbin/cryptsetup")
                        "open" "--type" "luks"

                        ;; Note: We cannot use the "UUID=source" syntax here
                        ;; because 'cryptsetup' implements it by searching the
                        ;; udev-populated /dev/disk/by-id directory but udev may
                        ;; be unavailable at the time we run this.
                        (if (bytevector? source)
                            (or (find-partition-by-luks-uuid source)
                                (error "LUKS partition not found" source))
                            source)

                        #$target)))))

(define (close-luks-device source target)
  "Return a gexp that closes TARGET, a LUKS device."
  #~(zero? (system* (string-append #$cryptsetup "/sbin/cryptsetup")
                    "close" #$target)))

(define luks-device-mapping
  ;; The type of LUKS mapped devices.
  (mapped-device-kind
   (open open-luks-device)
   (close close-luks-device)))

(define (open-raid-device source target)
  "Return a gexp that assembles SOURCE (a list of devices) to the RAID device
TARGET, using 'mdadm'."
  #~(let ((every (@ (srfi srfi-1) every)))
      (let loop ()
        (unless (every file-exists? '#$source)
          (format #t "waiting a bit...~%")
          (sleep 1)
          (loop)))
       (zero? (system* (string-append #$mdadm "/sbin/mdadm")
                                      "--assemble" #$target
                                      #$@source))))

(define (close-raid-device source target)
  "Return a gexp that stops the RAID device TARGET."
  #~(zero? (system* (string-append #$mdadm "/sbin/mdadm")
                    "--stop" #$target)))

(define raid-device-mapping
  ;; The type of RAID mapped devices.
  (mapped-device-kind
   (open open-raid-device)
   (close close-raid-device)))

;;; mapped-devices.scm ends here
