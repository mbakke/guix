;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2013 Nikita Karetnikov <nikita@karetnikov.org>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016 Hartmut Goebel <h.goebel@crazy-compilers.com>
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

(define-module (guix build python-build-system)
  #:use-module ((guix build gnu-build-system) #:prefix gnu:)
  #:use-module (guix build utils)
  #:use-module (ice-9 match)
  #:use-module (ice-9 ftw)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (%standard-phases
            python-build))

;; Commentary:
;;
;; Builder-side code of the standard Python package build procedure.
;;
;; Code:


(define (call-setuppy command params)
  (if (file-exists? "setup.py")
      (begin
         (format #t "running \"python setup.py\" with command ~s and parameters ~s~%"
                command params)
         (zero? (apply system* "python" "setup.py" command params)))
      (error "no setup.py found")))

(define* (build #:rest empty)
  "Build a given Python package."
  (call-setuppy "build" '()))

(define* (check #:key tests? test-target #:allow-other-keys)
  "Run the test suite of a given Python package."
  (if tests?
    (call-setuppy test-target '())
    #t))

(define (get-python-version python)
  (let* ((version     (last (string-split python #\-)))
         (components  (string-split version #\.))
         (major+minor (take components 2)))
    (string-join major+minor ".")))

(define* (install #:key outputs (configure-flags '())
                  #:allow-other-keys)
  "Install a given Python package."
  (let* ((out (assoc-ref outputs "out"))
         (params (append (list (string-append "--prefix=" out)
                               "--single-version-externally-managed"
                               "--root=/")
                         configure-flags)))
    (call-setuppy "install" params)))

(define* (wrap #:key inputs outputs #:allow-other-keys)
  (define (list-of-files dir)
    (map (cut string-append dir "/" <>)
         (or (scandir dir (lambda (f)
                            (let ((s (stat (string-append dir "/" f))))
                              (eq? 'regular (stat:type s)))))
             '())))

  (define bindirs
    (append-map (match-lambda
                 ((_ . dir)
                  (list (string-append dir "/bin")
                        (string-append dir "/sbin"))))
                outputs))

  (let* ((out  (assoc-ref outputs "out"))
         (python (assoc-ref inputs "python"))
         (var `("PYTHONPATH" prefix
                ,(cons (string-append out "/lib/python"
                                      (get-python-version python)
                                      "/site-packages")
                       (search-path-as-string->list
                        (or (getenv "PYTHONPATH") ""))))))
    (for-each (lambda (dir)
                (let ((files (list-of-files dir)))
                  (for-each (cut wrap-program <> var)
                            files)))
              bindirs)))

(define* (rename-pth-file #:key name inputs outputs #:allow-other-keys)
  "Rename easy-install.pth to NAME.pth to avoid conflicts between packages
installed with setuptools."
  (let* ((out (assoc-ref outputs "out"))
         (python (assoc-ref inputs "python"))
         (site-packages (string-append out "/lib/python"
                                       (get-python-version python)
                                       "/site-packages"))
         (easy-install-pth (string-append site-packages "/easy-install.pth"))
         (new-pth (string-append site-packages "/" name ".pth")))
    (when (file-exists? easy-install-pth)
      (rename-file easy-install-pth new-pth))
    #t))

(define* (ensure-no-mtimes-pre-1980 #:rest _)
  "Ensure that there are no mtimes before 1980-01-02 in the source tree."
  ;; Rationale: patch-and-repack creates tarballs with timestamps at the POSIX
  ;; epoch, 1970-01-01 UTC.  This causes problems with Python packages,
  ;; because Python eggs are ZIP files, and the ZIP format does not support
  ;; timestamps before 1980.
  (let ((early-1980 315619200))  ; 1980-01-02 UTC
    (ftw "." (lambda (file stat flag)
               (unless (<= early-1980 (stat:mtime stat))
                 (utime file early-1980 early-1980))
               #t))
    #t))

(define %standard-phases
  ;; 'configure' phase is not needed.
  (modify-phases gnu:%standard-phases
    (add-after 'unpack 'ensure-no-mtimes-pre-1980 ensure-no-mtimes-pre-1980)
    (delete 'configure)
    (replace 'install install)
    (replace 'check check)
    (replace 'build build)
    (add-after 'install 'wrap wrap)
    (add-before 'strip 'rename-pth-file rename-pth-file)))

(define* (python-build #:key inputs (phases %standard-phases)
                       #:allow-other-keys #:rest args)
  "Build the given Python package, applying all of PHASES in order."
  (apply gnu:gnu-build #:inputs inputs #:phases phases args))

;;; python-build-system.scm ends here
