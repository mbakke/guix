;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (guix scripts gc)
  #:use-module (guix ui)
  #:use-module (guix scripts)
  #:use-module (guix store)
  #:autoload   (guix build syscalls) (statfs)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-37)
  #:export (guix-gc))


;;;
;;; Command-line options.
;;;

(define %default-options
  ;; Alist of default option values.
  `((action . collect-garbage)))

(define (show-help)
  (display (_ "Usage: guix gc [OPTION]... PATHS...
Invoke the garbage collector.\n"))
  (display (_ "
  -C, --collect-garbage[=MIN]
                         collect at least MIN bytes of garbage"))
  (display (_ "
  -F, --free-space=FREE  attempt to reach FREE available space in the store"))
  (display (_ "
  -d, --delete           attempt to delete PATHS"))
  (display (_ "
      --optimize         optimize the store by deduplicating identical files"))
  (display (_ "
      --list-dead        list dead paths"))
  (display (_ "
      --list-live        list live paths"))
  (newline)
  (display (_ "
      --references       list the references of PATHS"))
  (display (_ "
  -R, --requisites       list the requisites of PATHS"))
  (display (_ "
      --referrers        list the referrers of PATHS"))
  (newline)
  (display (_ "
      --verify[=OPTS]    verify the integrity of the store; OPTS is a
                         comma-separated combination of 'repair' and
                         'contents'"))
  (display (_ "
      --list-failures    list cached build failures"))
  (display (_ "
      --clear-failures   remove PATHS from the set of cached failures"))
  (newline)
  (display (_ "
  -h, --help             display this help and exit"))
  (display (_ "
  -V, --version          display version information and exit"))
  (newline)
  (show-bug-report-information))

(define %options
  ;; Specification of the command-line options.
  (list (option '(#\h "help") #f #f
                (lambda args
                  (show-help)
                  (exit 0)))
        (option '(#\V "version") #f #f
                (lambda args
                  (show-version-and-exit "guix gc")))

        (option '(#\C "collect-garbage") #f #t
                (lambda (opt name arg result)
                  (let ((result (alist-cons 'action 'collect-garbage
                                            (alist-delete 'action result))))
                   (match arg
                     ((? string?)
                      (let ((amount (size->number arg)))
                        (if arg
                            (alist-cons 'min-freed amount result)
                            (leave (_ "invalid amount of storage: ~a~%")
                                   arg))))
                     (#f result)))))
        (option '(#\F "free-space") #t #f
                (lambda (opt name arg result)
                  (alist-cons 'free-space (size->number arg) result)))
        (option '(#\d "delete") #f #f
                (lambda (opt name arg result)
                  (alist-cons 'action 'delete
                              (alist-delete 'action result))))
        (option '("optimize") #f #f
                (lambda (opt name arg result)
                  (alist-cons 'action 'optimize
                              (alist-delete 'action result))))
        (option '("verify") #f #t
                (let ((not-comma (char-set-complement (char-set #\,))))
                  (lambda (opt name arg result)
                    (let ((options (if arg
                                       (map string->symbol
                                            (string-tokenize arg not-comma))
                                       '())))
                      (alist-cons 'action 'verify
                                  (alist-cons 'verify-options options
                                              (alist-delete 'action
                                                            result)))))))
        (option '("list-dead") #f #f
                (lambda (opt name arg result)
                  (alist-cons 'action 'list-dead
                              (alist-delete 'action result))))
        (option '("list-live") #f #f
                (lambda (opt name arg result)
                  (alist-cons 'action 'list-live
                              (alist-delete 'action result))))
        (option '("references") #f #f
                (lambda (opt name arg result)
                  (alist-cons 'action 'list-references
                              (alist-delete 'action result))))
        (option '(#\R "requisites") #f #f
                (lambda (opt name arg result)
                  (alist-cons 'action 'list-requisites
                              (alist-delete 'action result))))
        (option '("referrers") #f #f
                (lambda (opt name arg result)
                  (alist-cons 'action 'list-referrers
                              (alist-delete 'action result))))
        (option '("list-failures") #f #f
                (lambda (opt name arg result)
                  (alist-cons 'action 'list-failures
                              (alist-delete 'action result))))
        (option '("clear-failures") #f #f
                (lambda (opt name arg result)
                  (alist-cons 'action 'clear-failures
                              (alist-delete 'action result))))))


;;;
;;; Entry point.
;;;

(define (guix-gc . args)
  (define (parse-options)
    ;; Return the alist of option values.
    (args-fold* args %options
                (lambda (opt name arg result)
                  (leave (_ "~A: unrecognized option~%") name))
                (lambda (arg result)
                  (alist-cons 'argument arg result))
                %default-options))

  (define (symlink-target file)
    (let ((s (false-if-exception (lstat file))))
      (if (and s (eq? 'symlink (stat:type s)))
          (symlink-target (readlink file))
          file)))

  (define (store-directory file)
    ;; Return the store directory that holds FILE if it's in the store,
    ;; otherwise return FILE.
    (or (and=> (string-match (string-append "^" (regexp-quote (%store-prefix))
                                            "/([^/]+)")
                             file)
               (compose (cut string-append (%store-prefix) "/" <>)
                        (cut match:substring <> 1)))
        file))

  (define (ensure-free-space store space)
    ;; Attempt to have at least SPACE bytes available in STORE.
    (let* ((fs    (statfs (%store-prefix)))
           (free  (* (file-system-block-size fs)
                     (file-system-blocks-available fs))))
      (if (> free space)
          (info (_ "already ~h bytes available on ~a, nothing to do~%")
                free (%store-prefix))
          (let ((to-free (- space free)))
            (info (_ "freeing ~h bytes~%") to-free)
            (collect-garbage store to-free)))))

  (with-error-handling
    (let* ((opts  (parse-options))
           (store (open-connection))
           (paths (filter-map (match-lambda
                               (('argument . arg) arg)
                               (_ #f))
                              opts)))
      (define (assert-no-extra-arguments)
        (unless (null? paths)
          (leave (_ "extraneous arguments: ~{~a ~}~%") paths)))

      (define (list-relatives relatives)
        (for-each (compose (lambda (path)
                             (for-each (cut simple-format #t "~a~%" <>)
                                       (relatives store path)))
                           store-directory
                           symlink-target)
                  paths))

      (case (assoc-ref opts 'action)
        ((collect-garbage)
         (assert-no-extra-arguments)
         (let ((min-freed  (assoc-ref opts 'min-freed))
               (free-space (assoc-ref opts 'free-space)))
           (cond
            (free-space
             (ensure-free-space store free-space))
            (min-freed
             (let-values (((paths freed) (collect-garbage store min-freed)))
              (info (_ "freed ~h bytes~%") freed)))
            (else
             (let-values (((paths freed) (collect-garbage store)))
              (info (_ "freed ~h bytes~%") freed))))))
        ((delete)
         (delete-paths store (map direct-store-path paths)))
        ((list-references)
         (list-relatives references))
        ((list-requisites)
         (list-relatives (lambda (store item)
                           (requisites store (list item)))))
        ((list-referrers)
         (list-relatives referrers))
        ((optimize)
         (assert-no-extra-arguments)
         (optimize-store store))
        ((verify)
         (assert-no-extra-arguments)
         (let ((options (assoc-ref opts 'verify-options)))
           (exit
            (verify-store store
                          #:check-contents? (memq 'contents options)
                          #:repair? (memq 'repair options)))))
        ((list-failures)
         (for-each (cut simple-format #t "~a~%" <>)
                   (query-failed-paths store)))
        ((clear-failures)
         (clear-failed-paths store (map direct-store-path paths)))
        ((list-dead)
         (for-each (cut simple-format #t "~a~%" <>)
                   (dead-paths store)))
        ((list-live)
         (for-each (cut simple-format #t "~a~%" <>)
                   (live-paths store)))))))
