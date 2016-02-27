;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (guix grafts)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix records)
  #:use-module (guix derivations)
  #:use-module ((guix utils) #:select (%current-system))
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9 gnu)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)
  #:export (graft?
            graft
            graft-origin
            graft-replacement
            graft-origin-output
            graft-replacement-output

            graft-derivation
            graft-derivation/shallow

            %graft?
            set-grafting))

(define-record-type* <graft> graft make-graft
  graft?
  (origin             graft-origin)               ;derivation | store item
  (origin-output      graft-origin-output         ;string | #f
                      (default "out"))
  (replacement        graft-replacement)          ;derivation | store item
  (replacement-output graft-replacement-output    ;string | #f
                      (default "out")))

(define (write-graft graft port)
  "Write a concise representation of GRAFT to PORT."
  (define (->string thing output)
    (if (derivation? thing)
        (derivation->output-path thing output)
        thing))

  (match graft
    (($ <graft> origin origin-output replacement replacement-output)
     (format port "#<graft ~a ==> ~a ~a>"
             (->string origin origin-output)
             (->string replacement replacement-output)
             (number->string (object-address graft) 16)))))

(set-record-type-printer! <graft> write-graft)

(define (graft-origin-file-name graft)
  "Return the output file name of the origin of GRAFT."
  (match graft
    (($ <graft> (? derivation? origin) output)
     (derivation->output-path origin output))
    (($ <graft> (? string? item))
     item)))

(define* (graft-derivation/shallow store drv grafts
                                   #:key
                                   (name (derivation-name drv))
                                   (guile (%guile-for-build))
                                   (system (%current-system)))
  "Return a derivation called NAME, based on DRV but with all the GRAFTS
applied.  This procedure performs \"shallow\" grafting in that GRAFTS are not
recursively applied to dependencies of DRV."
  ;; XXX: Someday rewrite using gexps.
  (define mapping
    ;; List of store item pairs.
    (map (match-lambda
          (($ <graft> source source-output target target-output)
           (cons (if (derivation? source)
                     (derivation->output-path source source-output)
                     source)
                 (if (derivation? target)
                     (derivation->output-path target target-output)
                     target))))
         grafts))

  (define outputs
    (map (match-lambda
           ((name . output)
            (cons name (derivation-output-path output))))
         (derivation-outputs drv)))

  (define output-names
    (derivation-output-names drv))

  (define build
    `(begin
       (use-modules (guix build graft)
                    (guix build utils)
                    (ice-9 match))

       (let* ((old-outputs ',outputs)
              (mapping (append ',mapping
                               (map (match-lambda
                                      ((name . file)
                                       (cons (assoc-ref old-outputs name)
                                             file)))
                                    %outputs))))
         (for-each (lambda (input output)
                     (format #t "grafting '~a' -> '~a'...~%" input output)
                     (force-output)
                     (rewrite-directory input output mapping))
                   (match old-outputs
                     (((names . files) ...)
                      files))
                   (match %outputs
                     (((names . files) ...)
                      files))))))

  (define add-label
    (cut cons "x" <>))

  (match grafts
    ((($ <graft> sources source-outputs targets target-outputs) ...)
     (let ((sources (zip sources source-outputs))
           (targets (zip targets target-outputs)))
       (build-expression->derivation store name build
                                     #:system system
                                     #:guile-for-build guile
                                     #:modules '((guix build graft)
                                                 (guix build utils))
                                     #:inputs `(,@(map (lambda (out)
                                                         `("x" ,drv ,out))
                                                       output-names)
                                                ,@(append (map add-label sources)
                                                          (map add-label targets)))
                                     #:outputs output-names
                                     #:local-build? #t)))))
(define (item->deriver store item)
  "Return two values: the derivation that led to ITEM (a store item), and the
name of the output of that derivation ITEM corresponds to (for example
\"out\").  When ITEM has no deriver, for instance because it is a plain file,
#f and #f are returned."
  (match (valid-derivers store item)
    (()                                           ;ITEM is a plain file
     (values #f #f))
    ((drv-file _ ...)
     (let ((drv (call-with-input-file drv-file read-derivation)))
       (values drv
               (any (match-lambda
                      ((name . path)
                       (and (string=? item path) name)))
                    (derivation->output-paths drv)))))))

(define (non-self-references store drv outputs)
  "Return the list of references of the OUTPUTS of DRV, excluding self
references."
  (let ((refs (append-map (lambda (output)
                            (references store
                                        (derivation->output-path drv output)))
                          outputs))
        (self (match (derivation->output-paths drv)
                (((names . items) ...)
                 items))))
    (remove (cut member <> self) refs)))

(define* (cumulative-grafts store drv grafts
                            #:key
                            (outputs (derivation-output-names drv))
                            (guile (%guile-for-build))
                            (system (%current-system)))
  "Augment GRAFTS with additional grafts resulting from the application of
GRAFTS to the dependencies of DRV.  Return the resulting list of grafts."
  (define (dependency-grafts item)
    (let-values (((drv output) (item->deriver store item)))
      (if drv
          (cumulative-grafts store drv grafts
                             #:outputs (list output)
                             #:guile guile
                             #:system system)
          grafts)))

  ;; TODO: Memoize.
  (match (non-self-references store drv outputs)
    (()                                           ;no dependencies
     grafts)
    (deps                                         ;one or more dependencies
     (let* ((grafts  (delete-duplicates (append-map dependency-grafts deps)
                                        eq?))
            (origins (map graft-origin-file-name grafts)))
       (if (find (cut member <> deps) origins)
           (let ((new (graft-derivation/shallow store drv grafts
                                                #:guile guile
                                                #:system system)))
             (cons (graft (origin drv) (replacement new))
                   grafts))
           grafts)))))

(define* (graft-derivation store drv grafts
                           #:key (guile (%guile-for-build))
                           (system (%current-system)))
  "Applied GRAFTS to DRV and all its dependencies, recursively.  That is, if
GRAFTS apply only indirectly to DRV, graft the dependencies of DRV, and graft
DRV itself to refer to those grafted dependencies."

  ;; First, we need to build the ungrafted DRV so we can query its run-time
  ;; dependencies in 'cumulative-grafts'.
  (build-derivations store (list drv))

  (match (cumulative-grafts store drv grafts
                            #:guile guile #:system system)
    ((first . rest)
     ;; If FIRST is not a graft for DRV, it means that GRAFTS are not
     ;; applicable to DRV and nothing needs to be done.
     (if (equal? drv (graft-origin first))
         (graft-replacement first)
         drv))))


;; The following might feel more at home in (guix packages) but since (guix
;; gexp), which is a lower level, needs them, we put them here.

(define %graft?
  ;; Whether to honor package grafts by default.
  (make-parameter #t))

(define (set-grafting enable?)
  "This monadic procedure enables grafting when ENABLE? is true, and disables
it otherwise.  It returns the previous setting."
  (lambda (store)
    (values (%graft? enable?) store)))

;;; grafts.scm ends here
