;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (guix import cran)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module ((ice-9 rdelim) #:select (read-string))
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-41)
  #:use-module (ice-9 receive)
  #:use-module (web uri)
  #:use-module (guix combinators)
  #:use-module (guix http-client)
  #:use-module (guix hash)
  #:use-module (guix store)
  #:use-module (guix base32)
  #:use-module ((guix download) #:select (download-to-store))
  #:use-module (guix import utils)
  #:use-module ((guix build-system r) #:select (cran-uri bioconductor-uri))
  #:use-module (guix upstream)
  #:use-module (guix packages)
  #:use-module (gnu packages)
  #:export (cran->guix-package
            bioconductor->guix-package
            recursive-import
            %cran-updater
            %bioconductor-updater))

;;; Commentary:
;;;
;;; Generate a package declaration template for the latest version of an R
;;; package on CRAN, using the DESCRIPTION file downloaded from
;;; cran.r-project.org.
;;;
;;; Code:

(define string->license
  (match-lambda
   ("AGPL-3" 'agpl3+)
   ("Artistic-2.0" 'artistic2.0)
   ("Apache License 2.0" 'asl2.0)
   ("BSD_2_clause" 'bsd-2)
   ("BSD_2_clause + file LICENSE" 'bsd-2)
   ("BSD_3_clause" 'bsd-3)
   ("BSD_3_clause + file LICENSE" 'bsd-3)
   ("GPL" (list 'gpl2+ 'gpl3+))
   ("GPL (>= 2)" 'gpl2+)
   ("GPL (>= 3)" 'gpl3+)
   ("GPL-2" 'gpl2)
   ("GPL-3" 'gpl3)
   ("LGPL-2" 'lgpl2.0)
   ("LGPL-2.1" 'lgpl2.1)
   ("LGPL-3" 'lgpl3)
   ("LGPL (>= 2)" 'lgpl2.0+)
   ("LGPL (>= 3)" 'lgpl3+)
   ("MIT" 'expat)
   ("MIT + file LICENSE" 'expat)
   ((x) (string->license x))
   ((lst ...) `(list ,@(map string->license lst)))
   (_ #f)))


(define (description->alist description)
  "Convert a DESCRIPTION string into an alist."
  (let ((lines (string-split description #\newline))
        (parse (lambda (line acc)
                 (if (string-null? line) acc
                     ;; Keys usually start with a capital letter and end with
                     ;; ":".  There are some exceptions, unfortunately (such
                     ;; as "biocViews").  There are no blanks in a key.
                     (if (string-match "^[A-Za-z][^ :]+:( |\n|$)" line)
                         ;; New key/value pair
                         (let* ((pos   (string-index line #\:))
                                (key   (string-take line pos))
                                (value (string-drop line (+ 1 pos))))
                           (cons (cons key
                                       (string-trim-both value))
                                 acc))
                         ;; This is a continuation of the previous pair
                         (match-let ((((key . value) . rest) acc))
                           (cons (cons key (string-join
                                            (list value
                                                  (string-trim-both line))))
                                 rest)))))))
    (fold parse '() lines)))

(define (format-inputs names)
  "Generate a sorted list of package inputs from a list of package NAMES."
  (map (lambda (name)
         (list name (list 'unquote (string->symbol name))))
       (sort names string-ci<?)))

(define* (maybe-inputs package-inputs #:optional (type 'inputs))
  "Given a list of PACKAGE-INPUTS, tries to generate the TYPE field of a
package definition."
  (match package-inputs
    (()
     '())
    ((package-inputs ...)
     `((,type (,'quasiquote ,(format-inputs package-inputs)))))))

(define %cran-url "http://cran.r-project.org/web/packages/")
(define %bioconductor-url "http://bioconductor.org/packages/")

;; The latest Bioconductor release is 3.4.  Bioconductor packages should be
;; updated together.
(define %bioconductor-svn-url
  (string-append "https://readonly:readonly@"
                 "hedgehog.fhcrc.org/bioconductor/branches/RELEASE_3_4/"
                 "madman/Rpacks/"))


(define (fetch-description base-url name)
  "Return an alist of the contents of the DESCRIPTION file for the R package
NAME, or #f in case of failure.  NAME is case-sensitive."
  ;; This API always returns the latest release of the module.
  (let ((url (string-append base-url name "/DESCRIPTION")))
    (guard (c ((http-get-error? c)
               (format (current-error-port)
                       "error: failed to retrieve package information \
from ~s: ~a (~s)~%"
                       (uri->string (http-get-error-uri c))
                       (http-get-error-code c)
                       (http-get-error-reason c))
               #f))
      (description->alist (read-string (http-fetch url))))))

(define (listify meta field)
  "Look up FIELD in the alist META.  If FIELD contains a comma-separated
string, turn it into a list and strip off parenthetic expressions.  Return the
empty list when the FIELD cannot be found."
  (let ((value (assoc-ref meta field)))
    (if (not value)
        '()
        ;; Strip off parentheses
        (let ((items (string-split (regexp-substitute/global
                                    #f "( *\\([^\\)]+\\)) *"
                                    value 'pre 'post)
                                   #\,)))
          (remove (lambda (item)
                    (or (string-null? item)
                        ;; When there is whitespace inside of items it is
                        ;; probably because this was not an actual list to
                        ;; begin with.
                        (string-any char-set:whitespace item)))
                  (map string-trim-both items))))))

(define default-r-packages
  (list "KernSmooth"
        "MASS"
        "Matrix"
        "base"
        "boot"
        "class"
        "cluster"
        "codetools"
        "compiler"
        "datasets"
        "foreign"
        "grDevices"
        "graphics"
        "grid"
        "lattice"
        "methods"
        "mgcv"
        "nlme"
        "nnet"
        "parallel"
        "rpart"
        "spatial"
        "splines"
        "stats"
        "stats4"
        "survival"
        "tcltk"
        "tools"
        "translations"
        "utils"))

(define (guix-name name)
  "Return a Guix package name for a given R package name."
  (string-append "r-" (string-map (match-lambda
                                    (#\_ #\-)
                                    (#\. #\-)
                                    (chr (char-downcase chr)))
                                  name)))

(define (description->package repository meta)
  "Return the `package' s-expression for an R package published on REPOSITORY
from the alist META, which was derived from the R package's DESCRIPTION file."
  (let* ((base-url   (case repository
                       ((cran)         %cran-url)
                       ((bioconductor) %bioconductor-url)))
         (uri-helper (case repository
                       ((cran)         cran-uri)
                       ((bioconductor) bioconductor-uri)))
         (name       (assoc-ref meta "Package"))
         (synopsis   (assoc-ref meta "Title"))
         (version    (assoc-ref meta "Version"))
         (license    (string->license (assoc-ref meta "License")))
         ;; Some packages have multiple home pages.  Some have none.
         (home-page  (match (listify meta "URL")
                       ((url rest ...) url)
                       (_ (string-append base-url name))))
         (source-url (match (uri-helper name version)
                       ((url rest ...) url)
                       ((? string? url) url)
                       (_ #f)))
         (tarball    (with-store store (download-to-store store source-url)))
         (sysdepends (map string-downcase (listify meta "SystemRequirements")))
         (propagate  (filter (lambda (name)
                               (not (member name default-r-packages)))
                             (lset-union equal?
                                         (listify meta "Imports")
                                         (listify meta "LinkingTo")
                                         (delete "R"
                                                 (listify meta "Depends"))))))
    (values
     `(package
        (name ,(guix-name name))
        (version ,version)
        (source (origin
                  (method url-fetch)
                  (uri (,(procedure-name uri-helper) ,name version))
                  (sha256
                   (base32
                    ,(bytevector->nix-base32-string (file-sha256 tarball))))))
        ,@(if (not (equal? (string-append "r-" name)
                           (guix-name name)))
              `((properties ,`(,'quasiquote ((,'upstream-name . ,name)))))
              '())
        (build-system r-build-system)
        ,@(maybe-inputs sysdepends)
        ,@(maybe-inputs (map guix-name propagate) 'propagated-inputs)
        (home-page ,(if (string-null? home-page)
                        (string-append base-url name)
                        home-page))
        (synopsis ,synopsis)
        (description ,(beautify-description (or (assoc-ref meta "Description")
                                                "")))
        (license ,license))
     propagate)))

(define cran->guix-package
  (memoize
   (lambda* (package-name #:optional (repo 'cran))
     "Fetch the metadata for PACKAGE-NAME from REPO and return the `package'
s-expression corresponding to that package, or #f on failure."
     (let* ((url (case repo
                   ((cran)         %cran-url)
                   ((bioconductor) %bioconductor-svn-url)))
            (module-meta (fetch-description url package-name)))
       (and=> module-meta (cut description->package repo <>))))))

(define* (recursive-import package-name #:optional (repo 'cran))
  "Generate a stream of package expressions for PACKAGE-NAME and all its
dependencies."
  (receive (package . dependencies)
      (cran->guix-package package-name repo)
    (if (not package)
        stream-null

        ;; Generate a lazy stream of package expressions for all unknown
        ;; dependencies in the graph.
        (let* ((make-state (lambda (queue done)
                             (cons queue done)))
               (next       (match-lambda
                             (((next . rest) . done) next)))
               (imported   (match-lambda
                             ((queue . done) done)))
               (done?      (match-lambda
                             ((queue . done)
                              (zero? (length queue)))))
               (unknown?   (lambda* (dependency #:optional (done '()))
                             (and (not (member dependency
                                               done))
                                  (null? (find-packages-by-name
                                          (guix-name dependency))))))
               (update     (lambda (state new-queue)
                             (match state
                               (((head . tail) . done)
                                (make-state (lset-difference
                                             equal?
                                             (lset-union equal? new-queue tail)
                                             done)
                                            (cons head done)))))))
          (stream-cons
           package
           (stream-unfold
            ;; map: produce a stream element
            (lambda (state)
              (cran->guix-package (next state) repo))

            ;; predicate
            (compose not done?)

            ;; generator: update the queue
            (lambda (state)
              (receive (package . dependencies)
                  (cran->guix-package (next state) repo)
                (if package
                    (update state (filter (cut unknown? <>
                                               (cons (next state)
                                                     (imported state)))
                                          (car dependencies)))
                    ;; TODO: Try the other archives before giving up
                    (update state (imported state)))))

            ;; initial state
            (make-state (filter unknown? (car dependencies))
                        (list package-name))))))))


;;;
;;; Updater.
;;;

(define (package->upstream-name package)
  "Return the upstream name of the PACKAGE."
  (let* ((properties (package-properties package))
         (upstream-name (and=> properties
                               (cut assoc-ref <> 'upstream-name))))
    (if upstream-name
        upstream-name
        (match (package-source package)
          ((? origin? origin)
           (match (origin-uri origin)
             ((or (? string? url) (url _ ...))
              (let ((end   (string-rindex url #\_))
                    (start (string-rindex url #\/)))
                ;; The URL ends on
                ;; (string-append "/" name "_" version ".tar.gz")
                (substring url (+ start 1) end)))
             (_ #f)))
          (_ #f)))))

(define (latest-cran-release package)
  "Return an <upstream-source> for the latest release of PACKAGE."

  (define upstream-name
    (package->upstream-name package))

  (define meta
    (fetch-description %cran-url upstream-name))

  (and meta
       (let ((version (assoc-ref meta "Version")))
         ;; CRAN does not provide signatures.
         (upstream-source
          (package (package-name package))
          (version version)
          (urls (cran-uri upstream-name version))))))

(define (latest-bioconductor-release package)
  "Return an <upstream-source> for the latest release of PACKAGE."

  (define upstream-name
    (package->upstream-name package))

  (define meta
    (fetch-description %bioconductor-svn-url upstream-name))

  (and meta
       (let ((version (assoc-ref meta "Version")))
         ;; Bioconductor does not provide signatures.
         (upstream-source
          (package (package-name package))
          (version version)
          (urls (list (bioconductor-uri upstream-name version)))))))

(define (cran-package? package)
  "Return true if PACKAGE is an R package from CRAN."
  (and (string-prefix? "r-" (package-name package))
       (match (and=> (package-source package) origin-uri)
         ((? string? uri)
          (string-prefix? "mirror://cran" uri))
         ((? list? uris)
          (any (cut string-prefix? "mirror://cran" <>) uris))
         (_ #f))))

(define (bioconductor-package? package)
  "Return true if PACKAGE is an R package from Bioconductor."
  (and (string-prefix? "r-" (package-name package))
       (match (and=> (package-source package) origin-uri)
         ((? string? uri)
          (string-prefix? "http://bioconductor.org" uri))
         ((? list? uris)
          (any (cut string-prefix? "http://bioconductor.org" <>) uris))
         (_ #f))))

(define %cran-updater
  (upstream-updater
   (name 'cran)
   (description "Updater for CRAN packages")
   (pred cran-package?)
   (latest latest-cran-release)))

(define %bioconductor-updater
  (upstream-updater
   (name 'bioconductor)
   (description "Updater for Bioconductor packages")
   (pred bioconductor-package?)
   (latest latest-bioconductor-release)))

;;; cran.scm ends here
