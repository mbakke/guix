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

(define-module (test-gexp)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix gexp)
  #:use-module (guix grafts)
  #:use-module (guix derivations)
  #:use-module (guix packages)
  #:use-module (guix tests)
  #:use-module ((guix build utils) #:select (with-directory-excursion))
  #:use-module (gnu packages)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bootstrap)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-64)
  #:use-module (rnrs io ports)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 popen)
  #:use-module (ice-9 ftw))

;; Test the (guix gexp) module.

(define %store
  (open-connection-for-tests))

;; Globally disable grafts because they can trigger early builds.
(%graft? #f)

;; For white-box testing.
(define (gexp-inputs x)
  ((@@ (guix gexp) gexp-inputs) x))
(define (gexp-native-inputs x)
  ((@@ (guix gexp) gexp-native-inputs) x))
(define (gexp-outputs x)
  ((@@ (guix gexp) gexp-outputs) x))
(define (gexp->sexp . x)
  (apply (@@ (guix gexp) gexp->sexp) x))

(define* (gexp->sexp* exp #:optional target)
  (run-with-store %store (gexp->sexp exp
                                     #:target target)
                  #:guile-for-build (%guile-for-build)))

(define-syntax-rule (test-assertm name exp)
  (test-assert name
    (run-with-store %store exp
                    #:guile-for-build (%guile-for-build))))


(test-begin "gexp")

(test-equal "no refs"
  '(display "hello!")
  (let ((exp (gexp (display "hello!"))))
    (and (gexp? exp)
         (null? (gexp-inputs exp))
         (gexp->sexp* exp))))

(test-equal "unquote"
  '(display `(foo ,(+ 2 3)))
  (let ((exp (gexp (display `(foo ,(+ 2 3))))))
    (and (gexp? exp)
         (null? (gexp-inputs exp))
         (gexp->sexp* exp))))

(test-assert "one input package"
  (let ((exp (gexp (display (ungexp coreutils)))))
    (and (gexp? exp)
         (match (gexp-inputs exp)
           (((p "out"))
            (eq? p coreutils)))
         (equal? `(display ,(derivation->output-path
                             (package-derivation %store coreutils)))
                 (gexp->sexp* exp)))))

(test-assert "one input origin"
  (let ((exp (gexp (display (ungexp (package-source coreutils))))))
    (and (gexp? exp)
         (match (gexp-inputs exp)
           (((o "out"))
            (eq? o (package-source coreutils))))
         (equal? `(display ,(derivation->output-path
                             (package-source-derivation
                              %store (package-source coreutils))))
                 (gexp->sexp* exp)))))

(test-assert "one local file"
  (let* ((file  (search-path %load-path "guix.scm"))
         (local (local-file file))
         (exp   (gexp (display (ungexp local))))
         (intd  (add-to-store %store (basename file) #f
                              "sha256" file)))
    (and (gexp? exp)
         (match (gexp-inputs exp)
           (((x "out"))
            (eq? x local)))
         (equal? `(display ,intd) (gexp->sexp* exp)))))

(test-assert "one local file, symlink"
  (let ((file (search-path %load-path "guix.scm"))
        (link (tmpnam)))
    (dynamic-wind
      (const #t)
      (lambda ()
        (symlink (canonicalize-path file) link)
        (let* ((local (local-file link "my-file" #:recursive? #f))
               (exp   (gexp (display (ungexp local))))
               (intd  (add-to-store %store "my-file" #f
                                    "sha256" file)))
          (and (gexp? exp)
               (match (gexp-inputs exp)
                 (((x "out"))
                  (eq? x local)))
               (equal? `(display ,intd) (gexp->sexp* exp)))))
      (lambda ()
        (false-if-exception (delete-file link))))))

(test-equal "local-file, relative file name"
  (canonicalize-path (search-path %load-path "guix/base32.scm"))
  (let ((directory (dirname (search-path %load-path
                                         "guix/build-system/gnu.scm"))))
    (with-directory-excursion directory
        (let ((file (local-file "../guix/base32.scm")))
          (local-file-absolute-file-name file)))))

(test-assertm "local-file, #:select?"
  (mlet* %store-monad ((select? -> (lambda (file stat)
                                     (member (basename file)
                                             '("guix.scm" "tests"
                                               "gexp.scm"))))
                       (file -> (local-file ".." "directory"
                                            #:recursive? #t
                                            #:select? select?))
                       (dir (lower-object file)))
    (return (and (store-path? dir)
                 (equal? (scandir dir)
                         '("." ".." "guix.scm" "tests"))
                 (equal? (scandir (string-append dir "/tests"))
                         '("." ".." "gexp.scm"))))))

(test-assert "one plain file"
  (let* ((file     (plain-file "hi" "Hello, world!"))
         (exp      (gexp (display (ungexp file))))
         (expected (add-text-to-store %store "hi" "Hello, world!")))
    (and (gexp? exp)
         (match (gexp-inputs exp)
           (((x "out"))
            (eq? x file)))
         (equal? `(display ,expected) (gexp->sexp* exp)))))

(test-assert "same input twice"
  (let ((exp (gexp (begin
                     (display (ungexp coreutils))
                     (display (ungexp coreutils))))))
    (and (gexp? exp)
         (match (gexp-inputs exp)
           (((p "out"))
            (eq? p coreutils)))
         (let ((e `(display ,(derivation->output-path
                              (package-derivation %store coreutils)))))
           (equal? `(begin ,e ,e) (gexp->sexp* exp))))))

(test-assert "two input packages, one derivation, one file"
  (let* ((drv (build-expression->derivation
               %store "foo" 'bar
               #:guile-for-build (package-derivation %store %bootstrap-guile)))
         (txt (add-text-to-store %store "foo" "Hello, world!"))
         (exp (gexp (begin
                      (display (ungexp coreutils))
                      (display (ungexp %bootstrap-guile))
                      (display (ungexp drv))
                      (display (ungexp txt))))))
    (define (match-input thing)
      (match-lambda
       ((drv-or-pkg _ ...)
        (eq? thing drv-or-pkg))))

    (and (gexp? exp)
         (= 4 (length (gexp-inputs exp)))
         (every (lambda (input)
                  (find (match-input input) (gexp-inputs exp)))
                (list drv coreutils %bootstrap-guile txt))
         (let ((e0 `(display ,(derivation->output-path
                               (package-derivation %store coreutils))))
               (e1 `(display ,(derivation->output-path
                               (package-derivation %store %bootstrap-guile))))
               (e2 `(display ,(derivation->output-path drv)))
               (e3 `(display ,txt)))
           (equal? `(begin ,e0 ,e1 ,e2 ,e3) (gexp->sexp* exp))))))

(test-assert "file-append"
  (let* ((drv (package-derivation %store %bootstrap-guile))
         (fa  (file-append %bootstrap-guile "/bin/guile"))
         (exp #~(here we go #$fa)))
    (and (match (gexp->sexp* exp)
           (('here 'we 'go (? string? result))
            (string=? result
                      (string-append (derivation->output-path drv)
                                     "/bin/guile"))))
         (match (gexp-inputs exp)
           (((thing "out"))
            (eq? thing fa))))))

(test-assert "file-append, output"
  (let* ((drv (package-derivation %store glibc))
         (fa  (file-append glibc "/lib" "/debug"))
         (exp #~(foo #$fa:debug)))
    (and (match (gexp->sexp* exp)
           (('foo (? string? result))
            (string=? result
                      (string-append (derivation->output-path drv "debug")
                                     "/lib/debug"))))
         (match (gexp-inputs exp)
           (((thing "debug"))
            (eq? thing fa))))))

(test-assert "file-append, nested"
  (let* ((drv   (package-derivation %store glibc))
         (dir   (file-append glibc "/bin"))
         (slash (file-append dir "/"))
         (file  (file-append slash "getent"))
         (exp   #~(foo #$file)))
    (and (match (gexp->sexp* exp)
           (('foo (? string? result))
            (string=? result
                      (string-append (derivation->output-path drv)
                                     "/bin/getent"))))
         (match (gexp-inputs exp)
           (((thing "out"))
            (eq? thing file))))))

(test-assert "ungexp + ungexp-native"
  (let* ((exp    (gexp (list (ungexp-native %bootstrap-guile)
                             (ungexp coreutils)
                             (ungexp-native glibc)
                             (ungexp binutils))))
         (target "mips64el-linux")
         (guile  (derivation->output-path
                  (package-derivation %store %bootstrap-guile)))
         (cu     (derivation->output-path
                  (package-cross-derivation %store coreutils target)))
         (libc   (derivation->output-path
                  (package-derivation %store glibc)))
         (bu     (derivation->output-path
                  (package-cross-derivation %store binutils target))))
    (and (lset= equal?
                `((,%bootstrap-guile "out") (,glibc "out"))
                (gexp-native-inputs exp))
         (lset= equal?
                `((,coreutils "out") (,binutils "out"))
                (gexp-inputs exp))
         (equal? `(list ,guile ,cu ,libc ,bu)
                 (gexp->sexp* exp target)))))

(test-equal "ungexp + ungexp-native, nested"
  (list `((,%bootstrap-guile "out")) '<> `((,coreutils "out")))
  (let* ((exp (gexp (list (ungexp-native (gexp (ungexp coreutils)))
                          (ungexp %bootstrap-guile)))))
    (list (gexp-inputs exp) '<> (gexp-native-inputs exp))))

(test-equal "ungexp + ungexp-native, nested, special mixture"
  `(() <> ((,coreutils "out")))

  ;; (gexp-native-inputs exp) used to return '(), wrongfully.
  (let* ((foo (gexp (foo (ungexp-native coreutils))))
         (exp (gexp (bar (ungexp foo)))))
    (list (gexp-inputs exp) '<> (gexp-native-inputs exp))))

(test-assert "input list"
  (let ((exp   (gexp (display
                      '(ungexp (list %bootstrap-guile coreutils)))))
        (guile (derivation->output-path
                (package-derivation %store %bootstrap-guile)))
        (cu    (derivation->output-path
                (package-derivation %store coreutils))))
    (and (lset= equal?
                `((,%bootstrap-guile "out") (,coreutils "out"))
                (gexp-inputs exp))
         (equal? `(display '(,guile ,cu))
                 (gexp->sexp* exp)))))

(test-assert "input list + ungexp-native"
  (let* ((target "mips64el-linux")
         (exp   (gexp (display
                       (cons '(ungexp-native (list %bootstrap-guile coreutils))
                             '(ungexp (list glibc binutils))))))
         (guile (derivation->output-path
                 (package-derivation %store %bootstrap-guile)))
         (cu    (derivation->output-path
                 (package-derivation %store coreutils)))
         (xlibc (derivation->output-path
                 (package-cross-derivation %store glibc target)))
         (xbu   (derivation->output-path
                 (package-cross-derivation %store binutils target))))
    (and (lset= equal?
                `((,%bootstrap-guile "out") (,coreutils "out"))
                (gexp-native-inputs exp))
         (lset= equal?
                `((,glibc "out") (,binutils "out"))
                (gexp-inputs exp))
         (equal? `(display (cons '(,guile ,cu) '(,xlibc ,xbu)))
                 (gexp->sexp* exp target)))))

(test-assert "input list splicing"
  (let* ((inputs  (list (gexp-input glibc "debug") %bootstrap-guile))
         (outputs (list (derivation->output-path
                         (package-derivation %store glibc)
                         "debug")
                        (derivation->output-path
                         (package-derivation %store %bootstrap-guile))))
         (exp     (gexp (list (ungexp-splicing (cons (+ 2 3) inputs))))))
    (and (lset= equal?
                `((,glibc "debug") (,%bootstrap-guile "out"))
                (gexp-inputs exp))
         (equal? (gexp->sexp* exp)
                 `(list ,@(cons 5 outputs))))))

(test-assert "input list splicing + ungexp-native-splicing"
  (let* ((inputs (list (gexp-input glibc "debug" #:native? #t)
                       %bootstrap-guile))
         (exp    (gexp (list (ungexp-native-splicing (cons (+ 2 3) inputs))))))
    (and (lset= equal?
                `((,glibc "debug") (,%bootstrap-guile "out"))
                (gexp-native-inputs exp))
         (null? (gexp-inputs exp))
         (equal? (gexp->sexp* exp)                ;native
                 (gexp->sexp* exp "mips64el-linux")))))

(test-equal "output list"
  2
  (let ((exp (gexp (begin (mkdir (ungexp output))
                          (mkdir (ungexp output "bar"))))))
    (length (gexp-outputs exp))))                ;XXX: <output-ref> is private

(test-assert "output list, combined gexps"
  (let* ((exp0  (gexp (mkdir (ungexp output))))
         (exp1  (gexp (mkdir (ungexp output "foo"))))
         (exp2  (gexp (begin (display "hi!") (ungexp exp0) (ungexp exp1)))))
    (and (lset= equal?
                (append (gexp-outputs exp0) (gexp-outputs exp1))
                (gexp-outputs exp2))
         (= 2 (length (gexp-outputs exp2))))))

(test-equal "output list, combined gexps, duplicate output"
  1
  (let* ((exp0 (gexp (mkdir (ungexp output))))
         (exp1 (gexp (begin (mkdir (ungexp output)) (ungexp exp0))))
         (exp2 (gexp (begin (mkdir (ungexp output)) (ungexp exp1)))))
    (length (gexp-outputs exp2))))

(test-assert "output list + ungexp-splicing list, combined gexps"
  (let* ((exp0  (gexp (mkdir (ungexp output))))
         (exp1  (gexp (mkdir (ungexp output "foo"))))
         (exp2  (gexp (begin (display "hi!")
                             (ungexp-splicing (list exp0 exp1))))))
    (and (lset= equal?
                (append (gexp-outputs exp0) (gexp-outputs exp1))
                (gexp-outputs exp2))
         (= 2 (length (gexp-outputs exp2))))))

(test-assertm "gexp->file"
  (mlet* %store-monad ((exp -> (gexp (display (ungexp %bootstrap-guile))))
                       (guile  (package-file %bootstrap-guile))
                       (sexp   (gexp->sexp exp))
                       (drv    (gexp->file "foo" exp))
                       (out -> (derivation->output-path drv))
                       (done   (built-derivations (list drv)))
                       (refs   (references* out)))
    (return (and (equal? sexp (call-with-input-file out read))
                 (equal? (list guile) refs)))))

(test-assertm "gexp->file + file-append"
  (mlet* %store-monad ((exp -> #~#$(file-append %bootstrap-guile
                                                "/bin/guile"))
                       (guile  (package-file %bootstrap-guile))
                       (drv    (gexp->file "foo" exp))
                       (out -> (derivation->output-path drv))
                       (done   (built-derivations (list drv)))
                       (refs   (references* out)))
    (return (and (equal? (string-append guile "/bin/guile")
                         (call-with-input-file out read))
                 (equal? (list guile) refs)))))

(test-assertm "gexp->derivation"
  (mlet* %store-monad ((file    (text-file "foo" "Hello, world!"))
                       (exp ->  (gexp
                                 (begin
                                   (mkdir (ungexp output))
                                   (chdir (ungexp output))
                                   (symlink
                                    (string-append (ungexp %bootstrap-guile)
                                                   "/bin/guile")
                                    "foo")
                                   (symlink (ungexp file)
                                            (ungexp output "2nd")))))
                       (drv     (gexp->derivation "foo" exp))
                       (out ->  (derivation->output-path drv))
                       (out2 -> (derivation->output-path drv "2nd"))
                       (done    (built-derivations (list drv)))
                       (refs    (references* out))
                       (refs2   (references* out2))
                       (guile   (package-file %bootstrap-guile "bin/guile")))
    (return (and (string=? (readlink (string-append out "/foo")) guile)
                 (string=? (readlink out2) file)
                 (equal? refs (list (dirname (dirname guile))))
                 (equal? refs2 (list file))))))

(test-assertm "gexp->derivation vs. grafts"
  (mlet* %store-monad ((graft?  (set-grafting #f))
                       (p0 ->   (dummy-package "dummy"
                                               (arguments
                                                '(#:implicit-inputs? #f))))
                       (r  ->   (package (inherit p0) (name "DuMMY")))
                       (p1 ->   (package (inherit p0) (replacement r)))
                       (exp0 -> (gexp (frob (ungexp p0) (ungexp output))))
                       (exp1 -> (gexp (frob (ungexp p1) (ungexp output))))
                       (void    (set-guile-for-build %bootstrap-guile))
                       (drv0    (gexp->derivation "t" exp0 #:graft? #t))
                       (drv1    (gexp->derivation "t" exp1 #:graft? #t))
                       (drv1*   (gexp->derivation "t" exp1 #:graft? #f))
                       (_       (set-grafting graft?)))
    (return (and (not (string=? (derivation->output-path drv0)
                                (derivation->output-path drv1)))
                 (string=? (derivation->output-path drv0)
                           (derivation->output-path drv1*))))))

(test-assertm "gexp->derivation, composed gexps"
  (mlet* %store-monad ((exp0 -> (gexp (begin
                                        (mkdir (ungexp output))
                                        (chdir (ungexp output)))))
                       (exp1 -> (gexp (symlink
                                       (string-append (ungexp %bootstrap-guile)
                                                      "/bin/guile")
                                       "foo")))
                       (exp  -> (gexp (begin (ungexp exp0) (ungexp exp1))))
                       (drv     (gexp->derivation "foo" exp))
                       (out ->  (derivation->output-path drv))
                       (done    (built-derivations (list drv)))
                       (guile   (package-file %bootstrap-guile "bin/guile")))
    (return (string=? (readlink (string-append out "/foo"))
                      guile))))

(test-assertm "gexp->derivation, default system"
  ;; The default system should be the one at '>>=' time, not the one at
  ;; invocation time.  See <http://bugs.gnu.org/18002>.
  (let ((system (%current-system))
        (mdrv   (parameterize ((%current-system "foobar64-linux"))
                  (gexp->derivation "foo"
                                    (gexp
                                     (mkdir (ungexp output)))))))
    (mlet %store-monad ((drv mdrv))
      (return (string=? system (derivation-system drv))))))

(test-assertm "gexp->derivation, local-file"
  (mlet* %store-monad ((file ->  (search-path %load-path "guix.scm"))
                       (intd     (interned-file file #:recursive? #f))
                       (local -> (local-file file))
                       (exp ->   (gexp (begin
                                         (stat (ungexp local))
                                         (symlink (ungexp local)
                                                  (ungexp output)))))
                       (drv      (gexp->derivation "local-file" exp)))
    (mbegin %store-monad
      (built-derivations (list drv))
      (return (string=? (readlink (derivation->output-path drv))
                        intd)))))

(test-assertm "gexp->derivation, cross-compilation"
  (mlet* %store-monad ((target -> "mips64el-linux")
                       (exp    -> (gexp (list (ungexp coreutils)
                                              (ungexp output))))
                       (xdrv      (gexp->derivation "foo" exp
                                                    #:target target))
                       (refs      (references*
                                   (derivation-file-name xdrv)))
                       (xcu       (package->cross-derivation coreutils
                                                             target))
                       (cu        (package->derivation coreutils)))
    (return (and (member (derivation-file-name xcu) refs)
                 (not (member (derivation-file-name cu) refs))))))

(test-assertm "gexp->derivation, ungexp-native"
  (mlet* %store-monad ((target -> "mips64el-linux")
                       (exp    -> (gexp (list (ungexp-native coreutils)
                                              (ungexp output))))
                       (xdrv      (gexp->derivation "foo" exp
                                                    #:target target))
                       (drv       (gexp->derivation "foo" exp)))
    (return (string=? (derivation-file-name drv)
                      (derivation-file-name xdrv)))))

(test-assertm "gexp->derivation, ungexp + ungexp-native"
  (mlet* %store-monad ((target -> "mips64el-linux")
                       (exp    -> (gexp (list (ungexp-native coreutils)
                                              (ungexp glibc)
                                              (ungexp output))))
                       (xdrv      (gexp->derivation "foo" exp
                                                    #:target target))
                       (refs      (references*
                                   (derivation-file-name xdrv)))
                       (xglibc    (package->cross-derivation glibc target))
                       (cu        (package->derivation coreutils)))
    (return (and (member (derivation-file-name cu) refs)
                 (member (derivation-file-name xglibc) refs)))))

(test-assertm "gexp->derivation, ungexp-native + composed gexps"
  (mlet* %store-monad ((target -> "mips64el-linux")
                       (exp0   -> (gexp (list 1 2
                                              (ungexp coreutils))))
                       (exp    -> (gexp (list 0 (ungexp-native exp0))))
                       (xdrv      (gexp->derivation "foo" exp
                                                    #:target target))
                       (drv       (gexp->derivation "foo" exp)))
    (return (string=? (derivation-file-name drv)
                      (derivation-file-name xdrv)))))

(test-assertm "gexp->derivation, store copy"
  (let ((build-one #~(call-with-output-file #$output
                       (lambda (port)
                         (display "This is the one." port))))
        (build-two (lambda (one)
                     #~(begin
                         (mkdir #$output)
                         (symlink #$one (string-append #$output "/one"))
                         (call-with-output-file (string-append #$output "/two")
                           (lambda (port)
                             (display "This is the second one." port))))))
        (build-drv #~(begin
                       (use-modules (guix build store-copy))

                       (mkdir #$output)
                       (populate-store '("graph") #$output))))
    (mlet* %store-monad ((one (gexp->derivation "one" build-one))
                         (two (gexp->derivation "two" (build-two one)))
                         (drv (gexp->derivation "store-copy" build-drv
                                                #:references-graphs
                                                `(("graph" ,two))
                                                #:modules
                                                '((guix build store-copy)
                                                  (guix build utils))))
                         (ok? (built-derivations (list drv)))
                         (out -> (derivation->output-path drv)))
      (let ((one (derivation->output-path one))
            (two (derivation->output-path two)))
        (return (and ok?
                     (file-exists? (string-append out "/" one))
                     (file-exists? (string-append out "/" two))
                     (file-exists? (string-append out "/" two "/two"))
                     (string=? (readlink (string-append out "/" two "/one"))
                               one)))))))

(test-assertm "imported-files"
  (mlet* %store-monad
      ((files -> `(("x"     . ,(search-path %load-path "ice-9/q.scm"))
                   ("a/b/c" . ,(search-path %load-path
                                            "guix/derivations.scm"))
                   ("p/q"   . ,(search-path %load-path "guix.scm"))
                   ("p/z"   . ,(search-path %load-path "guix/store.scm"))))
       (drv (imported-files files)))
    (mbegin %store-monad
      (built-derivations (list drv))
      (let ((dir (derivation->output-path drv)))
        (return
         (every (match-lambda
                 ((path . source)
                  (equal? (call-with-input-file (string-append dir "/" path)
                            get-bytevector-all)
                          (call-with-input-file source
                            get-bytevector-all))))
                files))))))

(test-equal "gexp-modules & ungexp"
  '((bar) (foo))
  ((@@ (guix gexp) gexp-modules)
   #~(foo #$(with-imported-modules '((foo)) #~+)
          #+(with-imported-modules '((bar)) #~-))))

(test-equal "gexp-modules & ungexp-splicing"
  '((foo) (bar))
  ((@@ (guix gexp) gexp-modules)
   #~(foo #$@(list (with-imported-modules '((foo)) #~+)
                   (with-imported-modules '((bar)) #~-)))))

(test-assertm "gexp->derivation #:modules"
  (mlet* %store-monad
      ((build ->  #~(begin
                      (use-modules (guix build utils))
                      (mkdir-p (string-append #$output "/guile/guix/nix"))
                      #t))
       (drv       (gexp->derivation "test-with-modules" build
                                    #:modules '((guix build utils)))))
    (mbegin %store-monad
      (built-derivations (list drv))
      (let* ((p (derivation->output-path drv))
             (s (stat (string-append p "/guile/guix/nix"))))
        (return (eq? (stat:type s) 'directory))))))

(test-assertm "gexp->derivation & with-imported-modules"
  ;; Same test as above, but using 'with-imported-modules'.
  (mlet* %store-monad
      ((build ->  (with-imported-modules '((guix build utils))
                    #~(begin
                        (use-modules (guix build utils))
                        (mkdir-p (string-append #$output "/guile/guix/nix"))
                        #t)))
       (drv       (gexp->derivation "test-with-modules" build)))
    (mbegin %store-monad
      (built-derivations (list drv))
      (let* ((p (derivation->output-path drv))
             (s (stat (string-append p "/guile/guix/nix"))))
        (return (eq? (stat:type s) 'directory))))))

(test-assertm "gexp->derivation & nested with-imported-modules"
  (mlet* %store-monad
      ((build1 ->  (with-imported-modules '((guix build utils))
                     #~(begin
                         (use-modules (guix build utils))
                         (mkdir-p (string-append #$output "/guile/guix/nix"))
                         #t)))
       (build2 ->  (with-imported-modules '((guix build bournish))
                     #~(begin
                         (use-modules (guix build bournish)
                                      (system base compile))
                         #+build1
                         (call-with-output-file (string-append #$output "/b")
                           (lambda (port)
                             (write
                              (read-and-compile (open-input-string "cd /foo")
                                                #:from %bournish-language
                                                #:to 'scheme)
                              port))))))
       (drv        (gexp->derivation "test-with-modules" build2)))
    (mbegin %store-monad
      (built-derivations (list drv))
      (let* ((p (derivation->output-path drv))
             (s (stat (string-append p "/guile/guix/nix")))
             (b (string-append p "/b")))
        (return (and (eq? (stat:type s) 'directory)
                     (equal? '(chdir "/foo")
                             (call-with-input-file b read))))))))

(test-assertm "gexp->derivation #:references-graphs"
  (mlet* %store-monad
      ((one (text-file "one" (random-text)))
       (two (gexp->derivation "two"
                              #~(symlink #$one #$output:chbouib)))
       (build -> (with-imported-modules '((guix build store-copy)
                                          (guix build utils))
                   #~(begin
                       (use-modules (guix build store-copy))
                       (with-output-to-file #$output
                         (lambda ()
                           (write (call-with-input-file "guile"
                                    read-reference-graph))))
                       (with-output-to-file #$output:one
                         (lambda ()
                           (write (call-with-input-file "one"
                                    read-reference-graph))))
                       (with-output-to-file #$output:two
                         (lambda ()
                           (write (call-with-input-file "two"
                                    read-reference-graph)))))))
       (drv (gexp->derivation "ref-graphs" build
                              #:references-graphs `(("one" ,one)
                                                    ("two" ,two "chbouib")
                                                    ("guile" ,%bootstrap-guile))))
       (ok? (built-derivations (list drv)))
       (guile-drv  (package->derivation %bootstrap-guile))
       (bash       (interned-file (search-bootstrap-binary "bash"
                                                           (%current-system))
                                  "bash" #:recursive? #t))
       (g-one   -> (derivation->output-path drv "one"))
       (g-two   -> (derivation->output-path drv "two"))
       (g-guile -> (derivation->output-path drv)))
    (return (and ok?
                 (equal? (call-with-input-file g-one read) (list one))
                 (lset= string=?
                        (call-with-input-file g-two read)
                        (list one (derivation->output-path two "chbouib")))

                 ;; Note: %BOOTSTRAP-GUILE depends on the bootstrap Bash.
                 (lset= string=?
                        (call-with-input-file g-guile read)
                        (list (derivation->output-path guile-drv) bash))))))

(test-assertm "gexp->derivation #:allowed-references"
  (mlet %store-monad ((drv (gexp->derivation "allowed-refs"
                                             #~(begin
                                                 (mkdir #$output)
                                                 (chdir #$output)
                                                 (symlink #$output "self")
                                                 (symlink #$%bootstrap-guile
                                                          "guile"))
                                             #:allowed-references
                                             (list "out" %bootstrap-guile))))
    (built-derivations (list drv))))

(test-assertm "gexp->derivation #:allowed-references, specific output"
  (mlet* %store-monad ((in  (gexp->derivation "thing"
                                              #~(begin
                                                  (mkdir #$output:ok)
                                                  (mkdir #$output:not-ok))))
                       (drv (gexp->derivation "allowed-refs"
                                              #~(begin
                                                  (pk #$in:not-ok)
                                                  (mkdir #$output)
                                                  (chdir #$output)
                                                  (symlink #$output "self")
                                                  (symlink #$in:ok "ok"))
                                              #:allowed-references
                                              (list "out"
                                                    (gexp-input in "ok")))))
    (built-derivations (list drv))))

(test-assert "gexp->derivation #:allowed-references, disallowed"
  (let ((drv (run-with-store %store
               (gexp->derivation "allowed-refs"
                                 #~(begin
                                     (mkdir #$output)
                                     (chdir #$output)
                                     (symlink #$%bootstrap-guile "guile"))
                                 #:allowed-references '()))))
    (guard (c ((nix-protocol-error? c) #t))
      (build-derivations %store (list drv))
      #f)))

(test-assertm "gexp->derivation #:disallowed-references, allowed"
  (mlet %store-monad ((drv (gexp->derivation "disallowed-refs"
                                             #~(begin
                                                 (mkdir #$output)
                                                 (chdir #$output)
                                                 (symlink #$output "self")
                                                 (symlink #$%bootstrap-guile
                                                          "guile"))
                                             #:disallowed-references '())))
    (built-derivations (list drv))))


(test-assert "gexp->derivation #:disallowed-references"
  (let ((drv (run-with-store %store
               (gexp->derivation "disallowed-refs"
                                 #~(begin
                                     (mkdir #$output)
                                     (chdir #$output)
                                     (symlink #$%bootstrap-guile "guile"))
                                 #:disallowed-references (list %bootstrap-guile)))))
    (guard (c ((nix-protocol-error? c) #t))
      (build-derivations %store (list drv))
      #f)))

(define shebang
  (string-append "#!" (derivation->output-path (%guile-for-build))
                 "/bin/guile --no-auto-compile"))

;; If we're going to hit the silly shebang limit (128 chars on Linux-based
;; systems), then skip the following test.
(test-skip (if (> (string-length shebang) 127) 2 0))

(test-assertm "gexp->script"
  (mlet* %store-monad ((n ->   (random (expt 2 50)))
                       (exp -> (gexp
                                (system*
                                 (string-append (ungexp %bootstrap-guile)
                                                "/bin/guile")
                                 "-c" (object->string
                                       '(display (expt (ungexp n) 2))))))
                       (drv    (gexp->script "guile-thing" exp
                                             #:guile %bootstrap-guile))
                       (out -> (derivation->output-path drv))
                       (done   (built-derivations (list drv))))
    (let* ((pipe  (open-input-pipe out))
           (str   (get-string-all pipe)))
      (return (and (zero? (close-pipe pipe))
                   (= (expt n 2) (string->number str)))))))

(test-assertm "program-file"
  (let* ((n      (random (expt 2 50)))
         (exp    (with-imported-modules '((guix build utils))
                   (gexp (begin
                           (use-modules (guix build utils))
                           (display (ungexp n))))))
         (file   (program-file "program" exp
                               #:guile %bootstrap-guile)))
    (mlet* %store-monad ((drv (lower-object file))
                         (out -> (derivation->output-path drv)))
      (mbegin %store-monad
        (built-derivations (list drv))
        (let* ((pipe  (open-input-pipe out))
               (str   (get-string-all pipe)))
          (return (and (zero? (close-pipe pipe))
                       (= n (string->number str)))))))))

(test-assertm "scheme-file"
  (let* ((text   (plain-file "foo" "Hello, world!"))
         (scheme (scheme-file "bar" #~(list "foo" #$text))))
    (mlet* %store-monad ((drv  (lower-object scheme))
                         (text (lower-object text))
                         (out -> (derivation->output-path drv)))
      (mbegin %store-monad
        (built-derivations (list drv))
        (mlet %store-monad ((refs (references* out)))
          (return (and (equal? refs (list text))
                       (equal? `(list "foo" ,text)
                               (call-with-input-file out read)))))))))

(test-assert "text-file*"
  (run-with-store %store
    (mlet* %store-monad
        ((drv  (package->derivation %bootstrap-guile))
         (guile -> (derivation->output-path drv))
         (file (text-file "bar" "This is bar."))
         (text (text-file* "foo"
                           %bootstrap-guile "/bin/guile "
                           (gexp-input %bootstrap-guile "out") "/bin/guile "
                           drv "/bin/guile "
                           file))
         (done (built-derivations (list text)))
         (out -> (derivation->output-path text))
         (refs (references* out)))
      ;; Make sure we get the right references and the right content.
      (return (and (lset= string=? refs (list guile file))
                   (equal? (call-with-input-file out get-string-all)
                           (string-append guile "/bin/guile "
                                          guile "/bin/guile "
                                          guile "/bin/guile "
                                          file)))))
    #:guile-for-build (package-derivation %store %bootstrap-guile)))

(test-assertm "mixed-text-file"
  (mlet* %store-monad ((file ->   (mixed-text-file "mixed"
                                                   "export PATH="
                                                   %bootstrap-guile "/bin"))
                       (drv       (lower-object file))
                       (out ->    (derivation->output-path drv))
                       (guile-drv (package->derivation %bootstrap-guile))
                       (guile ->  (derivation->output-path guile-drv)))
    (mbegin %store-monad
      (built-derivations (list drv))
      (mlet %store-monad ((refs (references* out)))
        (return (and (string=? (string-append "export PATH=" guile "/bin")
                               (call-with-input-file out get-string-all))
                     (equal? refs (list guile))))))))

(test-assert "gexp->derivation vs. %current-target-system"
  (let ((mval (gexp->derivation "foo"
                                #~(begin
                                    (mkdir #$output)
                                    (foo #+gnu-make))
                                #:target #f)))
    ;; The value of %CURRENT-TARGET-SYSTEM at bind-time should have no
    ;; influence.
    (parameterize ((%current-target-system "fooooo"))
      (derivation? (run-with-store %store mval)))))

(test-assertm "lower-object"
  (mlet %store-monad ((drv1 (lower-object %bootstrap-guile))
                      (drv2 (lower-object (package-source coreutils)))
                      (item (lower-object (plain-file "foo" "Hello!"))))
    (return (and (derivation? drv1) (derivation? drv2)
                 (store-path? item)))))

(test-assertm "lower-object, computed-file"
  (let* ((text     (plain-file "foo" "Hello!"))
         (exp      #~(begin
                       (mkdir #$output)
                       (symlink #$%bootstrap-guile
                                (string-append #$output "/guile"))
                       (symlink #$text (string-append #$output "/text"))))
         (computed (computed-file "computed" exp)))
    (mlet* %store-monad ((text      (lower-object text))
                         (guile-drv (lower-object %bootstrap-guile))
                         (comp-drv  (lower-object computed))
                         (comp ->   (derivation->output-path comp-drv)))
      (mbegin %store-monad
        (built-derivations (list comp-drv))
        (return (and (string=? (readlink (string-append comp "/guile"))
                               (derivation->output-path guile-drv))
                     (string=? (readlink (string-append comp "/text"))
                               text)))))))

(test-assert "printer"
  (string-match "^#<gexp \\(string-append .*#<package coreutils.*\
 \"/bin/uname\"\\) [[:xdigit:]]+>$"
                (with-output-to-string
                  (lambda ()
                    (write
                     (gexp (string-append (ungexp coreutils)
                                          "/bin/uname")))))))

(test-assert "printer vs. ungexp-splicing"
  (string-match "^#<gexp .* [[:xdigit:]]+>$"
                (with-output-to-string
                  (lambda ()
                    ;; #~(begin #$@#~())
                    (write
                     (gexp (begin (ungexp-splicing (gexp ())))))))))

(test-equal "sugar"
  '(gexp (foo (ungexp bar) (ungexp baz "out")
              (ungexp (chbouib 42))
              (ungexp-splicing (list x y z))
              (ungexp-native foo) (ungexp-native foo "out")
              (ungexp-native (chbouib 42))
              (ungexp-native-splicing (list x y z))))
  '#~(foo #$bar #$baz:out #$(chbouib 42) #$@(list x y z)
          #+foo #+foo:out #+(chbouib 42) #+@(list x y z)))

(test-end "gexp")

;; Local Variables:
;; eval: (put 'test-assertm 'scheme-indent-function 1)
;; End:
