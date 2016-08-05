;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
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

(define-module (gnu packages readline)
  #:use-module (guix licenses)
  #:use-module (gnu packages)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages perl)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu))

(define-public readline
  (let ((post-install-phase
         '(lambda* (#:key outputs #:allow-other-keys)
            (let* ((out (assoc-ref outputs "out"))
                   (lib (string-append out "/lib")))
              ;; Make libraries writable so that `strip' can work.
              ;; Failing to do that, it bails out with "Permission
              ;; denied".
              (for-each (lambda (f) (chmod f #o755))
                        (find-files lib "\\.so"))
              (for-each (lambda (f) (chmod f #o644))
                        (find-files lib "\\.a"))))))
    (package
      (name "readline")
      (version "6.3")
      (source (origin
               (method url-fetch)
               (uri (string-append "mirror://gnu/readline/readline-"
                                   version ".tar.gz"))
               (sha256
                (base32
                 "0hzxr9jxqqx5sxsv9vmlxdnvlr9vi4ih1avjb869hbs6p5qn1fjn"))
               (patches (search-patches "readline-link-ncurses.patch"))
               (patch-flags '("-p0"))))
      (build-system gnu-build-system)
      (propagated-inputs `(("ncurses" ,ncurses)))
      (arguments `(#:configure-flags
                   (list (string-append "LDFLAGS=-Wl,-rpath -Wl,"
                                        (assoc-ref %build-inputs "ncurses")
                                        "/lib")

                         ;; This test does an 'AC_TRY_RUN', which aborts when
                         ;; cross-compiling, so provide the correct answer.
                         ,@(if (%current-target-system)
                               '("bash_cv_wcwidth_broken=no")
                               '()))

                   #:phases (alist-cons-after
                             'install 'post-install
                             ,post-install-phase
                             %standard-phases)))
      (synopsis "Edit command lines while typing, with history support")
      (description
       "The GNU readline library allows users to edit command lines as they
are typed in.  It can maintain a searchable history of previously entered
commands, letting you easily recall, edit and re-enter past commands.  It
features both Emacs-like and vi-like keybindings, making its usage
comfortable for anyone.")
      (license gpl3+)
      (home-page "http://savannah.gnu.org/projects/readline/"))))

(define-public readline-6.2
  (package (inherit readline)
    (version "6.2")
    (source (origin (inherit (package-source readline))
              (method url-fetch)
              (uri (string-append "mirror://gnu/readline/readline-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "10ckm2bd2rkxhvdmj7nmbsylmihw0abwcsnxf8y27305183rd9kr"))))))

(define-public rlwrap
  (package
    (name "rlwrap")
    (version "0.42")
    (source
      (origin
        (method url-fetch)
        (uri (string-append "http://utopia.knoware.nl/~hlub/uck/rlwrap/rlwrap-"
                            version ".tar.gz"))
        (sha256
         (base32
          "0i3yz303wscrysyzpdq04h4nrl9ajz9dbwi80risdl5rkm3dhw2s"))))
    (build-system gnu-build-system)
    (native-inputs `(("perl" ,perl)))
    (inputs
     `(("readline" ,readline)))
    (synopsis "Wrapper to allow the editing of keyboard commands")
    (description
     "Rlwrap is a 'readline wrapper', a small utility that uses the GNU
readline library to allow the editing of keyboard input for any command.  You
should consider rlwrap especially when you need user-defined completion (by way
of completion word lists) and persistent history, or if you want to program
'special effects' using the filter mechanism.")
    (home-page "http://utopia.knoware.nl/~hlub/uck/rlwrap/")
    (license gpl2+)))
