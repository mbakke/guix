;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Cyril Roelandt <tipecaml@gmail.com>
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

(define-module (gnu packages vim)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages gawk)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages admin) ; For GNU hostname
  #:use-module (gnu packages shells))

(define-public vim
  (package
    (name "vim")
    (version "7.4")
    (source (origin
             (method url-fetch)
             (uri (string-append "ftp://ftp.vim.org/pub/vim/unix/vim-"
                                 version ".tar.bz2"))
             (sha256
              (base32
               "1pjaffap91l2rb9pjnlbrpvb3ay5yhhr3g91zabjvw1rqk9adxfh"))))
    (build-system gnu-build-system)
    (arguments
     `(#:test-target "test"
       #:parallel-tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-after 'configure 'patch-config-files
           (lambda _
             (substitute* "runtime/tools/mve.awk"
               (("/usr/bin/nawk") (which "gawk")))
             (substitute* "src/testdir/Makefile"
               (("/bin/sh") (which "sh"))))))))
    (inputs
     `(("gawk" ,gawk)
       ("inetutils" ,inetutils)
       ("ncurses" ,ncurses)
       ("perl" ,perl)
       ("tcsh" ,tcsh))) ; For runtime/tools/vim32
    (home-page "http://www.vim.org/")
    (synopsis "Text editor based on vi")
    (description
     "Vim is a highly configurable text editor built to enable efficient text
editing.  It is an improved version of the vi editor distributed with most UNIX
systems.

Vim is often called a \"programmer's editor,\" and so useful for programming
that many consider it an entire IDE.  It's not just for programmers, though.
Vim is perfect for all kinds of text editing, from composing email to editing
configuration files.")
    (license license:vim)))
