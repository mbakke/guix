;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Taylan Ulrich Bayirli/Kammer <taylanbayirli@gmail.com>
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014, 2015, 2016 Alex Kost <alezost@gmail.com>
;;; Copyright © 2015 Federico Beffa <beffa@fbengineering.ch>
;;; Copyright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Chris Marusich <cmmarusich@gmail.com>
;;; Copyright © 2015, 2016 Christopher Allan Webber <cwebber@dustycloud.org>
;;; Copyright © 2016 humanitiesNerd <catonano@gmail.com>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 David Thompson <davet@gnu.org>
;;; Copyright © 2016 Matthew Jordan <matthewjordandevops@yandex.com>
;;; Copyright © 2016 Roel Janssen <roel@gnu.org>
;;; Copyright © 2016 ng0 <ng0@we.make.ritual.n0.is>
;;; Copyright © 2016 Alex Griffin <a@ajgrf.com>
;;; Copyright © 2016 Nicolas Goaziou <mail@nicolasgoaziou.fr>
;;; Copyright © 2016 Alex Vong <alexvong1995@gmail.com>
;;; Copyright © 2016 Arun Isaac <arunisaac@systemreboot.net>
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

(define-module (gnu packages emacs)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix gexp)
  #:use-module (guix monads)
  #:use-module (guix store)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system emacs)
  #:use-module (guix build-system glib-or-gtk)
  #:use-module (guix build-system trivial)
  #:use-module (gnu packages)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages lesstif)
  #:use-module (gnu packages image)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages version-control)
  #:use-module (gnu packages imagemagick)
  #:use-module (gnu packages w3m)
  #:use-module (gnu packages wget)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages base)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages acl)
  #:use-module (gnu packages package-management)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pdf)
  #:use-module (gnu packages scheme)
  #:use-module (gnu packages statistics)
  #:use-module (gnu packages xiph)
  #:use-module (gnu packages mp3)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages fribidi)
  #:use-module (gnu packages gd)
  #:use-module (gnu packages fontutils)
  #:use-module (guix utils)
  #:use-module (srfi srfi-1))

(define-public emacs
  (package
    (name "emacs")
    (version "25.1")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/emacs/emacs-"
                                 version ".tar.xz"))
             (sha256
              (base32
               "0cwgyiyymnx4xdg99dm2drfxcyhy2jmyf0rkr9fwj9mwwf77kwhr"))
             (patches (search-patches "emacs-exec-path.patch"
                                      "emacs-fix-scheme-indent-function.patch"
                                      "emacs-source-date-epoch.patch"))
             (modules '((guix build utils)))
             (snippet
              ;; Delete the bundled byte-compiled elisp files and
              ;; generated autoloads.
              '(with-directory-excursion "lisp"
                 (for-each delete-file
                           (append (find-files "." "\\.elc$")
                                   (find-files "." "loaddefs\\.el$")
                                   ;; This is the only "autoloads" file that
                                   ;; does not have "*loaddefs.el" name.
                                   '("eshell/esh-groups.el")))))))
    (build-system glib-or-gtk-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'configure 'fix-/bin/pwd
           (lambda _
             ;; Use `pwd', not `/bin/pwd'.
             (substitute* (find-files "." "^Makefile\\.in$")
               (("/bin/pwd")
                "pwd"))))
         (add-after 'install 'install-site-start
           ;; Copy guix-emacs.el from Guix and add it to site-start.el.  This
           ;; way, Emacs packages provided by Guix and installed in
           ;; ~/.guix-profile/share/emacs/site-lisp/guix.d/PACKAGE-VERSION are
           ;; automatically found.
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((guix-src (assoc-ref inputs "guix-src"))
                    (out      (assoc-ref outputs "out"))
                    (lisp-dir (string-append out "/share/emacs/site-lisp"))
                    (unpack   (assoc-ref %standard-phases 'unpack)))
               (mkdir "guix")
               (with-directory-excursion "guix"
                 (apply unpack (list #:source guix-src))
                 (install-file "emacs/guix-emacs.el" lisp-dir))
               (with-output-to-file (string-append lisp-dir "/site-start.el")
                 (lambda ()
                   (display "(require 'guix-emacs nil t)")))
               #t))))))
    (inputs
     `(("gnutls" ,gnutls)
       ("ncurses" ,ncurses)

       ;; TODO: Add the optional dependencies.
       ("libx11" ,libx11)
       ("gtk+" ,gtk+)
       ("libxft" ,libxft)
       ("libtiff" ,libtiff)
       ("giflib" ,giflib)
       ("libjpeg" ,libjpeg-8)
       ("acl" ,acl)

       ;; When looking for libpng `configure' links with `-lpng -lz', so we
       ;; must also provide zlib as an input.
       ("libpng" ,libpng)
       ("zlib" ,zlib)

       ("librsvg" ,librsvg)
       ("libxpm" ,libxpm)
       ("libxml2" ,libxml2)
       ("libice" ,libice)
       ("libsm" ,libsm)
       ("alsa-lib" ,alsa-lib)
       ("dbus" ,dbus)
       ("guix-src" ,(package-source guix))

       ;; multilingualization support
       ("libotf" ,libotf)
       ("m17n-lib" ,m17n-lib)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("texinfo" ,texinfo)))

    (native-search-paths
     (list (search-path-specification
            (variable "INFOPATH")
            (files '("share/info")))))

    (home-page "http://www.gnu.org/software/emacs/")
    (synopsis "The extensible, customizable, self-documenting text editor")
    (description
     "GNU Emacs is an extensible and highly customizable text editor.  It is
based on an Emacs Lisp interpreter with extensions for text editing.  Emacs
has been extended in essentially all areas of computing, giving rise to a
vast array of packages supporting, e.g., email, IRC and XMPP messaging,
spreadsheets, remote server editing, and much more.  Emacs includes extensive
documentation on all aspects of the system, from basic editing to writing
large Lisp programs.  It has full Unicode support for nearly all human
languages.")
    (license license:gpl3+)))

(define-public emacs-minimal
  ;; This is the version that you should use as an input to packages that just
  ;; need to byte-compile .el files.
  (package (inherit emacs)
    (name "emacs-minimal")
    (synopsis "The extensible text editor (used only for byte-compilation)")
    (build-system gnu-build-system)
    (arguments
     (substitute-keyword-arguments (package-arguments emacs)
       ((#:phases phases)
        `(modify-phases ,phases
           (delete 'install-site-start)))))
    (inputs
     `(("ncurses" ,ncurses)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))))

(define-public emacs-no-x
  (package (inherit emacs)
    (name "emacs-no-x")
    (synopsis "The extensible, customizable, self-documenting text
editor (console only)")
    (build-system gnu-build-system)
    (inputs (fold alist-delete
                  (package-inputs emacs)
                  '("libx11" "gtk+" "libxft" "libtiff" "giflib" "libjpeg"
                    "libpng" "librsvg" "libxpm" "libice" "libsm"

                    ;; D-Bus depends on libx11, so remove it as well.
                    "dbus")))))

(define-public emacs-no-x-toolkit
  (package (inherit emacs)
    (name "emacs-no-x-toolkit")
    (synopsis "The extensible, customizable, self-documenting text
editor (without an X toolkit)" )
    (build-system gnu-build-system)
    (inputs (append `(("inotify-tools" ,inotify-tools))
                    (alist-delete "gtk+" (package-inputs emacs))))
    (arguments (append '(#:configure-flags '("--with-x-toolkit=no"))
                       (package-arguments emacs)))))

(define-public guile-emacs
  (package (inherit emacs)
    (name "guile-emacs")
    (version "20150512.41120e0")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "git://git.hcoop.net/git/bpt/emacs.git")
                    (commit "41120e0f595b16387eebfbf731fff70481de1b4b")))
              (sha256
               (base32
                "0lvcvsz0f4mawj04db35p1dvkffdqkz8pkhc0jzh9j9x2i63kcz6"))))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("guile" ,guile-for-guile-emacs)
       ,@(package-native-inputs emacs)))
    (arguments
     (substitute-keyword-arguments `(;; Build fails if we allow parallel build.
                                     #:parallel-build? #f
                                     ;; Tests aren't passing for now.
                                     #:tests? #f
                                     ,@(package-arguments emacs))
       ((#:phases phases)
        `(modify-phases ,phases
           (add-after 'unpack 'autogen
                      (lambda _
                        (zero? (system* "sh" "autogen.sh"))))))))))


;;;
;;; Emacs hacking.
;;;

(define-public geiser
  (package
    (name "geiser")
    (version "0.9")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://savannah/geiser/" version
                                 "/geiser-" version ".tar.gz"))
             (sha256
              (base32
               "0phz9d8wjk4p13vqannv0003fwh8qqrp0gfzcs2hgq1mrmv1srss"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (alist-cons-after
                 'install 'post-install
                 (lambda* (#:key outputs #:allow-other-keys)
                   (symlink "geiser-install.el"
                            (string-append (assoc-ref outputs "out")
                                           "/share/emacs/site-lisp/"
                                           "geiser-autoloads.el")))
                 %standard-phases)))
    (inputs `(("guile" ,guile-2.0)))
    (native-inputs `(("emacs" ,emacs-minimal)))
    (home-page "http://nongnu.org/geiser/")
    (synopsis "Collection of Emacs modes for Guile and Racket hacking")
    (description
     "Geiser is a collection of Emacs major and minor modes that conspire with
one or more Scheme implementations to keep the Lisp Machine Spirit alive.  The
continuously running Scheme interpreter takes the center of the stage in
Geiser.  A bundle of Elisp shims orchestrates the dialog between the Scheme
implementation, Emacs and, ultimately, the schemer, giving them access to live
metadata.")
    (license license:bsd-3)))

(define-public geiser-next
  ;; This has become "geiser".
  (deprecated-package "geiser-next" geiser))

(define-public paredit
  (package
    (name "emacs-paredit")
    (version "24")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://mumble.net/~campbell/emacs/paredit-"
                                  version ".el"))
              (sha256
               (base32
                "0pp3n8q6kc70blqsaw0zlzp6bc327dpgdrjr0cnh7hqg1lras7ka"))))
    (build-system trivial-build-system)
    (native-inputs `(("emacs" ,emacs-minimal)))
    (arguments
     `(#:modules ((guix build utils)
                  (guix build emacs-utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (use-modules (guix build emacs-utils))

         (let* ((emacs    (string-append (assoc-ref %build-inputs "emacs")
                                         "/bin/emacs"))
                (source   (assoc-ref %build-inputs "source"))
                (lisp-dir (string-append %output
                                         "/share/emacs/site-lisp"))
                (target   (string-append lisp-dir "/paredit.el")))
           (mkdir-p lisp-dir)
           (copy-file source target)
           (with-directory-excursion lisp-dir
             (parameterize ((%emacs emacs))
               (emacs-generate-autoloads ,name lisp-dir)
               (emacs-batch-eval '(byte-compile-file "paredit.el"))))))))
    (home-page "http://mumble.net/~campbell/emacs/paredit/")
    (synopsis "Emacs minor mode for editing parentheses")
    (description
     "ParEdit (paredit.el) is a minor mode for performing structured editing
of S-expression data.  The typical example of this would be Lisp or Scheme
source code.

ParEdit helps **keep parentheses balanced** and adds many keys for moving
S-expressions and moving around in S-expressions.  Its behavior can be jarring
for those who may want transient periods of unbalanced parentheses, such as
when typing parentheses directly or commenting out code line by line.")
    (license license:gpl3+)))

(define-public paredit/old-name
  (deprecated-package "paredit" paredit))

(define-public git-modes
  (package
    (name "git-modes")
    (version "1.2.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/magit/git-modes/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0gb9c18jib8rpm14vig9774104lwmd8353ps0259m861syf6664d"))))
    (build-system gnu-build-system)
    (arguments
     `(#:modules ((guix build gnu-build-system)
                  (guix build emacs-utils)
                  (guix build utils))
       #:imported-modules (,@%gnu-build-system-modules
                           (guix build emacs-utils))

       #:make-flags (list (string-append "PREFIX="
                                         (assoc-ref %outputs "out"))
                          ;; Don't put .el files in a 'git-modes'
                          ;; sub-directory.
                          (string-append "LISPDIR="
                                         (assoc-ref %outputs "out")
                                         "/share/emacs/site-lisp"))
       #:tests? #f  ; no check target
       #:phases (modify-phases %standard-phases
                  (delete 'configure)
                  (add-after 'install 'emacs-autoloads
                             (lambda* (#:key outputs #:allow-other-keys)
                               (let* ((out  (assoc-ref outputs "out"))
                                      (lisp (string-append
                                             out "/share/emacs/site-lisp/")))
                                 (emacs-generate-autoloads ,name lisp)))))))
    (native-inputs `(("emacs" ,emacs-minimal)))
    (home-page "https://github.com/magit/git-modes")
    (synopsis "Emacs major modes for Git configuration files")
    (description
     "This package provides Emacs major modes for editing various Git
configuration files, such as .gitattributes, .gitignore, and .git/config.")
    (license license:gpl3+)))

(define-public emacs-with-editor
  (package
    (name "emacs-with-editor")
    (version "2.5.8")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/magit/with-editor/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1dghd0m5zwayv553g4cr990s4ig5lyh0b52qfdv5rbqnndpj3cjn"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-dash" ,emacs-dash)))
    (home-page "https://github.com/magit/with-editor")
    (synopsis "Emacs library for using Emacsclient as EDITOR")
    (description
     "This package provides an Emacs library to use the Emacsclient as
@code{$EDITOR} of child processes, making sure they know how to call home.
For remote processes a substitute is provided, which communicates with Emacs
on stdout instead of using a socket as the Emacsclient does.")
    (license license:gpl3+)))

(define-public magit
  (package
    (name "magit")
    (version "2.8.0")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "https://github.com/magit/magit/releases/download/"
                   version "/" name "-" version ".tar.gz"))
             (sha256
              (base32
               "1znvb7inwinrhifqzwp4lp9j6yp1l25j7riczc0zmvcjbpl5yhfq"))))
    (build-system gnu-build-system)
    (native-inputs `(("texinfo" ,texinfo)
                     ("emacs" ,emacs-minimal)))
    (inputs
     `(("git" ,git)
       ("perl" ,perl)))
    (propagated-inputs
     `(("dash" ,emacs-dash)
       ("with-editor" ,emacs-with-editor)))
    (arguments
     `(#:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (guix build emacs-utils))
       #:imported-modules (,@%gnu-build-system-modules
                           (guix build emacs-utils))

       #:test-target "test"
       #:tests? #f               ; tests are not included in the release

       #:make-flags
       (list (string-append "PREFIX=" %output)
             ;; Don't put .el files in a sub-directory.
             (string-append "lispdir=" %output "/share/emacs/site-lisp")
             (string-append "DASH_DIR="
                            (assoc-ref %build-inputs "dash")
                            "/share/emacs/site-lisp/guix.d/dash-"
                            ,(package-version emacs-dash))
             (string-append "WITH_EDITOR_DIR="
                            (assoc-ref %build-inputs "with-editor")
                            "/share/emacs/site-lisp/guix.d/with-editor-"
                            ,(package-version emacs-with-editor)))

       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (add-before
          'build 'patch-exec-paths
          (lambda* (#:key inputs #:allow-other-keys)
            (let ((git  (assoc-ref inputs "git"))
                  (perl (assoc-ref inputs "perl")))
              (emacs-substitute-variables "lisp/magit-git.el"
                ("magit-git-executable" (string-append git "/bin/git")))
              (substitute* "lisp/magit-sequence.el"
                (("perl") (string-append perl "/bin/perl")))
              #t))))))
    (home-page "http://magit.github.io/")
    (synopsis "Emacs interface for the Git version control system")
    (description
     "With Magit, you can inspect and modify your Git repositories with Emacs.
You can review and commit the changes you have made to the tracked files, for
example, and you can browse the history of past changes.  There is support for
cherry picking, reverting, merging, rebasing, and other common Git
operations.")
    (license license:gpl3+)))

(define-public magit-svn
  (package
    (name "magit-svn")
    (version "2.1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/magit/magit-svn/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "04y88j7q9h8xjbx5dbick6n5nr1522sn9i1znp0qwk3vjb4b5mzz"))))
    (build-system trivial-build-system)
    (native-inputs `(("emacs" ,emacs-minimal)
                     ("tar" ,tar)
                     ("gzip" ,gzip)))
    (propagated-inputs `(("dash" ,emacs-dash)
                         ("magit" ,magit)))
    (arguments
     `(#:modules ((guix build utils)
                  (guix build emacs-utils))

       #:builder
       (begin
         (use-modules (guix build utils)
                      (guix build emacs-utils))

         (let* ((tar      (string-append (assoc-ref %build-inputs "tar")
                                         "/bin/tar"))
                (PATH     (string-append (assoc-ref %build-inputs "gzip")
                                         "/bin"))
                (emacs    (string-append (assoc-ref %build-inputs "emacs")
                                         "/bin/emacs"))
                (magit    (string-append (assoc-ref %build-inputs "magit")
                                         "/share/emacs/site-lisp"))
                (dash     (string-append (assoc-ref %build-inputs "dash")
                                         "/share/emacs/site-lisp/guix.d/dash-"
                                         ,(package-version emacs-dash)))
                (source   (assoc-ref %build-inputs "source"))
                (lisp-dir (string-append %output "/share/emacs/site-lisp")))
           (setenv "PATH" PATH)
           (system* tar "xvf" source)

           (install-file (string-append ,name "-" ,version "/magit-svn.el")
                         lisp-dir)

           (with-directory-excursion lisp-dir
             (parameterize ((%emacs emacs))
               (emacs-generate-autoloads ,name lisp-dir)
               (setenv "EMACSLOADPATH"
                       (string-append ":" magit ":" dash))
               (emacs-batch-eval '(byte-compile-file "magit-svn.el"))))))))
    (home-page "https://github.com/magit/magit-svn")
    (synopsis "Git-SVN extension to Magit")
    (description
     "This package is an extension to Magit, the Git Emacs mode, providing
support for Git-SVN.")
    (license license:gpl3+)))

(define-public emacs-magit-popup
  (package
    (name "emacs-magit-popup")
    (version (package-version magit))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://raw.githubusercontent.com/magit/magit/"
                    version "/lisp/magit-popup.el"))
              (file-name (string-append "magit-popup-" version ".el"))
              (sha256
               (base32
                "0lmw824zp8c0vhikfkiay9wn4nmaksz6mfy0fldvy4wlx5c26yh3"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-dash" ,emacs-dash)))
    (home-page "https://github.com/magit/magit")
    (synopsis "Define prefix-infix-suffix command combos")
    (description
     "This library implements a generic interface for toggling switches and
setting options and then invoking an Emacs command which does something with
these arguments.  The prototypical use is for the command to call an external
process, passing on the arguments as command line arguments.")
    (license license:gpl3+)))

(define-public haskell-mode
  (package
    (name "haskell-mode")
    (version "16.1")
    (source (origin
              (method url-fetch)
              (file-name (string-append name "-" version ".tar.gz"))
              (uri (string-append
                    "https://github.com/haskell/haskell-mode/archive/v"
                    version ".tar.gz"))
              (sha256
               (base32 "0g6lcjw7lcgavv3yrd8xjcyqgfyjl787y32r1z14amw2f009m78h"))))
    (inputs
     `(("emacs-el-search" ,emacs-el-search) ; for tests
       ("emacs-stream" ,emacs-stream)))     ; for tests
    (propagated-inputs
     `(("emacs-dash" ,emacs-dash)))
    (native-inputs
     `(("emacs" ,emacs-minimal)
       ("texinfo" ,texinfo)))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags (list (string-append "EMACS="
                                         (assoc-ref %build-inputs "emacs")
                                         "/bin/emacs"))
       #:modules ((ice-9 match)
                  (srfi srfi-26)
                  ,@%gnu-build-system-modules)
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (add-before
          'build 'pre-build
          (lambda* (#:key inputs #:allow-other-keys)
            (define (el-dir store-dir)
              (match (find-files store-dir)
                ((f1 f2 ...) (dirname f1))
                (_ "")))

            (let ((sh (string-append (assoc-ref inputs "bash") "/bin/sh")))
              (define emacs-prefix? (cut string-prefix? "emacs-" <>))

              (setenv "SHELL" "sh")
              (setenv "EMACSLOADPATH"
                      (string-concatenate
                       (map (match-lambda
                              (((? emacs-prefix? name) . dir)
                               (string-append (el-dir dir) ":"))
                              (_ ""))
                            inputs)))
              (substitute* (find-files "." "\\.el") (("/bin/sh") sh))
              (substitute* "tests/haskell-code-conventions.el"
                ;; Function name recently changed in "emacs-el-search".
                (("el-search--search-pattern") "el-search-forward")
                ;; Don't contact home.
                (("\\(when \\(>= emacs-major-version 25\\)")
                 "(require 'el-search) (when nil"))
              #t)))
         (replace
          'install
          (lambda* (#:key outputs #:allow-other-keys)
            (let* ((out (assoc-ref outputs "out"))
                   (el-dir (string-append out "/share/emacs/site-lisp"))
                   (doc (string-append
                         out "/share/doc/haskell-mode-" ,version))
                   (info (string-append out "/share/info")))
              (define (copy-to-dir dir files)
                (for-each (lambda (f)
                            (install-file f dir))
                          files))

              (with-directory-excursion "doc"
                (unless (zero? (system* "makeinfo" "haskell-mode.texi"))
                  (error "makeinfo failed"))
                (install-file "haskell-mode.info" info))
               (copy-to-dir doc '("CONTRIBUTING.md" "NEWS" "README.md"))
               (copy-to-dir el-dir (find-files "." "\\.elc?"))
               ;; These are part of other packages.
               (with-directory-excursion el-dir
                 (for-each delete-file '("dash.el" "ert.el")))
               #t))))))
    (home-page "https://github.com/haskell/haskell-mode")
    (synopsis "Haskell mode for Emacs")
    (description
     "This is an Emacs mode for editing, debugging and developing Haskell
programs.")
    (license license:gpl3+)))

(define-public let-alist
  (package
    (name "emacs-let-alist")
    (version "1.0.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://elpa.gnu.org/packages/let-alist-"
                                  version ".el"))
              (sha256
               (base32
                "07312bvvyz86lf64vdkxg2l1wgfjl25ljdjwlf1bdzj01c4hm88x"))))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils)
                  (guix build emacs-utils))

       #:builder (begin
                   (use-modules (guix build emacs-utils)
                                (guix build utils))

                   (let* ((out     (assoc-ref %outputs "out"))
                          (lispdir (string-append out
                                                  "/share/emacs/site-lisp/"
                                                  "guix.d/let-alist-"
                                                  ,version))
                          (emacs   (assoc-ref %build-inputs "emacs")))

                     (mkdir-p lispdir)
                     (copy-file (assoc-ref %build-inputs "source")
                                (string-append lispdir "/let-alist.el"))

                     (setenv "PATH" (string-append emacs "/bin"))
                     (emacs-byte-compile-directory lispdir)
                     #t))))
    (native-inputs `(("emacs" ,emacs-minimal)))
    (home-page "https://elpa.gnu.org/packages/let-alist.html")
    (synopsis "Easily let-bind values of an assoc-list by their names")
    (description
     "This package offers a single Emacs Lisp macro, @code{let-alist}.  This
macro takes a first argument, whose value must be an alist (association list),
and a body.

The macro expands to a let form containing the body, where each dotted symbol
inside body is let-bound to their cdrs in the alist.  Only those present in
the body are let-bound and this search is done at compile time.")
    (license license:gpl3+)))

(define-public flycheck
  (package
    (name "emacs-flycheck")
    (version "28")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/flycheck/flycheck/releases/download/"
                    version "/flycheck-" version ".tar"))
              (sha256
               (base32
                "1yjxivk11d7w39zfhj2xr4h6xhwx1aj6yhyzd63rjrad7xpjfl86"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-dash" ,emacs-dash)
       ("emacs-let-alist" ,let-alist)
       ("emacs-seq" ,emacs-seq)))
    (home-page "https://www.flycheck.org")
    (synopsis "On-the-fly syntax checking")
    (description
     "This package provides on-the-fly syntax checking for GNU Emacs.  It is a
replacement for the older Flymake extension which is part of GNU Emacs, with
many improvements and additional features.

Flycheck provides fully-automatic, fail-safe, on-the-fly background syntax
checking for over 30 programming and markup languages with more than 70
different tools.  It highlights errors and warnings inline in the buffer, and
provides an optional IDE-like error list.")
    (license license:gpl3+)))                     ;+GFDLv1.3+ for the manual


;;;
;;; Web browsing.
;;;

(define-public emacs-w3m
  (package
    (name "emacs-w3m")
    (version "1.4.538+0.20141022")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://debian/pool/main/w/w3m-el/w3m-el_"
                                 version ".orig.tar.gz"))
             (sha256
              (base32
               "0zfxmq86pwk64yv0426gnjrvhjrgrjqn08sdcdhmmjmfpmqvm79y"))))
    (build-system gnu-build-system)
    (native-inputs `(("autoconf" ,autoconf)
                     ("emacs" ,emacs-minimal)))
    (inputs `(("w3m" ,w3m)
              ("imagemagick" ,imagemagick)))
    (arguments
     `(#:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (guix build emacs-utils))
       #:imported-modules (,@%gnu-build-system-modules
                           (guix build emacs-utils))
       #:configure-flags
       (let ((out (assoc-ref %outputs "out")))
         (list (string-append "--with-lispdir="
                              out "/share/emacs/site-lisp")
               (string-append "--with-icondir="
                              out "/share/images/emacs-w3m")
               ;; Leave .el files uncompressed, otherwise GC can't
               ;; identify run-time dependencies.  See
               ;; <http://lists.gnu.org/archive/html/guix-devel/2015-12/msg00208.html>
               "--without-compress-install"))
       #:tests? #f  ; no check target
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'autoconf
           (lambda _
             (zero? (system* "autoconf"))))
         (add-before 'build 'patch-exec-paths
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out"))
                   (w3m (assoc-ref inputs "w3m"))
                   (imagemagick (assoc-ref inputs "imagemagick"))
                   (coreutils (assoc-ref inputs "coreutils")))
               (emacs-substitute-variables "w3m.el"
                 ("w3m-command" (string-append w3m "/bin/w3m"))
                 ("w3m-touch-command"
                  (string-append coreutils "/bin/touch"))
                 ("w3m-image-viewer"
                  (string-append imagemagick "/bin/display"))
                 ("w3m-icon-directory"
                  (string-append out "/share/images/emacs-w3m")))
               (emacs-substitute-variables "w3m-image.el"
                 ("w3m-imagick-convert-program"
                  (string-append imagemagick "/bin/convert"))
                 ("w3m-imagick-identify-program"
                  (string-append imagemagick "/bin/identify")))
               #t)))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (and (zero? (system* "make" "install" "install-icons"))
                  (with-directory-excursion
                      (string-append (assoc-ref outputs "out")
                                     "/share/emacs/site-lisp")
                    (for-each delete-file '("ChangeLog" "ChangeLog.1"))
                    (symlink "w3m-load.el" "w3m-autoloads.el")
                    #t)))))))
    (home-page "http://emacs-w3m.namazu.org/")
    (synopsis "Simple Web browser for Emacs based on w3m")
    (description
     "Emacs-w3m is an emacs interface for the w3m web browser.")
    (license license:gpl2+)))

(define-public emacs-wget
  (package
    (name "emacs-wget")
    (version "0.5.0")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://debian/pool/main/w/wget-el/wget-el_"
                                 version ".orig.tar.gz"))
             (sha256
              (base32 "10byvyv9dk0ib55gfqm7bcpxmx2qbih1jd03gmihrppr2mn52nff"))))
    (build-system gnu-build-system)
    (inputs `(("wget" ,wget)))
    (native-inputs `(("emacs" ,emacs-minimal)))
    (arguments
     `(#:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (guix build emacs-utils))
       #:imported-modules (,@%gnu-build-system-modules
                           (guix build emacs-utils))
       #:tests? #f  ; no check target
       #:phases
       (alist-replace
        'configure
        (lambda* (#:key outputs #:allow-other-keys)
          (substitute* "Makefile"
            (("/usr/local") (assoc-ref outputs "out"))
            (("/site-lisp/emacs-wget") "/site-lisp")))
        (alist-cons-before
         'build 'patch-exec-paths
         (lambda* (#:key inputs outputs #:allow-other-keys)
           (let ((wget (assoc-ref inputs "wget")))
             (emacs-substitute-variables "wget.el"
               ("wget-command" (string-append wget "/bin/wget")))))
         (alist-cons-after
          'install 'post-install
          (lambda* (#:key outputs #:allow-other-keys)
            (emacs-generate-autoloads
             "wget" (string-append (assoc-ref outputs "out")
                                   "/share/emacs/site-lisp/")))
          %standard-phases)))))
    (home-page "http://www.emacswiki.org/emacs/EmacsWget")
    (synopsis "Simple file downloader for Emacs based on wget")
    (description
     "Emacs-wget is an emacs interface for the wget file downloader.")
    (license license:gpl2+)))


;;;
;;; Multimedia.
;;;

(define-public emms
  (package
    (name "emacs-emms")
    (version "4.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/emms/emms-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1xa9y64g5z8gfnxk1c2rf3plfjhqn4r6j8dpiygnfs6w4giysn22"))
              (modules '((guix build utils)))
              (snippet
               '(substitute* "Makefile"
                  (("/usr/bin/install-info")
                   ;; No need to use 'install-info' since it would create a
                   ;; useless 'dir' file.
                   "true")
                  (("^INFODIR=.*")
                   ;; Install Info files to $out/share/info, not $out/info.
                   "INFODIR := $(PREFIX)/share/info\n")
                  (("/site-lisp/emms")
                   ;; Install directly in share/emacs/site-lisp, not in a
                   ;; sub-directory.
                   "/site-lisp")
                  (("^all: (.*)\n" _ rest)
                   ;; Build 'emms-print-metadata'.
                   (string-append "all: " rest " emms-print-metadata\n"))))))
    (build-system gnu-build-system)
    (arguments
     `(#:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (guix build emacs-utils))
       #:imported-modules (,@%gnu-build-system-modules
                           (guix build emacs-utils))

       #:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let ((out     (assoc-ref outputs "out"))
                   (vorbis  (assoc-ref inputs "vorbis-tools"))
                   (alsa    (assoc-ref inputs "alsa-utils"))
                   (mpg321  (assoc-ref inputs "mpg321"))
                   (mp3info (assoc-ref inputs "mp3info")))
               ;; Specify the installation directory.
               (substitute* "Makefile"
                 (("PREFIX=.*$")
                  (string-append "PREFIX := " out "\n")))

               (setenv "SHELL" (which "sh"))
               (setenv "CC" "gcc")

               ;; Specify the absolute file names of the various
               ;; programs so that everything works out-of-the-box.
               (with-directory-excursion "lisp"
                 (emacs-substitute-variables
                     "emms-player-mpg321-remote.el"
                   ("emms-player-mpg321-remote-command"
                    (string-append mpg321 "/bin/mpg321")))
                 (substitute* "emms-player-simple.el"
                   (("\"ogg123\"")
                    (string-append "\"" vorbis "/bin/ogg123\"")))
                 (emacs-substitute-variables "emms-info-ogginfo.el"
                   ("emms-info-ogginfo-program-name"
                    (string-append vorbis "/bin/ogginfo")))
                 (emacs-substitute-variables "emms-info-libtag.el"
                   ("emms-info-libtag-program-name"
                    (string-append out "/bin/emms-print-metadata")))
                 (emacs-substitute-variables "emms-info-mp3info.el"
                   ("emms-info-mp3info-program-name"
                    (string-append mp3info "/bin/mp3info")))
                 (substitute* "emms-volume-amixer.el"
                   (("\"amixer\"")
                    (string-append "\"" alsa "/bin/amixer\"")))
                 (substitute* "emms-tag-editor.el"
                   (("\"mp3info\"")
                    (string-append "\"" mp3info "/bin/mp3info\"")))))))
         (add-before 'install 'pre-install
           (lambda* (#:key outputs #:allow-other-keys)
             ;; The 'install' rule expects the target directories to exist.
             (let* ((out  (assoc-ref outputs "out"))
                    (bin  (string-append out "/bin"))
                    (man1 (string-append out "/share/man/man1")))
               (mkdir-p bin)
               (mkdir-p man1)
               #t)))
         (add-after 'install 'post-install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (symlink "emms-auto.el"
                        (string-append out "/share/emacs/site-lisp/"
                                       "emms-autoloads.el"))))))
       #:tests? #f))
    (native-inputs `(("emacs" ,emacs-minimal)    ;for (guix build emacs-utils)
                     ("texinfo" ,texinfo)))
    (inputs `(("alsa-utils" ,alsa-utils)
              ("vorbis-tools" ,vorbis-tools)
              ("mpg321" ,mpg321)
              ("taglib" ,taglib)
              ("mp3info" ,mp3info)))
    (synopsis "Emacs Multimedia System")
    (description
     "EMMS is the Emacs Multimedia System.  It is a small front-end which
can control one of the supported external players.  Thus, it supports
whatever formats are supported by your music player.  It also
supports tagging and playlist management, all behind a clean and
light user interface.")
    (home-page "http://www.gnu.org/software/emms/")
    (license license:gpl3+)))

(define-public emacs-emms-player-mpv
  (package
    (name "emacs-emms-player-mpv")
    (version "0.0.10")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/dochang/emms-player-mpv/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1q81fpmwr8hpdgq71vbdai2nml4yyqbmk4ffdyl4irlwph8gfjyq"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emms" ,emms)))
    (home-page "https://github.com/dochang/emms-player-mpv/")
    (synopsis "Mpv support for EMMS")
    (description
     "This package provides an EMMS player that uses mpv.  It supports pause
and seeking.")
    (license license:gpl3+)))

(define-public emacs-emms-mode-line-cycle
  (package
    (name "emacs-emms-mode-line-cycle")
    (version "0.2.5")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/momomo5717/emms-mode-line-cycle"
                           "/archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0ifszi930pnaxk1x8pcydmvnp06868gc7nfx14q17zbajbx735k6"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emms" ,emms)))
    (home-page "https://github.com/momomo5717/emms-mode-line-cycle")
    (synopsis "Display the EMMS mode line as a ticker")
    (description
     "This is a minor mode for updating the EMMS mode-line string cyclically
within a specified width.  It is useful for displaying long track titles.")
    (license license:gpl3+)))


;;;
;;; Miscellaneous.
;;;

(define-public bbdb
  (package
    (name "bbdb")
    (version "3.1.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://savannah/bbdb/bbdb-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1gs16bbpiiy01w9pyg12868r57kx1v3hnw04gmqsmpc40l1hyy05"))
              (modules '((guix build utils)))
              (snippet
               ;; We don't want to build and install the PDF.
               '(substitute* "doc/Makefile.in"
                  (("^doc_DATA = .*$")
                   "doc_DATA =\n")))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases (alist-cons-after
                 'install 'post-install
                 (lambda* (#:key outputs #:allow-other-keys)
                   ;; Add an autoloads file with the right name for guix.el.
                   (let* ((out  (assoc-ref outputs "out"))
                          (site (string-append out "/share/emacs/site-lisp")))
                     (with-directory-excursion site
                       (symlink "bbdb-loaddefs.el" "bbdb-autoloads.el"))))
                 %standard-phases)))
    (native-inputs `(("emacs" ,emacs-minimal)))
    (home-page "http://savannah.nongnu.org/projects/bbdb/")
    (synopsis "Contact management utility for Emacs")
    (description
     "BBDB is the Insidious Big Brother Database for GNU Emacs.  It provides
an address book for email and snail mail addresses, phone numbers and the
like.  It can be linked with various Emacs mail clients (Message and Mail
mode, Rmail, Gnus, MH-E, and VM).  BBDB is fully customizable.")
    (license license:gpl3+)))

(define-public emacs-async
  (package
    (name "emacs-async")
    (version "1.9")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://elpa.gnu.org/packages/async-"
                                  version ".tar"))
              (sha256
               (base32
                "1ip5nc8xyln5szvqwp6wqva9xr84pn8ssn3nnphrszr19y4js2bm"))))
    (build-system emacs-build-system)
    (home-page "https://elpa.gnu.org/packages/async.html")
    (synopsis "Asynchronous processing in Emacs")
    (description
     "This package provides the ability to call asynchronous functions and
processes.  For example, it can be used to run dired commands (for copying,
moving, etc.) asynchronously using @code{dired-async-mode}.  Also it is used
as a library for other Emacs packages.")
    (license license:gpl3+)))

(define-public emacs-auctex
  (package
    (name "emacs-auctex")
    (version "11.88.6")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://elpa.gnu.org/packages/auctex-"
             version
             ".tar"))
       (sha256
        (base32
         "1pmki8hdjjikxlvip3pzi350bln3gcimr27yjf0xfwjvnp5hh9nc"))))
    (build-system emacs-build-system)
    ;; We use 'emacs' because AUCTeX requires dbus at compile time
    ;; ('emacs-minimal' does not provide dbus).
    (arguments `(#:emacs ,emacs))
    (native-inputs
     `(("perl" ,perl)))
    (home-page "http://www.gnu.org/software/auctex/")
    (synopsis "Integrated environment for TeX")
    (description
     "AUCTeX is a comprehensive customizable integrated environment for
writing input files for TeX, LaTeX, ConTeXt, Texinfo, and docTeX using Emacs
or XEmacs.")
    (license license:gpl3+)))

(define-public emacs-mmm-mode
  (package
    (name "emacs-mmm-mode")
    (version "0.5.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/purcell/mmm-mode/archive/"
             version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "10kwslnflbjqm62wkrq420crqzdqalzfflp9pqk1i12zm6dm4mfv"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'autogen
           (lambda _
             (zero? (system* "sh" "autogen.sh")))))))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("emacs" ,emacs-minimal)
       ("texinfo" ,texinfo)))
    (home-page "https://github.com/purcell/mmm-mode")
    (synopsis "Allow multiple major modes in an Emacs buffer")
    (description
     "MMM Mode is a minor mode that allows multiple major modes to coexist in a
single buffer.")
    (license license:gpl3+)))

(define-public emacs-pdf-tools
  (package
    (name "emacs-pdf-tools")
    (version "0.70")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/politza/pdf-tools/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1m0api6wiawswyk46bdsyk6r5rg3b86a4paar6nassm6x6c6vr77"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; there are no tests
       #:modules ((guix build gnu-build-system)
                  ((guix build emacs-build-system) #:prefix emacs:)
                  (guix build utils)
                  (guix build emacs-utils))
       #:imported-modules (,@%gnu-build-system-modules
                           (guix build emacs-build-system)
                           (guix build emacs-utils))
       #:phases
       (modify-phases %standard-phases
         ;; Build server side using 'gnu-build-system'.
         (add-after 'unpack 'enter-server-dir
           (lambda _ (chdir "server") #t))
         (add-before 'configure 'autogen
           (lambda _
             (zero? (system* "bash" "autogen.sh"))))

         ;; Build emacs side using 'emacs-build-system'.
         (add-after 'compress-documentation 'enter-lisp-dir
           (lambda _ (chdir "../lisp") #t))
         (add-after 'enter-lisp-dir 'emacs-patch-variables
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Set path to epdfinfo program.
             (emacs-substitute-variables "pdf-info.el"
               ("pdf-info-epdfinfo-program"
                (string-append (assoc-ref outputs "out")
                               "/bin/epdfinfo")))
             ;; Set 'pdf-tools-handle-upgrades' to nil to avoid "auto
             ;; upgrading" that pdf-tools tries to perform.
             (emacs-substitute-variables "pdf-tools.el"
               ("pdf-tools-handle-upgrades" '()))))
         (add-after 'emacs-patch-variables 'emacs-install
           (assoc-ref emacs:%standard-phases 'install))
         (add-after 'emacs-install 'emacs-build
           (assoc-ref emacs:%standard-phases 'build))
         (add-after 'emacs-install 'emacs-make-autoloads
           (assoc-ref emacs:%standard-phases 'make-autoloads)))))
    (native-inputs `(("autoconf" ,autoconf)
                     ("automake" ,automake)
                     ("pkg-config" ,pkg-config)
                     ("emacs" ,emacs-minimal)))
    (propagated-inputs
     `(("let-alist" ,let-alist)))
    (inputs `(("poppler" ,poppler)
              ("cairo" ,cairo)
              ("glib" ,glib)
              ("libpng" ,libpng)
              ("zlib" ,zlib)))
    (synopsis "Emacs support library for PDF files")
    (description
     "PDF Tools is, among other things, a replacement of DocView for PDF
files.  The key difference is that pages are not pre-rendered by
e.g. ghostscript and stored in the file-system, but rather created on-demand
and stored in memory.")
    (home-page "https://github.com/politza/pdf-tools")
    (license license:gpl3+)))

(define-public emacs-dash
  (package
    (name "emacs-dash")
    (version "2.13.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/magnars/dash.el/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1pjlkrzr8n45bnp3xs3dybvy0nz3gwamrfc7vsi1nhpkkw99ihhb"))))
    (build-system emacs-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'install 'check
                     (lambda _
                       (zero? (system* "./run-tests.sh")))))))
    (home-page "https://github.com/magnars/dash.el")
    (synopsis "Modern list library for Emacs")
    (description "This package provides a modern list API library for Emacs.")
    (license license:gpl3+)))

(define-public emacs-bui
  (package
    (name "emacs-bui")
    (version "1.0.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/alezost/bui.el/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0vsh1v99xxm6hhqp0vg9fbs230kawa7xb5dnd8fidf3vwm622aqh"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("dash" ,emacs-dash)))
    (home-page "https://github.com/alezost/bui.el")
    (synopsis "Buffer interface library for Emacs")
    (description
     "BUI (Buffer User Interface) is a library for making @code{list} and
@code{info} interfaces to display an arbitrary data of the same
type, for example: packages, buffers, files, etc.")
    (license license:gpl3+)))

(define-public emacs-guix
  (package
    (name "emacs-guix")
    (version "0.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/alezost/guix.el"
                                  "/releases/download/v" version
                                  "/emacs-guix-" version ".tar.gz"))
              (sha256
               (base32
                "0h168597am5vcix149l27g876v4f5yqwx8v0s9mmsdva1qqcq5s5"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags
       (let ((guix        (assoc-ref %build-inputs "guix"))
             (geiser      (assoc-ref %build-inputs "geiser"))
             (dash        (assoc-ref %build-inputs "dash"))
             (bui         (assoc-ref %build-inputs "bui"))
             (magit-popup (assoc-ref %build-inputs "magit-popup"))
             (site-lisp   "/share/emacs/site-lisp"))
         (list (string-append "--with-guix-site-dir="
                              guix "/share/guile/site/2.0")
               (string-append "--with-geiser-lispdir=" geiser site-lisp)
               (string-append "--with-dash-lispdir="
                              dash site-lisp "/guix.d/dash-"
                              ,(package-version emacs-dash))
               (string-append "--with-bui-lispdir="
                              bui site-lisp "/guix.d/bui-"
                              ,(package-version emacs-bui))
               (string-append "--with-popup-lispdir="
                              magit-popup site-lisp "/guix.d/magit-popup-"
                              ,(package-version emacs-magit-popup))))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("emacs" ,emacs-minimal)))
    (inputs
     `(("guile" ,guile-2.0)
       ("guix" ,guix)))
    (propagated-inputs
     `(("geiser" ,geiser)
       ("dash" ,emacs-dash)
       ("bui" ,emacs-bui)
       ("magit-popup" ,emacs-magit-popup)))
    (home-page "https://github.com/alezost/guix.el")
    (synopsis "Emacs interface for GNU Guix")
    (description
     "Emacs-Guix provides a visual interface, tools and features for the
GNU Guix package manager.  Particularly, it allows you to do various
package management tasks from Emacs.  To begin with, run @code{M-x
guix-help} command.")
    (license license:gpl3+)))

(define-public emacs-d-mode
  (package
    (name "emacs-d-mode")
    (version "2.0.8")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/Emacs-D-Mode-Maintainers/Emacs-D-Mode/"
                    "archive/" version ".tar.gz"))
              (sha256
               (base32
                "0knpgi55jm09282aqf8pv55zillpnpzf9f4sgm6gwsmvxf17xaw0"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-undercover" ,emacs-undercover)))
    (home-page "https://github.com/Emacs-D-Mode-Maintainers/Emacs-D-Mode")
    (synopsis "Emacs major mode for editing D code")
    (description "This package provides an Emacs major mode for highlighting
code written in the D programming language.  This mode is currently known to
work with Emacs 24 and 25.")
    (license license:gpl2+)))

(define-public emacs-undo-tree
  (package
    (name "emacs-undo-tree")
    (version "0.6.4")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "http://dr-qubit.org/git/undo-tree.git")
                    (commit "release/0.6.4")))
              (file-name (string-append name "-" version "-checkout"))
              (sha256
                (base32
                  "0b6hnv6bq1g5np5q2yw9r9aj1cxpp14akm21br7vpb7wp01fv4b3"))))
    (build-system emacs-build-system)
    (home-page "http://www.dr-qubit.org/emacs.php")
    (synopsis "Treat undo history as a tree")
    (description "Tree-like interface to Emacs undo system, providing
graphical tree presentation of all previous states of buffer that
allows easily move between them.")
    (license license:gpl3+)))

(define-public emacs-s
  (package
    (name "emacs-s")
    (version "1.11.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/magnars/s.el/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0krq5nz3llfx0vwdqn18pmq777ja0fac185w0h9qymppb1j1hvc2"))))
    (build-system emacs-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'install 'check
                     (lambda _
                       (zero? (system* "./run-tests.sh")))))))
    (home-page "https://github.com/magnars/s.el")
    (synopsis "Emacs string manipulation library")
    (description "This package provides an Emacs library for manipulating
strings.")
    (license license:gpl3+)))

(define-public emacs-f
  (package
    (name "emacs-f")
    (version "0.18.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/rejeep/f.el/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1926shh2ymdsgz05c6q181mzzz1rci99ch568j151xi865jinyg5"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-s" ,emacs-s)
       ("emacs-dash" ,emacs-dash)))
    (home-page "http://github.com/rejeep/f.el")
    (synopsis "Emacs API for working with files and directories")
    (description "This package provides an Emacs library for working with
files and directories.")
    (license license:gpl3+)))

(define-public emacs-el-mock
  (package
    (name "emacs-el-mock")
    (version "1.25.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/rejeep/el-mock.el/"
                           "archive/v" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "16xw94n58xxn3zvgyj72bmzs0k5lkvswjmzs79ws9n7rzdivb38b"))))
    (build-system emacs-build-system)
    (home-page "http://github.com/rejeep/el-mock.el")
    (synopsis "Tiny mock and stub framework in Emacs Lisp")
    (description
     "Emacs Lisp Mock is a library for mocking and stubbing using readable
syntax.  Most commonly Emacs Lisp Mock is used in conjunction with Emacs Lisp
Expectations, but it can be used in other contexts.")
    (license license:gpl3+)))

(define-public emacs-espuds
  (package
    (name "emacs-espuds")
    (version "0.3.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/ecukes/espuds/"
                           "archive/v" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0xv551376pbmh735a3zjwc9z4qdx6ngj1vpq3xqjpn0a1rwjyn4k"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-s" ,emacs-s)
       ("emacs-dash" ,emacs-dash)
       ("emacs-f" ,emacs-f)))
    (home-page "http://github.com/ecukes/espuds")
    (synopsis "Common step definitions for Ecukes")
    (description "Espuds is a collection of the most commonly used step
definitions for testing with the Ecukes framework.")
    (license license:gpl3+)))

(define-public emacs-es-mode
  (package
    (name "emacs-es-mode")
    (version "4.2.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/dakrone/es-mode/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "02as82clm553yss7jfjac888308zr1h2229cch4z1yij70j25c8y"))))
    (build-system emacs-build-system)
    (propagated-inputs
     ;; The version of org in Emacs 24.5 is not sufficient, and causes tables
     ;; to be rendered incorrectly
     `(("emacs-org" ,emacs-org)))
    (home-page "https://github.com/dakrone/es-mode")
    (synopsis "Major mode for editing Elasticsearch queries")
    (description "@code{es-mode} includes highlighting, completion and
indentation support for Elasticsearch queries.  Also supported are
@code{es-mode} blocks in @code{org-mode}, for which the results of queries can
be processed through @code{jq}, or in the case of aggregations, can be
rendered in to a table.  In addition, there is an @code{es-command-center}
mode, which displays information about Elasticsearch clusters.")
    (license license:gpl3+)))

(define-public emacs-expand-region
  (package
    (name "emacs-expand-region")
    (version "0.11.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/magnars/expand-region.el"
                           "/archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "08dy1f411sh9wwww53rjw80idcf3vpki6ba2arl4hl5jcw9651g0"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/magnars/expand-region.el")
    (synopsis "Increase selected region by semantic units")
    (description
     "Expand region increases the selected region by semantic units.  Just
keep pressing the key until it selects what you want.  There's also
@code{er/contract-region} if you expand too far.")
    (license license:gpl3+)))

(define-public emacs-fill-column-indicator
  (package
    (name "emacs-fill-column-indicator")
    (version "1.81")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/alpaker/Fill-Column-Indicator"
                           "/archive/v" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1xwyqbjbbicmvhlb85vg4j5snwy1vd7rfk89ws4viws5ljkhhyg8"))))
    (build-system emacs-build-system)
    (home-page "https://www.emacswiki.org/emacs/FillColumnIndicator")
    (synopsis "Graphically indicate the fill column")
    (description
     "Fill-column-indicator graphically indicates the location of the fill
column by drawing a thin line down the length of the editing window.")
    (license license:gpl3+)))

(define-public emacs-znc
  (package
    (name "emacs-znc")
    (version "0.0.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://marmalade-repo.org/packages/znc-"
                           version ".el"))
       (sha256
        (base32
         "1d8lqvybgyazin5z0g1c4l3rg1vzrrvf0saqs53jr1zcdg0lianh"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/sshirokov/ZNC.el")
    (synopsis "Make ERC and ZNC get along better")
    (description
     "This is a thin wrapper around @code{erc} that enables one to use the ZNC
IRC bouncer with ERC.")
    (license license:expat)))

(define-public emacs-shut-up
  (package
    (name "emacs-shut-up")
    (version "0.3.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/cask/shut-up/"
                           "archive/v" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "09kzrjdkb569iviyg7ydwq44yh84m3f9hkl7jizfrlk0w4gz67d1"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/cask/shut-up")
    (synopsis "Silence Emacs")
    (description "This package silences most output of Emacs when running an
Emacs shell script.")
    (license license:expat)))

(define-public emacs-undercover
  (package
    (name "emacs-undercover")
    (version "0.6.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/sviridov/undercover.el/"
                           "archive/v" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0f48fi0xnbsqs382rgh85m9mq1wdnr0yib7as9xhwzvq0hsr5m0a"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-dash" ,emacs-dash)
       ("emacs-shut-up" ,emacs-shut-up)))
    (home-page "https://github.com/sviridov/undercover.el")
    (synopsis "Test coverage library for Emacs Lisp")
    (description
     "Undercover is a test coverage library for software written in Emacs
Lisp.")
    (license license:expat)))

(define-public emacs-paren-face
  (package
    (name "emacs-paren-face")
    (version "1.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/tarsius/paren-face/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0y4qrhxa9332vsvr999jg7qj1ymnfgwpf591yi4a4jgg90pm7qnn"))))
    (build-system emacs-build-system)
    (home-page "http://github.com/tarsius/paren-face")
    (synopsis "Face for parentheses in lisp modes")
    (description
     "This library defines a face named @code{parenthesis} used just for
parentheses.  The intended purpose of this face is to make parentheses less
visible in Lisp code by dimming them.  Lispers probably don't need to be
constantly made aware of the existence of the parentheses.  Dimming them might
be even more useful for people new to lisp who have not yet learned to
subconsciously blend out the parentheses.")
    (license license:gpl3+)))

(define-public emacs-page-break-lines
  (package
    (name "emacs-page-break-lines")
    (version "0.11")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/purcell/page-break-lines/"
                           "archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1zzhziq5kbrm9rxk30kx2glz455fp1blqxg8cpcf6l8xl3w8z4pg"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/purcell/page-break-lines")
    (synopsis "Display page breaks as tidy horizontal lines")
    (description
     "This library provides a global mode which displays form feed characters
as horizontal rules.")
    (license license:gpl3+)))

(define-public emacs-simple-httpd
  (package
    (name "emacs-simple-httpd")
    (version "1.4.6")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/skeeto/emacs-web-server/"
                           "archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "01r7h3imnj4qx1m53a2wjafvbylcyz5f9r2rg2cs7ky3chlg220r"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/skeeto/emacs-http-server")
    (synopsis "HTTP server in pure Emacs Lisp")
    (description
     "This package provides a simple HTTP server written in Emacs Lisp to
serve files and directory listings.")
    (license license:unlicense)))

(define-public emacs-skewer-mode
  (package
    (name "emacs-skewer-mode")
    (version "1.6.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/skeeto/skewer-mode/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "07jpz374j0j964szy3zznrkyja2kpdl3xa87wh7349mzxivqxdx0"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-simple-httpd" ,emacs-simple-httpd)
       ("emacs-js2-mode" ,emacs-js2-mode)))
    (home-page "https://github.com/skeeto/skewer-mode")
    (synopsis "Live web development in Emacs")
    (description
     "Skewer-mode provides live interaction with JavaScript, CSS, and HTML in
a web browser.  Expressions are sent on-the-fly from an editing buffer to be
evaluated in the browser, just like Emacs does with an inferior Lisp process
in Lisp modes.")
    (license license:unlicense)))

(define-public emacs-rich-minority
  (package
    (name "emacs-rich-minority")
    (version "1.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/Malabarba/rich-minority/"
                           "archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1l0cb0q7kyi88nwfqd542psnkgwnjklpzc5rx32gzd3lkwkrbr8v"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/Malabarba/rich-minority")
    (synopsis "Clean-up and beautify the list of minor modes")
    (description
     "This Emacs package hides and/or highlights minor modes in the
mode-line.")
    (license license:gpl2+)))

(define-public emacs-smart-mode-line
  (package
    (name "emacs-smart-mode-line")
    (version "2.10.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/Malabarba/smart-mode-line/"
                           "archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0i9wajabrrsjzwd842q0m2611kf0q31p9hg1pdj81177gynkw8l8"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-rich-minority" ,emacs-rich-minority)))
    (home-page "http://github.com/Malabarba/smart-mode-line")
    (synopsis "Color-coded smart mode-line")
    (description
     "Smart Mode Line is a mode-line theme for Emacs.  It aims to be easy to
read from small to large monitors by using colors, a prefix feature, and smart
truncation.")
    (license license:gpl2+)))

(define-public emacs-shell-switcher
  (package
    (name "emacs-shell-switcher")
    (version "1.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/DamienCassou/shell-switcher"
                           "/archive/v" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1c23mfkdqz2g9rixd9smm323vzlvhzz3ng34ambcqjfq309qb2nz"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/DamienCassou/shell-switcher")
    (synopsis "Provide fast switching between shell buffers")
    (description
     "This package provides commands to quickly switch between shell buffers.")
    (license license:gpl3+)))

(define-public emacs-ob-ipython
  (package
    (name "emacs-ob-ipython")
    (version "20150704.8807064693")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (commit "880706469338ab59b5bb7dbe8460016f89755364")
                    (url "https://github.com/gregsexton/ob-ipython.git")))
              (sha256
               (base32
                "1scf25snbds9ymagpny30ijbsg479r3nm0ih01dy4m9d0g7qryb7"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-f" ,emacs-f)))
    (home-page "http://www.gregsexton.org")
    (synopsis "Org-Babel functions for IPython evaluation")
    (description "This package adds support to Org-Babel for evaluating Python
source code using IPython.")
    (license license:gpl3+)))

(define-public emacs-debbugs
  (package
    (name "emacs-debbugs")
    (version "0.12")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://elpa.gnu.org/packages/debbugs-"
                                  version ".tar"))
              (sha256
               (base32
                "1swi4d7fhahimid9j12cypmkz7dlqgffrnhfxy5ra44y3j2b35ph"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-async" ,emacs-async)))
    (home-page "https://elpa.gnu.org/packages/debbugs.html")
    (synopsis "Access the Debbugs bug tracker in Emacs")
    (description
     "This package lets you access the @uref{http://bugs.gnu.org,GNU Bug
Tracker} from within Emacs.

For instance, it defines the command @code{M-x debbugs-gnu} for listing bugs,
and the command @code{M-x debbugs-gnu-search} for bug searching.  If you
prefer the listing of bugs as TODO items of @code{org-mode}, you could use
@code{M-x debbugs-org} and related commands.

A minor mode @code{debbugs-browse-mode} let you browse URLs to the GNU Bug
Tracker as well as bug identifiers prepared for @code{bug-reference-mode}.")
    (license license:gpl3+)))

(define-public emacs-deferred
  (package
    (name "emacs-deferred")
    (version "0.3.2")
    (home-page "https://github.com/kiwanami/emacs-deferred")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url home-page)
                    (commit (string-append "v" version))))
              (sha256
               (base32
                "0059jy01ni5irpgrj9fa81ayd9j25nvmjjm79ms3210ysx4pgqdr"))
              (file-name (string-append name "-" version))))
    (build-system emacs-build-system)
    ;; FIXME: Would need 'el-expectations' to actually run tests.
    (synopsis "Simple asynchronous functions for Emacs Lisp")
    (description
     "The @code{deferred.el} library provides support for asynchronous tasks.
The API is almost the same as that of
@uref{https://github.com/cho45/jsdeferred, JSDeferred}, a JavaScript library
for asynchronous tasks.")
    (license license:gpl3+)))

(define-public butler
  (package
    (name "emacs-butler")
    (version "0.2.4")
    (home-page "https://github.com/AshtonKem/Butler")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url home-page)
                    (commit version)))
              (sha256
               (base32
                "1pii9dw4skq7nr4na6qxqasl36av8cwjp71bf1fgppqpcd9z8skj"))
              (file-name (string-append name "-" version))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-deferred" ,emacs-deferred)))
    (synopsis "Emacs client for Jenkins")
    (description
     "Butler provides an interface to connect to Jenkins continuous
integration servers.  Users can specify a list of server in the
@code{butler-server-list} variable and then use @code{M-x butler-status} to
view the build status of those servers' build jobs, and possibly to trigger
build jobs.")
    (license license:gpl3+)))

(define-public emacs-company
  (package
    (name "emacs-company")
    (version "0.8.12")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/company-mode/company-mode/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1vwmbqm7h4lrszv2qxy6fqzznm9raigi84cadx982c9m7shp0zzz"))))
    (build-system emacs-build-system)
    (home-page "http://company-mode.github.io/")
    (synopsis "Modular text completion framework")
    (description
     "Company is a modular completion mechanism.  Modules for retrieving
completion candidates are called back-ends, modules for displaying them are
front-ends.  Company comes with many back-ends, e.g. @code{company-elisp}.
These are distributed in separate files and can be used individually.")
    (license license:gpl3+)))

(define-public emacs-multiple-cursors
  (package
    (name "emacs-multiple-cursors")
    (version "1.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/magnars/multiple-cursors.el/"
                           "archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0hihihlvcvzayg5fnqzcg45fhvlmq6xlq58syy00rjwbry9w389k"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/magnars/multiple-cursors.el")
    (synopsis "Multiple cursors for Emacs")
    (description
     "This package adds support to Emacs for editing text with multiple
simultaneous cursors.")
    (license license:gpl3+)))

(define-public typo
  (package
    (name "emacs-typo")
    (version "1.1")
    (home-page "https://github.com/jorgenschaefer/typoel")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url home-page)
                    (commit (string-append "v" version))))
              (sha256
               (base32
                "1jhd4grch5iz12gyxwfbsgh4dmz5hj4bg4gnvphccg8dsnni05k2"))
              (file-name (string-append name "-" version))))
    (build-system emacs-build-system)
    (synopsis "Minor mode for typographic editing")
    (description
     "This package provides two Emacs modes, @code{typo-mode} and
@code{typo-global-mode}.  These modes automatically insert Unicode characters
for quotation marks, dashes, and ellipses.  For example, typing @kbd{\"}
automatically inserts a Unicode opening or closing quotation mark, depending
on context.")
    (license license:gpl3+)))

(define-public emacs-scheme-complete
  (let ((commit "9b5cf224bf2a5994bc6d5b152ff487517f1a9bb5"))
    (package
      (name "emacs-scheme-complete")
      (version (string-append "20151223." (string-take commit 8)))
      (source
       (origin
         (file-name (string-append name "-" version))
         (method git-fetch)
         (uri (git-reference
               (url "https://github.com/ashinn/scheme-complete.git")
               (commit commit)))
         (sha256
          (base32
           "141wn9l0m33w0g3dqmx8nxbfdny1r5xbr6ak61rsz21bk0qafs7x"))
         (patches
          (search-patches "emacs-scheme-complete-scheme-r5rs-info.patch"))))
      (build-system emacs-build-system)
      (home-page "https://github.com/ashinn/scheme-complete")
      (synopsis "Smart tab completion for Scheme in Emacs")
      (description
       "This file provides a single function, @code{scheme-smart-complete},
which you can use for intelligent, context-sensitive completion for any Scheme
implementation in Emacs.  To use it just load this file and bind that function
to a key in your preferred mode.")
      (license license:public-domain))))

(define-public emacs-mit-scheme-doc
  (package
    (name "emacs-mit-scheme-doc")
    (version "20140203")
    (source
     (origin
       (modules '((guix build utils)))
       (snippet
        ;; keep only file of interest
        '(begin
           (for-each delete-file '("dot-emacs.el" "Makefile"))
           (copy-file "6.945-config/mit-scheme-doc.el" "mit-scheme-doc.el")
           (delete-file-recursively "6.945-config")))
       (file-name (string-append name "-" version ".tar.bz2"))
       (method url-fetch)
       (uri (string-append "http://groups.csail.mit.edu/mac/users/gjs/"
                           "6.945/dont-panic/emacs-basic-config.tar.bz2"))
       (sha256
        (base32
         "0dqidg2bd66pawqfarvwca93w5gqf9mikn1k2a2rmd9ymfjpziq1"))))
    (build-system emacs-build-system)
    (inputs `(("mit-scheme" ,mit-scheme)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'configure-doc
           (lambda* (#:key inputs #:allow-other-keys)
             (let* ((mit-scheme-dir (assoc-ref inputs "mit-scheme"))
                    (doc-dir (string-append mit-scheme-dir "/share/doc/"
                                            "mit-scheme-"
                                            ,(package-version mit-scheme))))
               (substitute* "mit-scheme-doc.el"
                 (("http://www\\.gnu\\.org/software/mit-scheme/documentation/mit-scheme-ref/")
                  (string-append "file:" doc-dir "/mit-scheme-ref/")))))))))
    (home-page "http://groups.csail.mit.edu/mac/users/gjs/6.945/dont-panic/")
    (synopsis "MIT-Scheme documentation lookup for Emacs")
    (description
     "This package provides a set of Emacs functions to search definitions of
identifiers in the MIT-Scheme documentation.")
    (license license:gpl2+)))

(define-public emacs-constants
  (package
    (name "emacs-constants")
    (version "2.6")
    (home-page "https://staff.fnwi.uva.nl/c.dominik/Tools/constants")
    (source
     (origin
       (file-name (string-append name "-" version ".tar.gz"))
       (method url-fetch)
       (uri (string-append "https://github.com/fedeinthemix/emacs-constants"
                           "/archive/v" version ".tar.gz"))
       (sha256
        (base32
         "0pnrpmmxq8mh5h2hbrp5vcym0j0fh6dv3s7c5ccn18wllhzg9g7n"))))
    (build-system emacs-build-system)
    (synopsis "Enter definition of constants into an Emacs buffer")
    (description
     "This package provides functions for inserting the definition of natural
constants and units into an Emacs buffer.")
    (license license:gpl2+)))

(define-public emacs-tagedit
  (package
    (name "emacs-tagedit")
    (version "1.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/magnars/tagedit/"
                           "archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1apfnann4qklfdsmdi7icjsj18x7gwx8d83iqr4z25clszz95xfq"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-s" ,emacs-s)
       ("emacs-dash" ,emacs-dash)))
    (home-page "https://github.com/magnars/tagedit")
    (synopsis "Some paredit-like features for html-mode")
    (description
     "This package provides a collection of paredit-like functions for editing
in @code{html-mode}.")
    (license license:gpl3+)))

(define-public emacs-slime
  (package
    (name "emacs-slime")
    (version "2.18")
    (source
     (origin
       (file-name (string-append name "-" version ".tar.gz"))
       (method url-fetch)
       (uri (string-append
             "https://github.com/slime/slime/archive/v"
             version ".tar.gz"))
       (sha256
        (base32
         "146avwbwr6mw0nmgyihx8gkr0mv6al7a73igzxvysj62000cqvlj"))))
    (build-system emacs-build-system)
    (native-inputs
     `(("texinfo" ,texinfo)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'install 'configure
           (lambda* _
             (emacs-substitute-variables "slime.el"
               ("inferior-lisp-program" "sbcl"))
             #t))
         (add-before 'install 'install-doc
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (info-dir (string-append out "/share/info"))
                    (doc-dir (string-append out "/share/doc/"
                                            ,name "-" ,version))
                    (doc-files '("doc/slime-refcard.pdf"
                                 "README.md" "NEWS" "PROBLEMS"
                                 "CONTRIBUTING.md")))
               (with-directory-excursion "doc"
                 (substitute* "Makefile"
                   (("infodir=/usr/local/info")
                    (string-append "infodir=" info-dir)))
                 (system* "make" "html/index.html")
                 (system* "make" "slime.info")
                 (install-file "slime.info" info-dir)
                 (copy-recursively "html" (string-append doc-dir "/html")))
               (for-each (lambda (f)
                           (install-file f doc-dir)
                           (delete-file f))
                         doc-files)
               (delete-file-recursively "doc")
               #t))))))
    (home-page "https://github.com/slime/slime")
    (synopsis "Superior Lisp Interaction Mode for Emacs")
    (description
     "SLIME extends Emacs with support for interactive programming in
Common Lisp.  The features are centered around @{slime-mode}, an Emacs
minor mode that complements the standard @{lisp-mode}.  While lisp-mode
supports editing Lisp source files, @{slime-mode} adds support for
interacting with a running Common Lisp process for compilation,
debugging, documentation lookup, and so on.")
    (license license:gpl2+)))

(define-public emacs-popup
  (package
    (name "emacs-popup")
    (version "0.5.3")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/auto-complete/popup-el/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1yrgfj8y69xmcb6kwgplhq68ndm9410qwh7sd2knnd1gchpphdc0"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/auto-complete/popup-el")
    (synopsis "Visual Popup User Interface for Emacs")
    (description
     "Popup.el is a visual popup user interface library for Emacs.
This provides a basic API and common UI widgets such as popup tooltips
and popup menus.")
    (license license:gpl3+)))

(define-public emacs-god-mode
  (let ((commit "6cf0807b6555eb6fcf8387a4e3b667071ef38964")
        (revision "1"))
    (package
      (name "emacs-god-mode")
      (version (string-append "20151005.925."
                              revision "-" (string-take commit 9)))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "https://github.com/chrisdone/god-mode.git")
               (commit commit)))
         (file-name (string-append name "-" version "-checkout"))
         (sha256
          (base32
           "1am415k4xxcva6y3vbvyvknzc6bma49pq3p85zmpjsdmsp18qdix"))))
      (build-system emacs-build-system)
      (home-page "https://github.com/chrisdone/god-mode")
      (synopsis "Minor mode for entering commands without modifier keys")
      (description
       "This package provides a global minor mode for entering Emacs commands
without modifier keys.  It's similar to Vim's separation of commands and
insertion mode.  When enabled all keys are implicitly prefixed with
@samp{C-} (among other helpful shortcuts).")
      (license license:gpl3+))))

(define-public emacs-rfcview
  (package
    (name "emacs-rfcview")
    (version "0.13")
    (home-page "http://www.loveshack.ukfsn.org/emacs")
    (source (origin
              (method url-fetch)
              (uri "http://www.loveshack.ukfsn.org/emacs/rfcview.el")
              (sha256
               (base32
                "0ympj5rxig383zl2jf0pzdsa80nnq0dpvjiriq0ivfi98fj7kxbz"))))
    (build-system emacs-build-system)
    (synopsis "Prettify Request for Comments (RFC) documents")
    (description "The Internet Engineering Task Force (IETF) and the Internet
Society (ISOC) publish various Internet-related protocols and specifications
as \"Request for Comments\" (RFC) documents and Internet Standard (STD)
documents.  RFCs and STDs are published in a simple text form.  This package
provides an Emacs major mode, rfcview-mode, which makes it more pleasant to
read these documents in Emacs.  It prettifies the text and adds
hyperlinks/menus for easier navigation.  It also provides functions for
browsing the index of RFC documents and fetching them from remote servers or
local directories.")
    (license license:gpl3+)))

(define-public emacs-ffap-rfc-space
  (package
    (name "emacs-ffap-rfc-space")
    (version "12")
    (home-page "http://user42.tuxfamily.org/ffap-rfc-space/index.html")
    (source (origin
              (method url-fetch)
              (uri "http://download.tuxfamily.org/user42/ffap-rfc-space.el")
              (sha256
               (base32
                "1iv61dv57a73mdps7rn6zmgz7nqh14v0ninidyrasy45b1nv6gck"))))
    (build-system emacs-build-system)
    (synopsis "Make ffap recognize an RFC with a space before its number")
    (description "The Internet Engineering Task Force (IETF) and the
Internet Society (ISOC) publish various Internet-related protocols and
specifications as \"Request for Comments\" (RFC) documents.  The
built-in Emacs module \"ffap\" (Find File at Point) has the ability to
recognize names at point which look like \"RFC1234\" and \"RFC-1234\"
and load the appropriate RFC from a remote server.  However, it fails
to recognize a name like \"RFC 1234\".  This package enhances ffap so
that it correctly finds RFCs even when a space appears before the
number.")
    (license license:gpl3+)))

(define-public emacs-org-bullets
  (package
    (name "emacs-org-bullets")
    (version "0.2.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/sabof/org-bullets/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1dyxvpb73vj80v8br2q9rf255hfphrgaw91fbvwdcd735np9pcnh"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/sabof/org-bullets")
    (synopsis "Show bullets in org-mode as UTF-8 characters")
    (description
     "This package provides an Emacs minor mode causing bullets in
@code{org-mode} to be rendered as UTF-8 characters.")
    (license license:gpl3+)))

(define-public emacs-org-trello
  (package
    (name "emacs-org-trello")
    (version "0.7.9")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/org-trello/org-trello/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "074dka8g673bj1ck5vavbjaij5jyniygdlw51mdds005wd2br9wf"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-deferred" ,emacs-deferred)
       ("emacs-request" ,emacs-request)
       ("emacs-dash" ,emacs-dash)
       ("emacs-s" ,emacs-s)))
    (home-page "https://org-trello.github.io")
    (synopsis "Emacs minor mode for interacting with Trello")
    (description "This package provides an Emacs minor mode to extend
@code{org-mode} with Trello abilities.  Trello is an online project
organizer.")
    (license license:gpl3+)))

(define-public emacs-zenburn-theme
  (package
    (name "emacs-zenburn-theme")
    (version "2.4")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/bbatsov/zenburn-emacs/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0lyi84bm8sa7vj40n6zg6rlbsmi53mi1y9xn6gkjj29s5zbcnlg7"))))
    (build-system emacs-build-system)
    (home-page "http://github.com/bbatsov/zenburn-emacs")
    (synopsis "Low contrast color theme for Emacs")
    (description
     "Zenburn theme is a port of the popular Vim Zenburn theme for Emacs.
It is built on top of the custom theme support in Emacs 24 or later.")
    (license license:gpl3+)))

(define-public emacs-solarized-theme
  (package
    (name "emacs-solarized-theme")
    (version "1.2.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/bbatsov/solarized-emacs/"
                                  "archive/v"  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1ha3slc6d9wi9ilkhmwrzkvf308n6ph7b0k69pk369s9304awxzx"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-dash" ,emacs-dash)))
    (home-page "http://github.com/bbatsov/solarized-emacs")
    (synopsis "Port of the Solarized theme for Emacs")
    (description
     "Solarized for Emacs is a port of the Solarized theme for Vim.  This
package provides a light and a dark variant.")
    (license license:gpl3+)))

(define-public emacs-ahungry-theme
  (package
    (name "emacs-ahungry-theme")
    (version "1.3.0")
    (source
     (origin (method url-fetch)
             (uri (string-append "https://elpa.gnu.org/packages/ahungry-theme-"
                                 version ".tar"))
             (sha256
              (base32
               "1p2zaq0s4bbl5cx6wyab24wamw7m0mysb0v47dqjmnvfc25z84rq"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/ahungry/color-theme-ahungry")
    (synopsis "Ahungry color theme for Emacs")
    (description "Ahungry theme for Emacs provides bright and bold colors.
If you load it from a terminal, you will be able to make use of the
transparent background.  If you load it from a GUI, it will default to a
dark background.")
    (license license:gpl3+)))

(define-public emacs-smartparens
  (package
    (name "emacs-smartparens")
    (version "1.8.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/Fuco1/smartparens/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0xsqiklg0q4w6gj0js1hvsz4lkypvcx6c9kzb1mz232gwlqx1azw"))))
    (build-system emacs-build-system)
    (propagated-inputs `(("emacs-dash" ,emacs-dash)))
    (home-page "https://github.com/Fuco1/smartparens")
    (synopsis "Paredit-like insertion, wrapping and navigation with user
defined pairs")
    (description
     "Smartparens is a minor mode for Emacs that deals with parens pairs
and tries to be smart about it.  It started as a unification effort to
combine functionality of several existing packages in a single,
compatible and extensible way to deal with parentheses, delimiters, tags
and the like.  Some of these packages include autopair, textmate,
wrap-region, electric-pair-mode, paredit and others.  With the basic
features found in other packages it also brings many improvements as
well as completely new features.")
    (license license:gpl3+)))

(define-public emacs-hl-todo
  (package
    (name "emacs-hl-todo")
    (version "1.7.4")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://raw.githubusercontent.com/tarsius/hl-todo/"
                    version "/hl-todo.el"))
              (file-name (string-append "hl-todo-" version ".el"))
              (sha256
               (base32
                "016ivl4s0ysrm1xbfi86j5xcs759fcb0mkspxw81x8mpi3yb46ya"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/tarsius/hl-todo")
    (synopsis "Emacs mode to highlight TODO and similar keywords")
    (description
     "This package provides an Emacs mode to highlight TODO and similar
keywords in comments and strings.  This package also provides commands for
moving to the next or previous keyword and to invoke @code{occur} with a
regexp that matches all known keywords.")
    (license license:gpl3+)))

(define-public emacs-perspective
  (package
    (name "emacs-perspective")
    (version "1.12")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/nex3/perspective-el/"
                           "archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "078ahh0kmhdylq5ib9c81c76kz1n02xwc83pm729d00i84ibviic"))))
    (build-system emacs-build-system)
    (home-page "http://github.com/nex3/perspective-el")
    (synopsis "Switch between named \"perspectives\"")
    (description
     "This package provides tagged workspaces in Emacs, similar to workspaces in
windows managers such as Awesome and XMonad.  @code{perspective.el} provides
multiple workspaces (or \"perspectives\") for each Emacs frame.  Each
perspective is composed of a window configuration and a set of buffers.
Switching to a perspective activates its window configuration, and when in a
perspective only its buffers are available by default.")
    ;; This package is released under the same license as Emacs (GPLv3+) or
    ;; the Expat license.
    (license license:gpl3+)))

(define-public emacs-request
  (package
    (name "emacs-request")
    (version "0.2.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/tkf/emacs-request/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32 "0sll9g9x15jxrdr58pdxx4iz74rnjd43q521iqm890i6hmkrgwap"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/tkf/emacs-request")
    (synopsis "Package for speaking HTTP in Emacs Lisp")
    (description "This package provides a HTTP request library with multiple
backends.  It supports url.el which is shipped with Emacs and the curl command
line program.")
    (license license:gpl3+)))

(define-public emacs-rudel
  (package
    (name "emacs-rudel")
    (version "0.3.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://elpa.gnu.org/packages/rudel-"
                           version ".tar"))
       (sha256
        (base32
         "0glqa68g509p0s2vcc0i8kzlddnc9brd9jqhnm5rzxz4i050cvnz"))))
    (build-system emacs-build-system)
    (home-page "http://rudel.sourceforge.net/")
    (synopsis "Collaborative editing framework")
    (description
     "Rudel is a collaborative editing environment for GNU Emacs.  Its purpose
is to share buffers with other users in order to edit the contents of those
buffers collaboratively.  Rudel supports multiple backends to enable
communication with other collaborative editors using different protocols,
though currently Obby (for use with the Gobby editor) is the only
fully-functional one.")
    (license license:gpl3+)))

(define-public emacs-hydra
  (package
    (name "emacs-hydra")
    (version "0.13.6")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/abo-abo/hydra/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0575vh858gm35p57s49dy6pc2ij46dmj9zaa4z0cp98sqra3j3l0"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/abo-abo/hydra")
    (synopsis "Make Emacs bindings that stick around")
    (description
     "This package can be used to tie related commands into a family of short
bindings with a common prefix---a Hydra.  Once you summon the Hydra (through
the prefixed binding), all the heads can be called in succession with only a
short extension.  Any binding that isn't the Hydra's head vanquishes the
Hydra.  Note that the final binding, besides vanquishing the Hydra, will still
serve its original purpose, calling the command assigned to it.  This makes
the Hydra very seamless; it's like a minor mode that disables itself
automatically.")
    (license license:gpl3+)))

(define-public emacs-ivy
  (package
    (name "emacs-ivy")
    (version "0.8.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/abo-abo/swiper/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "18nqwl05is71dzswnvpfhlg7b0v3apvbsfxrwab9c0apwavi892q"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-hydra" ,emacs-hydra)))
    (home-page "http://oremacs.com/swiper/")
    (synopsis "Incremental vertical completion for Emacs")
    (description
     "This package provides @code{ivy-read} as an alternative to
@code{completing-read} and similar functions.  No attempt is made to determine
the best candidate.  Instead, the user can navigate candidates with
@code{ivy-next-line} and @code{ivy-previous-line}.  The matching is done by
splitting the input text by spaces and re-building it into a regular
expression.")
    (license license:gpl3+)))

(define-public emacs-avy
  (package
    (name "emacs-avy")
    (version "0.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/abo-abo/avy/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1wdrq512h25ymzjbf2kbsdymvd2ryfwzb6bh5bc3yv7q203im796"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/abo-abo/avy")
    (synopsis "Tree-based completion for Emacs")
    (description
     "This package provides a generic completion method based on building a
balanced decision tree with each candidate being a leaf.  To traverse the tree
from the root to a desired leaf, typically a sequence of @code{read-key} can
be used.

In order for @code{read-key} to make sense, the tree needs to be visualized
appropriately, with a character at each branch node.  So this completion
method works only for things that you can see on your screen, all at once,
such as the positions of characters, words, line beginnings, links, or
windows.")
    (license license:gpl3+)))

(define-public emacs-ace-window
  (package
    (name "emacs-ace-window")
    (version "0.9.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/abo-abo/ace-window/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1p2sgfl5dml4zbd6ldql6lm2m9vmd236ah996ni32x254s48j5pn"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-avy" ,emacs-avy)))
    (home-page "https://github.com/abo-abo/ace-window")
    (synopsis "Quickly switch windows in Emacs")
    (description
     "@code{ace-window} is meant to replace @code{other-window}.
In fact, when there are only two windows present, @code{other-window} is
called.  If there are more, each window will have its first character
highlighted.  Pressing that character will switch to that window.")
    (license license:gpl3+)))

(define-public emacs-iedit
  (package
    (name "emacs-iedit")
    (version "0.9.9")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/victorhge/iedit/archive/v"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "00v86zllcsivmiibigbr91qij2zdf1lr9db8z8again1sn63wkdj"))))
    (build-system emacs-build-system)
    (home-page "http://www.emacswiki.org/emacs/Iedit")
    (synopsis "Edit multiple regions in the same way simultaneously")
    (description
     "This package is an Emacs minor mode and allows you to edit one
occurrence of some text in a buffer (possibly narrowed) or region, and
simultaneously have other occurrences edited in the same way.

You can also use Iedit mode as a quick way to temporarily show only the buffer
lines that match the current text being edited.  This gives you the effect of
a temporary @code{keep-lines} or @code{occur}.")
    (license license:gpl3+)))

(define-public emacs-lispy
  (package
    (name "emacs-lispy")
    (version "0.26.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/abo-abo/lispy/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "15gig95cvamw5zlw99cxggd27c18b9scznjj97gvjn2zbljcaqzl"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-ace-window" ,emacs-ace-window)
       ("emacs-iedit" ,emacs-iedit)
       ("emacs-ivy" ,emacs-ivy)
       ("emacs-hydra" ,emacs-hydra)))
    (home-page "https://github.com/abo-abo/lispy")
    (synopsis "Modal S-expression editing")
    (description
     "Due to the structure of Lisp syntax it's very rare for the programmer to
want to insert characters right before \"(\" or right after \")\".  Thus
unprefixed printable characters can be used to call commands when the point is
at one of these special locations.  Lispy provides unprefixed keybindings for
S-expression editing when point is at the beginning or end of an
S-expression.")
    (license license:gpl3+)))

(define-public emacs-clojure-mode
  (package
    (name "emacs-clojure-mode")
    (version "5.3.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/clojure-emacs/clojure-mode/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0gi8ra3ap5m3mz4qh1yxp2cldn7z9xcxvypznr6rrlc6a9l8s5a6"))))
    (build-system emacs-build-system)
    (home-page "http://github.com/clojure-emacs/clojure-mode")
    (synopsis "Major mode for Clojure code")
    (description
     "This Emacs package provides font-lock, indentation, navigation and basic
refactoring for the @uref{http://clojure.org, Clojure programming language}.
It is recommended to use @code{clojure-mode} with paredit or smartparens.")
    (license license:gpl3+)))

(define-public emacs-epl
  (package
    (name "emacs-epl")
    (version "0.8")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/cask/epl/archive/"
                    version ".tar.gz"))
              (sha256
               (base32
                "1511n3a3f5gvaf2b4nh018by61ciyzi3y3603fzqma7p9hrckarc"))))
    (build-system emacs-build-system)
    (home-page "http://github.com/cask/epl")
    (synopsis "Emacs Package Library")
    (description
     "A package management library for Emacs, based on @code{package.el}.

The purpose of this library is to wrap all the quirks and hassle of
@code{package.el} into a sane API.")
    (license license:gpl3+)))

(define-public emacs-queue
  (package
    (name "emacs-queue")
    (version "0.1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://elpa.gnu.org/packages/queue-"
                                  version ".el"))
              (sha256
               (base32
                "0jw24fxqnf9qcaf2nh09cnds1kqfk7hal35dw83x1ari95say391"))))
    (build-system emacs-build-system)
    (home-page "http://www.dr-qubit.org/tags/computing-code-emacs.html")
    (synopsis "Queue data structure for Emacs")
    (description
     "This Emacs library provides queue data structure.  These queues can be
used both as a first-in last-out (FILO) and as a first-in first-out (FIFO)
stack, i.e. elements can be added to the front or back of the queue, and can
be removed from the front.  This type of data structure is sometimes called an
\"output-restricted deque\".")
    (license license:gpl3+)))

(define-public emacs-pkg-info
  (package
    (name "emacs-pkg-info")
    (version "0.6")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/lunaryorn/pkg-info.el/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1gy1jks5mmm02gg1c8gcyr4f8a9s5ggzhk56gv33b9mzjqzi5rd5"))))
    (build-system emacs-build-system)
    (propagated-inputs `(("emacs-epl" ,emacs-epl)))
    (home-page "https://github.com/lunaryorn/pkg-info.el")
    (synopsis "Information about Emacs packages")
    (description
     "This library extracts information from the installed Emacs packages.")
    (license license:gpl3+)))

(define-public emacs-spinner
  (package
    (name "emacs-spinner")
    (version "1.7.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://elpa.gnu.org/packages/spinner-"
                                  version ".el"))
              (sha256
               (base32
                "1fmwzdih0kbyvs8bn38mpm4sbs2mikqy2vdykfy9g20wpa8vb681"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/Malabarba/spinner.el")
    (synopsis "Emacs mode-line spinner for operations in progress")
    (description
     "This Emacs package adds spinners and progress-bars to the mode-line for
ongoing operations.")
    (license license:gpl3+)))

(define-public emacs-seq
  (package
    (name "emacs-seq")
    (version "2.15")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://elpa.gnu.org/packages/seq-"
                                  version ".tar"))
              (sha256
               (base32
                "09wi1765bmn7i8fg6ajjfaxgs4ipc42d58zx2fdqpidrdg9c7q73"))))
    (build-system emacs-build-system)
    (home-page "https://elpa.gnu.org/packages/seq.html")
    (synopsis "Sequence manipulation functions for Emacs")
    (description
     "This Emacs library provides sequence-manipulation functions that
complement basic functions provided by @code{subr.el}.  All provided functions
work on lists, strings and vectors.")
    (license license:gpl3+)))

(define-public emacs-better-defaults
  (package
    (name "emacs-better-defaults")
    (version "0.1.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/technomancy/better-defaults"
                           "/archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "08fg4zslzlxbvyil5g4gwvwd22fh4zsgqprs5wh9hv1rgc6757m2"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/technomancy/better-defaults")
    (synopsis "Better defaults for Emacs")
    (description
     "Better defaults attempts to address the most obvious deficiencies of the
Emacs default configuration in uncontroversial ways that nearly everyone can
agree upon.")
    (license license:gpl3+)))

(define-public emacs-eprime
  (let ((commit "17a481af26496be91c07139a9bfc05cfe722506f"))
    (package
      (name "emacs-eprime")
      (version (string-append "20140513-" (string-take commit 7)))
      (source (origin
                (method url-fetch)
                (uri (string-append "https://raw.githubusercontent.com"
                                    "/AndrewHynes/eprime-mode/"
                                    commit "/eprime-mode.el"))
                (file-name (string-append "eprime-" version ".el"))
                (sha256
                 (base32
                  "0v68lggkyq7kbcr9zyi573m2g2x251xy3jadlaw8kx02l8krwq8d"))))
      (build-system emacs-build-system)
      (home-page "https://github.com/AndrewHynes/eprime-mode")
      (synopsis "E-prime checking mode for Emacs")
      (description "This package provides an E-prime checking mode for Emacs
that highlights non-conforming text.  The subset of the English language called
E-Prime forbids the use of the \"to be\" form to strengthen your writing.")
      (license license:gpl3+))))

(define-public emacs-ess
  (package
    (name "emacs-ess")
    (version "16.04")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://ess.r-project.org/downloads/ess/ess-"
                                  version ".tgz"))
              (sha256
               (base32
                "0w7mbbajn377gdmvnd21mpyr368b2ia46gq6cb99y4y5rspf9pcg"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; There is no test suite.
       #:make-flags (list (string-append "PREFIX=" (assoc-ref %outputs "out")))
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (add-before 'build 'more-shebang-patching
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "Makeconf"
               (("SHELL = /bin/sh")
                (string-append "SHELL = " (which "sh")))))))))
    (inputs
     `(("emacs" ,emacs-minimal)
       ("r" ,r)))
    (native-inputs
     `(("perl" ,perl)
       ("texinfo" ,texinfo)
       ("texlive" ,texlive)))
    (home-page "http://ess.r-project.org/")
    (synopsis "Emacs mode for statistical analysis programs")
    (description "Emacs Speaks Statistics (ESS) is an add-on package for GNU
Emacs.  It is designed to support editing of scripts and interaction with
various statistical analysis programs such as R and OpenBUGS.")
    (license license:gpl2+)))

(define-public emacs-smex
  (package
    (name "emacs-smex")
    (version "3.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://raw.githubusercontent.com"
                                  "/nonsequitur/smex/" version "/smex.el"))
              (file-name (string-append "smex-" version ".el"))
              (sha256
               (base32
                "0ar310zx9k5y4i1vl2rawvi712xj9gx77160860jbs691p77cxqp"))))
    (build-system emacs-build-system)
    (home-page "http://github.com/nonsequitur/smex/")
    (synopsis "M-x interface with Ido-style fuzzy matching")
    (description
     "Smex is a M-x enhancement for Emacs.  Built on top of Ido, it provides a
convenient interface to your recently and most frequently used commands.  And
to all the other commands, too.")
    (license license:gpl3+)))

(define-public emacs-js2-mode
  (package
    (name "emacs-js2-mode")
    (version "20150909")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/mooz/js2-mode/archive/"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1nsm36c4kwb473p13i58fgrnlk8fbn3rdhj47d9xz70az4ra44q0"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/mooz/js2-mode/")
    (synopsis "Improved JavaScript editing mode for Emacs")
    (description
     "Js2-mode provides a JavaScript major mode for Emacs that is more
advanced than the built-in javascript-mode.  Features include accurate syntax
highlighting using a recursive-descent parser, on-the-fly reporting of syntax
errors and strict-mode warnings, smart line-wrapping within comments and
strings, and code folding.")
    (license license:gpl3+)))

(define-public emacs-markdown-mode
  (package
    (name "emacs-markdown-mode")
    (version "2.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://raw.githubusercontent.com/jrblevin"
                                  "/markdown-mode/v" version
                                  "/markdown-mode.el"))
              (file-name (string-append "markdown-mode-" version ".el"))
              (sha256
               (base32
                "1faibar32jnjia9202swblw91q6z1g5s4k9xmypwjahfh8yznl6w"))))
    (build-system emacs-build-system)
    (home-page "http://jblevins.org/projects/markdown-mode/")
    (synopsis "Emacs Major mode for Markdown files")
    (description
     "Markdown-mode is a major mode for editing Markdown-formatted text files
in Emacs.")
    (license license:gpl3+)))

(define-public emacs-projectile
  (package
    (name "emacs-projectile")
    (version "0.13.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://raw.githubusercontent.com/bbatsov"
                                  "/projectile/v" version "/projectile.el"))
              (file-name (string-append "projectile-" version ".el"))
              (sha256
               (base32
                "1pc6xb61hzxzc5hkqkli1ab0s7wz0rfgx4kcn9y30ksvhw18smbz"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-dash" ,emacs-dash)
       ("emacs-pkg-info" ,emacs-pkg-info)))
    (home-page "https://github.com/bbatsov/projectile")
    (synopsis "Manage and navigate projects in Emacs easily")
    (description
     "This library provides easy project management and navigation.  The
concept of a project is pretty basic - just a folder containing special file.
Currently git, mercurial and bazaar repos are considered projects by default.
If you want to mark a folder manually as a project just create an empty
.projectile file in it.")
    (license license:gpl3+)))

(define-public emacs-elfeed
  (package
    (name "emacs-elfeed")
    (version "1.4.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/skeeto/elfeed/archive/"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0i75r8x9ypbfjlnym04h16ikcrlks86p7wsgawrx7mh1lk4inp89"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/skeeto/elfeed")
    (synopsis "Atom/RSS feed reader for Emacs")
    (description
     "Elfeed is an extensible web feed reader for Emacs, supporting both Atom
and RSS, with a user interface inspired by notmuch.")
    (license license:gpl3+)))

(define-public emacs-rainbow-delimiters
  (package
    (name "emacs-rainbow-delimiters")
    (version "2.1.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://raw.githubusercontent.com/Fanael"
                                  "/rainbow-delimiters/" version
                                  "/rainbow-delimiters.el"))
              (file-name (string-append "rainbow-delimiters-" version ".el"))
              (sha256
               (base32
                "1b3kampwsjabhcqdp0khgff13wc5jqhy3rbvaa12vnv7qy22l9ck"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/Fanael/rainbow-delimiters")
    (synopsis "Highlight brackets according to their depth")
    (description
     "Rainbow-delimiters is a \"rainbow parentheses\"-like mode for Emacs which
highlights parentheses, brackets, and braces according to their depth.  Each
successive level is highlighted in a different color, making it easy to spot
matching delimiters, orient yourself in the code, and tell which statements
are at a given level.")
    (license license:gpl3+)))

(define-public emacs-rainbow-identifiers
  (package
    (name "emacs-rainbow-identifiers")
    (version "0.2.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://raw.githubusercontent.com/Fanael"
                                  "/rainbow-identifiers/" version
                                  "/rainbow-identifiers.el"))
              (file-name (string-append "rainbow-identifiers-" version ".el"))
              (sha256
               (base32
                "0325abxj47k0g1i8nqrq70w2wr6060ckhhf92krv1s072b3jzm31"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/Fanael/rainbow-identifiers")
    (synopsis "Highlight identifiers in source code")
    (description
     "Rainbow identifiers mode is an Emacs minor mode providing highlighting of
identifiers based on their names.  Each identifier gets a color based on a hash
of its name.")
    (license license:bsd-2)))

(define-public emacs-visual-fill-column
  (package
    (name "emacs-visual-fill-column")
    (version "1.7")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://codeload.github.com/joostkremers/"
                                  "visual-fill-column/tar.gz/" version))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "12vn7kdq2mpz9hgibbn1vhpf23lcm7c26k3fkz8nidhygwl5x5lq"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/joostkremers/visual-fill-column")
    (synopsis "Fill-column for visual-line-mode")
    (description
     "@code{visual-fill-column-mode} is a small Emacs minor mode that mimics
the effect of @code{fill-column} in @code{visual-line-mode}.  Instead of
wrapping lines at the window edge, which is the standard behaviour of
@code{visual-line-mode}, it wraps lines at @code{fill-column}.  If
@code{fill-column} is too large for the window, the text is wrapped at the
window edge.")
    (license license:gpl3+)))

(define-public emacs-ido-completing-read+
  (package
    (name "emacs-ido-completing-read+")
    (version "3.12")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://raw.githubusercontent.com"
                                  "/DarwinAwardWinner/ido-ubiquitous/v"
                                  version "/ido-completing-read+.el"))
              (file-name (string-append "ido-completing-read+-" version ".el"))
              (sha256
               (base32
                "1cyalb0p7nfsm4n6n9q6rjmvn6adqc0fq8ybnlj3n41n289dkfjf"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/DarwinAwardWinner/ido-ubiquitous")
    (synopsis "Replacement for completing-read using ido")
    (description
     "The ido-completing-read+ function is a wrapper for ido-completing-read.
Importantly, it detects edge cases that ordinary ido cannot handle and either
adjusts them so ido can handle them, or else simply falls back to the standard
Emacs completion function instead.")
    (license license:gpl3+)))

(define-public emacs-ido-ubiquitous
  (package
    (name "emacs-ido-ubiquitous")
    (version "3.12")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://raw.githubusercontent.com"
                                  "/DarwinAwardWinner/ido-ubiquitous/v"
                                  version "/ido-ubiquitous.el"))
              (file-name (string-append "ido-ubiquitous-" version ".el"))
              (sha256
               (base32
                "197ypji0fb6jsdcq40rpnknwlh3imas6s6jbsvkfm0pz9988c3q2"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-ido-completing-read+" ,emacs-ido-completing-read+)))
    (home-page "https://github.com/DarwinAwardWinner/ido-ubiquitous")
    (synopsis "Use ido (nearly) everywhere")
    (description
     "Ido-ubiquitous enables ido-style completion for almost every function
that uses the standard completion function completing-read.")
  (license license:gpl3+)))

(define-public emacs-yaml-mode
  (package
    (name "emacs-yaml-mode")
    (version "0.0.12")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://raw.githubusercontent.com/yoshiki"
                                  "/yaml-mode/v" version "/yaml-mode.el"))
              (file-name (string-append "yaml-mode-" version ".el"))
              (sha256
               (base32
                "17wq433ycli0qx4gdhgrmb392qblm6y2dwcyn38j5ja1lasfb0ax"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/yoshiki/yaml-mode")
    (synopsis "Major mode for editing YAML files")
    (description
     "Yaml-mode is an Emacs major mode for editing files in the YAML data
serialization format.  It was initially developed by Yoshiki Kurihara and many
features were added by Marshall Vandegrift.  As YAML and Python share the fact
that indentation determines structure, this mode provides indentation and
indentation command behavior very similar to that of python-mode.")
    (license license:gpl3+)))

(define-public emacs-web-mode
  (package
    (name "emacs-web-mode")
    (version "14")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://raw.githubusercontent.com/fxbois"
                                  "/web-mode/v" version "/web-mode.el"))
              (file-name (string-append "web-mode-" version ".el"))
              (sha256
               (base32
                "086hik5fmxg3kx74qmransx9cz961qd22d4m6ah2dw6cwaj1s3s5"))))
    (build-system emacs-build-system)
    (synopsis "Major mode for editing web templates")
    (description "Web-mode is an Emacs major mode for editing web templates
aka HTML files embedding parts (CSS/JavaScript) and blocks (pre rendered by
client/server side engines).  Web-mode is compatible with many template
engines: PHP, JSP, ASP, Django, Twig, Jinja, Mustache, ERB, FreeMarker,
Velocity, Cheetah, Smarty, CTemplate, Mustache, Blade, ErlyDTL, Go Template,
Dust.js, React/JSX, Angularjs, ejs, etc.")
    (home-page "http://web-mode.org/")
    (license license:gpl3+)))

(define-public emacs-helm
  (package
    (name "emacs-helm")
    (version "1.9.8")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/" name "/helm/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "019dpzr6l83k1fgxn40aqxjvrpz4dl5d9vi7fc5wjnifmxaqxia6"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-async" ,emacs-async)
       ("emacs-popup" ,emacs-popup)))
    (home-page "https://emacs-helm.github.io/helm/")
    (synopsis "Incremental completion and selection narrowing
framework for Emacs")
    (description "Helm is incremental completion and selection narrowing
framework for Emacs.  It will help steer you in the right direction when
you're looking for stuff in Emacs (like buffers, files, etc).  Helm is a fork
of @code{anything.el} originally written by Tamas Patrovic and can be
considered to be its successor.  Helm sets out to clean up the legacy code in
@code{anything.el} and provide a cleaner, leaner and more modular tool, that's
not tied in the trap of backward compatibility.")
    (license license:gpl3+)))

(define-public emacs-cider
  (package
    (name "emacs-cider")
    (version "0.12.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/clojure-emacs/cider/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "00qzbfjy3w6bcnki7gw0clmi0cc5yqjdrcyhgv4ymijjs79h9p5s"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-clojure-mode" ,emacs-clojure-mode)
       ("emacs-spinner" ,emacs-spinner)
       ("emacs-pkg-info" ,emacs-pkg-info)
       ("emacs-queue" ,emacs-queue)
       ("emacs-seq" ,emacs-seq)))
    (home-page "https://cider.readthedocs.org/")
    (synopsis "Clojure development environment for Emacs")
    (description
     "CIDER (Clojure Interactive Development Environment that Rocks) aims to
provide an interactive development experience similar to the one you'd get
when programming in Emacs Lisp, Common Lisp (with SLIME or Sly), Scheme (with
Geiser) and Smalltalk.

CIDER is the successor to the now deprecated combination of using SLIME +
swank-clojure for Clojure development.

There are plenty of differences between CIDER and SLIME, but the core ideas
are pretty much the same (and SLIME served as the principle inspiration for
CIDER).")
    (license license:gpl3+)))

(define-public emacs-lua-mode
  (package
    (name "emacs-lua-mode")
    (version "20151025")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/immerrr/lua-mode/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0sbhfny5ib65cnx6xcy6h9bbw27mw034s8m9cca00bhxqaqi6p4v"))))
    (build-system emacs-build-system)
    (home-page "http://github.com/immerrr/lua-mode/")
    (synopsis "Major mode for lua")
    (description
     "This Emacs package provides a mode for @uref{https://www.lua.org/,
Lua programing language}.")
    (license license:gpl2+)))

(define-public emacs-ebuild-mode
  (package
    (name "emacs-ebuild-mode")
    (version "1.30")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://dev.gentoo.org/~ulm/emacs/ebuild-mode"
                    "-" version ".tar.xz"))
              (file-name (string-append name "-" version ".tar.xz"))
              (sha256
               (base32
                "0vp7lq1kvmh1b2bms2x1kf2k76dy9m02d7cirkxpiglwaxa0h9vz"))))
    (build-system emacs-build-system)
    (home-page "https://devmanual.gentoo.org")
    (synopsis "Major modes for Gentoo package files")
    (description
     "This Emacs package provides modes for ebuild, eclass, eblit, GLEP42
news items, openrc and runscripts.")
    (license license:gpl2+)))

(define-public emacs-evil
  (package
    (name "emacs-evil")
    (version "1.2.12")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://bitbucket.org/lyro/evil/get/"
                           version ".tar.bz2"))
       (file-name (string-append name "-" version ".tar.bz2"))
       (sha256
        (base32
         "17cda9fnbq3gmjcxs3lyq64gxswrf37y864bm53rldwsk3khq2yi"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-undo-tree" ,emacs-undo-tree)
       ("emacs-goto-chg" ,emacs-goto-chg)))
    (home-page "https://bitbucket.com/lyro/evil")
    (synopsis "Extensible Vi layer for Emacs")
    (description
     "Evil is an extensible vi layer for Emacs.  It emulates the
main features of Vim, and provides facilities for writing custom
extensions.")
    (license license:gpl3+)))

(define-public emacs-goto-chg
  (package
    (name "emacs-goto-chg")
    (version "1.6")
    (source
     (origin
       (method url-fetch)
       ;; There is no versioned source.
       (uri "https://www.emacswiki.org/emacs/download/goto-chg.el")
       (sha256
        (base32
         "078d6p4br5vips7b9x4v6cy0wxf6m5ij9gpqd4g33bryn22gnpij"))))
    (build-system emacs-build-system)
    ;; There is no other home page.
    (home-page "https://www.emacswiki.org/emacs/goto-chg.el")
    (synopsis "Go to the last change in the Emacs buffer")
    (description
     "This package provides @code{M-x goto-last-change} command that goes to
the point of the most recent edit in the current Emacs buffer.  When repeated,
go to the second most recent edit, etc.  Negative argument, @kbd{C-u -}, is
used for reverse direction.")
    (license license:gpl2+)))

(define-public emacs-writegood-mode
  (package
    (name "emacs-writegood-mode")
    (version "2.0.2")
    (home-page "http://github.com/bnbeckwith/writegood-mode")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url home-page)
                    (commit (string-append "v" version))))
              (sha256
               (base32
                "1nnjn1r669hvvzfycllwap4w04m8rfsk4nzcg8057m1f263kj31b"))
              (file-name (string-append name "-checkout"))))
    (build-system emacs-build-system)
    (synopsis "Polish up poor writing on the fly")
    (description
     "This minor mode tries to find and highlight problems with your writing
in English as you type.  It primarily detects \"weasel words\" and abuse of
passive voice.")
    (license license:gpl3+)))

(define-public emacs-neotree
  (package
    (name "emacs-neotree")
    (version "0.2.1")
    (home-page "https://github.com/jaypei/emacs-neotree")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/jaypei/" name
                    "/archive/v" version ".tar.gz"))
              (sha256
               (base32
                "0cr37pdkwjgfijfws5bjskfh1rq9rfngxblcj6v5383vpmn83q7s"))
              (file-name (string-append name "-" version ".tar.gz"))))
    (build-system emacs-build-system)
    (synopsis "Folder tree view for Emacs")
    (description "This Emacs package provides a folder tree view.")
    (license license:gpl3+)))

(define-public emacs-org
  (package
    (name "emacs-org")
    (version "20161214")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://elpa.gnu.org/packages/org-"
                                  version ".tar"))
              (sha256
               (base32
                "0pa9d0l6axif5wlzi7lvxl0fpjwwvc79cy9d37z7md4hxyjdvwzm"))))
    (build-system emacs-build-system)
    (home-page "http://orgmode.org/")
    (synopsis "Outline-based notes management and organizer")
    (description "Org is an Emacs mode for keeping notes, maintaining TODO
lists, and project planning with a fast and effective plain-text system.  It
also is an authoring system with unique support for literate programming and
reproducible research.")
    (license license:gpl3+)))

(define-public emacs-flx
  (package
    (name "emacs-flx")
    (version "0.6.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/lewang/"
                           "flx/archive/v" version ".tar.gz"))
       (sha256
        (base32
         "0bkcpnf1j4i2fcc2rllwbz62l00sw2mcia6rm5amgwvlkqavmkv6"))
       (file-name (string-append name "-" version ".tar.gz"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/lewang/flx")
    (synopsis "Fuzzy matching for Emacs")
    (description
     "Flx provides fuzzy matching for emacs a la sublime text.
The sorting algorithm is a balance between word beginnings (abbreviation)
and contiguous matches (substring).  The longer the substring match,
the higher it scores. This maps well to how we think about matching.
Flx has support for ido (interactively do things) through flx-ido.")
    (license license:gpl3+)))

(define-public emacs-cyberpunk-theme
  (package
    (name "emacs-cyberpunk-theme")
    (version "1.18")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/n3mo/cyberpunk-theme.el/"
                           "archive/" version ".tar.gz"))
       (sha256
        (base32
         "0pxzbw0qjxgkhhs3gn3k9qy41kl1a4pfzbw83dk24l4b3nxd24wg"))
       (file-name (string-append name "-" version ".tar.gz"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/n3mo/cyberpunk-theme.el")
    (synopsis "Cyberpunk theme for emacs built-in color theme support")
    (description
     "Cyberpunk color theme for the emacs 24+ built-in color theme support
known loosely as deftheme.  Many mode-specific customizations are included.")
    (license license:gpl3+)))

(define-public emacs-danneskjold-theme
  (let* ((commit "8733d2fe8743e8a01826ea6d4430ef376c727e57")
         (revision "1"))
    (package
      (name "emacs-danneskjold-theme")
      (version (string-append "0.0.0-" revision "." (string-take commit 7)))
      (home-page "https://github.com/rails-to-cosmos/danneskjold-theme")
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url home-page)
               (commit commit)))
         (file-name (string-append name "-" version "-checkout"))
         (sha256
          (base32
           "0s6rbsb0y8i8m5b9xm4gw1p1cxsxdqnqxqqb638pygz9f76mbir1"))))
      (build-system emacs-build-system)
      (arguments
       `(#:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'delete-screenshots
             (lambda _
               (delete-file-recursively "screenshots") #t)))))
      (synopsis "High-contrast Emacs theme")
      (description
       "@code{danneskjold-theme} is a high-contrast theme for Emacs.")
      (license license:gpl3+))))

(define-public emacs-auto-complete
  (package
    (name "emacs-auto-complete")
    (version "1.5.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/auto-complete/"
                           "auto-complete/archive/v" version ".tar.gz"))
       (sha256
        (base32
         "1jvq4lj00hwml75lpmlciazy8f3bbg13gffsfnl835p4qd8l7yqv"))
       (file-name (string-append name "-" version ".tar.gz"))))
    (build-system emacs-build-system)
    (propagated-inputs
     `(("emacs-popup" ,emacs-popup)))
    (home-page "https://github.com/auto-complete/auto-complete")
    (synopsis "Intelligent auto-completion extension for Emacs")
    (description
     "Auto-Complete is an intelligent auto-completion extension for Emacs.
It extends the standard Emacs completion interface and provides an environment
that allows users to concentrate more on their own work.  Its features are:
a visual interface, reduce overhead of completion by using statistic method,
extensibility.")
    (license license:gpl3+)))

(define-public m17n-db
  (package
    (name "m17n-db")
    (version "1.7.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://savannah/m17n/m17n-db-"
                           version ".tar.gz"))
       (sha256
        (base32 "1w08hnsbknrcjlzp42c99bgwc9hzsnf5m4apdv0dacql2s09zfm2"))))
    (build-system gnu-build-system)
    (inputs
     `(("gettext" ,gettext-minimal)))
    (arguments
     `(#:configure-flags
       (list (string-append "--with-charmaps="
                            (assoc-ref %build-inputs "libc")
                            "/share/i18n/charmaps"))))
    ;; With `guix lint' the home-page URI returns a small page saying
    ;; that your browser does not handle frames. This triggers the "URI
    ;; returns suspiciously small file" warning.
    (home-page "http://www.nongnu.org/m17n/")
    (synopsis "Multilingual text processing library (database)")
    (description "The m17n library realizes multilingualization of
many aspects of applications.  The m17n library represents
multilingual text as an object named M-text.  M-text is a string with
attributes called text properties, and designed to substitute for
string in C.  Text properties carry any information required to input,
display and edit the text.

This package contains the library database.")
    (license license:lgpl2.1+)))

(define-public m17n-lib
  (package
    (name "m17n-lib")
    (version "1.7.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://savannah/m17n/m17n-lib-"
                           version ".tar.gz"))
       (sha256
        (base32 "10yv730i25g1rpzv6q49m6xn4p8fjm7jdwvik2h70sn8w3hm7f4f"))))
    (build-system gnu-build-system)
    (inputs
     `(("fribidi" ,fribidi)
       ("gd" ,gd)
       ("libotf" ,libotf)
       ("libxft" ,libxft)
       ("libxml2" ,libxml2)
       ("m17n-db" ,m17n-db)))
    (arguments
     `(#:parallel-build? #f))
    ;; With `guix lint' the home-page URI returns a small page saying
    ;; that your browser does not handle frames. This triggers the "URI
    ;; returns suspiciously small file" warning.
    (home-page "http://www.nongnu.org/m17n/")
    (synopsis "Multilingual text processing library (runtime)")
    (description "The m17n library realizes multilingualization of
many aspects of applications.  The m17n library represents
multilingual text as an object named M-text.  M-text is a string with
attributes called text properties, and designed to substitute for
string in C.  Text properties carry any information required to input,
display and edit the text.

This package contains the library runtime.")
    (license license:lgpl2.1+)))

(define-public emacs-nginx-mode
  (package
    (name "emacs-nginx-mode")
    (version "1.1.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/ajc/nginx-mode/archive/v"
             version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1lvkj07kq0jkskr2f61vqb5rlrbnaz9a76ikq40w6925i2r970rr"))))
    (build-system emacs-build-system)
    (home-page "https://github.com/ajc/nginx-mode")
    (synopsis "Emacs major mode for editing nginx config files")
    (description "This package provides an Emacs major mode for
editing nginx config files.")
    (license license:gpl2+)))

(define-public emacs-stream
  (package
    (name "emacs-stream")
    (version "2.2.0")
    (home-page "https://github.com/NicolasPetton/stream")
    (source
     (origin
       (method url-fetch)
       (file-name (string-append name "-" version ".tar.gz"))
       (uri (string-append home-page "/archive/"version ".tar.gz"))
       (sha256
        (base32 "03ql4nqfz5pn55mjly6clhvc3g7x2d28kj7mrlqmigvjbql39xxc"))))
    (build-system emacs-build-system)
    (synopsis "Implementation of streams for Emacs")
    (description "This library provides an implementation of streams for Emacs.
Streams are implemented as delayed evaluation of cons cells.")
    (license license:gpl3+)))

(define-public emacs-el-search
  (let ((commit "f26277bfbb3fc3fc74beea6592f294c439796bd4")
        (revision "1"))
    (package
      (name "emacs-el-search")
      ;; No ufficial release.
      (version (string-append "0.0-" revision "." (string-take commit 7)))
      (home-page "https://github.com/emacsmirror/el-search")
      (source
       (origin
         (method git-fetch)
         (file-name (string-append name "-" version ".tar.gz"))
         (uri (git-reference
               (commit commit)
               (url (string-append home-page ".git"))))
         (sha256
          (base32 "12xf40h9sb7xxg2r97gsia94q02543mgiiiw46fzh1ac7b7993g6"))))
      (build-system emacs-build-system)
      (inputs `(("emacs-stream" ,emacs-stream)))
      (synopsis "Expression based interactive search for emacs-lisp-mode")
      (description "This package provides expression based interactive search
procedures for emacs-lisp-mode.")
      (license license:gpl3+))))
