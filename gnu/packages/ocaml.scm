;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Cyril Roelandt <tipecaml@gmail.com>
;;; Copyright © 2014, 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2015 David Hashe <david.hashe@dhashe.com>
;;; Copyright © 2016 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2016 Jan Nieuwenhuizen <janneke@gnu.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Julien Lepiller <julien@lepiller.eu>
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

(define-module (gnu packages ocaml)
  #:use-module ((guix licenses) #:hide (zlib))
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix svn-download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages base)
  #:use-module (gnu packages emacs)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages lynx)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages python)
  #:use-module (gnu packages m4)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages version-control)
  #:use-module (gnu packages curl))

(define-public ocaml
  (package
    (name "ocaml")
    (version "4.02.3")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://caml.inria.fr/pub/distrib/ocaml-"
                    (version-major+minor version)
                    "/ocaml-" version ".tar.xz"))
              (sha256
               (base32
                "1qwwvy8nzd87hk8rd9sm667nppakiapnx4ypdwcrlnav2dz6kil3"))
              (patches (search-patches "ocaml-CVE-2015-8869.patch"))))
    (build-system gnu-build-system)
    (native-search-paths
     (list (search-path-specification
            (variable "OCAMLPATH")
            (files (list (string-append "lib/ocaml"))))))
    (native-inputs
     `(("perl" ,perl)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("libx11" ,libx11)
       ;; For libiberty, needed for objdump support.
       ("gcc:lib" ,(canonical-package gcc-4.9) "lib")
       ("zlib" ,zlib)))                       ;also needed for objdump support
    (arguments
     `(#:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (web server))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-/bin/sh-references
                    (lambda* (#:key inputs #:allow-other-keys)
                      (let* ((sh (string-append (assoc-ref inputs "bash")
                                                "/bin/sh"))
                             (quoted-sh (string-append "\"" sh "\"")))
                        (with-fluids ((%default-port-encoding #f))
                          (for-each (lambda (file)
                                      (substitute* file
                                        (("\"/bin/sh\"")
                                         (begin
                                           (format (current-error-port) "\
patch-/bin/sh-references: ~a: changing `\"/bin/sh\"' to `~a'~%"
                                                   file quoted-sh)
                                           quoted-sh))))
                                    (find-files "." "\\.ml$"))
                          #t))))
         (replace 'configure
                  (lambda* (#:key outputs #:allow-other-keys)
                    (let* ((out (assoc-ref outputs "out"))
                           (mandir (string-append out "/share/man")))
                      ;; Custom configure script doesn't recognize
                      ;; --prefix=<PREFIX> syntax (with equals sign).
                      (zero? (system* "./configure"
                                      "--prefix" out
                                      "--mandir" mandir)))))
         (replace 'build
                  (lambda _
                    (zero? (system* "make" "-j" (number->string
                                                 (parallel-job-count))
                                    "world.opt"))))
         (delete 'check)
         (add-after 'install 'check
                    (lambda _
                      (with-directory-excursion "testsuite"
                        (zero? (system* "make" "all")))))
         (add-before 'check 'prepare-socket-test
                     (lambda _
                       (format (current-error-port)
                               "Spawning local test web server on port 8080~%")
                       (when (zero? (primitive-fork))
                         (run-server (lambda (request request-body)
                                       (values '((content-type . (text/plain)))
                                               "Hello!"))
                                     'http '(#:port 8080)))
                       (let ((file "testsuite/tests/lib-threads/testsocket.ml"))
                         (format (current-error-port)
                                 "Patching ~a to use localhost port 8080~%"
                                 file)
                         (substitute* file
                           (("caml.inria.fr") "localhost")
                           (("80") "8080")
                           (("HTTP1.0") "HTTP/1.0"))
                         #t))))))
    (home-page "https://ocaml.org/")
    (synopsis "The OCaml programming language")
    (description
     "OCaml is a general purpose industrial-strength programming language with
an emphasis on expressiveness and safety.  Developed for more than 20 years at
Inria it benefits from one of the most advanced type systems and supports
functional, imperative and object-oriented styles of programming.")
    ;; The compiler is distributed under qpl1.0 with a change to choice of
    ;; law: the license is governed by the laws of France.  The library is
    ;; distributed under lgpl2.0.
    (license (list qpl lgpl2.0))))

(define-public opam
  (package
    (name "opam")
    (version "1.2.2")
    (source (origin
              (method url-fetch)
              ;; Use the '-full' version, which includes all the dependencies.
              (uri (string-append
                    "https://github.com/ocaml/opam/releases/download/"
                    version "/opam-full-" version ".tar.gz")
               ;; (string-append "https://github.com/ocaml/opam/archive/"
               ;;                    version ".tar.gz")
               )
              (sha256
               (base32
                "004gwn6rbpcb53y3rpb3v23vk39rp2xmf0liyd5iy12ij8bigrhm"))))
    (build-system gnu-build-system)
    (arguments
     '(;; Sometimes, 'make -jX' would fail right after ./configure with
       ;; "Fatal error: exception End_of_file".
       #:parallel-build? #f

       ;; For some reason, 'ocp-build' needs $TERM to be set.
       #:make-flags `("TERM=screen"
                      ,(string-append "SHELL="
                                      (assoc-ref %build-inputs "bash")
                                      "/bin/sh"))
       #:test-target "tests"

       ;; FIXME: There's an obscure test failure:
       ;;   …/_obuild/opam/opam.asm install P1' failed.
       #:tests? #f

       #:phases (modify-phases %standard-phases
                 (add-before 'build 'pre-build
                   (lambda* (#:key inputs make-flags #:allow-other-keys)
                     (let ((bash (assoc-ref inputs "bash")))
                       (substitute* "src/core/opamSystem.ml"
                         (("\"/bin/sh\"")
                          (string-append "\"" bash "/bin/sh\"")))
                       ;; Build dependencies
                       (zero? (apply system* "make" "lib-ext" make-flags)))))
                 (add-before 'check 'pre-check
                   (lambda _
                     (setenv "HOME" (getcwd))
                     (and (system "git config --global user.email guix@gnu.org")
                          (system "git config --global user.name Guix")))))))
    (native-inputs
     `(("git" ,git)                               ;for the tests
       ("python" ,python)                         ;for the tests
       ("camlp4" ,camlp4)))
    (inputs
     `(("ocaml" ,ocaml)
       ("ncurses" ,ncurses)
       ("curl" ,curl)))
    (home-page "http://opam.ocamlpro.com/")
    (synopsis "Package manager for OCaml")
    (description
     "OPAM is a tool to manage OCaml packages.  It supports multiple
simultaneous compiler installations, flexible package constraints, and a
Git-friendly development workflow.")

    ;; The 'LICENSE' file waives some requirements compared to LGPLv3.
    (license lgpl3)))

(define-public camlp4
  (package
    (name "camlp4")
    (version "4.02+6")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/ocaml/camlp4/archive/"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0icdfzhsbgf89925gc8gl3fm8z2xzszzlib0v9dj5wyzkyv3a342"))
              (file-name (string-append name "-" version ".tar.gz"))))
    (build-system gnu-build-system)
    (native-inputs `(("ocaml" ,ocaml)
                     ("which" ,which)))
    (inputs `(("ocaml" ,ocaml)))
    (arguments
     '(#:tests? #f                                ;no documented test target
       #:phases (modify-phases %standard-phases
                  (replace
                   'configure
                   (lambda* (#:key outputs #:allow-other-keys)
                     ;; This is a home-made 'configure' script.
                     (let ((out (assoc-ref outputs "out")))
                       (zero? (system* "./configure"
                                       (string-append "--libdir=" out "/lib")
                                       (string-append "--bindir=" out "/bin")
                                       (string-append "--pkgdir=" out)))))))))
    (home-page "https://github.com/ocaml/camlp4")
    (synopsis "Write parsers in OCaml")
    (description
     "Camlp4 is a software system for writing extensible parsers for
programming languages.  It provides a set of OCaml libraries that are used to
define grammars as well as loadable syntax extensions of such grammars.
Camlp4 stands for Caml Preprocessor and Pretty-Printer and one of its most
important applications is the definition of domain-specific extensions of the
syntax of OCaml.")

    ;; This is LGPLv2 with an exception that allows packages statically-linked
    ;; against the library to be released under any terms.
    (license lgpl2.0)))

(define-public camlp5
  (package
    (name "camlp5")
    (version "6.14")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://camlp5.gforge.inria.fr/distrib/src/"
                                  name "-" version ".tgz"))
              (sha256
               (base32
                "1ql04iyvclpyy9805kpddc4ndjb5d0qg4shhi2fc6bixi49fvy89"))))
    (build-system gnu-build-system)
    (inputs
     `(("ocaml" ,ocaml)))
    (arguments
     `(#:tests? #f  ; XXX TODO figure out how to run the tests
       #:phases
       (modify-phases %standard-phases
         (replace 'configure
                  (lambda* (#:key outputs #:allow-other-keys)
                    (let* ((out (assoc-ref outputs "out"))
                           (mandir (string-append out "/share/man")))
                      ;; Custom configure script doesn't recognize
                      ;; --prefix=<PREFIX> syntax (with equals sign).
                      (zero? (system* "./configure"
                                      "--prefix" out
                                      "--mandir" mandir)))))
         (replace 'build
                  (lambda _
                    (zero? (system* "make" "-j" (number->string
                                                 (parallel-job-count))
                                    "world.opt")))))))
    (home-page "http://camlp5.gforge.inria.fr/")
    (synopsis "Pre-processor Pretty Printer for OCaml")
    (description
     "Camlp5 is a Pre-Processor-Pretty-Printer for Objective Caml.  It offers
tools for syntax (Stream Parsers and Grammars) and the ability to modify the
concrete syntax of the language (Quotations, Syntax Extensions).")
    ;; Most files are distributed under bsd-3, but ocaml_stuff/* is under qpl.
    (license (list bsd-3 qpl))))

(define-public hevea
  (package
    (name "hevea")
    (version "2.28")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://hevea.inria.fr/old/"
                                  name "-" version ".tar.gz"))
              (sha256
               (base32
                "14fns13wlnpiv9i05841kvi3cq4b9v2sw5x3ff6ziws28q701qnd"))))
    (build-system gnu-build-system)
    (inputs
     `(("ocaml" ,ocaml)))
    (arguments
     `(#:tests? #f  ; no test suite
       #:make-flags (list (string-append "PREFIX=" %output))
       #:phases (modify-phases %standard-phases
                  (delete 'configure)
                  (add-before 'build 'patch-/bin/sh
                    (lambda _
                      (substitute* "_tags"
                        (("/bin/sh") (which "sh")))
                      #t)))))
    (home-page "http://hevea.inria.fr/")
    (synopsis "LaTeX to HTML translator")
    (description
     "HeVeA is a LaTeX to HTML translator that generates modern HTML 5.  It is
written in Objective Caml.")
    (license qpl)))

(define-public coq
  (package
    (name "coq")
    (version "8.5pl2")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://coq.inria.fr/distrib/V" version
                                  "/files/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "0wyywia0darak2zmc5v0ra9rn0b9whwdfiahralm8v5za499s8w3"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("texlive" ,texlive)
       ("findlib" ,ocaml-findlib)
       ("hevea" ,hevea)))
    (inputs
     `(("ocaml" ,ocaml)
       ("lablgtk" ,lablgtk)
       ("camlp5" ,camlp5)))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (mandir (string-append out "/share/man"))
                    (browser "icecat -remote \"OpenURL(%s,new-tab)\""))
               (zero? (system* "./configure"
                               "-prefix" out
                               "-mandir" mandir
                               "-browser" browser
                               "-coqide" "opt")))))
         (replace 'build
           (lambda _
             (zero? (system* "make" "-j" (number->string
                                          (parallel-job-count))
                             "world"))))
         (delete 'check)
         (add-after 'install 'check
           (lambda _
             (with-directory-excursion "test-suite"
               (zero? (system* "make"))))))))
    (home-page "https://coq.inria.fr")
    (synopsis "Proof assistant for higher-order logic")
    (description
     "Coq is a proof assistant for higher-order logic, which allows the
development of computer programs consistent with their formal specification.
It is developed using Objective Caml and Camlp5.")
    ;; The code is distributed under lgpl2.1.
    ;; Some of the documentation is distributed under opl1.0+.
    (license (list lgpl2.1 opl1.0+))))

(define-public proof-general
  (package
    (name "proof-general")
    (version "4.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://proofgeneral.inf.ed.ac.uk/releases/"
                    "ProofGeneral-" version ".tgz"))
              (sha256
               (base32
                "09qb0myq66fw17v4ziz401ilsb5xlxz1nl2wsp69d0vrfy0bcrrm"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("which" ,which)
       ("emacs" ,emacs-minimal)
       ("texinfo" ,texinfo)))
    (inputs
     `(("host-emacs" ,emacs)
       ("perl" ,perl)
       ("coq" ,coq)))
    (arguments
     `(#:tests? #f  ; no check target
       #:make-flags (list (string-append "PREFIX=" %output)
                          (string-append "DEST_PREFIX=" %output))
       #:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (guix build emacs-utils))
       #:imported-modules (,@%gnu-build-system-modules
                           (guix build emacs-utils))
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (add-after 'unpack 'disable-byte-compile-error-on-warn
                    (lambda _
                      (substitute* "Makefile"
                        (("\\(setq byte-compile-error-on-warn t\\)")
                         "(setq byte-compile-error-on-warn nil)"))
                      #t))
         (add-after 'unpack 'patch-hardcoded-paths
                    (lambda* (#:key inputs outputs #:allow-other-keys)
                      (let ((out   (assoc-ref outputs "out"))
                            (coq   (assoc-ref inputs "coq"))
                            (emacs (assoc-ref inputs "host-emacs")))
                        (define (coq-prog name)
                          (string-append coq "/bin/" name))
                        (emacs-substitute-variables "coq/coq.el"
                          ("coq-prog-name"           (coq-prog "coqtop"))
                          ("coq-compiler"            (coq-prog "coqc"))
                          ("coq-dependency-analyzer" (coq-prog "coqdep")))
                        (substitute* "Makefile"
                          (("/sbin/install-info") "install-info"))
                        (substitute* "bin/proofgeneral"
                          (("^PGHOMEDEFAULT=.*" all)
                           (string-append all
                                          "PGHOME=$PGHOMEDEFAULT\n"
                                          "EMACS=" emacs "/bin/emacs")))
                        #t)))
         (add-after 'unpack 'clean
                    (lambda _
                      ;; Delete the pre-compiled elc files for Emacs 23.
                      (zero? (system* "make" "clean"))))
         (add-after 'install 'install-doc
                    (lambda* (#:key make-flags #:allow-other-keys)
                      ;; XXX FIXME avoid building/installing pdf files,
                      ;; due to unresolved errors building them.
                      (substitute* "Makefile"
                        ((" [^ ]*\\.pdf") ""))
                      (zero? (apply system* "make" "install-doc"
                                    make-flags)))))))
    (home-page "http://proofgeneral.inf.ed.ac.uk/")
    (synopsis "Generic front-end for proof assistants based on Emacs")
    (description
     "Proof General is a major mode to turn Emacs into an interactive proof
assistant to write formal mathematical proofs using a variety of theorem
provers.")
    (license gpl2+)))

(define-public ocaml-menhir
  (package
    (name "ocaml-menhir")
    (version "20161115")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://gallium.inria.fr/~fpottier/menhir/"
                    "menhir-" version ".tar.gz"))
              (sha256
               (base32
                "1j8nmcj2gq6hyyi16z27amiahplgrnk4ppchpm0v4qy80kwkf47k"))))
    (build-system gnu-build-system)
    (inputs
     `(("ocaml" ,ocaml)))
    (arguments
     `(#:parallel-build? #f ; Parallel build causes failure
       #:tests? #f ; No check target
       #:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (setenv "PREFIX" out))
             #t)))))
    (home-page "http://gallium.inria.fr/~fpottier/menhir")
    (synopsis "Parser generator")
    (description "Menhir is a parser generator.  It turns high-level grammar
specifications, decorated with semantic actions expressed in the OCaml
programming language into parsers, again expressed in OCaml. It is based on
Knuth’s LR(1) parser construction technique.")
    ;; The file src/standard.mly and all files listed in src/mnehirLib.mlpack
    ;; that have an *.ml or *.mli extension are GPL licensed. All other files
    ;; are QPL licensed.
    (license (list gpl2+ qpl))))

(define-public lablgtk
  (package
    (name "lablgtk")
    (version "2.18.5")
    (source
      (origin
        (method url-fetch)
          (uri (string-append "https://forge.ocamlcore.org/frs/download.php/"
                              "1627/lablgtk-2.18.5.tar.gz"))
          (sha256
            (base32
              "0cyj6sfdvzx8hw7553lhgwc0krlgvlza0ph3dk9gsxy047dm3wib"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("camlp4" ,camlp4)
       ("ocaml" ,ocaml)
       ("findlib" ,ocaml-findlib)
       ("pkg-config" ,pkg-config)))
    ;; FIXME: Add inputs gtkgl-2.0, libpanelapplet-2.0, gtkspell-2.0,
    ;; and gtk+-quartz-2.0 once available.
    (inputs
     `(("gtk+" ,gtk+-2)
       ("gtksourceview" ,gtksourceview-2)
       ("libgnomecanvas" ,libgnomecanvas)
       ("libgnomeui" ,libgnomeui)
       ("libglade" ,libglade)
       ("librsvg" ,librsvg)))
    (arguments
     `(#:tests? #f ; no check target

       ;; opt: also install cmxa files
       #:make-flags (list "all" "opt"
                          (string-append "FINDLIBDIR="
                                         (assoc-ref %outputs "out")
                                         "/lib/ocaml"))
       ;; Occasionally we would get "Error: Unbound module GtkThread" when
       ;; compiling 'gtkThInit.ml', with 'make -j'.  So build sequentially.
       #:parallel-build? #f

       #:phases
         (modify-phases %standard-phases
           (add-before 'install 'prepare-install
             (lambda* (#:key inputs outputs #:allow-other-keys)
               (let ((out (assoc-ref outputs "out"))
                     (ocaml (assoc-ref inputs "ocaml")))
                 ;; Install into the output and not the ocaml directory.
                 (mkdir-p (string-append out "/lib/ocaml"))
                 (substitute* "config.make"
                   ((ocaml) out))
                 #t))))))
    (home-page "http://lablgtk.forge.ocamlcore.org/")
    (synopsis "GTK+ bindings for OCaml")
    (description
     "LablGtk is an OCaml interface to GTK+ 1.2 and 2.x.  It provides
a strongly-typed object-oriented interface that is compatible with the
dynamic typing of GTK+.  Most widgets and methods are available.  LablGtk
also provides bindings to
gdk-pixbuf, the GLArea widget (in combination with LablGL), gnomecanvas,
gnomeui, gtksourceview, gtkspell,
libglade (and it an generate OCaml code from .glade files),
libpanel, librsvg and quartz.")
    (license lgpl2.1)))

(define-public unison
  (package
    (name "unison")
    (version "2.48.3")
    (source
      (origin
        (method svn-fetch)
        (uri (svn-reference
              (url (string-append "https://webdav.seas.upenn.edu/svn/"
                                  "unison/branches/"
                                  (version-major+minor version)))
              (revision 535)))
        (file-name (string-append name "-" version "-checkout"))
        (sha256
         (base32
          "0486s53wyayicj9f2raj2dvwvk4xyzar219rccc1iczdwixm4x05"))
        (modules '((guix build utils)
                   (ice-9 rdelim)
                   (ice-9 regex)
                   (srfi srfi-1)))
        (snippet
         `(begin
            ;; The svn revision in the release tarball appears to be
            ;; artificially manipulated in order to set the desired point
            ;; version number.  Because the point version is calculated during
            ;; the build, we can offset pointVersionOrigin by the desired
            ;; point version and write that into "Rev: %d".  We do this rather
            ;; than hardcoding the necessary revision number, for
            ;; maintainability.
            (with-atomic-file-replacement "src/mkProjectInfo.ml"
              (lambda (in out)
                (let ((pt-ver (string->number (third (string-split ,version #\.))))
                      (pt-rx  (make-regexp "^let pointVersionOrigin = ([0-9]+)"))
                      (rev-rx (make-regexp "Rev: [0-9]+")))
                  (let loop ((pt-origin #f))
                    (let ((line (read-line in 'concat)))
                      (cond
                       ((regexp-exec pt-rx line)
                        => (lambda (m)
                             (display line out)
                             (loop (string->number (match:substring m 1)))))
                       ((regexp-exec rev-rx line)
                        => (lambda (m)
                             (format out "~aRev: ~d~a"
                                     (match:prefix m)
                                     (+ pt-origin pt-ver)
                                     (match:suffix m))
                             (dump-port in out))) ;done
                       (else
                        (display line out)
                        (loop pt-origin))))))))
            ;; Without the '-fix' argument, the html file produced does not
            ;; have functioning internal hyperlinks.
            (substitute* "doc/Makefile"
              (("hevea unison") "hevea -fix unison"))))))
    (build-system gnu-build-system)
    (outputs '("out"
               "doc"))                  ; 1.9 MiB of documentation
    (native-inputs
     `(("ocaml" ,ocaml)
       ;; For documentation
       ("ghostscript" ,ghostscript)
       ("texlive" ,texlive)
       ("hevea" ,hevea)
       ("lynx" ,lynx)))
    (arguments
     `(#:parallel-build? #f
       #:parallel-tests? #f
       #:test-target "selftest"
       #:tests? #f ; Tests require writing to $HOME.
                   ; If some $HOME is provided, they fail with the message
                   ; "Fatal error: Skipping some tests -- remove me!"
       #:phases
         (modify-phases %standard-phases
           (delete 'configure)
           (add-before 'install 'prepare-install
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out"))
                      (bin (string-append out "/bin")))
                 (mkdir-p bin)
                 (setenv "HOME" out) ; forces correct INSTALLDIR in Makefile
                 #t)))
           (add-after 'install 'install-fsmonitor
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out"))
                      (bin (string-append out "/bin")))
                 ;; 'unison-fsmonitor' is used in "unison -repeat watch" mode.
                 (install-file "src/unison-fsmonitor" bin))))
           (add-after 'install 'install-doc
             (lambda* (#:key outputs #:allow-other-keys)
               (let ((doc (string-append (assoc-ref outputs "doc")
                                         "/share/doc/unison")))
                 (mkdir-p doc)
                 ;; This file needs write-permissions, because it's
                 ;; overwritten by 'docs' during documentation generation.
                 (chmod "src/strings.ml" #o600)
                 (and (zero? (system* "make" "docs"
                                      "TEXDIRECTIVES=\\\\draftfalse"))
                      (begin
                        (for-each (lambda (f)
                                    (install-file f doc))
                                  (map (lambda (ext)
                                         (string-append
                                          "doc/unison-manual." ext))
                                       ;; Install only html documentation,
                                       ;; since the build is currently
                                       ;; non-reproducible with the ps, pdf,
                                       ;; and dvi docs.
                                       '(;;"ps" "pdf" "dvi"
                                         "html")))
                        #t))))))))
    (home-page "https://www.cis.upenn.edu/~bcpierce/unison/")
    (synopsis "File synchronizer")
    (description
     "Unison is a file-synchronization tool.  It allows two replicas of
a collection of files and directories to be stored on different hosts
(or different disks on the same host), modified separately, and then
brought up to date by propagating the changes in each replica
to the other.")
    (license gpl3+)))

(define-public ocaml-findlib
  (package
    (name "ocaml-findlib")
    (version "1.6.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://download.camlcity.org/download/"
                                  "findlib" "-" version ".tar.gz"))
              (sha256
               (base32
                "02abg1lsnwvjg3igdyb8qjgr5kv1nbwl4gaf8mdinzfii5p82721"))
              (patches (search-patches "ocaml-findlib-make-install.patch"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("camlp4" ,camlp4)
       ("m4" ,m4)
       ("ocaml" ,ocaml)))
    (arguments
     `(#:tests? #f  ; no test suite
       #:parallel-build? #f
       #:make-flags (list "all" "opt")
       #:phases (modify-phases %standard-phases
                  (replace
                   'configure
                   (lambda* (#:key inputs outputs #:allow-other-keys)
                     (let ((out (assoc-ref outputs "out")))
                       (system*
                        "./configure"
                        "-bindir" (string-append out "/bin")
                        "-config" (string-append out "/etc/ocamfind.conf")
                        "-mandir" (string-append out "/share/man")
                        "-sitelib" (string-append out "/lib/ocaml/site-lib")
                        "-with-toolbox")))))))
    (home-page "http://projects.camlcity.org/projects/findlib.html")
    (synopsis "Management tool for OCaml libraries")
    (description
     "The \"findlib\" library provides a scheme to manage reusable software
components (packages), and includes tools that support this scheme.  Packages
are collections of OCaml modules for which metainformation can be stored.  The
packages are kept in the file system hierarchy, but with strict directory
structure.  The library contains functions to look the directory up that
stores a package, to query metainformation about a package, and to retrieve
dependency information about multiple packages.  There is also a tool that
allows the user to enter queries on the command-line.  In order to simplify
compilation and linkage, there are new frontends of the various OCaml
compilers that can directly deal with packages.")
    (license x11)))
