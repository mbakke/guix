;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Cyril Roelandt <tipecaml@gmail.com>
;;; Copyright © 2014 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Alex Griffin <a@ajgrf.com>
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

(define-module (gnu packages screen)
  #:use-module (guix licenses)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages python)
  #:use-module (gnu packages slang)
  #:use-module (gnu packages texinfo))

(define-public screen
  (package
    (name "screen")
    (version "4.4.0")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/screen/screen-"
                                 version ".tar.gz"))
             (sha256
              (base32 "12r12xwhsg59mlprikbbmn60gh8lqhrvyar7mlxg4fwsfma2lwpg"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("makeinfo" ,texinfo)))
    (inputs
     `(("ncurses" ,ncurses)
       ("perl" ,perl)))
    (arguments
     `(#:configure-flags
       ;; By default, screen supports 16 colors, but we want 256 when
       ;; ~/.screenrc contains 'term xterm-256color'.
       '("--enable-colors256")))
    (home-page "http://www.gnu.org/software/screen/")
    (synopsis "Full-screen window manager providing multiple terminals")
    (description
     "GNU Screen is a terminal window manager that multiplexes a single
terminal between several processes.  The virtual terminals each provide
features such as a scroll-back buffer and a copy-and-paste mechanism.  Screen
then manages the different virtual terminals, allowing you to easily switch
between them, to detach them from the current session, or even splitting the
view to show two terminals at once.")
    (license gpl2+)))

(define-public dtach
  (package
    (name "dtach")
    (version "0.9")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/" name "/" name "/"
                                  version "/" name "-" version ".tar.gz"))
              (sha256
               (base32
                "1wwj2hlngi8qn2pisvhyfxxs8gyqjlgrrv5lz91w8ly54dlzvs9j"))))
    (build-system gnu-build-system)
    (arguments
     ;; No install target.
     '(#:phases
       (modify-phases %standard-phases
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (install-file "dtach" (string-append out "/bin"))))))
       ;; No check target.
       #:tests? #f))
    (home-page "http://dtach.sourceforge.net/")
    (synopsis "Emulates the detach feature of screen")
    (description
     "dtach is a tiny program that emulates the detach feature of screen,
allowing you to run a program in an environment that is protected from the
controlling terminal and attach to it later.")
    (license gpl2+)))

(define-public byobu
  (package
    (name "byobu")
    (version "5.98")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://launchpad.net/byobu/trunk/"
                           version "/+download/byobu_"
                           version ".orig.tar.gz"))
       (sha256
        (base32
         "1s8nh4wbds1nh52i0d1hy1b308jjf4siwpq92lna1zh9ll4x71j5"))
       (patches (search-patches "byobu-writable-status.patch"))))
    (build-system gnu-build-system)
    (inputs
     `(("python" ,python-wrapper)       ;for config and session GUIs
       ("python-newt" ,newt "python")))
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before
          'configure 'provide-locale
          (lambda* (#:key inputs #:allow-other-keys)
            (let ((libc   (assoc-ref inputs "libc"))) ;implicit input
              (substitute* "usr/bin/byobu.in"
                (("locale") (string-append libc "/bin/locale"))))))
         (add-after
          'install 'wrap-python-scripts
          (lambda* (#:key inputs outputs #:allow-other-keys)
            (let* ((python (string-append (assoc-ref inputs "python")
                                          "/bin/python"))
                   (out    (assoc-ref outputs "out"))
                   (config (string-append out "/bin/byobu-config"))
                   (select (string-append out "/bin/byobu-select-session")))
              (wrap-program config
                `("BYOBU_PYTHON" = (,python))
                `("PYTHONPATH" ":" prefix (,(getenv "PYTHONPATH"))))
              (wrap-program select
                `("BYOBU_PYTHON" = (,python)))
              #t))))))
    (home-page "http://byobu.co/index.html")
    (synopsis "Text-based window manager and terminal multiplexer")
    (description
     "Byobu is a Japanese term for decorative, multi-panel screens that serve
as folding room dividers.  The Byobu software includes an enhanced profile,
configuration utilities, and system status notifications for the GNU Screen
window manager as well as the Tmux terminal multiplexer.")
    (license gpl3+)))

(define-public reptyr
  (package
    (name "reptyr")
    (version "0.6.2")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/nelhage/reptyr/archive"
                           "/reptyr-" version ".tar.gz"))
       (sha256
        (base32
         "07pfl0rkgm8m3f3jy8r9l2yvnhf8lgllpsk3mh57mhzdxq8fagf7"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ; no tests
       #:make-flags (list "CC=gcc"
                          (string-append "PREFIX=" %output))
       #:phases (modify-phases %standard-phases (delete 'configure))))
    (home-page "https://github.com/nelhage/reptyr")
    (synopsis "Tool for reparenting a running program to a new terminal")
    (description
     "reptyr is a utility for taking an existing running program and attaching
it to a new terminal.  Started a long-running process over @code{ssh}, but have
to leave and don't want to interrupt it?  Just start a @code{screen}, use
reptyr to grab it, and then kill the @code{ssh} session and head on home.")
    (license expat)))
