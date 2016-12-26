;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Steve Sprang <scs@stevesprang.com>
;;; Copyright © 2015, 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2015 Aljosha Papsch <misc@rpapsch.de>
;;; Copyright © 2016 Christopher Allan Webber <cwebber@dustycloud.org>
;;; Copyright © 2016 Jessica Tallon <tsyesika@tsyesika.se>
;;; Copyright © 2016 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2016 Lukas Gradl <lgradl@openmailbox.org>
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

(define-module (gnu packages password-utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system gnu)
  #:use-module (guix download)
  #:use-module (guix packages)
  #:use-module (gnu packages)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages base)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages man)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages qt)
  #:use-module (gnu packages version-control)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xorg)
  #:use-module (guix build-system python))

(define-public pwgen
  (package
    (name "pwgen")
    (version "2.07")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/pwgen/pwgen/" version
                           "/pwgen-" version ".tar.gz"))
       (sha256
        (base32 "0mhmw700kkh238fzivcwnwi94bj9f3h36yfh3k3j2v19b0zmjx7b"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f)) ; no test suite
    (home-page "http://pwgen.sourceforge.net/")
    (synopsis "Password generator")
    (description "Pwgen generates passwords which can be easily memorized by a
human.")
    (license license:gpl2)))

(define-public keepassx
  (package
    (name "keepassx")
    (version "2.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://www.keepassx.org/releases/" version
                           "/keepassx-" version ".tar.gz"))
       (sha256
        (base32
         "1ia7cqx9ias38mnffsl7da7g1f66bcbjsi23k49sln0c6spb9zr3"))))
    (build-system cmake-build-system)
    (inputs
     `(("libgcrypt" ,libgcrypt)
       ("libxi" ,libxi)
       ("libxtst" ,libxtst)
       ("qt" ,qt-4)))
    (native-inputs
     `(("zlib" ,zlib)))
    (home-page "https://www.keepassx.org")
    (synopsis "Password manager")
    (description "KeePassX is a password manager or safe which helps you to
manage your passwords in a secure way.  You can put all your passwords in one
database, which is locked with one master key or a key-file which can be stored
on an external storage device.  The databases are encrypted using the
algorithms AES or Twofish.")
    ;; Non functional parts use various licences.
    (license license:gpl3)))

(define-public shroud
  (package
    (name "shroud")
    (version "0.1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://files.dthompson.us/shroud/shroud-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1y43yhgy2zbrk5bqj3qyx9rkcz2bma9sinlrg7dip3jqms9gq4lr"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (add-after 'install 'wrap-shroud
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out       (assoc-ref outputs "out"))
                    (ccachedir (string-append out "/lib/guile/2.0/ccache"))
                    (prog      (string-append out "/bin/shroud")))
               (wrap-program prog
                 `("GUILE_LOAD_COMPILED_PATH" ":" prefix (,ccachedir)))
               #t))))))
    (inputs
     `(("guile" ,guile-2.0)
       ("gnupg" ,gnupg)
       ("xclip" ,xclip)))
    (synopsis "GnuPG-based secret manager")
    (description "Shroud is a simple secret manager with a command line
interface.  The password database is stored as a Scheme s-expression and
encrypted with a GnuPG key.  Secrets consist of an arbitrary number of
key/value pairs, making Shroud suitable for more than just password storage.
For copying and pasting secrets into web browsers and other graphical
applications, there is xclip integration." )
    (home-page "http://dthompson.us/pages/software/shroud.html")
    (license license:gpl3+)))

(define-public yapet
  (package
    (name "yapet")
    (version "1.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.guengel.ch/myapps/yapet/downloads/yapet-"
                                  version
                                  ".tar.bz2"))
              (sha256
               (base32
                "0ydbnqw6icdh07pnv2w6dhvq501bdfvrklv4xmyr8znca9d753if"))))
    (build-system gnu-build-system)
    (inputs
     `(("ncurses" ,ncurses)
       ("openssl" ,openssl)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (synopsis "Yet Another Password Encryption Tool")
    (description "YAPET is a text based password manager using the Blowfish
encryption algorithm.  Because of its small footprint and very few library
dependencies, it is suited for installing on desktop and server systems alike.
The text based user interface allows you to run YAPET easily in a Secure Shell
session.  Two companion utilities enable users to convert CSV files to YAPET
and vice versa.")
    (home-page "http://www.guengel.ch/myapps/yapet/")
    (license license:gpl3+)))

(define-public cracklib
  (package
    (name "cracklib")
    (version "2.9.6")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/cracklib/cracklib/"
                                  "releases/download/" name "-" version "/"
                                  name "-" version ".tar.gz"))
              (patches (search-patches "cracklib-CVE-2016-6318.patch"))
              (sha256
               (base32
                "0hrkb0prf7n92w6rxgq0ilzkk6rkhpys2cfqkrbzswp27na7dkqp"))))
    (build-system gnu-build-system)
    (synopsis "Password checking library")
    (home-page "https://github.com/cracklib/cracklib")
    (description
     "CrackLib is a library containing a C function which may be used in a
passwd like program.  The idea is simple: try to prevent users from choosing
passwords that could be guessed by crack by filtering them out, at source.")
    (license license:lgpl2.1)))

(define-public libpwquality
  (package
    (name "libpwquality")
    (version "1.3.0")
    (source (origin
              (method url-fetch)
              (uri (list
                    (string-append "https://fedorahosted.org/releases/l/i/"
                                   name "/" name "-" version ".tar.bz2")
                    (string-append "https://launchpad.net/libpwquality/trunk/"
                                   version "/+download/"
                                   name "-" version ".tar.bz2")))
              (sha256
               (base32
                "0aidriag6h0syfm33nzdfdsqgrnsgihwjv3a5lgkqch3w68fmlkl"))))
    (build-system gnu-build-system)
    (arguments
     ;; XXX: have RUNPATH issue.
     '(#:configure-flags '("--disable-python-bindings")))
    (inputs
     `(("cracklib" ,cracklib)))
    (synopsis "Password quality checker")
    (home-page "https://fedorahosted.org/libpwquality/")
    (description
     "Libpwquality is a library for password quality checking and generation of
random passwords that pass the checks.")
    (license license:gpl2+)))

(define-public assword
  (package
    (name "assword")
    (version "0.8")
    (source (origin
              (method url-fetch)
              (uri (list
                    (string-append
                     "http://http.debian.net/debian/pool/main/a/assword/"
                     "assword_" version ".orig.tar.gz")))
              (sha256
               (base32
                "0dl4wizbi0r21wxzykm8s445xbvqim5nabi799dmpkdnnh8i546i"))))
    (arguments
     `(#:python ,python-2
       ;; irritatingly, tests do run but not there are two problems:
       ;;  - "import gtk" fails for unknown reasons here despite it the
       ;;    program working (indeed, I've found I have to do a logout and log
       ;;    back in in after an install order for some mumbo jumbo environment
       ;;    variable mess to work with pygtk and assword... what's up with
       ;;    that?)
       ;;  - even when the tests fail, they don't return a nonzero status,
       ;;    so I'm not sure how to programmatically get that information
       #:tests? #f
       #:phases
       (modify-phases %standard-phases
         (add-after 'install 'manpage
           (lambda* (#:key outputs #:allow-other-keys)
             (and
              (zero? (system* "make" "assword.1"))
              (install-file
               "assword.1"
               (string-append (assoc-ref outputs "out") "/share/man/man1"))))))))
    (build-system python-build-system)
    (native-inputs
     `(("help2man" ,help2man)))
    (inputs
     `(("python2-xdo" ,python2-xdo)
       ("python2-pygpgme" ,python2-pygpgme)
       ("python2-pygtk" ,python2-pygtk)))
    (propagated-inputs
     `(("xclip" ,xclip)))
    (home-page "https://finestructure.net/assword/")
    (synopsis "Password manager")
    (description "assword is a simple password manager using GPG-wrapped
JSON files.  It has a command line interface as well as a very simple
graphical interface, which can even \"type\" your passwords into
any X11 window.")
    (license license:gpl3+)))

(define-public password-store
  (package
    (name "password-store")
    (version "1.6.5")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "https://git.zx2c4.com/password-store/snapshot/"
                              name "-" version ".tar.xz"))
              (sha256
               (base32
                "05bk3lrp5jwg0v338lvylp7glpliydzz4jf5pjr6k3kagrv3jyik"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (delete 'build)
         (add-after 'install 'wrap-path
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out"))
                   (path (map (lambda (pkg)
                                (string-append (assoc-ref inputs pkg) "/bin"))
                              '("coreutils" "getopt" "git" "gnupg" "pwgen"
                                "sed" "tree" "which" "xclip"))))
               (wrap-program (string-append out "/bin/pass")
                 `("PATH" ":" prefix (,(string-join path ":"))))))))
       #:make-flags (list "CC=gcc" (string-append "PREFIX=" %output))
       ;; Parallel tests may cause a race condition leading to a
       ;; timeout in some circumstances.
       #:parallel-tests? #f
       #:test-target "test"))
    (inputs
     `(("getopt" ,util-linux)
       ("git" ,git)
       ("gnupg" ,gnupg)
       ("pwgen" ,pwgen)
       ("sed" ,sed)
       ("tree" ,tree)
       ("which" ,which)
       ("xclip" ,xclip)))
    (home-page "http://www.passwordstore.org/")
    (synopsis "Encrypted password manager")
    (description "Password-store is a password manager which uses GnuPG to
store and retrieve passwords.  The tool stores each password in its own
GnuPG-encrypted file, allowing the program to be simple yet secure.
Synchronization is possible using the integrated git support, which commits
changes to your password database to a git repository that can be managed
through the pass command.")
    (license license:gpl2+)))

(define-public argon2
  (package
    (name "argon2")
    (version "20161029")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "https://github.com/P-H-C/phc-winner-argon2/archive/"
                       version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1rymikbysasdadm325jx69i0q19d9srqkny69jwmhswlidr4j07y"))))
    (build-system gnu-build-system)
    (arguments
     `(#:test-target "test"
       #:make-flags '("CC=gcc")
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'install
           (lambda _
             (let ((out (assoc-ref %outputs "out")))
               (install-file "argon2" (string-append out "/bin"))
               (install-file "libargon2.a" (string-append out "/lib"))
               (install-file "libargon2.so" (string-append out "/lib"))
               (copy-recursively "include"
                                 (string-append out "/include"))))))))
    (home-page "https://www.argon2.com/")
    (synopsis "Password hashing library")
    (description "Argon2 provides a key derivation function that was declared
winner of the 2015 Password Hashing Competition.")
    (license license:cc0)))

(define-public python-bcrypt
  (package
    (name "python-bcrypt")
    (version "3.1.0")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "bcrypt" version))
        (sha256
         (base32
          "1giy0dvd8gvq6flxh44np1v2nqwsji5qsnrz038mgwzgp7c20j75"))))
        (build-system python-build-system)
    (native-inputs
     `(("python-pycparser" ,python-pycparser)
       ("python-pytest" ,python-pytest)))
    (propagated-inputs
     `(("python-cffi" ,python-cffi)
       ("python-six" ,python-six)))
    (home-page "https://github.com/pyca/bcrypt/")
    (synopsis
     "Modern password hashing library")
    (description
     "Bcrypt is a Python module which provides a password hashing method based
on the Blowfish password hashing algorithm, as described in
@url{http://static.usenix.org/events/usenix99/provos.html,\"A Future-Adaptable
Password Scheme\"} by Niels Provos and David Mazieres.")
    (license license:asl2.0)))

(define-public python2-bcrypt
  (package-with-python2 python-bcrypt))
