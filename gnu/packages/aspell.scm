;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015, 2016 Alex Kost <alezost@gmail.com>
;;; Copyright © 2016 John Darrington <jmd@gnu.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Christopher Andersson <christopher@8bits.nu>
;;; Copyright © 2016 Theodoros Foradis <theodoros.for@openmailbox.org>
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

(define-module (gnu packages aspell)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix licenses)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages base))

(define-public aspell
  (package
    (name "aspell")
    (version "0.60.6.1")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/aspell/aspell-"
                          version ".tar.gz"))
      (sha256
       (base32
        "1qgn5psfyhbrnap275xjfrzppf5a83fb67gpql0kfqv37al869gm"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'install 'wrap-aspell
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((bin/aspell (string-append (assoc-ref outputs "out")
                                              "/bin/aspell")))
               (wrap-program bin/aspell
                 '("ASPELL_CONF" "" =
                   ("${ASPELL_CONF:-\"dict-dir ${GUIX_PROFILE:-$HOME/.guix-profile}/lib/aspell\"}")))))))))
    (inputs `(("perl" ,perl)))
    (home-page "http://aspell.net/")
    (synopsis "Spell checker")
    (description
     "Aspell is a spell-checker which can be used either as a library or as
a standalone program.  Notable features of Aspell include its full support of
documents written in the UTF-8 encoding and its ability to use multiple
dictionaries, including personal ones.")
    (license lgpl2.1+)))


;;;
;;; Dictionaries.
;;;
;;; Use 'export ASPELL_CONF="dict-dir $HOME/.guix-profile/lib/aspell"' to use
;;; them.
;;;

(define* (aspell-dictionary dict-name full-name
                            #:key version sha256 (prefix "aspell6-"))
  (package
    (name (string-append "aspell-dict-" dict-name))
    (version version)
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/aspell/dict/" dict-name
                                  "/" prefix dict-name "-"
                                  version ".tar.bz2"))
              (sha256 sha256)))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (zero? (system* "./configure"))))))
       #:make-flags
       (let ((out (assoc-ref %outputs "out")))
         (list (string-append "dictdir=" out "/lib/aspell")
               (string-append "datadir=" out "/lib/aspell")))
       #:tests? #f))
    (native-inputs `(("aspell" ,aspell)
                     ("which" ,which)))
    (synopsis (string-append full-name " dictionary for GNU Aspell")) ; XXX: i18n
    (description
     "This package provides a dictionary for the GNU Aspell spell checker.")
    (license gpl2+)
    (home-page "http://aspell.net/")))


(define-public aspell-dict-de
  (aspell-dictionary "de" "German"
                     #:version "20030222-1"
                     #:sha256
                     (base32
                      "01p92qj66cqb346gk7hjfynaap5sbcn85xz07kjfdq623ghr8v5s")))

(define-public aspell-dict-en
  (aspell-dictionary "en" "English"
                     #:version "2016.11.20-0"
                     #:sha256
                     (base32
                      "1496jnhh2jvhkzcj0p4vy89bcs4g5wz6a76m33vw4dhchn5xm9jw")))

(define-public aspell-dict-eo
  (aspell-dictionary "eo" "Esperanto"
                     #:version "2.1.20000225a-2"
                     #:sha256
                     (base32
                      "09vf0mbiicbmyb4bwb7v7lgpabnylg0wy7m3hlhl5rjdda6x3lj1")))

(define-public aspell-dict-es
  (aspell-dictionary "es" "Spanish"
                     #:version "1.11-2"
                     #:sha256
                     (base32
                      "1k5g328ac1hdpp6fsg57d8md6i0aqcwlszp3gbmp5706wyhpydmd")))

(define-public aspell-dict-fr
  (aspell-dictionary "fr" "French"
                     #:version "0.50-3"
                     #:prefix "aspell-"
                     #:sha256
                     (base32
                      "14ffy9mn5jqqpp437kannc3559bfdrpk7r36ljkzjalxa53i0hpr")))

(define-public aspell-dict-ru
  (aspell-dictionary "ru" "Russian"
                     #:version "0.99f7-1"
                     #:sha256
                     (base32
                      "0ip6nq43hcr7vvzbv4lwwmlwgfa60hrhsldh9xy3zg2prv6bcaaw")))

(define-public aspell-dict-it
  (aspell-dictionary "it" "Italian"
                     #:version "2.2_20050523-0"
                     #:sha256
                     (base32
                      "1gdf7bc1a0kmxsmphdqq8pl01h667mjsj6hihy6kqy14k5qdq69v")))

(define-public aspell-dict-nl
  (aspell-dictionary "nl" "Dutch"
                     #:version "0.50-2"
                     #:prefix "aspell-"
                     #:sha256
                     (base32
                      "0ffb87yjsh211hllpc4b9khqqrblial4pzi1h9r3v465z1yhn3j4")))

(define-public aspell-dict-he
  (aspell-dictionary "he" "Hebrew"
                     #:version "1.0-0"
                     #:sha256
                     (base32
                      "13bhbghx5b8g0119g3wxd4n8mlf707y41vlf59irxjj0kynankfn")))

(define-public aspell-dict-sv
  (aspell-dictionary "sv" "Swedish"
                     #:version "0.51-0"
                     #:prefix "aspell-"
                     #:sha256
                     (base32
                      "02jwkjhr32kvyibnyzgx3smbnm576jwdzg3avdf6zxwckhy5fw4v")))

(define-public aspell-dict-el
  (aspell-dictionary "el" "Greek"
                     #:version "0.08-0"
                     #:prefix "aspell6-"
                     #:sha256
                     (base32
                      "1ljcc30zg2v2h3w5h5jr5im41mw8jbsgvvhdd2cii2yzi8d0zxja")))

(define-public aspell-dict-grc
  (aspell-dictionary "grc" "Ancient Greek"
                     #:version "0.02-0"
                     #:sha256
                     (base32
                      "1zxr8958v37v260fkqd4pg37ns5h5kyqm54hn1hg70wq5cz8h512")))
