;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
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

(define-module (gnu packages nutrition)
  #:use-module (guix packages)
  #:use-module (guix licenses)
  #:use-module (guix download)
  #:use-module (guix build-system python)
  #:use-module (gnu packages)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages image)
  #:use-module (gnu packages python))

(define-public gourmet
  (package
    (name "gourmet")
    (version "0.17.4")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "https://github.com/thinkle/gourmet/archive/"
                          version ".tar.gz"))
      (file-name (string-append name "-" version ".tar.gz"))
      (sha256
       (base32
        "1qvz175arzqm10lpfx8ffadrgirs3240zzqcp0h7sl53qfwx7v8k"))))
    (build-system python-build-system)
    (native-inputs
     `(("distutils-extra"   ,python2-distutils-extra)
       ("intltool"          ,intltool)
       ("python-pygtk"      ,python2-pygtk))) ;for tests
    ;; TODO: Add python-reportlab and/or python-poppler for printing/pdf
    ;; export, and python-beautifulsoup for web import plugin.
    (inputs
     `(("pygtk"             ,python2-pygtk)
       ("sqlalchemy"        ,python2-sqlalchemy)
       ("python-pillow"     ,python2-pillow)
       ("elib.intl"         ,python2-elib.intl)))
    (arguments
     `(#:python ,python-2               ;exception and print syntax
       #:tests? #f))                    ;tests look bitrotted
    (home-page "http://thinkle.github.io/gourmet/")
    (synopsis "Recipe organizer")
    (description
     "Gourmet Recipe Manager is a recipe organizer that allows you to collect,
search, organize, and browse your recipes.  Gourmet can also generate shopping
lists and calculate nutritional information.  It imports Mealmaster,
MasterCook and KRecipe files and exports PDFs, webpages, and other formats.")
    (license gpl2+)))
