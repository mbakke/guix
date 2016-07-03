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

(define-module (gnu system locale)
  #:use-module (guix gexp)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix records)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (gnu packages base)
  #:use-module (gnu packages compression)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)
  #:export (locale-definition
            locale-definition?
            locale-definition-name
            locale-definition-source
            locale-definition-charset

            locale-name->definition
            locale-directory

            %default-locale-libcs
            %default-locale-definitions))

;;; Commentary:
;;;
;;; Locale definitions, and compilation thereof.
;;;
;;; Code:

(define-record-type* <locale-definition> locale-definition
  make-locale-definition
  locale-definition?
  (name    locale-definition-name)                ;string--e.g., "fr_FR.utf8"
  (source  locale-definition-source)              ;string--e.g., "fr_FR"
  (charset locale-definition-charset              ;string--e.g., "UTF-8"
           (default "UTF-8")))

(define %not-dot
  (char-set-complement (char-set #\.)))

(define (denormalize-codeset codeset)
  "Attempt to guess the \"real\" name of CODESET, a normalized codeset as
defined in (info \"(libc) Using gettextized software\")."
  (cond ((string=? codeset "utf8")
         "UTF-8")
        ((string-prefix? "iso8859" codeset)
         (string-append "ISO-8859-" (string-drop codeset 7)))
        ((string=? codeset "eucjp")
         "EUC-JP")
        (else                                ;cross fingers, hope for the best
         codeset)))

(define (locale-name->definition name)
  "Return a <locale-definition> corresponding to NAME, guessing the charset,
or #f on failure."
  (match (string-tokenize name %not-dot)
    ((source charset)
     ;; XXX: NAME is supposed to use the "normalized codeset", such as "utf8",
     ;; whereas the actual name used is different.  Add a special case to make
     ;; the right guess for UTF-8.
     (locale-definition (name name)
                        (source source)
                        (charset (denormalize-codeset charset))))
    (_
     #f)))

(define* (localedef-command locale
                            #:key (libc (canonical-package glibc)))
  "Return a gexp that runs 'localedef' from LIBC to build LOCALE."
  (define (maybe-version-directory)
    ;; XXX: For libc prior to 2.22, GuixSD did not store locale data in a
    ;; version-specific sub-directory.  Check whether this is the case.
    ;; TODO: Remove this hack once libc 2.21 is buried.
    (let ((version (package-version libc)))
      (if (version>=? version "2.22")
          (list version "/")
          '())))

  #~(begin
      (format #t "building locale '~a'...~%"
              #$(locale-definition-name locale))
      (zero? (system* (string-append #$libc "/bin/localedef")
                      "--no-archive" "--prefix" #$output
                      "-i" #$(locale-definition-source locale)
                      "-f" #$(locale-definition-charset locale)
                      (string-append #$output "/"
                                     #$@(maybe-version-directory)
                                     #$(locale-definition-name locale))))))

(define* (single-locale-directory locales
                                  #:key (libc (canonical-package glibc)))
  "Return a directory containing all of LOCALES for LIBC compiled.

Because locale data formats are incompatible when switching from one libc to
another, locale data is put in a sub-directory named after the 'version' field
of LIBC."
  (define version
    (package-version libc))

  (define build
    #~(begin
        (mkdir #$output)

        ;; XXX: For libcs < 2.22, locale data is stored in the top-level
        ;; directory.
        ;; TODO: Remove this hack once libc 2.21 is buried.
        #$(if (version>=? version "2.22")
              #~(mkdir (string-append #$output "/" #$version))
              #~(symlink "." (string-append #$output "/" #$version)))

        ;; 'localedef' executes 'gzip' to access compressed locale sources.
        (setenv "PATH" (string-append #$gzip "/bin"))

        (exit
         (and #$@(map (cut localedef-command <> #:libc libc)
                      locales)))))

  (gexp->derivation (string-append "locale-" version) build
                    #:local-build? #t))

(define* (locale-directory locales
                           #:key (libcs %default-locale-libcs))
  "Return a locale directory containing all of LOCALES for each libc package
listed in LIBCS.

It is useful to list more than one libc when willing to support
already-installed packages built against a different libc since the locale
data format changes between libc versions."
  (match libcs
    ((libc)
     (single-locale-directory locales #:libc libc))
    ((libcs ..1)
     (mlet %store-monad ((dirs (mapm %store-monad
                                     (lambda (libc)
                                       (single-locale-directory locales
                                                                #:libc libc))
                                     libcs)))
       (gexp->derivation "locale-multiple-versions"
                         (with-imported-modules '((guix build union))
                           #~(begin
                               (use-modules (guix build union))
                               (union-build #$output (list #$@dirs))))
                         #:local-build? #t
                         #:substitutable? #f)))))

(define %default-locale-libcs
  ;; The libcs for which we build locales by default.
  (list (canonical-package glibc)))

(define %default-locale-definitions
  ;; Arbitrary set of locales that are built by default.  They are here mostly
  ;; to facilitate first-time use to some people, while others may have to add
  ;; a specific <locale-definition>.
  (letrec-syntax ((utf8-locale (syntax-rules ()
                                 ((_ name*)
                                  (locale-definition
                                   ;; Note: We choose "utf8", which is the
                                   ;; "normalized codeset".
                                   (name (string-append name* ".utf8"))
                                   (source name*)
                                   (charset "UTF-8")))))
                  (utf8-locales (syntax-rules ()
                                  ((_ name ...)
                                   (list (utf8-locale name) ...)))))
    ;; Add "en_US.UTF-8" for compatibility with Guix 0.8.
    (cons (locale-definition
           (name "en_US.UTF-8")
           (source "en_US")
           (charset "UTF-8"))
          (utf8-locales "ca_ES"
                        "cs_CZ"
                        "da_DK"
                        "de_DE"
                        "el_GR"
                        "en_AU"
                        "en_CA"
                        "en_GB"
                        "en_US"
                        "es_AR"
                        "es_CL"
                        "es_ES"
                        "es_MX"
                        "fi_FI"
                        "fr_BE"
                        "fr_CA"
                        "fr_CH"
                        "fr_FR"
                        "ga_IE"
                        "it_IT"
                        "ja_JP"
                        "ko_KR"
                        "nb_NO"
                        "nl_NL"
                        "pl_PL"
                        "pt_PT"
                        "ro_RO"
                        "ru_RU"
                        "sv_SE"
                        "tr_TR"
                        "uk_UA"
                        "vi_VN"
                        "zh_CN"))))

;;; locale.scm ends here
