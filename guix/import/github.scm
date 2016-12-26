;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 Ben Woodcroft <donttrustben@gmail.com>
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

(define-module (guix import github)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1)
  #:use-module (json)
  #:use-module (guix utils)
  #:use-module ((guix download) #:prefix download:)
  #:use-module (guix import utils)
  #:use-module (guix import json)
  #:use-module (guix packages)
  #:use-module (guix upstream)
  #:use-module (web uri)
  #:export (%github-updater))

(define (find-extension url)
  "Return the extension of the archive e.g. '.tar.gz' given a URL, or
false if none is recognized"
  (find (lambda (x) (string-suffix? x url))
        (list ".tar.gz" ".tar.bz2" ".tar.xz" ".zip" ".tar" ".tgz" ".love")))

(define (updated-github-url old-package new-version)
  ;; Return a url for the OLD-PACKAGE with NEW-VERSION.  If no source url in
  ;; the OLD-PACKAGE is a GitHub url, then return false.

  (define (updated-url url)
    (if (string-prefix? "https://github.com/" url)
        (let ((ext     (find-extension url))
              (name    (package-name old-package))
              (version (package-version old-package))
              (prefix  (string-append "https://github.com/"
                                      (github-user-slash-repository url)))
              (repo    (github-repository url)))
          (cond
           ((string-suffix? (string-append "/tarball/v" version) url)
            (string-append prefix "/tarball/v" new-version))
           ((string-suffix? (string-append "/tarball/" version) url)
            (string-append prefix "/tarball/" new-version))
           ((string-suffix? (string-append "/archive/v" version ext) url)
            (string-append prefix "/archive/v" new-version ext))
           ((string-suffix? (string-append "/archive/" version ext) url)
            (string-append prefix "/archive/" new-version ext))
           ((string-suffix? (string-append "/archive/" name "-" version ext)
                            url)
            (string-append prefix "/archive/" name "-" new-version ext))
           ((string-suffix? (string-append "/releases/download/v" version "/"
                                           name "-" version ext)
                            url)
            (string-append prefix "/releases/download/v" new-version "/" name
                           "-" new-version ext))
           ((string-suffix? (string-append "/releases/download/" version "/"
                                           name "-" version ext)
                            url)
            (string-append prefix "/releases/download/" new-version "/" name
                           "-" new-version ext))
           ((string-suffix? (string-append "/releases/download/" version "/"
                                           repo "-" version ext)
                            url)
            (string-append prefix "/releases/download/" new-version "/" repo
                           "-" new-version ext))
           ((string-suffix? (string-append "/releases/download/" repo "-"
                                           version "/" repo "-" version ext)
                            url)
            (string-append "/releases/download/" repo "-" version "/" repo "-"
                           version ext))
           (#t #f))) ; Some URLs are not recognised.
        #f))

  (let ((source-url (and=> (package-source old-package) origin-uri))
        (fetch-method (and=> (package-source old-package) origin-method)))
    (if (eq? fetch-method download:url-fetch)
        (match source-url
          ((? string?)
           (updated-url source-url))
          ((source-url ...)
           (find updated-url source-url)))
        #f)))

(define (github-package? package)
  "Return true if PACKAGE is a package from GitHub, else false."
  (not (eq? #f (updated-github-url package "dummy"))))

(define (github-repository url)
  "Return a string e.g. bedtools2 of the name of the repository, from a string
URL of the form 'https://github.com/arq5x/bedtools2/archive/v2.24.0.tar.gz'"
  (match (string-split (uri-path (string->uri url)) #\/)
    ((_ owner project . rest)
     (string-append project))))

(define (github-user-slash-repository url)
  "Return a string e.g. arq5x/bedtools2 of the owner and the name of the
repository separated by a forward slash, from a string URL of the form
'https://github.com/arq5x/bedtools2/archive/v2.24.0.tar.gz'"
  (match (string-split (uri-path (string->uri url)) #\/)
    ((_ owner project . rest)
     (string-append owner "/" project))))

(define %github-token
  ;; Token to be passed to Github.com to avoid the 60-request per hour
  ;; limit, or #f.
  (make-parameter (getenv "GUIX_GITHUB_TOKEN")))

(define (latest-released-version url package-name)
  "Return a string of the newest released version name given a string URL like
'https://github.com/arq5x/bedtools2/archive/v2.24.0.tar.gz' and the name of
the package e.g. 'bedtools2'.  Return #f if there is no releases"
  (let* ((token (%github-token))
         (api-url (string-append
                   "https://api.github.com/repos/"
                   (github-user-slash-repository url)
                   "/releases"))
         (json (json-fetch
                (if token
                    (string-append api-url "?access_token=" token)
                    api-url))))
    (if (eq? json #f)
        (if token
            (error "Error downloading release information through the GitHub
API when using a GitHub token")
            (error "Error downloading release information through the GitHub
API. This may be fixed by using an access token and setting the environment
variable GUIX_GITHUB_TOKEN, for instance one procured from
https://github.com/settings/tokens"))
        (let ((proper-releases
               (filter
                (lambda (x)
                  ;; example pre-release:
                  ;; https://github.com/wwood/OrfM/releases/tag/v0.5.1
                  ;; or an all-prerelease set
                  ;; https://github.com/powertab/powertabeditor/releases
                  (not (hash-ref x "prerelease")))
                json)))
          (match proper-releases
            (()                       ;empty release list
             #f)
            ((release . rest)         ;one or more releases
             (let ((tag (hash-ref release "tag_name"))
                   (name-length (string-length package-name)))
               ;; some tags include the name of the package e.g. "fdupes-1.51"
               ;; so remove these
               (if (and (< name-length (string-length tag))
                        (string=? (string-append package-name "-")
                                  (substring tag 0 (+ name-length 1))))
                   (substring tag (+ name-length 1))
                   ;; some tags start with a "v" e.g. "v0.25.0"
                   ;; where some are just the version number
                   (if (eq? (string-ref tag 0) #\v)
                       (substring tag 1) tag)))))))))

(define (latest-release pkg)
  "Return an <upstream-source> for the latest release of PKG."
  (let* ((source-uri (origin-uri (package-source pkg)))
         (name (package-name pkg))
         (newest-version (latest-released-version source-uri name)))
    (if newest-version
        (upstream-source
         (package name)
         (version newest-version)
         (urls (list (updated-github-url pkg newest-version))))
        #f))) ; On GitHub but no proper releases

(define %github-updater
  (upstream-updater
   (name 'github)
   (description "Updater for GitHub packages")
   (pred github-package?)
   (latest latest-release)))


