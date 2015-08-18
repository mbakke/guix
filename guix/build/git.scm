;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Ludovic Courtès <ludo@gnu.org>
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

(define-module (guix build git)
  #:use-module (guix build utils)
  #:export (git-fetch))

;;; Commentary:
;;;
;;; This is the build-side support code of (guix git-download).  It allows a
;;; Git repository to be cloned and checked out at a specific commit.
;;;
;;; Code:

(define* (git-fetch url commit directory
                    #:key tag (git-command "git") recursive?)
  "Fetch COMMIT from URL into DIRECTORY.  COMMIT must be a valid Git commit
identifier.  When RECURSIVE? is true, all the sub-modules of URL are fetched,
recursively.  Return #t on success, #f otherwise."
  ;; Disable TLS certificate verification.  The hash of the checkout is known
  ;; in advance anyway.
  (setenv "GIT_SSL_NO_VERIFY" "true")

  (mkdir directory)
  (with-directory-excursion directory
    (and (zero? (system* git-command "init"))
         (zero? (system* git-command "remote" "add" "origin" url))
         (cond
          ;; If there's a tag, do a shallow fetch.  Otherwise we do a full
          ;; fetch.
          (tag
           (and (zero? (system* git-command "fetch" "--depth=1" "origin" tag))
                ;; Either there is no commit specified, in which case we are
                ;; good, or there is a commit and it is the same as the tag,
                ;; in which case we're still good, or there's a commit and
                ;; it's under the tag so we have to unshallow the checkout and
                ;; try again.
                (if commit
                    (or (zero? (system* git-command "checkout" commit))
                        (and (zero? (system* git-command "fetch" "--unshallow"))
                             (zero? (system* git-command "checkout" commit))))
                    (zero? (system* git-command "checkout" "FETCH_HEAD")))))
          (else
           ;; Fall back to a full fetch.  In that case print available tags.
           (and (zero? (system* git-command "fetch" "origin"))
                (zero? (system* git-command "tag" "-l"))
                (zero? (system* git-command "checkout" commit)))))
         (or (not recursive?)
             (zero? (system* git-command
                             "submodule" "update" "--init" "--recursive")))
         (begin
           ;; The contents of '.git' vary as a function of the current
           ;; status of the Git repo.  Since we want a fixed output, this
           ;; directory needs to be taken out.
           (delete-file-recursively ".git")

           (when recursive?
             ;; In sub-modules, '.git' is a flat file, not a directory,
             ;; so we can use 'find-files' here.
             (for-each delete-file-recursively
                       (find-files directory "^\\.git$")))
           #t))))

;;; git.scm ends here
