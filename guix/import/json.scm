;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 David Thompson <davet@gnu.org>
;;; Copyright © 2015, 2016 Eric Bavier <bavier@member.fsf.org>
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

(define-module (guix import json)
  #:use-module (json)
  #:use-module (guix http-client)
  #:use-module (guix import utils)
  #:use-module (srfi srfi-34)
  #:export (json-fetch))

(define (json-fetch url)
  "Return an alist representation of the JSON resource URL, or #f on failure."
  (guard (c ((and (http-get-error? c)
                  (= 404 (http-get-error-code c)))
             #f))                       ;"expected" if package is unknown
    (let* ((port (http-fetch url))
           (result (hash-table->alist (json->scm port))))
      (close-port port)
      result)))
