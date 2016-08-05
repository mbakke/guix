;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Cyril Roelandt <tipecaml@gmail.com>
;;; Copyright © 2014, 2015 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015, 2016 Mathieu Lirzin <mthl@gnu.org>
;;; Copyright © 2016 Danny Milosavljevic <dannym+a@scratchpost.org>
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

(define-module (guix scripts lint)
  #:use-module ((guix store) #:hide (close-connection))
  #:use-module (guix base32)
  #:use-module (guix download)
  #:use-module (guix ftp-client)
  #:use-module (guix http-client)
  #:use-module (guix packages)
  #:use-module (guix licenses)
  #:use-module (guix records)
  #:use-module (guix ui)
  #:use-module (guix utils)
  #:use-module (guix combinators)
  #:use-module (guix scripts)
  #:use-module (guix gnu-maintenance)
  #:use-module (guix monads)
  #:use-module (guix cve)
  #:use-module (gnu packages)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 format)
  #:use-module (web uri)
  #:use-module ((guix build download)
                #:select (maybe-expand-mirrors
                          open-connection-for-uri
                          close-connection))
  #:use-module (web request)
  #:use-module (web response)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-6)                      ;Unicode string ports
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:use-module (srfi srfi-37)
  #:use-module (ice-9 rdelim)
  #:export (guix-lint
            check-description-style
            check-inputs-should-be-native
            check-patch-file-names
            check-synopsis-style
            check-derivation
            check-home-page
            check-source
            check-source-file-name
            check-license
            check-vulnerabilities
            check-formatting
            run-checkers

            %checkers
            lint-checker
            lint-checker?
            lint-checker-name
            lint-checker-description
            lint-checker-check))


;;;
;;; Helpers
;;;
(define* (emit-warning package message #:optional field)
  ;; Emit a warning about PACKAGE, printing the location of FIELD if it is
  ;; given, the location of PACKAGE otherwise, the full name of PACKAGE and the
  ;; provided MESSAGE.
  (let ((loc (or (package-field-location package field)
                 (package-location package))))
    (format (guix-warning-port) "~a: ~a: ~a~%"
            (location->string loc)
            (package-full-name package)
            message)))

(define (call-with-accumulated-warnings thunk)
  "Call THUNK, accumulating any warnings in the current state, using the state
monad."
  (let ((port (open-output-string)))
    (mlet %state-monad ((state      (current-state))
                        (result ->  (parameterize ((guix-warning-port port))
                                      (thunk)))
                        (warning -> (get-output-string port)))
      (mbegin %state-monad
        (munless (string=? "" warning)
          (set-current-state (cons warning state)))
        (return result)))))

(define-syntax-rule (with-accumulated-warnings exp ...)
  "Evaluate EXP and accumulate warnings in the state monad."
  (call-with-accumulated-warnings
   (lambda ()
     exp ...)))


;;;
;;; Checkers
;;;
(define-record-type* <lint-checker>
  lint-checker make-lint-checker
  lint-checker?
  ;; TODO: add a 'certainty' field that shows how confident we are in the
  ;; checker. Then allow users to only run checkers that have a certain
  ;; 'certainty' level.
  (name        lint-checker-name)
  (description lint-checker-description)
  (check       lint-checker-check))

(define (list-checkers-and-exit)
  ;; Print information about all available checkers and exit.
  (format #t (_ "Available checkers:~%"))
  (for-each (lambda (checker)
              (format #t "- ~a: ~a~%"
                      (lint-checker-name checker)
                      (_ (lint-checker-description checker))))
            %checkers)
  (exit 0))

(define (properly-starts-sentence? s)
  (string-match "^[(\"'`[:upper:][:digit:]]" s))

(define (starts-with-abbreviation? s)
  "Return #t if S starts with what looks like an abbreviation or acronym."
  (string-match "^[A-Z][A-Z0-9]+\\>" s))

(define (check-description-style package)
  ;; Emit a warning if stylistic issues are found in the description of PACKAGE.
  (define (check-not-empty description)
    (when (string-null? description)
      (emit-warning package
                    (_ "description should not be empty")
                    'description)))

  (define (check-texinfo-markup description)
    "Check that DESCRIPTION can be parsed as a Texinfo fragment.  If the
markup is valid return a plain-text version of DESCRIPTION, otherwise #f."
    (catch #t
      (lambda () (texi->plain-text description))
      (lambda (keys . args)
        (emit-warning package
                      (_ "Texinfo markup in description is invalid")
                      'description)
        #f)))

  (define (check-proper-start description)
    (unless (or (properly-starts-sentence? description)
                (string-prefix-ci? (package-name package) description))
      (emit-warning package
                    (_ "description should start with an upper-case letter or digit")
                    'description)))

  (define (check-end-of-sentence-space description)
    "Check that an end-of-sentence period is followed by two spaces."
    (let ((infractions
           (reverse (fold-matches
                     "\\. [A-Z]" description '()
                     (lambda (m r)
                       ;; Filter out matches of common abbreviations.
                       (if (find (lambda (s)
                                   (string-suffix-ci? s (match:prefix m)))
                                 '("i.e" "e.g" "a.k.a" "resp"))
                           r (cons (match:start m) r)))))))
      (unless (null? infractions)
        (emit-warning package
                      (format #f (_ "sentences in description should be followed ~
by two spaces; possible infraction~p at ~{~a~^, ~}")
                              (length infractions)
                              infractions)
                      'description))))

  (let ((description (package-description package)))
    (if (string? description)
        (begin
          (check-not-empty description)
          ;; Use raw description for this because Texinfo rendering
          ;; automatically fixes end of sentence space.
          (check-end-of-sentence-space description)
          (and=> (check-texinfo-markup description)
                 check-proper-start))
        (emit-warning package
                      (format #f (_ "invalid description: ~s") description)
                      'description))))

(define (check-inputs-should-be-native package)
  ;; Emit a warning if some inputs of PACKAGE are likely to belong to its
  ;; native inputs.
  (let ((linted package)
        (inputs (package-inputs package))
        (native-inputs
          '("pkg-config"
            "extra-cmake-modules"
            "glib:bin"
            "intltool"
            "itstool"
            "qttools")))
    (match inputs
      (((labels packages . outputs) ...)
       (for-each (lambda (package output)
                   (when (package? package)
                     (let ((input (string-append
                                   (package-name package)
                                   (if (> (length output) 0)
                                       (string-append ":" (car output))
                                       ""))))
                       (when (member input native-inputs)
                         (emit-warning linted
                                       (format #f (_ "'~a' should probably \
be a native input")
                                               input)
                                       'inputs)))))
                 packages outputs)))))

(define (package-name-regexp package)
  "Return a regexp that matches PACKAGE's name as a word at the beginning of a
line."
  (make-regexp (string-append "^" (regexp-quote (package-name package))
                              "\\>")
               regexp/icase))

(define (check-synopsis-style package)
  ;; Emit a warning if stylistic issues are found in the synopsis of PACKAGE.
  (define (check-not-empty synopsis)
    (when (string-null? synopsis)
      (emit-warning package
                    (_ "synopsis should not be empty")
                    'synopsis)))

  (define (check-final-period synopsis)
    ;; Synopsis should not end with a period, except for some special cases.
    (when (and (string-suffix? "." synopsis)
               (not (string-suffix? "etc." synopsis)))
      (emit-warning package
                    (_ "no period allowed at the end of the synopsis")
                    'synopsis)))

  (define check-start-article
    ;; Skip this check for GNU packages, as suggested by Karl Berry's reply to
    ;; <http://lists.gnu.org/archive/html/bug-womb/2014-11/msg00000.html>.
    (if (false-if-exception (gnu-package? package))
        (const #t)
        (lambda (synopsis)
          (when (or (string-prefix-ci? "A " synopsis)
                    (string-prefix-ci? "An " synopsis))
            (emit-warning package
                          (_ "no article allowed at the beginning of \
the synopsis")
                          'synopsis)))))

  (define (check-synopsis-length synopsis)
    (when (>= (string-length synopsis) 80)
      (emit-warning package
                    (_ "synopsis should be less than 80 characters long")
                    'synopsis)))

  (define (check-proper-start synopsis)
    (unless (properly-starts-sentence? synopsis)
      (emit-warning package
                    (_ "synopsis should start with an upper-case letter or digit")
                    'synopsis)))

  (define (check-start-with-package-name synopsis)
    (when (and (regexp-exec (package-name-regexp package) synopsis)
               (not (starts-with-abbreviation? synopsis)))
      (emit-warning package
                    (_ "synopsis should not start with the package name")
                    'synopsis)))

  (define checks
    (list check-not-empty check-proper-start check-final-period
          check-start-article check-start-with-package-name
          check-synopsis-length))

  (match (package-synopsis package)
    ((? string? synopsis)
     (for-each (lambda (proc)
                 (proc synopsis))
               checks))
    (invalid
     (emit-warning package (format #f (_ "invalid synopsis: ~s") invalid)
                   'synopsis))))

(define* (probe-uri uri #:key timeout)
  "Probe URI, a URI object, and return two values: a symbol denoting the
probing status, such as 'http-response' when we managed to get an HTTP
response from URI, and additional details, such as the actual HTTP response.

TIMEOUT is the maximum number of seconds (possibly an inexact number) to wait
for connections to complete; when TIMEOUT is #f, wait as long as needed."
  (define headers
    '((User-Agent . "GNU Guile")
      (Accept . "*/*")))

  (let loop ((uri     uri)
             (visited '()))
    (match (uri-scheme uri)
      ((or 'http 'https)
       (catch #t
         (lambda ()
           (let ((port    (open-connection-for-uri uri #:timeout timeout))
                 (request (build-request uri #:headers headers)))
             (define response
               (dynamic-wind
                 (const #f)
                 (lambda ()
                   (write-request request port)
                   (force-output port)
                   (read-response port))
                 (lambda ()
                   (close-connection port))))

             (case (response-code response)
               ((301 302 307)
                (let ((location (response-location response)))
                  (if (or (not location) (member location visited))
                      (values 'http-response response)
                      (loop location (cons location visited))))) ;follow the redirect
               (else
                (values 'http-response response)))))
         (lambda (key . args)
           (case key
             ((bad-header bad-header-component)
              ;; This can happen if the server returns an invalid HTTP header,
              ;; as is the case with the 'Date' header at sqlite.org.
              (values 'invalid-http-response #f))
             ((getaddrinfo-error system-error gnutls-error)
              (values key args))
             (else
              (apply throw key args))))))
      ('ftp
       (catch #t
         (lambda ()
           (let ((conn (ftp-open (uri-host uri) #:timeout timeout)))
             (define response
               (dynamic-wind
                 (const #f)
                 (lambda ()
                   (ftp-chdir conn (dirname (uri-path uri)))
                   (ftp-size conn (basename (uri-path uri))))
                 (lambda ()
                   (ftp-close conn))))
             (values 'ftp-response '(ok))))
         (lambda (key . args)
           (case key
             ((ftp-error)
              (values 'ftp-response `(error ,@args)))
             ((getaddrinfo-error system-error gnutls-error)
              (values key args))
             (else
              (apply throw key args))))))
      (_
       (values 'unknown-protocol #f)))))

(define (validate-uri uri package field)
  "Return #t if the given URI can be reached, otherwise return #f and emit a
warning for PACKAGE mentionning the FIELD."
  (let-values (((status argument)
                (probe-uri uri #:timeout 3)))     ;wait at most 3 seconds
    (case status
      ((http-response)
       (if (= 200 (response-code argument))
           (match (response-content-length argument)
             ((? number? length)
              ;; As of July 2016, SourceForge returns 200 (instead of 404)
              ;; with a small HTML page upon failure.  Attempt to detect such
              ;; malicious behavior.
              (or (> length 1000)
                  (begin
                    (emit-warning package
                                  (format #f
                                          (_ "URI ~a returned \
suspiciously small file (~a bytes)")
                                          (uri->string uri)
                                          length))
                    #f)))
             (_ #t))
           (begin
             (emit-warning package
                           (format #f
                                   (_ "URI ~a not reachable: ~a (~s)")
                                   (uri->string uri)
                                   (response-code argument)
                                   (response-reason-phrase argument))
                           field)
             #f)))
      ((ftp-response)
       (match argument
         (('ok) #t)
         (('error port command code message)
          (emit-warning package
                        (format #f
                                (_ "URI ~a not reachable: ~a (~s)")
                                (uri->string uri)
                                code (string-trim-both message)))
          #f)))
      ((getaddrinfo-error)
       (emit-warning package
                     (format #f
                             (_ "URI ~a domain not found: ~a")
                             (uri->string uri)
                             (gai-strerror (car argument)))
                     field)
       #f)
      ((system-error)
       (emit-warning package
                     (format #f
                             (_ "URI ~a unreachable: ~a")
                             (uri->string uri)
                             (strerror
                              (system-error-errno
                               (cons status argument))))
                     field)
       #f)
      ((invalid-http-response gnutls-error)
       ;; Probably a misbehaving server; ignore.
       #f)
      ((unknown-protocol)                             ;nothing we can do
       #f)
      (else
       (error "internal linter error" status)))))

(define (check-home-page package)
  "Emit a warning if PACKAGE has an invalid 'home-page' field, or if that
'home-page' is not reachable."
  (let ((uri (and=> (package-home-page package) string->uri)))
    (cond
     ((uri? uri)
      (validate-uri uri package 'home-page))
     ((not (package-home-page package))
      (unless (or (string-contains (package-name package) "bootstrap")
                  (string=? (package-name package) "ld-wrapper"))
        (emit-warning package
                      (_ "invalid value for home page")
                      'home-page)))
     (else
      (emit-warning package (format #f (_ "invalid home page URL: ~s")
                                    (package-home-page package))
                    'home-page)))))

(define (check-patch-file-names package)
  "Emit a warning if the patches requires by PACKAGE are badly named or if the
patch could not be found."
  (guard (c ((message-condition? c)     ;raised by 'search-patch'
             (emit-warning package (condition-message c)
                           'patch-file-names)))
    (unless (every (match-lambda        ;patch starts with package name?
                     ((? string? patch)
                      (and=> (string-contains (basename patch)
                                              (package-name package))
                             zero?))
                     (_  #f))     ;must be an <origin> or something like that.
                   (or (and=> (package-source package) origin-patches)
                       '()))
      (emit-warning
       package
       (_ "file names of patches should start with the package name")
       'patch-file-names))))

(define (escape-quotes str)
  "Replace any quote character in STR by an escaped quote character."
  (list->string
   (string-fold-right (lambda (chr result)
                        (match chr
                          (#\" (cons* #\\ #\"result))
                          (_   (cons chr result))))
                      '()
                      str)))

(define official-gnu-packages*
  (memoize
   (lambda ()
     "A memoizing version of 'official-gnu-packages' that returns the empty
list when something goes wrong, such as a networking issue."
     (let ((gnus (false-if-exception (official-gnu-packages))))
       (or gnus '())))))

(define (check-gnu-synopsis+description package)
  "Make sure that, if PACKAGE is a GNU package, it uses the synopsis and
descriptions maintained upstream."
  (match (find (lambda (descriptor)
                 (string=? (gnu-package-name descriptor)
                           (package-name package)))
               (official-gnu-packages*))
    (#f                                   ;not a GNU package, so nothing to do
     #t)
    (descriptor                                   ;a genuine GNU package
     (let ((upstream   (gnu-package-doc-summary descriptor))
           (downstream (package-synopsis package))
           (loc        (or (package-field-location package 'synopsis)
                           (package-location package))))
       (when (and upstream
                  (or (not (string? downstream))
                      (not (string=? upstream downstream))))
         (format (guix-warning-port)
                 (_ "~a: ~a: proposed synopsis: ~s~%")
                 (location->string loc) (package-full-name package)
                 upstream)))

     (let ((upstream   (gnu-package-doc-description descriptor))
           (downstream (package-description package))
           (loc        (or (package-field-location package 'description)
                           (package-location package))))
       (when (and upstream
                  (or (not (string? downstream))
                      (not (string=? (fill-paragraph upstream 100)
                                     (fill-paragraph downstream 100)))))
         (format (guix-warning-port)
                 (_ "~a: ~a: proposed description:~%     \"~a\"~%")
                 (location->string loc) (package-full-name package)
                 (fill-paragraph (escape-quotes upstream) 77 7)))))))

(define (check-source package)
  "Emit a warning if PACKAGE has an invalid 'source' field, or if that
'source' is not reachable."
  (define (try-uris uris)
    (run-with-state
        (anym %state-monad
              (lambda (uri)
                (with-accumulated-warnings
                 (validate-uri uri package 'source)))
              (append-map (cut maybe-expand-mirrors <> %mirrors)
                          uris))
      '()))

  (let ((origin (package-source package)))
    (when (and origin
               (eqv? (origin-method origin) url-fetch))
      (let* ((strings (origin-uri origin))
             (uris (if (list? strings)
                       (map string->uri strings)
                       (list (string->uri strings)))))

        ;; Just make sure that at least one of the URIs is valid.
        (call-with-values
            (lambda () (try-uris uris))
          (lambda (success? warnings)
            ;; When everything fails, report all of WARNINGS, otherwise don't
            ;; report anything.
            ;;
            ;; XXX: Ideally we'd still allow warnings to be raised if *some*
            ;; URIs are unreachable, but distinguish that from the error case
            ;; where *all* the URIs are unreachable.
            (unless success?
              (emit-warning package
                            (_ "all the source URIs are unreachable:")
                            'source)
              (for-each (lambda (warning)
                          (display warning (guix-warning-port)))
                        (reverse warnings)))))))))

(define (check-source-file-name package)
  "Emit a warning if PACKAGE's origin has no meaningful file name."
  (define (origin-file-name-valid? origin)
    ;; Return #t if the source file name contains only a version or is #f;
    ;; indicates that the origin needs a 'file-name' field.
    (let ((file-name (origin-actual-file-name origin))
          (version (package-version package)))
      (and file-name
           (not (or (string-prefix? version file-name)
                    ;; Common in many projects is for the filename to start
                    ;; with a "v" followed by the version,
                    ;; e.g. "v3.2.0.tar.gz".
                    (string-prefix? (string-append "v" version) file-name))))))

  (let ((origin (package-source package)))
    (unless (or (not origin) (origin-file-name-valid? origin))
      (emit-warning package
                    (_ "the source file name should contain the package name")
                    'source))))

(define (check-derivation package)
  "Emit a warning if we fail to compile PACKAGE to a derivation."
  (catch #t
    (lambda ()
      (guard (c ((nix-protocol-error? c)
                 (emit-warning package
                               (format #f (_ "failed to create derivation: ~a")
                                       (nix-protocol-error-message c))))
                ((message-condition? c)
                 (emit-warning package
                               (format #f (_ "failed to create derivation: ~a")
                                       (condition-message c)))))
        (with-store store
          ;; Disable grafts since it can entail rebuilds.
          (package-derivation store package #:graft? #f)

          ;; If there's a replacement, make sure we can compute its
          ;; derivation.
          (match (package-replacement package)
            (#f #t)
            (replacement
             (package-derivation store replacement #:graft? #f))))))
    (lambda args
      (emit-warning package
                    (format #f (_ "failed to create derivation: ~s~%")
                            args)))))

(define (check-license package)
  "Warn about type errors of the 'license' field of PACKAGE."
  (match (package-license package)
    ((or (? license?)
         ((? license?) ...))
     #t)
    (x
     (emit-warning package (_ "invalid license field")
                   'license))))

(define (patch-file-name patch)
  "Return the basename of PATCH's file name, or #f if the file name could not
be determined."
  (match patch
    ((? string?)
     (basename patch))
    ((? origin?)
     (and=> (origin-actual-file-name patch) basename))))

(define (current-vulnerabilities*)
  "Like 'current-vulnerabilities', but return the empty list upon networking
or HTTP errors.  This allows network-less operation and makes problems with
the NIST server non-fatal.."
  (guard (c ((http-get-error? c)
             (warning (_ "failed to retrieve CVE vulnerabilities \
from ~s: ~a (~s)~%")
                      (uri->string (http-get-error-uri c))
                      (http-get-error-code c)
                      (http-get-error-reason c))
             (warning (_ "assuming no CVE vulnerabilities~%"))
             '()))
    (catch 'getaddrinfo-error
      (lambda ()
        (current-vulnerabilities))
      (lambda (key errcode)
        (warning (_ "failed to lookup NIST host: ~a~%")
                 (gai-strerror errcode))
        (warning (_ "assuming no CVE vulnerabilities~%"))
        '()))))

(define package-vulnerabilities
  (let ((lookup (delay (vulnerabilities->lookup-proc
                        (current-vulnerabilities*)))))
    (lambda (package)
      "Return a list of vulnerabilities affecting PACKAGE."
      ;; First we retrieve the Common Platform Enumeration (CPE) name and
      ;; version for PACKAGE, then we can pass them to LOOKUP.
      (let ((name    (or (assoc-ref (package-properties package)
                                    'cpe-name)
                         (package-name package)))
            (version (or (assoc-ref (package-properties package)
                                    'cpe-version)
                         (package-version package))))
        ((force lookup) name version)))))

(define (check-vulnerabilities package)
  "Check for known vulnerabilities for PACKAGE."
  (match (package-vulnerabilities package)
    (()
     #t)
    ((vulnerabilities ...)
     (let* ((package   (or (package-replacement package) package))
            (patches   (filter-map patch-file-name
                                   (or (and=> (package-source package)
                                              origin-patches)
                                       '())))
            (unpatched (remove (lambda (vuln)
                                 (find (cute string-contains
                                         <> (vulnerability-id vuln))
                                       patches))
                               vulnerabilities)))
       (unless (null? unpatched)
         (emit-warning package
                       (format #f (_ "probably vulnerable to ~a")
                               (string-join (map vulnerability-id unpatched)
                                            ", "))))))))


;;;
;;; Source code formatting.
;;;

(define (report-tabulations package line line-number)
  "Warn about tabulations found in LINE."
  (match (string-index line #\tab)
    (#f #t)
    (index
     (emit-warning package
                   (format #f (_ "tabulation on line ~a, column ~a")
                           line-number index)))))

(define (report-trailing-white-space package line line-number)
  "Warn about trailing white space in LINE."
  (unless (or (string=? line (string-trim-right line))
              (string=? line (string #\page)))
    (emit-warning package
                  (format #f
                          (_ "trailing white space on line ~a")
                          line-number))))

(define (report-long-line package line line-number)
  "Emit a warning if LINE is too long."
  ;; Note: We don't warn at 80 characters because sometimes hashes and URLs
  ;; make it hard to fit within that limit and we want to avoid making too
  ;; much noise.
  (when (> (string-length line) 90)
    (emit-warning package
                  (format #f (_ "line ~a is way too long (~a characters)")
                          line-number (string-length line)))))

(define %hanging-paren-rx
  (make-regexp "^[[:blank:]]*[()]+[[:blank:]]*$"))

(define (report-lone-parentheses package line line-number)
  "Emit a warning if LINE contains hanging parentheses."
  (when (regexp-exec %hanging-paren-rx line)
    (emit-warning package
                  (format #f
                          (_ "line ~a: parentheses feel lonely, \
move to the previous or next line")
                          line-number))))

(define %formatting-reporters
  ;; List of procedures that report formatting issues.  These are not separate
  ;; checkers because they would need to re-read the file.
  (list report-tabulations
        report-trailing-white-space
        report-long-line
        report-lone-parentheses))

(define* (report-formatting-issues package file starting-line
                                   #:key (reporters %formatting-reporters))
  "Report white-space issues in FILE starting from STARTING-LINE, and report
them for PACKAGE."
  (define last-line
    ;; Number of the presumed last line.
    ;; XXX: Ideally we'd stop at the boundaries of the surrounding sexp, but
    ;; for now just use this simple heuristic.
    (+ starting-line 60))

  (call-with-input-file file
    (lambda (port)
      (let loop ((line-number 1))
        (let ((line (read-line port)))
          (or (eof-object? line)
              (> line-number last-line)
              (begin
                (unless (< line-number starting-line)
                  (for-each (lambda (report)
                              (report package line line-number))
                            reporters))
                (loop (+ 1 line-number)))))))))

(define (check-formatting package)
  "Check the formatting of the source code of PACKAGE."
  (let ((location (package-location package)))
    (when location
      (and=> (search-path %load-path (location-file location))
             (lambda (file)
               ;; Report issues starting from the line before the 'package'
               ;; form, which usually contains the 'define' form.
               (report-formatting-issues package file
                                         (- (location-line location) 1)))))))


;;;
;;; List of checkers.
;;;

(define %checkers
  (list
   (lint-checker
     (name        'description)
     (description "Validate package descriptions")
     (check       check-description-style))
   (lint-checker
     (name        'gnu-description)
     (description "Validate synopsis & description of GNU packages")
     (check       check-gnu-synopsis+description))
   (lint-checker
     (name        'inputs-should-be-native)
     (description "Identify inputs that should be native inputs")
     (check       check-inputs-should-be-native))
   (lint-checker
     (name        'patch-file-names)
     (description "Validate file names and availability of patches")
     (check       check-patch-file-names))
   (lint-checker
     (name        'home-page)
     (description "Validate home-page URLs")
     (check       check-home-page))
   (lint-checker
     (name        'license)
     ;; TRANSLATORS: <license> is the name of a data type and must not be
     ;; translated.
     (description "Make sure the 'license' field is a <license> \
or a list thereof")
     (check       check-license))
   (lint-checker
     (name        'source)
     (description "Validate source URLs")
     (check       check-source))
   (lint-checker
     (name        'source-file-name)
     (description "Validate file names of sources")
     (check       check-source-file-name))
   (lint-checker
     (name        'derivation)
     (description "Report failure to compile a package to a derivation")
     (check       check-derivation))
   (lint-checker
     (name        'synopsis)
     (description "Validate package synopses")
     (check       check-synopsis-style))
   (lint-checker
     (name        'cve)
     (description "Check the Common Vulnerabilities and Exposures\
 (CVE) database")
     (check       check-vulnerabilities))
   (lint-checker
     (name        'formatting)
     (description "Look for formatting issues in the source")
     (check       check-formatting))))

(define* (run-checkers package #:optional (checkers %checkers))
  "Run the given CHECKERS on PACKAGE."
  (let ((tty? (isatty? (current-error-port)))
        (name (package-full-name package)))
    (for-each (lambda (checker)
                (when tty?
                  (format (current-error-port) "checking ~a [~a]...\x1b[K\r"
                          name (lint-checker-name checker))
                  (force-output (current-error-port)))
                ((lint-checker-check checker) package))
              checkers)
    (when tty?
      (format (current-error-port) "\x1b[K")
      (force-output (current-error-port)))))


;;;
;;; Command-line options.
;;;

(define %default-options
  ;; Alist of default option values.
  '())

(define (show-help)
  (display (_ "Usage: guix lint [OPTION]... [PACKAGE]...
Run a set of checkers on the specified package; if none is specified,
run the checkers on all packages.\n"))
  (display (_ "
  -c, --checkers=CHECKER1,CHECKER2...
                         only run the specified checkers"))
  (display (_ "
  -h, --help             display this help and exit"))
  (display (_ "
  -l, --list-checkers    display the list of available lint checkers"))
  (display (_ "
  -V, --version          display version information and exit"))
  (newline)
  (show-bug-report-information))


(define %options
  ;; Specification of the command-line options.
  ;; TODO: add some options:
  ;; * --certainty=[low,medium,high]: only run checkers that have at least this
  ;;                                  'certainty'.
  (list (option '(#\c "checkers") #t #f
                (lambda (opt name arg result)
                  (let ((names (map string->symbol (string-split arg #\,))))
                    (for-each (lambda (c)
                                (unless (memq c
                                              (map lint-checker-name
                                                   %checkers))
                                  (leave (_ "~a: invalid checker~%") c)))
                              names)
                    (alist-cons 'checkers
                                (filter (lambda (checker)
                                          (member (lint-checker-name checker)
                                                  names))
                                        %checkers)
                                result))))
        (option '(#\h "help") #f #f
                (lambda args
                  (show-help)
                  (exit 0)))
        (option '(#\l "list-checkers") #f #f
                (lambda args
                   (list-checkers-and-exit)))
        (option '(#\V "version") #f #f
                (lambda args
                  (show-version-and-exit "guix lint")))))


;;;
;;; Entry Point
;;;

(define (guix-lint . args)
  (define (parse-options)
    ;; Return the alist of option values.
    (args-fold* args %options
                (lambda (opt name arg result)
                  (leave (_ "~A: unrecognized option~%") name))
                (lambda (arg result)
                  (alist-cons 'argument arg result))
                %default-options))

  (let* ((opts (parse-options))
         (args (filter-map (match-lambda
                            (('argument . value)
                             value)
                            (_ #f))
                           (reverse opts)))
         (checkers (or (assoc-ref opts 'checkers) %checkers)))
     (if (null? args)
          (fold-packages (lambda (p r) (run-checkers p checkers)) '())
          (for-each (lambda (spec)
                      (run-checkers (specification->package spec) checkers))
                    args))))
