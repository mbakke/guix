;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Steve Sprang <scs@stevesprang.com>
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

(define-module (guix build download)
  #:use-module (web uri)
  #:use-module (web http)
  #:use-module ((web client) #:hide (open-socket-for-uri))
  #:use-module (web response)
  #:use-module (guix base64)
  #:use-module (guix ftp-client)
  #:use-module (guix build utils)
  #:use-module (rnrs io ports)
  #:use-module (rnrs bytevectors)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-19)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)
  #:use-module (ice-9 format)
  #:export (open-socket-for-uri
            open-connection-for-uri
            close-connection
            resolve-uri-reference
            maybe-expand-mirrors
            url-fetch
            byte-count->string
            current-terminal-columns
            progress-proc
            uri-abbreviation
            nar-uri-abbreviation
            store-path-abbreviation))

;;; Commentary:
;;;
;;; Fetch data such as tarballs over HTTP or FTP (builder-side code).
;;;
;;; Code:

(define %http-receive-buffer-size
  ;; Size of the HTTP receive buffer.
  65536)

(define current-terminal-columns
  ;; Number of columns of the terminal.
  (make-parameter 80))

(define (nearest-exact-integer x)
  "Given a real number X, return the nearest exact integer, with ties going to
the nearest exact even integer."
  (inexact->exact (round x)))

(define (duration->seconds duration)
  "Return the number of seconds represented by DURATION, a 'time-duration'
object, as an inexact number."
  (+ (time-second duration)
     (/ (time-nanosecond duration) 1e9)))

(define (seconds->string duration)
  "Given DURATION in seconds, return a string representing it in 'mm:ss' or
'hh:mm:ss' format, as needed."
  (if (not (number? duration))
      "00:00"
      (let* ((total-seconds (nearest-exact-integer duration))
             (extra-seconds (modulo total-seconds 3600))
             (num-hours     (quotient total-seconds 3600))
             (hours         (and (positive? num-hours) num-hours))
             (mins          (quotient extra-seconds 60))
             (secs          (modulo extra-seconds 60)))
        (format #f "~@[~2,'0d:~]~2,'0d:~2,'0d" hours mins secs))))

(define (byte-count->string size)
  "Given SIZE in bytes, return a string representing it in a human-readable
way."
  (let ((KiB 1024.)
        (MiB (expt 1024. 2))
        (GiB (expt 1024. 3))
        (TiB (expt 1024. 4)))
    (cond
     ((< size KiB) (format #f "~dB"     (nearest-exact-integer size)))
     ((< size MiB) (format #f "~dKiB"   (nearest-exact-integer (/ size KiB))))
     ((< size GiB) (format #f "~,1fMiB" (/ size MiB)))
     ((< size TiB) (format #f "~,2fGiB" (/ size GiB)))
     (else         (format #f "~,3fTiB" (/ size TiB))))))

(define* (progress-bar % #:optional (bar-width 20))
  "Return % as a string representing an ASCII-art progress bar.  The total
width of the bar is BAR-WIDTH."
  (let* ((fraction (/ % 100))
         (filled   (inexact->exact (floor (* fraction bar-width))))
         (empty    (- bar-width filled)))
    (format #f "[~a~a]"
            (make-string filled #\#)
            (make-string empty #\space))))

(define (string-pad-middle left right len)
  "Combine LEFT and RIGHT with enough padding in the middle so that the
resulting string has length at least LEN (it may overflow).  If the string
does not overflow, the last char in RIGHT will be flush with the LEN
column."
  (let* ((total-used (+ (string-length left)
                        (string-length right)))
         (num-spaces (max 1 (- len total-used)))
         (padding    (make-string num-spaces #\space)))
    (string-append left padding right)))

(define* (ellipsis #:optional (port (current-output-port)))
  "Make a rough guess at whether Unicode's HORIZONTAL ELLIPSIS can be written
in PORT's encoding, and return either that or ASCII dots."
  (if (equal? (port-encoding port) "UTF-8")
      "…"
      "..."))

(define* (store-path-abbreviation store-path #:optional (prefix-length 6))
  "If STORE-PATH is the file name of a store entry, return an abbreviation of
STORE-PATH for display, showing PREFIX-LENGTH characters of the hash.
Otherwise return STORE-PATH."
  (if (string-prefix? (%store-directory) store-path)
      (let ((base (basename store-path)))
        (string-append (string-take base prefix-length)
                       (ellipsis)
                       (string-drop base 32)))
      store-path))

(define* (progress-proc file size
                        #:optional (log-port (current-output-port))
                        #:key (abbreviation basename))
  "Return a procedure to show the progress of FILE's download, which is SIZE
bytes long.  The returned procedure is suitable for use as an argument to
`dump-port'.  The progress report is written to LOG-PORT, with ABBREVIATION
used to shorten FILE for display."
  ;; XXX: Because of <http://bugs.gnu.org/19939> this procedure is often not
  ;; called as frequently as we'd like too; this is especially bad with Nginx
  ;; on hydra.gnu.org, which returns whole nars as a single chunk.
  (let ((start-time #f))
    (let-syntax ((with-elapsed-time
                     (syntax-rules ()
                       ((_ elapsed body ...)
                        (let* ((now     (current-time time-monotonic))
                               (elapsed (and start-time
                                             (duration->seconds
                                              (time-difference now
                                                               start-time)))))
                          (unless start-time
                            (set! start-time now))
                          body ...)))))
      (if (number? size)
          (lambda (transferred cont)
            (with-elapsed-time elapsed
              (let* ((%          (* 100.0 (/ transferred size)))
                     (throughput (if elapsed
                                     (/ transferred elapsed)
                                     0))
                     (left       (format #f " ~a  ~a"
                                         (abbreviation file)
                                         (byte-count->string size)))
                     (right      (format #f "~a/s ~a ~a~6,1f%"
                                         (byte-count->string throughput)
                                         (seconds->string elapsed)
                                         (progress-bar %) %)))
                (display "\r\x1b[K" log-port)
                (display (string-pad-middle left right
                                            (current-terminal-columns))
                         log-port)
                (flush-output-port log-port)
                (cont))))
          (lambda (transferred cont)
            (with-elapsed-time elapsed
              (let* ((throughput (if elapsed
                                     (/ transferred elapsed)
                                     0))
                     (left       (format #f " ~a"
                                         (abbreviation file)))
                     (right      (format #f "~a/s ~a | ~a transferred"
                                         (byte-count->string throughput)
                                         (seconds->string elapsed)
                                         (byte-count->string transferred))))
                (display "\r\x1b[K" log-port)
                (display (string-pad-middle left right
                                            (current-terminal-columns))
                         log-port)
                (flush-output-port log-port)
                (cont))))))))

(define* (uri-abbreviation uri #:optional (max-length 42))
  "If URI's string representation is larger than MAX-LENGTH, return an
abbreviation of URI showing the scheme, host, and basename of the file."
  (define uri-as-string
    (uri->string uri))

  (define (elide-path)
    (let* ((path   (uri-path uri))
           (base   (basename path))
           (prefix (string-append (symbol->string (uri-scheme uri)) "://"

                                  ;; `file' URIs have no host part.
                                  (or (uri-host uri) "")

                                  (string-append "/" (ellipsis) "/"))))
      (if (> (+ (string-length prefix) (string-length base)) max-length)
          (string-append prefix (ellipsis)
                         (string-drop base (quotient (string-length base) 2)))
          (string-append prefix base))))

  (if (> (string-length uri-as-string) max-length)
      (let ((short (elide-path)))
        (if (< (string-length short) (string-length uri-as-string))
            short
            uri-as-string))
      uri-as-string))

(define (nar-uri-abbreviation uri)
  "Abbreviate URI, which is assumed to be the URI of a nar as served by Hydra
and 'guix publish', something like
\"http://example.org/nar/1ldrllwbna0aw5z8kpci4fsvbd2w8cw4-texlive-bin-2015\"."
  (let* ((uri  (if (string? uri) (string->uri uri) uri))
         (path (basename (uri-path uri))))
    (if (and (> (string-length path) 33)
             (char=? (string-ref path 32) #\-))
        (string-drop path 33)
        path)))

(define* (ftp-fetch uri file #:key timeout)
  "Fetch data from URI and write it to FILE.  Return FILE on success.  Bail
out if the connection could not be established in less than TIMEOUT seconds."
  (let* ((conn (ftp-open (uri-host uri) #:timeout timeout))
         (size (false-if-exception (ftp-size conn (uri-path uri))))
         (in   (ftp-retr conn (basename (uri-path uri))
                         (dirname (uri-path uri)))))
    (call-with-output-file file
      (lambda (out)
        (dump-port in out
                   #:buffer-size %http-receive-buffer-size
                   #:progress (progress-proc (uri-abbreviation uri) size))))

    (ftp-close conn))
    (newline)
  file)

;; Autoload GnuTLS so that this module can be used even when GnuTLS is
;; not available.  At compile time, this yields "possibly unbound
;; variable" warnings, but these are OK: we know that the variables will
;; be bound if we need them, because (guix download) adds GnuTLS as an
;; input in that case.

;; XXX: Use this hack instead of #:autoload to avoid compilation errors.
;; See <http://bugs.gnu.org/12202>.
(module-autoload! (current-module)
                  '(gnutls) '(make-session connection-end/client))

(define %tls-ports
  ;; Mapping of session record ports to the underlying file port.
  (make-weak-key-hash-table))

(define (register-tls-record-port record-port port)
  "Hold a weak reference from RECORD-PORT to PORT, where RECORD-PORT is a TLS
session record port using PORT as its underlying communication port."
  (hashq-set! %tls-ports record-port port))

(define (tls-wrap port server)
  "Return PORT wrapped in a TLS connection to SERVER.  SERVER must be a DNS
host name without trailing dot."
  (define (log level str)
    (format (current-error-port)
            "gnutls: [~a|~a] ~a" (getpid) level str))

  (let ((session (make-session connection-end/client)))

    ;; Some servers such as 'cloud.github.com' require the client to support
    ;; the 'SERVER NAME' extension.  However, 'set-session-server-name!' is
    ;; not available in older GnuTLS releases.  See
    ;; <http://bugs.gnu.org/18526> for details.
    (if (module-defined? (resolve-interface '(gnutls))
                         'set-session-server-name!)
        (set-session-server-name! session server-name-type/dns server)
        (format (current-error-port)
                "warning: TLS 'SERVER NAME' extension not supported~%"))

    (set-session-transport-fd! session (fileno port))
    (set-session-default-priority! session)

    ;; The "%COMPAT" bit allows us to work around firewall issues (info
    ;; "(gnutls) Priority Strings"); see <http://bugs.gnu.org/23311>.
    ;; Explicitly disable SSLv3, which is insecure:
    ;; <https://tools.ietf.org/html/rfc7568>.
    (set-session-priorities! session "NORMAL:%COMPAT:-VERS-SSL3.0")

    (set-session-credentials! session (make-certificate-credentials))

    ;; Uncomment the following lines in case of debugging emergency.
    ;;(set-log-level! 10)
    ;;(set-log-procedure! log)

    (handshake session)
    (let ((record (session-record-port session)))
      ;; Since we use `fileno' above, the file descriptor behind PORT would be
      ;; closed when PORT is GC'd.  If we used `port->fdes', it would instead
      ;; never be closed.  So we use `fileno', but keep a weak reference to
      ;; PORT, so the file descriptor gets closed when RECORD is GC'd.
      (register-tls-record-port record port)
      record)))

(define (ensure-uri uri-or-string)                ;XXX: copied from (web http)
  (cond
   ((string? uri-or-string) (string->uri uri-or-string))
   ((uri? uri-or-string) uri-or-string)
   (else (error "Invalid URI" uri-or-string))))

(define current-http-proxy
  ;; XXX: Add a dummy definition for Guile < 2.0.10; this is used in
  ;; 'open-socket-for-uri'.
  (or (and=> (module-variable (resolve-interface '(web client))
                              'current-http-proxy)
             variable-ref)
      (const #f)))

(define* (open-socket-for-uri uri-or-string #:key timeout)
  "Return an open input/output port for a connection to URI.  When TIMEOUT is
not #f, it must be a (possibly inexact) number denoting the maximum duration
in seconds to wait for the connection to complete; passed TIMEOUT, an
ETIMEDOUT error is raised."
  ;; Includes a fix for <http://bugs.gnu.org/15368> which affects Guile's
  ;; 'open-socket-for-uri' up to 2.0.11 included, uses 'connect*' instead
  ;; of 'connect', and uses AI_ADDRCONFIG.

  (define http-proxy (current-http-proxy))
  (define uri (ensure-uri (or http-proxy uri-or-string)))
  (define addresses
    (let ((port (uri-port uri)))
      (delete-duplicates
       (getaddrinfo (uri-host uri)
                    (cond (port => number->string)
                          (else (symbol->string (uri-scheme uri))))
                    (if (number? port)
                        (logior AI_ADDRCONFIG AI_NUMERICSERV)
                        AI_ADDRCONFIG))
       (lambda (ai1 ai2)
         (equal? (addrinfo:addr ai1) (addrinfo:addr ai2))))))

  (let loop ((addresses addresses))
    (let* ((ai (car addresses))
           (s  (with-fluids ((%default-port-encoding #f))
                 ;; Restrict ourselves to TCP.
                 (socket (addrinfo:fam ai) SOCK_STREAM IPPROTO_IP))))
      (catch 'system-error
        (lambda ()
          (connect* s (addrinfo:addr ai) timeout)

          ;; Buffer input and output on this port.
          (setvbuf s _IOFBF)
          ;; If we're using a proxy, make a note of that.
          (when http-proxy (set-http-proxy-port?! s #t))
          s)
        (lambda args
          ;; Connection failed, so try one of the other addresses.
          (close s)
          (if (null? (cdr addresses))
              (apply throw args)
              (loop (cdr addresses))))))))

(define* (open-connection-for-uri uri #:key timeout)
  "Like 'open-socket-for-uri', but also handle HTTPS connections.  The
resulting port must be closed with 'close-connection'."
  (define https?
    (eq? 'https (uri-scheme uri)))

  (let-syntax ((with-https-proxy
                (syntax-rules ()
                  ((_ exp)
                   ;; For HTTPS URIs, honor 'https_proxy', not 'http_proxy'.
                   ;; FIXME: Proxying is not supported for https.
                   (let ((thunk (lambda () exp)))
                     (if (and https?
                              (module-variable
                               (resolve-interface '(web client))
                               'current-http-proxy))
                         (parameterize ((current-http-proxy #f))
                           (when (and=> (getenv "https_proxy")
                                        (negate string-null?))
                             (format (current-error-port)
                                     "warning: 'https_proxy' is ignored~%"))
                           (thunk))
                         (thunk)))))))
    (with-https-proxy
     (let ((s (open-socket-for-uri uri #:timeout timeout)))
       ;; Buffer input and output on this port.
       (setvbuf s _IOFBF %http-receive-buffer-size)

       (if https?
           (tls-wrap s (uri-host uri))
           s)))))

(define (close-connection port)
  "Like 'close-port', but (1) idempotent, and (2) also closes the underlying
port if PORT is a TLS session record port."
  ;; FIXME: This is a partial workaround for <http://bugs.gnu.org/20145>,
  ;; because 'http-fetch' & co. may return a chunked input port whose 'close'
  ;; method calls 'close-port', not 'close-connection'.
  (unless (port-closed? port)
    (close-port port))
  (and=> (hashq-ref %tls-ports port)
         close-connection))

;; XXX: This is an awful hack to make sure the (set-port-encoding! p
;; "ISO-8859-1") call in `read-response' passes, even during bootstrap
;; where iconv is not available.
(module-define! (resolve-module '(web response))
                'set-port-encoding!
                (lambda (p e) #f))

;; XXX: Work around <http://bugs.gnu.org/13095>, present in Guile
;; up to 2.0.7.
(module-define! (resolve-module '(web client))
                'shutdown (const #f))


;; XXX: Work around <http://bugs.gnu.org/23421>, fixed in Guile commit
;; 16050431f29d56f80c4a8253506fc851b8441840.  Guile's date validation
;; procedure rejects dates in which the hour is not padded with a zero but
;; with whitespace.
(begin
  (define-syntax string-match?
    (lambda (x)
      (syntax-case x ()
        ((_ str pat) (string? (syntax->datum #'pat))
         (let ((p (syntax->datum #'pat)))
           #`(let ((s str))
               (and
                (= (string-length s) #,(string-length p))
                #,@(let lp ((i 0) (tests '()))
                     (if (< i (string-length p))
                         (let ((c (string-ref p i)))
                           (lp (1+ i)
                               (case c
                                 ((#\.)  ; Whatever.
                                  tests)
                                 ((#\d)  ; Digit.
                                  (cons #`(char-numeric? (string-ref s #,i))
                                        tests))
                                 ((#\a)  ; Alphabetic.
                                  (cons #`(char-alphabetic? (string-ref s #,i))
                                        tests))
                                 (else   ; Literal.
                                  (cons #`(eqv? (string-ref s #,i) #,c)
                                        tests)))))
                         tests)))))))))

  (define (parse-rfc-822-date str space zone-offset)
    (let ((parse-non-negative-integer (@@ (web http) parse-non-negative-integer))
          (parse-month (@@ (web http) parse-month))
          (bad-header (@@ (web http) bad-header)))
      ;; We could verify the day of the week but we don't.
      (cond ((string-match? (substring str 0 space) "aaa, dd aaa dddd dd:dd:dd")
             (let ((date (parse-non-negative-integer str 5 7))
                   (month (parse-month str 8 11))
                   (year (parse-non-negative-integer str 12 16))
                   (hour (parse-non-negative-integer str 17 19))
                   (minute (parse-non-negative-integer str 20 22))
                   (second (parse-non-negative-integer str 23 25)))
               (make-date 0 second minute hour date month year zone-offset)))
            ((string-match? (substring str 0 space) "aaa, d aaa dddd dd:dd:dd")
             (let ((date (parse-non-negative-integer str 5 6))
                   (month (parse-month str 7 10))
                   (year (parse-non-negative-integer str 11 15))
                   (hour (parse-non-negative-integer str 16 18))
                   (minute (parse-non-negative-integer str 19 21))
                   (second (parse-non-negative-integer str 22 24)))
               (make-date 0 second minute hour date month year zone-offset)))

            ;; The next two clauses match dates that have a space instead of
            ;; a leading zero for hours, like " 8:49:37".
            ((string-match? (substring str 0 space) "aaa, dd aaa dddd  d:dd:dd")
             (let ((date (parse-non-negative-integer str 5 7))
                   (month (parse-month str 8 11))
                   (year (parse-non-negative-integer str 12 16))
                   (hour (parse-non-negative-integer str 18 19))
                   (minute (parse-non-negative-integer str 20 22))
                   (second (parse-non-negative-integer str 23 25)))
               (make-date 0 second minute hour date month year zone-offset)))
            ((string-match? (substring str 0 space) "aaa, d aaa dddd  d:dd:dd")
             (let ((date (parse-non-negative-integer str 5 6))
                   (month (parse-month str 7 10))
                   (year (parse-non-negative-integer str 11 15))
                   (hour (parse-non-negative-integer str 17 18))
                   (minute (parse-non-negative-integer str 19 21))
                   (second (parse-non-negative-integer str 22 24)))
               (make-date 0 second minute hour date month year zone-offset)))

            (else
             (bad-header 'date str)        ; prevent tail call
             #f))))
  (module-set! (resolve-module '(web http))
               'parse-rfc-822-date parse-rfc-822-date))

;; XXX: Work around <http://bugs.gnu.org/19840>, present in Guile
;; up to 2.0.11.
(unless (or (> (string->number (major-version)) 2)
            (> (string->number (minor-version)) 0)
            (> (string->number (micro-version)) 11))
  (let ((var (module-variable (resolve-module '(web http))
                              'declare-relative-uri-header!)))
    ;; If 'declare-relative-uri-header!' doesn't exist, forget it.
    (when (and var (variable-bound? var))
      (let ((declare-relative-uri-header! (variable-ref var)))
        (declare-relative-uri-header! "Location")))))

(define (resolve-uri-reference ref base)
  "Resolve the URI reference REF, interpreted relative to the BASE URI, into a
target URI, according to the algorithm specified in RFC 3986 section 5.2.2.
Return the resulting target URI."

  (define (merge-paths base-path rel-path)
    (let* ((base-components (string-split base-path #\/))
           (base-directory-components (match base-components
                                        ((components ... last) components)
                                        (() '())))
           (base-directory (string-join base-directory-components "/")))
      (string-append base-directory "/" rel-path)))

  (define (remove-dot-segments path)
    (let loop ((in
                ;; Drop leading "." and ".." components from a relative path.
                ;; (absolute paths will start with a "" component)
                (drop-while (match-lambda
                              ((or "." "..") #t)
                              (_ #f))
                            (string-split path #\/)))
               (out '()))
      (match in
        (("." . rest)
         (loop rest out))
        ((".." . rest)
         (match out
           ((or () (""))
            (error "remove-dot-segments: too many '..' components" path))
           (_
            (loop rest (cdr out)))))
        ((component . rest)
         (loop rest (cons component out)))
        (()
         (string-join (reverse out) "/")))))

  (cond ((or (uri-scheme ref)
             (uri-host   ref))
         (build-uri (or (uri-scheme ref)
                        (uri-scheme base))
                    #:userinfo (uri-userinfo ref)
                    #:host     (uri-host     ref)
                    #:port     (uri-port     ref)
                    #:path     (remove-dot-segments (uri-path ref))
                    #:query    (uri-query    ref)
                    #:fragment (uri-fragment ref)))
        ((string-null? (uri-path ref))
         (build-uri (uri-scheme base)
                    #:userinfo (uri-userinfo base)
                    #:host     (uri-host     base)
                    #:port     (uri-port     base)
                    #:path     (remove-dot-segments (uri-path base))
                    #:query    (or (uri-query ref)
                                   (uri-query base))
                    #:fragment (uri-fragment ref)))
        (else
         (build-uri (uri-scheme base)
                    #:userinfo (uri-userinfo base)
                    #:host     (uri-host     base)
                    #:port     (uri-port     base)
                    #:path     (remove-dot-segments
                                (if (string-prefix? "/" (uri-path ref))
                                    (uri-path ref)
                                    (merge-paths (uri-path base)
                                                 (uri-path ref))))
                    #:query    (uri-query    ref)
                    #:fragment (uri-fragment ref)))))

(define* (http-fetch uri file #:key timeout)
  "Fetch data from URI and write it to FILE; when TIMEOUT is true, bail out if
the connection could not be established in less than TIMEOUT seconds.  Return
FILE on success."

  (define post-2.0.7?
    (or (> (string->number (major-version)) 2)
        (> (string->number (minor-version)) 0)
        (> (string->number (micro-version)) 7)
        (string>? (version) "2.0.7")))

  (define headers
    `(;; Some web sites, such as http://dist.schmorp.de, would block you if
      ;; there's no 'User-Agent' header, presumably on the assumption that
      ;; you're a spammer.  So work around that.
      (User-Agent . "GNU Guile")

      ;; Some servers, such as https://alioth.debian.org, return "406 Not
      ;; Acceptable" when not explicitly told that everything is accepted.
      (Accept . "*/*")

      ;; Basic authentication, if needed.
      ,@(match (uri-userinfo uri)
          ((? string? str)
           `((Authorization . ,(string-append "Basic "
                                              (base64-encode
                                               (string->utf8 str))))))
          (_ '()))))

  (let*-values (((connection)
                 (open-connection-for-uri uri #:timeout timeout))
                ((resp bv-or-port)
                 ;; XXX: `http-get*' was introduced in 2.0.7, and replaced by
                 ;; #:streaming? in 2.0.8.  We know we're using it within the
                 ;; chroot, but `guix-download' might be using a different
                 ;; version.  So keep this compatibility hack for now.
                 (if post-2.0.7?
                     (http-get uri #:port connection #:decode-body? #f
                               #:streaming? #t
                               #:headers headers)
                     (if (module-defined? (resolve-interface '(web client))
                                          'http-get*)
                         (http-get* uri #:port connection #:decode-body? #f
                                    #:headers headers)
                         (http-get uri #:port connection #:decode-body? #f
                                   #:extra-headers headers))))
                ((code)
                 (response-code resp))
                ((size)
                 (response-content-length resp)))
    (case code
      ((200)                                      ; OK
       (begin
         (call-with-output-file file
           (lambda (p)
             (if (port? bv-or-port)
                 (begin
                   (dump-port bv-or-port p
                              #:buffer-size %http-receive-buffer-size
                              #:progress (progress-proc (uri-abbreviation uri)
                                                        size))
                   (newline))
                 (put-bytevector p bv-or-port))))
         file))
      ((301                                       ; moved permanently
        302                                       ; found (redirection)
        307)                                      ; temporary redirection
       (let ((uri (resolve-uri-reference (response-location resp) uri)))
         (format #t "following redirection to `~a'...~%"
                 (uri->string uri))
         (close connection)
         (http-fetch uri file #:timeout timeout)))
      (else
       (error "download failed" (uri->string uri)
              code (response-reason-phrase resp))))))


(define-syntax-rule (false-if-exception* body ...)
  "Like `false-if-exception', but print the exception on the error port."
  (catch #t
    (lambda ()
      body ...)
    (lambda (key . args)
      #f)
    (lambda (key . args)
      (print-exception (current-error-port) #f key args))))

(define (uri-vicinity dir file)
  "Concatenate DIR, slash, and FILE, keeping only one slash in between.
This is required by some HTTP servers."
  (string-append (string-trim-right dir #\/) "/"
                 (string-trim file #\/)))

(define (maybe-expand-mirrors uri mirrors)
  "If URI uses the 'mirror' scheme, expand it according to the MIRRORS alist.
Return a list of URIs."
  (case (uri-scheme uri)
    ((mirror)
     (let ((kind (string->symbol (uri-host uri)))
           (path (uri-path uri)))
       (match (assoc-ref mirrors kind)
         ((mirrors ..1)
          (map (compose string->uri (cut uri-vicinity <> path))
               mirrors))
         (_
          (error "unsupported URL mirror kind" kind uri)))))
    (else
     (list uri))))

(define* (url-fetch url file
                    #:key
                    (timeout 10)
                    (mirrors '()) (content-addressed-mirrors '())
                    (hashes '()))
  "Fetch FILE from URL; URL may be either a single string, or a list of
string denoting alternate URLs for FILE.  Return #f on failure, and FILE
on success.

When MIRRORS is defined, it must be an alist of mirrors; it is used to resolve
'mirror://' URIs.

HASHES must be a list of algorithm/hash pairs, where each algorithm is a
symbol such as 'sha256 and each hash is a bytevector.
CONTENT-ADDRESSED-MIRRORS must be a list of procedures that, given a hash
algorithm and a hash, return a URL where the specified data can be retrieved
or #f."
  (define uri
    (append-map (cut maybe-expand-mirrors <> mirrors)
                (match url
                  ((_ ...) (map string->uri url))
                  (_       (list (string->uri url))))))

  (define (fetch uri file)
    (format #t "~%Starting download of ~a~%From ~a...~%"
            file (uri->string uri))
    (case (uri-scheme uri)
      ((http https)
       (false-if-exception* (http-fetch uri file #:timeout timeout)))
      ((ftp)
       (false-if-exception* (ftp-fetch uri file #:timeout timeout)))
      (else
       (format #t "skipping URI with unsupported scheme: ~s~%"
               uri)
       #f)))

  (define content-addressed-uris
    (append-map (lambda (make-url)
                  (filter-map (match-lambda
                                ((hash-algo . hash)
                                 (let ((file (strip-store-file-name file)))
                                   (string->uri (make-url file hash-algo hash)))))
                              hashes))
                content-addressed-mirrors))

  ;; Make this unbuffered so 'progress-proc' works as expected.  _IOLBF means
  ;; '\n', not '\r', so it's not appropriate here.
  (setvbuf (current-output-port) _IONBF)

  (setvbuf (current-error-port) _IOLBF)

  (let try ((uri (append uri content-addressed-uris)))
    (match uri
      ((uri tail ...)
       (or (fetch uri file)
           (try tail)))
      (()
       (format (current-error-port) "failed to download ~s from ~s~%"
               file url)
       #f))))

;;; Local Variables:
;;; eval: (put 'with-elapsed-time 'scheme-indent-function 1)
;;; End:

;;; download.scm ends here
