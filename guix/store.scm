;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (guix store)
  #:use-module (guix utils)
  #:use-module (guix config)
  #:use-module (guix combinators)
  #:use-module (guix serialization)
  #:use-module (guix monads)
  #:autoload   (guix base32) (bytevector->base32-string)
  #:autoload   (guix build syscalls) (terminal-columns)
  #:use-module (rnrs bytevectors)
  #:use-module (rnrs io ports)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-9 gnu)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:use-module (srfi srfi-39)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 vlist)
  #:use-module (ice-9 popen)
  #:export (%daemon-socket-file
            %gc-roots-directory
            %default-substitute-urls

            nix-server?
            nix-server-major-version
            nix-server-minor-version
            nix-server-socket

            &nix-error nix-error?
            &nix-connection-error nix-connection-error?
            nix-connection-error-file
            nix-connection-error-code
            &nix-protocol-error nix-protocol-error?
            nix-protocol-error-message
            nix-protocol-error-status

            hash-algo
            build-mode

            open-connection
            close-connection
            with-store
            set-build-options
            set-build-options*
            valid-path?
            query-path-hash
            hash-part->path
            query-path-info
            add-text-to-store
            add-to-store
            build-things
            build
            query-failed-paths
            clear-failed-paths
            add-temp-root
            add-indirect-root
            add-permanent-root
            remove-permanent-root

            substitutable?
            substitutable-path
            substitutable-deriver
            substitutable-references
            substitutable-download-size
            substitutable-nar-size
            has-substitutes?
            substitutable-paths
            substitutable-path-info

            path-info?
            path-info-deriver
            path-info-hash
            path-info-references
            path-info-registration-time
            path-info-nar-size

            references
            references/substitutes
            requisites
            referrers
            optimize-store
            verify-store
            topologically-sorted
            valid-derivers
            query-derivation-outputs
            live-paths
            dead-paths
            collect-garbage
            delete-paths
            import-paths
            export-paths

            current-build-output-port

            register-path

            %store-monad
            store-bind
            store-return
            store-lift
            store-lower
            run-with-store
            %guile-for-build
            current-system
            set-current-system
            text-file
            interned-file

            %store-prefix
            store-path?
            direct-store-path?
            derivation-path?
            store-path-package-name
            store-path-hash-part
            direct-store-path
            log-file))

(define %protocol-version #x10f)

(define %worker-magic-1 #x6e697863)               ; "nixc"
(define %worker-magic-2 #x6478696f)               ; "dxio"

(define (protocol-major magic)
  (logand magic #xff00))
(define (protocol-minor magic)
  (logand magic #x00ff))

(define-syntax define-enumerate-type
  (syntax-rules ()
    ((_ name->int (name id) ...)
     (define-syntax name->int
       (syntax-rules (name ...)
         ((_ name) id) ...)))))

(define-enumerate-type operation-id
  ;; operation numbers from worker-protocol.hh
  (quit 0)
  (valid-path? 1)
  (has-substitutes? 3)
  (query-path-hash 4)
  (query-references 5)
  (query-referrers 6)
  (add-to-store 7)
  (add-text-to-store 8)
  (build-things 9)
  (ensure-path 10)
  (add-temp-root 11)
  (add-indirect-root 12)
  (sync-with-gc 13)
  (find-roots 14)
  (export-path 16)
  (query-deriver 18)
  (set-options 19)
  (collect-garbage 20)
  ;;(query-substitutable-path-info 21)  ; obsolete as of #x10c
  (query-derivation-outputs 22)
  (query-all-valid-paths 23)
  (query-failed-paths 24)
  (clear-failed-paths 25)
  (query-path-info 26)
  (import-paths 27)
  (query-derivation-output-names 28)
  (query-path-from-hash-part 29)
  (query-substitutable-path-infos 30)
  (query-valid-paths 31)
  (query-substitutable-paths 32)
  (query-valid-derivers 33)
  (optimize-store 34)
  (verify-store 35))

(define-enumerate-type hash-algo
  ;; hash.hh
  (md5 1)
  (sha1 2)
  (sha256 3))

(define-enumerate-type build-mode
  ;; store-api.hh
  (normal 0)
  (repair 1)
  (check 2))

(define-enumerate-type gc-action
  ;; store-api.hh
  (return-live 0)
  (return-dead 1)
  (delete-dead 2)
  (delete-specific 3))

(define %default-socket-path
  (string-append %state-directory "/daemon-socket/socket"))

(define %daemon-socket-file
  ;; File name of the socket the daemon listens too.
  (make-parameter (or (getenv "GUIX_DAEMON_SOCKET")
                      %default-socket-path)))



;; Information about a substitutable store path.
(define-record-type <substitutable>
  (substitutable path deriver refs dl-size nar-size)
  substitutable?
  (path      substitutable-path)
  (deriver   substitutable-deriver)
  (refs      substitutable-references)
  (dl-size   substitutable-download-size)
  (nar-size  substitutable-nar-size))

(define (read-substitutable-path-list p)
  (let loop ((len    (read-int p))
             (result '()))
    (if (zero? len)
        (reverse result)
        (let ((path     (read-store-path p))
              (deriver  (read-store-path p))
              (refs     (read-store-path-list p))
              (dl-size  (read-long-long p))
              (nar-size (read-long-long p)))
          (loop (- len 1)
                (cons (substitutable path deriver refs dl-size nar-size)
                      result))))))

;; Information about a store path.
(define-record-type <path-info>
  (path-info deriver hash references registration-time nar-size)
  path-info?
  (deriver path-info-deriver)                     ;string | #f
  (hash path-info-hash)
  (references path-info-references)
  (registration-time path-info-registration-time)
  (nar-size path-info-nar-size))

(define (read-path-info p)
  (let ((deriver  (match (read-store-path p)
                    ("" #f)
                    (x  x)))
        (hash     (base16-string->bytevector (read-string p)))
        (refs     (read-store-path-list p))
        (registration-time (read-int p))
        (nar-size (read-long-long p)))
    (path-info deriver hash refs registration-time nar-size)))

(define-syntax write-arg
  (syntax-rules (integer boolean string string-list string-pairs
                 store-path store-path-list base16)
    ((_ integer arg p)
     (write-int arg p))
    ((_ boolean arg p)
     (write-int (if arg 1 0) p))
    ((_ string arg p)
     (write-string arg p))
    ((_ string-list arg p)
     (write-string-list arg p))
    ((_ string-pairs arg p)
     (write-string-pairs arg p))
    ((_ store-path arg p)
     (write-store-path arg p))
    ((_ store-path-list arg p)
     (write-store-path-list arg p))
    ((_ base16 arg p)
     (write-string (bytevector->base16-string arg) p))))

(define-syntax read-arg
  (syntax-rules (integer boolean string store-path store-path-list
                 substitutable-path-list path-info base16)
    ((_ integer p)
     (read-int p))
    ((_ boolean p)
     (not (zero? (read-int p))))
    ((_ string p)
     (read-string p))
    ((_ store-path p)
     (read-store-path p))
    ((_ store-path-list p)
     (read-store-path-list p))
    ((_ substitutable-path-list p)
     (read-substitutable-path-list p))
    ((_ path-info p)
     (read-path-info p))
    ((_ base16 p)
     (base16-string->bytevector (read-string p)))))


;; remote-store.cc

(define-record-type <nix-server>
  (%make-nix-server socket major minor
                    ats-cache atts-cache)
  nix-server?
  (socket nix-server-socket)
  (major  nix-server-major-version)
  (minor  nix-server-minor-version)

  ;; Caches.  We keep them per-connection, because store paths build
  ;; during the session are temporary GC roots kept for the duration of
  ;; the session.
  (ats-cache  nix-server-add-to-store-cache)
  (atts-cache nix-server-add-text-to-store-cache))

(set-record-type-printer! <nix-server>
                          (lambda (obj port)
                            (format port "#<build-daemon ~a.~a ~a>"
                                    (nix-server-major-version obj)
                                    (nix-server-minor-version obj)
                                    (number->string (object-address obj)
                                                    16))))

(define-condition-type &nix-error &error
  nix-error?)

(define-condition-type &nix-connection-error &nix-error
  nix-connection-error?
  (file   nix-connection-error-file)
  (errno  nix-connection-error-code))

(define-condition-type &nix-protocol-error &nix-error
  nix-protocol-error?
  (message nix-protocol-error-message)
  (status  nix-protocol-error-status))

(define* (open-connection #:optional (file (%daemon-socket-file))
                          #:key (reserve-space? #t) cpu-affinity)
  "Connect to the daemon over the Unix-domain socket at FILE.  When
RESERVE-SPACE? is true, instruct it to reserve a little bit of extra space on
the file system so that the garbage collector can still operate, should the
disk become full.  When CPU-AFFINITY is true, it must be an integer
corresponding to an OS-level CPU number to which the daemon's worker process
for this connection will be pinned.  Return a server object."
  (let ((s (with-fluids ((%default-port-encoding #f))
             ;; This trick allows use of the `scm_c_read' optimization.
             (socket PF_UNIX SOCK_STREAM 0)))
        (a (make-socket-address PF_UNIX file)))

    (catch 'system-error
      (cut connect s a)
      (lambda args
        ;; Translate the error to something user-friendly.
        (let ((errno (system-error-errno args)))
          (raise (condition (&nix-connection-error
                             (file file)
                             (errno errno)))))))

    (write-int %worker-magic-1 s)
    (let ((r (read-int s)))
      (and (eqv? r %worker-magic-2)
           (let ((v (read-int s)))
             (and (eqv? (protocol-major %protocol-version)
                        (protocol-major v))
                  (begin
                    (write-int %protocol-version s)
                    (when (>= (protocol-minor v) 14)
                      (write-int (if cpu-affinity 1 0) s)
                      (when cpu-affinity
                        (write-int cpu-affinity s)))
                    (when (>= (protocol-minor v) 11)
                      (write-int (if reserve-space? 1 0) s))
                    (let ((s (%make-nix-server s
                                               (protocol-major v)
                                               (protocol-minor v)
                                               (make-hash-table 100)
                                               (make-hash-table 100))))
                      (let loop ((done? (process-stderr s)))
                        (or done? (process-stderr s)))
                      s))))))))

(define (close-connection server)
  "Close the connection to SERVER."
  (close (nix-server-socket server)))

(define-syntax-rule (with-store store exp ...)
  "Bind STORE to an open connection to the store and evaluate EXPs;
automatically close the store when the dynamic extent of EXP is left."
  (let ((store (open-connection)))
    (dynamic-wind
      (const #f)
      (lambda ()
        exp ...)
      (lambda ()
        (false-if-exception (close-connection store))))))

(define current-build-output-port
  ;; The port where build output is sent.
  (make-parameter (current-error-port)))

(define* (dump-port in out
                    #:optional len
                    #:key (buffer-size 16384))
  "Read LEN bytes from IN (or as much as possible if LEN is #f) and write it
to OUT, using chunks of BUFFER-SIZE bytes."
  (define buffer
    (make-bytevector buffer-size))

  (let loop ((total 0)
             (bytes (get-bytevector-n! in buffer 0
                                       (if len
                                           (min len buffer-size)
                                           buffer-size))))
    (or (eof-object? bytes)
        (and len (= total len))
        (let ((total (+ total bytes)))
          (put-bytevector out buffer 0 bytes)
          (loop total
                (get-bytevector-n! in buffer 0
                                   (if len
                                       (min (- len total) buffer-size)
                                       buffer-size)))))))

(define %newlines
  ;; Newline characters triggering a flush of 'current-build-output-port'.
  ;; Unlike Guile's _IOLBF, we flush upon #\return so that progress reports
  ;; that use that trick are correctly displayed.
  (char-set #\newline #\return))

(define* (process-stderr server #:optional user-port)
  "Read standard output and standard error from SERVER, writing it to
CURRENT-BUILD-OUTPUT-PORT.  Return #t when SERVER is done sending data, and
#f otherwise; in the latter case, the caller should call `process-stderr'
again until #t is returned or an error is raised.

Since the build process's output cannot be assumed to be UTF-8, we
conservatively consider it to be Latin-1, thereby avoiding possible
encoding conversion errors."
  (define p
    (nix-server-socket server))

  ;; magic cookies from worker-protocol.hh
  (define %stderr-next  #x6f6c6d67)          ; "olmg", build log
  (define %stderr-read  #x64617461)          ; "data", data needed from source
  (define %stderr-write #x64617416)          ; "dat\x16", data for sink
  (define %stderr-last  #x616c7473)          ; "alts", we're done
  (define %stderr-error #x63787470)          ; "cxtp", error reporting

  (let ((k (read-int p)))
    (cond ((= k %stderr-write)
           ;; Write a byte stream to USER-PORT.
           (let* ((len (read-int p))
                  (m   (modulo len 8)))
             (dump-port p user-port len)
             (unless (zero? m)
               ;; Consume padding, as for strings.
               (get-bytevector-n p (- 8 m))))
           #f)
          ((= k %stderr-read)
           ;; Read a byte stream from USER-PORT.
           ;; Note: Avoid 'get-bytevector-n' to work around
           ;; <http://bugs.gnu.org/17591> in Guile up to 2.0.11.
           (let* ((max-len (read-int p))
                  (data    (make-bytevector max-len))
                  (len     (get-bytevector-n! user-port data 0 max-len)))
             (write-int len p)
             (put-bytevector p data 0 len)
             (write-padding len p)
             #f))
          ((= k %stderr-next)
           ;; Log a string.  Build logs are usually UTF-8-encoded, but they
           ;; may also contain arbitrary byte sequences that should not cause
           ;; this to fail.  Thus, use the permissive
           ;; 'read-maybe-utf8-string'.
           (let ((s (read-maybe-utf8-string p)))
             (display s (current-build-output-port))
             (when (string-any %newlines s)
               (flush-output-port (current-build-output-port)))
             #f))
          ((= k %stderr-error)
           ;; Report an error.
           (let ((error  (read-maybe-utf8-string p))
                 ;; Currently the daemon fails to send a status code for early
                 ;; errors like DB schema version mismatches, so check for EOF.
                 (status (if (and (>= (nix-server-minor-version server) 8)
                                  (not (eof-object? (lookahead-u8 p))))
                             (read-int p)
                             1)))
             (raise (condition (&nix-protocol-error
                                (message error)
                                (status  status))))))
          ((= k %stderr-last)
           ;; The daemon is done (see `stopWork' in `nix-worker.cc'.)
           #t)
          (else
           (raise (condition (&nix-protocol-error
                              (message "invalid error code")
                              (status   k))))))))

(define %default-substitute-urls
  ;; Default list of substituters.  This is *not* the list baked in
  ;; 'guix-daemon', but it is used by 'guix-service-type' and and a couple of
  ;; clients ('guix build --log-file' uses it.)
  (map (if (false-if-exception (resolve-interface '(gnutls)))
           (cut string-append "https://" <>)
           (cut string-append "http://" <>))
       '("mirror.hydra.gnu.org")))

(define* (set-build-options server
                            #:key keep-failed? keep-going? fallback?
                            (verbosity 0)
                            rounds                ;number of build rounds
                            (max-build-jobs 1)
                            timeout
                            (max-silent-time 3600)
                            (use-build-hook? #t)
                            (build-verbosity 0)
                            (log-type 0)
                            (print-build-trace #t)
                            (build-cores (current-processor-count))
                            (use-substitutes? #t)

                            ;; Client-provided substitute URLs.  If it is #f,
                            ;; the daemon's settings are used.  Otherwise, it
                            ;; overrides the daemons settings; see 'guix
                            ;; substitute'.
                            (substitute-urls #f)

                            ;; Number of columns in the client's terminal.
                            (terminal-columns (terminal-columns))

                            ;; Locale of the client.
                            (locale (false-if-exception (setlocale LC_ALL))))
  ;; Must be called after `open-connection'.

  (define socket
    (nix-server-socket server))

  (let-syntax ((send (syntax-rules ()
                       ((_ (type option) ...)
                        (begin
                          (write-arg type option socket)
                          ...)))))
    (write-int (operation-id set-options) socket)
    (send (boolean keep-failed?) (boolean keep-going?)
          (boolean fallback?) (integer verbosity)
          (integer max-build-jobs) (integer max-silent-time))
    (when (>= (nix-server-minor-version server) 2)
      (send (boolean use-build-hook?)))
    (when (>= (nix-server-minor-version server) 4)
      (send (integer build-verbosity) (integer log-type)
            (boolean print-build-trace)))
    (when (>= (nix-server-minor-version server) 6)
      (send (integer build-cores)))
    (when (>= (nix-server-minor-version server) 10)
      (send (boolean use-substitutes?)))
    (when (>= (nix-server-minor-version server) 12)
      (let ((pairs `(,@(if timeout
                           `(("build-timeout" . ,(number->string timeout)))
                           '())
                     ,@(if substitute-urls
                           `(("substitute-urls"
                              . ,(string-join substitute-urls)))
                           '())
                     ,@(if rounds
                           `(("build-repeat"
                              . ,(number->string (max 0 (1- rounds)))))
                           '())
                     ,@(if terminal-columns
                           `(("terminal-columns"
                              . ,(number->string terminal-columns)))
                           '())
                     ,@(if locale
                           `(("locale" . ,locale))
                           '()))))
        (send (string-pairs pairs))))
    (let loop ((done? (process-stderr server)))
      (or done? (process-stderr server)))))

(define-syntax operation
  (syntax-rules ()
    "Define a client-side RPC stub for the given operation."
    ((_ (name (type arg) ...) docstring return ...)
     (lambda (server arg ...)
       docstring
       (let ((s (nix-server-socket server)))
         (write-int (operation-id name) s)
         (write-arg type arg s)
         ...
         ;; Loop until the server is done sending error output.
         (let loop ((done? (process-stderr server)))
           (or done? (loop (process-stderr server))))
         (values (read-arg return s) ...))))))

(define-syntax-rule (define-operation (name args ...)
                      docstring return ...)
  (define name
    (operation (name args ...) docstring return ...)))

(define-operation (valid-path? (string path))
  "Return #t when PATH designates a valid store item and #f otherwise (an
invalid item may exist on disk but still be invalid, for instance because it
is the result of an aborted or failed build.)

A '&nix-protocol-error' condition is raised if PATH is not prefixed by the
store directory (/gnu/store)."
  boolean)

(define-operation (query-path-hash (store-path path))
  "Return the SHA256 hash of the nar serialization of PATH as a bytevector."
  base16)

(define hash-part->path
  (let ((query-path-from-hash-part
         (operation (query-path-from-hash-part (string hash))
                    #f
                    store-path)))
   (lambda (server hash-part)
     "Return the store path whose hash part is HASH-PART (a nix-base32
string).  Raise an error if no such path exists."
     ;; This RPC is primarily used by Hydra to reply to HTTP GETs of
     ;; /HASH.narinfo.
     (query-path-from-hash-part server hash-part))))

(define-operation (query-path-info (store-path path))
  "Return the info (hash, references, etc.) for PATH."
  path-info)

(define add-text-to-store
  ;; A memoizing version of `add-to-store', to avoid repeated RPCs with
  ;; the very same arguments during a given session.
  (let ((add-text-to-store
         (operation (add-text-to-store (string name) (string text)
                                       (string-list references))
                    #f
                    store-path)))
    (lambda* (server name text #:optional (references '()))
      "Add TEXT under file NAME in the store, and return its store path.
REFERENCES is the list of store paths referred to by the resulting store
path."
      (let ((args  `(,text ,name ,references))
            (cache (nix-server-add-text-to-store-cache server)))
        (or (hash-ref cache args)
            (let ((path (add-text-to-store server name text references)))
              (hash-set! cache args path)
              path))))))

(define true
  ;; Define it once and for all since we use it as a default value for
  ;; 'add-to-store' and want to make sure two default values are 'eq?' for the
  ;; purposes or memoization.
  (lambda (file stat)
    #t))

(define add-to-store
  ;; A memoizing version of `add-to-store'.  This is important because
  ;; `add-to-store' leads to huge data transfers to the server, and
  ;; because it's often called many times with the very same argument.
  (let ((add-to-store
         (lambda* (server basename recursive? hash-algo file-name
                          #:key (select? true))
           ;; We don't use the 'operation' macro so we can pass SELECT? to
           ;; 'write-file'.
           (let ((port (nix-server-socket server)))
             (write-int (operation-id add-to-store) port)
             (write-string basename port)
             (write-int 1 port)                   ;obsolete, must be #t
             (write-int (if recursive? 1 0) port)
             (write-string hash-algo port)
             (write-file file-name port #:select? select?)
             (let loop ((done? (process-stderr server)))
               (or done? (loop (process-stderr server))))
             (read-store-path port)))))
    (lambda* (server basename recursive? hash-algo file-name
                     #:key (select? true))
      "Add the contents of FILE-NAME under BASENAME to the store.  When
RECURSIVE? is false, FILE-NAME must designate a regular file--not a directory
nor a symlink.  When RECURSIVE? is true and FILE-NAME designates a directory,
the contents of FILE-NAME are added recursively; if FILE-NAME designates a
flat file and RECURSIVE? is true, its contents are added, and its permission
bits are kept.  HASH-ALGO must be a string such as \"sha256\".

When RECURSIVE? is true, call (SELECT?  FILE STAT) for each directory entry,
where FILE is the entry's absolute file name and STAT is the result of
'lstat'; exclude entries for which SELECT? does not return true."
      (let* ((st    (false-if-exception (lstat file-name)))
             (args  `(,st ,basename ,recursive? ,hash-algo ,select?))
             (cache (nix-server-add-to-store-cache server)))
        (or (and st (hash-ref cache args))
            (let ((path (add-to-store server basename recursive?
                                      hash-algo file-name
                                      #:select? select?)))
              (hash-set! cache args path)
              path))))))

(define build-things
  (let ((build (operation (build-things (string-list things)
                                        (integer mode))
                          "Do it!"
                          boolean))
        (build/old (operation (build-things (string-list things))
                              "Do it!"
                              boolean)))
    (lambda* (store things #:optional (mode (build-mode normal)))
      "Build THINGS, a list of store items which may be either '.drv' files or
outputs, and return when the worker is done building them.  Elements of THINGS
that are not derivations can only be substituted and not built locally.
Return #t on success."
      (if (>= (nix-server-minor-version store) 15)
          (build store things mode)
          (if (= mode (build-mode normal))
              (build/old store things)
              (raise (condition (&nix-protocol-error
                                 (message "unsupported build mode")
                                 (status  1)))))))))

(define-operation (add-temp-root (store-path path))
  "Make PATH a temporary root for the duration of the current session.
Return #t."
  boolean)

(define-operation (add-indirect-root (string file-name))
  "Make the symlink FILE-NAME an indirect root for the garbage collector:
whatever store item FILE-NAME points to will not be collected.  Return #t on
success.

FILE-NAME can be anywhere on the file system, but it must be an absolute file
name--it is the caller's responsibility to ensure that it is an absolute file
name."
  boolean)

(define %gc-roots-directory
  ;; The place where garbage collector roots (symlinks) are kept.
  (string-append %state-directory "/gcroots"))

(define (add-permanent-root target)
  "Add a garbage collector root pointing to TARGET, an element of the store,
preventing TARGET from even being collected.  This can also be used if TARGET
does not exist yet.

Raise an error if the caller does not have write access to the GC root
directory."
  (let* ((root (string-append %gc-roots-directory "/" (basename target))))
    (catch 'system-error
      (lambda ()
        (symlink target root))
      (lambda args
        ;; If ROOT already exists, this is fine; otherwise, re-throw.
        (unless (= EEXIST (system-error-errno args))
          (apply throw args))))))

(define (remove-permanent-root target)
  "Remove the permanent garbage collector root pointing to TARGET.  Raise an
error if there is no such root."
  (delete-file (string-append %gc-roots-directory "/" (basename target))))

(define references
  (operation (query-references (store-path path))
             "Return the list of references of PATH."
             store-path-list))

(define %reference-cache
  ;; Brute-force cache mapping store items to their list of references.
  ;; Caching matters because when building a profile in the presence of
  ;; grafts, we keep calling 'graft-derivation', which in turn calls
  ;; 'references/substitutes' many times with the same arguments.  Ideally we
  ;; would use a cache associated with the daemon connection instead (XXX).
  (make-hash-table 100))

(define (references/substitutes store items)
  "Return the list of list of references of ITEMS; the result has the same
length as ITEMS.  Query substitute information for any item missing from the
store at once.  Raise a '&nix-protocol-error' exception if reference
information for one of ITEMS is missing."
  (let* ((local-refs (map (lambda (item)
                            (or (hash-ref %reference-cache item)
                                (guard (c ((nix-protocol-error? c) #f))
                                  (references store item))))
                          items))
         (missing    (fold-right (lambda (item local-ref result)
                                   (if local-ref
                                       result
                                       (cons item result)))
                                 '()
                                 items local-refs))

         ;; Query all the substitutes at once to minimize the cost of
         ;; launching 'guix substitute' and making HTTP requests.
         (substs     (substitutable-path-info store missing)))
    (when (< (length substs) (length missing))
      (raise (condition (&nix-protocol-error
                         (message "cannot determine \
the list of references")
                         (status 1)))))

    ;; Intersperse SUBSTS and LOCAL-REFS.
    (let loop ((items       items)
               (local-refs  local-refs)
               (result      '()))
      (match items
        (()
         (let ((result (reverse result)))
           (for-each (cut hash-set! %reference-cache <> <>)
                     items result)
           result))
        ((item items ...)
         (match local-refs
           ((#f tail ...)
            (loop items tail
                  (cons (any (lambda (subst)
                               (and (string=? (substitutable-path subst) item)
                                    (substitutable-references subst)))
                             substs)
                        result)))
           ((head tail ...)
            (loop items tail
                  (cons head result)))))))))

(define* (fold-path store proc seed paths
                    #:optional (relatives (cut references store <>)))
  "Call PROC for each of the RELATIVES of PATHS, exactly once, and return the
result formed from the successive calls to PROC, the first of which is passed
SEED."
  (let loop ((paths  paths)
             (result seed)
             (seen   vlist-null))
    (match paths
      ((path rest ...)
       (if (vhash-assoc path seen)
           (loop rest result seen)
           (let ((seen   (vhash-cons path #t seen))
                 (rest   (append rest (relatives path)))
                 (result (proc path result)))
             (loop rest result seen))))
      (()
       result))))

(define (requisites store paths)
  "Return the requisites of PATHS, including PATHS---i.e., their closures (all
its references, recursively)."
  (fold-path store cons '() paths))

(define (topologically-sorted store paths)
  "Return a list containing PATHS and all their references sorted in
topological order."
  (define (traverse)
    ;; Do a simple depth-first traversal of all of PATHS.
    (let loop ((paths   paths)
               (visited vlist-null)
               (result  '()))
      (define (visit n)
        (vhash-cons n #t visited))

      (define (visited? n)
        (vhash-assoc n visited))

      (match paths
        ((head tail ...)
         (if (visited? head)
             (loop tail visited result)
             (call-with-values
                 (lambda ()
                   (loop (references store head)
                         (visit head)
                         result))
               (lambda (visited result)
                 (loop tail
                       visited
                       (cons head result))))))
        (()
         (values visited result)))))

  (call-with-values traverse
    (lambda (_ result)
      (reverse result))))

(define referrers
  (operation (query-referrers (store-path path))
             "Return the list of path that refer to PATH."
             store-path-list))

(define valid-derivers
  (operation (query-valid-derivers (store-path path))
             "Return the list of valid \"derivers\" of PATH---i.e., all the
.drv present in the store that have PATH among their outputs."
             store-path-list))

(define query-derivation-outputs  ; avoid name clash with `derivation-outputs'
  (operation (query-derivation-outputs (store-path path))
             "Return the list of outputs of PATH, a .drv file."
             store-path-list))

(define-operation (has-substitutes? (store-path path))
  "Return #t if binary substitutes are available for PATH, and #f otherwise."
  boolean)

(define substitutable-paths
  (operation (query-substitutable-paths (store-path-list paths))
             "Return the subset of PATHS that is substitutable."
             store-path-list))

(define substitutable-path-info
  (operation (query-substitutable-path-infos (store-path-list paths))
             "Return information about the subset of PATHS that is
substitutable.  For each substitutable path, a `substitutable?' object is
returned; thus, the resulting list can be shorter than PATHS.  Furthermore,
that there is no guarantee that the order of the resulting list matches the
order of PATHS."
             substitutable-path-list))

(define-operation (optimize-store)
  "Optimize the store by hard-linking identical files (\"deduplication\".)
Return #t on success."
  ;; Note: the daemon in Guix <= 0.8.2 does not implement this RPC.
  boolean)

(define verify-store
  (let ((verify (operation (verify-store (boolean check-contents?)
                                         (boolean repair?))
                           "Verify the store."
                           boolean)))
    (lambda* (store #:key check-contents? repair?)
      "Verify the integrity of the store and return false if errors remain,
and true otherwise.  When REPAIR? is true, repair any missing or altered store
items by substituting them (this typically requires root privileges because it
is not an atomic operation.)  When CHECK-CONTENTS? is true, check the contents
of store items; this can take a lot of time."
      (not (verify store check-contents? repair?)))))

(define (run-gc server action to-delete min-freed)
  "Perform the garbage-collector operation ACTION, one of the
`gc-action' values.  When ACTION is `delete-specific', the TO-DELETE is
the list of store paths to delete.  IGNORE-LIVENESS? should always be
#f.  MIN-FREED is the minimum amount of disk space to be freed, in
bytes, before the GC can stop.  Return the list of store paths delete,
and the number of bytes freed."
  (let ((s (nix-server-socket server)))
    (write-int (operation-id collect-garbage) s)
    (write-int action s)
    (write-store-path-list to-delete s)
    (write-arg boolean #f s)                      ; ignore-liveness?
    (write-long-long min-freed s)
    (write-int 0 s)                               ; obsolete
    (when (>= (nix-server-minor-version server) 5)
      ;; Obsolete `use-atime' and `max-atime' parameters.
      (write-int 0 s)
      (write-int 0 s))

    ;; Loop until the server is done sending error output.
    (let loop ((done? (process-stderr server)))
      (or done? (loop (process-stderr server))))

    (let ((paths    (read-store-path-list s))
          (freed    (read-long-long s))
          (obsolete (read-long-long s)))
      (unless (null? paths)
        ;; To be on the safe side, completely invalidate both caches.
        ;; Otherwise we could end up returning store paths that are no longer
        ;; valid.
        (hash-clear! (nix-server-add-to-store-cache server))
        (hash-clear! (nix-server-add-text-to-store-cache server)))

     (values paths freed))))

(define-syntax-rule (%long-long-max)
  ;; Maximum unsigned 64-bit integer.
  (- (expt 2 64) 1))

(define (live-paths server)
  "Return the list of live store paths---i.e., store paths still
referenced, and thus not subject to being garbage-collected."
  (run-gc server (gc-action return-live) '() (%long-long-max)))

(define (dead-paths server)
  "Return the list of dead store paths---i.e., store paths no longer
referenced, and thus subject to being garbage-collected."
  (run-gc server (gc-action return-dead) '() (%long-long-max)))

(define* (collect-garbage server #:optional (min-freed (%long-long-max)))
  "Collect garbage from the store at SERVER.  If MIN-FREED is non-zero,
then collect at least MIN-FREED bytes.  Return the paths that were
collected, and the number of bytes freed."
  (run-gc server (gc-action delete-dead) '() min-freed))

(define* (delete-paths server paths #:optional (min-freed (%long-long-max)))
  "Delete PATHS from the store at SERVER, if they are no longer
referenced.  If MIN-FREED is non-zero, then stop after at least
MIN-FREED bytes have been collected.  Return the paths that were
collected, and the number of bytes freed."
  (run-gc server (gc-action delete-specific) paths min-freed))

(define (import-paths server port)
  "Import the set of store paths read from PORT into SERVER's store.  An error
is raised if the set of paths read from PORT is not signed (as per
'export-path #:sign? #t'.)  Return the list of store paths imported."
  (let ((s (nix-server-socket server)))
    (write-int (operation-id import-paths) s)
    (let loop ((done? (process-stderr server port)))
      (or done? (loop (process-stderr server port))))
    (read-store-path-list s)))

(define* (export-path server path port #:key (sign? #t))
  "Export PATH to PORT.  When SIGN? is true, sign it."
  (let ((s (nix-server-socket server)))
    (write-int (operation-id export-path) s)
    (write-store-path path s)
    (write-arg boolean sign? s)
    (let loop ((done? (process-stderr server port)))
      (or done? (loop (process-stderr server port))))
    (= 1 (read-int s))))

(define* (export-paths server paths port #:key (sign? #t) recursive?)
  "Export the store paths listed in PATHS to PORT, in topological order,
signing them if SIGN? is true.  When RECURSIVE? is true, export the closure of
PATHS---i.e., PATHS and all their dependencies."
  (define ordered
    (let ((sorted (topologically-sorted server paths)))
      ;; When RECURSIVE? is #f, filter out the references of PATHS.
      (if recursive?
          sorted
          (filter (cut member <> paths) sorted))))

  (let loop ((paths ordered))
    (match paths
      (()
       (write-int 0 port))
      ((head tail ...)
       (write-int 1 port)
       (and (export-path server head port #:sign? sign?)
            (loop tail))))))

(define-operation (query-failed-paths)
  "Return the list of store items for which a build failure is cached.

The result is always the empty list unless the daemon was started with
'--cache-failures'."
  store-path-list)

(define-operation (clear-failed-paths (store-path-list items))
  "Remove ITEMS from the list of cached build failures.

This makes sense only when the daemon was started with '--cache-failures'."
  boolean)

(define* (register-path path
                        #:key (references '()) deriver prefix
                        state-directory)
  "Register PATH as a valid store file, with REFERENCES as its list of
references, and DERIVER as its deriver (.drv that led to it.)  If PREFIX is
not #f, it must be the name of the directory containing the new store to
initialize; if STATE-DIRECTORY is not #f, it must be a string containing the
absolute file name to the state directory of the store being initialized.
Return #t on success.

Use with care as it directly modifies the store!  This is primarily meant to
be used internally by the daemon's build hook."
  ;; Currently this is implemented by calling out to the fine C++ blob.
  (let ((pipe (apply open-pipe* OPEN_WRITE %guix-register-program
                     `(,@(if prefix
                             `("--prefix" ,prefix)
                             '())
                       ,@(if state-directory
                             `("--state-directory" ,state-directory)
                             '())))))
    (and pipe
         (begin
           (format pipe "~a~%~a~%~a~%"
                   path (or deriver "") (length references))
           (for-each (cut format pipe "~a~%" <>) references)
           (zero? (close-pipe pipe))))))


;;;
;;; Store monad.
;;;

(define-syntax-rule (define-alias new old)
  (define-syntax new (identifier-syntax old)))

;; The store monad allows us to (1) build sequences of operations in the
;; store, and (2) make the store an implicit part of the execution context,
;; rather than a parameter of every single function.
(define-alias %store-monad %state-monad)
(define-alias store-return state-return)
(define-alias store-bind state-bind)

(define (preserve-documentation original proc)
  "Return PROC with documentation taken from ORIGINAL."
  (set-object-property! proc 'documentation
                        (procedure-property original 'documentation))
  proc)

(define (store-lift proc)
  "Lift PROC, a procedure whose first argument is a connection to the store,
in the store monad."
  (preserve-documentation proc
                          (lambda args
                            (lambda (store)
                              (values (apply proc store args) store)))))

(define (store-lower proc)
  "Lower PROC, a monadic procedure in %STORE-MONAD, to a \"normal\" procedure
taking the store as its first argument."
  (preserve-documentation proc
                          (lambda (store . args)
                            (run-with-store store (apply proc args)))))

;;
;; Store monad operators.
;;

(define* (text-file name text
                    #:optional (references '()))
  "Return as a monadic value the absolute file name in the store of the file
containing TEXT, a string.  REFERENCES is a list of store items that the
resulting text file refers to; it defaults to the empty list."
  (lambda (store)
    (values (add-text-to-store store name text references)
            store)))

(define* (interned-file file #:optional name
                        #:key (recursive? #t) (select? true))
  "Return the name of FILE once interned in the store.  Use NAME as its store
name, or the basename of FILE if NAME is omitted.

When RECURSIVE? is true, the contents of FILE are added recursively; if FILE
designates a flat file and RECURSIVE? is true, its contents are added, and its
permission bits are kept.

When RECURSIVE? is true, call (SELECT?  FILE STAT) for each directory entry,
where FILE is the entry's absolute file name and STAT is the result of
'lstat'; exclude entries for which SELECT? does not return true."
  (lambda (store)
    (values (add-to-store store (or name (basename file))
                          recursive? "sha256" file
                          #:select? select?)
            store)))

(define build
  ;; Monadic variant of 'build-things'.
  (store-lift build-things))

(define set-build-options*
  (store-lift set-build-options))

(define-inlinable (current-system)
  ;; Consult the %CURRENT-SYSTEM fluid at bind time.  This is equivalent to
  ;; (lift0 %current-system %store-monad), but inlinable, thus avoiding
  ;; closure allocation in some cases.
  (lambda (state)
    (values (%current-system) state)))

(define-inlinable (set-current-system system)
  ;; Set the %CURRENT-SYSTEM fluid at bind time.
  (lambda (state)
    (values (%current-system system) state)))

(define %guile-for-build
  ;; The derivation of the Guile to be used within the build environment,
  ;; when using 'gexp->derivation' and co.
  (make-parameter #f))

(define* (run-with-store store mval
                         #:key
                         (guile-for-build (%guile-for-build))
                         (system (%current-system)))
  "Run MVAL, a monadic value in the store monad, in STORE, an open store
connection, and return the result."
  ;; Initialize the dynamic bindings here to avoid bad surprises.  The
  ;; difficulty lies in the fact that dynamic bindings are resolved at
  ;; bind-time and not at call time, which can be disconcerting.
  (parameterize ((%guile-for-build guile-for-build)
                 (%current-system system)
                 (%current-target-system #f))
    (call-with-values (lambda ()
                        (run-with-state mval store))
      (lambda (result store)
        ;; Discard the state.
        result))))


;;;
;;; Store paths.
;;;

(define %store-prefix
  ;; Absolute path to the Nix store.
  (make-parameter %store-directory))

(define (store-path? path)
  "Return #t if PATH is a store path."
  ;; This is a lightweight check, compared to using a regexp, but this has to
  ;; be fast as it's called often in `derivation', for instance.
  ;; `isStorePath' in Nix does something similar.
  (string-prefix? (%store-prefix) path))

(define (direct-store-path? path)
  "Return #t if PATH is a store path, and not a sub-directory of a store path.
This predicate is sometimes needed because files *under* a store path are not
valid inputs."
  (and (store-path? path)
       (not (string=? path (%store-prefix)))
       (let ((len (+ 1 (string-length (%store-prefix)))))
         (not (string-index (substring path len) #\/)))))

(define (direct-store-path path)
  "Return the direct store path part of PATH, stripping components after
'/gnu/store/xxxx-foo'."
  (let ((prefix-length (+ (string-length (%store-prefix)) 35)))
    (if (> (string-length path) prefix-length)
        (let ((slash (string-index path #\/ prefix-length)))
          (if slash (string-take path slash) path))
        path)))

(define (derivation-path? path)
  "Return #t if PATH is a derivation path."
  (and (store-path? path) (string-suffix? ".drv" path)))

(define store-regexp*
  ;; The substituter makes repeated calls to 'store-path-hash-part', hence
  ;; this optimization.
  (memoize
   (lambda (store)
     "Return a regexp matching a file in STORE."
     (make-regexp (string-append "^" (regexp-quote store)
                                 "/([0-9a-df-np-sv-z]{32})-([^/]+)$")))))

(define (store-path-package-name path)
  "Return the package name part of PATH, a file name in the store."
  (let ((path-rx (store-regexp* (%store-prefix))))
    (and=> (regexp-exec path-rx path)
           (cut match:substring <> 2))))

(define (store-path-hash-part path)
  "Return the hash part of PATH as a base32 string, or #f if PATH is not a
syntactically valid store path."
  (let ((path-rx (store-regexp* (%store-prefix))))
    (and=> (regexp-exec path-rx path)
           (cut match:substring <> 1))))

(define (log-file store file)
  "Return the build log file for FILE, or #f if none could be found.  FILE
must be an absolute store file name, or a derivation file name."
  (cond ((derivation-path? file)
         (let* ((base    (basename file))
                (log     (string-append (dirname %state-directory) ; XXX
                                        "/log/guix/drvs/"
                                        (string-take base 2) "/"
                                        (string-drop base 2)))
                (log.bz2 (string-append log ".bz2")))
           (cond ((file-exists? log.bz2) log.bz2)
                 ((file-exists? log) log)
                 (else #f))))
        (else
         (match (valid-derivers store file)
           ((derivers ...)
            ;; Return the first that works.
            (any (cut log-file store <>) derivers))
           (_ #f)))))
