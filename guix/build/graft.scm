;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Mark H Weaver <mhw@netris.org>
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

(define-module (guix build graft)
  #:use-module (guix build utils)
  #:use-module (rnrs bytevectors)
  #:use-module (rnrs io ports)
  #:use-module (ice-9 vlist)
  #:use-module (ice-9 match)
  #:use-module (ice-9 threads)
  #:use-module (ice-9 binary-ports)
  #:use-module (srfi srfi-1)   ; list library
  #:use-module (srfi srfi-26)  ; cut and cute
  #:export (replace-store-references
            rewrite-directory))

;;; Commentary:
;;;
;;; This module supports "grafts".  Grafting a directory means rewriting it,
;;; with references to some specific items replaced by references to other
;;; store items---the grafts.
;;;
;;; This method is used to provide fast security updates as only the leaves of
;;; the dependency graph need to be grafted, even when the security updates
;;; affect a core component such as Bash or libc.  It is based on the idea of
;;; 'replace-dependency' implemented by Shea Levy in Nixpkgs.
;;;
;;; Code:

(define-syntax-rule (define-inline name val)
  (define-syntax name (identifier-syntax val)))

(define-inline hash-length 32)

(define nix-base32-char?
  (cute char-set-contains?
        ;; ASCII digits and lower case letters except e o t u
        (string->char-set "0123456789abcdfghijklmnpqrsvwxyz")
        <>))

(define* (replace-store-references input output replacement-table
                                   #:optional (store (%store-directory)))
  "Read data from INPUT, replacing store references according to
REPLACEMENT-TABLE, and writing the result to OUTPUT.  REPLACEMENT-TABLE is a
vhash that maps strings (original hashes) to bytevectors (replacement hashes).
Note: We use string keys to work around the fact that guile-2.0 hashes all
bytevectors to the same value."

  (define (lookup-replacement s)
    (match (vhash-assoc s replacement-table)
      ((origin . replacement)
       replacement)
      (#f #f)))

  (define (optimize-u8-predicate pred)
    (cute vector-ref
          (list->vector (map pred (iota 256)))
          <>))

  (define nix-base32-byte?
    (optimize-u8-predicate
     (compose nix-base32-char?
              integer->char)))

  (define (dash? byte) (= byte 45))

  (define request-size (expt 2 20))  ; 1 MiB

  ;; We scan the file for the following 33-byte pattern: 32 bytes of
  ;; nix-base32 characters followed by a dash.  To accommodate large files,
  ;; we do not read the entire file, but instead work on buffers of up to
  ;; 'request-size' bytes.  To ensure that every 33-byte sequence appears
  ;; entirely within exactly one buffer, adjacent buffers must overlap,
  ;; i.e. they must share 32 byte positions.  We accomplish this by
  ;; "ungetting" the last 32 bytes of each buffer before reading the next
  ;; buffer, unless we know that we've reached the end-of-file.
  (let ((buffer (make-bytevector request-size)))
    (let loop ()
      ;; Note: We avoid 'get-bytevector-n' to work around
      ;; <http://bugs.gnu.org/17466>.
      (match (get-bytevector-n! input buffer 0 request-size)
        ((? eof-object?) 'done)
        (end
         ;; We scan the buffer for dashes that might be preceded by a
         ;; nix-base32 hash.  The key optimization here is that whenever we
         ;; find a NON-nix-base32 character at position 'i', we know that it
         ;; cannot be part of a hash, so the earliest position where the next
         ;; hash could start is i+1 with the following dash at position i+33.
         ;;
         ;; Since nix-base32 characters comprise only 1/8 of the 256 possible
         ;; byte values, and exclude some of the most common letters in
         ;; English text (e t o u), in practice we can advance by 33 positions
         ;; most of the time.
         (let scan-from ((i hash-length) (written 0))
           ;; 'i' is the first position where we look for a dash.  'written'
           ;; is the number of bytes in the buffer that have already been
           ;; written.
           (if (< i end)
               (let ((byte (bytevector-u8-ref buffer i)))
                 (cond ((and (dash? byte)
                             ;; We've found a dash.  Note that we do not know
                             ;; whether the preceeding 32 bytes are nix-base32
                             ;; characters, but we do not need to know.  If
                             ;; they are not, the following lookup will fail.
                             (lookup-replacement
                              (string-tabulate (lambda (j)
                                                 (integer->char
                                                  (bytevector-u8-ref buffer
                                                   (+ j (- i hash-length)))))
                                               hash-length)))
                        => (lambda (replacement)
                             ;; We've found a hash that needs to be replaced.
                             ;; First, write out all bytes preceding the hash
                             ;; that have not yet been written.
                             (put-bytevector output buffer written
                                             (- i hash-length written))
                             ;; Now write the replacement hash.
                             (put-bytevector output replacement)
                             ;; Since the byte at position 'i' is a dash,
                             ;; which is not a nix-base32 char, the earliest
                             ;; position where the next hash might start is
                             ;; i+1, and the earliest position where the
                             ;; following dash might start is (+ i 1
                             ;; hash-length).  Also, we have now written up to
                             ;; position 'i' in the buffer.
                             (scan-from (+ i 1 hash-length) i)))
                       ;; If the byte at position 'i' is a nix-base32 char,
                       ;; then the dash we're looking for might be as early as
                       ;; the following byte, so we can only advance by 1.
                       ((nix-base32-byte? byte)
                        (scan-from (+ i 1) written))
                       ;; If the byte at position 'i' is NOT a nix-base32
                       ;; char, then the earliest position where the next hash
                       ;; might start is i+1, with the following dash at
                       ;; position (+ i 1 hash-length).
                       (else
                        (scan-from (+ i 1 hash-length) written))))

               ;; We have finished scanning the buffer.  Now we determine how
               ;; many bytes have not yet been written, and how many bytes to
               ;; "unget".  If 'end' is less than 'request-size' then we read
               ;; less than we asked for, which indicates that we are at EOF,
               ;; so we needn't unget anything.  Otherwise, we unget up to
               ;; 'hash-length' bytes (32 bytes).  However, we must be careful
               ;; not to unget bytes that have already been written, because
               ;; that would cause them to be written again from the next
               ;; buffer.  In practice, this case occurs when a replacement is
               ;; made near the end of the buffer.
               (let* ((unwritten   (- end written))
                      (unget-size  (if (= end request-size)
                                       (min hash-length unwritten)
                                       0))
                      (write-size  (- unwritten unget-size)))
                 (put-bytevector output buffer written write-size)
                 (unget-bytevector input buffer (+ written write-size)
                                   unget-size)
                 (loop)))))))))

(define (rename-matching-files directory mapping)
  "Apply MAPPING to the names of all the files in DIRECTORY, where MAPPING is
a list of store file name pairs."
  (let* ((mapping (map (match-lambda
                        ((source . target)
                         (cons (basename source) (basename target))))
                       mapping))
         (matches (find-files directory
                              (lambda (file stat)
                                (assoc-ref mapping (basename file)))
                              #:directories? #t)))

    ;; XXX: This is not quite correct: if MAPPING contains "foo", and
    ;; DIRECTORY contains "bar/foo/foo", we first rename "bar/foo" and then
    ;; "bar/foo/foo" no longer exists so we fail.  Oh well, surely that's good
    ;; enough!
    (for-each (lambda (file)
                (let ((target (assoc-ref mapping (basename file))))
                  (rename-file file
                               (string-append (dirname file) "/" target))))
              matches)))

(define (exit-on-exception proc)
  "Return a procedure that wraps PROC so that 'primitive-exit' is called when
an exception is caught."
  (lambda (arg)
    (catch #t
      (lambda ()
        (proc arg))
      (lambda (key . args)
        ;; Since ports are not thread-safe as of Guile 2.0, reopen stderr.
        (let ((port (fdopen 2 "w0")))
          (print-exception port #f key args)
          (primitive-exit 1))))))

(define* (rewrite-directory directory output mapping
                            #:optional (store (%store-directory)))
  "Copy DIRECTORY to OUTPUT, replacing strings according to MAPPING, a list of
file name pairs."

  (define hash-mapping
    (let* ((prefix (string-append store "/"))
           (start  (string-length prefix))
           (end    (+ start hash-length)))
      (define (valid-hash? h)
        (every nix-base32-char? (string->list h)))
      (define (valid-suffix? s)
        (string-prefix? "-" s))
      (define (hash+suffix s)
        (and (< end (string-length s))
             (let ((hash   (substring s start end))
                   (suffix (substring s end)))
               (and (string-prefix? prefix s)
                    (valid-hash?    hash)
                    (valid-suffix?  suffix)
                    (list hash suffix)))))
      (map (match-lambda
             (((= hash+suffix (origin-hash      suffix))
               .
               (= hash+suffix (replacement-hash suffix)))
              (cons origin-hash (string->utf8 replacement-hash)))
             ((origin . replacement)
              (error "invalid replacement" origin replacement)))
           mapping)))

  (define replacement-table
    (alist->vhash hash-mapping))

  (define prefix-len
    (string-length directory))

  (define (destination file)
    (string-append output (string-drop file prefix-len)))

  (define (rewrite-leaf file)
    (let ((stat (lstat file))
          (dest (destination file)))
      (mkdir-p (dirname dest))
      (case (stat:type stat)
        ((symlink)
         (let ((target (readlink file)))
           (symlink (call-with-output-string
                      (lambda (output)
                        (replace-store-references (open-input-string target)
                                                  output replacement-table
                                                  store)))
                    dest)))
        ((regular)
         (call-with-input-file file
           (lambda (input)
             (call-with-output-file dest
               (lambda (output)
                 (replace-store-references input output replacement-table
                                           store)
                 (chmod output (stat:perms stat)))))))
        ((directory)
         (mkdir-p dest))
        (else
         (error "unsupported file type" stat)))))

  ;; XXX: Work around occasional "suspicious ownership or permission" daemon
  ;; errors that arise when we create the top-level /gnu/store/… directory as
  ;; #o777.
  (umask #o022)

  ;; Use 'exit-on-exception' to force an exit upon I/O errors, given that
  ;; 'n-par-for-each' silently swallows exceptions.
  ;; See <http://bugs.gnu.org/23581>.
  (n-par-for-each (parallel-job-count)
                  (exit-on-exception rewrite-leaf)
                  (find-files directory (const #t)
                              #:directories? #t))
  (rename-matching-files output mapping))

;;; graft.scm ends here
