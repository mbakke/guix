;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016 Ludovic Courtès <ludo@gnu.org>
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

(define-module (guix zlib)
  #:use-module (rnrs bytevectors)
  #:use-module (ice-9 binary-ports)
  #:use-module (ice-9 match)
  #:use-module (system foreign)
  #:use-module (guix config)
  #:export (zlib-available?
            make-gzip-input-port
            make-gzip-output-port
            call-with-gzip-input-port
            call-with-gzip-output-port
            %default-buffer-size
            %default-compression-level))

;;; Commentary:
;;;
;;; Bindings to the gzip-related part of zlib's API.  The main limitation of
;;; this API is that it requires a file descriptor as the source or sink.
;;;
;;; Code:

(define %zlib
  ;; File name of zlib's shared library.  When updating via 'guix pull',
  ;; '%libz' might be undefined so protect against it.
  (delay (dynamic-link (if (defined? '%libz)
                           %libz
                           "libz"))))

(define (zlib-available?)
  "Return true if zlib is available, #f otherwise."
  (false-if-exception (force %zlib)))

(define (zlib-procedure ret name parameters)
  "Return a procedure corresponding to C function NAME in libz, or #f if
either zlib or the function could not be found."
  (match (false-if-exception (dynamic-func name (force %zlib)))
    ((? pointer? ptr)
     (pointer->procedure ret ptr parameters))
    (#f
     #f)))

(define-wrapped-pointer-type <gzip-file>
  ;; Scheme counterpart of the 'gzFile' opaque type.
  gzip-file?
  pointer->gzip-file
  gzip-file->pointer
  (lambda (obj port)
    (format port "#<gzip-file ~a>"
            (number->string (object-address obj) 16))))

(define gzerror
  (let ((proc (zlib-procedure '* "gzerror" '(* *))))
    (lambda (gzfile)
      (let* ((errnum* (make-bytevector (sizeof int)))
             (ptr     (proc (gzip-file->pointer gzfile)
                            (bytevector->pointer errnum*))))
        (values (bytevector-sint-ref errnum* 0
                                     (native-endianness) (sizeof int))
                (pointer->string ptr))))))

(define gzdopen
  (let ((proc (zlib-procedure '* "gzdopen" (list int '*))))
    (lambda (fd mode)
      "Open file descriptor FD as a gzip stream with the given MODE.  MODE must
be a string denoting the how FD is to be opened, such as \"r\" for reading or
\"w9\" for writing data compressed at level 9 to FD.  Calling 'gzclose' also
closes FD."
      (let ((result (proc fd (string->pointer mode))))
        (if (null-pointer? result)
            (throw 'zlib-error 'gzdopen)
            (pointer->gzip-file result))))))

(define gzread!
  (let ((proc (zlib-procedure int "gzread" (list '* '* unsigned-int))))
    (lambda* (gzfile bv #:optional (start 0) (count (bytevector-length bv)))
      "Read up to COUNT bytes from GZFILE into BV at offset START.  Return the
number of uncompressed bytes actually read; it is zero if COUNT is zero or if
the end-of-stream has been reached."
      (let ((ret (proc (gzip-file->pointer gzfile)
                       (bytevector->pointer bv start)
                       count)))
        (if (< ret 0)
            (throw 'zlib-error 'gzread! ret)
            ret)))))

(define gzwrite
  (let ((proc (zlib-procedure int "gzwrite" (list '* '* unsigned-int))))
    (lambda* (gzfile bv #:optional (start 0) (count (bytevector-length bv)))
      "Write up to COUNT bytes from BV at offset START into GZFILE.  Return
the number of uncompressed bytes written, a strictly positive integer."
      (let ((ret (proc (gzip-file->pointer gzfile)
                       (bytevector->pointer bv start)
                       count)))
        (if (<= ret 0)
            (throw 'zlib-error 'gzwrite ret)
            ret)))))

(define gzbuffer!
  (let ((proc (zlib-procedure int "gzbuffer" (list '* unsigned-int))))
    (lambda (gzfile size)
      "Change the internal buffer size of GZFILE to SIZE bytes."
      (let ((ret (proc (gzip-file->pointer gzfile) size)))
        (unless (zero? ret)
          (throw 'zlib-error 'gzbuffer! ret))))))

(define gzeof?
  (let ((proc (zlib-procedure int "gzeof" '(*))))
    (lambda (gzfile)
      "Return true if the end-of-file has been reached on GZFILE."
      (not (zero? (proc (gzip-file->pointer gzfile)))))))

(define gzclose
  (let ((proc (zlib-procedure int "gzclose" '(*))))
    (lambda (gzfile)
      "Close GZFILE."
      (let ((ret (proc (gzip-file->pointer gzfile))))
        (unless (zero? ret)
          (throw 'zlib-error 'gzclose ret (gzerror gzfile)))))))



;;;
;;; Port interface.
;;;

(define %default-buffer-size
  ;; Default buffer size, as documented in <zlib.h>.
  8192)

(define %default-compression-level
  ;; Z_DEFAULT_COMPRESSION.
  -1)

(define (close-procedure gzfile port)
  "Return a procedure that closes GZFILE, ensuring its underlying PORT is
closed even if closing GZFILE triggers an exception."
  (lambda ()
    (catch 'zlib-error
      (lambda ()
        ;; 'gzclose' closes the underlying file descriptor.  'close-port'
        ;; calls close(2), gets EBADF, which is ignores.
        (gzclose gzfile)
        (close-port port))
      (lambda args
        ;; Make sure PORT is closed despite the zlib error.
        (close-port port)
        (apply throw args)))))

(define* (make-gzip-input-port port #:key (buffer-size %default-buffer-size))
  "Return an input port that decompresses data read from PORT, a file port.
PORT is automatically closed when the resulting port is closed.  BUFFER-SIZE
is the size in bytes of the internal buffer, 8 KiB by default; using a larger
buffer increases decompression speed.  An error is thrown if PORT contains
buffered input, which would be lost (and is lost anyway)."
  (define gzfile
    (match (drain-input port)
      (""                                         ;PORT's buffer is empty
       (gzdopen (fileno port) "r"))
      (_
       ;; This is unrecoverable but it's better than having the buffered input
       ;; be lost, leading to unclear end-of-file or corrupt-data errors down
       ;; the path.
       (throw 'zlib-error 'make-gzip-input-port
              "port contains buffered input" port))))

  (define (read! bv start count)
    (gzread! gzfile bv start count))

  (unless (= buffer-size %default-buffer-size)
    (gzbuffer! gzfile buffer-size))

  (make-custom-binary-input-port "gzip-input" read! #f #f
                                 (close-procedure gzfile port)))

(define* (make-gzip-output-port port
                                #:key
                                (level %default-compression-level)
                                (buffer-size %default-buffer-size))
  "Return an output port that compresses data at the given LEVEL, using PORT,
a file port, as its sink.  PORT is automatically closed when the resulting
port is closed."
  (define gzfile
    (begin
      (force-output port)                         ;empty PORT's buffer
      (gzdopen (fileno port)
               (string-append "w" (number->string level)))))

  (define (write! bv start count)
    (gzwrite gzfile bv start count))

  (unless (= buffer-size %default-buffer-size)
    (gzbuffer! gzfile buffer-size))

  (make-custom-binary-output-port "gzip-output" write! #f #f
                                  (close-procedure gzfile port)))

(define* (call-with-gzip-input-port port proc
                                    #:key (buffer-size %default-buffer-size))
  "Call PROC with a port that wraps PORT and decompresses data read from it.
PORT is closed upon completion.  The gzip internal buffer size is set to
BUFFER-SIZE bytes."
  (let ((gzip (make-gzip-input-port port #:buffer-size buffer-size)))
    (dynamic-wind
      (const #t)
      (lambda ()
        (proc gzip))
      (lambda ()
        (close-port gzip)))))

(define* (call-with-gzip-output-port port proc
                                     #:key
                                     (level %default-compression-level)
                                     (buffer-size %default-buffer-size))
  "Call PROC with an output port that wraps PORT and compresses data.  PORT is
close upon completion.  The gzip internal buffer size is set to BUFFER-SIZE
bytes."
  (let ((gzip (make-gzip-output-port port
                                     #:level level
                                     #:buffer-size buffer-size)))
    (dynamic-wind
      (const #t)
      (lambda ()
        (proc gzip))
      (lambda ()
        (close-port gzip)))))

;;; zlib.scm ends here
