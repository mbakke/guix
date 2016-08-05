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

(define-module (guix build gnu-build-system)
  #:use-module (guix build utils)
  #:use-module (guix build gremlin)
  #:use-module (guix elf)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-19)
  #:use-module (srfi srfi-26)
  #:use-module (rnrs io ports)
  #:export (%standard-phases
            gnu-build))

;; Commentary:
;;
;; Standard build procedure for packages using the GNU Build System or
;; something compatible ("./configure && make && make install").  This is the
;; builder-side code.
;;
;; Code:

(define* (set-SOURCE-DATE-EPOCH #:rest _)
  "Set the 'SOURCE_DATE_EPOCH' environment variable.  This is used by tools
that incorporate timestamps as a way to tell them to use a fixed timestamp.
See https://reproducible-builds.org/specs/source-date-epoch/."
  (setenv "SOURCE_DATE_EPOCH" "1")
  #t)

(define (first-subdirectory dir)
  "Return the path of the first sub-directory of DIR."
  (file-system-fold (lambda (path stat result)
                      (string=? path dir))
                    (lambda (path stat result) result) ; leaf
                    (lambda (path stat result) result) ; down
                    (lambda (path stat result) result) ; up
                    (lambda (path stat result)         ; skip
                      (or result path))
                    (lambda (path stat errno result)   ; error
                      (error "first-subdirectory" (strerror errno)))
                    #f
                    dir))

(define* (set-paths #:key target inputs native-inputs
                    (search-paths '()) (native-search-paths '())
                    #:allow-other-keys)
  (define input-directories
    (match inputs
      (((_ . dir) ...)
       dir)))

  (define native-input-directories
    (match native-inputs
      (((_ . dir) ...)
       dir)
      (#f                                         ; not cross compiling
       '())))

  ;; When cross building, $PATH must refer only to native (host) inputs since
  ;; target inputs are not executable.
  (set-path-environment-variable "PATH" '("bin" "sbin")
                                 (append native-input-directories
                                         (if target
                                             '()
                                             input-directories)))

  (for-each (match-lambda
             ((env-var (files ...) separator type pattern)
              (set-path-environment-variable env-var files
                                             input-directories
                                             #:separator separator
                                             #:type type
                                             #:pattern pattern)))
            search-paths)

  (when native-search-paths
    ;; Search paths for native inputs, when cross building.
    (for-each (match-lambda
               ((env-var (files ...) separator type pattern)
                (set-path-environment-variable env-var files
                                               native-input-directories
                                               #:separator separator
                                               #:type type
                                               #:pattern pattern)))
              native-search-paths))

  #t)

(define* (install-locale #:key
                         (locale "en_US.utf8")
                         (locale-category LC_ALL)
                         #:allow-other-keys)
  "Try to install LOCALE; emit a warning if that fails.  The main goal is to
use a UTF-8 locale so that Guile correctly interprets UTF-8 file names.

This phase must typically happen after 'set-paths' so that $LOCPATH has a
chance to be set."
  (catch 'system-error
    (lambda ()
      (setlocale locale-category locale)

      ;; While we're at it, pass it to sub-processes.
      (setenv (locale-category->string locale-category) locale)

      (format (current-error-port) "using '~a' locale for category ~s~%"
              locale (locale-category->string locale-category))
      #t)
    (lambda args
      ;; This is known to fail for instance in early bootstrap where locales
      ;; are not available.
      (format (current-error-port)
              "warning: failed to install '~a' locale: ~a~%"
              locale (strerror (system-error-errno args)))
      #t)))

(define* (unpack #:key source #:allow-other-keys)
  "Unpack SOURCE in the working directory, and change directory within the
source.  When SOURCE is a directory, copy it in a sub-directory of the current
working directory."
  (if (file-is-directory? source)
      (begin
        (mkdir "source")
        (chdir "source")

        ;; Preserve timestamps (set to the Epoch) on the copied tree so that
        ;; things work deterministically.
        (copy-recursively source "."
                          #:keep-mtime? #t)
        #t)
      (and (if (string-suffix? ".zip" source)
               (zero? (system* "unzip" source))
               (zero? (system* "tar" "xvf" source)))
           (chdir (first-subdirectory ".")))))

;; See <http://bugs.gnu.org/17840>.
(define* (patch-usr-bin-file #:key native-inputs inputs
                             (patch-/usr/bin/file? #t)
                             #:allow-other-keys)
  "Patch occurrences of \"/usr/bin/file\" in all the executable 'configure'
files found in the source tree.  This works around Libtool's Autoconf macros,
which generates invocations of \"/usr/bin/file\" that are used to determine
things like the ABI being used."
  (when patch-/usr/bin/file?
    (for-each (lambda (file)
                (when (executable-file? file)
                  (patch-/usr/bin/file file)))
              (find-files "." "^configure$")))
  #t)

(define* (patch-source-shebangs #:key source #:allow-other-keys)
  "Patch shebangs in all source files; this includes non-executable
files such as `.in' templates.  Most scripts honor $SHELL and
$CONFIG_SHELL, but some don't, such as `mkinstalldirs' or Automake's
`missing' script."
  (for-each patch-shebang
            (remove (lambda (file)
                      (or (not (file-exists? file)) ;dangling symlink
                          (file-is-directory? file)))
                    (find-files "."))))

(define (patch-generated-file-shebangs . rest)
  "Patch shebangs in generated files, including `SHELL' variables in
makefiles."
  ;; Patch executable files, some of which might have been generated by
  ;; `configure'.
  (for-each patch-shebang
            (filter (lambda (file)
                      (and (file-exists? file)
                           (executable-file? file)
                           (not (file-is-directory? file))))
                    (find-files ".")))

  ;; Patch `SHELL' in generated makefiles.
  (for-each patch-makefile-SHELL (find-files "." "^(GNU)?[mM]akefile$")))

(define* (configure #:key build target native-inputs inputs outputs
                    (configure-flags '()) out-of-source?
                    #:allow-other-keys)
  (define (package-name)
    (let* ((out  (assoc-ref outputs "out"))
           (base (basename out))
           (dash (string-rindex base #\-)))
      ;; XXX: We'd rather use `package-name->name+version' or similar.
      (string-drop (if dash
                       (substring base 0 dash)
                       base)
                   (+ 1 (string-index base #\-)))))

  (let* ((prefix     (assoc-ref outputs "out"))
         (bindir     (assoc-ref outputs "bin"))
         (libdir     (assoc-ref outputs "lib"))
         (includedir (assoc-ref outputs "include"))
         (docdir     (assoc-ref outputs "doc"))
         (bash       (or (and=> (assoc-ref (or native-inputs inputs) "bash")
                                (cut string-append <> "/bin/bash"))
                         "/bin/sh"))
         (flags      `(,@(if target             ; cross building
                             '("CC_FOR_BUILD=gcc")
                             '())
                       ,(string-append "CONFIG_SHELL=" bash)
                       ,(string-append "SHELL=" bash)
                       ,(string-append "--prefix=" prefix)
                       "--enable-fast-install"    ; when using Libtool

                       ;; Produce multiple outputs when specific output names
                       ;; are recognized.
                       ,@(if bindir
                              (list (string-append "--bindir=" bindir "/bin"))
                              '())
                       ,@(if libdir
                              (cons (string-append "--libdir=" libdir "/lib")
                                    (if includedir
                                        '()
                                        (list
                                         (string-append "--includedir="
                                                        libdir "/include"))))
                              '())
                       ,@(if includedir
                             (list (string-append "--includedir="
                                                  includedir "/include"))
                             '())
                       ,@(if docdir
                             (list (string-append "--docdir=" docdir
                                                  "/share/doc/" (package-name)))
                             '())
                       ,@(if build
                             (list (string-append "--build=" build))
                             '())
                       ,@(if target               ; cross building
                             (list (string-append "--host=" target))
                             '())
                       ,@configure-flags))
         (abs-srcdir (getcwd))
         (srcdir     (if out-of-source?
                         (string-append "../" (basename abs-srcdir))
                         ".")))
    (format #t "source directory: ~s (relative from build: ~s)~%"
            abs-srcdir srcdir)
    (if out-of-source?
        (begin
          (mkdir "../build")
          (chdir "../build")))
    (format #t "build directory: ~s~%" (getcwd))
    (format #t "configure flags: ~s~%" flags)

    ;; Use BASH to reduce reliance on /bin/sh since it may not always be
    ;; reliable (see
    ;; <http://thread.gmane.org/gmane.linux.distributions.nixos/9748>
    ;; for a summary of the situation.)
    ;;
    ;; Call `configure' with a relative path.  Otherwise, GCC's build system
    ;; (for instance) records absolute source file names, which typically
    ;; contain the hash part of the `.drv' file, leading to a reference leak.
    (zero? (apply system* bash
                  (string-append srcdir "/configure")
                  flags))))

(define* (build #:key (make-flags '()) (parallel-build? #t)
                #:allow-other-keys)
  (zero? (apply system* "make"
                `(,@(if parallel-build?
                        `("-j" ,(number->string (parallel-job-count)))
                        '())
                  ,@make-flags))))

(define* (check #:key target (make-flags '()) (tests? (not target))
                (test-target "check") (parallel-tests? #t)
                #:allow-other-keys)
  (if tests?
      (zero? (apply system* "make" test-target
                    `(,@(if parallel-tests?
                            `("-j" ,(number->string (parallel-job-count)))
                            '())
                      ,@make-flags)))
      (begin
        (format #t "test suite not run~%")
        #t)))

(define* (install #:key (make-flags '()) #:allow-other-keys)
  (zero? (apply system* "make" "install" make-flags)))

(define* (patch-shebangs #:key inputs outputs (patch-shebangs? #t)
                         #:allow-other-keys)
  (define (list-of-files dir)
    (map (cut string-append dir "/" <>)
         (or (scandir dir (lambda (f)
                            (let ((s (lstat (string-append dir "/" f))))
                              (eq? 'regular (stat:type s)))))
             '())))

  (define bin-directories
    (match-lambda
     ((_ . dir)
      (list (string-append dir "/bin")
            (string-append dir "/sbin")))))

  (define output-bindirs
    (append-map bin-directories outputs))

  (define input-bindirs
    ;; Shebangs should refer to binaries of the target system---i.e., from
    ;; "inputs", not from "native-inputs".
    (append-map bin-directories inputs))

  (when patch-shebangs?
    (let ((path (append output-bindirs input-bindirs)))
      (for-each (lambda (dir)
                  (let ((files (list-of-files dir)))
                    (for-each (cut patch-shebang <> path) files)))
                output-bindirs)))
  #t)

(define* (strip #:key target outputs (strip-binaries? #t)
                (strip-command (if target
                                   (string-append target "-strip")
                                   "strip"))
                (objcopy-command (if target
                                     (string-append target "-objcopy")
                                     "objcopy"))
                (strip-flags '("--strip-debug"
                               "--enable-deterministic-archives"))
                (strip-directories '("lib" "lib64" "libexec"
                                     "bin" "sbin"))
                #:allow-other-keys)
  (define debug-output
    ;; If an output is called "debug", then that's where debugging information
    ;; will be stored instead of being discarded.
    (assoc-ref outputs "debug"))

  (define debug-file-extension
    ;; File name extension for debugging information.
    ".debug")

  (define (debug-file file)
    ;; Return the name of the debug file for FILE, an absolute file name.
    ;; Once installed in the user's profile, it is in $PROFILE/lib/debug/FILE,
    ;; which is where GDB looks for it (info "(gdb) Separate Debug Files").
    (string-append debug-output "/lib/debug/"
                   file debug-file-extension))

  (define (make-debug-file file)
    ;; Create a file in DEBUG-OUTPUT containing the debugging info of FILE.
    (let ((debug (debug-file file)))
      (mkdir-p (dirname debug))
      (copy-file file debug)
      (and (zero? (system* strip-command "--only-keep-debug" debug))
           (begin
             (chmod debug #o400)
             #t))))

  (define (add-debug-link file)
    ;; Add a debug link in FILE (info "(binutils) strip").

    ;; `objcopy --add-gnu-debuglink' wants to have the target of the debug
    ;; link around so it can compute a CRC of that file (see the
    ;; `bfd_fill_in_gnu_debuglink_section' function.)  No reference to
    ;; DEBUG-OUTPUT is kept because bfd keeps only the basename of the debug
    ;; file.
    (zero? (system* objcopy-command "--enable-deterministic-archives"
                    (string-append "--add-gnu-debuglink="
                                   (debug-file file))
                    file)))

  (define (strip-dir dir)
    (format #t "stripping binaries in ~s with ~s and flags ~s~%"
            dir strip-command strip-flags)
    (when debug-output
      (format #t "debugging output written to ~s using ~s~%"
              debug-output objcopy-command))
    (file-system-fold (const #t)
                      (lambda (path stat result)  ; leaf
                        (and (file-exists? path)  ;discard dangling symlinks
                             (or (elf-file? path) (ar-file? path))
                             (or (not debug-output)
                                 (make-debug-file path))
                             (zero? (apply system* strip-command
                                           (append strip-flags (list path))))
                             (or (not debug-output)
                                 (add-debug-link path))))
                      (const #t)                  ; down
                      (const #t)                  ; up
                      (const #t)                  ; skip
                      (lambda (path stat errno result)
                        (format (current-error-port)
                                "strip: failed to access `~a': ~a~%"
                                path (strerror errno))
                        #f)
                      #t
                      dir))

  (or (not strip-binaries?)
      (every strip-dir
             (append-map (match-lambda
                          ((_ . dir)
                           (filter-map (lambda (d)
                                         (let ((sub (string-append dir "/" d)))
                                           (and (directory-exists? sub) sub)))
                                       strip-directories)))
                         outputs))))

(define* (validate-runpath #:key
                           (validate-runpath? #t)
                           (elf-directories '("lib" "lib64" "libexec"
                                              "bin" "sbin"))
                           outputs #:allow-other-keys)
  "When VALIDATE-RUNPATH? is true, validate that all the ELF files in
ELF-DIRECTORIES have their dependencies found in their 'RUNPATH'.

Since the ELF parser needs to have a copy of files in memory, better run this
phase after stripping."
  (define (sub-directory parent)
    (lambda (directory)
      (let ((directory (string-append parent "/" directory)))
        (and (directory-exists? directory) directory))))

  (define (validate directory)
    (define (file=? file1 file2)
      (let ((st1 (stat file1))
            (st2 (stat file2)))
        (= (stat:ino st1) (stat:ino st2))))

    ;; There are always symlinks from '.so' to '.so.1' and so on, so delete
    ;; duplicates.
    (let ((files (delete-duplicates (find-files directory (lambda (file stat)
                                                            (elf-file? file)))
                                    file=?)))
      (format (current-error-port)
              "validating RUNPATH of ~a binaries in ~s...~%"
              (length files) directory)
      (every* validate-needed-in-runpath files)))

  (if validate-runpath?
      (let ((dirs (append-map (match-lambda
                                (("debug" . _)
                                 ;; The "debug" output is full of ELF files
                                 ;; that are not worth checking.
                                 '())
                                ((name . output)
                                 (filter-map (sub-directory output)
                                             elf-directories)))
                              outputs)))
        (every* validate dirs))
      (begin
        (format (current-error-port) "skipping RUNPATH validation~%")
        #t)))

(define* (validate-documentation-location #:key outputs
                                          #:allow-other-keys)
  "Documentation should go to 'share/info' and 'share/man', not just 'info/'
and 'man/'.  This phase moves directories to the right place if needed."
  (define (validate-sub-directory output sub-directory)
    (let ((directory (string-append output "/" sub-directory)))
      (when (directory-exists? directory)
        (let ((target (string-append output "/share/" sub-directory)))
          (format #t "moving '~a' to '~a'~%" directory target)
          (mkdir-p (dirname target))
          (rename-file directory target)))))

  (define (validate-output output)
    (for-each (cut validate-sub-directory output <>)
              '("man" "info")))

  (match outputs
    (((names . directories) ...)
     (for-each validate-output directories)))
  #t)

(define* (compress-documentation #:key outputs
                                 (compress-documentation? #t)
                                 (documentation-compressor "gzip")
                                 (documentation-compressor-flags
                                  '("--best" "--no-name"))
                                 (compressed-documentation-extension ".gz")
                                 #:allow-other-keys)
  "When COMPRESS-DOCUMENTATION? is true, compress man pages and Info files
found in OUTPUTS using DOCUMENTATION-COMPRESSOR, called with
DOCUMENTATION-COMPRESSOR-FLAGS."
  (define (retarget-symlink link)
    (let ((target (readlink link)))
      (delete-file link)
      (symlink (string-append target compressed-documentation-extension)
               link)))

  (define (has-links? file)
    ;; Return #t if FILE has hard links.
    (> (stat:nlink (lstat file)) 1))

  (define (maybe-compress-directory directory regexp)
    (or (not (directory-exists? directory))
        (match (find-files directory regexp)
          (()                                     ;nothing to compress
           #t)
          ((files ...)                            ;one or more files
           (format #t
                   "compressing documentation in '~a' with ~s and flags ~s~%"
                   directory documentation-compressor
                   documentation-compressor-flags)
           (call-with-values
               (lambda ()
                 (partition symbolic-link? files))
             (lambda (symlinks regular-files)
               ;; Compress the non-symlink files, and adjust symlinks to refer
               ;; to the compressed files.  Leave files that have hard links
               ;; unchanged ('gzip' would refuse to compress them anyway.)
               (and (zero? (apply system* documentation-compressor
                                  (append documentation-compressor-flags
                                          (remove has-links? regular-files))))
                    (every retarget-symlink
                           (filter (cut string-match regexp <>)
                                   symlinks)))))))))

  (define (maybe-compress output)
    (and (maybe-compress-directory (string-append output "/share/man")
                                   "\\.[0-9]+$")
         (maybe-compress-directory (string-append output "/share/info")
                                   "\\.info(-[0-9]+)?$")))

  (if compress-documentation?
      (match outputs
        (((names . directories) ...)
         (every maybe-compress directories)))
      (begin
        (format #t "not compressing documentation~%")
        #t)))

(define* (delete-info-dir-file #:key outputs #:allow-other-keys)
  "Delete any 'share/info/dir' file from OUTPUTS."
  (for-each (match-lambda
          ((output . directory)
           (let ((info-dir-file (string-append directory "/share/info/dir")))
             (when (file-exists? info-dir-file)
               (delete-file info-dir-file)))))
            outputs)
  #t)

(define %standard-phases
  ;; Standard build phases, as a list of symbol/procedure pairs.
  (let-syntax ((phases (syntax-rules ()
                         ((_ p ...) `((p . ,p) ...)))))
    (phases set-SOURCE-DATE-EPOCH set-paths install-locale unpack
            patch-usr-bin-file
            patch-source-shebangs configure patch-generated-file-shebangs
            build check install
            patch-shebangs strip
            validate-runpath
            validate-documentation-location
            delete-info-dir-file
            compress-documentation)))


(define* (gnu-build #:key (source #f) (outputs #f) (inputs #f)
                    (phases %standard-phases)
                    #:allow-other-keys
                    #:rest args)
  "Build from SOURCE to OUTPUTS, using INPUTS, and by running all of PHASES
in order.  Return #t if all the PHASES succeeded, #f otherwise."
  (define (elapsed-time end start)
    (let ((diff (time-difference end start)))
      (+ (time-second diff)
         (/ (time-nanosecond diff) 1e9))))

  (setvbuf (current-output-port) _IOLBF)
  (setvbuf (current-error-port) _IOLBF)

  ;; Encoding/decoding errors shouldn't be silent.
  (fluid-set! %default-port-conversion-strategy 'error)

  ;; The trick is to #:allow-other-keys everywhere, so that each procedure in
  ;; PHASES can pick the keyword arguments it's interested in.
  (every (match-lambda
          ((name . proc)
           (let ((start (current-time time-monotonic)))
             (format #t "starting phase `~a'~%" name)
             (let ((result (apply proc args))
                   (end    (current-time time-monotonic)))
               (format #t "phase `~a' ~:[failed~;succeeded~] after ~,1f seconds~%"
                       name result
                       (elapsed-time end start))

               ;; Dump the environment variables as a shell script, for handy debugging.
               (system "export > $NIX_BUILD_TOP/environment-variables")
               result))))
         phases))
