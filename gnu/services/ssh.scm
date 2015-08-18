;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015 Ludovic Courtès <ludo@gnu.org>
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

(define-module (gnu services ssh)
  #:use-module (guix gexp)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (gnu services)
  #:use-module (gnu system linux)                 ; 'pam-service'
  #:use-module (gnu packages lsh)
  #:export (lsh-service))

;;; Commentary:
;;;
;;; This module implements secure shell (SSH) services.
;;;
;;; Code:

(define %yarrow-seed
  "/var/spool/lsh/yarrow-seed-file")

(define (activation lsh host-key)
  "Return the gexp to activate the LSH service for HOST-KEY."
  #~(begin
      (unless (file-exists? #$%yarrow-seed)
        (system* (string-append #$lsh "/bin/lsh-make-seed")
                 "--sloppy" "-o" #$%yarrow-seed))

      (unless (file-exists? #$host-key)
        (mkdir-p (dirname #$host-key))
        (format #t "creating SSH host key '~a'...~%" #$host-key)

        ;; FIXME: We're just doing a simple pipeline, but 'system' cannot be
        ;; used yet because /bin/sh might be dangling; factorize this somehow.
        (let* ((in+out (pipe))
               (keygen (primitive-fork)))
          (case keygen
            ((0)
             (close-port (car in+out))
             (close-fdes 1)
             (dup2 (fileno (cdr in+out)) 1)
             (execl (string-append #$lsh "/bin/lsh-keygen")
                    "lsh-keygen" "--server"))
            (else
             (let ((write-key (primitive-fork)))
               (case write-key
                 ((0)
                  (close-port (cdr in+out))
                  (close-fdes 0)
                  (dup2 (fileno (car in+out)) 0)
                  (execl (string-append #$lsh "/bin/lsh-writekey")
                         "lsh-writekey" "--server" "-o" #$host-key))
                 (else
                  (close-port (car in+out))
                  (close-port (cdr in+out))
                  (waitpid keygen)
                  (waitpid write-key))))))))))

(define* (lsh-service #:key
                      (lsh lsh)
                      (daemonic? #t)
                      (host-key "/etc/lsh/host-key")
                      (interfaces '())
                      (port-number 22)
                      (allow-empty-passwords? #f)
                      (root-login? #f)
                      (syslog-output? #t)
                      (pid-file? #f)
                      (pid-file "/var/run/lshd.pid")
                      (x11-forwarding? #t)
                      (tcp/ip-forwarding? #t)
                      (password-authentication? #t)
                      (public-key-authentication? #t)
                      (initialize? #t)
                      (additional-session-modules '()))
  "Run the @command{lshd} program from @var{lsh} to listen on port @var{port-number}.
@var{host-key} must designate a file containing the host key, and readable
only by root.

When @var{daemonic?} is true, @command{lshd} will detach from the
controlling terminal and log its output to syslogd, unless one sets
@var{syslog-output?} to false.  Obviously, it also makes lsh-service
depend on existence of syslogd service.  When @var{pid-file?} is true,
@command{lshd} writes its PID to the file called @var{pid-file}.

When @var{initialize?} is true, automatically create the seed and host key
upon service activation if they do not exist yet.  This may take long and
require interaction.

When @var{initialize?} is false, it is up to the user to initialize the
randomness generator (@pxref{lsh-make-seed,,, lsh, LSH Manual}), and to create
a key pair with the private key stored in file @var{host-key} (@pxref{lshd
basics,,, lsh, LSH Manual}).

When @var{interfaces} is empty, lshd listens for connections on all the
network interfaces; otherwise, @var{interfaces} must be a list of host names
or addresses.

@var{allow-empty-passwords?} specifies whether to accept log-ins with empty
passwords, and @var{root-login?} specifies whether to accept log-ins as
root.

The other options should be self-descriptive."
  (define lsh-command
    (append
     (cons #~(string-append #$lsh "/sbin/lshd")
           (if daemonic?
               (let ((syslog (if syslog-output? '()
                                 (list "--no-syslog"))))
                 (cons "--daemonic"
                       (if pid-file?
                           (cons #~(string-append "--pid-file=" #$pid-file)
                                 syslog)
                           (cons "--no-pid-file" syslog))))
               (if pid-file?
                   (list #~(string-append "--pid-file=" #$pid-file))
                   '())))
     (cons* #~(string-append "--host-key=" #$host-key)
            #~(string-append "--password-helper=" #$lsh "/sbin/lsh-pam-checkpw")
            #~(string-append "--subsystems=sftp=" #$lsh "/sbin/sftp-server")
            "-p" (number->string port-number)
            (if password-authentication? "--password" "--no-password")
            (if public-key-authentication?
                "--publickey" "--no-publickey")
            (if root-login?
                "--root-login" "--no-root-login")
            (if x11-forwarding?
                "--x11-forward" "--no-x11-forward")
            (if tcp/ip-forwarding?
                "--tcpip-forward" "--no-tcpip-forward")
            (if (null? interfaces)
                '()
                (list (string-append "--interfaces="
                                     (string-join interfaces ",")))))))

  (define requires
    (if (and daemonic? syslog-output?)
        '(networking syslogd)
        '(networking)))

  (with-monad %store-monad
    (return (service
             (documentation "GNU lsh SSH server")
             (provision '(ssh-daemon))
             (requirement requires)
             (start #~(make-forkexec-constructor (list #$@lsh-command)))
             (stop  #~(make-kill-destructor))
             (pam-services
              (list (unix-pam-service
                     "lshd"
                     #:allow-empty-passwords? allow-empty-passwords?
                     #:additional-session-modules additional-session-modules)))
             (activate #~(begin
                           (use-modules (guix build utils))
                           (mkdir-p "/var/spool/lsh")
                           #$(if initialize?
                                 (activation lsh host-key)
                                 #t)))))))

;;; ssh.scm ends here
