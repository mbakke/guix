;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 David Craven <david@craven.ch>
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
  #:use-module (gnu packages ssh)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu system pam)
  #:use-module (guix gexp)
  #:use-module (guix records)
  #:use-module (srfi srfi-26)
  #:export (lsh-configuration
            lsh-configuration?
            lsh-service
            lsh-service-type

            dropbear-configuration
            dropbear-configuration?
            dropbear-service-type
            dropbear-service))

;;; Commentary:
;;;
;;; This module implements secure shell (SSH) services.
;;;
;;; Code:

;; TODO: Export.
(define-record-type* <lsh-configuration>
  lsh-configuration make-lsh-configuration
  lsh-configuration?
  (lsh lsh-configuration-lsh
       (default lsh))
  (daemonic? lsh-configuration-daemonic?)
  (host-key lsh-configuration-host-key)
  (interfaces lsh-configuration-interfaces)
  (port-number lsh-configuration-port-number)
  (allow-empty-passwords? lsh-configuration-allow-empty-passwords?)
  (root-login? lsh-configuration-root-login?)
  (syslog-output? lsh-configuration-syslog-output?)
  (pid-file? lsh-configuration-pid-file?)
  (pid-file lsh-configuration-pid-file)
  (x11-forwarding? lsh-configuration-x11-forwarding?)
  (tcp/ip-forwarding? lsh-configuration-tcp/ip-forwarding?)
  (password-authentication? lsh-configuration-password-authentication?)
  (public-key-authentication? lsh-configuration-public-key-authentication?)
  (initialize? lsh-configuration-initialize?))

(define %yarrow-seed
  "/var/spool/lsh/yarrow-seed-file")

(define (lsh-initialization lsh host-key)
  "Return the gexp to initialize the LSH service for HOST-KEY."
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

(define (lsh-activation config)
  "Return the activation gexp for CONFIG."
  #~(begin
      (use-modules (guix build utils))
      (mkdir-p "/var/spool/lsh")
      #$(if (lsh-configuration-initialize? config)
            (lsh-initialization (lsh-configuration-lsh config)
                                (lsh-configuration-host-key config))
            #t)))

(define (lsh-shepherd-service config)
  "Return a <shepherd-service> for lsh with CONFIG."
  (define lsh (lsh-configuration-lsh config))
  (define pid-file (lsh-configuration-pid-file config))
  (define pid-file? (lsh-configuration-pid-file? config))
  (define daemonic? (lsh-configuration-daemonic? config))
  (define interfaces (lsh-configuration-interfaces config))

  (define lsh-command
    (append
     (cons #~(string-append #$lsh "/sbin/lshd")
           (if daemonic?
               (let ((syslog (if (lsh-configuration-syslog-output? config)
                                 '()
                                 (list "--no-syslog"))))
                 (cons "--daemonic"
                       (if pid-file?
                           (cons #~(string-append "--pid-file=" #$pid-file)
                                 syslog)
                           (cons "--no-pid-file" syslog))))
               (if pid-file?
                   (list #~(string-append "--pid-file=" #$pid-file))
                   '())))
     (cons* #~(string-append "--host-key="
                             #$(lsh-configuration-host-key config))
            #~(string-append "--password-helper=" #$lsh "/sbin/lsh-pam-checkpw")
            #~(string-append "--subsystems=sftp=" #$lsh "/sbin/sftp-server")
            "-p" (number->string (lsh-configuration-port-number config))
            (if (lsh-configuration-password-authentication? config)
                "--password" "--no-password")
            (if (lsh-configuration-public-key-authentication? config)
                "--publickey" "--no-publickey")
            (if (lsh-configuration-root-login? config)
                "--root-login" "--no-root-login")
            (if (lsh-configuration-x11-forwarding? config)
                "--x11-forward" "--no-x11-forward")
            (if (lsh-configuration-tcp/ip-forwarding? config)
                "--tcpip-forward" "--no-tcpip-forward")
            (if (null? interfaces)
                '()
                (map (cut string-append "--interface=" <>)
                     interfaces)))))

  (define requires
    (if (and daemonic? (lsh-configuration-syslog-output? config))
        '(networking syslogd)
        '(networking)))

  (list (shepherd-service
         (documentation "GNU lsh SSH server")
         (provision '(ssh-daemon))
         (requirement requires)
         (start #~(make-forkexec-constructor (list #$@lsh-command)))
         (stop  #~(make-kill-destructor)))))

(define (lsh-pam-services config)
  "Return a list of <pam-services> for lshd with CONFIG."
  (list (unix-pam-service
         "lshd"
         #:allow-empty-passwords?
         (lsh-configuration-allow-empty-passwords? config))))

(define lsh-service-type
  (service-type (name 'lsh)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          lsh-shepherd-service)
                       (service-extension pam-root-service-type
                                          lsh-pam-services)
                       (service-extension activation-service-type
                                          lsh-activation)))))

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
                      (initialize? #t))
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
  (service lsh-service-type
           (lsh-configuration (lsh lsh) (daemonic? daemonic?)
                              (host-key host-key) (interfaces interfaces)
                              (port-number port-number)
                              (allow-empty-passwords? allow-empty-passwords?)
                              (root-login? root-login?)
                              (syslog-output? syslog-output?)
                              (pid-file? pid-file?) (pid-file pid-file)
                              (x11-forwarding? x11-forwarding?)
                              (tcp/ip-forwarding? tcp/ip-forwarding?)
                              (password-authentication?
                               password-authentication?)
                              (public-key-authentication?
                               public-key-authentication?)
                              (initialize? initialize?))))


;;;
;;; Dropbear.
;;;

(define-record-type* <dropbear-configuration>
  dropbear-configuration make-dropbear-configuration
  dropbear-configuration?
  (dropbear               dropbear-configuration-dropbear
                          (default dropbear))
  (port-number            dropbear-configuration-port-number
                          (default 22))
  (syslog-output?         dropbear-configuration-syslog-output?
                          (default #t))
  (pid-file               dropbear-configuration-pid-file
                          (default "/var/run/dropbear.pid"))
  (root-login?            dropbear-configuration-root-login?
                          (default #f))
  (allow-empty-passwords? dropbear-configuration-allow-empty-passwords?
                          (default #f))
  (password-authentication? dropbear-configuration-password-authentication?
                            (default #t)))

(define (dropbear-activation config)
  "Return the activation gexp for CONFIG."
  #~(begin
      (mkdir-p "/etc/dropbear")))

(define (dropbear-shepherd-service config)
  "Return a <shepherd-service> for dropbear with CONFIG."
  (define dropbear
    (dropbear-configuration-dropbear config))

  (define pid-file
    (dropbear-configuration-pid-file config))

  (define dropbear-command
    #~(list (string-append #$dropbear "/sbin/dropbear")

            ;; '-R' allows host keys to be automatically generated upon first
            ;; connection, at a time when /dev/urandom is more likely securely
            ;; seeded.
            "-F" "-R"

            "-p" #$(number->string (dropbear-configuration-port-number config))
            "-P" #$pid-file
            #$@(if (dropbear-configuration-syslog-output? config) '() '("-E"))
            #$@(if (dropbear-configuration-root-login? config) '() '("-w"))
            #$@(if (dropbear-configuration-password-authentication? config)
                   '()
                   '("-s" "-g"))
            #$@(if (dropbear-configuration-allow-empty-passwords? config)
                   '("-B")
                   '())))

  (define requires
    (if (dropbear-configuration-syslog-output? config)
        '(networking syslogd) '(networking)))

  (list (shepherd-service
         (documentation "Dropbear SSH server.")
         (requirement requires)
         (provision '(ssh-daemon))
         (start #~(make-forkexec-constructor #$dropbear-command
                                             #:pid-file #$pid-file))
         (stop #~(make-kill-destructor)))))

(define dropbear-service-type
  (service-type (name 'dropbear)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          dropbear-shepherd-service)
                       (service-extension activation-service-type
                                          dropbear-activation)))))

(define* (dropbear-service #:optional (config (dropbear-configuration)))
  "Run the @uref{https://matt.ucc.asn.au/dropbear/dropbear.html,Dropbear SSH
daemon} with the given @var{config}, a @code{<dropbear-configuration>}
object."
  (service dropbear-service-type config))

;;; ssh.scm ends here
