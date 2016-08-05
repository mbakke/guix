;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Andy Wingo <wingo@igalia.com>
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
;;;
;;; Some of the help text was taken from the default dovecot.conf files.

(define-module (gnu services mail)
  #:use-module (gnu services)
  #:use-module (gnu services base)
  #:use-module (gnu services shepherd)
  #:use-module (gnu system pam)
  #:use-module (gnu system shadow)
  #:use-module (gnu packages mail)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages tls)
  #:use-module (guix records)
  #:use-module (guix packages)
  #:use-module (guix gexp)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:use-module (ice-9 match)
  #:export (&dovecot-configuation-error
            dovecot-configuration-error?

            dovecot-service
            dovecot-service-type
            dovecot-configuration
            opaque-dovecot-configuration

            dict-configuration
            passdb-configuration
            userdb-configuration
            unix-listener-configuration
            fifo-listener-configuration
            inet-listener-configuration
            service-configuration
            protocol-configuration
            plugin-configuration
            mailbox-configuration
            namespace-configuration))

;;; Commentary:
;;;
;;; This module provides service definitions for the Dovecot POP3 and IMAP
;;; mail server.
;;;
;;; Code:

(define-condition-type &dovecot-configuration-error &error
  dovecot-configuration-error?)

(define (dovecot-error message)
  (raise (condition (&message (message message))
                    (&dovecot-configuration-error))))
(define (dovecot-configuration-field-error field val)
  (dovecot-error
   (format #f "Invalid value for field ~a: ~s" field val)))
(define (dovecot-configuration-missing-field kind field)
  (dovecot-error
   (format #f "~a configuration missing required field ~a" kind field)))

(define-record-type* <configuration-field>
  configuration-field make-configuration-field configuration-field?
  (name configuration-field-name)
  (type configuration-field-type)
  (getter configuration-field-getter)
  (predicate configuration-field-predicate)
  (serializer configuration-field-serializer)
  (default-value-thunk configuration-field-default-value-thunk)
  (documentation configuration-field-documentation))

(define-syntax define-configuration
  (lambda (stx)
    (define (id ctx part . parts)
      (let ((part (syntax->datum part)))
        (datum->syntax
         ctx
         (match parts
           (() part)
           (parts (symbol-append part
                                 (syntax->datum (apply id ctx parts))))))))
    (syntax-case stx ()
      ((_ stem (field (field-type def) doc) ...)
       (with-syntax (((field-getter ...)
                      (map (lambda (field)
                             (id #'stem #'stem #'- field))
                           #'(field ...)))
                     ((field-predicate ...)
                      (map (lambda (type)
                             (id #'stem type #'?))
                           #'(field-type ...)))
                     ((field-serializer ...)
                      (map (lambda (type)
                             (id #'stem #'serialize- type))
                           #'(field-type ...))))
           #`(begin
               (define-record-type* #,(id #'stem #'< #'stem #'>)
                 stem #,(id #'stem #'make- #'stem) #,(id #'stem #'stem #'?)
                 (field field-getter (default def))
                 ...)
               (define #,(id #'stem #'stem #'-fields)
                 (list (configuration-field
                        (name 'field)
                        (type 'field-type)
                        (getter field-getter)
                        (predicate field-predicate)
                        (serializer field-serializer)
                        (default-value-thunk (lambda () def))
                        (documentation doc))
                       ...))))))))

(define (serialize-configuration config fields)
  (for-each (lambda (field)
              ((configuration-field-serializer field)
               (configuration-field-name field)
               ((configuration-field-getter field) config)))
            fields))

(define (validate-configuration config fields)
  (for-each (lambda (field)
              (let ((val ((configuration-field-getter field) config)))
                (unless ((configuration-field-predicate field) val)
                  (dovecot-configuration-field-error
                   (configuration-field-name field) val))))
            fields))

(define (validate-package field-name package)
  (unless (package? package)
    (dovecot-configuration-field-error field-name package)))

(define (uglify-field-name field-name)
  (let ((str (symbol->string field-name)))
    (string-join (string-split (if (string-suffix? "?" str)
                                   (substring str 0 (1- (string-length str)))
                                   str)
                               #\-)
                 "_")))

(define (serialize-package field-name val)
  #f)

(define (serialize-field field-name val)
  (format #t "~a=~a\n" (uglify-field-name field-name) val))

(define (serialize-string field-name val)
  (serialize-field field-name val))

(define (space-separated-string-list? val)
  (and (list? val)
       (and-map (lambda (x)
                  (and (string? x) (not (string-index x #\space))))
                val)))
(define (serialize-space-separated-string-list field-name val)
  (serialize-field field-name (string-join val " ")))

(define (comma-separated-string-list? val)
  (and (list? val)
       (and-map (lambda (x)
                  (and (string? x) (not (string-index x #\,))))
                val)))
(define (serialize-comma-separated-string-list field-name val)
  (serialize-field field-name (string-join val ",")))

(define (file-name? val)
  (and (string? val)
       (string-prefix? "/" val)))
(define (serialize-file-name field-name val)
  (serialize-string field-name val))

(define (colon-separated-file-name-list? val)
  (and (list? val)
       ;; Trailing slashes not needed and not
       (and-map file-name? val)))
(define (serialize-colon-separated-file-name-list field-name val)
  (serialize-field field-name (string-join val ":")))

(define (serialize-boolean field-name val)
  (serialize-string field-name (if val "yes" "no")))

(define (non-negative-integer? val)
  (and (exact-integer? val) (not (negative? val))))
(define (serialize-non-negative-integer field-name val)
  (serialize-field field-name val))

(define (hours? val) (non-negative-integer? val))
(define (serialize-hours field-name val)
  (serialize-field field-name (format #f "~a hours" val)))

(define (free-form-fields? val)
  (match val
    (() #t)
    ((((? symbol?) . (? string)) . val) (free-form-fields? val))
    (_ #f)))
(define (serialize-free-form-fields field-name val)
  (for-each (match-lambda ((k . v) (serialize-field k v))) val))

(define (free-form-args? val)
  (match val
    (() #t)
    ((((? symbol?) . (? string)) . val) (free-form-args? val))
    (_ #f)))
(define (serialize-free-form-args field-name val)
  (serialize-field field-name
                   (string-join
                    (map (match-lambda ((k . v) (format #t "~a=~a" k v))) val)
                    " ")))

(define-configuration dict-configuration
  (entries
   (free-form-fields '())
   "A list of key-value pairs that this dict should hold."))

(define (serialize-dict-configuration field-name val)
  (format #t "dict {\n")
  (serialize-configuration val dict-configuration-fields)
  (format #t "}\n"))

(define-configuration passdb-configuration
  (driver
   (string "pam")
   "The driver that the passdb should use.  Valid values include
@samp{pam}, @samp{passwd}, @samp{shadow}, @samp{bsdauth}, and
@samp{static}.")
  (args
   (free-form-args '())
   "A list of key-value args to the passdb driver."))

(define (serialize-passdb-configuration field-name val)
  (format #t "passdb {\n")
  (serialize-configuration val passdb-configuration-fields)
  (format #t "}\n"))
(define (passdb-configuration-list? val)
  (and (list? val) (and-map passdb-configuration? val)))
(define (serialize-passdb-configuration-list field-name val)
  (for-each (lambda (val) (serialize-passdb-configuration field-name val)) val))

(define-configuration userdb-configuration
  (driver
   (string "passwd")
   "The driver that the userdb should use.  Valid values include
@samp{passwd} and @samp{static}.")
  (args
   (free-form-args '())
   "A list of key-value args to the userdb driver.")
  (override-fields
   (free-form-args '())
   "Override fields from passwd."))

(define (serialize-userdb-configuration field-name val)
  (format #t "userdb {\n")
  (serialize-configuration val userdb-configuration-fields)
  (format #t "}\n"))
(define (userdb-configuration-list? val)
  (and (list? val) (and-map userdb-configuration? val)))
(define (serialize-userdb-configuration-list field-name val)
  (for-each (lambda (val) (serialize-userdb-configuration field-name val)) val))

(define-configuration unix-listener-configuration
  (path
   (file-name (dovecot-configuration-missing-field 'unix-listener 'path))
   "The file name on which to listen.")
  (mode
   (string "0600")
   "The access mode for the socket.")
  (user
   (string "")
   "The user to own the the socket.")
  (group
   (string "")
   "The group to own the socket."))

(define (serialize-unix-listener-configuration field-name val)
  (format #t "unix_listener ~a {\n" (unix-listener-configuration-path val))
  (serialize-configuration val (cdr unix-listener-configuration-fields))
  (format #t "}\n"))

(define-configuration fifo-listener-configuration
  (path
   (file-name (dovecot-configuration-missing-field 'fifo-listener 'path))
   "The file name on which to listen.")
  (mode
   (string "0600")
   "The access mode for the socket.")
  (user
   (string "")
   "The user to own the the socket.")
  (group
   (string "")
   "The group to own the socket."))

(define (serialize-fifo-listener-configuration field-name val)
  (format #t "fifo_listener ~a {\n" (fifo-listener-configuration-path val))
  (serialize-configuration val (cdr fifo-listener-configuration-fields))
  (format #t "}\n"))

(define-configuration inet-listener-configuration
  (protocol
   (string (dovecot-configuration-missing-field 'inet-listener 'protocol))
   "The protocol to listen for.")
  (address
   (string "")
   "The address on which to listen, or empty for all addresses.")
  (port
   (non-negative-integer
    (dovecot-configuration-missing-field 'inet-listener 'port))
   "The port on which to listen.")
  (ssl?
   (boolean #t)
   "Whether to use SSL for this service; @samp{yes}, @samp{no}, or
@samp{required}."))

(define (serialize-inet-listener-configuration field-name val)
  (format #t "inet_listener ~a {\n" (inet-listener-configuration-protocol val))
  (serialize-configuration val (cdr inet-listener-configuration-fields))
  (format #t "}\n"))

(define (listener-configuration? val)
  (or (unix-listener-configuration? val)
      (fifo-listener-configuration? val)
      (inet-listener-configuration? val)))
(define (serialize-listener-configuration field-name val)
  (cond
   ((unix-listener-configuration? val)
    (serialize-unix-listener-configuration field-name val))
   ((fifo-listener-configuration? val)
    (serialize-fifo-listener-configuration field-name val))
   ((inet-listener-configuration? val)
    (serialize-inet-listener-configuration field-name val))
   (else (dovecot-configuration-field-error field-name val))))
(define (listener-configuration-list? val)
  (and (list? val) (and-map listener-configuration? val)))
(define (serialize-listener-configuration-list field-name val)
  (for-each (lambda (val)
              (serialize-listener-configuration field-name val))
            val))

(define-configuration service-configuration
  (kind
   (string (dovecot-configuration-missing-field 'service 'kind))
   "The service kind.  Valid values include @code{director},
@code{imap-login}, @code{pop3-login}, @code{lmtp}, @code{imap},
@code{pop3}, @code{auth}, @code{auth-worker}, @code{dict},
@code{tcpwrap}, @code{quota-warning}, or anything else.")
  (listeners
   (listener-configuration-list '())
   "Listeners for the service.  A listener is either an
@code{unix-listener-configuration}, a @code{fifo-listener-configuration}, or
an @code{inet-listener-configuration}.")
  (service-count
   (non-negative-integer 1)
   "Number of connections to handle before starting a new process.
Typically the only useful values are 0 (unlimited) or 1.  1 is more
secure, but 0 is faster.  <doc/wiki/LoginProcess.txt>.")
  (process-min-avail
   (non-negative-integer 0)
   "Number of processes to always keep waiting for more connections.")
  ;; FIXME: Need to be able to take the default for this value from other
  ;; parts of the config.
  (vsz-limit
   (non-negative-integer #e256e6)
   "If you set @samp{service-count 0}, you probably need to grow
this."))

(define (serialize-service-configuration field-name val)
  (format #t "service ~a {\n" (service-configuration-kind val))
  (serialize-configuration val (cdr service-configuration-fields))
  (format #t "}\n"))
(define (service-configuration-list? val)
  (and (list? val) (and-map service-configuration? val)))
(define (serialize-service-configuration-list field-name val)
  (for-each (lambda (val)
              (serialize-service-configuration field-name val))
            val))

(define-configuration protocol-configuration
  (name
   (string (dovecot-configuration-missing-field 'protocol 'name))
   "The name of the protocol.")
  (auth-socket-path
   (string "/var/run/dovecot/auth-userdb")
   "UNIX socket path to master authentication server to find users.
This is used by imap (for shared users) and lda.")
  (mail-plugins
   (space-separated-string-list '("$mail_plugins"))
   "Space separated list of plugins to load.")
  (mail-max-userip-connections
   (non-negative-integer 10)
   "Maximum number of IMAP connections allowed for a user from each IP
address.  NOTE: The username is compared case-sensitively."))

(define (serialize-protocol-configuration field-name val)
  (format #t "protocol ~a {\n" (protocol-configuration-name val))
  (serialize-configuration val (cdr protocol-configuration-fields))
  (format #t "}\n"))
(define (protocol-configuration-list? val)
  (and (list? val) (and-map protocol-configuration? val)))
(define (serialize-protocol-configuration-list field-name val)
  (serialize-field 'protocols
                   (string-join (map protocol-configuration-name val) " "))
  (for-each (lambda (val)
              (serialize-protocol-configuration field-name val))
            val))

(define-configuration plugin-configuration
  (entries
   (free-form-fields '())
   "A list of key-value pairs that this dict should hold."))

(define (serialize-plugin-configuration field-name val)
  (format #t "plugin {\n")
  (serialize-configuration val plugin-configuration-fields)
  (format #t "}\n"))

(define-configuration mailbox-configuration
  (name
   (string (error "mailbox name is required"))
   "Name for this mailbox.")

  (auto
   (string "no")
   "@samp{create} will automatically create this mailbox.
@samp{subscribe} will both create and subscribe to the mailbox.")

  (special-use
   (space-separated-string-list '())
   "List of IMAP @code{SPECIAL-USE} attributes as specified by RFC 6154.
Valid values are @code{\\All}, @code{\\Archive}, @code{\\Drafts},
@code{\\Flagged}, @code{\\Junk}, @code{\\Sent}, and @code{\\Trash}."))

(define (serialize-mailbox-configuration field-name val)
  (format #t "mailbox \"~a\" {\n" (mailbox-configuration-name val))
  (serialize-configuration val (cdr mailbox-configuration-fields))
  (format #t "}\n"))
(define (mailbox-configuration-list? val)
  (and (list? val) (and-map mailbox-configuration? val)))
(define (serialize-mailbox-configuration-list field-name val)
  (for-each (lambda (val)
              (serialize-mailbox-configuration field-name val))
            val))

(define-configuration namespace-configuration
  (name
   (string (error "namespace name is required"))
   "Name for this namespace.")

  (type
   (string "private")
   "Namespace type: @samp{private}, @samp{shared} or @samp{public}.")

  (separator
   (string "")
   "Hierarchy separator to use. You should use the same separator for
all namespaces or some clients get confused.  @samp{/} is usually a good
one.  The default however depends on the underlying mail storage
format.")

  (prefix
   (string "")
   "Prefix required to access this namespace.  This needs to be
different for all namespaces. For example @samp{Public/}.")

  (location
   (string "")
   "Physical location of the mailbox. This is in same format as
mail_location, which is also the default for it.")

  (inbox?
   (boolean #f)
   "There can be only one INBOX, and this setting defines which
namespace has it.")

  (hidden?
   (boolean #f)
   "If namespace is hidden, it's not advertised to clients via NAMESPACE
extension. You'll most likely also want to set @samp{list? #f}.  This is mostly
useful when converting from another server with different namespaces
which you want to deprecate but still keep working.  For example you can
create hidden namespaces with prefixes @samp{~/mail/}, @samp{~%u/mail/}
and @samp{mail/}.")

  (list?
   (boolean #t)
   "Show the mailboxes under this namespace with LIST command. This
makes the namespace visible for clients that don't support NAMESPACE
extension.  The special @code{children} value lists child mailboxes, but
hides the namespace prefix.")

  (subscriptions?
   (boolean #t)
   "Namespace handles its own subscriptions.  If set to @code{#f}, the
parent namespace handles them.  The empty prefix should always have this
as @code{#t}.)")

  (mailboxes
   (mailbox-configuration-list '())
   "List of predefined mailboxes in this namespace."))

(define (serialize-namespace-configuration field-name val)
  (format #t "namespace ~a {\n" (namespace-configuration-name val))
  (serialize-configuration val (cdr namespace-configuration-fields))
  (format #t "}\n"))
(define (list-of-namespace-configuration? val)
  (and (list? val) (and-map namespace-configuration? val)))
(define (serialize-list-of-namespace-configuration field-name val)
  (for-each (lambda (val)
              (serialize-namespace-configuration field-name val))
            val))

(define-configuration dovecot-configuration
  (dovecot
   (package dovecot)
   "The dovecot package.")

  (listen
   (comma-separated-string-list '("*" "::"))
   "A list of IPs or hosts where to listen in for connections.  @samp{*}
listens in all IPv4 interfaces, @samp{::} listens in all IPv6
interfaces.  If you want to specify non-default ports or anything more
complex, customize the address and port fields of the
@samp{inet-listener} of the specific services you are interested in.")

  (protocols
   (protocol-configuration-list
    (list (protocol-configuration
           (name "imap"))))
   "List of protocols we want to serve.  Available protocols include
@samp{imap}, @samp{pop3}, and @samp{lmtp}.")

  (services
   (service-configuration-list
    (list
     (service-configuration
      (kind "imap-login")
      (listeners
       (list
        (inet-listener-configuration (protocol "imap") (port 143) (ssl? #f))
        (inet-listener-configuration (protocol "imaps") (port 993) (ssl? #t)))))
     (service-configuration
      (kind "pop3-login")
      (listeners
       (list
        (inet-listener-configuration (protocol "pop3") (port 110) (ssl? #f))
        (inet-listener-configuration (protocol "pop3s") (port 995) (ssl? #t)))))
     (service-configuration
      (kind "lmtp")
      (listeners
       (list (unix-listener-configuration (path "lmtp") (mode "0666")))))
     (service-configuration (kind "imap"))
     (service-configuration (kind "pop3"))
     (service-configuration (kind "auth")
      ;; In what could be taken to be a bug, the default value of 1 for
      ;; service-count makes it so that a PAM auth worker can't fork off
      ;; subprocesses for making blocking queries.  The result is that nobody
      ;; can log in -- very secure, but not very useful!  If we simply omit
      ;; the service-count, it will default to the value of
      ;; auth-worker-max-count, which is 30, instead of defaulting to 1, which
      ;; is the default for all other services.  As a hack, bump this value to
      ;; 30.
      (service-count 30)
      (listeners
       (list (unix-listener-configuration (path "auth-userdb")))))
     (service-configuration (kind "auth-worker"))
     (service-configuration (kind "dict")
      (listeners (list (unix-listener-configuration (path "dict")))))))
   "List of services to enable.  Available services include @samp{imap},
@samp{imap-login}, @samp{pop3}, @samp{pop3-login}, @samp{auth}, and
@samp{lmtp}.")

  (dict
   (dict-configuration (dict-configuration))
   "Dict configuration, as created by the @code{dict-configuration}
constructor.")

  (passdbs
   (passdb-configuration-list (list (passdb-configuration (driver "pam"))))
   "List of passdb configurations, each one created by the
@code{passdb-configuration} constructor.")

  (userdbs
   (userdb-configuration-list (list (userdb-configuration (driver "passwd"))))
   "List of userdb configurations, each one created by the
@code{userdb-configuration} constructor.")

  (plugin-configuration
   (plugin-configuration (plugin-configuration))
   "Plug-in configuration, created by the @code{plugin-configuration}
constructor.")

  (namespaces
   (list-of-namespace-configuration
    (list
     (namespace-configuration
      (name "inbox")
      (prefix "")
      (inbox? #t)
      (mailboxes
       (list
        (mailbox-configuration (name "Drafts") (special-use '("\\Drafts")))
        (mailbox-configuration (name "Junk") (special-use '("\\Junk")))
        (mailbox-configuration (name "Trash") (special-use '("\\Trash")))
        (mailbox-configuration (name "Sent") (special-use '("\\Sent")))
        (mailbox-configuration (name "Sent Messages") (special-use '("\\Sent")))
        (mailbox-configuration (name "Drafts") (special-use '("\\Drafts"))))))))
   "List of namespaces.  Each item in the list is created by the
@code{namespace-configuration} constructor.")

  (base-dir
   (file-name "/var/run/dovecot/")
   "Base directory where to store runtime data.")

  (login-greeting
   (string "Dovecot ready.")
   "Greeting message for clients.")

  (login-trusted-networks
   (space-separated-string-list '())
   "List of trusted network ranges.  Connections from these IPs are
allowed to override their IP addresses and ports (for logging and for
authentication checks).  @samp{disable-plaintext-auth} is also ignored
for these networks.  Typically you'd specify your IMAP proxy servers
here.")

  (login-access-sockets
   (space-separated-string-list '())
   "List of login access check sockets (e.g. tcpwrap).")

  (verbose-proctitle?
   (boolean #f)
   "Show more verbose process titles (in ps).  Currently shows user name
and IP address.  Useful for seeing who are actually using the IMAP
processes (e.g. shared mailboxes or if same uid is used for multiple
accounts).")

  (shutdown-clients?
   (boolean #t)
   "Should all processes be killed when Dovecot master process shuts down.
Setting this to @code{#f} means that Dovecot can be upgraded without
forcing existing client connections to close (although that could also
be a problem if the upgrade is e.g. because of a security fix).")

  (doveadm-worker-count
   (non-negative-integer 0)
   "If non-zero, run mail commands via this many connections to doveadm
server, instead of running them directly in the same process.")

  (doveadm-socket-path
   (string "doveadm-server")
   "UNIX socket or host:port used for connecting to doveadm server.")

  (import-environment
   (space-separated-string-list '("TZ"))
   "List of environment variables that are preserved on Dovecot startup
and passed down to all of its child processes.  You can also give
key=value pairs to always set specific settings.")

;;; Authentication processes

  (disable-plaintext-auth?
   (boolean #t)
   "Disable LOGIN command and all other plaintext authentications unless
SSL/TLS is used (LOGINDISABLED capability).  Note that if the remote IP
matches the local IP (i.e. you're connecting from the same computer),
the connection is considered secure and plaintext authentication is
allowed.  See also ssl=required setting.")

  (auth-cache-size
   (non-negative-integer 0)
   "Authentication cache size (e.g. @samp{#e10e6}).  0 means it's disabled.
Note that bsdauth, PAM and vpopmail require @samp{cache-key} to be set
for caching to be used.")

  (auth-cache-ttl
   (string "1 hour")
   "Time to live for cached data.  After TTL expires the cached record
is no longer used, *except* if the main database lookup returns internal
failure.  We also try to handle password changes automatically: If
user's previous authentication was successful, but this one wasn't, the
cache isn't used.  For now this works only with plaintext
authentication.")

  (auth-cache-negative-ttl
   (string "1 hour")
   "TTL for negative hits (user not found, password mismatch).
0 disables caching them completely.")

  (auth-realms
   (space-separated-string-list '())
   "List of realms for SASL authentication mechanisms that need them.
You can leave it empty if you don't want to support multiple realms.
Many clients simply use the first one listed here, so keep the default
realm first.")

  (auth-default-realm
   (string "")
   "Default realm/domain to use if none was specified.  This is used for
both SASL realms and appending @@domain to username in plaintext
logins.")

  (auth-username-chars
   (string
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@")
   "List of allowed characters in username.  If the user-given username
contains a character not listed in here, the login automatically fails.
This is just an extra check to make sure user can't exploit any
potential quote escaping vulnerabilities with SQL/LDAP databases.  If
you want to allow all characters, set this value to empty.")

  (auth-username-translation
   (string "")
   "Username character translations before it's looked up from
databases.  The value contains series of from -> to characters.  For
example @samp{#@@/@@} means that @samp{#} and @samp{/} characters are
translated to @samp{@@}.")

  (auth-username-format
   (string "%Lu")
   "Username formatting before it's looked up from databases.  You can
use the standard variables here, e.g. %Lu would lowercase the username,
%n would drop away the domain if it was given, or @samp{%n-AT-%d} would
change the @samp{@@} into @samp{-AT-}.  This translation is done after
@samp{auth-username-translation} changes.")

  (auth-master-user-separator
   (string "")
   "If you want to allow master users to log in by specifying the master
username within the normal username string (i.e. not using SASL
mechanism's support for it), you can specify the separator character
here.  The format is then <username><separator><master username>.
UW-IMAP uses @samp{*} as the separator, so that could be a good
choice.")

  (auth-anonymous-username
   (string "anonymous")
   "Username to use for users logging in with ANONYMOUS SASL
mechanism.")

  (auth-worker-max-count
   (non-negative-integer 30)
   "Maximum number of dovecot-auth worker processes.  They're used to
execute blocking passdb and userdb queries (e.g. MySQL and PAM).
They're automatically created and destroyed as needed.")

  (auth-gssapi-hostname
   (string "")
   "Host name to use in GSSAPI principal names.  The default is to use
the name returned by gethostname().  Use @samp{$ALL} (with quotes) to
allow all keytab entries.")

  (auth-krb5-keytab
   (string "")
   "Kerberos keytab to use for the GSSAPI mechanism.  Will use the
system default (usually /etc/krb5.keytab) if not specified.  You may
need to change the auth service to run as root to be able to read this
file.")

  (auth-use-winbind?
   (boolean #f)
   "Do NTLM and GSS-SPNEGO authentication using Samba's winbind daemon
and @samp{ntlm-auth} helper.
<doc/wiki/Authentication/Mechanisms/Winbind.txt>.")

  (auth-winbind-helper-path
   (file-name "/usr/bin/ntlm_auth")
   "Path for Samba's @samp{ntlm-auth} helper binary.")

  (auth-failure-delay
   (string "2 secs")
   "Time to delay before replying to failed authentications.")

  (auth-ssl-require-client-cert?
   (boolean #f)
   "Require a valid SSL client certificate or the authentication
fails.")

  (auth-ssl-username-from-cert?
   (boolean #f)
   "Take the username from client's SSL certificate, using
@code{X509_NAME_get_text_by_NID()} which returns the subject's DN's
CommonName.")

  (auth-mechanisms
   (space-separated-string-list '("plain"))
   "List of wanted authentication mechanisms.  Supported mechanisms are:
@samp{plain}, @samp{login}, @samp{digest-md5}, @samp{cram-md5},
@samp{ntlm}, @samp{rpa}, @samp{apop}, @samp{anonymous}, @samp{gssapi},
@samp{otp}, @samp{skey}, and @samp{gss-spnego}.  NOTE: See also
@samp{disable-plaintext-auth} setting.")

  (director-servers
   (space-separated-string-list '())
   "List of IPs or hostnames to all director servers, including ourself.
Ports can be specified as ip:port.  The default port is the same as what
director service's @samp{inet-listener} is using.")

  (director-mail-servers
   (space-separated-string-list '())
   "List of IPs or hostnames to all backend mail servers.  Ranges are
allowed too, like 10.0.0.10-10.0.0.30.")

  (director-user-expire
   (string "15 min")
   "How long to redirect users to a specific server after it no longer
has any connections.")

  (director-doveadm-port
   (non-negative-integer 0)
   "TCP/IP port that accepts doveadm connections (instead of director
connections) If you enable this, you'll also need to add
@samp{inet-listener} for the port.")

  (director-username-hash
   (string "%Lu")
   "How the username is translated before being hashed.  Useful values
include %Ln if user can log in with or without @@domain, %Ld if mailboxes
are shared within domain.")

;;; Log destination.

  (log-path
   (string "syslog")
   "Log file to use for error messages.  @samp{syslog} logs to syslog,
@samp{/dev/stderr} logs to stderr.")

  (info-log-path
   (string "")
   "Log file to use for informational messages.  Defaults to
@samp{log-path}.")

  (debug-log-path
   (string "")
   "Log file to use for debug messages.  Defaults to
@samp{info-log-path}.")

  (syslog-facility
   (string "mail")
   "Syslog facility to use if you're logging to syslog.  Usually if you
don't want to use @samp{mail}, you'll use local0..local7.  Also other
standard facilities are supported.")

  (auth-verbose?
   (boolean #f)
   "Log unsuccessful authentication attempts and the reasons why they
failed.")

  (auth-verbose-passwords?
   (boolean #f)
   "In case of password mismatches, log the attempted password.  Valid
values are no, plain and sha1.  sha1 can be useful for detecting brute
force password attempts vs.  user simply trying the same password over
and over again.  You can also truncate the value to n chars by appending
\":n\" (e.g. sha1:6).")

  (auth-debug?
   (boolean #f)
   "Even more verbose logging for debugging purposes.  Shows for example
SQL queries.")

  (auth-debug-passwords?
   (boolean #f)
   "In case of password mismatches, log the passwords and used scheme so
the problem can be debugged.  Enabling this also enables
@samp{auth-debug}.")

  (mail-debug?
   (boolean #f)
   "Enable mail process debugging.  This can help you figure out why
Dovecot isn't finding your mails.")

  (verbose-ssl?
   (boolean #f)
   "Show protocol level SSL errors.")

  (log-timestamp
   (string "\"%b %d %H:%M:%S \"")
   "Prefix for each line written to log file.  % codes are in
strftime(3) format.")

  (login-log-format-elements
   (space-separated-string-list
    '("user=<%u>" "method=%m" "rip=%r" "lip=%l" "mpid=%e" "%c"))
   "List of elements we want to log.  The elements which have a
non-empty variable value are joined together to form a comma-separated
string.")

  (login-log-format
   (string "%$: %s")
   "Login log format.  %s contains @samp{login-log-format-elements}
string, %$ contains the data we want to log.")

  (mail-log-prefix
   (string "\"%s(%u): \"")
   "Log prefix for mail processes.  See doc/wiki/Variables.txt for list
of possible variables you can use.")

  (deliver-log-format
   (string "msgid=%m: %$")
   "Format to use for logging mail deliveries.  You can use variables:
@table @code
@item %$
Delivery status message (e.g. @samp{saved to INBOX})
@item %m
Message-ID
@item %s
Subject
@item %f
From address
@item %p
Physical size
@item %w
Virtual size.
@end table")

;;; Mailbox locations and namespaces

  (mail-location
   (string "")
   "Location for users' mailboxes.  The default is empty, which means
that Dovecot tries to find the mailboxes automatically.  This won't work
if the user doesn't yet have any mail, so you should explicitly tell
Dovecot the full location.

If you're using mbox, giving a path to the INBOX
file (e.g. /var/mail/%u) isn't enough.  You'll also need to tell Dovecot
where the other mailboxes are kept.  This is called the \"root mail
directory\", and it must be the first path given in the
@samp{mail-location} setting.

There are a few special variables you can use, eg.:

@table @samp
@item %u
username
@item %n
user part in user@@domain, same as %u if there's no domain
@item %d
domain part in user@@domain, empty if there's no domain
@item %h
home director
@end table

See doc/wiki/Variables.txt for full list.  Some examples:
@table @samp
@item maildir:~/Maildir
@item mbox:~/mail:INBOX=/var/mail/%u
@item mbox:/var/mail/%d/%1n/%n:INDEX=/var/indexes/%d/%1n/%
@end table")

  (mail-uid
   (string "")
   "System user and group used to access mails.  If you use multiple,
userdb can override these by returning uid or gid fields.  You can use
either numbers or names.  <doc/wiki/UserIds.txt>.")

  (mail-gid
   (string "")
   "")

  (mail-privileged-group
   (string "")
   "Group to enable temporarily for privileged operations.  Currently
this is used only with INBOX when either its initial creation or
dotlocking fails.  Typically this is set to \"mail\" to give access to
/var/mail.")

  (mail-access-groups
   (string "")
   "Grant access to these supplementary groups for mail processes.
Typically these are used to set up access to shared mailboxes.  Note
that it may be dangerous to set these if users can create
symlinks (e.g. if \"mail\" group is set here, ln -s /var/mail ~/mail/var
could allow a user to delete others' mailboxes, or ln -s
/secret/shared/box ~/mail/mybox would allow reading it).")

  (mail-full-filesystem-access?
   (boolean #f)
   "Allow full filesystem access to clients.  There's no access checks
other than what the operating system does for the active UID/GID.  It
works with both maildir and mboxes, allowing you to prefix mailboxes
names with e.g. /path/ or ~user/.")

;;; Mail processes

  (mmap-disable?
   (boolean #f)
   "Don't use mmap() at all.  This is required if you store indexes to
shared filesystems (NFS or clustered filesystem).")

  (dotlock-use-excl?
   (boolean #t)
   "Rely on @samp{O_EXCL} to work when creating dotlock files.  NFS
supports @samp{O_EXCL} since version 3, so this should be safe to use
nowadays by default.")

  (mail-fsync
   (string "optimized")
   "When to use fsync() or fdatasync() calls:
@table @code
@item optimized
Whenever necessary to avoid losing important data
@item always
Useful with e.g. NFS when write()s are delayed
@item never
Never use it (best performance, but crashes can lose data).
@end table")

  (mail-nfs-storage?
   (boolean #f)
   "Mail storage exists in NFS.  Set this to yes to make Dovecot flush
NFS caches whenever needed.  If you're using only a single mail server
this isn't needed.")

  (mail-nfs-index?
   (boolean #f)
   "Mail index files also exist in NFS.  Setting this to yes requires
@samp{mmap-disable? #t} and @samp{fsync-disable? #f}.")

  (lock-method
   (string "fcntl")
   "Locking method for index files.  Alternatives are fcntl, flock and
dotlock.  Dotlocking uses some tricks which may create more disk I/O
than other locking methods.  NFS users: flock doesn't work, remember to
change @samp{mmap-disable}.")

  (mail-temp-dir
   (file-name "/tmp")
   "Directory in which LDA/LMTP temporarily stores incoming mails >128
kB.")

  (first-valid-uid
   (non-negative-integer 500)
   "Valid UID range for users.  This is mostly to make sure that users can't
log in as daemons or other system users.  Note that denying root logins is
hardcoded to dovecot binary and can't be done even if @samp{first-valid-uid}
is set to 0.")

  (last-valid-uid
   (non-negative-integer 0)
   "")

  (first-valid-gid
   (non-negative-integer 1)
   "Valid GID range for users.  Users having non-valid GID as primary group ID
aren't allowed to log in.  If user belongs to supplementary groups with
non-valid GIDs, those groups are not set.")

  (last-valid-gid
   (non-negative-integer 0)
   "")

  (mail-max-keyword-length
   (non-negative-integer 50)
   "Maximum allowed length for mail keyword name.  It's only forced when
trying to create new keywords.")

  (valid-chroot-dirs
   (colon-separated-file-name-list '())
   "List of directories under which chrooting is allowed for mail
processes (i.e. /var/mail will allow chrooting to /var/mail/foo/bar
too).  This setting doesn't affect @samp{login-chroot}
@samp{mail-chroot} or auth chroot settings.  If this setting is empty,
\"/./\" in home dirs are ignored.  WARNING: Never add directories here
which local users can modify, that may lead to root exploit.  Usually
this should be done only if you don't allow shell access for users.
<doc/wiki/Chrooting.txt>.")

  (mail-chroot
   (string "")
   "Default chroot directory for mail processes.  This can be overridden
for specific users in user database by giving /./ in user's home
directory (e.g. /home/./user chroots into /home).  Note that usually
there is no real need to do chrooting, Dovecot doesn't allow users to
access files outside their mail directory anyway.  If your home
directories are prefixed with the chroot directory, append \"/.\" to
@samp{mail-chroot}.  <doc/wiki/Chrooting.txt>.")

  (auth-socket-path
   (file-name "/var/run/dovecot/auth-userdb")
   "UNIX socket path to master authentication server to find users.
This is used by imap (for shared users) and lda.")

  (mail-plugin-dir
   (file-name "/usr/lib/dovecot")
   "Directory where to look up mail plugins.")

  (mail-plugins
   (space-separated-string-list '())
   "List of plugins to load for all services.  Plugins specific to IMAP,
LDA, etc. are added to this list in their own .conf files.")


  (mail-cache-min-mail-count
   (non-negative-integer 0)
   "The minimum number of mails in a mailbox before updates are done to
cache file.  This allows optimizing Dovecot's behavior to do less disk
writes at the cost of more disk reads.")

  (mailbox-idle-check-interval
   (string "30 secs")
   "When IDLE command is running, mailbox is checked once in a while to
see if there are any new mails or other changes.  This setting defines
the minimum time to wait between those checks.  Dovecot can also use
dnotify, inotify and kqueue to find out immediately when changes
occur.")

  (mail-save-crlf?
   (boolean #f)
   "Save mails with CR+LF instead of plain LF.  This makes sending those
mails take less CPU, especially with sendfile() syscall with Linux and
FreeBSD.  But it also creates a bit more disk I/O which may just make it
slower.  Also note that if other software reads the mboxes/maildirs,
they may handle the extra CRs wrong and cause problems.")

  (maildir-stat-dirs?
   (boolean #f)
   "By default LIST command returns all entries in maildir beginning
with a dot.  Enabling this option makes Dovecot return only entries
which are directories.  This is done by stat()ing each entry, so it
causes more disk I/O.
 (For systems setting struct @samp{dirent->d_type} this check is free
and it's done always regardless of this setting).")

  (maildir-copy-with-hardlinks?
   (boolean #t)
   "When copying a message, do it with hard links whenever possible.
This makes the performance much better, and it's unlikely to have any
side effects.")

  (maildir-very-dirty-syncs?
   (boolean #f)
   "Assume Dovecot is the only MUA accessing Maildir: Scan cur/
directory only when its mtime changes unexpectedly or when we can't find
the mail otherwise.")

  (mbox-read-locks
   (space-separated-string-list '("fcntl"))
   "Which locking methods to use for locking mbox.  There are four
available:

@table @code
@item dotlock
Create <mailbox>.lock file.  This is the oldest and most NFS-safe
solution.  If you want to use /var/mail/ like directory, the users will
need write access to that directory.
@item dotlock-try
Same as dotlock, but if it fails because of permissions or because there
isn't enough disk space, just skip it.
@item fcntl
Use this if possible.  Works with NFS too if lockd is used.
@item flock
May not exist in all systems.  Doesn't work with NFS. 
@item lockf
May not exist in all systems.  Doesn't work with NFS.
@end table

You can use multiple locking methods; if you do the order they're declared
in is important to avoid deadlocks if other MTAs/MUAs are using multiple
locking methods as well.  Some operating systems don't allow using some of
them simultaneously.")

  (mbox-write-locks
   (space-separated-string-list '("dotlock" "fcntl"))
   "")

  (mbox-lock-timeout
   (string "5 mins")
   "Maximum time to wait for lock (all of them) before aborting.")

  (mbox-dotlock-change-timeout
   (string "2 mins")
   "If dotlock exists but the mailbox isn't modified in any way,
override the lock file after this much time.")

  (mbox-dirty-syncs?
   (boolean #t)
   "When mbox changes unexpectedly we have to fully read it to find out
what changed.  If the mbox is large this can take a long time.  Since
the change is usually just a newly appended mail, it'd be faster to
simply read the new mails.  If this setting is enabled, Dovecot does
this but still safely fallbacks to re-reading the whole mbox file
whenever something in mbox isn't how it's expected to be.  The only real
downside to this setting is that if some other MUA changes message
flags, Dovecot doesn't notice it immediately.  Note that a full sync is
done with SELECT, EXAMINE, EXPUNGE and CHECK commands.")

  (mbox-very-dirty-syncs?
   (boolean #f)
   "Like @samp{mbox-dirty-syncs}, but don't do full syncs even with SELECT,
EXAMINE, EXPUNGE or CHECK commands.  If this is set,
@samp{mbox-dirty-syncs} is ignored.")

  (mbox-lazy-writes?
   (boolean #t)
   "Delay writing mbox headers until doing a full write sync (EXPUNGE
and CHECK commands and when closing the mailbox).  This is especially
useful for POP3 where clients often delete all mails.  The downside is
that our changes aren't immediately visible to other MUAs.")

  (mbox-min-index-size
   (non-negative-integer 0)
   "If mbox size is smaller than this (e.g. 100k), don't write index
files.  If an index file already exists it's still read, just not
updated.")

  (mdbox-rotate-size
   (non-negative-integer #e2e6)
   "Maximum dbox file size until it's rotated.")

  (mdbox-rotate-interval
   (string "1d")
   "Maximum dbox file age until it's rotated.  Typically in days.  Day
begins from midnight, so 1d = today, 2d = yesterday, etc.  0 = check
disabled.")

  (mdbox-preallocate-space?
   (boolean #f)
   "When creating new mdbox files, immediately preallocate their size to
@samp{mdbox-rotate-size}.  This setting currently works only in Linux
with some filesystems (ext4, xfs).")

  (mail-attachment-dir
   (string "")
   "sdbox and mdbox support saving mail attachments to external files,
which also allows single instance storage for them.  Other backends
don't support this for now.

WARNING: This feature hasn't been tested much yet.  Use at your own risk.

Directory root where to store mail attachments.  Disabled, if empty.")

  (mail-attachment-min-size
   (non-negative-integer #e128e3)
   "Attachments smaller than this aren't saved externally.  It's also
possible to write a plugin to disable saving specific attachments
externally.")

  (mail-attachment-fs
   (string "sis posix")
   "Filesystem backend to use for saving attachments:
@table @code
@item posix
No SiS done by Dovecot (but this might help FS's own deduplication)
@item sis posix
SiS with immediate byte-by-byte comparison during saving
@item sis-queue posix
SiS with delayed comparison and deduplication.
@end table")

  (mail-attachment-hash
   (string "%{sha1}")
   "Hash format to use in attachment filenames.  You can add any text and
variables: @code{%@{md4@}}, @code{%@{md5@}}, @code{%@{sha1@}},
@code{%@{sha256@}}, @code{%@{sha512@}}, @code{%@{size@}}.  Variables can be
truncated, e.g. @code{%@{sha256:80@}} returns only first 80 bits.")

  (default-process-limit
    (non-negative-integer 100)
    "")

  (default-client-limit
    (non-negative-integer 1000)
    "")

  (default-vsz-limit
    (non-negative-integer #e256e6)
    "Default VSZ (virtual memory size) limit for service processes.
This is mainly intended to catch and kill processes that leak memory
before they eat up everything.")

  (default-login-user
    (string "dovenull")
    "Login user is internally used by login processes.  This is the most
untrusted user in Dovecot system.  It shouldn't have access to anything
at all.")

  (default-internal-user
    (string "dovecot")
    "Internal user is used by unprivileged processes.  It should be
separate from login user, so that login processes can't disturb other
processes.")

  (ssl?
   (string "required")
   "SSL/TLS support: yes, no, required.  <doc/wiki/SSL.txt>.")

  (ssl-cert
   (string "</etc/dovecot/default.pem")
   "PEM encoded X.509 SSL/TLS certificate (public key).")

  (ssl-key
   (string "</etc/dovecot/private/default.pem")
   "PEM encoded SSL/TLS private key.  The key is opened before
dropping root privileges, so keep the key file unreadable by anyone but
root.")

  (ssl-key-password
   (string "")
   "If key file is password protected, give the password here.
Alternatively give it when starting dovecot with -p parameter.  Since
this file is often world-readable, you may want to place this setting
instead to a different.")

  (ssl-ca
   (string "")
   "PEM encoded trusted certificate authority.  Set this only if you
intend to use @samp{ssl-verify-client-cert? #t}.  The file should
contain the CA certificate(s) followed by the matching
CRL(s).  (e.g. @samp{ssl-ca </etc/ssl/certs/ca.pem}).")
  (ssl-require-crl?
   (boolean #t)
   "Require that CRL check succeeds for client certificates.")
  (ssl-verify-client-cert?
   (boolean #f)
   "Request client to send a certificate.  If you also want to require
it, set @samp{auth-ssl-require-client-cert? #t} in auth section.")

  (ssl-cert-username-field
   (string "commonName")
   "Which field from certificate to use for username.  commonName and
x500UniqueIdentifier are the usual choices.  You'll also need to set
@samp{auth-ssl-username-from-cert? #t}.")

  (ssl-parameters-regenerate
   (hours 168)
   "How often to regenerate the SSL parameters file.  Generation is
quite CPU intensive operation.  The value is in hours, 0 disables
regeneration entirely.")

  (ssl-protocols
   (string "!SSLv2")
   "SSL protocols to use.")

  (ssl-cipher-list
   (string "ALL:!LOW:!SSLv2:!EXP:!aNULL")
   "SSL ciphers to use.")

  (ssl-crypto-device
   (string "")
   "SSL crypto device to use, for valid values run \"openssl engine\".")

  (postmaster-address
   (string "")
   "Address to use when sending rejection mails.
Default is postmaster@@<your domain>.  %d expands to recipient domain.")

  (hostname
   (string "")
   "Hostname to use in various parts of sent mails (e.g. in Message-Id)
and in LMTP replies.  Default is the system's real hostname@@domain.")

  (quota-full-tempfail?
   (boolean #f)
   "If user is over quota, return with temporary failure instead of
bouncing the mail.")

  (sendmail-path
   (file-name "/usr/sbin/sendmail")
   "Binary to use for sending mails.")

  (submission-host
   (string "")
   "If non-empty, send mails via this SMTP host[:port] instead of
sendmail.")

  (rejection-subject
   (string "Rejected: %s")
   "Subject: header to use for rejection mails.  You can use the same
variables as for @samp{rejection-reason} below.")

  (rejection-reason
   (string "Your message to <%t> was automatically rejected:%n%r")
   "Human readable error message for rejection mails.  You can use
variables:

@table @code
@item %n
CRLF
@item %r
reason
@item %s
original subject
@item %t
recipient
@end table")

  (recipient-delimiter
   (string "+")
   "Delimiter character between local-part and detail in email
address.")

  (lda-original-recipient-header
   (string "")
   "Header where the original recipient address (SMTP's RCPT TO:
address) is taken from if not available elsewhere.  With dovecot-lda -a
parameter overrides this.  A commonly used header for this is
X-Original-To.")

  (lda-mailbox-autocreate?
   (boolean #f)
   "Should saving a mail to a nonexistent mailbox automatically create
it?.")

  (lda-mailbox-autosubscribe?
   (boolean #f)
   "Should automatically created mailboxes be also automatically
subscribed?.")


  (imap-max-line-length
   (non-negative-integer #e64e3)
   "Maximum IMAP command line length.  Some clients generate very long
command lines with huge mailboxes, so you may need to raise this if you
get \"Too long argument\" or \"IMAP command line too large\" errors
often.")

  (imap-logout-format
   (string "in=%i out=%o")
   "IMAP logout format string:
@table @code
@item %i
total number of bytes read from client
@item %o
total number of bytes sent to client.
@end table")

  (imap-capability
   (string "")
   "Override the IMAP CAPABILITY response.  If the value begins with '+',
add the given capabilities on top of the defaults (e.g. +XFOO XBAR).")

  (imap-idle-notify-interval
   (string "2 mins")
   "How long to wait between \"OK Still here\" notifications when client
is IDLEing.")

  (imap-id-send
   (string "")
   "ID field names and values to send to clients.  Using * as the value
makes Dovecot use the default value.  The following fields have default
values currently: name, version, os, os-version, support-url,
support-email.")

  (imap-id-log
   (string "")
   "ID fields sent by client to log.  * means everything.")

  (imap-client-workarounds
   (space-separated-string-list '())
   "Workarounds for various client bugs:

@table @code
@item delay-newmail
Send EXISTS/RECENT new mail notifications only when replying to NOOP and
CHECK commands.  Some clients ignore them otherwise, for example OSX
Mail (<v2.1).  Outlook Express breaks more badly though, without this it
may show user \"Message no longer in server\" errors.  Note that OE6
still breaks even with this workaround if synchronization is set to
\"Headers Only\".

@item tb-extra-mailbox-sep
Thunderbird gets somehow confused with LAYOUT=fs (mbox and dbox) and
adds extra @samp{/} suffixes to mailbox names.  This option causes Dovecot to
ignore the extra @samp{/} instead of treating it as invalid mailbox name.

@item tb-lsub-flags
Show \\Noselect flags for LSUB replies with LAYOUT=fs (e.g. mbox).
This makes Thunderbird realize they aren't selectable and show them
greyed out, instead of only later giving \"not selectable\" popup error.
@end table
")

  (imap-urlauth-host
   (string "")
   "Host allowed in URLAUTH URLs sent by client.  \"*\" allows all.")  )

(define-configuration opaque-dovecot-configuration
  (dovecot
   (package dovecot)
   "The dovecot package.")

  (string
   (string (dovecot-configuration-missing-field 'opaque-dovecot-configuration
                                                'string))
   "The contents of the @code{dovecot.conf} to use."))

(define %dovecot-accounts
  ;; Account and group for the Dovecot daemon.
  (list (user-group (name "dovecot") (system? #t))
        (user-account
         (name "dovecot")
         (group "dovecot")
         (system? #t)
         (comment "Dovecot daemon user")
         (home-directory "/var/empty")
         (shell #~(string-append #$shadow "/sbin/nologin")))

        (user-group (name "dovenull") (system? #t))
        (user-account
         (name "dovenull")
         (group "dovenull")
         (system? #t)
         (comment "Dovecot daemon login user")
         (home-directory "/var/empty")
         (shell #~(string-append #$shadow "/sbin/nologin")))))

(define %dovecot-activation
  ;; Activation gexp.
  #~(begin
      (use-modules (guix build utils))
      (define (mkdir-p/perms directory owner perms)
        (mkdir-p directory)
        (chown "/var/run/dovecot" (passwd:uid owner) (passwd:gid owner))
        (chmod directory perms))
      (define (build-subject parameters)
        (string-concatenate
         (map (lambda (pair)
                (let ((k (car pair)) (v (cdr pair)))
                  (define (escape-char str chr)
                    (string-join (string-split str chr) (string #\\ chr)))
                  (string-append "/" k "="
                                 (escape-char (escape-char v #\=) #\/))))
              (filter (lambda (pair) (cdr pair)) parameters))))
      (define* (create-self-signed-certificate-if-absent
                #:key private-key public-key (owner (getpwnam "root"))
                (common-name (gethostname))
                (organization-name "GuixSD")
                (organization-unit-name "Default Self-Signed Certificate")
                (subject-parameters `(("CN" . ,common-name)
                                      ("O" . ,organization-name)
                                      ("OU" . ,organization-unit-name)))
                (subject (build-subject subject-parameters)))
        ;; Note that by default, OpenSSL outputs keys in PEM format.  This
        ;; is what we want.
        (unless (file-exists? private-key)
          (cond
           ((zero? (system* (string-append #$openssl "/bin/openssl")
                            "genrsa" "-out" private-key "2048"))
            (chown private-key (passwd:uid owner) (passwd:gid owner))
            (chmod private-key #o400))
           (else
            (format (current-error-port)
                    "Failed to create private key at ~a.\n" private-key))))
        (unless (file-exists? public-key)
          (cond
           ((zero? (system* (string-append #$openssl "/bin/openssl")
                            "req" "-new" "-x509" "-key" private-key
                            "-out" public-key "-days" "3650"
                            "-batch" "-subj" subject))
            (chown public-key (passwd:uid owner) (passwd:gid owner))
            (chmod public-key #o444))
           (else
            (format (current-error-port)
                    "Failed to create public key at ~a.\n" public-key)))))
      (let ((user (getpwnam "dovecot")))
        (mkdir-p/perms "/var/run/dovecot" user #o755)
        (mkdir-p/perms "/var/lib/dovecot" user #o755)
        (mkdir-p/perms "/etc/dovecot" user #o755)
        (mkdir-p/perms "/etc/dovecot/private" user #o700)
        (create-self-signed-certificate-if-absent
         #:private-key "/etc/dovecot/private/default.pem"
         #:public-key "/etc/dovecot/default.pem"
         #:owner (getpwnam "root")
         #:common-name (format #f "Dovecot service on ~a" (gethostname))))))

(define (dovecot-shepherd-service config)
  "Return a list of <shepherd-service> for CONFIG."
  (let* ((config-str
          (cond
           ((opaque-dovecot-configuration? config)
            (opaque-dovecot-configuration-string config))
           (else
            (with-output-to-string
              (lambda ()
                (serialize-configuration config
                                         dovecot-configuration-fields))))))
         (config-file (plain-file "dovecot.conf" config-str))
         (dovecot (if (opaque-dovecot-configuration? config)
                      (opaque-dovecot-configuration-dovecot config)
                      (dovecot-configuration-dovecot config))))
    (list (shepherd-service
           (documentation "Run the Dovecot POP3/IMAP mail server.")
           (provision '(dovecot))
           (requirement '(networking))
           (start #~(make-forkexec-constructor
                     (list (string-append #$dovecot "/sbin/dovecot")
                           "-F" "-c" #$config-file)))
           (stop #~(make-forkexec-constructor
                    (list (string-append #$dovecot "/sbin/dovecot")
                          "-c" #$config-file "stop")))))))

(define %dovecot-pam-services
  (list (unix-pam-service "dovecot")))

(define dovecot-service-type
  (service-type (name 'dovecot)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          dovecot-shepherd-service)
                       (service-extension account-service-type
                                          (const %dovecot-accounts))
                       (service-extension pam-root-service-type
                                          (const %dovecot-pam-services))
                       (service-extension activation-service-type
                                          (const %dovecot-activation))))))

(define* (dovecot-service #:key (config (dovecot-configuration)))
  "Return a service that runs @command{dovecot}, a mail server that can run
POP3, IMAP, and LMTP.  @var{config} should be a configuration object created
by @code{dovecot-configuration}.  @var{config} may also be created by
@code{opaque-dovecot-configuration}, which allows specification of the
@code{dovecot.conf} as a string."
  (validate-configuration config
                          (if (opaque-dovecot-configuration? config)
                              opaque-dovecot-configuration-fields
                              dovecot-configuration-fields))
  (service dovecot-service-type config))

;; A little helper to make it easier to document all those fields.
(define (generate-documentation)
  (define documentation
    `((dovecot-configuration
       ,dovecot-configuration-fields
       (dict dict-configuration)
       (namespaces namespace-configuration)
       (plugin plugin-configuration)
       (passdbs passdb-configuration)
       (userdbs userdb-configuration)
       (services service-configuration)
       (protocols protocol-configuration))
      (dict-configuration ,dict-configuration-fields)
      (plugin-configuration ,plugin-configuration-fields)
      (passdb-configuration ,passdb-configuration-fields)
      (userdb-configuration ,userdb-configuration-fields)
      (unix-listener-configuration ,unix-listener-configuration-fields)
      (fifo-listener-configuration ,fifo-listener-configuration-fields)
      (inet-listener-configuration ,inet-listener-configuration-fields)
      (namespace-configuration
       ,namespace-configuration-fields
       (mailboxes mailbox-configuration))
      (mailbox-configuration ,mailbox-configuration-fields)
      (service-configuration
       ,service-configuration-fields
       (listeners unix-listener-configuration fifo-listener-configuration
                  inet-listener-configuration))
      (protocol-configuration ,protocol-configuration-fields)))
  (define (generate configuration-name)
    (match (assq-ref documentation configuration-name)
      ((fields . sub-documentation)
       (format #t "\nAvailable @code{~a} fields are:\n\n" configuration-name)
       (for-each
        (lambda (f)
          (let ((field-name (configuration-field-name f))
                (field-type (configuration-field-type f))
                (field-docs (string-trim-both
                             (configuration-field-documentation f)))
                (default (catch #t
                           (configuration-field-default-value-thunk f)
                           (lambda _ 'nope))))
            (define (escape-chars str chars escape)
              (with-output-to-string
                (lambda ()
                  (string-for-each (lambda (c)
                                     (when (char-set-contains? chars c)
                                       (display escape))
                                     (display c))
                                   str))))
            (define (show-default? val)
              (or (string? default) (number? default) (boolean? default)
                  (and (list? val) (and-map show-default? val))))
            (format #t "@deftypevr {@code{~a} parameter} ~a ~a\n~a\n"
                    configuration-name field-type field-name field-docs)
            (when (show-default? default)
              (format #t "Defaults to @samp{~a}.\n"
                      (escape-chars (format #f "~s" default)
                                    (char-set #\@ #\{ #\})
                                    #\@)))
            (for-each generate (or (assq-ref sub-documentation field-name) '()))
            (format #t "@end deftypevr\n\n")))
        fields))))
  (generate 'dovecot-configuration))
