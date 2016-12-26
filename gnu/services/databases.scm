;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 David Thompson <davet@gnu.org>
;;; Copyright © 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
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

(define-module (gnu services databases)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu system shadow)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages databases)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (ice-9 match)
  #:export (postgresql-configuration
            postgresql-configuration?
            postgresql-service
            postgresql-service-type

            mysql-service
            mysql-service-type
            mysql-configuration
            mysql-configuration?))

;;; Commentary:
;;;
;;; Database services.
;;;
;;; Code:

(define-record-type* <postgresql-configuration>
  postgresql-configuration make-postgresql-configuration
  postgresql-configuration?
  (postgresql     postgresql-configuration-postgresql ;<package>
                  (default postgresql))
  (port           postgresql-configuration-port
                  (default 5432))
  (locale         postgresql-configuration-locale
                  (default "en_US.utf8"))
  (config-file    postgresql-configuration-file)
  (data-directory postgresql-configuration-data-directory))

(define %default-postgres-hba
  (plain-file "pg_hba.conf"
              "
local	all	all			trust
host	all	all	127.0.0.1/32 	trust
host	all	all	::1/128 	trust"))

(define %default-postgres-ident
  (plain-file "pg_ident.conf"
             "# MAPNAME       SYSTEM-USERNAME         PG-USERNAME"))

(define %default-postgres-config
  (mixed-text-file "postgresql.conf"
                   "log_destination = 'syslog'\n"
                   "hba_file = '" %default-postgres-hba "'\n"
                   "ident_file = '" %default-postgres-ident "'\n"))

(define %postgresql-accounts
  (list (user-group (name "postgres") (system? #t))
        (user-account
         (name "postgres")
         (group "postgres")
         (system? #t)
         (comment "PostgreSQL server user")
         (home-directory "/var/empty")
         (shell (file-append shadow "/sbin/nologin")))))

(define postgresql-activation
  (match-lambda
    (($ <postgresql-configuration> postgresql port locale config-file data-directory)
     #~(begin
         (use-modules (guix build utils)
                      (ice-9 match))

         (let ((user (getpwnam "postgres"))
               (initdb (string-append #$postgresql "/bin/initdb"))
               (initdb-args
                (append
                 (if #$locale
                     (list (string-append "--locale=" #$locale))
                     '()))))
           ;; Create db state directory.
           (mkdir-p #$data-directory)
           (chown #$data-directory (passwd:uid user) (passwd:gid user))

           ;; Drop privileges and init state directory in a new
           ;; process.  Wait for it to finish before proceeding.
           (match (primitive-fork)
             (0
              ;; Exit with a non-zero status code if an exception is thrown.
              (dynamic-wind
                (const #t)
                (lambda ()
                  (setgid (passwd:gid user))
                  (setuid (passwd:uid user))
                  (primitive-exit
                   (apply system*
                          initdb
                          "-D"
                          #$data-directory
                          initdb-args)))
                (lambda ()
                  (primitive-exit 1))))
             (pid (waitpid pid))))))))

(define postgresql-shepherd-service
  (match-lambda
    (($ <postgresql-configuration> postgresql port locale config-file data-directory)
     (let ((start-script
            ;; Wrapper script that switches to the 'postgres' user before
            ;; launching daemon.
            (program-file "start-postgres"
                          #~(let ((user (getpwnam "postgres"))
                                  (postgres (string-append #$postgresql
                                                           "/bin/postgres")))
                              (setgid (passwd:gid user))
                              (setuid (passwd:uid user))
                              (system* postgres
                                       (string-append "--config-file="
                                                      #$config-file)
                                       "-p" (number->string #$port)
                                       "-D" #$data-directory)))))
       (list (shepherd-service
              (provision '(postgres))
              (documentation "Run the PostgreSQL daemon.")
              (requirement '(user-processes loopback syslogd))
              (start #~(make-forkexec-constructor #$start-script))
              (stop #~(make-kill-destructor))))))))

(define postgresql-service-type
  (service-type (name 'postgresql)
                (extensions
                 (list (service-extension shepherd-root-service-type
                                          postgresql-shepherd-service)
                       (service-extension activation-service-type
                                          postgresql-activation)
                       (service-extension account-service-type
                                          (const %postgresql-accounts))))))

(define* (postgresql-service #:key (postgresql postgresql)
                             (port 5432)
                             (locale "en_US.utf8")
                             (config-file %default-postgres-config)
                             (data-directory "/var/lib/postgresql/data"))
  "Return a service that runs @var{postgresql}, the PostgreSQL database server.

The PostgreSQL daemon loads its runtime configuration from @var{config-file}
and stores the database cluster in @var{data-directory}."
  (service postgresql-service-type
           (postgresql-configuration
            (postgresql postgresql)
            (port port)
            (locale locale)
            (config-file config-file)
            (data-directory data-directory))))


;;;
;;; MySQL.
;;;

(define-record-type* <mysql-configuration>
  mysql-configuration make-mysql-configuration
  mysql-configuration?
  (mysql mysql-configuration-mysql (default mariadb))
  (port mysql-configuration-port (default 3306)))

(define %mysql-accounts
  (list (user-group
         (name "mysql")
         (system? #t))
        (user-account
         (name "mysql")
         (group "mysql")
         (system? #t)
         (home-directory "/var/empty")
         (shell (file-append shadow "/sbin/nologin")))))

(define mysql-configuration-file
  (match-lambda
    (($ <mysql-configuration> mysql port)
     (mixed-text-file "my.cnf" "[mysqld]
datadir=/var/lib/mysql
socket=/run/mysqld/mysqld.sock
port=" (number->string port) "
"))))

(define (%mysql-activation config)
  "Return an activation gexp for the MySQL or MariaDB database server."
  (let ((mysql  (mysql-configuration-mysql config))
        (my.cnf (mysql-configuration-file config)))
    #~(begin
        (use-modules (ice-9 popen)
                     (guix build utils))
        (let* ((mysqld  (string-append #$mysql "/bin/mysqld"))
               (user    (getpwnam "mysql"))
               (uid     (passwd:uid user))
               (gid     (passwd:gid user))
               (datadir "/var/lib/mysql")
               (rundir  "/run/mysqld"))
          (mkdir-p datadir)
          (chown datadir uid gid)
          (mkdir-p rundir)
          (chown rundir uid gid)
          ;; Initialize the database when it doesn't exist.
          (when (not (file-exists? (string-append datadir "/mysql")))
            (if (string-prefix? "mysql-" (strip-store-file-name #$mysql))
                ;; For MySQL.
                (system* mysqld
                         (string-append "--defaults-file=" #$my.cnf)
                         "--initialize"
                         "--user=mysql")
                ;; For MariaDB.
                ;; XXX: The 'mysql_install_db' script doesn't work directly
                ;;      due to missing 'mkdir' in PATH.
                (let ((p (open-pipe* OPEN_WRITE mysqld
                                     (string-append
                                      "--defaults-file=" #$my.cnf)
                                     "--bootstrap"
                                     "--user=mysql")))
                  ;; Create the system database, as does by 'mysql_install_db'.
                  (display "create database mysql;\n" p)
                  (display "use mysql;\n" p)
                  (for-each
                   (lambda (sql)
                     (call-with-input-file
                         (string-append #$mysql "/share/mysql/" sql)
                       (lambda (in) (dump-port in p))))
                   '("mysql_system_tables.sql"
                     "mysql_performance_tables.sql"
                     "mysql_system_tables_data.sql"
                     "fill_help_tables.sql"))
                  ;; Remove the anonymous user and disable root access from
                  ;; remote machines, as does by 'mysql_secure_installation'.
                  (display "
DELETE FROM user WHERE User='';
DELETE FROM user WHERE User='root' AND
  Host NOT IN  ('localhost', '127.0.0.1', '::1');
FLUSH PRIVILEGES;
" p)
                  (close-pipe p))))))))

(define (mysql-shepherd-service config)
  (list (shepherd-service
         (provision '(mysql))
         (documentation "Run the MySQL server.")
         (start (let ((mysql  (mysql-configuration-mysql config))
                      (my.cnf (mysql-configuration-file config)))
                  #~(make-forkexec-constructor
                     (list (string-append #$mysql "/bin/mysqld")
                           (string-append "--defaults-file=" #$my.cnf))
                     #:user "mysql" #:group "mysql")))
         (stop #~(make-kill-destructor)))))

(define mysql-service-type
  (service-type
   (name 'mysql)
   (extensions
    (list (service-extension account-service-type
                             (const %mysql-accounts))
          (service-extension activation-service-type
                             %mysql-activation)
          (service-extension shepherd-root-service-type
                             mysql-shepherd-service)))))

(define* (mysql-service #:key (config (mysql-configuration)))
  "Return a service that runs @command{mysqld}, the MySQL or MariaDB
database server.

The optional @var{config} argument specifies the configuration for
@command{mysqld}, which should be a @code{<mysql-configuration>} object."
  (service mysql-service-type config))
