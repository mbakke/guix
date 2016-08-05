# GNU Guix --- Functional package management for GNU
# Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
#
# This file is part of GNU Guix.
#
# GNU Guix is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or (at
# your option) any later version.
#
# GNU Guix is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

#
# Test the 'guix-register' command-line utility.
#

guix-register --version

new_store="t-register-$$"
closure="t-register-closure-$$"
rm -rf "$new_store"

exit_hook=":"
trap "chmod -R +w $new_store ; rm -rf $new_store $closure ; \$exit_hook" EXIT

#
# Registering items in the current store---i.e., without '--prefix'.
#

new_file="$NIX_STORE_DIR/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-guix-register-$$"
echo "Fake store file to test registration." > "$new_file"

# Register the file with zero references and no deriver.
guix-register <<EOF
$new_file

0
EOF

# Register an idendical file, and make sure it gets deduplicated.
new_file2="$new_file-duplicate"
cat "$new_file" > "$new_file2"
guix-register <<EOF
$new_file2

0
EOF

guile -c "
  (exit (= (stat:ino (stat \"$new_file\"))
           (stat:ino (stat \"$new_file2\"))))"

# Make sure both are valid.
guile -c "
   (use-modules (guix store))
   (define s (open-connection))
   (exit (and (valid-path? s \"$new_file\")
              (valid-path? s \"$new_file2\")
              (null? (references s \"$new_file\"))
              (null? (references s \"$new_file2\"))))"


#
# Registering items in a new store, with '--prefix'.
#

mkdir -p "$new_store/$storedir"
new_store_dir="`cd "$new_store/$storedir" ; pwd -P`"
new_store="`cd "$new_store" ; pwd -P`"

to_copy="`guix build guile-bootstrap`"
cp -r "$to_copy" "$new_store_dir"
copied="$new_store_dir/`basename $to_copy`"

# Create a file representing a closure with zero references, and with an empty
# "deriver" field.  Note that we give the file name as it appears in the
# original store, and 'guix-register' translates it to match the prefix.
cat >> "$closure" <<EOF
$to_copy

0
EOF

# Register it.
guix-register -p "$new_store" < "$closure"

# Doing it a second time shouldn't hurt.
guix-register --prefix "$new_store" "$closure"

# Same, but with the database stored in a different place.
guix-register -p "$new_store" \
    --state-directory "$new_store/chbouib" "$closure"

# Register duplicate files.
cp "$new_file" "$new_file2" "$new_store_dir"
guix-register -p "$new_store" <<EOF
$new_file

0
EOF
guix-register -p "$new_store" <<EOF
$new_file2

0
EOF

copied_duplicate1="$new_store_dir/`basename $new_file`"
copied_duplicate2="$new_store_dir/`basename $new_file2`"

# Make sure there is indeed deduplication under $new_store and that there are
# no cross-store hard links.
guile -c "
  (exit (and (= (stat:ino (stat \"$copied_duplicate1\"))
                (stat:ino (stat \"$copied_duplicate2\")))
             (not (= (stat:ino (stat \"$new_file\"))
                     (stat:ino (stat \"$copied_duplicate1\"))))))"

# Delete them.
guix gc -d "$new_file" "$new_file2"

# Now make sure this is recognized as valid.

ls -R "$new_store"
for state_dir in "$localstatedir/guix" "/chbouib"
do
    NIX_STORE_DIR="$new_store_dir"
    NIX_STATE_DIR="$new_store$state_dir"
    NIX_LOG_DIR="$new_store$state_dir/log/guix"
    NIX_DB_DIR="$new_store$state_dir/db"
    GUIX_DAEMON_SOCKET="$NIX_STATE_DIR/daemon-socket/socket"

    export NIX_IGNORE_SYMLINK_STORE NIX_STORE_DIR NIX_STATE_DIR	\
	   NIX_LOG_DIR NIX_DB_DIR GUIX_DAEMON_SOCKET

    # Check whether we overflow the limitation on local socket name lengths.
    if [ `echo "$GUIX_DAEMON_SOCKET" | wc -c` -ge 108 ]
    then
	# Mark the test as skipped even though we already did some work so
	# that the remainder is not silently skipped.
	exit 77
    fi

    guix-daemon --disable-chroot &
    subdaemon_pid=$!
    exit_hook="kill $subdaemon_pid"

    final_name="$storedir/`basename $to_copy`"

    # At this point the copy in $new_store must be valid, and unreferenced.
    # The database under $NIX_DB_DIR uses the $final_name, but we can't use
    # that name in a 'valid-path?' query because 'assertStorePath' would kill
    # us because of the wrong prefix.  So we just list dead paths instead.
    guile -c "
      (use-modules (guix store) (srfi srfi-1) (srfi srfi-34))

      (define s
        (let loop ((i 5))
          (guard (c ((nix-connection-error? c)
                     (if (<= i 0)
                         (raise c)
                         (begin
                           (display \"waiting for daemon socket...\")
                           (newline)
                           (sleep 1)
                           (loop (- i 1))))))
             (open-connection \"$GUIX_DAEMON_SOCKET\"))))

      (exit (lset= string=?
                   (pk 1 (list \"$copied\" \"$copied_duplicate1\"
                               \"$copied_duplicate2\"))
                   (pk 2 (dead-paths s))))"

    # Kill the daemon so we can access the database below (otherwise we may
    # get "database is locked" errors.)
    kill $subdaemon_pid
    exit_hook=":"
    while kill -0 $subdaemon_pid ; do sleep 0.5 ; done

    # When 'sqlite3' is available, check the name in the database.
    if type -P sqlite3
    then
	echo "select * from ValidPaths where path=\"$final_name\";" | \
	    sqlite3 "$NIX_DB_DIR/db.sqlite"
    fi
done
