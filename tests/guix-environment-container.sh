# GNU Guix --- Functional package management for GNU
# Copyright © 2015 David Thompson <davet@gnu.org>
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
# Test 'guix environment'.
#

set -e

guix environment --version

if ! guile -c '((@@ (guix scripts environment) assert-container-features))'
then
    # User containers are not supported; skip this test.
    exit 77
fi

tmpdir="t-guix-environment-$$"
trap 'rm -r "$tmpdir"' EXIT

mkdir "$tmpdir"

# Make sure the exit value is preserved.
if guix environment --container --ad-hoc --bootstrap guile-bootstrap \
        -- guile -c '(exit 42)'
then
    false
else
    test $? = 42
fi

# Make sure that the right directories are mapped.
mount_test_code="
(use-modules (ice-9 rdelim)
             (ice-9 match)
             (srfi srfi-1))

(define mappings
  (filter-map (lambda (line)
                (match (string-split line #\space)
                  ;; Empty line.
                  ((\"\") #f)
                  ;; Ignore these types of file systems.
                  ((_ _ (or \"tmpfs\" \"proc\" \"sysfs\" \"devtmpfs\"
                            \"devpts\" \"cgroup\" \"mqueue\") _ _ _)
                   #f)
                  ((_ mount _ _ _ _)
                   mount)))
              (string-split (call-with-input-file \"/proc/mounts\" read-string)
                            #\newline)))

(for-each (lambda (mount)
            (display mount)
            (newline))
          mappings)"

guix environment --container --ad-hoc --bootstrap guile-bootstrap \
     -- guile -c "$mount_test_code" > $tmpdir/mounts

cat "$tmpdir/mounts"
test `wc -l < $tmpdir/mounts` -eq 4

current_dir="`cd $PWD; pwd -P`"
grep -e "$current_dir$" $tmpdir/mounts # current directory
grep $(guix build guile-bootstrap) $tmpdir/mounts
grep -e "$NIX_STORE_DIR/.*-bash" $tmpdir/mounts # bootstrap bash

rm $tmpdir/mounts

if guix environment --bootstrap --container \
	--ad-hoc bootstrap-binaries -- kill -SEGV 2
then false;
else
    test $? -gt 127
fi
