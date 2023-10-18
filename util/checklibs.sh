#!/bin/sh

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

status=0

#
# Check for missing #include <isc/strerr.h>
#
list=`git grep -wl strerror_r lib bin |
      grep '\.c$' |
      grep -vE -e '(lib/bind|lib/dns/rdata|lib/dns/gen.c)' \
	       -e lib/isc/string.c \
	       -e '(dlzexternal/driver.c)' |
      xargs grep -EL "(isc/strerr.h)" 2> /dev/null`
[ -n "$list" ] && {
    status=1
    echo 'Missing #include <isc/strerr.h>:'
    echo "$list"
}

#
# Check for missing #include <inttypes.h>"
#
list=`git grep -l uintptr_t lib bin |
      grep '\.c$' |
      grep -vE -e '(lib/bind|lib/dns/rdata|lib/dns/gen.c)' \
	       -e '(lib/isc/win32/time.c)' |
      xargs grep -L "<inttypes.h>"`
[ -n "$list" ] && {
    status=1
    echo 'Missing #include <inttypes.h>:'
    echo "$list"
}

exit $status
