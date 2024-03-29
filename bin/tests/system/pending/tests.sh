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

set -e

. ../conf.sh

# replace_data dname RR old_data new_data
replace_data()
{
	if [ $# -ne 4 ]; then
		echo_i "unexpected input for replace_data"
		return 1
	fi

	_dname=$1
	_rr=$2
	_olddata=$3
	_newdata=$4

	_ret=0
	$NSUPDATE -d <<END >> nsupdate.out.test 2>&1 || _ret=1
server 10.53.0.2 ${PORT}
update delete ${_dname} 30 ${_rr} ${_olddata}
update add ${_dname} 30 ${_rr} ${_newdata}
send
END

	if [ $_ret != 0 ]; then
		echo_i "failed to update the test data"
		return 1
	fi

	return 0
}

status=0
n=0

DIGOPTS="+short +tcp -p ${PORT}"
DIGOPTS_CD="$DIGOPTS +cd"

echo_i "Priming cache."
ret=0
expect="10 mail.example."
ans=$($DIG $DIGOPTS_CD @10.53.0.4 hostile MX) || ret=1
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

echo_i "Checking that bogus additional is not returned with +CD."
ret=0
expect="10.0.0.2"
ans=$($DIG $DIGOPTS_CD @10.53.0.4 mail.example A) || ret=1
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

#
# Prime cache with pending additional records.  These should not be promoted
# to answer.
#
echo_i "Priming cache (pending additional A and AAAA)"
ret=0
expect="10 mail.example.com."
ans=$($DIG $DIGOPTS @10.53.0.4 example.com MX) || ret=1
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

echo_i "Replacing pending A"
ret=0
replace_data mail.example.com. A 192.0.2.2 192.0.2.3 || ret=1
status=$((status + ret))

echo_i "Replacing pending AAAA"
ret=0
replace_data mail.example.com. AAAA 2001:db8::2 2001:db8::3 || ret=1
status=$((status + ret))

echo_i "Checking updated data to be returned (without CD)"
ret=0
expect="192.0.2.3"
ans=$($DIG $DIGOPTS @10.53.0.4 mail.example.com A) || ret=1
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

echo_i "Checking updated data to be returned (with CD)"
ret=0
expect="2001:db8::3"
ans=$($DIG $DIGOPTS_CD @10.53.0.4 mail.example.com AAAA) || ret=1
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

#
# Prime cache with a pending answer record.  It can be returned (without
# validation) with +CD.
#
echo_i "Priming cache (pending answer)"
ret=0
expect="192.0.2.2"
ans=$($DIG $DIGOPTS_CD @10.53.0.4 pending-ok.example.com A) || ret=1
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

echo_i "Replacing pending data"
ret=0
replace_data pending-ok.example.com. A 192.0.2.2 192.0.2.3 || ret=1
status=$((status + ret))

echo_i "Confirming cached pending data to be returned with CD"
ret=0
expect="192.0.2.2"
ans=$($DIG $DIGOPTS_CD @10.53.0.4 pending-ok.example.com A) || ret=1
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

#
# Prime cache with a pending answer record.  It should not be returned
# to no-DNSSEC clients.
#
echo_i "Priming cache (pending answer)"
ret=0
expect="192.0.2.102"
ans=$($DIG $DIGOPTS_CD @10.53.0.4 pending-ng.example.com A) || ret=1
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

echo_i "Replacing pending data"
ret=0
replace_data pending-ng.example.com. A 192.0.2.102 192.0.2.103 || ret=1
status=$((status + ret))

echo_i "Confirming updated data returned, not the cached one, without CD"
ret=0
expect="192.0.2.103"
ans=$($DIG $DIGOPTS @10.53.0.4 pending-ng.example.com A) || ret=1
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

#
# Try to fool the resolver with an out-of-bailiwick CNAME
#
echo_i "Trying to Prime out-of-bailiwick pending answer with CD"
ret=0
expect="10.10.10.10"
ans=$($DIG $DIGOPTS_CD @10.53.0.4 bad.example. A) || ret=1
ans=$(echo $ans | awk '{print $NF}')
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

echo_i "Confirming the out-of-bailiwick answer is not cached or reused with CD"
ret=0
expect="10.10.10.10"
ans=$($DIG $DIGOPTS_CD @10.53.0.4 nice.good. A) || ret=1
ans=$(echo $ans | awk '{print $NF}')
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

#
# Make sure the resolver doesn't cache bogus NXDOMAIN
#
echo_i "Trying to Prime bogus NXDOMAIN"
ret=0
expect="SERVFAIL"
ans=$($DIG +tcp -p ${PORT} @10.53.0.4 removed.example.com. A) || ret=1
ans=$(echo $ans | sed 's/^.*status: \([A-Z][A-Z]*\).*$/\1/')
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

echo_i "Confirming the bogus NXDOMAIN was not cached"
ret=0
expect="SERVFAIL"
ans=$($DIG +tcp -p ${PORT} @10.53.0.4 removed.example.com. A) || ret=1
ans=$(echo $ans | sed 's/^.*status: \([A-Z][A-Z]*\).*$/\1/')
test "$ans" = "$expect" || ret=1
test $ret = 0 || echo_i "failed, got '$ans', expected '$expect'"
status=$((status + ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
