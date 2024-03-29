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

#
# Clean up after tsig tests.
#

rm -f dig.out.*
rm -f */named.memstats
rm -f */named.conf
rm -f ns1/named-fips.conf
rm -f */named.run
rm -f ns*/named.lock
rm -f Kexample.net.*
rm -f keygen.out?
rm -f ns*/managed-keys.bind*
rm -f packet.out
