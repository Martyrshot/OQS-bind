/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * As a workaround, include an OpenSSL header file before including cmocka.h,
 * because OpenSSL 3.1.0 uses __attribute__(malloc), conflicting with a
 * redefined malloc in cmocka.h.
 */
#include <openssl/err.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/util.h>

#include "dst_internal.h"

#include <tests/dns.h>

static int
setup_test(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = dst_lib_init(mctx, NULL);

	if (result != ISC_R_SUCCESS) {
		return (1);
	}

	return (0);
}

static int
teardown_test(void **state) {
	UNUSED(state);

	dst_lib_destroy();

	return (0);
}

static unsigned char d[10] = { 0xa,  0x10, 0xbb, 0,    0xfe,
			       0x15, 0x1,  0x88, 0xcc, 0x7d };

static unsigned char sigsha1[256] = {
	0x45, 0x55, 0xd6, 0xf8, 0x05, 0xd2, 0x2e, 0x79, 0x14, 0x2b, 0x1b, 0xd1,
	0x4b, 0xb7, 0xcd, 0xc0, 0xa2, 0xf3, 0x85, 0x32, 0x1f, 0xa3, 0xfd, 0x1f,
	0x30, 0xe0, 0xde, 0xb2, 0x6f, 0x3c, 0x8e, 0x2b, 0x82, 0x92, 0xcd, 0x1c,
	0x1b, 0xdf, 0xe6, 0xd5, 0x4d, 0x93, 0xe6, 0xaa, 0x40, 0x28, 0x1b, 0x7b,
	0x2e, 0x40, 0x4d, 0xb5, 0x4d, 0x43, 0xe8, 0xfc, 0x93, 0x86, 0x68, 0xe3,
	0xbf, 0x73, 0x9a, 0x1e, 0x6b, 0x5d, 0x52, 0xb8, 0x98, 0x1c, 0x94, 0xe1,
	0x85, 0x8b, 0xee, 0xb1, 0x4f, 0x22, 0x71, 0xcb, 0xfd, 0xb2, 0xa8, 0x88,
	0x64, 0xb4, 0xb1, 0x4a, 0xa1, 0x7a, 0xce, 0x52, 0x83, 0xd8, 0xf2, 0x9e,
	0x67, 0x4c, 0xc3, 0x37, 0x74, 0xfe, 0xe0, 0x25, 0x2a, 0xfd, 0xa3, 0x09,
	0xff, 0x8a, 0x92, 0x0d, 0xa9, 0xb3, 0x90, 0x23, 0xbe, 0x6a, 0x2c, 0x9e,
	0x5c, 0x6d, 0xb4, 0xa7, 0xd7, 0x97, 0xdd, 0xc6, 0xb8, 0xae, 0xd4, 0x88,
	0x64, 0x63, 0x1e, 0x85, 0x20, 0x09, 0xea, 0xc4, 0x0b, 0xca, 0xbf, 0x83,
	0x5c, 0x89, 0xae, 0x64, 0x15, 0x76, 0x06, 0x51, 0xb6, 0xa1, 0x99, 0xb2,
	0x3c, 0x50, 0x99, 0x86, 0x7d, 0xc7, 0xca, 0x4e, 0x1d, 0x2c, 0x17, 0xbb,
	0x6c, 0x7a, 0xc9, 0x3f, 0x5e, 0x28, 0x57, 0x2c, 0xda, 0x01, 0x1d, 0xe8,
	0x01, 0xf8, 0xf6, 0x37, 0xe1, 0x34, 0x56, 0xae, 0x6e, 0xb1, 0xd4, 0xa2,
	0xc4, 0x02, 0xc1, 0xca, 0x96, 0xb0, 0x06, 0x72, 0x2a, 0x27, 0xaa, 0xc8,
	0xd5, 0x50, 0x81, 0x49, 0x46, 0x33, 0xf8, 0xf7, 0x6b, 0xf4, 0x9c, 0x30,
	0x90, 0x50, 0xf6, 0x16, 0x76, 0x9d, 0xc6, 0x73, 0xb5, 0xbc, 0x8a, 0xb6,
	0x1d, 0x98, 0xcb, 0xce, 0x36, 0x6f, 0x60, 0xec, 0x96, 0x49, 0x08, 0x85,
	0x5b, 0xc1, 0x8e, 0xb0, 0xea, 0x9e, 0x1f, 0xd6, 0x27, 0x7f, 0xb6, 0xe0,
	0x04, 0x12, 0xd2, 0x81
};

static unsigned char sigsha256[256] = {
	0x83, 0x53, 0x15, 0xfc, 0xca, 0xdb, 0xf6, 0x0d, 0x53, 0x24, 0x5b, 0x5a,
	0x8e, 0xd0, 0xbe, 0x5e, 0xbc, 0xe8, 0x9e, 0x92, 0x3c, 0xfa, 0x93, 0x03,
	0xce, 0x2f, 0xc7, 0x6d, 0xd0, 0xbb, 0x9d, 0x06, 0x83, 0xc6, 0xd3, 0xc0,
	0xc1, 0x57, 0x9c, 0x82, 0x17, 0x7f, 0xb5, 0xf8, 0x31, 0x18, 0xda, 0x46,
	0x05, 0x2c, 0xf8, 0xea, 0xaa, 0xcd, 0x99, 0x18, 0xff, 0x23, 0x5e, 0xef,
	0xf0, 0x87, 0x47, 0x6e, 0x91, 0xfd, 0x19, 0x0b, 0x39, 0x19, 0x6a, 0xc8,
	0xdf, 0x71, 0x66, 0x8e, 0xa9, 0xa0, 0x79, 0x5c, 0x2c, 0x52, 0x00, 0x61,
	0x17, 0x86, 0x66, 0x03, 0x52, 0xad, 0xec, 0x06, 0x53, 0xd9, 0x6d, 0xe3,
	0xe3, 0xea, 0x28, 0x15, 0xb3, 0x75, 0xf4, 0x61, 0x7d, 0xed, 0x69, 0x2c,
	0x24, 0xf3, 0x21, 0xb1, 0x8a, 0xea, 0x60, 0xa2, 0x9e, 0x6a, 0xa6, 0x53,
	0x12, 0xf6, 0x5c, 0xef, 0xd7, 0x49, 0x4a, 0x02, 0xe7, 0xf8, 0x64, 0x89,
	0x13, 0xac, 0xd5, 0x1e, 0x58, 0xff, 0xa1, 0x63, 0xdd, 0xa0, 0x1f, 0x44,
	0x99, 0x6a, 0x59, 0x7f, 0x35, 0xbd, 0xf1, 0xf3, 0x7a, 0x28, 0x44, 0xe3,
	0x4c, 0x68, 0xb1, 0xb3, 0x97, 0x3c, 0x46, 0xe3, 0xc2, 0x12, 0x9e, 0x68,
	0x0b, 0xa6, 0x6c, 0x8f, 0x58, 0x48, 0x44, 0xa4, 0xf7, 0xa7, 0xc2, 0x91,
	0x8f, 0xbf, 0x00, 0xd0, 0x01, 0x35, 0xd4, 0x86, 0x6e, 0x1f, 0xea, 0x42,
	0x60, 0xb1, 0x84, 0x27, 0xf4, 0x99, 0x36, 0x06, 0x98, 0x12, 0x83, 0x32,
	0x9f, 0xcd, 0x50, 0x5a, 0x5e, 0xb8, 0x8e, 0xfe, 0x8d, 0x8d, 0x33, 0x2d,
	0x45, 0xe1, 0xc9, 0xdf, 0x2a, 0xd8, 0x38, 0x1d, 0x95, 0xd4, 0x42, 0xee,
	0x93, 0x5b, 0x0f, 0x1e, 0x07, 0x06, 0x3a, 0x92, 0xf1, 0x59, 0x1d, 0x6e,
	0x1c, 0x31, 0xf3, 0xce, 0xa9, 0x1f, 0xad, 0x4d, 0x76, 0x4d, 0x24, 0x98,
	0xe2, 0x0e, 0x8c, 0x35
};

static unsigned char sigsha512[512] = {
	0x4e, 0x2f, 0x63, 0x42, 0xc5, 0xf3, 0x05, 0x4a, 0xa6, 0x3a, 0x93, 0xa0,
	0xd9, 0x33, 0xa0, 0xd1, 0x46, 0x33, 0x42, 0xe8, 0x74, 0xeb, 0x3b, 0x10,
	0x82, 0xd7, 0xcf, 0x39, 0x23, 0xb3, 0xe9, 0x23, 0x53, 0x87, 0x8c, 0xee,
	0x78, 0xcb, 0xb3, 0xd9, 0xd2, 0x6d, 0x1a, 0x7c, 0x01, 0x4f, 0xed, 0x8d,
	0xf2, 0x72, 0xe4, 0x6a, 0x00, 0x8a, 0x60, 0xa6, 0xd5, 0x9c, 0x43, 0x6c,
	0xef, 0x38, 0x0c, 0x74, 0x82, 0x5d, 0x22, 0xaa, 0x87, 0x81, 0x90, 0x9c,
	0x64, 0x07, 0x9b, 0x13, 0x51, 0xe0, 0xa5, 0xc2, 0x83, 0x78, 0x2b, 0x9b,
	0xb3, 0x8a, 0x9d, 0x36, 0x33, 0xbd, 0x0d, 0x53, 0x84, 0xae, 0xe8, 0x13,
	0x36, 0xf6, 0xdf, 0x96, 0xe9, 0xda, 0xc3, 0xd7, 0xa9, 0x2f, 0xf3, 0x5e,
	0x5f, 0x1f, 0x7f, 0x38, 0x7e, 0x8d, 0xbe, 0x90, 0x5e, 0x13, 0xb2, 0x20,
	0xbb, 0x9d, 0xfe, 0xe1, 0x52, 0xce, 0xe6, 0x80, 0xa7, 0x95, 0x24, 0x59,
	0xe3, 0xac, 0x24, 0xc4, 0xfa, 0x1c, 0x44, 0x34, 0x29, 0x8d, 0xb1, 0xd0,
	0xd9, 0x4c, 0xff, 0xc4, 0xdb, 0xca, 0xc4, 0x3f, 0x38, 0xf9, 0xe4, 0xaf,
	0x75, 0x0a, 0x67, 0x4d, 0xa0, 0x2b, 0xb0, 0x83, 0xce, 0x53, 0xc4, 0xb9,
	0x2e, 0x61, 0xb6, 0x64, 0xe5, 0xb5, 0xe5, 0xac, 0x9d, 0x51, 0xec, 0x58,
	0x42, 0x90, 0x78, 0xf6, 0x46, 0x96, 0xef, 0xb6, 0x97, 0xb7, 0x54, 0x28,
	0x1a, 0x4c, 0x29, 0xf4, 0x7a, 0x33, 0xc6, 0x07, 0xfd, 0xec, 0x97, 0x36,
	0x1d, 0x42, 0x88, 0x94, 0x27, 0xc2, 0xa3, 0xe1, 0xd4, 0x87, 0xa1, 0x8a,
	0x2b, 0xff, 0x47, 0x60, 0xfe, 0x1f, 0xaf, 0xc2, 0xeb, 0x17, 0xdd, 0x56,
	0xc5, 0x94, 0x5c, 0xcb, 0x23, 0xe5, 0x49, 0x4d, 0x99, 0x06, 0x02, 0x5a,
	0xfc, 0xfc, 0xdc, 0xee, 0x49, 0xbc, 0x47, 0x60, 0xff, 0x6a, 0x63, 0x8b,
	0xe1, 0x2e, 0xa3, 0xa7
};

/* RSA verify */
ISC_RUN_TEST_IMPL(isc_rsa_verify) {
	isc_result_t ret;
	dns_fixedname_t fname;
	isc_buffer_t buf;
	dns_name_t *name;
	dst_key_t *key = NULL;
	dst_context_t *ctx = NULL;
	isc_region_t r;

	UNUSED(state);

	name = dns_fixedname_initname(&fname);
	isc_buffer_constinit(&buf, "rsa.", 4);
	isc_buffer_add(&buf, 4);
	ret = dns_name_fromtext(name, &buf, NULL, 0, NULL);
	assert_int_equal(ret, ISC_R_SUCCESS);

	ret = dst_key_fromfile(name, 29238, DST_ALG_RSASHA256, DST_TYPE_PUBLIC,
			       TESTS_DIR, mctx, &key);
	assert_int_equal(ret, ISC_R_SUCCESS);

	/* RSASHA1 - May not be supported by the OS */
	if (dst_algorithm_supported(DST_ALG_RSASHA1)) {
		key->key_alg = DST_ALG_RSASHA1;

		ret = dst_context_create(key, mctx, DNS_LOGCATEGORY_DNSSEC,
					 false, 0, &ctx);
		assert_int_equal(ret, ISC_R_SUCCESS);

		r.base = d;
		r.length = 10;
		ret = dst_context_adddata(ctx, &r);
		assert_int_equal(ret, ISC_R_SUCCESS);

		r.base = sigsha1;
		r.length = 256;
		ret = dst_context_verify(ctx, &r);
		assert_int_equal(ret, ISC_R_SUCCESS);

		dst_context_destroy(&ctx);
	}

	/* RSASHA256 */

	key->key_alg = DST_ALG_RSASHA256;

	ret = dst_context_create(key, mctx, DNS_LOGCATEGORY_DNSSEC, false, 0,
				 &ctx);
	assert_int_equal(ret, ISC_R_SUCCESS);

	r.base = d;
	r.length = 10;
	ret = dst_context_adddata(ctx, &r);
	assert_int_equal(ret, ISC_R_SUCCESS);

	r.base = sigsha256;
	r.length = 256;
	ret = dst_context_verify(ctx, &r);
	assert_int_equal(ret, ISC_R_SUCCESS);

	dst_context_destroy(&ctx);

	/* RSASHA512 */

	key->key_alg = DST_ALG_RSASHA512;

	ret = dst_context_create(key, mctx, DNS_LOGCATEGORY_DNSSEC, false, 0,
				 &ctx);
	assert_int_equal(ret, ISC_R_SUCCESS);

	r.base = d;
	r.length = 10;
	ret = dst_context_adddata(ctx, &r);
	assert_int_equal(ret, ISC_R_SUCCESS);

	r.base = sigsha512;
	r.length = 256;
	ret = dst_context_verify(ctx, &r);
	assert_int_equal(ret, ISC_R_SUCCESS);

	dst_context_destroy(&ctx);

	dst_key_free(&key);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(isc_rsa_verify, setup_test, teardown_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN
