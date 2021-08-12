/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <stdbool.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h> // Need to find out the falcon equiv... :(
#include <openssl/err.h>
#include <openssl/objects.h>
#if !defined(OPENSSL_NO_ENGINE)
#include <openssl/engine.h>
#endif

#include <isc/mem.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include <dst/result.h>

#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"

#ifndef NID_X9_62_prime256v1
#error "P-256 group is not known (NID_X9_62_prime256v1)"
#endif /* ifndef NID_X9_62_prime256v1 */
#ifndef NID_secp384r1
#error "P-384 group is not known (NID_secp384r1)"
#endif /* ifndef NID_secp384r1 */

#define FALCON512_PUBLICKEY_SIZE 897
#define FALCON512_PRIVATEKEY_SIZE 1281


#define DST_RET(a)        \
	{                 \
		ret = a;  \
		goto err; \
	}

//#if !HAVE_ECDSA_SIG_GET0
/* From OpenSSL 1.1 */
/*
static void
ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
	if (pr != NULL) {
		*pr = sig->r;
	}
	if (ps != NULL) {
		*ps = sig->s;
	}
}

static int
ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
	if (r == NULL || s == NULL) {
		return (0);
	}

	BN_clear_free(sig->r);
	BN_clear_free(sig->s);
	sig->r = r;
	sig->s = s;

	return (1);
} */
// #endif /* !HAVE_ECDSA_SIG_GET0 */
static bool
isprivate(EVP_PKEY *pkey) {
	int rc;
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	size_t size = DNS_SIG_FALCON512SIZE;
	unsigned char buff[size];
	rc = EVP_DigestSignInit(ctx, NULL, EVP_get_digestbynid(EVP_PKEY_FALCON512), NULL, pkey);
	if (rc != 1) {
		EVP_MD_CTX_free(ctx);
		return (dst__openssl_toresult2("EVP_DigestSignInit", DST_R_OPENSSLFAILURE));
	}
	rc = EVP_DigestUpdate(ctx, "FILLERMSG", 10);
	if (rc != 1) {
		EVP_MD_CTX_free(ctx);
		return (dst__openssl_toresult2("EVP_DigestUpdate", DST_R_OPENSSLFAILURE));
	}
	rc = EVP_DigestSignFinal(ctx, buff, &size);
	EVP_MD_CTX_free(ctx);
	return (rc == 1);
}

static isc_result_t
opensslfalcon512_createctx(dst_key_t *key, dst_context_t *dctx) {
	EVP_MD_CTX *evp_md_ctx;
	const EVP_MD *type = NULL;
	UNUSED(key);
	REQUIRE(dctx->key->key_alg == DST_ALG_FALCON512);
	EVP_PKEY *pkey = key->keydata.pkey;

	evp_md_ctx = EVP_MD_CTX_create();
	if (evp_md_ctx == NULL) {
		return (ISC_R_NOMEMORY);
	}
	type = EVP_get_digestbyname("falcon512");
	if (type == NULL) {
		return (dst__openssl_toresult3(dctx->category, "EVP_DIGEST_TYPE", ISC_R_FAILURE));
	}
	// What kind of key is this?
	// TODO This might break something, but assume if the key ***can***
	// sign things, that it will only every sign things
	// o.w. it will only verify things
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (isprivate(pkey)) {
		if (!EVP_DigestSignInit(evp_md_ctx, &pctx, type, NULL, pkey)) {
			EVP_MD_CTX_destroy(evp_md_ctx);
			return (dst__openssl_toresult3(
				dctx->category, "EVP_DigestInit_ex", ISC_R_FAILURE));
		}
	} else {
		if (!EVP_DigestVerifyInit(evp_md_ctx, &pctx, type, NULL, pkey)) {
			EVP_MD_CTX_destroy(evp_md_ctx);
			return (dst__openssl_toresult3(
				dctx->category, "EVP_DigestInit_ex", ISC_R_FAILURE));
		}

	}
/*
	if (!EVP_DigestInit_ex(evp_md_ctx, type, NULL)) {
		EVP_MD_CTX_destroy(evp_md_ctx);
		return (dst__openssl_toresult3(
			dctx->category, "EVP_DigestInit_ex", ISC_R_FAILURE));
	}
*/
	dctx->ctxdata.evp_md_ctx = evp_md_ctx;

	return (ISC_R_SUCCESS);
}

static void
opensslfalcon512_destroyctx(dst_context_t *dctx) {
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;

	REQUIRE(dctx->key->key_alg == DST_ALG_FALCON512);

	if (evp_md_ctx != NULL) {
		EVP_MD_CTX_destroy(evp_md_ctx);
		dctx->ctxdata.evp_md_ctx = NULL;
	}
}

static isc_result_t
opensslfalcon512_adddata(dst_context_t *dctx, const isc_region_t *data) {
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;

	REQUIRE(dctx->key->key_alg == DST_ALG_FALCON512);
	// DigestVerifyUpdate and DigestSignUpdate both are just typedef'd to DigestUpdate
	// So use the general one here
	if (!EVP_DigestUpdate(evp_md_ctx, data->base, data->length)) {
		return (dst__openssl_toresult3(
			dctx->category, "EVP_DigestUpdate", ISC_R_FAILURE));
	}

	return (ISC_R_SUCCESS);
}
/*
BN_bn2bin_fixed(const BIGNUM *bn, unsigned char *buf, int size) {
	int bytes = size - BN_num_bytes(bn);

	while (bytes-- > 0) {
		*buf++ = 0;
	}
	BN_bn2bin(bn, buf);
	return (size);
}
*/
static isc_result_t
opensslfalcon512_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_result_t ret;
	//dst_key_t *key = dctx->key;
	isc_region_t region;
	//ECDSA_SIG *ecdsasig; // TODO can this be replaced with a falcon specific sig?
	REQUIRE(dctx->key->key_alg == DST_ALG_FALCON512);
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
	//EVP_PKEY *pkey = key->keydata.pkey;
	//EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pkey); // TODO can this be replaced with a falcon specific key?
	size_t siglen;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned char *sigout = NULL;
//	const BIGNUM *r, *s; // need to figure out what the falcon512 equiv is

/*
	if (eckey == NULL) {
		return (ISC_R_FAILURE);
	}
*/
	// First let's do a sanity check that buffer will fit a signature up to DNS_SIGFLACON512SIZE
//	REQUIRE(siglen == DNS_SIG_FALCON512SIZE);
	EVP_DigestSignFinal(evp_md_ctx, NULL, &siglen);
	isc_buffer_availableregion(sig, &region);
	if (region.length < siglen) {
		DST_RET(ISC_R_NOSPACE);
	}

	if (!EVP_DigestSignFinal(evp_md_ctx, sigout, &siglen)) {
		DST_RET(dst__openssl_toresult3(
			dctx->category, "EVP_DigestFinal", ISC_R_FAILURE))
	}

	
/*	ECDSA_SIG_get0(ecdsasig, &r, &s);
	BN_bn2bin_fixed(r, region.base, siglen / 2);
	isc_region_consume(&region, siglen / 2);
	BN_bn2bin_fixed(s, region.base, siglen / 2);
	isc_region_consume(&region, siglen / 2);
	ECDSA_SIG_free(ecdsasig);
	isc_buffer_add(sig, siglen);
*/
	unsigned char *buff = region.base;
	for (unsigned long i = 0; i < siglen; i++) {
		buff[i] = 0;
	}

	memcpy(buff, digest, siglen);
	ret = ISC_R_SUCCESS;

err:
//	EC_KEY_free(eckey);
	return (ret);
}

static isc_result_t
opensslfalcon512_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	int status;
	//unsigned char *cp = sig->base;
	//ECDSA_SIG *ecdsasig = NULL; // TODO replace?
	REQUIRE(key->key_alg == DST_ALG_FALCON512);
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
	//EVP_PKEY *pkey = key->keydata.pkey;
	// EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pkey); // TODO replace?
	unsigned int siglen;
	//BIGNUM *r = NULL, *s = NULL;
/*
	if (eckey == NULL) {
		return (ISC_R_FAILURE);
	}
*/
	siglen = DNS_SIG_FALCON512SIZE;

	if (sig->length != siglen) {
		return (DST_R_VERIFYFAILURE);
	}


	status = EVP_DigestVerifyFinal(evp_md_ctx, sig->base, siglen);

	//ecdsasig = ECDSA_SIG_new(); // TODO replace
	//if (ecdsasig == NULL) {
	//	DST_RET(ISC_R_NOMEMORY);
	//}
	//r = BN_bin2bn(cp, siglen / 2, NULL);
	//cp += siglen / 2;
	//s = BN_bin2bn(cp, siglen / 2, NULL);
	//ECDSA_SIG_set0(ecdsasig, r, s);
	/* cp += siglen / 2; */

//	status = ECDSA_do_verify(digest, dgstlen, ecdsasig, eckey);
	switch (status) {
	case 1:
		ret = ISC_R_SUCCESS;
		break;
	case 0:
		ret = dst__openssl_toresult(DST_R_VERIFYFAILURE);
		break;
	default:
		ret = dst__openssl_toresult3(dctx->category, "ECDSA_do_verify",
					     DST_R_VERIFYFAILURE);
		break;
	}

	// TODO lookup how to free this stuff, if needed
	/*
	if (ecdsasig != NULL) {
		ECDSA_SIG_free(ecdsasig);
	}
	EC_KEY_free(eckey);
	*/
	return (ret);
}

static bool
opensslfalcon512_compare(const dst_key_t *key1, const dst_key_t *key2) {
	
	EVP_PKEY *pkey1 = key1->keydata.pkey;
	EVP_PKEY *pkey2 = key2->keydata.pkey;
	/*
	EC_KEY *eckey1 = NULL; // TODO replace
	EC_KEY *eckey2 = NULL; // TODO replace
	const BIGNUM *priv1, *priv2;

	if (pkey1 == NULL && pkey2 == NULL) {
		return (true);
	} else if (pkey1 == NULL || pkey2 == NULL) {
		return (false);
	}

	eckey1 = EVP_PKEY_get1_EC_KEY(pkey1); // TODO replace
	eckey2 = EVP_PKEY_get1_EC_KEY(pkey2); // TODO replace
	if (eckey1 == NULL && eckey2 == NULL) {
		DST_RET(true);
	} else if (eckey1 == NULL || eckey2 == NULL) {
		DST_RET(false);
	}

	status = EVP_PKEY_cmp(pkey1, pkey2);
	if (status != 1) {
		DST_RET(false);
	}

	priv1 = EC_KEY_get0_private_key(eckey1); // TODO might need to replace
	priv2 = EC_KEY_get0_private_key(eckey2); // TODO might need to replace
	if (priv1 != NULL || priv2 != NULL) {
		if (priv1 == NULL || priv2 == NULL) {
			DST_RET(false);
		}
		if (BN_cmp(priv1, priv2) != 0) {
			DST_RET(false);
		}
	}
	ret = true;

err:
	if (eckey1 != NULL) {
		EC_KEY_free(eckey1);
	}
	if (eckey2 != NULL) {
		EC_KEY_free(eckey2);
	}
	*/

	return (EVP_PKEY_cmp(pkey1, pkey2));
}

static isc_result_t
opensslfalcon512_generate(dst_key_t *key, int unused, void (*callback)(int)) {
	isc_result_t ret;
	EVP_PKEY *pkey = NULL;
	//EC_KEY *eckey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
	//int falcon512_nid;
	REQUIRE(key->key_alg == DST_ALG_FALCON512);
	UNUSED(unused);
	UNUSED(callback);
	key->key_size = DNS_KEY_FALCON512SIZE;
/*
	falcon512_nid = NID_falcon512;
	key->key_size = DNS_KEY_FALCON512SIZE * 4; //??????? Why 4?


	eckey = EC_KEY_new_by_curve_name(group_nid); // TODO replace
	if (eckey == NULL) {
		return (dst__openssl_toresult2("EC_KEY_new_by_curve_name",
					       DST_R_OPENSSLFAILURE));
	}

	if (EC_KEY_generate_key(eckey) != 1) {
		DST_RET(dst__openssl_toresult2("EC_KEY_generate_key",
					       DST_R_OPENSSLFAILURE));
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		DST_RET(ISC_R_NOMEMORY);
	}
	if (!EVP_PKEY_set1_EC_KEY(pkey, eckey)) {
		EVP_PKEY_free(pkey);
		DST_RET(ISC_R_FAILURE);
	}
	key->keydata.pkey = pkey;
	ret = ISC_R_SUCCESS;

err:
	EC_KEY_free(eckey);
	return (ret);
*/
	if ((pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_FALCON512, NULL)) == NULL) {
		return (dst__openssl_toresult2("EVP_PKEY_CTX_new_id",
							DST_R_OPENSSLFAILURE));
	}
	if (EVP_PKEY_keygen_init(pkctx) != 1) {
		return (dst__openssl_toresult2("EVP_PKEY_keygen_init",
							DST_R_OPENSSLFAILURE));
	}
	if (EVP_PKEY_keygen(pkctx, &pkey) != 1) {
		return (dst__openssl_toresult2("EVP_PKEY_keygen",
							DST_R_OPENSSLFAILURE));
	}
	key->keydata.pkey = pkey;
	ret = ISC_R_SUCCESS;
	EVP_PKEY_CTX_free(pkctx);
	return (ret);
}

static bool
opensslfalcon512_isprivate(const dst_key_t *key) {
	EVP_PKEY *pkey = key->keydata.pkey;
	return isprivate(pkey);
}

static void
opensslfalcon512_destroy(dst_key_t *key) {
	EVP_PKEY *pkey = key->keydata.pkey;
	if (key->keydata.pkey == NULL) printf("pkey is NULL\n");
	printf("In destroy...\n");
	EVP_PKEY_free(pkey);
	key->keydata.pkey = NULL;
}

static isc_result_t
opensslfalcon512_todns(const dst_key_t *key, isc_buffer_t *data) {
	EVP_PKEY *pkey = key->keydata.pkey;
	isc_region_t r;
	size_t len;

	REQUIRE(pkey != NULL);
	REQUIRE(key->key_alg == DST_ALG_FALCON512);
	len = DNS_KEY_FALCON512SIZE;
/*	if (key->key_alg == DST_ALG_ED25519) {
		len = DNS_KEY_ED25519SIZE;
	} else {
		len = DNS_KEY_ED448SIZE;
	}*/

	isc_buffer_availableregion(data, &r);
	if (r.length < len) {
		return (ISC_R_NOSPACE);
	}

	if (EVP_PKEY_get_raw_public_key(pkey, r.base, &len) != 1)
		return (dst__openssl_toresult(ISC_R_FAILURE));

	isc_buffer_add(data, len);
	return (ISC_R_SUCCESS);
/*	isc_result_t ret;
	EVP_PKEY *pkey;
//	EC_KEY *eckey = NULL;
	size_t publen = DNS_KEY_FALCON512SIZE;
	isc_region_t r;
	unsigned char buf[DNS_KEY_FALCON512SIZE];

	REQUIRE(key->keydata.pkey != NULL);
	pkey = key->keydata.pkey;
	//eckey = EVP_PKEY_get1_EC_KEY(pkey);
	//if (eckey == NULL) {
	//	return (dst__openssl_toresult(ISC_R_FAILURE));
	//}
	// Use new raw functions here
//	len = i2o_ECPublicKey(eckey, NULL);
	// skip form
//	len--;

	isc_buffer_availableregion(data, &r);
	if (r.length < (unsigned int)publen) {
		DST_RET(ISC_R_NOSPACE);
	}
//	if (!i2o_ECPublicKey(eckey, &cp)) {
//		DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
//	}
	if (!EVP_PKEY_get_raw_public_key(pkey, buf, &publen)) {
		DST_RET(DST_R_INVALIDPUBLICKEY);
	}
	memmove(r.base, buf, publen);
	isc_buffer_add(data, publen);
	ret = ISC_R_SUCCESS;

err:
//	EC_KEY_free(eckey);
	printf("in todns\n");
	return (ret); */
}
// TODO bugs in here!
static isc_result_t
opensslfalcon512_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_result_t ret;
	isc_region_t r;
	size_t len;
	EVP_PKEY *pkey;

	REQUIRE(key->key_alg == DST_ALG_FALCON512);

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return (ISC_R_SUCCESS);
	}

	len = r.length;
	if (len < DNS_KEY_FALCON512SIZE) {
		return (DST_R_INVALIDPUBLICKEY);
	}

	pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_FALCON512, NULL, r.base, len);
	if (pkey == NULL) {
		return (dst__openssl_toresult(DST_R_INVALIDPUBLICKEY));
	}

	isc_buffer_forward(data, len);
	key->keydata.pkey = pkey;
	key->key_size = len;
	return (ISC_R_SUCCESS);

/*
	printf("fromdns called\n");
	isc_result_t ret;
	EVP_PKEY *pkey;
	isc_region_t r;
	unsigned int len;
	unsigned char buf[DNS_KEY_FALCON512SIZE];

	REQUIRE(key->key_alg == DST_ALG_FALCON512);
	len = FALCON512_PUBLICKEY_SIZE;

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return (ISC_R_SUCCESS);
	}
	if (r.length < len) {
		return (DST_R_INVALIDPUBLICKEY);
	}

	memmove(buf, r.base, len);
	// set raw public key
	//if (o2i_ECPublicKey(&eckey, (const unsigned char **)&cp,
	//		    (long)len + 1) == NULL) {
	//	DST_RET(dst__openssl_toresult(DST_R_INVALIDPUBLICKEY));
	//}
	// Skiping snaity check, will need to add this back for production
	//if (EC_KEY_check_key(eckey) != 1) {
	//	DST_RET(dst__openssl_toresult(DST_R_INVALIDPUBLICKEY));
	//}

	//pkey = EVP_PKEY_new();
	//if (pkey == NULL) {
	//	DST_RET(ISC_R_NOMEMORY);
	//}
	//if (!EVP_PKEY_set1_EC_KEY(pkey, eckey)) {
	//	EVP_PKEY_free(pkey);
	//	DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
	//}
	pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_FALCON512, NULL, buf, len);
	if (pkey == NULL) {
		return (DST_R_INVALIDPUBLICKEY);
	}
	isc_buffer_forward(data, len);
	key->keydata.pkey = pkey;
	key->key_size = len; //may need to be *4, but I don't see why yet so leaving it as is
	ret = ISC_R_SUCCESS;

//	if (eckey != NULL) {
//		EC_KEY_free(eckey);
//	}
//
	return (ret);
*/
}

static isc_result_t
opensslfalcon512_tofile(const dst_key_t *key, const char *directory) {
	isc_result_t ret;
	dst_private_t priv;
	unsigned char *pubbuf = NULL;
	unsigned char *privbuf = NULL;
	size_t publen = FALCON512_PUBLICKEY_SIZE;
	size_t privlen = FALCON512_PRIVATEKEY_SIZE;
	int i;

	REQUIRE(key->key_alg == DST_ALG_FALCON512);

	if (key->keydata.pkey == NULL) {
		return (DST_R_NULLKEY);
	}

	if (key->external) {
		priv.nelements = 0;
		return (dst__privstruct_writefile(key, &priv, directory));
	}

	i = 0;

	if (opensslfalcon512_isprivate(key)) {
		privbuf = isc_mem_get(key->mctx, privlen);
		if (EVP_PKEY_get_raw_private_key(key->keydata.pkey, privbuf,
						 &privlen) != 1)
			DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
		priv.elements[i].tag = TAG_FALCON512_PRIVATEKEY;
		priv.elements[i].length = privlen;
		priv.elements[i].data = privbuf;
		i++;
		pubbuf = isc_mem_get(key->mctx, publen);
		if (EVP_PKEY_get_raw_public_key(key->keydata.pkey, pubbuf,
						 &publen) != 1)
			DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
		priv.elements[i].tag = TAG_FALCON512_PUBLICKEY;
		priv.elements[i].length = publen;
		priv.elements[i].data = pubbuf;
		i++;
	}
	/*
	if (key->engine != NULL) {
		priv.elements[i].tag = TAG_FALCON512_ENGINE;
		priv.elements[i].length = (unsigned short)strlen(key->engine) +
					  1;
		priv.elements[i].data = (unsigned char *)key->engine;
		i++;
	}
	if (key->label != NULL) {
		priv.elements[i].tag = TAG_FALCON512_LABEL;
		priv.elements[i].length = (unsigned short)strlen(key->label) +
					  1;
		priv.elements[i].data = (unsigned char *)key->label;
		i++;
	}
*/
	priv.nelements = i;
	ret = dst__privstruct_writefile(key, &priv, directory);

err:
	if (privbuf != NULL) {
		isc_mem_put(key->mctx, privbuf, privlen);
	}
	if (pubbuf != NULL) {
		isc_mem_put(key->mctx, pubbuf, publen);
	}
	return (ret);

	
/*
	isc_result_t ret;
	EVP_PKEY *pkey;
	dst_private_t priv;
	unsigned char *privkey = isc_mem_get(key->mctx, FALCON512_PRIVATEKEY_SIZE);
	unsigned char *pubkey = isc_mem_get(key->mctx, FALCON512_PUBLICKEY_SIZE);
	unsigned short i;

	if (key->keydata.pkey == NULL) {
		return (DST_R_NULLKEY);
	}

	if (key->external) {
		priv.nelements = 0;
		return (dst__privstruct_writefile(key, &priv, directory));
	}
	pkey = key->keydata.pkey;
//	eckey = EVP_PKEY_get1_EC_KEY(pkey);
//	if (eckey == NULL) {
//		return (dst__openssl_toresult(DST_R_OPENSSLFAILURE));
//	}
//	privkey = EC_KEY_get0_private_key(eckey);
	if (privkey == NULL) {
		ret = dst__openssl_toresult(DST_R_OPENSSLFAILURE);
		goto err;
	}

	privkey = isc_mem_get(key->mctx, FALCON512_PRIVATEKEY_SIZE);
	pubkey = isc_mem_get(key->mctx, FALCON512_PUBLICKEY_SIZE);
	size_t privlen = FALCON512_PRIVATEKEY_SIZE;
	size_t publen = FALCON512_PUBLICKEY_SIZE;
	i = 0;

	priv.elements[i].tag = TAG_FALCON512_PRIVATEKEY;
	priv.elements[i].length = FALCON512_PRIVATEKEY_SIZE;
	if (!EVP_PKEY_get_raw_private_key(pkey, privkey, &privlen)) {
		ret = dst__openssl_toresult(DST_R_OPENSSLFAILURE);
		goto err;
	}
//	BN_bn2bin(privkey, buf);
	// bug not using thier memory manager...
	priv.elements[i].data = privkey;
	i++;
	priv.elements[i].tag = TAG_FALCON512_PUBLICKEY;
	priv.elements[i].length = FALCON512_PUBLICKEY_SIZE;
	printf("here\n");
	if (!EVP_PKEY_get_raw_public_key(pkey, pubkey, &publen)) {
		ret = dst__openssl_toresult(DST_R_OPENSSLFAILURE);
		goto err;
	}
	priv.elements[i].data = pubkey;
// Also save public key for now, check if there is a nice function to derive public keys
// from oqs to make this cleaner

//	if (key->engine != NULL) {
//		priv.elements[i].tag = TAG_ECDSA_ENGINE;
//		priv.elements[i].length = (unsigned short)strlen(key->engine) +
//					  1;
//		priv.elements[i].data = (unsigned char *)key->engine;
//		i++;
//	}

//	if (key->label != NULL) {
//		priv.elements[i].tag = TAG_ECDSA_LABEL;
//		priv.elements[i].length = (unsigned short)strlen(key->label) +
					  1;
//		priv.elements[i].data = (unsigned char *)key->label;
//		i++;
//	}

	i++;
	priv.nelements = i;
	ret = dst__privstruct_writefile(key, &priv, directory);
	if (ISC_R_SUCCESS != ret) printf("failed to write file\n");
err:
//	EC_KEY_free(eckey);
	if (privkey != NULL) {
		isc_mem_put(key->mctx, privkey, FALCON512_PRIVATEKEY_SIZE);
	}
	if (pubkey != NULL) {
		isc_mem_put(key->mctx, pubkey, FALCON512_PUBLICKEY_SIZE);
	}
	return (ret);*/
}

typedef struct
{
  /* OpenSSL NID */
  int nid;
  /* OQS signature context */
  OQS_SIG *s;
  /* OQS public key */
  uint8_t *pubkey;
  /* OQS private key */
  uint8_t *privkey;
  /* Classical key pair for hybrid schemes; either a private or public key depending on context */
  EVP_PKEY *classical_pkey;
  /* Security bits for the scheme */
  int security_bits;
  /* digest engine for CMS: */
  EVP_MD_CTX * digest;
} OQS_KEY;


static isc_result_t
load_privkey_from_privstruct(EVP_PKEY **key, dst_private_t *priv) {
	unsigned char *privkey = priv->elements[0].data;
	int privLen = priv->elements[0].length;
	unsigned char *pubkey = priv->elements[1].data;
	isc_result_t result = ISC_R_SUCCESS;

	if (privkey == NULL || pubkey == NULL) {
		return (ISC_R_NOMEMORY);
	}
	// I need a way to derive a public key from a private key. For now, going to break the api
	// and store the pubkey with the private key
	if ((*key = EVP_PKEY_new_raw_private_key(EVP_PKEY_FALCON512, NULL, privkey, privLen)) == NULL) {
		return (ISC_R_NOMEMORY);
	}
	// Likely sketchy, check here if bugs!!!
	OQS_KEY *oqs_key = EVP_PKEY_get0(*key);
	if (oqs_key == NULL) {
		return (ISC_R_NOMEMORY);
	}
	oqs_key->pubkey = pubkey;
	
	return (result);
}
/*
static isc_result_t
eckey_to_pkey(EC_KEY *eckey, EVP_PKEY **pkey) {
	REQUIRE(pkey != NULL && *pkey == NULL);

	*pkey = EVP_PKEY_new();
	if (*pkey == NULL) {
		return (ISC_R_NOMEMORY);
	}
	if (!EVP_PKEY_set1_EC_KEY(*pkey, eckey)) {
		EVP_PKEY_free(*pkey);
		*pkey = NULL;
		return (dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	return (ISC_R_SUCCESS);
}
*/

static isc_result_t
finalize_pkey(dst_key_t *key, EVP_PKEY *pkey, const char *engine,
	       const char *label) {
	UNUSED(label);
	UNUSED(engine);
	key->keydata.pkey = pkey;
// Should never hit here
/*
	if (label != NULL) {
		key->label = isc_mem_strdup(key->mctx, label);
		key->engine = isc_mem_strdup(key->mctx, engine);
	}
*/
	key->key_size = DNS_KEY_FALCON512SIZE;

	return (ISC_R_SUCCESS);
}
/*
static isc_result_t
dst__key_to_evp_pkey(dst_key_t *key, EVP_PKEY **eckey) {
	REQUIRE(eckey != NULL && *eckey == NULL);

	int group_nid;
	switch (key->key_alg) {
	case DST_ALG_ECDSA256:
		group_nid = NID_X9_62_prime256v1;
		break;
	case DST_ALG_ECDSA384:
		group_nid = NID_secp384r1;
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
	*eckey = EC_KEY_new_by_curve_name(group_nid);
	if (*eckey == NULL) {
		return (dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	return (ISC_R_SUCCESS);
}
*/

static isc_result_t
opensslfalcon512_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	dst_private_t priv;
	isc_result_t ret;
	int i, privkey_index, pubkey_index = -1;
	const char *engine = NULL, *label = NULL;
	EVP_PKEY *pkey = NULL, *pubpkey = NULL;
	size_t len;
	isc_mem_t *mctx = key->mctx;

	REQUIRE(key->key_alg == DST_ALG_FALCON512);

	/* read private key file */
	ret = dst__privstruct_parse(key, DST_ALG_ED25519, lexer, mctx, &priv);
	if (ret != ISC_R_SUCCESS) {
		goto err;
	}

	if (key->external) {
		if (priv.nelements != 0) {
			DST_RET(DST_R_INVALIDPRIVATEKEY);
		}
		if (pub == NULL) {
			DST_RET(DST_R_INVALIDPRIVATEKEY);
		}
		key->keydata.pkey = pub->keydata.pkey;
		pub->keydata.pkey = NULL;
		dst__privstruct_free(&priv, mctx);
		isc_safe_memwipe(&priv, sizeof(priv));
		return (ISC_R_SUCCESS);
	}

	if (pub != NULL) {
		pubpkey = pub->keydata.pkey;
	}

	for (i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_FALCON512_ENGINE:
			engine = (char *)priv.elements[i].data;
			break;
		case TAG_FALCON512_LABEL:
			label = (char *)priv.elements[i].data;
			break;
		case TAG_FALCON512_PRIVATEKEY:
			privkey_index = i;
			break;
		case TAG_FALCON512_PUBLICKEY:
			pubkey_index = i;
			break;
		default:
			break;
		}
	}
/*
	if (label != NULL) {
		ret = openssleddsa_fromlabel(key, engine, label, NULL);
		if (ret != ISC_R_SUCCESS) {
			goto err;
		}
		if (eddsa_check(key->keydata.pkey, pubpkey) != ISC_R_SUCCESS) {
			DST_RET(DST_R_INVALIDPRIVATEKEY);
		}
		DST_RET(ISC_R_SUCCESS);
	}
*/
	if (privkey_index < 0) {
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}
	if (pubkey_index < 0) {
		DST_RET(DST_R_INVALIDPUBLICKEY);
	}

	len = priv.elements[privkey_index].length;
	//ret = raw_key_to_ossl(key->key_alg, 1,
	//		      priv.elements[privkey_index].data, &len, &pkey);

	if (len < FALCON512_PUBLICKEY_SIZE) {
		return (DST_R_INVALIDPRIVATEKEY);
	}
	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_FALCON512, NULL, priv.elements[privkey_index].data, len);
	if (pkey == NULL) {
		return (dst__openssl_toresult(ret));
	}

	len = priv.elements[pubkey_index].length;
	//ret = raw_key_to_ossl(key->key_alg, 0,
	//		      priv.elements[pubkey_index].data, &len, &pkey);
	OQS_KEY *oqs_key = EVP_PKEY_get0(pkey);
	oqs_key->pubkey = OPENSSL_secure_malloc(len);
	if (oqs_key->pubkey == NULL) {
		return (dst__openssl_toresult(ISC_R_NOSPACE));
	}
	memcpy(oqs_key->pubkey, priv.elements[pubkey_index].data, len);
	/*
	if (eddsa_check(pkey, pubpkey) != ISC_R_SUCCESS) {
		EVP_PKEY_free(pkey);
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}
	*/
	key->keydata.pkey = pkey;
	key->key_size = DNS_KEY_FALCON512SIZE;
	ret = ISC_R_SUCCESS;

err:
	dst__privstruct_free(&priv, mctx);
	isc_safe_memwipe(&priv, sizeof(priv));
	return (ret);
	/*
	dst_private_t priv;
	isc_result_t result = ISC_R_SUCCESS;
	EVP_PKEY *pkey = NULL;
//	EC_KEY *eckey = NULL;
//	EC_KEY *pubeckey = NULL;
	const char *engine = NULL;
	const char *label = NULL;
	int i, privkey_index, pubkey_index = -1;
	bool finalize_key = false;

	// read private key file
	// TODO, may need to update this function
	result = dst__privstruct_parse(key, DST_ALG_FALCON512, lexer, key->mctx,
				       &priv);
	if (result != ISC_R_SUCCESS) {
		goto end;
	}

	// Is key from an external source? (I think)
	if (key->external) {
		if (priv.nelements != 0 || pub == NULL) {
			result = DST_R_INVALIDPRIVATEKEY;
			goto end;
		}
		key->keydata.pkey = pub->keydata.pkey;
		pub->keydata.pkey = NULL;
		goto end;
	}

	for (i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_FALCON512_ENGINE:
			engine = (char *)priv.elements[i].data;
			break;
		case TAG_FALCON512_LABEL:
			label = (char *)priv.elements[i].data;
			break;
		case TAG_FALCON512_PRIVATEKEY:
			privkey_index = i;
			break;
		case TAG_FALCON512_PUBLICKEY:
			pubkey_index = i;
			break;
		default:
			break;
		}
	}

	if (privkey_index < 0 || pubkey_index < 0) {
		result = DST_R_INVALIDPRIVATEKEY;
		goto end;
	}
	// Still not exactly sure if we care about these right now...
	// the fromlabel tool says it's for using HSM specifically
	// but it's not clear if this "label" is the same as the DNS
	// label or not
	if (label != NULL) {
		result = DST_R_NOENGINE;

		printf("Should never get to lable in parse. uh-oh...\n");
		goto end;

		result = opensslecdsa_fromlabel(key, engine, label, NULL);
		if (result != ISC_R_SUCCESS) {
			goto end;
		}

		eckey = EVP_PKEY_get1_EC_KEY(key->keydata.pkey);
		if (eckey == NULL) {
			result = dst__openssl_toresult(DST_R_OPENSSLFAILURE);
			goto end;
		}

	} else {
		//result = dst__key_to_eckey(key, &eckey);
		//if (result != ISC_R_SUCCESS) {
		//	goto end;
		//}
		// should just be a pkey
		result = load_privkey_from_privstruct(&pkey, &priv);
		if (pkey == NULL) printf("pkey is null after load?\n");
		if (result != ISC_R_SUCCESS) {
			goto end;
		}

		finalize_key = true;
	}

	if (pub != NULL && pub->keydata.pkey != NULL) {
		pubeckey = EVP_PKEY_get1_EC_KEY(pub->keydata.pkey);
	}

	if (ecdsa_check(eckey, pubeckey) != ISC_R_SUCCESS) {
		result = DST_R_INVALIDPRIVATEKEY;
		goto end;
	}

	if (finalize_key) {
		printf("Finalizing\n");
		result = finalize_pkey(key, pkey, engine, label);
	}

end:

	if (pubeckey != NULL) {
		EC_KEY_free(pubeckey);
	}
	if (eckey != NULL) {
		EC_KEY_free(eckey);
	}

	dst__privstruct_free(&priv, key->mctx);
	isc_safe_memwipe(&priv, sizeof(priv));
	return (result);
	*/
}

static dst_func_t opensslfalcon512_functions = {
	opensslfalcon512_createctx,
	NULL, /*%< createctx2 */
	opensslfalcon512_destroyctx,
	opensslfalcon512_adddata,
	opensslfalcon512_sign,
	opensslfalcon512_verify,
	NULL, /*%< verify2 */
	NULL, /*%< computesecret */
	opensslfalcon512_compare,
	NULL, /*%< paramcompare */
	opensslfalcon512_generate,
	opensslfalcon512_isprivate,
	opensslfalcon512_destroy, 
	opensslfalcon512_todns,   // called by dst_key_todns converts a dst_key to a buffer
	opensslfalcon512_fromdns, // called by from buffer and constructs a key from dns
	opensslfalcon512_tofile,  // All this does is write the private key, writing public keys are handled elsewhere
	opensslfalcon512_parse,
	NULL,			    /*%< cleanup */
	NULL, //opensslfalcon512_fromlabel, /*%< fromlabel */ //re-add this line if errors happen, but honestly they shouldn't
	NULL,			    /*%< dump */
	NULL,			    /*%< restore */
};

isc_result_t
dst__opensslfalcon512_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL);
	if (*funcp == NULL) {
		*funcp = &opensslfalcon512_functions;
	}
	return (ISC_R_SUCCESS);
}
