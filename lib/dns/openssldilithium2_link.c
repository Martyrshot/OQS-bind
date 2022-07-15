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
#include <openssl/ecdsa.h>
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

#define DILITHIUM2_PUBLICKEY_SIZE 1312
#define DILITHIUM2_PRIVATEKEY_SIZE 2528


#define DST_RET(a)        \
	{                 \
		ret = a;  \
		goto err; \
	}

static bool
isprivate(EVP_PKEY *pkey) {
	size_t len;

	if (pkey == NULL) {
		return (false);
	}

	if (EVP_PKEY_get_raw_private_key(pkey, NULL, &len) == 1 && len > 0) {
		return (true);
	}
	/* can check if first error is EC_R_INVALID_PRIVATE_KEY */
	while (ERR_get_error() != 0) {
		/**/
	}
	return (false);

}

static isc_result_t
openssldilithium2_createctx(dst_key_t *key, dst_context_t *dctx) {
	isc_buffer_t *buf = NULL;

	UNUSED(key);
	REQUIRE(dctx->key->key_alg == DST_ALG_DILITHIUM2);

	isc_buffer_allocate(dctx->mctx, &buf, 64); // Need to figure out how big...
	dctx->ctxdata.generic = buf;

	return (ISC_R_SUCCESS);
}

static void
openssldilithium2_destroyctx(dst_context_t *dctx) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;

	REQUIRE(dctx->key->key_alg == DST_ALG_DILITHIUM2);
	if (buf != NULL) {
		isc_buffer_free(&buf);
	}
	dctx->ctxdata.generic = NULL;
}

static isc_result_t
openssldilithium2_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	isc_buffer_t *nbuf = NULL;
	isc_region_t r;
	unsigned int length;
	isc_result_t result;

	REQUIRE(dctx->key->key_alg == DST_ALG_DILITHIUM2);
	result = isc_buffer_copyregion(buf, data);
	if (result == ISC_R_SUCCESS) {
		return (ISC_R_SUCCESS);
	}

	length = isc_buffer_length(buf) + data->length + 64;
	isc_buffer_allocate(dctx->mctx, &nbuf, length);
	isc_buffer_usedregion(buf, &r);
	(void)isc_buffer_copyregion(nbuf, &r);
	(void)isc_buffer_copyregion(nbuf, data);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = nbuf;

	return (ISC_R_SUCCESS);
}

static isc_result_t
openssldilithium2_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	isc_region_t tbsreg;
	isc_region_t sigreg;
	EVP_PKEY *pkey = key->keydata.pkey;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	size_t siglen;

	REQUIRE(key->key_alg == DST_ALG_DILITHIUM2);

	if (ctx == NULL) {
		return (ISC_R_NOMEMORY);
	}

	siglen = DNS_SIG_DILITHIUM2SIZE;

	isc_buffer_availableregion(sig, &sigreg);
	// zero out buffer
	unsigned char *_sig = sigreg.base;
	for (size_t i = 0; i < siglen; i++) {
		_sig[i] = 0;
	}
	if (sigreg.length < (unsigned int)siglen) {
		DST_RET(ISC_R_NOSPACE);
	}

	isc_buffer_usedregion(buf, &tbsreg);

	if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1) {
		DST_RET(dst__openssl_toresult3(
			dctx->category, "EVP_DigestSignInit", ISC_R_FAILURE));
	}
	if (EVP_DigestSign(ctx, sigreg.base, &siglen, tbsreg.base,
			   tbsreg.length) != 1) {
		DST_RET(dst__openssl_toresult3(dctx->category, "EVP_DigestSign",
					       DST_R_SIGNFAILURE));
	}
	siglen = DNS_SIG_DILITHIUM2SIZE;
	isc_buffer_add(sig, (unsigned int)siglen);
	ret = ISC_R_SUCCESS;

err:
	EVP_MD_CTX_free(ctx);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return (ret);

}

static isc_result_t
openssldilithium2_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	int status;
	isc_region_t tbsreg;
	EVP_PKEY *pkey = key->keydata.pkey;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	unsigned int siglen = 0;

	REQUIRE(key->key_alg == DST_ALG_DILITHIUM2);

	if (ctx == NULL) {
		return (ISC_R_NOMEMORY);
	}

	siglen = DNS_SIG_DILITHIUM2SIZE;
	if (siglen == 0) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	if (sig->length != siglen) {
		return (DST_R_VERIFYFAILURE);
	}
	unsigned char *_sig = sig->base;
	int ending_key = -1;
        if (siglen == DNS_SIG_DILITHIUM2SIZE) {
                for (unsigned int i = 0; i < siglen; i++) {
                        if (_sig[i] == 0 && ending_key == -1) ending_key = i;
                        else if (_sig[i] == 0) continue;
                        else ending_key = -1;
                }
        }
        if (ending_key != -1) {
                siglen = ending_key;
        }

	isc_buffer_usedregion(buf, &tbsreg);

	if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1) {
		DST_RET(dst__openssl_toresult3(
			dctx->category, "EVP_DigestVerifyInit", ISC_R_FAILURE));
	}

	status = EVP_DigestVerify(ctx, sig->base, siglen, tbsreg.base,
				  tbsreg.length);

	switch (status) {
	case 1:
		ret = ISC_R_SUCCESS;
		break;
	case 0:
		ret = dst__openssl_toresult(DST_R_VERIFYFAILURE);
		break;
	default:
		ret = dst__openssl_toresult3(dctx->category, "EVP_DigestVerify",
					     DST_R_VERIFYFAILURE);
		break;
	}

err:
	EVP_MD_CTX_free(ctx);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return (ret);
}

static bool
openssldilithium2_compare(const dst_key_t *key1, const dst_key_t *key2) {
	
	EVP_PKEY *pkey1 = key1->keydata.pkey;
	EVP_PKEY *pkey2 = key2->keydata.pkey;

	return (EVP_PKEY_cmp(pkey1, pkey2));
}

static isc_result_t
openssldilithium2_generate(dst_key_t *key, int unused, void (*callback)(int)) {
	isc_result_t ret;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
	REQUIRE(key->key_alg == DST_ALG_DILITHIUM2);
	UNUSED(unused);
	UNUSED(callback);
	key->key_size = DNS_KEY_DILITHIUM2SIZE;

	if ((pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DILITHIUM2, NULL)) == NULL) {
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
openssldilithium2_isprivate(const dst_key_t *key) {
	EVP_PKEY *pkey = key->keydata.pkey;
	return isprivate(pkey);
}

static void
openssldilithium2_destroy(dst_key_t *key) {
	EVP_PKEY *pkey = key->keydata.pkey;
	EVP_PKEY_free(pkey);
	key->keydata.pkey = NULL;
}

static isc_result_t
openssldilithium2_todns(const dst_key_t *key, isc_buffer_t *data) {
	EVP_PKEY *pkey = key->keydata.pkey;
	isc_region_t r;
	size_t len;

	REQUIRE(pkey != NULL);
	REQUIRE(key->key_alg == DST_ALG_DILITHIUM2);
	len = DNS_KEY_DILITHIUM2SIZE;

	isc_buffer_availableregion(data, &r);
	if (r.length < len) {
		return (ISC_R_NOSPACE);
	}

	if (EVP_PKEY_get_raw_public_key(pkey, r.base, &len) != 1)
		return (dst__openssl_toresult(ISC_R_FAILURE));

	isc_buffer_add(data, len);
	return (ISC_R_SUCCESS);
}

static isc_result_t
openssldilithium2_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_region_t r;
	size_t len;
	EVP_PKEY *pkey;

	REQUIRE(key->key_alg == DST_ALG_DILITHIUM2);

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return (ISC_R_SUCCESS);
	}

	len = r.length;
	if (len < DNS_KEY_DILITHIUM2SIZE) {
		return (DST_R_INVALIDPUBLICKEY);
	}

	pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_DILITHIUM2, NULL, r.base, len);
	if (pkey == NULL) {
		return (dst__openssl_toresult(DST_R_INVALIDPUBLICKEY));
	}

	isc_buffer_forward(data, len);
	key->keydata.pkey = pkey;
	key->key_size = len;
	return (ISC_R_SUCCESS);

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
openssldilithium2_tofile(const dst_key_t *key, const char *directory) {
	isc_result_t ret;
	dst_private_t priv;
	unsigned char *pubbuf = NULL;
	unsigned char *privbuf = NULL;
	size_t publen = DILITHIUM2_PUBLICKEY_SIZE;
	size_t privlen = DILITHIUM2_PRIVATEKEY_SIZE;
	int i;

	REQUIRE(key->key_alg == DST_ALG_DILITHIUM2);
	if (key->keydata.pkey == NULL) {
		return (DST_R_NULLKEY);
	}

	if (key->external) {
		priv.nelements = 0;
		return (dst__privstruct_writefile(key, &priv, directory));
	}

	i = 0;

	if (openssldilithium2_isprivate(key)) {
		privbuf = isc_mem_get(key->mctx, privlen);
		if (privbuf == NULL) {
			printf("Failed to get a privbuf\n");
		}
		OQS_KEY *oqs_key = EVP_PKEY_get0(key->keydata.pkey);
		if (oqs_key == NULL) {
			printf("oqs_key is null\n");
		}
		printf("privlen: %lu - %lu\n", privlen, oqs_key->s->length_secret_key);
		if (EVP_PKEY_get_raw_private_key(key->keydata.pkey, privbuf,
						 &privlen) != 1) {
			printf("Failed to get raw private_key\n");
			DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
		}
		priv.elements[i].tag = TAG_DILITHIUM2_PRIVATEKEY;
		priv.elements[i].length = privlen;
		priv.elements[i].data = privbuf;
		i++;
		pubbuf = isc_mem_get(key->mctx, publen);
		if (pubbuf == NULL) {
			printf("Failed to get a pubbuf\n");
		}
		if (EVP_PKEY_get_raw_public_key(key->keydata.pkey, pubbuf,
						 &publen) != 1) {
			printf("Failed to get raw public_key\n");
		}
			DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
		priv.elements[i].tag = TAG_DILITHIUM2_PUBLICKEY;
		priv.elements[i].length = publen;
		priv.elements[i].data = pubbuf;
		i++;
	}
	priv.nelements = i;
	printf("pre-privstruct_writefile\n");
	ret = dst__privstruct_writefile(key, &priv, directory);
	printf("!=tofile ret = %d\n", ret);
err:
	if (privbuf != NULL) {
		isc_mem_put(key->mctx, privbuf, privlen);
	}
	if (pubbuf != NULL) {
		isc_mem_put(key->mctx, pubbuf, publen);
	}
	return (ret);
}


static isc_result_t
openssldilithium2_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	dst_private_t priv;
	isc_result_t ret;
	int i, privkey_index, pubkey_index = -1;
	const char *engine = NULL, *label = NULL;
	EVP_PKEY *pkey = NULL, *pubpkey = NULL;
	size_t len;
	isc_mem_t *mctx = key->mctx;
	UNUSED(engine);
	UNUSED(label);
	UNUSED(pubpkey);
	REQUIRE(key->key_alg == DST_ALG_DILITHIUM2);

	/* read private key file */
	ret = dst__privstruct_parse(key, DST_ALG_DILITHIUM2, lexer, mctx, &priv);
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
		// This is set so that sanity checks can be made,
		// but currently don't have those checks implemented
		pubpkey = pub->keydata.pkey;
	}
	// Currently donot support HSMs, but leaving the parsing code
	// in for future use.
	for (i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_DILITHIUM2_ENGINE:
			engine = (char *)priv.elements[i].data;
			break;
		case TAG_DILITHIUM2_LABEL:
			label = (char *)priv.elements[i].data;
			break;
		case TAG_DILITHIUM2_PRIVATEKEY:
			privkey_index = i;
			break;
		case TAG_DILITHIUM2_PUBLICKEY:
			pubkey_index = i;
			break;
		default:
			break;
		}
	}
	if (privkey_index < 0) {
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}
	if (pubkey_index < 0) {
		DST_RET(DST_R_INVALIDPUBLICKEY);
	}

	len = priv.elements[privkey_index].length;

	if (len < DILITHIUM2_PUBLICKEY_SIZE) {
		return (DST_R_INVALIDPRIVATEKEY);
	}
	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_DILITHIUM2, NULL, priv.elements[privkey_index].data, len);
	if (pkey == NULL) {
		return (dst__openssl_toresult(ret));
	}

	len = priv.elements[pubkey_index].length;
	OQS_KEY *oqs_key = EVP_PKEY_get0(pkey);
	oqs_key->pubkey = OPENSSL_secure_malloc(len);
	if (oqs_key->pubkey == NULL) {
		return (dst__openssl_toresult(ISC_R_NOSPACE));
	}
	memcpy(oqs_key->pubkey, priv.elements[pubkey_index].data, len);
	key->keydata.pkey = pkey;
	key->key_size = priv.elements[pubkey_index].length;
	ret = ISC_R_SUCCESS;

err:
	dst__privstruct_free(&priv, mctx);
	isc_safe_memwipe(&priv, sizeof(priv));
	return (ret);
}

static dst_func_t openssldilithium2_functions = {
	openssldilithium2_createctx,
	NULL, /*%< createctx2 */
	openssldilithium2_destroyctx,
	openssldilithium2_adddata,
	openssldilithium2_sign,
	openssldilithium2_verify,
	NULL, /*%< verify2 */
	NULL, /*%< computesecret */
	openssldilithium2_compare,
	NULL, /*%< paramcompare */
	openssldilithium2_generate,
	openssldilithium2_isprivate,
	openssldilithium2_destroy, 
	openssldilithium2_todns,   // called by dst_key_todns converts a dst_key to a buffer
	openssldilithium2_fromdns, // called by from buffer and constructs a key from dns
	openssldilithium2_tofile,  // All this does is write the private key, writing public keys are handled elsewhere
	openssldilithium2_parse,
	NULL,			    /*%< cleanup */
	NULL, 			    /*%< fromlabel */
	NULL,			    /*%< dump */
	NULL,			    /*%< restore */
};

isc_result_t
dst__openssldilithium2_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL);
	if (*funcp == NULL) {
		*funcp = &openssldilithium2_functions;
	}
	return (ISC_R_SUCCESS);
}
