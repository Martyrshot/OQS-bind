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


#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"

#define DST_RET(a)        \
	{                 \
		ret = a;  \
		goto err; \
	}

#define FALCON512_PRIVATE_KEYSIZE 1281

typedef struct falcon512_alginfo {
	int pkey_type;
	unsigned int key_size, priv_key_size, sig_size;
} falcon512_alginfo_t;

static const falcon512_alginfo_t *
opensslfalcon512_alg_info(unsigned int key_alg) {
	if (key_alg == DST_ALG_FALCON512) {
		static const falcon512_alginfo_t falcon512_alginfo = {
			.pkey_type = EVP_PKEY_FALCON512,
			.key_size = DNS_KEY_FALCON512SIZE,
			.priv_key_size = FALCON512_PRIVATE_KEYSIZE,
			.sig_size = DNS_SIG_FALCON512SIZE,
		};
		return &falcon512_alginfo;
	}
	return NULL;
}

static isc_result_t
raw_key_to_ossl(const falcon512_alginfo_t *alginfo, int private,
		const unsigned char *key, size_t *key_len, EVP_PKEY **pkey) {
	isc_result_t ret;
	int pkey_type = alginfo->pkey_type;

	ret = (private ? DST_R_INVALIDPRIVATEKEY : DST_R_INVALIDPUBLICKEY);
	if (private) {
		if (*key_len < alginfo->priv_key_size) {
			return (ret);
		}
		*pkey = EVP_PKEY_new_raw_private_key(pkey_type, NULL, key, alginfo->priv_key_size);
	} else {
		if (*key_len < alginfo->key_size) {
			return (ret);
		}
		*pkey = EVP_PKEY_new_raw_public_key(pkey_type, NULL, key, alginfo->key_size);
	}
	if (*pkey == NULL) {
		return (dst__openssl_toresult(ret));
	}
	*key_len = (private ? alginfo->priv_key_size : alginfo->key_size);
	return (ISC_R_SUCCESS);
}

static isc_result_t
opensslfalcon512_createctx(dst_key_t *key, dst_context_t *dctx) {
	isc_buffer_t *buf = NULL;
	const falcon512_alginfo_t *alginfo =
		opensslfalcon512_alg_info(dctx->key->key_alg);
	UNUSED(key);
	REQUIRE(alginfo != NULL);

	isc_buffer_allocate(dctx->mctx, &buf, 64);
	dctx->ctxdata.generic = buf;

	return (ISC_R_SUCCESS);
}

static void
opensslfalcon512_destroyctx(dst_context_t *dctx) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;

	const falcon512_alginfo_t *alginfo =
		opensslfalcon512_alg_info(dctx->key->key_alg);

	REQUIRE(alginfo != NULL);
	if (buf != NULL) {
		isc_buffer_free(&buf);
	}
	dctx->ctxdata.generic = NULL;
}

static isc_result_t
opensslfalcon512_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	isc_buffer_t *nbuf = NULL;
	isc_region_t r;
	unsigned int length;
	isc_result_t result;
	const falcon512_alginfo_t *alginfo =
		opensslfalcon512_alg_info(dctx->key->key_alg);

	REQUIRE(alginfo != NULL);

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
opensslfalcon512_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	isc_region_t tbsreg;
	isc_region_t sigreg;
	EVP_PKEY *pkey = key->keydata.pkeypair.priv;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	const falcon512_alginfo_t *alginfo = opensslfalcon512_alg_info(key->key_alg);
	size_t siglen;

	REQUIRE(alginfo != NULL);

	if (ctx == NULL) {
		return (ISC_R_NOMEMORY);
	}

	siglen = alginfo->sig_size;
	isc_buffer_availableregion(sig, &sigreg);
	if (sigreg.length < (unsigned int)siglen) {
		DST_RET(ISC_R_NOSPACE);
	}
	// TODO update to newer liboqs so we don't have to do this gross hack anymore
	// zero out buffer
	unsigned char *_sig = sigreg.base;
	for (size_t i = 0; i < siglen; i++) {
		_sig[i] = 0;
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
	siglen = DNS_SIG_FALCON512SIZE;
	isc_buffer_add(sig, (unsigned int)siglen);
	ret = ISC_R_SUCCESS;

err:
	EVP_MD_CTX_free(ctx);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return (ret);

}

static isc_result_t
opensslfalcon512_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	int status;
	isc_region_t tbsreg;
	EVP_PKEY *pkey = key->keydata.pkeypair.pub;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	const falcon512_alginfo_t *alginfo = opensslfalcon512_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);

	if (ctx == NULL) {
		return (ISC_R_NOMEMORY);
	}

	if (sig->length != alginfo->sig_size) {
		return (DST_R_VERIFYFAILURE);
	}

	// TODO update to latest version of liboqs to remove this hack
	unsigned char *_sig = sig->base;
	int ending_key = -1;
	size_t siglen = sig->length;
        if (siglen == DNS_SIG_FALCON512SIZE) {
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

static isc_result_t
opensslfalcon512_generate(dst_key_t *key, int unused, void (*callback)(int)) {
	isc_result_t ret;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	const falcon512_alginfo_t *alginfo = opensslfalcon512_alg_info(key->key_alg);
	int status;

	REQUIRE(alginfo != NULL);
	UNUSED(unused);
	UNUSED(callback);
	key->key_size = alginfo->key_size;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_FALCON512, NULL);
	if (ctx == NULL) {
		return (dst__openssl_toresult2("EVP_PKEY_CTX_new_id",
							DST_R_OPENSSLFAILURE));
	}

	status = EVP_PKEY_keygen_init(ctx);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_keygen_init",
						DST_R_OPENSSLFAILURE));
	}

	status = EVP_PKEY_keygen(ctx, &pkey);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_keygen",
						DST_R_OPENSSLFAILURE));
	}

	key->key_size = alginfo->key_size * 8;
	key->keydata.pkeypair.priv = pkey;
	key->keydata.pkeypair.pub = pkey;
	ret = ISC_R_SUCCESS;

err:
	EVP_PKEY_CTX_free(ctx);
	return (ret);
}

static isc_result_t
opensslfalcon512_todns(const dst_key_t *key, isc_buffer_t *data) {
	const falcon512_alginfo_t *alginfo = opensslfalcon512_alg_info(key->key_alg);
	EVP_PKEY *pkey = key->keydata.pkeypair.pub;
	isc_region_t r;
	size_t len;

	REQUIRE(pkey != NULL);
	REQUIRE(alginfo != NULL);

	len = alginfo->key_size;
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
opensslfalcon512_fromdns(dst_key_t *key, isc_buffer_t *data) {
	const falcon512_alginfo_t *alginfo = opensslfalcon512_alg_info(key->key_alg);
	isc_result_t ret;
	isc_region_t r;
	size_t len;
	EVP_PKEY *pkey = NULL;

	REQUIRE(alginfo != NULL);

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return (ISC_R_SUCCESS);
	}

	len = r.length;
	ret = raw_key_to_ossl(alginfo, 0, r.base, &len, &pkey);
	if (ret != ISC_R_SUCCESS) {
		return ret;
	}

	isc_buffer_forward(data, len);
	key->keydata.pkeypair.pub = pkey;
	key->key_size = len * 8;
	return (ISC_R_SUCCESS);

}

static isc_result_t
opensslfalcon512_tofile(const dst_key_t *key, const char *directory) {
	const falcon512_alginfo_t *alginfo = opensslfalcon512_alg_info(key->key_alg);
	isc_result_t ret;
	dst_private_t priv;
	unsigned char *pubbuf = NULL;
	unsigned char *privbuf = NULL;
	size_t publen;
	size_t privlen;
	int i;

	REQUIRE(alginfo != NULL);

	publen = alginfo->key_size;
	privlen = alginfo->priv_key_size;
	if (key->keydata.pkeypair.pub == NULL || key->keydata.pkeypair.priv == NULL) {
		return (DST_R_NULLKEY);
	}

	if (key->external) {
		priv.nelements = 0;
		return (dst__privstruct_writefile(key, &priv, directory));
	}

	i = 0;

	if (dst__openssl_keypair_isprivate(key)) {
		privbuf = isc_mem_get(key->mctx, privlen);
		if (EVP_PKEY_get_raw_private_key(key->keydata.pkeypair.priv, privbuf,
						 &privlen) != 1)
			DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
		priv.elements[i].tag = TAG_FALCON512_PRIVATEKEY;
		priv.elements[i].length = privlen;
		priv.elements[i].data = privbuf;
		i++;
		pubbuf = isc_mem_get(key->mctx, publen);
		if (EVP_PKEY_get_raw_public_key(key->keydata.pkeypair.priv, pubbuf,
						 &publen) != 1)
			DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
		priv.elements[i].tag = TAG_FALCON512_PUBLICKEY;
		priv.elements[i].length = publen;
		priv.elements[i].data = pubbuf;
		i++;
	}
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
opensslfalcon512_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	const falcon512_alginfo_t *alginfo = opensslfalcon512_alg_info(key->key_alg);
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
	REQUIRE(alginfo != NULL);

	/* read private key file */
	ret = dst__privstruct_parse(key, DST_ALG_FALCON512, lexer, mctx, &priv);
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
		key->keydata.pkeypair.priv = pub->keydata.pkeypair.priv;
		key->keydata.pkeypair.pub = pub->keydata.pkeypair.pub;
		pub->keydata.pkeypair.priv = NULL;
		pub->keydata.pkeypair.pub = NULL;
		DST_RET(ISC_R_SUCCESS);
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
	if (privkey_index < 0) {
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}
	if (pubkey_index < 0) {
		DST_RET(DST_R_INVALIDPUBLICKEY);
	}
	len = priv.elements[privkey_index].length;
	REQUIRE(len == alginfo->priv_key_size);
	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_FALCON512, NULL, priv.elements[privkey_index].data, len);
	if (pkey == NULL) {
		return (dst__openssl_toresult(ret));
	}

	len = priv.elements[pubkey_index].length;
	REQUIRE(len == alginfo->key_size);
	OQS_KEY *oqs_key = EVP_PKEY_get0(pkey);
	oqs_key->pubkey = OPENSSL_secure_malloc(len);
	if (oqs_key->pubkey == NULL) {
		return (dst__openssl_toresult(ISC_R_NOSPACE));
	}
	memcpy(oqs_key->pubkey, priv.elements[pubkey_index].data, len);
	key->keydata.pkeypair.priv = pkey;
	key->keydata.pkeypair.pub = pkey;
	key->key_size = priv.elements[pubkey_index].length;
	ret = ISC_R_SUCCESS;

err:
	dst__privstruct_free(&priv, mctx);
	isc_safe_memwipe(&priv, sizeof(priv));
	return (ret);
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
	dst__openssl_keypair_compare,
	NULL, /*%< paramcompare */
	opensslfalcon512_generate,
	dst__openssl_keypair_isprivate,
	dst__openssl_keypair_destroy, 
	opensslfalcon512_todns,   // called by dst_key_todns converts a dst_key to a buffer
	opensslfalcon512_fromdns, // called by from buffer and constructs a key from dns
	opensslfalcon512_tofile,
	opensslfalcon512_parse,
	NULL,			    /*%< cleanup */
	NULL, 			    /*%< fromlabel */
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
