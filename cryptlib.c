/*
 * Driver for /dev/crypto device (aka CryptoDev)
 *
 * Copyright (c) 2010,2011 Nikos Mavrogiannopoulos <nmav@gnutls.org>
 * Portions Copyright (c) 2010 Michael Weiser
 * Portions Copyright (c) 2010 Phil Sutter
 *
 * This file is part of linux cryptodev.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/ioctl.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/uaccess.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/cryptodev.h>
#include <crypto/aead.h>
#include <linux/rtnetlink.h>
#include <crypto/authenc.h>
#include "cryptodev_int.h"
#include "cipherapi.h"
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4, 3, 0))
#include <linux/asn1_ber_bytecode.h>
#include <crypto/akcipher.h>
#endif

extern const struct crypto_type crypto_givcipher_type;

static void cryptodev_complete(struct crypto_async_request *req, int err)
{
	struct cryptodev_result *res = req->data;

	if (err == -EINPROGRESS)
		return;

	res->err = err;
	complete(&res->completion);
}

int cryptodev_get_cipher_keylen(unsigned int *keylen, struct session_op *sop,
		int aead)
{
	/*
	 * For blockciphers (AES-CBC) or non-composite aead ciphers (like AES-GCM),
	 * the key length is simply the cipher keylen obtained from userspace. If
	 * the cipher is composite aead, the keylen is the sum of cipher keylen,
	 * hmac keylen and a key header length. This key format is the one used in
	 * Linux kernel for composite aead ciphers (crypto/authenc.c)
	 */
	unsigned int klen = sop->keylen;

	if (unlikely(sop->keylen > CRYPTO_CIPHER_MAX_KEY_LEN))
		return -EINVAL;

	if (aead && sop->mackeylen) {
		if (unlikely(sop->mackeylen > CRYPTO_HMAC_MAX_KEY_LEN))
			return -EINVAL;
		klen += sop->mackeylen;
		klen += RTA_SPACE(sizeof(struct crypto_authenc_key_param));
	}

	*keylen = klen;
	return 0;
}

int cryptodev_get_cipher_key(uint8_t *key, struct session_op *sop, int aead)
{
	/*
	 * Get cipher key from user-space. For blockciphers just copy it from
	 * user-space. For composite aead ciphers combine it with the hmac key in
	 * the format used by Linux kernel in crypto/authenc.c:
	 *
	 * [[AUTHENC_KEY_HEADER + CIPHER_KEYLEN] [AUTHENTICATION KEY] [CIPHER KEY]]
	 */
	struct crypto_authenc_key_param *param;
	struct rtattr *rta;
	int ret = 0;

	if (aead && sop->mackeylen) {
		/*
		 * Composite aead ciphers. The first four bytes are the header type and
		 * header length for aead keys
		 */
		rta = (void *)key;
		rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
		rta->rta_len = RTA_LENGTH(sizeof(*param));

		/*
		 * The next four bytes hold the length of the encryption key
		 */
		param = RTA_DATA(rta);
		param->enckeylen = cpu_to_be32(sop->keylen);

		/* Advance key pointer eight bytes and copy the hmac key */
		key += RTA_SPACE(sizeof(*param));
		if (unlikely(copy_from_user(key, sop->mackey, sop->mackeylen))) {
			ret = -EFAULT;
			goto error;
		}
		/* Advance key pointer past the hmac key */
		key += sop->mackeylen;
	}
	/* now copy the blockcipher key */
	if (unlikely(copy_from_user(key, sop->key, sop->keylen)))
		ret = -EFAULT;

error:
	return ret;
}

/* Was correct key length supplied? */
static int check_key_size(size_t keylen, const char *alg_name,
			  unsigned int min_keysize, unsigned int max_keysize)
{
	if (max_keysize > 0 && unlikely((keylen < min_keysize) ||
					(keylen > max_keysize))) {
		ddebug(1, "Wrong keylen '%zu' for algorithm '%s'. Use %u to %u.",
		       keylen, alg_name, min_keysize, max_keysize);
		return -EINVAL;
	}

	return 0;
}

int cryptodev_cipher_init(struct cipher_data *out, const char *alg_name,
				uint8_t *keyp, size_t keylen, int stream, int aead)
{
	int ret;

	if (aead == 0) {
		unsigned int min_keysize, max_keysize;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0))
		struct crypto_tfm *tfm;
#else
		struct ablkcipher_alg *alg;
#endif

		out->async.s = cryptodev_crypto_alloc_blkcipher(alg_name, 0, 0);
		if (unlikely(IS_ERR(out->async.s))) {
			ddebug(1, "Failed to load cipher %s", alg_name);
				return -EINVAL;
		}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0))
		tfm = crypto_skcipher_tfm(out->async.s);
		if ((tfm->__crt_alg->cra_type == &crypto_ablkcipher_type) ||
		    (tfm->__crt_alg->cra_type == &crypto_givcipher_type)) {
			struct ablkcipher_alg *alg;

			alg = &tfm->__crt_alg->cra_ablkcipher;
			min_keysize = alg->min_keysize;
			max_keysize = alg->max_keysize;
		} else {
			struct skcipher_alg *alg;

			alg = crypto_skcipher_alg(out->async.s);
			min_keysize = alg->min_keysize;
			max_keysize = alg->max_keysize;
		}
#else
		alg = crypto_ablkcipher_alg(out->async.s);
		min_keysize = alg->min_keysize;
		max_keysize = alg->max_keysize;
#endif
		ret = check_key_size(keylen, alg_name, min_keysize,
				     max_keysize);
		if (ret)
			goto error;

		out->blocksize = cryptodev_crypto_blkcipher_blocksize(out->async.s);
		out->ivsize = cryptodev_crypto_blkcipher_ivsize(out->async.s);
		out->alignmask = cryptodev_crypto_blkcipher_alignmask(out->async.s);

		ret = cryptodev_crypto_blkcipher_setkey(out->async.s, keyp, keylen);
	} else {
		out->async.as = crypto_alloc_aead(alg_name, 0, 0);
		if (unlikely(IS_ERR(out->async.as))) {
			ddebug(1, "Failed to load cipher %s", alg_name);
			return -EINVAL;
		}

		out->blocksize = crypto_aead_blocksize(out->async.as);
		out->ivsize = crypto_aead_ivsize(out->async.as);
		out->alignmask = crypto_aead_alignmask(out->async.as);

		ret = crypto_aead_setkey(out->async.as, keyp, keylen);
	}

	if (unlikely(ret)) {
		ddebug(1, "Setting key failed for %s-%zu.", alg_name, keylen*8);
		ret = -EINVAL;
		goto error;
	}

	out->stream = stream;
	out->aead = aead;

	init_completion(&out->async.result.completion);

	if (aead == 0) {
		out->async.request = cryptodev_blkcipher_request_alloc(out->async.s, GFP_KERNEL);
		if (unlikely(!out->async.request)) {
			derr(1, "error allocating async crypto request");
			ret = -ENOMEM;
			goto error;
		}

		cryptodev_blkcipher_request_set_callback(out->async.request,
					CRYPTO_TFM_REQ_MAY_BACKLOG,
					cryptodev_complete, &out->async.result);
	} else {
		out->async.arequest = aead_request_alloc(out->async.as, GFP_KERNEL);
		if (unlikely(!out->async.arequest)) {
			derr(1, "error allocating async crypto request");
			ret = -ENOMEM;
			goto error;
		}

		aead_request_set_callback(out->async.arequest,
					CRYPTO_TFM_REQ_MAY_BACKLOG,
					cryptodev_complete, &out->async.result);
	}

	out->init = 1;
	return 0;
error:
	if (aead == 0) {
		cryptodev_blkcipher_request_free(out->async.request);
		cryptodev_crypto_free_blkcipher(out->async.s);
	} else {
		if (out->async.arequest)
			aead_request_free(out->async.arequest);
		if (out->async.as)
			crypto_free_aead(out->async.as);
	}

	return ret;
}

void cryptodev_cipher_deinit(struct cipher_data *cdata)
{
	if (cdata->init) {
		if (cdata->aead == 0) {
			cryptodev_blkcipher_request_free(cdata->async.request);
			cryptodev_crypto_free_blkcipher(cdata->async.s);
		} else {
			if (cdata->async.arequest)
				aead_request_free(cdata->async.arequest);
			if (cdata->async.as)
				crypto_free_aead(cdata->async.as);
		}

		cdata->init = 0;
	}
}

static inline int waitfor(struct cryptodev_result *cr, ssize_t ret)
{
	switch (ret) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		wait_for_completion(&cr->completion);
		/* At this point we known for sure the request has finished,
		 * because wait_for_completion above was not interruptible.
		 * This is important because otherwise hardware or driver
		 * might try to access memory which will be freed or reused for
		 * another request. */

		if (unlikely(cr->err)) {
			derr(0, "error from async request: %d", cr->err);
			return cr->err;
		}

		break;
	default:
		return ret;
	}

	return 0;
}

ssize_t cryptodev_cipher_encrypt(struct cipher_data *cdata,
		const struct scatterlist *src, struct scatterlist *dst,
		size_t len)
{
	int ret;

	reinit_completion(&cdata->async.result.completion);

	if (cdata->aead == 0) {
		cryptodev_blkcipher_request_set_crypt(cdata->async.request,
			(struct scatterlist *)src, dst,
			len, cdata->async.iv);
		ret = cryptodev_crypto_blkcipher_encrypt(cdata->async.request);
	} else {
		aead_request_set_crypt(cdata->async.arequest,
			(struct scatterlist *)src, dst,
			len, cdata->async.iv);
		ret = crypto_aead_encrypt(cdata->async.arequest);
	}

	return waitfor(&cdata->async.result, ret);
}

ssize_t cryptodev_cipher_decrypt(struct cipher_data *cdata,
		const struct scatterlist *src, struct scatterlist *dst,
		size_t len)
{
	int ret;

	reinit_completion(&cdata->async.result.completion);
	if (cdata->aead == 0) {
		cryptodev_blkcipher_request_set_crypt(cdata->async.request,
			(struct scatterlist *)src, dst,
			len, cdata->async.iv);
		ret = cryptodev_crypto_blkcipher_decrypt(cdata->async.request);
	} else {
		aead_request_set_crypt(cdata->async.arequest,
			(struct scatterlist *)src, dst,
			len, cdata->async.iv);
		ret = crypto_aead_decrypt(cdata->async.arequest);
	}

	return waitfor(&cdata->async.result, ret);
}

/* Hash functions */

int cryptodev_hash_init(struct hash_data *hdata, const char *alg_name,
			int hmac_mode, void *mackey, size_t mackeylen)
{
	int ret;

	hdata->async.s = crypto_alloc_ahash(alg_name, 0, 0);
	if (unlikely(IS_ERR(hdata->async.s))) {
		ddebug(1, "Failed to load transform for %s", alg_name);
		return -EINVAL;
	}

	/* Copy the key from user and set to TFM. */
	if (hmac_mode != 0) {
		ret = crypto_ahash_setkey(hdata->async.s, mackey, mackeylen);
		if (unlikely(ret)) {
			ddebug(1, "Setting hmac key failed for %s-%zu.",
					alg_name, mackeylen*8);
			ret = -EINVAL;
			goto error;
		}
	}

	hdata->digestsize = crypto_ahash_digestsize(hdata->async.s);
	hdata->alignmask = crypto_ahash_alignmask(hdata->async.s);

	init_completion(&hdata->async.result.completion);

	hdata->async.request = ahash_request_alloc(hdata->async.s, GFP_KERNEL);
	if (unlikely(!hdata->async.request)) {
		derr(0, "error allocating async crypto request");
		ret = -ENOMEM;
		goto error;
	}

	ahash_request_set_callback(hdata->async.request,
			CRYPTO_TFM_REQ_MAY_BACKLOG,
			cryptodev_complete, &hdata->async.result);
	hdata->init = 1;
	return 0;

error:
	crypto_free_ahash(hdata->async.s);
	return ret;
}

void cryptodev_hash_deinit(struct hash_data *hdata)
{
	if (hdata->init) {
		ahash_request_free(hdata->async.request);
		crypto_free_ahash(hdata->async.s);
		hdata->init = 0;
	}
}

int cryptodev_hash_reset(struct hash_data *hdata)
{
	int ret;

	ret = crypto_ahash_init(hdata->async.request);
	if (unlikely(ret)) {
		derr(0, "error in crypto_hash_init()");
		return ret;
	}

	return 0;

}

ssize_t cryptodev_hash_update(struct hash_data *hdata,
				struct scatterlist *sg, size_t len)
{
	int ret;

	reinit_completion(&hdata->async.result.completion);
	ahash_request_set_crypt(hdata->async.request, sg, NULL, len);

	ret = crypto_ahash_update(hdata->async.request);

	return waitfor(&hdata->async.result, ret);
}

int cryptodev_hash_final(struct hash_data *hdata, void *output)
{
	int ret;

	reinit_completion(&hdata->async.result.completion);
	ahash_request_set_crypt(hdata->async.request, NULL, output, 0);

	ret = crypto_ahash_final(hdata->async.request);

	return waitfor(&hdata->async.result, ret);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4, 3, 0))
/* This function is necessary because the bignums in Linux kernel are MSB first
 * (big endian) as opposed to LSB first as OpenBSD crypto layer uses */
void reverse_buf(uint8_t *buf, size_t sz)
{
	int i;
	uint8_t *end;
	uint8_t tmp;

	end = buf + sz;

	for (i = 0; i < sz/2; i++) {
		end--;

		tmp = *buf;
		*buf = *end;
		*end = tmp;

		buf++;
	}
}

int ber_wr_tag(uint8_t **ber_ptr, uint8_t tag)
{
	**ber_ptr = tag;
	*ber_ptr += 1;

	return 0;
}

int ber_wr_len(uint8_t **ber_ptr, size_t len, size_t sz)
{
	if (len < 127) {
		**ber_ptr = len;
		*ber_ptr += 1;
	} else {
		size_t sz_save = sz;

		sz--;
		**ber_ptr = 0x80 | sz;

		while (sz > 0) {
			*(*ber_ptr + sz) = len & 0xff;
			len >>= 8;
			sz--;
		}
		*ber_ptr += sz_save;
	}

	return 0;
}

int ber_wr_int(uint8_t **ber_ptr, uint8_t *crp_p, size_t sz)
{
	int ret;

	ret = copy_from_user(*ber_ptr, crp_p, sz);
	reverse_buf(*ber_ptr, sz);

	*ber_ptr += sz;

	return ret;
}

/* calculate the size of the length field itself in BER encoding */
size_t ber_enc_len(size_t len)
{
	size_t sz;

	sz = 1;
	if (len > 127) {		/* long encoding */
		while (len != 0) {
			len >>= 8;
			sz++;
		}
	}

	return sz;
}

void *cryptodev_alloc_rsa_pub_key(struct kernel_crypt_pkop *pkop,
		uint32_t *key_len)
{
	struct crypt_kop *cop = &pkop->pkop;
	uint8_t *ber_key;
	uint8_t *ber_ptr;
	uint32_t ber_key_len;
	size_t s_sz;
	size_t e_sz;
	size_t n_sz;
	size_t s_enc_len;
	size_t e_enc_len;
	size_t n_enc_len;
	int err;

	/* BER public key format:
	 * SEQUENCE TAG         1 byte
	 * SEQUENCE LENGTH	s_enc_len bytes
	 * INTEGER TAG		1 byte
	 * INTEGER LENGTH	n_enc_len bytes
	 * INTEGER (n modulus)	n_sz bytes
	 * INTEGER TAG		1 byte
	 * INTEGER LENGTH	e_enc_len bytes
	 * INTEGER (e exponent)	e_sz bytes
	 */

	e_sz = (cop->crk_param[1].crp_nbits + 7)/8;
	n_sz = (cop->crk_param[2].crp_nbits + 7)/8;

	e_enc_len = ber_enc_len(e_sz);
	n_enc_len = ber_enc_len(n_sz);

	/*
	 * Sequence length is the size of all the fields following the sequence
	 * tag, added together. The two added bytes account for the two INT
	 * tags in the Public Key sequence
	 */
	s_sz = e_sz + e_enc_len + n_sz + n_enc_len + 2;
	s_enc_len = ber_enc_len(s_sz);

	/* The added byte accounts for the SEQ tag at the start of the key */
	ber_key_len = s_sz + s_enc_len + 1;

	/* Linux asn1_ber_decoder doesn't like keys that are too large */
	if (ber_key_len > 65535) {
		return NULL;
	}

	ber_key = kmalloc(ber_key_len, GFP_DMA);
	if (!ber_key) {
		return NULL;
	}

	ber_ptr = ber_key;

	err = ber_wr_tag(&ber_ptr, _tag(UNIV, CONS, SEQ))         ||
	      ber_wr_len(&ber_ptr, s_sz, s_enc_len)               ||
	      ber_wr_tag(&ber_ptr, _tag(UNIV, PRIM, INT))         ||
	      ber_wr_len(&ber_ptr, n_sz, n_enc_len)               ||
	      ber_wr_int(&ber_ptr, cop->crk_param[2].crp_p, n_sz) ||
	      ber_wr_tag(&ber_ptr, _tag(UNIV, PRIM, INT))         ||
	      ber_wr_len(&ber_ptr, e_sz, e_enc_len)               ||
	      ber_wr_int(&ber_ptr, cop->crk_param[1].crp_p, e_sz);
	if (err != 0) {
		goto free_key;
	}

	*key_len = ber_key_len;
	return ber_key;

free_key:
	kfree(ber_key);
	return NULL;
}

int crypto_bn_modexp(struct kernel_crypt_pkop *pkop)
{
	struct crypt_kop *cop = &pkop->pkop;
	uint8_t *ber_key;
	uint32_t ber_key_len;
	size_t m_sz;
	size_t c_sz;
	size_t c_sz_max;
	uint8_t *m_buf;
	uint8_t *c_buf;
	struct scatterlist src;
	struct scatterlist dst;
	int err;

	ber_key = cryptodev_alloc_rsa_pub_key(pkop, &ber_key_len);
	if (!ber_key) {
		return -ENOMEM;
	}

	err = crypto_akcipher_set_pub_key(pkop->s, ber_key, ber_key_len);
	if (err != 0) {
		goto free_key;
	}

	m_sz = (cop->crk_param[0].crp_nbits + 7)/8;
	c_sz = (cop->crk_param[3].crp_nbits + 7)/8;

	m_buf = kmalloc(m_sz, GFP_DMA);
	if (!m_buf) {
		err = -ENOMEM;
		goto free_key;
	}

	err = copy_from_user(m_buf, cop->crk_param[0].crp_p, m_sz);
	if (err != 0) {
		goto free_m_buf;
	}
	reverse_buf(m_buf, m_sz);

	c_sz_max = crypto_akcipher_maxsize(pkop->s);
	if (c_sz > c_sz_max) {
		err = -EINVAL;
		goto free_m_buf;
	}

	c_buf = kzalloc(c_sz_max, GFP_KERNEL);
	if (!c_buf) {
		goto free_m_buf;
	}

	sg_init_one(&src, m_buf, m_sz);
	sg_init_one(&dst, c_buf, c_sz);

	init_completion(&pkop->result.completion);
	akcipher_request_set_callback(pkop->req, 0,
			cryptodev_complete, &pkop->result);
	akcipher_request_set_crypt(pkop->req, &src, &dst, m_sz, c_sz);

	err = crypto_akcipher_encrypt(pkop->req);
	err = waitfor(&pkop->result, err);

	if (err == 0) {
		reverse_buf(c_buf, c_sz);
		err = copy_to_user(cop->crk_param[3].crp_p, c_buf, c_sz);
	}

	kfree(c_buf);
free_m_buf:
	kfree(m_buf);
free_key:
	kfree(ber_key);

	return err;
}
#endif
