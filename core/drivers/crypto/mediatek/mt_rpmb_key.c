// SPDX-License-Identifier: BSD-2-Clause

#include <config.h>
#include <sej.h>
#include <stdint.h>
#include <string.h>
#include <string_ext.h>
#include <tee/rpmb_key.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#define MTK_RPMB_CID_SIZE	16
#define MTK_RPMB_KEY_SIZE	32

static void mt_reverse(uint8_t *buf, size_t size)
{
	size_t i = 0;

	for (i = 0; i < size / 2; i++) {
		uint8_t tmp = buf[size - i - 1];

		buf[size - i - 1] = buf[i];
		buf[i] = tmp;
	}
}

TEE_Result plat_rpmb_key_gen(const uint8_t *cid, uint8_t *key, uint32_t len)
{
	uint8_t expand[MTK_RPMB_KEY_SIZE] = { };
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	if (!cid || !key || len != MTK_RPMB_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Repeat the 16 byte CID to fill two AES blocks. */
	for (i = 0; i < sizeof(expand); i++)
		expand[i] = cid[i % MTK_RPMB_CID_SIZE];

	res = sp_sej_enc(sej_ctx_get(), expand, expand, sizeof(expand));
	if (res) {
		EMSG("RPMB: SEJ key derivation failed: %#"PRIx32, res);
		goto out;
	}

	/* Reverse the whole 32 byte result. */
	mt_reverse(expand, sizeof(expand));

	memcpy(key, expand, len);
out:
	memzero_explicit(expand, sizeof(expand));

	return res;
}
