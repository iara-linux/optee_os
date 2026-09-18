// SPDX-License-Identifier: BSD-2-Clause

#include <kernel/tee_common_otp.h>
#include <sej.h>
#include <stdint.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <util.h>

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	uint32_t din[HW_UNIQUE_KEY_LENGTH / sizeof(uint32_t)] = { };
	uint32_t dout[HW_UNIQUE_KEY_LENGTH / sizeof(uint32_t)] = { };
	TEE_Result res = TEE_SUCCESS;

	COMPILE_TIME_ASSERT(sizeof(hwkey->data) == sizeof(dout));

	if (tee_otp_get_die_id((uint8_t *)din, sizeof(din)))
		return TEE_ERROR_SECURITY;

	res = sp_sej_enc(sej_ctx_get(), (const uint8_t *)din, (uint8_t *)dout,
			 sizeof(dout));
	if (!res)
		memcpy(hwkey->data, dout, sizeof(hwkey->data));
	else
		memset(hwkey->data, 0, sizeof(hwkey->data));

	memzero_explicit(din, sizeof(din));
	memzero_explicit(dout, sizeof(dout));

	return res;
}
