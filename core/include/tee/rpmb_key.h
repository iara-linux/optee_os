/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef __TEE_RPMB_KEY_H
#define __TEE_RPMB_KEY_H

#include <stdint.h>
#include <tee_api_types.h>

/*
 * plat_rpmb_key_gen() - Derive the RPMB authentication key
 * @cid: Raw 16 byte eMMC CID
 * @key: Output buffer
 * @len: Size of @key, always RPMB_KEY_MAC_SIZE
 *
 * OP-TEE has set a very partciular way to derieve the RPMB key, which
 * involves taking the CID and masking off the fields which change across
 * eMMC FFU. It then derives the key from the HUK provided by HUK_SUBKEY_RPMB.
 *
 * That won't work for everybody however. There are many different RPMB key
 * derivation schemes and OP-TEE's default won't be what every vendor uses.
 *
 * And since RPMB keys cannot just be magically changed after already being
 * programmed, the only realistic way forward for devices using a different
 * scheme, is to allow people to override the default with their own, which is
 * what this function allows for.
 */
TEE_Result plat_rpmb_key_gen(const uint8_t *cid, uint8_t *key, uint32_t len);

#endif /*__TEE_RPMB_KEY_H*/
