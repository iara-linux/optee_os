/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef __SEJ_H__
#define __SEJ_H__

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define SEJ_REG_SIZE        (0x1000)

#define SEJ_CON             (0x0000)
#define SEJ_ACON            (0x0004)
#define SEJ_ACON2           (0x0008)
#define SEJ_ACONK           (0x000C)
#define SEJ_ASRC0           (0x0010)
#define SEJ_ASRC1           (0x0014)
#define SEJ_ASRC2           (0x0018)
#define SEJ_ASRC3           (0x001C)
#define SEJ_AKEY0           (0x0020)
#define SEJ_AKEY1           (0x0024)
#define SEJ_AKEY2           (0x0028)
#define SEJ_AKEY3           (0x002C)
#define SEJ_AKEY4           (0x0030)
#define SEJ_AKEY5           (0x0034)
#define SEJ_AKEY6           (0x0038)
#define SEJ_AKEY7           (0x003C)
#define SEJ_ACFG0           (0x0040)
#define SEJ_ACFG1           (0x0044)
#define SEJ_ACFG2           (0x0048)
#define SEJ_ACFG3           (0x004C)
#define SEJ_AOUT0           (0x0050)
#define SEJ_AOUT1           (0x0054)
#define SEJ_AOUT2           (0x0058)
#define SEJ_AOUT3           (0x005C)
#define SEJ_SW_OTP0         (0x0060)
#define SEJ_SW_OTP1         (0x0064)
#define SEJ_SW_OTP2         (0x0068)
#define SEJ_SW_OTP3         (0x006C)
#define SEJ_SW_OTP4         (0x0070)
#define SEJ_SW_OTP5         (0x0074)
#define SEJ_SW_OTP6         (0x0078)
#define SEJ_SW_OTP7         (0x007C)

#define SEJ_AES_DEC         (0 << 0)
#define SEJ_AES_ENC         (1 << 0)

#define SEJ_AES_ECB         (0 << 1)
#define SEJ_AES_CBC         (1 << 1)

#define SEJ_AES_128         (0 << 4)
#define SEJ_AES_192         (1 << 4)
#define SEJ_AES_256         (2 << 4)

#define SEJ_AES_CHG_BO_OFF  (0 << 12)
#define SEJ_AES_CHG_BO_ON   (1 << 12)

#define SEJ_AES_START       (1 << 0)
#define SEJ_AES_CLR         (1 << 1)
#define SEJ_AES_RDY         (1 << 15)

#define SEJ_AES_BK2C        (1 << 4)
#define SEJ_AES_R2K         (1 << 8)

#define AES_BLK_SZ          (16)

typedef enum {
	AES_DEC,
	AES_ENC
} AES_OPS;

struct sej_ctx {
	unsigned int lock;
	vaddr_t base;
};

struct sej_ctx *sej_ctx_get(void);

TEE_Result sp_sej_enc(struct sej_ctx *ctx, const uint8_t *in, uint8_t *out,
		      size_t size);
TEE_Result sp_sej_dec(struct sej_ctx *ctx, const uint8_t *in, uint8_t *out,
		      size_t size);

#endif /* __SEJ_H__ */
