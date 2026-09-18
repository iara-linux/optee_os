// SPDX-License-Identifier: BSD-2-Clause

#include <io.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <sej.h>
#include <stdint.h>
#include <string.h>
#include <string_ext.h>
#include <util.h>

#define SEJ_READY_RETRIES	100000

static const uint32_t g_AC_FIXED_PATTERN[3][4] = {
	{ 0x2D44BB70, 0xA744D227, 0xD0A9864B, 0x83FFC244 },
	{ 0x7EC8266B, 0x43E80FB2, 0x01A6348A, 0x2067F9A0 },
	{ 0x54536405, 0xD546A6B1, 0x1CC3EC3A, 0xDE377A83 }
};

static const uint32_t g_AC_BOOTROM_IV[8] = {
	0x9ED40400, 0x00E884A1, 0xE3F083BD, 0x2F4E6D8A,
	0xFF838E5C, 0xE940A0E3, 0x8D4DECC6, 0x45FC0989
};

static struct sej_ctx g_sej_ctx = {
	.lock = SPINLOCK_UNLOCK,
};

register_phys_mem_pgdir(MEM_AREA_IO_SEC, HACC_BASE, SEJ_REG_SIZE);

struct sej_ctx *sej_ctx_get(void)
{
	return &g_sej_ctx;
}

static bool sej_wait_ready(struct sej_ctx *ctx)
{
	unsigned int i = 0;

	for (i = 0; i < SEJ_READY_RETRIES; i++)
		if (io_read32(ctx->base + SEJ_ACON2) & SEJ_AES_RDY)
			return true;

	return false;
}

static void sej_write_iv(struct sej_ctx *ctx, const uint32_t *iv)
{
	io_write32(ctx->base + SEJ_ACFG0, iv[0]);
	io_write32(ctx->base + SEJ_ACFG1, iv[1]);
	io_write32(ctx->base + SEJ_ACFG2, iv[2]);
	io_write32(ctx->base + SEJ_ACFG3, iv[3]);
}

static void sej_clear_key(struct sej_ctx *ctx)
{
	int i = 0;

	for (i = 0; i < 8; i++)
		io_write32(ctx->base + SEJ_AKEY0 + (i * 4), 0);
}

static TEE_Result SEJ_V3_Init(struct sej_ctx *ctx, AES_OPS encrypt,
			      const uint32_t *iv)
{
	uint32_t acon_settings = 0;
	int i = 0;

	/* Keep byte order to LE, 128 bit key, CBC */
	acon_settings = SEJ_AES_CHG_BO_OFF | SEJ_AES_128 | SEJ_AES_CBC;
	acon_settings |= (encrypt == AES_ENC) ? SEJ_AES_ENC : SEJ_AES_DEC;

	/* Clear any leftover key */
	sej_clear_key(ctx);

	/* Derive META KEY */
	io_write32(ctx->base + SEJ_ACON,
		   SEJ_AES_CHG_BO_OFF | SEJ_AES_CBC | SEJ_AES_128 |
		   SEJ_AES_DEC);
	io_write32(ctx->base + SEJ_ACONK, SEJ_AES_BK2C | SEJ_AES_R2K);
	io_write32(ctx->base + SEJ_ACON2, SEJ_AES_CLR);

	sej_write_iv(ctx, iv);

	/*
	 * Derive a pattern that is fed back to the SEJ internal algo, and
	 * use that as key.
	 */
	for (i = 0; i < 3; i++) {
		io_write32(ctx->base + SEJ_ASRC0, g_AC_FIXED_PATTERN[i][0]);
		io_write32(ctx->base + SEJ_ASRC1, g_AC_FIXED_PATTERN[i][1]);
		io_write32(ctx->base + SEJ_ASRC2, g_AC_FIXED_PATTERN[i][2]);
		io_write32(ctx->base + SEJ_ASRC3, g_AC_FIXED_PATTERN[i][3]);

		io_write32(ctx->base + SEJ_ACON2, SEJ_AES_START);

		if (!sej_wait_ready(ctx))
			return TEE_ERROR_BUSY;
	}

	/* Clear AES_SRC, AES_CFG and AES_OUT */
	io_write32(ctx->base + SEJ_ACON2, SEJ_AES_CLR);

	sej_write_iv(ctx, iv);

	io_write32(ctx->base + SEJ_ACONK, 0);
	io_write32(ctx->base + SEJ_ACON, acon_settings);

	return TEE_SUCCESS;
}

static TEE_Result SEJ_V3_Run(struct sej_ctx *ctx, const uint8_t *src,
			     uint8_t *dst, size_t len)
{
	size_t blocks = len / AES_BLK_SZ;
	uint32_t blk[4] = { };
	size_t i = 0;

	while (blocks--) {
		memcpy(blk, src, sizeof(blk));

		for (i = 0; i < ARRAY_SIZE(blk); i++)
			io_write32(ctx->base + SEJ_ASRC0 + (i * 4), blk[i]);

		io_write32(ctx->base + SEJ_ACON2, SEJ_AES_START);

		if (!sej_wait_ready(ctx)) {
			memzero_explicit(blk, sizeof(blk));
			return TEE_ERROR_BUSY;
		}

		for (i = 0; i < ARRAY_SIZE(blk); i++)
			blk[i] = io_read32(ctx->base + SEJ_AOUT0 + (i * 4));

		memcpy(dst, blk, sizeof(blk));

		src += AES_BLK_SZ;
		dst += AES_BLK_SZ;
	}

	memzero_explicit(blk, sizeof(blk));

	return TEE_SUCCESS;
}

static void SEJ_V3_Terminate(struct sej_ctx *ctx)
{
	/* Clear AES_SRC, AES_CFG and AES_OUT */
	io_write32(ctx->base + SEJ_ACON2, SEJ_AES_CLR);

	/* Clear AES key */
	sej_clear_key(ctx);
}

static TEE_Result sej_do_hw_aes(struct sej_ctx *ctx, AES_OPS ops,
			     const uint8_t *in, uint8_t *out, size_t size)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t exceptions = 0;

	if (!ctx || !in || !out)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!size || !IS_ALIGNED(size, AES_BLK_SZ))
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = cpu_spin_lock_xsave(&ctx->lock);

	if (!ctx->base)
		ctx->base = (vaddr_t)phys_to_virt(HACC_BASE, MEM_AREA_IO_SEC,
						  SEJ_REG_SIZE);

	if (ctx->base) {
		res = SEJ_V3_Init(ctx, ops, g_AC_BOOTROM_IV);
		if (!res)
			res = SEJ_V3_Run(ctx, in, out, size);

		SEJ_V3_Terminate(ctx);
	} else {
		res = TEE_ERROR_GENERIC;
	}

	cpu_spin_unlock_xrestore(&ctx->lock, exceptions);

	return res;
}

TEE_Result sp_sej_enc(struct sej_ctx *ctx, const uint8_t *in, uint8_t *out,
		      size_t size)
{
	return sej_do_hw_aes(ctx, AES_ENC, in, out, size);
}

TEE_Result sp_sej_dec(struct sej_ctx *ctx, const uint8_t *in, uint8_t *out,
		      size_t size)
{
	return sej_do_hw_aes(ctx, AES_DEC, in, out, size);
}
