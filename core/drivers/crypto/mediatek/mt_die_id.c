// SPDX-License-Identifier: BSD-2-Clause

#include <io.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <types_ext.h>

#define EFUSE_REG_SIZE		0x1000

#define EFUSE_DIE_ID0		0x140
#define EFUSE_DIE_ID1		0x144

#define MTK_DIE_ID_SIZE		8

register_phys_mem_pgdir(MEM_AREA_IO_SEC, EFUSE_BASE, EFUSE_REG_SIZE);

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	uint32_t die_id[MTK_DIE_ID_SIZE / sizeof(uint32_t)] = { };
	vaddr_t base = 0;

	if (!buffer || len < MTK_DIE_ID_SIZE)
		return -1;

	base = (vaddr_t)phys_to_virt(EFUSE_BASE, MEM_AREA_IO_SEC,
				     EFUSE_REG_SIZE);
	if (!base)
		return -1;

	die_id[0] = io_read32(base + EFUSE_DIE_ID0);
	die_id[1] = io_read32(base + EFUSE_DIE_ID1);

	memcpy(buffer, die_id, sizeof(die_id));

	if (len > MTK_DIE_ID_SIZE)
		memset(buffer + MTK_DIE_ID_SIZE, 0, len - MTK_DIE_ID_SIZE);

	return 0;
}
