ifeq ($(CFG_MTK_CRYPTO_DRIVER),y)

CFG_MTK_SEJ ?= y
CFG_MTK_DIE_ID ?= y

ifeq ($(CFG_MTK_SEJ),y)
$(call force,CFG_MTK_DIE_ID,y,Mandated by CFG_MTK_SEJ)
endif

CFG_MTK_RPMB_KEY ?= $(CFG_RPMB_FS)

ifeq ($(CFG_MTK_RPMB_KEY),y)
$(call force,CFG_MTK_SEJ,y,Mandated by CFG_MTK_RPMB_KEY)
CFG_MTK_RPMB_KEY_CID_SWAP ?= y
endif

endif # CFG_MTK_CRYPTO_DRIVER
