CFG_TEE_TA_LOG_LEVEL ?= 4
CFG_TA_OPTEE_CORE_API_COMPAT_1_1=y

# The UUID for the Trusted Application
BINARY=7566754d-6889-4873-b94c-eaeadb7ff795

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
	@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
