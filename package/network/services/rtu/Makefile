#
# Copyright (C) 2014 Gemtek
#
# $Id: $

include $(TOPDIR)/rules.mk

PKG_NAME:=rtu
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk


define Package/rtu
	SECTION:=net
  CATEGORY:=Network
  TITLE:=rtu
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef
#		TARGET_CFLAGS="$(TARGET_CFLAGS)" \

define Build/Compile
	$(MAKE) -C "$(PKG_BUILD_DIR)" \
		CC="$(TARGET_CC)" \
		LD="$(TARGET_CROSS)ld" \
		OBJCOPY="$(TARGET_CROSS)objcopy" \
		CFLAGS+="$(TARGET_CFLAGS) -fPIC -Iinc -Wall -I$(STAGING_DIR)/usr/include/lib60870/inc -I$(STAGING_DIR)/usr/include/lib60870/api -lpthread" \
		TARGET_CFLAGS="$(TARGET_CFLAGS)" \
		TARGET_LDFLAGS="$(TARGET_LDFLAGS)"\
		TARGET_PIPPO="$(STAGING_DIR)/usr/lib/lib60870.a"
endef

define Package/rtu/install
	@echo "elaborate -> $(INSTALL_DIR) $(1)/usr/bin"
	$(INSTALL_DIR) $(1)/usr/bin
	@echo "elaborate -> $(INSTALL_BIN) $(PKG_BUILD_DIR)/rtu $(1)/usr/bin/rtu"
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rtu $(1)/usr/bin/rtu
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/rtu.init $(1)/etc/init.d/rtu
endef

$(eval $(call BuildPackage,rtu))
