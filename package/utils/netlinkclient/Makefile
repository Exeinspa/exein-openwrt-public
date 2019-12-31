#
# Copyright (C) 2019 Exein
#
# $Id: $

include $(TOPDIR)/rules.mk

PKG_NAME:=NetlinkClient
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/NetlinkClient
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=NetlinkClient
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./files/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(PKG_BUILD_DIR)" \
		CC="$(TARGET_CC)" \
		LD="$(TARGET_CROSS)ld" \
		CFLAGS+="$(TARGET_CFLAGS) -fPIC -Iinc -Wall -lpthread" \
		TARGET_CFLAGS="$(TARGET_CFLAGS)" \
		TARGET_LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/NetlinkClient/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/NetlinkClient $(1)/usr/bin/NetlinkClient
endef

$(eval $(call BuildPackage,NetlinkClient))
