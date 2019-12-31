#
# Copyright (C) 2019 Exien
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=lib60870
PKG_VERSION:=2.1.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/lib60870
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=open source libraries for IEC 61850 and IEC 60870-5-104
  URL:=https://libiec61850.com/libiec61850/
endef

CONFIGURE_ARGS += \
	--enable-static

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./files/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(PKG_BUILD_DIR)" \
		CC="$(TARGET_CC)" \
		LD="$(TARGET_CROSS)ld" \
		TARGET_CFLAGS="$(TARGET_CFLAGS)" \
		TARGET_LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	mkdir -p $(1)/usr/include/lib60870
	$(CP) $(PKG_BUILD_DIR)/src/inc/api $(1)/usr/include/lib60870
	$(CP) $(PKG_BUILD_DIR)/src/hal/inc  $(1)/usr/include/lib60870
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/build/lib60870.a $(1)/usr/lib/
endef

$(eval $(call BuildPackage,lib60870))
