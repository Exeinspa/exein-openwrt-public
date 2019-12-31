#
# $Id: $

include $(TOPDIR)/rules.mk

PKG_NAME:=nlt
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk


define Package/nlt
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=nlt
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(PKG_BUILD_DIR)" \
		CC="$(TARGET_CC)" \
		LD="$(TARGET_CROSS)ld" \
		OBJCOPY="$(TARGET_CROSS)objcopy" \
		CFLAGS+="$(TARGET_CFLAGS) -fPIC -Iinc -Wall" \
		TARGET_CFLAGS="$(TARGET_CFLAGS)" \
		TARGET_LDFLAGS="$(TARGET_LDFLAGS)" 
endef

define Package/nlt/install
	@echo "elaborate -> $(INSTALL_DIR) $(1)/usr/bin"
	$(INSTALL_DIR) $(1)/usr/bin
	@echo "elaborate -> $(INSTALL_BIN) $(PKG_BUILD_DIR)/nlt $(1)/usr/bin/nlt"
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nlt $(1)/usr/bin/nlt
endef

$(eval $(call BuildPackage,nlt))
