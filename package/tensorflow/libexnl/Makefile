include $(TOPDIR)/rules.mk

PKG_NAME:=libexnl
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/libexnl
	SECTION:=libs
	CATEGORY:=Tensorflow
	SUBMENU:=Libraries
	TITLE:=simple library for handling the MLE netlink channel.
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) $(TARGET_CONFIGURE_OPTS) -C $(PKG_BUILD_DIR)
endef

define Package/libexnl/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/* $(1)/usr/lib
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/* $(1)/usr/lib

	$(INSTALL_DIR) $(1)/usr/include
	cat $(PKG_BUILD_DIR)/libexnl.h|sed -r 's/^([\t ]*)\.([a-zA-Z0-9_]*)([\t ]*)=([\t ]*)(.*)/\t\5/' >$(1)/usr/include/libexnl.h
	$(CP) -a $(PKG_BUILD_DIR)/uthash.h $(1)/usr/include/
endef

$(eval $(call BuildPackage,libexnl))
