include $(TOPDIR)/rules.mk

PKG_NAME:=tf-exein
PKG_RELEASE:=1
PKG_BUILD_DEPENDS:=tensorflow-lite libexnl xtensor flatbuffers

include $(INCLUDE_DIR)/package.mk

define Package/tf-exein
	SECTION:=libs
	CATEGORY:=Tensorflow
	TITLE:=TensorFlow Lite Exein player.
	SUBMENU:=MLE Player
	DEPENDS:=+tensorflow-lite +libstdcpp +flatbuffers +libexnl
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) $(TARGET_CONFIGURE_OPTS) -C $(PKG_BUILD_DIR)
endef

define Package/tf-exein/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tf-exein $(1)/usr/bin/tf-exein

	$(INSTALL_DIR) $(1)/etc/exein
	$(INSTALL_BIN) ./files/* $(1)/etc/exein
endef


$(eval $(call BuildPackage,tf-exein))
