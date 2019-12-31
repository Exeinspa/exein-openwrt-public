include $(TOPDIR)/rules.mk

PKG_NAME:=vulnwww
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk


define Package/vulnwww
	SECTION:=net
  CATEGORY:=Network
  TITLE:=vulnwww
endef

define Build/Compile
endef

define Package/vulnwww/install
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(CP) ./files/* $(1)/www/cgi-bin/
endef

$(eval $(call BuildPackage,vulnwww))
