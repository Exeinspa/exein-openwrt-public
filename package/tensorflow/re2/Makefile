include $(TOPDIR)/rules.mk

PKG_NAME:=re2
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/google/re2.git
PKG_SOURCE_VERSION:=2206f4f59a3862e5220712e1c4dcbd8b45f70861
PKG_MIRROR_HASH:=99ff365dd58b2e44f1e7c708084654f3f447ae2346afda1fa0eef029d5d7fd0b

PKG_INSTALL:=1
PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Exein <info@exein.io>


include $(INCLUDE_DIR)/package.mk

define Package/re2
	SECTION:=libs
	CATEGORY:=Tensorflow
	SUBMENU:=Libraries
	DEPENDS:=+libstdcpp
	TITLE:=a regular expression library.
endef

define Build/Compile
	$(MAKE) -C "$(PKG_BUILD_DIR)"
endef

define Package/re2/install
	$(INSTALL_DIR) $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/obj/so/libre2* $(1)/usr/lib/
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/obj/so/libre2* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,re2))
