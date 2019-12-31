include $(TOPDIR)/rules.mk

PKG_NAME:=xtl
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/xtensor-stack/xtl.git
PKG_SOURCE_VERSION:=f0dd1fd367156174fbaa25324a4ed7748691874f

PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Exein <info@exein.io>

include $(INCLUDE_DIR)/package.mk


define Package/xtl
	SECTION:=libs
	CATEGORY:=Tensorflow
	SUBMENU:=Libraries
	TITLE:=Basic tools (containers, algorithms) used by other quantstack packages.
	DEPENDS:=+libstdcpp
endef

define Build/Compile
endef

define Package/xtl/install
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/xtl
	$(CP) -a $(PKG_BUILD_DIR)/include/xtl $(1)/usr/include
endef

$(eval $(call BuildPackage,xtl))
