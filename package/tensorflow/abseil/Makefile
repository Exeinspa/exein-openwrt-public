include $(TOPDIR)/rules.mk

PKG_NAME:=abseil
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/abseil/abseil-cpp.git
PKG_SOURCE_VERSION:=cc8dcd307b76a575d2e3e0958a4fe4c7193c2f68
PKG_MIRROR_HASH:=e35082e88b9da04f4d68094c05ba112502a5063712f3021adfa465306d238c76
PKG_BUILD_DEPENDS:=abseil/host

PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Exein <info@exein.io>

CMAKE_INSTALL:=1
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/host-build.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/abseil
	SECTION:=libs
	CATEGORY:=Tensorflow
	SUBMENU:=Libraries
	TITLE:=open-source collection of C++ code.
endef

CMAKE_OPTIONS += \
	-DBUILD_TESTING=OFF

CMAKE_HOST_OPTIONS += \
	-DBUILD_TESTING=OFF \
	-DCMAKE_CXX_FLAGS="$(TARGET_CPPFLAGS) -fPIC"

define Package/abseil/install
	$(INSTALL_DIR) $(1)/usr/lib/
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/libabsl_* $(1)/usr/lib/
endef


define Host/Compile
endef

define Host/Install
	$(INSTALL_DIR) $(STAGING_DIR_HOST)/include/absl
	$(INSTALL_DATA) $(HOST_BUILD_DIR)/absl/*/*.h $(STAGING_DIR_HOST)/include/absl
endef


$(eval $(call HostBuild))
$(eval $(call BuildPackage,abseil))
