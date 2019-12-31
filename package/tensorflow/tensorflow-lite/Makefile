include $(TOPDIR)/rules.mk

PKG_NAME:=tensorflow-lite
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/tensorflow/tensorflow.git
PKG_SOURCE_VERSION:=v2.0.0
PKG_MIRROR_HASH:=49b5f0495cd681cbcb5296a4476853d4aea19a43bdd9f179c928a977308a0617
PKG_BUILD_DEPENDS:=protobuf abseil flatbuffers eigen farmhash fft2d libdouble-conversion re2 nsync gemmlowp
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Exein <info@exein.io>


PKG_INSTALL:=1
CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/host-build.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/tensorflow-lite
	SECTION:=libs
	CATEGORY:=Tensorflow
	TITLE:=TensorFlow Lite is the official solution for running machine learning models on mobile and embedded devices.
	DEPENDS:=+protobuf +abseil +flatbuffers +farmhash +fft2d +libdouble-conversion +re2 +nsync +gemmlowp +libatomic
endef

CMAKE_OPTIONS += \
	-DTFLITE_TESTING=off \
	-DTFLITE_TYPE=full \
	-DSYSROOT=$(STAGING_DIR) \
	-DCMAKE_INSTALL_PREFIX="/usr" \
	-DCMAKE_COLOR_MAKEFILE=OFF \
	-DBUILD_DOC=OFF \
	-DBUILD_EXAMPLE=OFF \
	-DBUILD_TEST=OFF \
	-DBUILD_TESTING=OFF \
	-DBUILD_SHARED_LIBS=ON \
	-DCMAKE_CXX_FLAGS="$(TARGET_CPPFLAGS) -std=c++11" \


define Package/tensorflow-lite/install
	$(INSTALL_DIR) $(1)/usr/lib/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tensorflow/lite/*.so $(1)/usr/lib
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tensorflow/lite/*.so $(1)/usr/lib

	# TODO
	mkdir -p $(1)/usr/include/tensorflow/./lite
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/*.h $(1)/usr/include/tensorflow/./lite
	mkdir -p $(1)/usr/include/tensorflow/./lite/c
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/c/*.h $(1)/usr/include/tensorflow/./lite/c
	mkdir -p $(1)/usr/include/tensorflow/./lite/core
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/core/*.h $(1)/usr/include/tensorflow/./lite/core
	mkdir -p $(1)/usr/include/tensorflow/./lite/core/api
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/core/api/*.h $(1)/usr/include/tensorflow/./lite/core/api
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/flex
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/flex/*.h $(1)/usr/include/tensorflow/./lite/delegates/flex
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/gpu
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/gpu/*.h $(1)/usr/include/tensorflow/./lite/delegates/gpu
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/gpu/common
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/gpu/common/*.h $(1)/usr/include/tensorflow/./lite/delegates/gpu/common
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/gpu/common/testing
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/gpu/common/testing/*.h $(1)/usr/include/tensorflow/./lite/delegates/gpu/common/testing
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/gpu/common/transformations
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/gpu/common/transformations/*.h $(1)/usr/include/tensorflow/./lite/delegates/gpu/common/transformations
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/gpu/gl
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/gpu/gl/*.h $(1)/usr/include/tensorflow/./lite/delegates/gpu/gl
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/gpu/gl/compiler
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/gpu/gl/compiler/*.h $(1)/usr/include/tensorflow/./lite/delegates/gpu/gl/compiler
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/gpu/gl/converters
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/gpu/gl/converters/*.h $(1)/usr/include/tensorflow/./lite/delegates/gpu/gl/converters
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/gpu/gl/kernels
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/gpu/gl/kernels/*.h $(1)/usr/include/tensorflow/./lite/delegates/gpu/gl/kernels
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/gpu/gl/runtime
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/gpu/gl/runtime/*.h $(1)/usr/include/tensorflow/./lite/delegates/gpu/gl/runtime
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/gpu/gl/workgroups
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/gpu/gl/workgroups/*.h $(1)/usr/include/tensorflow/./lite/delegates/gpu/gl/workgroups
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/gpu/metal
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/gpu/metal/*.h $(1)/usr/include/tensorflow/./lite/delegates/gpu/metal
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/gpu/metal/kernels
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/gpu/metal/kernels/*.h $(1)/usr/include/tensorflow/./lite/delegates/gpu/metal/kernels
	mkdir -p $(1)/usr/include/tensorflow/./lite/delegates/nnapi
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/delegates/nnapi/*.h $(1)/usr/include/tensorflow/./lite/delegates/nnapi
	mkdir -p $(1)/usr/include/tensorflow/./lite/experimental/resource_variable
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/experimental/resource_variable/*.h $(1)/usr/include/tensorflow/./lite/experimental/resource_variable
	mkdir -p $(1)/usr/include/tensorflow/./lite/kernels
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/kernels/*.h $(1)/usr/include/tensorflow/./lite/kernels
	mkdir -p $(1)/usr/include/tensorflow/./lite/kernels/internal
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/kernels/internal/*.h $(1)/usr/include/tensorflow/./lite/kernels/internal
	mkdir -p $(1)/usr/include/tensorflow/./lite/kernels/internal/optimized
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/kernels/internal/optimized/*.h $(1)/usr/include/tensorflow/./lite/kernels/internal/optimized
	mkdir -p $(1)/usr/include/tensorflow/./lite/kernels/internal/optimized/integer_ops
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/kernels/internal/optimized/integer_ops/*.h $(1)/usr/include/tensorflow/./lite/kernels/internal/optimized/integer_ops
	mkdir -p $(1)/usr/include/tensorflow/./lite/kernels/internal/reference
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/kernels/internal/reference/*.h $(1)/usr/include/tensorflow/./lite/kernels/internal/reference
	mkdir -p $(1)/usr/include/tensorflow/./lite/kernels/internal/reference/integer_ops
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/kernels/internal/reference/integer_ops/*.h $(1)/usr/include/tensorflow/./lite/kernels/internal/reference/integer_ops
	mkdir -p $(1)/usr/include/tensorflow/./lite/nnapi
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/nnapi/*.h $(1)/usr/include/tensorflow/./lite/nnapi
	mkdir -p $(1)/usr/include/tensorflow/./lite/profiling
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/profiling/*.h $(1)/usr/include/tensorflow/./lite/profiling
	mkdir -p $(1)/usr/include/tensorflow/./lite/schema
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/schema/*.h $(1)/usr/include/tensorflow/./lite/schema
	mkdir -p $(1)/usr/include/tensorflow/./lite/schema/builtin_ops_header
	$(CP)  $(PKG_BUILD_DIR)/tensorflow/./lite/schema/builtin_ops_header/*.h $(1)/usr/include/tensorflow/./lite/schema/builtin_ops_header
endef

$(eval $(call BuildPackage,tensorflow-lite))
