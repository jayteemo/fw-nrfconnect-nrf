# Install script for directory: /Users/justin/Github/FORKS/fota_v2/zephyr

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "TRUE")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/zephyr/arch/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/zephyr/lib/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/zephyr/soc/arm/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/zephyr/boards/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/zephyr/subsys/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/zephyr/drivers/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/nrf/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/mcuboot/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/mcumgr/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/nrfxlib/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/cmsis/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/canopennode/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/civetweb/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/fatfs/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/nordic/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/st/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/libmetal/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/lvgl/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/mbedtls/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/open-amp/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/loramac-node/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/openthread/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/segger/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/tinycbor/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/tinycrypt/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/littlefs/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/mipi-sys-t/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/nrf_hw_models/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/zephyr/kernel/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/zephyr/cmake/flash/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/zephyr/cmake/usage/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/zephyr/cmake/reports/cmake_install.cmake")

endif()

