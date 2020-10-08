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
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/zephyr/arch/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/zephyr/lib/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/zephyr/soc/arm/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/zephyr/boards/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/zephyr/subsys/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/zephyr/drivers/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/nrf/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/mcuboot/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/mcumgr/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/nrfxlib/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/cmsis/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/canopennode/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/civetweb/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/fatfs/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/nordic/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/st/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/libmetal/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/lvgl/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/mbedtls/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/open-amp/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/loramac-node/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/openthread/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/segger/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/tinycbor/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/tinycrypt/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/littlefs/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/mipi-sys-t/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/modules/nrf_hw_models/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/zephyr/kernel/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/zephyr/cmake/flash/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/zephyr/cmake/usage/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/zephyr/cmake/reports/cmake_install.cmake")

endif()

