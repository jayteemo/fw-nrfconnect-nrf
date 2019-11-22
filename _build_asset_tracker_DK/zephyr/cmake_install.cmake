# Install script for directory: /Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/zephyr

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
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/arch/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/lib/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/soc/arm/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/boards/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/ext/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/subsys/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/drivers/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/nrf/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/nffs/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/segger/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/mbedtls/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/mcuboot/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/mcumgr/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/tinycbor/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/nrfxlib/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/civetweb/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/fatfs/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/nordic/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/st/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/libmetal/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/lvgl/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/open-amp/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/openthread/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/modules/littlefs/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/kernel/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/cmake/flash/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/zephyr/cmake/reports/cmake_install.cmake")

endif()

