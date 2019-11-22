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
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/arch/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/lib/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/soc/arm/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/boards/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/ext/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/subsys/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/drivers/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/nrf/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/nffs/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/segger/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/mbedtls/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/mcuboot/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/mcumgr/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/tinycbor/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/nrfxlib/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/civetweb/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/fatfs/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/nordic/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/st/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/libmetal/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/lvgl/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/open-amp/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/openthread/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/modules/littlefs/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/kernel/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/cmake/flash/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/WIP_cloud_cmds_json_format/nrf/_build_asset_tracker_DK/spm/zephyr/cmake/reports/cmake_install.cmake")

endif()

