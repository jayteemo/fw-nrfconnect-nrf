# Install script for directory: /Users/justin/Github/FORKS/fsm_cleanup/nrf/subsys/net/lib

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
  include("/Users/justin/Github/FORKS/fsm_cleanup/nrf/_build_asset_tracker_DK/zephyr/modules/nrf/subsys/net/lib/cloud/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fsm_cleanup/nrf/_build_asset_tracker_DK/zephyr/modules/nrf/subsys/net/lib/nrf_cloud/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fsm_cleanup/nrf/_build_asset_tracker_DK/zephyr/modules/nrf/subsys/net/lib/download_client/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fsm_cleanup/nrf/_build_asset_tracker_DK/zephyr/modules/nrf/subsys/net/lib/fota_download/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fsm_cleanup/nrf/_build_asset_tracker_DK/zephyr/modules/nrf/subsys/net/lib/aws_jobs/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fsm_cleanup/nrf/_build_asset_tracker_DK/zephyr/modules/nrf/subsys/net/lib/aws_fota/cmake_install.cmake")

endif()

