# Install script for directory: /Users/justin/Github/FORKS/fota_v2/nrf

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
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/nrf/ext/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/nrf/lib/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/nrf/samples/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/nrf/subsys/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/nrf/drivers/cmake_install.cmake")
  include("/Users/justin/Github/FORKS/fota_v2/nrf/_build_asset_tracker_DK/spm/modules/nrf/tests/cmake_install.cmake")

endif()

