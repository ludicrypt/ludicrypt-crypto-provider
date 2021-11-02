cmake_minimum_required(VERSION 3.15)

#set(VCPKG_CRT_LINKAGE dynamic CACHE STRING "")
#set(VCPKG_LIBRARY_LINKAGE static CACHE STRING "")
#set(VCPKG_TARGET_TRIPLET x64-windows-static CACHE STRING "Vcpkg target triplet" FORCE)

#set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake
#    CACHE STRING "Vcpkg toolchain file")

if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
endif()

project(ludicrypt VERSION 0.1.0 LANGUAGES CXX)

#set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(src)
