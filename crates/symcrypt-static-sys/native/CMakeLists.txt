cmake_minimum_required(VERSION 3.16)
project(symcrypt_static_bridge LANGUAGES C CXX)

option(SC_FREESTANDING "Build for the x86_64 freestanding ABI" OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(SYMCRYPT_BUILD_MODULES OFF CACHE BOOL "" FORCE)
set(SYMCRYPT_UNIT_TESTS OFF CACHE BOOL "" FORCE)
set(SYMCRYPT_USE_ASM ON CACHE BOOL "" FORCE)
set(SYMCRYPT_FIPS_BUILD ON CACHE BOOL "" FORCE)
set(SYMCRYPT_STACK_PROTECTION ON CACHE BOOL "" FORCE)
set(SYMCRYPT_TARGET_ARCH AMD64 CACHE STRING "" FORCE)
set(SYMCRYPT_SYMCRUST OFF CACHE BOOL "" FORCE)

add_compile_options(-ffunction-sections -fdata-sections -fno-builtin-bcmp)
if(SC_FREESTANDING)
    # The embedding firmware supplies the global stack guard and failure handler.
    add_compile_options(-ffreestanding -mno-red-zone -mstack-protector-guard=global)
endif()

add_subdirectory(SymCrypt symcrypt)
add_library(symcrypt_bridge STATIC environment.c bridge.c symmetric.c ecc.c rsa.c)
target_include_directories(symcrypt_bridge PRIVATE
    SymCrypt/inc SymCrypt/lib "${CMAKE_CURRENT_BINARY_DIR}/symcrypt/inc")
target_compile_options(symcrypt_bridge PRIVATE
    -Wall -Wextra -Werror -Wno-unknown-pragmas -Wno-multichar
    -fms-extensions -mssse3 -maes -mpclmul -fstack-protector-strong)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(symcrypt_bridge PRIVATE DBG=1)
endif()
target_compile_definitions(symcrypt_bridge PRIVATE SYMCRYPT_MODULE_DO_FIPS_SELFTESTS=1)
target_link_libraries(symcrypt_bridge PRIVATE symcrypt_common)
set_target_properties(symcrypt_bridge PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib")
