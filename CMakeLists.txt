cmake_minimum_required(VERSION 3.22)

project(zonetrace CXX)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(AshitaSDK REQUIRED)
ashita_sdk_initialize()

add_library(zonetrace MODULE
    "src/exports.def"
    "src/key.cpp"
    "src/key.hpp"
    "src/log.cpp"
    "src/log.hpp"
    "src/memory.cpp"
    "src/memory.hpp"
    "src/plugin.cpp"
    "src/port.cpp"
    "src/port.hpp"
    "src/recv.cpp"
    "src/recv.hpp"
    "src/sockets.cpp"
    "src/sockets.hpp"
)
set_target_properties(zonetrace PROPERTIES
    CXX_EXTENSIONS ON
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    LINKER_LANGUAGE CXX
)

# running clients hold the dll open, so builds can target a staging folder instead
set(ZONETRACE_OUTPUT_DIR "E:/Ashita-v4beta/polplugins" CACHE PATH "Directory zonetrace.dll is written to")
set_target_properties(zonetrace PROPERTIES
    OUTPUT_NAME "zonetrace"
    LIBRARY_OUTPUT_DIRECTORY "${ZONETRACE_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${ZONETRACE_OUTPUT_DIR}"
)

ashita_sdk_attach(zonetrace)
ashita_sdk_set_compiler_defaults(zonetrace)
ashita_sdk_set_compiler_warn_level(zonetrace 4)
ashita_sdk_set_compiler_warnings_as_errors(zonetrace)
if (MSVC)
    # C5298: stray U+1A character in the Ashita SDK's d3d8/dxfile.h
    target_compile_options(zonetrace PRIVATE /wd5298)
endif()
ashita_sdk_set_linker_defaults(zonetrace)
ashita_sdk_set_linker_disable_debug_linking(zonetrace)
