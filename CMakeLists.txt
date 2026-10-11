cmake_minimum_required(VERSION 3.22)

# version.txt is bumped by release-please
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/version.txt" ZONETRACE_VERSION LIMIT_COUNT 1)
project(zonetrace VERSION ${ZONETRACE_VERSION} LANGUAGES CXX)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/version.txt")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(AshitaSDK REQUIRED)
ashita_sdk_initialize()

add_library(zonetrace MODULE
    "src/common/log.cpp"
    "src/common/log.h"
    "src/common/memory.cpp"
    "src/common/memory.h"
    "src/enums/attempt.h"
    "src/exports.def"
    "src/hooks/port.cpp"
    "src/hooks/port.h"
    "src/hooks/sockets.cpp"
    "src/hooks/sockets.h"
    "src/plugin.cpp"
    "src/plugin.h"
    "src/readers/key.cpp"
    "src/readers/key.h"
    "src/readers/recv.cpp"
    "src/readers/recv.h"
)
target_include_directories(zonetrace PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
set_target_properties(zonetrace PROPERTIES
    CXX_EXTENSIONS ON
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
    LINKER_LANGUAGE CXX
)

set(ZONETRACE_OUTPUT_DIR "" CACHE PATH "Directory zonetrace.dll is written to, the build directory if empty")
set_target_properties(zonetrace PROPERTIES OUTPUT_NAME "zonetrace")
if(ZONETRACE_OUTPUT_DIR)
    set_target_properties(zonetrace PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY "${ZONETRACE_OUTPUT_DIR}"
        RUNTIME_OUTPUT_DIRECTORY "${ZONETRACE_OUTPUT_DIR}"
    )
endif()

target_compile_definitions(zonetrace PRIVATE
    ZONETRACE_VERSION="${PROJECT_VERSION}"
    ZONETRACE_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    ZONETRACE_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    ZONETRACE_VERSION_PATCH=${PROJECT_VERSION_PATCH}
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
