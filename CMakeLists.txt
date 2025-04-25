cmake_minimum_required(VERSION 3.5)
project(netrace)

option(NT_ENABLE_ASAN "Enable AddressSanitizer" OFF)
if (NT_ENABLE_ASAN)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

set(NT_VERSION "unknown" CACHE STRING "Project version string")

###############################################################################
# Support functions
###############################################################################
function(setup_target_wall name)
    if (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
        target_compile_options(${name} PRIVATE /W4 /WX)
    else ()
        target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    endif ()
endfunction()

###############################################################################
# Setup library and executable file
###############################################################################

add_library(lib${PROJECT_NAME} STATIC
    "src/runtime/__init__.c"
    "src/runtime/dns.c"
    "src/runtime/raw.c"
    "src/runtime/socks5.c"
    "src/trace/__init__.c"
    "src/trace/accept.c"
    "src/trace/accept4.c"
    "src/trace/bind.c"
    "src/trace/clone.c"
    "src/trace/close.c"
    "src/trace/close_range.c"
    "src/trace/connect.c"
    "src/trace/dup.c"
    "src/trace/dup2.c"
    "src/trace/dup3.c"
    "src/trace/execve.c"
    "src/trace/fcntl.c"
    "src/trace/getpeername.c"
    "src/trace/getpid.c"
    "src/trace/getsockname.c"
    "src/trace/getuid.c"
    "src/trace/ioctl.c"
    "src/trace/listen.c"
    "src/trace/pipe2.c"
    "src/trace/pread64.c"
    "src/trace/pwrite64.c"
    "src/trace/read.c"
    "src/trace/recvfrom.c"
    "src/trace/sendmmsg.c"
    "src/trace/sendto.c"
    "src/trace/setsockopt.c"
    "src/trace/shutdown.c"
    "src/trace/socket.c"
    "src/trace/socketpair.c"
    "src/trace/write.c"
    "src/utils/cmdoption.c"
    "src/utils/cstr.c"
    "src/utils/dns.c"
    "src/utils/file.c"
    "src/utils/ipfilter.c"
    "src/utils/list.c"
    "src/utils/log.c"
    "src/utils/map.c"
    "src/utils/memory.c"
    "src/utils/random.c"
    "src/utils/socket.c"
    "src/utils/str.c"
    "src/utils/syscall.c"
    "src/utils/time.c"
    "src/utils/urlparser.c"
)
setup_target_wall(lib${PROJECT_NAME})
target_include_directories(lib${PROJECT_NAME}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_options(lib${PROJECT_NAME}
    PUBLIC
        -DCMAKE_PROJECT_NAME="${CMAKE_PROJECT_NAME}"
        -DNT_VERSION="${NT_VERSION}"
)

add_executable(${PROJECT_NAME}
    "src/main.c"
)
setup_target_wall(${PROJECT_NAME})
target_link_libraries(${PROJECT_NAME} PRIVATE lib${PROJECT_NAME})

###############################################################################
# 3rd
###############################################################################

include(third_party/cJSON.cmake)
target_link_libraries(${PROJECT_NAME} PRIVATE cJSON)

###############################################################################
# Build test
###############################################################################

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
endif()
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(test)
endif()
