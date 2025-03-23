cmake_minimum_required(VERSION 3.5)
project(netrace
    VERSION 0.0.1
)

option(NT_ENABLE_ASAN "Enable AddressSanitizer" OFF)
if (NT_ENABLE_ASAN)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

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
    "src/runtime/raw.c"
    "src/runtime/socks5.c"
    "src/utils/list.c"
    "src/utils/log.c"
    "src/utils/map.c"
    "src/utils/memory.c"
    "src/utils/socket.c"
    "src/utils/str.c"
    "src/utils/syscall.c"
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
        -DCMAKE_PROJECT_VERSION="${CMAKE_PROJECT_VERSION}"
)

add_executable(${PROJECT_NAME}
    "src/main.c"
)
setup_target_wall(${PROJECT_NAME})
target_link_libraries(${PROJECT_NAME} PRIVATE lib${PROJECT_NAME})

###############################################################################
# Build test
###############################################################################

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
endif()
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(test)
endif()
