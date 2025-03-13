cmake_minimum_required(VERSION 3.5)
project(netrace
    VERSION 0.0.1
)

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
# Setup library
###############################################################################

set(cio_sources
    "cio.c"
)

add_executable(${PROJECT_NAME}
    "src/utils/log.c"
    "src/utils/map.c"
    "src/utils/syscall.c"
    "src/main.c"
)
setup_target_wall(${PROJECT_NAME})

target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(${PROJECT_NAME}
    PRIVATE
        -DCMAKE_PROJECT_NAME="${CMAKE_PROJECT_NAME}"
        -DCMAKE_PROJECT_VERSION="${CMAKE_PROJECT_VERSION}"
)

###############################################################################
# Build test
###############################################################################

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
endif()
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(test)
endif()
