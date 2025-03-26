
add_executable(${PROJECT_NAME}_test
    "cases/connect.c"
    "cases/exitcode.c"
    "cases/grandchild.c"
    "tools/__init__.c"
    "tools/exit.c"
    "tools/slice.c"
    "utils/socket2.c"
    "cutest.c"
    "runtime.c"
    "main.c"
)
target_include_directories(${PROJECT_NAME}_test
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)
setup_target_wall(${PROJECT_NAME}_test)
target_link_libraries(${PROJECT_NAME}_test PRIVATE lib${PROJECT_NAME})

add_test(NAME ${PROJECT_NAME}_test
    COMMAND $<TARGET_FILE:${PROJECT_NAME}_test> --netrace=$<TARGET_FILE:${PROJECT_NAME}>
)

add_executable(trace_fork "trace_fork.c")
setup_target_wall(trace_fork)
add_test(NAME trace_fork
    COMMAND $<TARGET_FILE:trace_fork>
)
