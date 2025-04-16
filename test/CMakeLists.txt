
add_executable(${PROJECT_NAME}_test
    "cases/clone_escape.c"
    "cases/connect.c"
    "cases/cstr.c"
    "cases/dns_parser.c"
    "cases/exitcode.c"
    "cases/grandchild.c"
    "cases/pid.c"
    "cases/urlparser.c"
    "tools/__init__.c"
    "tools/exit.c"
    "tools/slice.c"
    "utils/msg.c"
    "utils/simple_server.c"
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
