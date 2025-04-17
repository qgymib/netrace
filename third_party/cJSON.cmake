set(CJSON_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cJSON)

add_library(cJSON STATIC
    ${CJSON_ROOT}/cJSON.c
    ${CJSON_ROOT}/cJSON_Utils.c
)

target_include_directories(cJSON
    PUBLIC
        $<BUILD_INTERFACE:${CJSON_ROOT}>
)
