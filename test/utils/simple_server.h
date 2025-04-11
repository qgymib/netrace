#ifndef NT_TEST_UTILS_SIMPLE_SERVER_H
#define NT_TEST_UTILS_SIMPLE_SERVER_H
#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_simple_server nt_simple_server_t;

/**
 * @brief Data callback.
 * @param[in] fd  Connection fd.
 * @param[in] arg User defined argument.
 * @return Non-zero to close this connection.
 */
typedef int (*nt_simple_server_cb_t)(int fd, void* arg);

/**
 * @brief Create simple server.
 * @param[out] server   Server handle.
 * @param[in] type      SOCK_STREAM or SOCK_DGRAM.
 * @param[in] ip        Listen address.
 * @param[in] port      Listen port.
 * @param[in] cb        Data callback.
 * @param[in] arg       User defined argument.
 * @return 0 if success.
 */
int nt_simple_server_create(nt_simple_server_t** server, int type, const char* ip, int port,
                            nt_simple_server_cb_t cb, void* arg);

void nt_simple_server_destroy(nt_simple_server_t* server);

void nt_simple_server_get_bind_addr(nt_simple_server_t* server, struct sockaddr_storage* addr);

#ifdef __cplusplus
}
#endif
#endif
