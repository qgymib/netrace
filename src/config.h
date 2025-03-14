#ifndef NT_CONFIG_H
#define NT_CONFIG_H

/**
 * @brief Default remote socks5 server address.
 */
#ifndef NT_DEFAULT_SOCKS5_ADDR
#define NT_DEFAULT_SOCKS5_ADDR "127.0.0.1"
#endif

/**
 * @brief Default remote socks5 server port.
 */
#ifndef NT_DEFAULT_SOCKS5_PORT
#define NT_DEFAULT_SOCKS5_PORT 1080
#endif

/**
 * @brief Default socket buffer size.
 */
#ifndef NT_SOCKET_BUFFER_SIZE
#define NT_SOCKET_BUFFER_SIZE (4 * 1024)
#endif

#endif
