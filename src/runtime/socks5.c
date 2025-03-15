#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include "utils/defs.h"
#include "utils/memory.h"
#include "utils/list.h"
#include "utils/socket.h"
#include "utils/log.h"
#include "socks5.h"
#include "config.h"

typedef struct socks5_channel
{
    ev_list_node_t          node;
    struct sockaddr_storage peeraddr; /* Peer address. */
} socks5_channel_t;

typedef struct nt_proxy_socks5
{
    nt_proxy_t basis; /* Base handle. */

    struct sockaddr_storage socks5_peeraddr; /* Socks5 server address. */
    char*                   socks5_username; /* Socks5 server username. */
    char*                   socks5_password; /* Socks5 server password. */
    char*                   socks5_ip;       /* Socks5 server ip. */
    int                     socks5_port;     /* Socks5 server port. */

    pthread_mutex_t addr_queue_mutex; /* Mutex for #nt_proxy_socks5_t::addr_queue. */
    ev_list_t       addr_queue;       /* #socks5_channel_t */
} nt_proxy_socks5_t;

static void s_nt_proxy_socks5_release(struct nt_proxy* thiz)
{
    nt_proxy_socks5_t* socks5 = container_of(thiz, nt_proxy_socks5_t, basis);

    pthread_mutex_destroy(&socks5->addr_queue_mutex);
    if (socks5->socks5_username != NULL)
    {
        nt_free(socks5->socks5_username);
        socks5->socks5_username = NULL;
    }
    if (socks5->socks5_password != NULL)
    {
        nt_free(socks5->socks5_password);
        socks5->socks5_password = NULL;
    }
    if (socks5->socks5_ip != NULL)
    {
        nt_free(socks5->socks5_ip);
        socks5->socks5_ip = NULL;
    }
    nt_free(socks5);
}

static void s_proxy_socks5_queue(struct nt_proxy* thiz, struct sockaddr* addr)
{
    nt_proxy_socks5_t* socks5 = container_of(thiz, nt_proxy_socks5_t, basis);
    socks5_channel_t*  channel = nt_malloc(sizeof(socks5_channel_t));
    nt_sockaddr_copy((struct sockaddr*)&channel->peeraddr, addr);

    pthread_mutex_lock(&socks5->addr_queue_mutex);
    ev_list_push_back(&socks5->addr_queue, &channel->node);
    pthread_mutex_unlock(&socks5->addr_queue_mutex);
}

/**
 * @brief Parser url.
 * Syntax:
 * socks5://[user[:pass]@][host[:port]]
 */
static int s_socks5_url_parser(nt_proxy_socks5_t* socks5, const char* url)
{
    const char* origurl = url;
    /* Check prefix. */
    if (strncmp(url, "socks5://", 9) != 0)
    {
        return EINVAL;
    }
    url += 9;

    /* Parser username and password. */
    const char* p_userpass = strstr(url, "@");
    if (p_userpass != NULL)
    {
        socks5->socks5_username = nt_strndup(url, p_userpass - url);
        char* p_user = strstr(socks5->socks5_username, ":");
        if (p_user != NULL)
        {
            socks5->socks5_password = nt_strdup(p_user + 1);
            *p_user = '\0';
        }
    }
    url = p_userpass + 1;

    /* Passer ip and port. */
    const char* p_port = strstr(url, ":");
    if (p_port != NULL)
    {
        socks5->socks5_ip = nt_strndup(url, p_port - url);
        if (sscanf(p_port + 1, "%d", &socks5->socks5_port) != 1)
        {
            LOG_E("Invalid port for `%s`.", origurl);
            goto ERR;
        }
    }
    else
    {
        socks5->socks5_ip = nt_strdup(url);
    }

    return 0;

ERR:
    nt_free(socks5->socks5_username);
    socks5->socks5_username = NULL;
    nt_free(socks5->socks5_password);
    socks5->socks5_password = NULL;
    nt_free(socks5->socks5_ip);
    socks5->socks5_ip = NULL;
    return EINVAL;
}

int nt_proxy_socks5_create(nt_proxy_t** proxy, const char* url)
{
    int retval = 0;
    nt_proxy_socks5_t* socks5 = nt_calloc(1, sizeof(nt_proxy_socks5_t));
    socks5->basis.release = s_nt_proxy_socks5_release;
    socks5->basis.queue = s_proxy_socks5_queue;
    socks5->socks5_port = NT_DEFAULT_SOCKS5_PORT;
    if ((retval = s_socks5_url_parser(socks5, url)) != 0)
    {
        return retval;
    }
    pthread_mutex_init(&socks5->addr_queue_mutex, NULL);
    ev_list_init(&socks5->addr_queue);

    *proxy = &socks5->basis;
    return 0;
}
