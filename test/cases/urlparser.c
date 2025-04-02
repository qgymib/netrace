#include "utils/urlparser.h"
#include "runtime.h"

static url_comp_t* s_url = NULL;

TEST_FIXTURE_SETUP(urlparser)
{
}

TEST_FIXTURE_TEARDOWN(urlparser)
{
    if (s_url != NULL)
    {
        nt_url_comp_free(s_url);
        s_url = NULL;
    }
}

TEST_F(urlparser, scheme)
{
    const char* url = "test://";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_PTR(s_url->host, NULL);
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_ipv4)
{
    const char* url = "test://172.16.0.1";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "172.16.0.1");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_ipv6)
{
    const char* url = "test://::1";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "::1");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_ipv4_slash)
{
    const char* url = "test://172.16.0.1/";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "172.16.0.1");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_ipv6_slash)
{
    const char* url = "test://::1/";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "::1");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_ipv4_port)
{
    const char* url = "test://127.0.0.1:4321";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "127.0.0.1");
    ASSERT_EQ_UINT(*s_url->port, 4321);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_ipv6_port)
{
    const char* url = "test://::1:1234";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "::1");
    ASSERT_EQ_UINT(*s_url->port, 1234);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_ipv4_port_slash)
{
    const char* url = "test://127.0.0.1:4321/";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "127.0.0.1");
    ASSERT_EQ_UINT(*s_url->port, 4321);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_ipv6_port_slash)
{
    const char* url = "test://::1:1234/";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "::1");
    ASSERT_EQ_UINT(*s_url->port, 1234);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_user_ipv4)
{
    const char* url = "test://user@10.0.0.0";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_STR(s_url->username, "user");
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "10.0.0.0");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_user_ipv6)
{
    const char* url = "test://user@::1";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_STR(s_url->username, "user");
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "::1");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_user_pass_ipv4)
{
    const char* url = "test://user:pass@10.0.0.0";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_STR(s_url->username, "user");
    ASSERT_EQ_STR(s_url->password, "pass");
    ASSERT_EQ_STR(s_url->host, "10.0.0.0");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_user_pass_ipv6)
{
    const char* url = "test://user:pass@::1";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_STR(s_url->username, "user");
    ASSERT_EQ_STR(s_url->password, "pass");
    ASSERT_EQ_STR(s_url->host, "::1");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_user_pass_ipv4_port)
{
    const char* url = "test://user:pass@10.0.0.0:9999";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_STR(s_url->username, "user");
    ASSERT_EQ_STR(s_url->password, "pass");
    ASSERT_EQ_STR(s_url->host, "10.0.0.0");
    ASSERT_EQ_UINT(*s_url->port, 9999);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_user_pass_ipv6_port)
{
    const char* url = "test://user:pass@::1:1";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_STR(s_url->username, "user");
    ASSERT_EQ_STR(s_url->password, "pass");
    ASSERT_EQ_STR(s_url->host, "::1");
    ASSERT_EQ_UINT(*s_url->port, 1);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_ipv4_path)
{
    const char* url = "test://127.0.0.1/a";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "127.0.0.1");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_STR(s_url->path, "a");
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_ipv4_path_slash)
{
    const char* url = "test://127.0.0.1/a/";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "127.0.0.1");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_STR(s_url->path, "a/");
    ASSERT_EQ_PTR(s_url->query, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 0);
}

TEST_F(urlparser, scheme_ipv4_path_query)
{
    const char* url = "test://127.0.0.1/a?b=0";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "127.0.0.1");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_STR(s_url->path, "a");
    ASSERT_EQ_SIZE(s_url->query_sz, 1);
    ASSERT_EQ_STR(s_url->query[0].k, "b");
    ASSERT_EQ_STR(s_url->query[0].v, "0");
}

TEST_F(urlparser, scheme_ipv4_path_query2)
{
    const char* url = "test://127.0.0.1/a?a=0&b=1";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "127.0.0.1");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_STR(s_url->path, "a");
    ASSERT_EQ_SIZE(s_url->query_sz, 2);
    ASSERT_EQ_STR(s_url->query[0].k, "a");
    ASSERT_EQ_STR(s_url->query[0].v, "0");
    ASSERT_EQ_STR(s_url->query[1].k, "b");
    ASSERT_EQ_STR(s_url->query[1].v, "1");
}

TEST_F(urlparser, scheme_ipv4_query)
{
    const char* url = "test://127.0.0.1/?b=0";
    ASSERT_EQ_INT(nt_url_comp_parser(&s_url, url), 0);
    ASSERT_EQ_STR(s_url->scheme, "test");
    ASSERT_EQ_PTR(s_url->username, NULL);
    ASSERT_EQ_PTR(s_url->password, NULL);
    ASSERT_EQ_STR(s_url->host, "127.0.0.1");
    ASSERT_EQ_PTR(s_url->port, NULL);
    ASSERT_EQ_PTR(s_url->path, NULL);
    ASSERT_EQ_SIZE(s_url->query_sz, 1);
    ASSERT_EQ_STR(s_url->query[0].k, "b");
    ASSERT_EQ_STR(s_url->query[0].v, "0");
}
