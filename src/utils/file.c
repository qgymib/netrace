#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include "utils/socket.h"
#include "file.h"

#include <string.h>

c_str_t nt_read_file(const char* path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        return NULL;
    }

    c_str_t content = c_str_new("");

    char    buff[1024];
    int     total_sz = 0;
    ssize_t read_sz;
    while ((read_sz = nt_read(fd, buff, sizeof(buff))) > 0)
    {
        content = c_str_cat_len(content, buff, read_sz);
        total_sz += read_sz;
    }

    close(fd);
    return content;
}

c_str_t nt_getenv(const char* env)
{
    char* val = getenv(env);
    return val != NULL ? c_str_new(val) : NULL;
}

c_str_t nt_exepath(void)
{
    char buff[4096];
    ssize_t read_sz = readlink("/proc/self/exe", buff, sizeof(buff));
    if (read_sz < 0)
    {
        return NULL;
    }

    return c_str_new_len(buff, read_sz);
}

c_str_t nt_dirname(const c_str_t path)
{
    c_str_t name = c_str_dup(path);
    char* pos = dirname(name);
    size_t pos_sz = strlen(pos);
    c_str_t dir_name = c_str_substr(name, 0, pos_sz);
    c_str_free(name);
    return dir_name;
}
