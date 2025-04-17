#include <assert.h>
#include <cJSON.h>
#include "utils/defs.h"
#include "utils/file.h"
#include "utils/log.h"
#include "runtime/__init__.h"
#include "config.h"

static int s_fill_option_from_file(nt_cmd_opt_t* opt, const char* path)
{
#define FILL_STRING_FROM_JSON(key)                                                                 \
    do                                                                                             \
    {                                                                                              \
        if (opt->key != NULL)                                                                      \
        {                                                                                          \
            break;                                                                                 \
        }                                                                                          \
        cJSON* key = cJSON_GetObjectItem(json, #key);                                              \
        if (key == NULL)                                                                           \
        {                                                                                          \
            break;                                                                                 \
        }                                                                                          \
        if (!cJSON_IsString(key))                                                                  \
        {                                                                                          \
            LOG_E("Invalid key `%s` in `%s`.", #key, path);                                        \
            return NT_ERR(EINVAL);                                                                 \
        }                                                                                          \
        opt->key = c_str_new(cJSON_GetStringValue(key));                                           \
    } while (0)

    c_str_t data = nt_read_file(path);
    if (data == NULL)
    {
        return NT_ERR(ENOENT);
    }

    cJSON* json = cJSON_Parse(data);
    c_str_free(data);
    if (json == NULL)
    {
        LOG_E("Cannot parse `%s`.", path);
        return NT_ERR(EPROTO);
    }

    FILL_STRING_FROM_JSON(bypass);
    FILL_STRING_FROM_JSON(dns);
    FILL_STRING_FROM_JSON(gid);
    FILL_STRING_FROM_JSON(loglevel);
    FILL_STRING_FROM_JSON(proxy);
    FILL_STRING_FROM_JSON(uid);

    cJSON_Delete(json);
    return 0;

#undef FILL_STRING_FROM_JSON
}

static int s_load_config_from_exepath(nt_cmd_opt_t* opt)
{
    c_str_t exepath = nt_exepath();
    c_str_t path = nt_dirname(exepath);
    path = c_str_cat(path, "/config.json");

    int ret = s_fill_option_from_file(opt, path);

    c_str_free(exepath);
    c_str_free(path);

    return ret;
}

static int s_load_config_from_xdg(nt_cmd_opt_t* opt)
{
    int     ret = 0;
    c_str_t path = nt_getenv("XDG_CONFIG_HOME");
    if (path == NULL)
    {
        return NT_ERR(ENOENT);
    }
    path = c_str_cat(path, "/" NT_PROGRAM_NAMESPACE "/config.json");

    /* Parse option. */
    ret = s_fill_option_from_file(opt, path);

    c_str_free(path);
    return ret;
}

static int s_load_config_from_home(nt_cmd_opt_t* opt)
{
    c_str_t path = nt_getenv("HOME");
    if (path == NULL)
    {
        return NT_ERR(ENOENT);
    }
    path = c_str_cat(path, "/.config/" NT_PROGRAM_NAMESPACE "/config.json");

    int ret = s_fill_option_from_file(opt, path);
    c_str_free(path);

    return ret;
}

static int s_load_config_from_system(nt_cmd_opt_t* opt)
{
    const char* path = "/etc/" NT_PROGRAM_NAMESPACE "/config.json";
    return s_fill_option_from_file(opt, path);
}

static int s_load_config_from_opt(nt_cmd_opt_t* opt)
{
    if (opt->config == NULL)
    {
        return NT_ERR(ENOENT);
    }

    return s_fill_option_from_file(opt, opt->config);
}

static int s_append_from_config_file(nt_cmd_opt_t* opt)
{
#define TRY_LOAD_CONFIG(fn)                                                                        \
    do                                                                                             \
    {                                                                                              \
        int ret = fn(opt);                                                                         \
        if (ret == 0 || ret == NT_ERR(EPROTO))                                                     \
        {                                                                                          \
            return ret;                                                                            \
        }                                                                                          \
        assert(ret == NT_ERR(ENOENT));                                                             \
    } while (0)

    TRY_LOAD_CONFIG(s_load_config_from_opt);
    TRY_LOAD_CONFIG(s_load_config_from_exepath);
    TRY_LOAD_CONFIG(s_load_config_from_xdg);
    TRY_LOAD_CONFIG(s_load_config_from_home);
    TRY_LOAD_CONFIG(s_load_config_from_system);

    return 0;

#undef TRY_LOAD_CONFIG
}

int main(int argc, char* argv[])
{
    int ret;

    /* Parser command line arguments. */
    nt_cmd_opt_t options;
    memset(&options, 0, sizeof(options));
    nt_cmd_opt_parse(&options, argc, argv);

    /* Respect options from configuration file. */
    s_append_from_config_file(&options);

    /* Run */
    ret = nt_run(&options);
    nt_cmd_opt_free(&options);

    return ret;
}
