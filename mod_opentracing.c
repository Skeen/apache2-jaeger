/* 
**  mod_opentracing.c -- Apache opentracing module
*/ 

/* Include the required headers from httpd */
#include "httpd.h"
#include "http_log.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"

#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "apr_hash.h"
#include "apr_base64.h"
#include "apr_dbd.h"
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_tables.h>

static apr_status_t opentracing_end_generation(request_rec *rec);
static apr_status_t opentracing_headers_fixup(request_rec *rec);

/********************************************** CONFIGURATION STRUCTURE *******************************************/
typedef struct {
    /* Enable or disable our module */
    int  enabled;      
} opentracing_config;

/********************************************** DIRECTIVES DEFINITION *********************************************/
const char *opentracing_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    opentracing_config *config = (opentracing_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(!strcasecmp(arg, "on")) config->enabled = 1;
    else config->enabled = 0;
    return NULL;
}

static const command_rec opentracing_directives[] =
{
    AP_INIT_TAKE1("OpenTracingEnabled", opentracing_set_enabled, NULL, ACCESS_CONF, "Enable or disable mod_open_tracing"),
    { NULL }
};


/********************************* CREATE AND MERGE DIR FUNCTIONS **************************************************/
void *create_dir_conf(apr_pool_t *pool, char *context)
{
    context = context ? context : "Newly created configuration";

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    opentracing_config *cfg = apr_pcalloc(pool, sizeof(opentracing_config));
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(cfg)
    {
        /* Set some default values */
        cfg->enabled = 0;
    }

    return cfg;
}

/********************************************* MAIN DECLARATION **************************************************/
static void opentracing_register_hooks(apr_pool_t *pool)
{
    ap_hook_fixups(opentracing_headers_fixup, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_log_transaction(opentracing_end_generation, NULL, NULL, APR_HOOK_MIDDLE);
}


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA opentracing_module = {
    STANDARD20_MODULE_STUFF, 
    // Per-directory configuration handler
    create_dir_conf,
    // Merge handler for per-directory configurations
    NULL,
    // Per-server configuration handler
    NULL,
    // Merge handler for per-server configurations
    NULL,
    // Any directives we may have for httpd
    opentracing_directives,            
    // Our hook registering function
    opentracing_register_hooks
};



static int opentracing_end_generation(request_rec *rec)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    opentracing_config *config = (opentracing_config *) ap_get_module_config(rec->per_dir_config, &opentracing_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    if(config->enabled == 0) return DECLINED;

    ap_log_rerror(APLOG_MARK, APLOG_ERR, HTTP_FORBIDDEN, rec, "end_generation");
    return DECLINED;
}

static apr_status_t opentracing_headers_fixup(request_rec *rec)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    opentracing_config *config = (opentracing_config *) ap_get_module_config(rec->per_dir_config, &opentracing_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    if(config->enabled == 0) return DECLINED;

    apr_table_setn(rec->headers_in, "X-OpenTracing", "Totally open");
    ap_log_rerror(APLOG_MARK, APLOG_ERR, HTTP_FORBIDDEN, rec, "headers_fixup");
    ap_log_rerror(APLOG_MARK, APLOG_ERR, HTTP_FORBIDDEN, rec, "JOHN");
    return DECLINED;
}
