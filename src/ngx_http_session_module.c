

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* 31 Dec 2037 23:55:55 GMT */
#define NGX_HTTP_SESSION_MAX_EXPIRES  2145916555

typedef struct {
    ngx_int_t   service;

    ngx_str_t   name;
    ngx_str_t   domain;
    ngx_str_t   path;
    ngx_str_t   redirect_location;
    ngx_str_t   post_redirect_location;
    ngx_str_t   final_location;
    ngx_str_t   p3p;

    time_t      expires;

} ngx_http_session_conf_t;


typedef struct {
	u_char      got[41];
    u_char      set[41];
    ngx_str_t   cookie;
    size_t		found;
    size_t		generated;
} ngx_http_session_ctx_t;

static ngx_int_t send_empty_gif(ngx_http_request_t *r);

static char *
ngx_http_session(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_http_session_ctx_t *ngx_http_session_get_uid(ngx_http_request_t *r,
    ngx_http_session_conf_t *conf);
static ngx_int_t ngx_http_session_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_str_t *name, u_char *uid);
static ngx_int_t ngx_http_session_set_uid(ngx_http_request_t *r,
    ngx_http_session_ctx_t *ctx, ngx_http_session_conf_t *conf);

static ngx_int_t ngx_http_session_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_session_init(ngx_conf_t *cf);
static void *ngx_http_session_create_conf(ngx_conf_t *cf);
static char *ngx_http_session_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_session_domain(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_session_path(ngx_conf_t *cf, void *post, void *data);

static char *ngx_http_session_expires(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_session_p3p(ngx_conf_t *cf, void *post, void *data);

static ngx_int_t ngx_http_session_init_worker(ngx_cycle_t *cycle);

static uint32_t is_redirect(ngx_http_request_t *r, ngx_http_session_conf_t *conf);

static uint32_t  start_value;
static uint32_t  sequencer_v2 = 0x03030302;

// sha
int hash(long val, int *hashval);
int sha_hash(int *data, int *hash);
int sha_init(int *hash);
int make_sid(u_char *sid);

static u_char expires[] = "; expires=Thu, 31-Dec-37 23:55:55 GMT";

/* the minimal single pixel transparent GIF, 43 bytes */

static u_char  ngx_empty_gif[] = {

    'G', 'I', 'F', '8', '9', 'a',  /* header                                 */

                                   /* logical screen descriptor              */
    0x01, 0x00,                    /* logical screen width                   */
    0x01, 0x00,                    /* logical screen height                  */
    0x80,                          /* global 1-bit color table               */
    0x01,                          /* background color #1                    */
    0x00,                          /* no aspect ratio                        */

                                   /* global color table                     */
    0x00, 0x00, 0x00,              /* #0: black                              */
    0xff, 0xff, 0xff,              /* #1: white                              */

                                   /* graphic control extension              */
    0x21,                          /* extension introducer                   */
    0xf9,                          /* graphic control label                  */
    0x04,                          /* block size                             */
    0x01,                          /* transparent color is given,            */
                                   /*     no disposal specified,             */
                                   /*     user input is not expected         */
    0x00, 0x00,                    /* delay time                             */
    0x01,                          /* transparent color #1                   */
    0x00,                          /* block terminator                       */

                                   /* image descriptor                       */
    0x2c,                          /* image separator                        */
    0x00, 0x00,                    /* image left position                    */
    0x00, 0x00,                    /* image top position                     */
    0x01, 0x00,                    /* image width                            */
    0x01, 0x00,                    /* image height                           */
    0x00,                          /* no local color table, no interlaced    */

                                   /* table based image data                 */
    0x02,                          /* LZW minimum code size,                 */
                                   /*     must be at least 2-bit             */
    0x02,                          /* block size                             */
    0x4c, 0x01,                    /* compressed bytes 01_001_100, 0000000_1 */
                                   /* 100: clear code                        */
                                   /* 001: 1                                 */
                                   /* 101: end of information code           */
    0x00,                          /* block terminator                       */

    0x3B                           /* trailer                                */
};

static ngx_conf_post_handler_pt  ngx_http_session_domain_p =
    ngx_http_session_domain;
static ngx_conf_post_handler_pt  ngx_http_session_path_p = ngx_http_session_path;
static ngx_conf_post_handler_pt  ngx_http_session_p3p_p = ngx_http_session_p3p;

static ngx_command_t  ngx_http_session_commands[] = {

	 { ngx_string("session"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_session,
      0,
      0,
      NULL },

    { ngx_string("session_service"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, service),
      NULL },

    { ngx_string("session_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, name),
      NULL },

    { ngx_string("session_domain"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, domain),
      &ngx_http_session_domain_p },

    { ngx_string("session_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, path),
      &ngx_http_session_path_p },

    { ngx_string("session_expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_session_expires,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("session_p3p"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, p3p),
      &ngx_http_session_p3p_p },
    
   	  { ngx_string("session_redirect_location"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, redirect_location),
      NULL },
      
     { ngx_string("session_post_redirect_location"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, post_redirect_location),
      NULL },
      
      { ngx_string("session_final_location"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, final_location),
      NULL },
      
      ngx_null_command
};


static ngx_http_module_t  ngx_http_session_module_ctx = {
    ngx_http_session_add_variables,         /* preconfiguration */
    ngx_http_session_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_session_create_conf,           /* create location configration */
    ngx_http_session_merge_conf             /* merge location configration */
};


ngx_module_t  ngx_http_session_module = {
    NGX_MODULE_V1,
    &ngx_http_session_module_ctx,    /* module context */
    ngx_http_session_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_session_init_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_session_got = ngx_string("got");
static ngx_str_t  ngx_http_session_set = ngx_string("set");


static ngx_int_t
ngx_http_session_handler(ngx_http_request_t *r)
{
 	ngx_http_session_ctx_t   *ctx;
    ngx_http_session_conf_t  *conf;
 	ngx_int_t     rc;
    
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }
    
	// check user cookie first
	conf = ngx_http_get_module_loc_conf(r, ngx_http_session_module);

    ctx = ngx_http_session_get_uid(r, conf);

    if (ctx == NULL) {
        return NGX_ERROR;
    }
	
    if (ctx->found == 1) {
    	 if (conf->final_location.len > 0) {
			return ngx_http_internal_redirect(r, &conf->final_location, NULL);
		} else {
			return send_empty_gif(r);
		}
    }
    
    if (!is_redirect(r, conf)) {
    	// try to generate sid
    	if (ngx_http_session_set_uid(r, ctx, conf) == NGX_OK) {
    		return ngx_http_internal_redirect(r, &conf->redirect_location, &r->args);
    	}
    } else {
    	if (conf->final_location.len > 0) {
			return ngx_http_internal_redirect(r, &conf->final_location, NULL);
		} else {
			return send_empty_gif(r);
		}
    }
    
	return NGX_ERROR;
}

static ngx_int_t send_empty_gif(ngx_http_request_t *r)
{
	ngx_buf_t    *b;
    ngx_chain_t   out;
    ngx_int_t     rc;

	r->headers_out.content_type.len = sizeof("image/gif") - 1;
    r->headers_out.content_type.data = (u_char *) "image/gif";

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = sizeof(ngx_empty_gif);
        //r->headers_out.last_modified_time = 23349600;

        return ngx_http_send_header(r);
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->pos = ngx_empty_gif;
    b->last = ngx_empty_gif + sizeof(ngx_empty_gif);
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = sizeof(ngx_empty_gif);
    //r->headers_out.last_modified_time = 23349600;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_session_got_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_session_ctx_t   *ctx;
    ngx_http_session_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_session_module);

    ctx = ngx_http_session_get_uid(r, conf);
	
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->found == 1) {
        return ngx_http_session_variable(r, v, &conf->name, ctx->got);
    }

    /* ctx->status == NGX_DECLINED */

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_session_set_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_session_ctx_t   *ctx;
    ngx_http_session_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_session_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_session_module);

	if (ctx->generated == 1) {
    	return ngx_http_session_variable(r, v, &conf->name, ctx->set);
    }
    
    return NGX_OK;
}


static ngx_http_session_ctx_t *
ngx_http_session_get_uid(ngx_http_request_t *r, ngx_http_session_conf_t *conf)
{
    ngx_int_t                n;
    ngx_table_elt_t        **cookies;
    ngx_http_session_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_session_module);
	
    if (ctx) {
        return ctx;
    }
	
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_session_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_session_module);
    }
	
    n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &conf->name,
                                          &ctx->cookie);	
	
    if (n == NGX_DECLINED) {
        return ctx;
    }

    if (ctx->cookie.len < 40) {
        cookies = r->headers_in.cookies.elts;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent too short session cookie \"%V\"",
                      &cookies[n]->value);
        return ctx;
    }
	
	ngx_cpystrn(ctx->got, ctx->cookie.data, 41);
	ctx->found = 1;
	
    return ctx;
}


static ngx_int_t
ngx_http_session_set_uid(ngx_http_request_t *r, ngx_http_session_ctx_t *ctx,
    ngx_http_session_conf_t *conf)
{
    u_char           *cookie, *p;
    size_t            len;
    ngx_table_elt_t  *set_cookie, *p3p;
	
    if (ctx->found == 0) {
        // generate here
        make_sid(ctx->set);
		ctx->generated = 1;
    } else {
    	ngx_cpystrn(ctx->set, ctx->got, 41);
    }

    len = conf->name.len + 1 + 40 + conf->path.len;

    if (conf->expires) {
        len += sizeof(expires) - 1 + 2;
    }

    if (conf->domain.len) {
        len += conf->domain.len;
    }

    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(cookie, conf->name.data, conf->name.len);
    *p++ = '=';
	
    if (ctx->found == 0) {
		p = ngx_cpymem(p, ctx->set, 40);
    } else {
        p = ngx_cpymem(p, ctx->got, 40);
    }

    if (conf->expires == NGX_HTTP_SESSION_MAX_EXPIRES) {
        p = ngx_cpymem(p, expires, sizeof(expires) - 1);

    } else if (conf->expires) {
        p = ngx_cpymem(p, expires, sizeof("; expires=") - 1);
        p = ngx_http_cookie_time(p, ngx_time() + conf->expires);
    }

    p = ngx_copy(p, conf->domain.data, conf->domain.len);

    p = ngx_copy(p, conf->path.data, conf->path.len);

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    set_cookie->key.len = sizeof("Set-Cookie") - 1;
    set_cookie->key.data = (u_char *) "Set-Cookie";
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;
	
    if (conf->p3p.len == 0) {
        return NGX_OK;
    }

    p3p = ngx_list_push(&r->headers_out.headers);
    if (p3p == NULL) {
        return NGX_ERROR;
    }

    p3p->hash = 1;
    p3p->key.len = sizeof("P3P") - 1;
    p3p->key.data = (u_char *) "P3P";
    p3p->value = conf->p3p;
    
    return NGX_OK;
}


static ngx_int_t
ngx_http_session_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    ngx_str_t *name, u_char *uid)
{
    v->len = name->len + 41;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ngx_sprintf(v->data, "%V=%s", name, uid);

    return NGX_OK;
}


static ngx_int_t
ngx_http_session_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_session_got, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_session_got_variable;

    var = ngx_http_add_variable(cf, &ngx_http_session_set, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_session_set_variable;

    return NGX_OK;
}


static void *
ngx_http_session_create_conf(ngx_conf_t *cf)
{
    ngx_http_session_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_session_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->name.len = 0;
     *     conf->name.date = NULL;
     *     conf->domain.len = 0;
     *     conf->domain.date = NULL;
     *     conf->path.len = 0;
     *     conf->path.date = NULL;
     *     conf->p3p.len = 0;
     *     conf->p3p.date = NULL;
     */

    conf->service = NGX_CONF_UNSET;
    conf->expires = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_session_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_session_conf_t *prev = parent;
    ngx_http_session_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->name, prev->name, "uid");
    ngx_conf_merge_str_value(conf->domain, prev->domain, "");
    ngx_conf_merge_str_value(conf->path, prev->path, "; path=/");
    ngx_conf_merge_str_value(conf->p3p, prev->p3p, "");

    ngx_conf_merge_value(conf->service, prev->service, NGX_CONF_UNSET);
    ngx_conf_merge_sec_value(conf->expires, prev->expires, 0);

    return NGX_CONF_OK;
}

static char *
ngx_http_session(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
   	ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_session_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_session_init(ngx_conf_t *cf)
{

    return NGX_OK;
}


static char *
ngx_http_session_domain(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *domain = data;

    u_char  *p, *new;

    if (ngx_strcmp(domain->data, "none") == 0) {
        domain->len = 0;
        domain->data = (u_char *) "";

        return NGX_CONF_OK;
    }

    new = ngx_pnalloc(cf->pool, sizeof("; domain=") - 1 + domain->len);
    if (new == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(new, "; domain=", sizeof("; domain=") - 1);
    ngx_memcpy(p, domain->data, domain->len);

    domain->len += sizeof("; domain=") - 1;
    domain->data = new;

    return NGX_CONF_OK;
}


static char *
ngx_http_session_path(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *path = data;

    u_char  *p, *new;

    new = ngx_pnalloc(cf->pool, sizeof("; path=") - 1 + path->len);
    if (new == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(new, "; path=", sizeof("; path=") - 1);
    ngx_memcpy(p, path->data, path->len);

    path->len += sizeof("; path=") - 1;
    path->data = new;

    return NGX_CONF_OK;
}

static char *
ngx_http_session_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_session_conf_t *ucf = conf;

    ngx_str_t  *value;

    if (ucf->expires != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "max") == 0) {
        ucf->expires = NGX_HTTP_SESSION_MAX_EXPIRES;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ucf->expires = 0;
        return NGX_CONF_OK;
    }

    ucf->expires = ngx_parse_time(&value[1], 1);
    if (ucf->expires == NGX_ERROR) {
        return "invalid value";
    }

    if (ucf->expires == NGX_PARSE_LARGE_TIME) {
        return "value must be less than 68 years";
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_session_p3p(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *p3p = data;

    if (ngx_strcmp(p3p->data, "none") == 0) {
        p3p->len = 0;
        p3p->data = (u_char *) "";
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_session_init_worker(ngx_cycle_t *cycle)
{
    struct timeval  tp;

    ngx_gettimeofday(&tp);

    /* use the most significant usec part that fits to 16 bits */
    start_value = ((tp.tv_usec / 20) << 16) | ngx_pid;

    return NGX_OK;
}


//===================== SHA ============================

#define Ai 0x67452301
#define Bi 0xefcdab89
#define Ci 0x98badcfe
#define Di 0x10325476
#define Ei 0xc3d2e1f0

#define A 0
#define B 1
#define C 2
#define D 3
#define E 4

#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc 
#define K4 0xca62c1d6

#define f1(X,Y,Z) ((X & Y) | ((!X) ^ Z))
#define f2(X,Y,Z) (X ^ Y ^ Z)
#define f3(X,Y,Z) ((X & Y) | (X & Z) | (Y & Z))

#define rol1(x) ((x<<1) | ((x>>31) & 1))
#define rol5(x) ((x<<5) | ((x>>27) & 0x1f))
#define rol30(x) ((x<<30) | ((x>>2) & 0x3fffffff))

int sha_hash(int *data, int *hash) {
  int W[80];
  int a=hash[A], b=hash[B], c=hash[C], d=hash[D], e=hash[E], t, x, TEMP;
  
  /** Data expansion from 16 to 80 blocks **/
  for (t=0; t<16; t++) {
    W[t]=data[t];
  }
  for (t=16; t<80; t++) {
    x=W[t-3] ^ W[t-8] ^ W[t-16];
    W[t]=rol1(x);
  }
  
  /** Main loops **/
  for (t=0; t<20; t++) {
    TEMP=rol5(a) + f1(b,c,d) + e + W[t] + K1;
    e=d;
    d=c;
    c=rol30(b);
    b=a;
    a=TEMP;
  }
  for (; t<40; t++) {
    TEMP=rol5(a) + f2(b,c,d) + e + W[t] + K2;
    e=d;
    d=c;
    c=rol30(b);
    b=a;
    a=TEMP;
  }
  for (; t<60; t++) {
    TEMP=rol5(a) + f3(b,c,d) + e + W[t] + K3;
    e=d;
    d=c;
    c=rol30(b);
    b=a;
    a=TEMP;
  }
  for (; t<80; t++) {
    TEMP=rol5(a) + f2(b,c,d) + e + W[t] + K4;
    e=d;
    d=c;
    c=rol30(b);
    b=a;
    a=TEMP;
  }
  hash[A]+=a; 
  hash[B]+=b;
  hash[C]+=c;
  hash[D]+=d;
  hash[E]+=e;
  return 0;
}

int sha_init(int *hash) {
  hash[A]=Ai;
  hash[B]=Bi;
  hash[C]=Ci;
  hash[D]=Di;
  hash[E]=Ei;
  return 0;
}

int hash(long val, int *hashval) 
{
	char buffer[64];
	int c = 1, i, length=0;
	
  	sha_init(hashval);
  
  	sprintf(buffer,"%ld", val);
  
  	c = strlen(buffer);
  	length += c;
  
  	for (i = c; i < 61; i++) {
		if (i == c)
			buffer[i] = 0x10;
		else
	    	if (i == 60)
	    		((int*) buffer)[15] = length * 8;
	    	else
	    		buffer[i]=0;
  	}
  
  	sha_hash((int *)buffer, hashval);
  
  	return length;
}

int make_sid(u_char *sid)
{
	int hashval[5];
	
	unsigned int seed =
		(uint32_t) ngx_time()
		+ start_value
		+ sequencer_v2;

	// increase sequencer
	sequencer_v2 += 0x100;
	if (sequencer_v2 < 0x03030302) {
    	sequencer_v2 = 0x03030302;
   	}
            
  	hash(seed, hashval);
 
  	ngx_sprintf(
  		sid, "%08xd%08xd%08xd%08xd%08xd",
  		hashval[0],
  		hashval[1],
  		hashval[2],
  		hashval[3],
  		hashval[4]
  	);
  
  	sid[40] = '\0';
  	return 0;
}

static uint32_t is_redirect(ngx_http_request_t *r, ngx_http_session_conf_t *conf)
{
	if (r->uri.len == 0) {
		return 0;
	}
	
	if (ngx_strcasecmp(r->uri.data, (u_char*) conf->post_redirect_location.data) >= 0) {
    	return 1;
	} else
		return 0;
}
