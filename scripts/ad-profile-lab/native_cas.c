/* NON-DEPLOYABLE synthetic DC laboratory module. No production ABI/endpoint.
 * Native LDB operation: signature, fresh policy and USN checks inside the
 * caller's DSDB transaction, followed by the unchanged downstream ACL stack.
 * Never constructs a session or escalates the authenticated caller.
 */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <dirent.h>
#include <core/ntstatus.h>
#include <core/werror.h>
#include <util/data_blob.h>
#include <util/time.h>
#include <gen_ndr/auth.h>
#include <ldb.h>
#include <ldb_module.h>
#include <ldb_version.h>
#include <tdb.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "native_config.h"

#define ATTR "identityLabCAS"
#define JOURNAL "/tmp/native-cas/journal.tdb"
#define DENY LDB_ERR_UNWILLING_TO_PERFORM
static const char *fields[] = {"displayName", "givenName", "sn", "mail"};
static const unsigned limits[] = {256,64,64,254};
static const char *attrs[] = {"objectGUID","objectSid","uSNChanged","userAccountControl",
    "primaryGroupID","adminCount","memberOf","servicePrincipalName","sIDHistory",
    "lockoutTime","accountExpires","pwdLastSet","msDS-User-Account-Control-Computed",
    "msDS-KeyCredentialLink","msDS-AllowedToDelegateTo","msDS-AllowedToActOnBehalfOfOtherIdentity",NULL};

struct packet {
    const uint8_t *id, *values[4];
    uint16_t sizes[4];
    uint64_t version, issued, expires;
    uint8_t digest[32], mask;
};
struct state {
    bool tx, pending, applied;
    uint8_t id[16], digest[32], mask;
    uint64_t committed_version;
};
struct callback_context {struct ldb_request *parent;struct ldb_module *module;};

static uint64_t be64(const uint8_t *p) {
    uint64_t n=0; for (unsigned i=0;i<8;i++) n=(n<<8)|p[i]; return n;
}
static bool fresh(const struct packet *p) {
    time_t now=time(NULL);
    return now>=0 && p->issued <= (uint64_t)now && (uint64_t)now < p->expires &&
        p->expires > p->issued && p->expires-p->issued<=60;
}
static bool equal_attr(const struct ldb_message *m,const char *a,const uint8_t *v,size_t n) {
    const struct ldb_message_element *e=ldb_msg_find_element(m,a);
    return e && e->num_values==1 && e->values[0].length==n && !memcmp(e->values[0].data,v,n);
}
static bool absent(const struct ldb_message *m,const char *a) {
    const struct ldb_message_element *e=ldb_msg_find_element(m,a); return !e || e->num_values==0;
}
static bool number(const struct ldb_message *m,const char *a,uint64_t *out) {
    const struct ldb_val *v=ldb_msg_find_ldb_val(m,a); uint64_t n=0;
    if (!v || !v->length || v->length>20) return false;
    for(size_t i=0;i<v->length;i++) {
        if(v->data[i]<'0'||v->data[i]>'9'||n>(UINT64_MAX-(v->data[i]-'0'))/10) return false;
        n=n*10+(v->data[i]-'0');
    }
    *out=n; return true;
}
static bool sid_equal(const struct dom_sid *s,const uint8_t *raw,size_t n) {
    if(!s || s->num_auths<0 || s->num_auths>15 || n!=8+4*(size_t)s->num_auths ||
       raw[0]!=s->sid_rev_num || raw[1]!=(uint8_t)s->num_auths || memcmp(raw+2,s->id_auth,6)) return false;
    for(unsigned i=0;i<(unsigned)s->num_auths;i++) {
        uint32_t v=(uint32_t)raw[8+4*i]|(uint32_t)raw[9+4*i]<<8|(uint32_t)raw[10+4*i]<<16|(uint32_t)raw[11+4*i]<<24;
        if(v!=s->sub_auths[i]) return false;
    }
    return true;
}
static bool writer_token(struct ldb_context *ldb) {
    const struct auth_session_info *s=ldb_get_opaque(ldb,"sessionInfo");
    const struct security_token *t=s?s->security_token:NULL;
    if(!t || !t->sids || !t->num_sids || t->num_sids>64 || !sid_equal(&t->sids[0],PIN_WRITER_SID,sizeof(PIN_WRITER_SID))) return false;
    if(t->privilege_mask & ~(uint64_t)SEC_PRIV_CHANGE_NOTIFY_BIT) return false;
    for(unsigned i=0;i<t->num_sids;i++) {
        const struct dom_sid *sid=&t->sids[i];
        if(sid->num_auths<=0 || sid->num_auths>15) return false;
        uint32_t rid=sid->sub_auths[sid->num_auths-1];
        if(rid==500||rid==512||rid==518||rid==519||rid==544) return false;
    }
    return true;
}
static int parse(const uint8_t *data,size_t n,struct packet *p) {
    if(n<144+8+64 || n>1024 || memcmp(data,"SWCAS001",8)) return DENY;
    EVP_PKEY *key=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,PIN_PUBLIC_KEY,32);
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); int ok=0;
    if(key&&ctx&&EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,key)==1)
        ok=EVP_DigestVerify(ctx,data+n-64,64,data,n-64);
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key); if(ok!=1) return DENY;
    const uint8_t *v=data+8;
    p->id=v; v+=16;
    const uint8_t *pins[]={PIN_DOMAIN_GUID,PIN_DC_GUID,PIN_TARGET_GUID,PIN_ACTOR_GUID,PIN_WRITER_GUID,PIN_GROUP_GUID};
    for(unsigned i=0;i<6;i++,v+=16) if(memcmp(v,pins[i],16)) return DENY;
    p->version=be64(v); v+=8; p->issued=be64(v);v+=8;p->expires=be64(v);v+=8;
    if(!fresh(p)) return DENY;
    for(unsigned i=0;i<4;i++) {
        if((size_t)(data+n-64-v)<2) return DENY;
        unsigned len=((unsigned)v[0]<<8)|v[1];v+=2;p->sizes[i]=len;
        if(len==65535) continue;
        if(len>limits[i] || (size_t)(data+n-64-v)<len) return DENY;
        for(unsigned j=0;j<len;j++) if(v[j]<32 || v[j]>126) return DENY;
        p->mask|=1u<<i;p->values[i]=v;v+=len;
    }
    if(!p->mask || v!=data+n-64) return DENY;
    if(!SHA256(data,n-64,p->digest)) return DENY;
    return LDB_SUCCESS;
}

static struct ldb_message *read_one(struct ldb_context *ldb,TALLOC_CTX *mem,const char *dn,
        enum ldb_scope scope,const char *filter,const char *const *wanted) {
    struct ldb_result *r=NULL;
    int rc=ldb_search(ldb,mem,&r,ldb_dn_new(mem,ldb,dn),scope,wanted,"%s",filter);
    if(rc!=LDB_SUCCESS || !r || r->count!=1) return NULL;
    return r->msgs[0];
}
static bool clean_user(const struct ldb_message *m,bool target) {
    uint64_t uac=0,pg=0,admin=0;
    if(!number(m,"userAccountControl",&uac) || (uac!=512 && !(target&&uac==514)) ||
       !number(m,"primaryGroupID",&pg) || pg!=513) return false;
    if(!absent(m,"adminCount") && (!number(m,"adminCount",&admin)||admin)) return false;
    if(!target) {
        uint64_t locked=0,expires=0,pwd=0,computed=0;
        time_t now=time(NULL);
        if(now<0 || (!absent(m,"lockoutTime") && (!number(m,"lockoutTime",&locked)||locked)) ||
           !number(m,"accountExpires",&expires)||!number(m,"pwdLastSet",&pwd)||!pwd||
           !number(m,"msDS-User-Account-Control-Computed",&computed)||computed) return false;
        uint64_t filetime=((uint64_t)now+11644473600ULL)*10000000ULL;
        if(expires && expires!=0x7fffffffffffffffULL && expires<=filetime) return false;
    }
    const char *risk[]={"servicePrincipalName","sIDHistory","msDS-KeyCredentialLink",
        "msDS-AllowedToDelegateTo","msDS-AllowedToActOnBehalfOfOtherIdentity",NULL};
    for(unsigned i=0;risk[i];i++) if(!absent(m,risk[i])) return false;
    return !target || absent(m,"memberOf");
}
static int policy(struct ldb_context *ldb,TALLOC_CTX *mem,const struct packet *p,struct ldb_message **target) {
    if(!writer_token(ldb)) return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
    struct ldb_message *domain=read_one(ldb,mem,PIN_BASE,LDB_SCOPE_BASE,"(objectClass=*)",attrs);
    struct ldb_message *writer=read_one(ldb,mem,PIN_WRITER_DN,LDB_SCOPE_BASE,"(objectClass=user)",attrs);
    struct ldb_message *actor=read_one(ldb,mem,PIN_ACTOR_DN,LDB_SCOPE_BASE,"(objectClass=user)",attrs);
    const char *group_attrs[]={"objectGUID","member","memberOf",NULL};
    struct ldb_message *group=read_one(ldb,mem,PIN_GROUP_DN,LDB_SCOPE_BASE,"(objectClass=group)",group_attrs);
    const char *root_attrs[]={"dsServiceName",NULL}, *dc_attrs[]={"invocationId",NULL};
    struct ldb_message *root=read_one(ldb,mem,"",LDB_SCOPE_BASE,"(objectClass=*)",root_attrs);
    const struct ldb_val *service=root?ldb_msg_find_ldb_val(root,"dsServiceName"):NULL;
    struct ldb_message *dc=service?read_one(ldb,mem,talloc_strndup(mem,(const char*)service->data,service->length),LDB_SCOPE_BASE,"(objectClass=*)",dc_attrs):NULL;
    if(!domain||!writer||!actor||!group||!dc ||
       !equal_attr(domain,"objectGUID",PIN_DOMAIN_GUID,16)||!equal_attr(domain,"objectSid",PIN_DOMAIN_SID,sizeof(PIN_DOMAIN_SID))||
       !equal_attr(dc,"invocationId",PIN_DC_GUID,16)||!equal_attr(group,"objectGUID",PIN_GROUP_GUID,16)||!absent(group,"memberOf")||
       !equal_attr(writer,"objectGUID",PIN_WRITER_GUID,16)||!equal_attr(writer,"objectSid",PIN_WRITER_SID,sizeof(PIN_WRITER_SID))||
       !equal_attr(actor,"objectGUID",PIN_ACTOR_GUID,16)||!equal_attr(actor,"objectSid",PIN_ACTOR_SID,sizeof(PIN_ACTOR_SID))||
       !clean_user(writer,false)||!absent(writer,"memberOf")||!clean_user(actor,false)) return DENY;
    const struct ldb_message_element *members=ldb_msg_find_element(group,"member"); bool member=false;
    if(members) for(unsigned i=0;i<members->num_values;i++) {
        struct ldb_dn *dn=ldb_dn_from_ldb_val(mem,ldb,&members->values[i]);
        if(dn && ldb_dn_compare(dn,actor->dn)==0) member=true;
    }
    if(!member) return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
    const struct ldb_message_element *actor_groups=ldb_msg_find_element(actor,"memberOf");
    if(!actor_groups || actor_groups->num_values!=1) return DENY;
    struct ldb_dn *actor_group=ldb_dn_from_ldb_val(mem,ldb,&actor_groups->values[0]);
    if(!actor_group || ldb_dn_compare(actor_group,group->dn)) return DENY;
    /* Fixed filter, fixed OU and compiled GUID/SID. No client DN or filter. */
    *target=read_one(ldb,mem,PIN_MANAGED_OU,LDB_SCOPE_ONELEVEL,PIN_TARGET_FILTER,attrs);
    if(!*target||!equal_attr(*target,"objectGUID",PIN_TARGET_GUID,16)||
       !equal_attr(*target,"objectSid",PIN_TARGET_SID,sizeof(PIN_TARGET_SID))||!clean_user(*target,true)) return DENY;
    (void)p; return LDB_SUCCESS;
}

static TDB_DATA td(const void *p,size_t n) { TDB_DATA d={(unsigned char*)p,n};return d; }
static struct tdb_context *journal(void) {
    struct stat st,original;
    if(lstat("/tmp/native-cas",&st)||!S_ISDIR(st.st_mode)||st.st_uid!=0||(st.st_mode&077)!=0) return NULL;
    if(lstat(JOURNAL,&original)||!S_ISREG(original.st_mode)||original.st_uid!=0||original.st_nlink!=1||(original.st_mode&077)!=0) return NULL;
    struct tdb_context *db=tdb_open(JOURNAL,0,TDB_DEFAULT,O_RDWR|O_NOFOLLOW,0600);
    if(!db) return NULL;
    if(fstat(tdb_fd(db),&st)||!S_ISREG(st.st_mode)||st.st_uid!=0||st.st_nlink!=1||(st.st_mode&077)!=0||st.st_ino!=original.st_ino||st.st_dev!=original.st_dev) {tdb_close(db);return NULL;}
    return db;
}
static TDB_DATA opkey(uint8_t key[17],const uint8_t id[16]) {key[0]='O';memcpy(key+1,id,16);return td(key,17);}
static int claim(struct state *s,const struct packet *p) {
    struct tdb_context *db=journal(); if(!db) return LDB_ERR_OPERATIONS_ERROR;
    int rc=LDB_ERR_BUSY; uint8_t key[17],value[33];TDB_DATA k=opkey(key,p->id),old={0},target={0};
    if(tdb_transaction_start_nonblock(db)) goto done;
    old=tdb_fetch(db,k);
    if(old.dptr) {
        if(old.dsize==33 && !memcmp(old.dptr,p->digest,32)) rc=old.dptr[32]==2?LDB_SUCCESS:LDB_ERR_BUSY;
        else rc=DENY;
        goto cancel;
    }
    if(tdb_error(db)!=TDB_ERR_NOEXIST) goto cancel;
    target=tdb_fetch(db,td("target",6)); if(target.dptr) goto cancel;
    if(tdb_error(db)!=TDB_ERR_NOEXIST) goto cancel;
    memcpy(value,p->digest,32);value[32]=1;
    if(tdb_store(db,k,td(value,33),TDB_INSERT)||tdb_store(db,td("target",6),td(p->id,16),TDB_INSERT)) goto cancel;
    key[0]='C';
    uint8_t audit[sizeof(PIN_ACTOR_SID)+17];memcpy(audit,PIN_ACTOR_SID,sizeof(PIN_ACTOR_SID));
    memcpy(audit+sizeof(PIN_ACTOR_SID),PIN_TARGET_GUID,16);audit[sizeof(audit)-1]=p->mask;
    if(tdb_store(db,td(key,17),td(audit,sizeof(audit)),TDB_INSERT)) goto cancel;
    if(tdb_transaction_commit(db)) goto done;
    s->pending=true;s->applied=false;memcpy(s->id,p->id,16);memcpy(s->digest,p->digest,32);s->mask=p->mask;
    rc=-1;goto done; /* fresh durable claim, distinct from stored success */
cancel: tdb_transaction_cancel(db);
done: free(old.dptr);free(target.dptr);tdb_close(db);return rc;
}
static int finish(struct state *s,uint8_t state) {
    struct tdb_context *db=journal();if(!db) return LDB_ERR_OPERATIONS_ERROR;
    int rc=LDB_ERR_OPERATIONS_ERROR;uint8_t key[17];TDB_DATA k=opkey(key,s->id),old={0},target={0};
    if(tdb_transaction_start_nonblock(db)) goto done;
    old=tdb_fetch(db,k);target=tdb_fetch(db,td("target",6));
    if(old.dsize!=33 || !old.dptr || memcmp(old.dptr,s->digest,32)||old.dptr[32]!=1||target.dsize!=16||!target.dptr||memcmp(target.dptr,s->id,16)) goto cancel;
    old.dptr[32]=state;
    if(tdb_store(db,k,old,TDB_MODIFY)||tdb_delete(db,td("target",6))) goto cancel;
    key[0]='F';if(tdb_store(db,td(key,17),td(&state,1),TDB_INSERT)) goto cancel;
    if(state==2) {
        uint8_t version[8];uint64_t n=s->committed_version;
        if(!n) goto cancel;
        for(unsigned i=0;i<8;i++) {version[7-i]=n&255;n>>=8;}
        key[0]='V';if(tdb_store(db,td(key,17),td(version,8),TDB_INSERT)) goto cancel;
    }
    if(tdb_transaction_commit(db)) goto done;
    rc=LDB_SUCCESS;goto done;
cancel: tdb_transaction_cancel(db);
done: free(old.dptr);free(target.dptr);tdb_close(db);return rc;
}
static bool fault(const char *value) {
#ifdef IDENTITY_NATIVE_LAB_FAULTS
    char buf[40]={0};int fd=open("/tmp/native-cas/fault",O_RDONLY|O_NOFOLLOW);struct stat st;
    if(fd<0) return false;
    bool ok=!fstat(fd,&st)&&S_ISREG(st.st_mode)&&st.st_uid==0&&st.st_nlink==1&&!(st.st_mode&077);
    ssize_t n=ok?read(fd,buf,sizeof(buf)-1):-1;close(fd);
    return n>0&&!strcmp(buf,value);
#else
    (void)value;return false;
#endif
}
static int start(struct ldb_module *m) {
    struct state *s=ldb_module_get_private(m);int rc=ldb_next_start_trans(m);
    if(rc==LDB_SUCCESS) {s->tx=true;s->pending=false;s->applied=false;s->committed_version=0;}return rc;
}
static int prepare(struct ldb_module *m) {
    struct state *s=ldb_module_get_private(m);
    if(s->pending&&s->applied&&fault("before_commit")) _exit(91);
    return ldb_next_prepare_commit(m);
}
static int commit(struct ldb_module *m) {
    struct state *s=ldb_module_get_private(m);int rc=ldb_next_end_trans(m);s->tx=false;
    if(s->pending && rc==LDB_SUCCESS) {
        if(s->applied&&fault("after_commit")) _exit(92);
        if(s->applied&&fault("commit_ack_error")) {s->pending=false;return LDB_ERR_OPERATIONS_ERROR;}
        rc=finish(s,s->applied?2:3);
    }
    s->pending=false;return rc;
}
static int cancel(struct ldb_module *m) {
    struct state *s=ldb_module_get_private(m);int rc=ldb_next_del_trans(m);s->tx=false;
    if(s->pending&&rc==LDB_SUCCESS) rc=finish(s,3);
    s->pending=false;return rc;
}
static int modified(struct ldb_request *req,struct ldb_reply *reply) {
    struct callback_context *context=req->context;
    struct ldb_request *parent=context->parent;
    struct state *s=ldb_module_get_private(context->module);
    if(!reply || reply->type!=LDB_REPLY_DONE) {
        return ldb_module_done(parent,NULL,NULL,LDB_ERR_OPERATIONS_ERROR);
    }
    s->applied=reply->error==LDB_SUCCESS;
    if(s->applied) {
        const char *wanted[]={"uSNChanged",NULL};
        struct ldb_context *ldb=ldb_module_get_ctx(context->module);
        struct ldb_message *row=read_one(ldb,req,ldb_dn_get_linearized(req->op.mod.message->dn),
            LDB_SCOPE_BASE,"(objectClass=user)",wanted);
        if(!row||!number(row,"uSNChanged",&s->committed_version)||!s->committed_version)
            return ldb_module_done(parent,NULL,NULL,LDB_ERR_OPERATIONS_ERROR);
    }
    return ldb_module_done(parent,reply->controls,reply->response,reply->error);
}
static int modify_request(struct ldb_module *m,struct ldb_request *req) {
    const struct ldb_message *msg=req->op.mod.message;
    const struct ldb_message_element *e=ldb_msg_find_element(msg,ATTR);
    struct ldb_context *ldb=ldb_module_get_ctx(m);struct state *s=ldb_module_get_private(m);
    const struct auth_session_info *session=ldb_get_opaque(ldb,"sessionInfo");
    bool writer=session&&session->security_token&&session->security_token->num_sids&&session->security_token->sids&&
        sid_equal(&session->security_token->sids[0],PIN_WRITER_SID,sizeof(PIN_WRITER_SID));
    if(!e) return writer?DENY:ldb_next_request(m,req);
    if(!s->tx||s->pending) {ldb_set_errstring(ldb,"native transaction state");return DENY;}
    if(msg->num_elements!=1||e->num_values!=1||LDB_FLAG_MOD_TYPE(e->flags)!=LDB_FLAG_MOD_REPLACE) {ldb_set_errstring(ldb,"native frame shape");return DENY;}
    /* Samba's normal 636 listener adds NO_GLOBAL_CATALOG. This flag carries
     * no authorization and is not a bypass control. No other control accepted. */
    if(req->controls) for(unsigned i=0;req->controls[i];i++) {
        if(i>0 || strcmp(req->controls[i]->oid,"1.3.6.1.4.1.7165.4.3.17") || req->controls[i]->data) {
            ldb_set_errstring(ldb,"native controls denied");return DENY;
        }
    }
    struct packet p={0};int rc=parse(e->values[0].data,e->values[0].length,&p);if(rc) {ldb_set_errstring(ldb,"native signed frame denied");return rc;}
    if(!writer_token(ldb)) return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
    struct ldb_message *target=NULL;rc=policy(ldb,req,&p,&target);if(rc) {ldb_set_errstring(ldb,"native current policy denied");return rc;}
    if(ldb_dn_compare(msg->dn,target->dn)) return DENY;
    rc=claim(s,&p);if(rc!=-1) return ldb_module_done(req,NULL,NULL,rc);
    uint64_t version=0;
    if(!number(target,"uSNChanged",&version)||version!=p.version) return LDB_ERR_COMPARE_FALSE;
    if(fault("hold_before_modify")) {
        int fd=open("/tmp/native-cas/holding",O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600);
        if(fd<0) return LDB_ERR_OPERATIONS_ERROR;
        close(fd);sleep(2);
    }
    if(fault("expire_before_modify")) sleep(2);
    if(!fresh(&p)) return DENY;
    struct ldb_message *out=ldb_msg_new(req);if(!out) return LDB_ERR_OPERATIONS_ERROR;
    out->dn=ldb_dn_copy(out,target->dn);
    for(unsigned i=0;i<4;i++) {
        if(p.sizes[i]==65535) continue;
        rc=ldb_msg_add_empty(out,fields[i],LDB_FLAG_MOD_REPLACE,NULL);if(rc) return rc;
        if(p.sizes[i]) {struct ldb_val v={(uint8_t*)p.values[i],p.sizes[i]};rc=ldb_msg_add_value(out,fields[i],&v,NULL);if(rc) return rc;}
    }
    struct ldb_request *next=NULL;
    struct callback_context *context=talloc(req,struct callback_context);if(!context) return LDB_ERR_OPERATIONS_ERROR;
    context->parent=req;context->module=m;
    rc=ldb_build_mod_req(&next,ldb,req,out,req->controls,context,modified,req);if(rc) return rc;
    /* No session substitution, no bypass flag, no untrusted controls. */
    return ldb_next_request(m,next);
}
static int other_write(struct ldb_module *m,struct ldb_request *req) {
    struct ldb_context *ldb=ldb_module_get_ctx(m);
    const struct auth_session_info *session=ldb_get_opaque(ldb,"sessionInfo");
    if(session&&session->security_token&&session->security_token->num_sids&&session->security_token->sids&&
       sid_equal(&session->security_token->sids[0],PIN_WRITER_SID,sizeof(PIN_WRITER_SID))) return DENY;
    return ldb_next_request(m,req);
}
static int init(struct ldb_module *m) {
    struct ldb_context *ldb=ldb_module_get_ctx(m);
    const char *url=ldb_get_opaque(ldb,"ldb_url");const char *env=getenv("IDENTITY_AD_PROFILE_LAB");
    if(!url||strcmp(url,"/tmp/profile-domain/private/sam.ldb")||!env||strcmp(env,"/tmp/lab-config.json")) return DENY;
    DIR *dir=opendir("/sys/class/net");struct dirent *entry;bool loopback=false,bad=false;
    if(!dir) return DENY;
    while((entry=readdir(dir))) {if(entry->d_name[0]=='.')continue;if(!strcmp(entry->d_name,"lo"))loopback=true;else bad=true;}
    closedir(dir);if(!loopback||bad) return DENY;
    struct state *s=talloc_zero(m,struct state);if(!s) return LDB_ERR_OPERATIONS_ERROR;
    ldb_module_set_private(m,s);return ldb_next_init(m);
}
static const struct ldb_module_ops ops={.name="identity_native_cas_lab",.init_context=init,
    .modify=modify_request,.add=other_write,.del=other_write,.rename=other_write,
    .start_transaction=start,.prepare_commit=prepare,.end_transaction=commit,.del_transaction=cancel};
int ldb_init_module(const char *version) {LDB_MODULE_CHECK_VERSION(version);return ldb_register_module(&ops);}
