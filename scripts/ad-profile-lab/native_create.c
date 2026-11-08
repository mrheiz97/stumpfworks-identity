/* Synthetic CREATE laboratory only. Never enabled by ordinary v1/v2 setup.
 * Signature is issuer assertion, not independent actor proof. Normal DSDB ACLs.
 */
static int created(struct ldb_request *req,struct ldb_reply *reply) {
    struct callback_context *c=req->context;
    struct state *s=ldb_module_get_private(c->module);
    if(!reply||reply->type!=LDB_REPLY_DONE)return ldb_module_done(c->parent,NULL,NULL,LDB_ERR_OPERATIONS_ERROR);
    s->applied=reply->error==LDB_SUCCESS;
    if(s->applied) {
        const char *wanted[]={"uSNChanged","userAccountControl","objectGUID","objectSid",NULL};
        struct ldb_message *row=read_one(ldb_module_get_ctx(c->module),req,
            ldb_dn_get_linearized(req->op.add.message->dn),LDB_SCOPE_BASE,"(objectClass=user)",wanted);
        uint64_t uac=0;
        if(!row||!number(row,"uSNChanged",&s->committed_version)||!s->committed_version||
           !number(row,"userAccountControl",&uac)||uac!=514||!ldb_msg_find_ldb_val(row,"objectGUID")||
           !ldb_msg_find_ldb_val(row,"objectSid"))return ldb_module_done(c->parent,NULL,NULL,LDB_ERR_CONSTRAINT_VIOLATION);
        const struct ldb_val *guid=ldb_msg_find_ldb_val(row,"objectGUID"),*sid=ldb_msg_find_ldb_val(row,"objectSid");
        if(guid->length!=16||sid->length<8||sid->length>68)return ldb_module_done(c->parent,NULL,NULL,LDB_ERR_CONSTRAINT_VIOLATION);
        memcpy(s->create_identity,guid->data,16);memcpy(s->create_identity+16,sid->data,sid->length);
        s->create_identity_len=16+sid->length;
    }
    return ldb_module_done(c->parent,reply->controls,reply->response,reply->error);
}
static int create_request(struct ldb_module *m,struct ldb_request *req) {
    struct ldb_context *ldb=ldb_module_get_ctx(m);
    const struct ldb_message *input=req->op.add.message;
    const struct ldb_message_element *e=ldb_msg_find_element(input,"identityLabCreate");
#ifdef IDENTITY_CREATE_FENCE
    if(!e&&has_upn_write(input))return DENY;
#endif
    if(!e)return other_write(m,req);
    struct state *s=ldb_module_get_private(m);
    if(!s->tx||s->pending||!writer_token(ldb)||input->num_elements!=1||e->num_values!=1||!protocol_controls(req->controls))return DENY;
    const uint8_t *v=e->values[0].data;size_t n=e->values[0].length;
#ifdef IDENTITY_CREATE_FENCE
    if(n<276||n>552||memcmp(v,"SWNEW002",8)||!protocol_verify(v,n))return DENY;
    size_t offset=208;
#else
    if(n<268||n>544||memcmp(v,"SWNEW001",8)||!protocol_verify(v,n))return DENY;
    size_t offset=200;
#endif
    const uint8_t *pins[]={PIN_DOMAIN_GUID,PIN_DC_GUID,PIN_CREATE_OU_GUID,PIN_ACTOR_GUID,PIN_WRITER_GUID,PIN_GROUP_GUID};
    for(unsigned i=0;i<6;i++)if(memcmp(v+24+i*16,pins[i],16))return DENY;
    struct packet p={.id=v+8,.issued=be64(v+120),.expires=be64(v+128),.mask=1,.creating=true,.scope_target=PIN_CREATE_OU_GUID};
    uint8_t zero[32]={0};
    if(!fresh(&p)||!memcmp(p.id,zero,16)||!memcmp(v+136,zero,32)||memcmp(v+168,PIN_POLICY_HASH,32)||!SHA256(v,n-64,p.digest))return DENY;
    uint8_t binding[144]={0};memcpy(binding,v+136,64);p.binding=binding;
    char name[21]={0},display[257]={0};
    char *outvalues[]={name,display};const unsigned limits_create[]={20,256};
    for(unsigned i=0;i<2;i++) {
        if(offset+2>n-64)return DENY;
        unsigned len=(unsigned)v[offset]*256+v[offset+1];offset+=2;
        if(!len||len>limits_create[i]||offset+len>n-64)return DENY;
        for(unsigned j=0;j<len;j++) {
            uint8_t b=v[offset+j];
            if(i==0) {if(!((b>='a'&&b<='z')||(j>0&&((b>='0'&&b<='9')||b=='-'||b=='.'||b=='_'))))return DENY;}
            else if(b<32||b>126)return DENY;
        }
        memcpy(outvalues[i],v+offset,len);offset+=len;
    }
    if(offset!=n-64)return DENY;
    struct ldb_message *target=NULL;int rc=policy(ldb,req,&p,&target);if(rc)return rc;
    const char *ouattrs[]={"objectGUID",NULL};
    struct ldb_message *ou=read_one(ldb,req,PIN_MANAGED_OU,LDB_SCOPE_BASE,"(objectClass=organizationalUnit)",ouattrs);
    if(!ou||!equal_attr(ou,"objectGUID",PIN_CREATE_OU_GUID,16))return DENY;
    char *dn=talloc_asprintf(req,"CN=%s,%s",name,PIN_MANAGED_OU);
    struct ldb_dn *expected=ldb_dn_new(req,ldb,dn);
    if(!expected||ldb_dn_compare(expected,input->dn))return DENY;
#ifdef IDENTITY_CREATE_FENCE
    if(s->create_fence>=0||!reserve_create(s,name,v+200,p.digest))return DENY;
    char *upn=talloc_asprintf(req,"%s" CREATE_UPN_SUFFIX,name);
#else
    char *upn=talloc_asprintf(req,"%s@profile.test",name);
#endif
    if(!upn)return LDB_ERR_OPERATIONS_ERROR;
    rc=claim(s,&p);if(rc!=-1)return ldb_module_done(req,NULL,NULL,rc);
    struct ldb_result *matches=NULL;
    rc=ldb_search(ldb,req,&matches,ldb_dn_new(req,ldb,PIN_BASE),LDB_SCOPE_SUBTREE,ouattrs,
        "(|(sAMAccountName=%s)(userPrincipalName=%s))",name,upn);
    if(rc)return rc;
    if(matches->count)return LDB_ERR_ENTRY_ALREADY_EXISTS;
    if(!fresh(&p))return DENY;
    struct ldb_message *out=ldb_msg_new(req);if(!out)return LDB_ERR_OPERATIONS_ERROR;
    out->dn=expected;
    const char *keys[]={"objectClass","cn","sAMAccountName","userPrincipalName","displayName","userAccountControl"};
    const char *values[]={"user",name,name,upn,display,"514"};
    /* Downstream Add is asynchronous: never retain pointers into stack buffers. */
    for(unsigned i=0;i<6;i++){
        char *owned=talloc_strdup(out,values[i]);if(!owned)return LDB_ERR_OPERATIONS_ERROR;
        rc=ldb_msg_add_string(out,keys[i],owned);if(rc)return rc;
    }
    struct callback_context *c=talloc(req,struct callback_context);if(!c)return LDB_ERR_OPERATIONS_ERROR;
    c->parent=req;c->module=m;struct ldb_request *next=NULL;
    rc=ldb_build_add_req(&next,ldb,req,out,req->controls,c,created,req);if(rc)return rc;
    return ldb_next_request(m,next);
}

#define CREATE_STATUS_DN "CN=NativeCreateReceipt," PIN_BASE
#ifdef IDENTITY_CREATE_FENCE
#define CREATE_QUERY_MAGIC "SWCSTAT2"
#define CREATE_RECEIPT_MAGIC "SWCRECP2"
#else
#define CREATE_QUERY_MAGIC "SWCSTAT1"
#define CREATE_RECEIPT_MAGIC "SWCRECP1"
#endif
static int create_status(struct ldb_module *m,struct ldb_request *req,const uint8_t *q,uint8_t *out) {
    struct ldb_context *ldb=ldb_module_get_ctx(m);uint8_t zero[16]={0};
    if(memcmp(q,CREATE_QUERY_MAGIC,8)||!protocol_verify(q,QUERY_SIZE)||!memcmp(q+88,zero,16))return DENY;
    const uint8_t *pins[]={PIN_DOMAIN_GUID,PIN_DC_GUID,PIN_CREATE_OU_GUID,PIN_ACTOR_GUID};
    for(unsigned i=0;i<4;i++)if(memcmp(q+104+i*16,pins[i],16))return DENY;
    if(memcmp(q+168,PIN_POLICY_HASH,32)||memcmp(q+200,PIN_SCOPE_HASH,32))return DENY;
    struct packet timing={.issued=be64(q+232),.expires=be64(q+240)};
    if(!fresh(&timing)||timing.expires-timing.issued>30)return DENY;
    struct ldb_message *target=NULL;int rc=policy(ldb,req,NULL,&target);if(rc)return rc;
    struct journal_handle *h=journal_mode(true);if(!h)return LDB_ERR_OPERATIONS_ERROR;
    struct tdb_context *db=h->db;uint8_t key[17],state=0;uint64_t usn=0;
    TDB_DATA op=tdb_fetch(db,opkey(key,q+8)),binding={0},action={0},identity={0},version={0},terminal={0},audit={0};
    rc=LDB_ERR_OPERATIONS_ERROR;
    if(!op.dptr){if(tdb_error(db)!=TDB_ERR_NOEXIST)goto done;}
    else {
        if(op.dsize!=33||memcmp(op.dptr,q+56,32)||op.dptr[32]<1||op.dptr[32]>3)goto done;
        state=op.dptr[32];key[0]='A';action=tdb_fetch(db,td(key,17));
        key[0]='B';binding=tdb_fetch(db,td(key,17));
        if(!action.dptr||action.dsize!=1||action.dptr[0]!=1||!binding.dptr||binding.dsize!=144||memcmp(binding.dptr,q+24,32)||memcmp(binding.dptr+32,PIN_POLICY_HASH,32))goto done;
        key[0]='C';audit=tdb_fetch(db,td(key,17));
        if(!audit.dptr||audit.dsize!=sizeof(PIN_ACTOR_SID)+17||memcmp(audit.dptr,PIN_ACTOR_SID,sizeof(PIN_ACTOR_SID))||memcmp(audit.dptr+sizeof(PIN_ACTOR_SID),PIN_CREATE_OU_GUID,16)||audit.dptr[audit.dsize-1]!=1)goto done;
        key[0]='F';terminal=tdb_fetch(db,td(key,17));
        if(state==1){if(terminal.dptr||tdb_error(db)!=TDB_ERR_NOEXIST)goto done;}
        else if(!terminal.dptr||terminal.dsize!=1||terminal.dptr[0]!=state)goto done;
        key[0]='V';version=tdb_fetch(db,td(key,17));
        if(state==2){if(!version.dptr||version.dsize!=8||!(usn=be64(version.dptr)))goto done;}
        else if(version.dptr||tdb_error(db)!=TDB_ERR_NOEXIST)goto done;
        key[0]='N';identity=tdb_fetch(db,td(key,17));
        if(state==2){if(!identity.dptr||identity.dsize<24||identity.dsize>84||identity.dptr[16]!=1||identity.dsize!=24+4*(size_t)identity.dptr[17])goto done;}
        else if(identity.dptr||tdb_error(db)!=TDB_ERR_NOEXIST)goto done;
    }
    memset(out,0,430);memcpy(out,CREATE_RECEIPT_MAGIC,8);memcpy(out+8,q,QUERY_BODY);out[256]=state;put64(out+257,usn);
    if(state==2){memcpy(out+265,identity.dptr,16);out[281]=identity.dsize-16;memcpy(out+282,identity.dptr+16,identity.dsize-16);}
    uint64_t now=(uint64_t)time(NULL);if(!fresh(&timing)){rc=DENY;goto done;}
    put64(out+350,now);put64(out+358,timing.expires);rc=LDB_SUCCESS;
done:
    free(op.dptr);free(binding.dptr);free(action.dptr);free(identity.dptr);free(version.dptr);free(terminal.dptr);free(audit.dptr);journal_close(h);
    if(rc==LDB_SUCCESS&&!protocol_sign(out,366))rc=LDB_ERR_OPERATIONS_ERROR;
    return rc;
}
static int create_search(struct ldb_module *m,struct ldb_request *req) {
    struct ldb_context *ldb=ldb_module_get_ctx(m);
    struct ldb_dn *dn=ldb_dn_new(req,ldb,CREATE_STATUS_DN);
    if(ldb_dn_compare(req->op.search.base,dn)){
#ifdef IDENTITY_FIXED_CREATE_DC
        return ldb_next_request(m,req);
#else
        return protocol_search(m,req);
#endif
    }
    struct state *s=ldb_module_get_private(m);const struct ldb_parse_tree *t=req->op.search.tree;
    const char *const *attrs=req->op.search.attrs;
    if(s->tx||!writer_token(ldb)||req->op.search.scope!=LDB_SCOPE_BASE||!t||t->operation!=LDB_OP_EQUALITY||
       strcasecmp(t->u.equality.attr,"identityLabCreateStatus")||!attrs||!attrs[0]||attrs[1]||
       strcasecmp(attrs[0],"identityLabCreateReceipt")||!protocol_controls(req->controls)||t->u.equality.value.length!=624)return DENY;
    uint8_t q[QUERY_SIZE],out[430];
    for(unsigned i=0;i<QUERY_SIZE;i++){
        unsigned n=0;for(unsigned j=0;j<2;j++){uint8_t c=t->u.equality.value.data[i*2+j];if(c>='0'&&c<='9')n=n*16+c-'0';else if(c>='a'&&c<='f')n=n*16+c-'a'+10;else return DENY;}q[i]=n;
    }
    int rc=ldb_next_read_lock(m);if(rc)return rc;
    rc=create_status(m,req,q,out);int unlock=ldb_next_read_unlock(m);if(unlock)return LDB_ERR_OPERATIONS_ERROR;if(rc)return rc;
    struct ldb_message *msg=ldb_msg_new(req);if(!msg)return LDB_ERR_OPERATIONS_ERROR;msg->dn=dn;struct ldb_val v={out,sizeof(out)};
    rc=ldb_msg_add_value(msg,"identityLabCreateReceipt",&v,NULL);if(rc)return rc;
    rc=ldb_module_send_entry(req,msg,NULL);if(rc)return rc;return ldb_module_done(req,NULL,NULL,LDB_SUCCESS);
}
