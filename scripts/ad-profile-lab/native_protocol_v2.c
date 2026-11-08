/* Included only in the explicitly selected synthetic protocol-v2 module.
 * No public OID, installer, generic directory reader or mutation in status.
 */
#define STATUS_DN "CN=NativeCASReceipt," PIN_BASE
#define QUERY_BODY 248
#define QUERY_SIZE 312
#define RECEIPT_BODY 393

static bool profile_hash(const struct ldb_message *m,uint8_t out[32]) {
    uint8_t buffer[646];size_t used=0;
    for(unsigned i=0;i<4;i++) {
        const struct ldb_message_element *e=ldb_msg_find_element(m,fields[i]);
        size_t n=0;const uint8_t *v=NULL;
        if(e&&e->num_values) {
            if(e->num_values!=1) return false;
            n=e->values[0].length;v=e->values[0].data;
            if(!n||n>limits[i]) return false;
            for(size_t j=0;j<n;j++) if(v[j]<32||v[j]>126)return false;
        }
        if(used+2+n>sizeof(buffer))return false;
        buffer[used++]=n>>8;buffer[used++]=n&255;
        if(n){memcpy(buffer+used,v,n);used+=n;}
    }
    return SHA256(buffer,used,out)!=NULL;
}

static bool protocol_parent(struct tdb_context *db,const struct packet *p) {
    uint8_t zero[16]={0},key[17];
    if(!p->binding)return false;
    const uint8_t *parent=p->binding+64;
    if(!memcmp(parent,zero,16))return true;
    TDB_DATA op=tdb_fetch(db,opkey(key,parent));
    key[0]='A';TDB_DATA action=tdb_fetch(db,td(key,17));
    bool wrong_action=action.dptr!=NULL||tdb_error(db)!=TDB_ERR_NOEXIST;free(action.dptr);
    key[0]='B';TDB_DATA binding=tdb_fetch(db,td(key,17));
    key[0]='V';TDB_DATA version=tdb_fetch(db,td(key,17));
    bool ok=!wrong_action&&op.dptr&&op.dsize==33&&op.dptr[32]==2&&binding.dptr&&binding.dsize==144&&
        version.dptr&&version.dsize==8&&be64(version.dptr)==p->version&&
        !memcmp(binding.dptr+32,p->binding+32,32)&&
        !memcmp(binding.dptr+112,p->binding+80,32)&&!memcmp(binding.dptr+80,p->binding+112,32);
    free(op.dptr);free(binding.dptr);free(version.dptr);return ok;
}

static bool protocol_verify(const uint8_t *p,size_t n) {
    if(n<64)return false;
    EVP_PKEY *key=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,PIN_PUBLIC_KEY,32);
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();int ok=0;
    if(key&&ctx&&EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,key)==1)ok=EVP_DigestVerify(ctx,p+n-64,64,p,n-64);
    EVP_MD_CTX_free(ctx);EVP_PKEY_free(key);return ok==1;
}
static bool protocol_controls(struct ldb_control **controls) {
    if(controls)for(unsigned i=0;controls[i];i++)
        if(i>0||strcmp(controls[i]->oid,"1.3.6.1.4.1.7165.4.3.17")||controls[i]->data)return false;
    return true;
}
static void put64(uint8_t *p,uint64_t n) {for(unsigned i=0;i<8;i++){p[7-i]=n&255;n>>=8;}}

static bool protocol_sign(uint8_t *receipt,size_t body_size) {
    int fd=open(NATIVE_DIR "/receipt.pem",O_RDONLY|O_NOFOLLOW);struct stat st;
    if(fd<0)return false;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=0||st.st_nlink!=1||(st.st_mode&077)||st.st_size>4096){close(fd);return false;}
    FILE *stream=fdopen(fd,"r");if(!stream){close(fd);return false;}
    EVP_PKEY *key=PEM_read_PrivateKey(stream,NULL,NULL,NULL);fclose(stream);
    uint8_t public[32];size_t public_len=32,signature_len=64;bool ok=false;
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    if(key&&ctx&&EVP_PKEY_id(key)==EVP_PKEY_ED25519&&EVP_PKEY_get_raw_public_key(key,public,&public_len)==1&&
       public_len==32&&!memcmp(public,PIN_RECEIPT_PUBLIC_KEY,32)&&EVP_DigestSignInit(ctx,NULL,NULL,NULL,key)==1)
        ok=EVP_DigestSign(ctx,receipt+body_size,&signature_len,receipt,body_size)==1&&signature_len==64;
    EVP_MD_CTX_free(ctx);EVP_PKEY_free(key);return ok;
}

static int protocol_receipt(struct ldb_context *ldb,TALLOC_CTX *mem,const uint8_t *q,uint8_t *out) {
    if(memcmp(q,"SWSTAT02",8)||!protocol_verify(q,QUERY_SIZE))return DENY;
    uint8_t zero[16]={0};if(!memcmp(q+88,zero,16))return DENY;
    const uint8_t *identity[]={PIN_DOMAIN_GUID,PIN_DC_GUID,PIN_TARGET_GUID,PIN_ACTOR_GUID};
    for(unsigned i=0;i<4;i++)if(memcmp(q+104+i*16,identity[i],16))return DENY;
    if(memcmp(q+168,PIN_POLICY_HASH,32)||memcmp(q+200,PIN_SCOPE_HASH,32))return DENY;
    struct packet timing={.issued=be64(q+232),.expires=be64(q+240)};
    if(!fresh(&timing)||timing.expires-timing.issued>30)return DENY;
    struct ldb_message *target=NULL;int rc=policy(ldb,mem,NULL,&target);if(rc)return rc;
    struct journal_handle *h=journal_mode(true);if(!h){ldb_set_errstring(ldb,"native-status-open");return LDB_ERR_OPERATIONS_ERROR;}
    struct tdb_context *db=h->db;
    uint8_t key[17],state=0;uint64_t version=0;
    TDB_DATA op=tdb_fetch(db,opkey(key,q+8)),binding={0},committed={0},audit={0},terminal={0};
    rc=LDB_ERR_OPERATIONS_ERROR;ldb_set_errstring(ldb,"native-status-record");
    if(!op.dptr) {
        if(tdb_error(db)!=TDB_ERR_NOEXIST)goto done;
    } else {
        key[0]='A';TDB_DATA action=tdb_fetch(db,td(key,17));
        bool is_create=action.dptr!=NULL;free(action.dptr);
        if(is_create||tdb_error(db)!=TDB_ERR_NOEXIST){rc=DENY;goto done;}
        if(op.dsize!=33||op.dptr[32]<1||op.dptr[32]>3||memcmp(op.dptr,q+56,32)){rc=DENY;goto done;}
        state=op.dptr[32];key[0]='B';binding=tdb_fetch(db,td(key,17));
        if(!binding.dptr||binding.dsize!=144||memcmp(binding.dptr,q+24,32)||memcmp(binding.dptr+32,PIN_POLICY_HASH,32)){rc=DENY;goto done;}
        key[0]='C';audit=tdb_fetch(db,td(key,17));
        if(!audit.dptr||audit.dsize!=sizeof(PIN_ACTOR_SID)+17||memcmp(audit.dptr,PIN_ACTOR_SID,sizeof(PIN_ACTOR_SID))||
           memcmp(audit.dptr+sizeof(PIN_ACTOR_SID),PIN_TARGET_GUID,16)||!audit.dptr[audit.dsize-1]||audit.dptr[audit.dsize-1]>15)goto done;
        key[0]='F';terminal=tdb_fetch(db,td(key,17));
        if(state==1) {if(terminal.dptr||tdb_error(db)!=TDB_ERR_NOEXIST)goto done;}
        else if(!terminal.dptr||terminal.dsize!=1||terminal.dptr[0]!=state)goto done;
        key[0]='V';committed=tdb_fetch(db,td(key,17));
        if(state==2) {if(!committed.dptr||committed.dsize!=8||!(version=be64(committed.dptr)))goto done;}
        else if(committed.dptr||tdb_error(db)!=TDB_ERR_NOEXIST)goto done;
    }
    memset(out,0,RECEIPT_BODY+64);memcpy(out,"SWRECP02",8);memcpy(out+8,q,QUERY_BODY);
    out[256]=state;put64(out+257,version);
    if(state) {memcpy(out+265,binding.dptr+64,16);memcpy(out+281,binding.dptr+80,64);}
    uint8_t reference[105];memcpy(reference,q+8,16);memcpy(reference+16,q+24,64);
    memcpy(reference+80,out+265,16);reference[96]=state;memcpy(reference+97,out+257,8);
    if(!SHA256(reference,sizeof(reference),out+345))goto done;
    uint64_t now=(uint64_t)time(NULL),expires=now+30;
    if(expires>timing.expires)expires=timing.expires;
    if(!fresh(&timing)) {rc=DENY;goto done;}
    put64(out+377,now);put64(out+385,expires);
    rc=LDB_SUCCESS;
done:
    free(op.dptr);free(binding.dptr);free(committed.dptr);free(audit.dptr);free(terminal.dptr);
    journal_close(h);
    if(rc==LDB_SUCCESS){ldb_set_errstring(ldb,"native-status-sign");if(!protocol_sign(out,RECEIPT_BODY))rc=LDB_ERR_OPERATIONS_ERROR;}
    return rc;
}

static int __attribute__((unused)) protocol_search(struct ldb_module *m,struct ldb_request *req) {
    struct ldb_context *ldb=ldb_module_get_ctx(m);
    struct ldb_dn *virtual=ldb_dn_new(req,ldb,STATUS_DN);
    if(ldb_dn_compare(req->op.search.base,virtual))return ldb_next_request(m,req);
    struct state *s=ldb_module_get_private(m);
    const struct ldb_parse_tree *tree=req->op.search.tree;
    const char *const *wanted=req->op.search.attrs;
    if(s->tx||!writer_token(ldb)||req->op.search.scope!=LDB_SCOPE_BASE||!tree||tree->operation!=LDB_OP_EQUALITY||
       strcasecmp(tree->u.equality.attr,"identityLabStatus")||!wanted||!wanted[0]||wanted[1]||
       strcasecmp(wanted[0],"identityLabReceipt")||!protocol_controls(req->controls))return DENY;
    const struct ldb_val *hex=&tree->u.equality.value;
    if(hex->length!=QUERY_SIZE*2)return DENY;
    uint8_t query[QUERY_SIZE],receipt[RECEIPT_BODY+64];
    for(unsigned i=0;i<QUERY_SIZE;i++) {
        unsigned n=0;
        for(unsigned j=0;j<2;j++){uint8_t c=hex->data[2*i+j];if(c>='0'&&c<='9')n=n*16+c-'0';else if(c>='a'&&c<='f')n=n*16+c-'a'+10;else return DENY;}
        query[i]=n;
    }
    /* No network and no AD/TDB mutation. Do not upgrade the LDAP search's read
     * lock to a write transaction. Hold the downstream DSDB read lock while
     * checking current authorization, then a separate TDB read lock. */
    int rc=ldb_next_read_lock(m);if(rc){ldb_set_errstring(ldb,"native-status-start");return rc;}
    rc=protocol_receipt(ldb,req,query,receipt);
    int unlocked=ldb_next_read_unlock(m);if(unlocked){ldb_set_errstring(ldb,"native-status-cancel");return LDB_ERR_OPERATIONS_ERROR;}
    if(rc)return rc;
    struct ldb_message *out=ldb_msg_new(req);if(!out)return LDB_ERR_OPERATIONS_ERROR;
    out->dn=ldb_dn_copy(out,virtual);struct ldb_val value={receipt,sizeof(receipt)};
    rc=ldb_msg_add_value(out,"identityLabReceipt",&value,NULL);if(rc)return rc;
    rc=ldb_module_send_entry(req,out,NULL);if(rc)return rc;
    return ldb_module_done(req,NULL,NULL,LDB_SUCCESS);
}
