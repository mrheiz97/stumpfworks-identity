/* Single-host laboratory authority. Every writer and the handoff controller
 * use the same stable inode. Root and DSDB replication remain trusted. */
#ifndef IDENTITY_FIXED_CREATE_DC
#define CREATE_AUTHORITY "/tmp/create-authority"
#define CREATE_UPN_SUFFIX "@managed.profile.test"
#endif

static int release_create_fence(struct state *s) {
    if(s->create_fence>=0)close(s->create_fence);
    s->create_fence=-1;
    return 0;
}

static bool upn_attribute(const char *name,const char *type) {
    size_t len=strlen(type);
    return !strncasecmp(name,type,len)&&(name[len]=='\0'||name[len]==';');
}

static bool has_upn_write(const struct ldb_message *msg) {
    for(unsigned i=0;i<msg->num_elements;i++) {
        const char *name=msg->elements[i].name;
        if(!upn_attribute(name,"userPrincipalName")&&
           !upn_attribute(name,"1.2.840.113556.1.4.656"))continue;
#ifdef IDENTITY_FIXED_CREATE_DC
        const struct ldb_message_element *element=&msg->elements[i];
        const size_t length=sizeof(CREATE_UPN_SUFFIX)-1;
        for(unsigned j=0;j<element->num_values;j++){
            const struct ldb_val *value=&element->values[j];
            for(size_t offset=0;offset+length<=value->length;offset++)
                if(!strncasecmp((const char*)value->data+offset,CREATE_UPN_SUFFIX,length))return true;
        }
#else
        return true;
#endif
    }
    return false;
}

static bool private_regular(int fd) {
    struct stat st;
    return !fstat(fd,&st)&&S_ISREG(st.st_mode)&&st.st_uid==0&&st.st_nlink==1&&
        (st.st_mode&0777)==0600;
}

static bool reserve_create(struct state *s,const char *name,const uint8_t *epoch,
                           const uint8_t digest[32]) {
    struct stat st;
    int dir=open(CREATE_AUTHORITY,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dir<0)return false;
    int lock=-1,route=-1,claimfd=-1;bool allowed=false;
    if(fstat(dir,&st)||st.st_uid!=0||(st.st_mode&0777)!=0700)goto done;
    lock=openat(dir,"lock",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(lock<0||!private_regular(lock)||flock(lock,LOCK_EX|LOCK_NB))goto done;
#ifdef IDENTITY_FIXED_CREATE_DC
    if(fstatat(dir,"enabled",&st,AT_SYMLINK_NOFOLLOW)||!S_ISREG(st.st_mode)||
       st.st_uid!=0||st.st_nlink!=1||(st.st_mode&0777)!=0600||st.st_size!=0)goto done;
#endif
    route=openat(dir,"route",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(route<0||!private_regular(route))goto done;
    uint8_t record[25],zero[8]={0};
    if(pread(route,record,sizeof(record),0)!=24||!memcmp(epoch,zero,8)||
       memcmp(record,epoch,8)||memcmp(record+8,PIN_DC_GUID,16))goto done;
    char claim[26];
    snprintf(claim,sizeof(claim),"upn-%s",name);
    claimfd=openat(dir,claim,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(claimfd>=0) {
        allowed=write(claimfd,digest,32)==32&&!fsync(claimfd)&&!fsync(dir);
    } else if(errno==EEXIST) {
        uint8_t saved[33];
        claimfd=openat(dir,claim,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        allowed=claimfd>=0&&private_regular(claimfd)&&
            pread(claimfd,saved,sizeof(saved),0)==32&&!memcmp(saved,digest,32)&&
            !fsync(claimfd)&&!fsync(dir);
    }
done:
    if(claimfd>=0)close(claimfd);
    if(route>=0)close(route);
    close(dir);
    if(allowed)s->create_fence=lock;
    else if(lock>=0)close(lock);
    return allowed;
}
