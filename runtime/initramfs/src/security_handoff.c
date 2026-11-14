/* Public boot context only. No guard write, Trusty ioctl, storage proxy or keys.
 * Failure blocks the later native credential gate only; UI/Android/ADB survive.
 */
#define TFB_SECURITY_CONTEXT "/dev/treeforge-altos/security-context-v1"
static int tfb_security_boot_value(const char *boot, const char *key, char *out, usize cap) {
    usize bytes=tfb_strlen(boot),k=tfb_strlen(key);unsigned found=0;
    for(usize p=0;p<bytes;){usize end=p;while(end<bytes && boot[end]!='\n')end++;
        if(end-p>k+5 && memcmp(boot+p,key,k)==0 && memcmp(boot+p+k," = \"",4)==0){
            usize n=end-p-k-5;if(++found!=1 || !n || n>=cap || boot[end-1]!='"')return 0;
            for(usize j=0;j<n;j++)if(boot[p+k+4+j]<33 || boot[p+k+4+j]>126 || boot[p+k+4+j]=='"' || boot[p+k+4+j]=='\\')return 0;
            memcpy(out,boot+p+k+4,n);out[n]=0;}
        p=end+1;}
    return found==1;
}
static int tfb_security_append(char *record,usize *used,const char *key,const char *value) {
    usize k=tfb_strlen(key),v=tfb_strlen(value);if(*used+k+v+2>=2048)return 0;
    char *p=record+*used;memcpy(p,key,k);p+=k;*p++='=';memcpy(p,value,v);p+=v;*p++='\n';
    *used=(usize)(p-record);*p=0;return 1;
}
static int tfb_security_produce(void) {
    unsigned char profile[256],hash[32];char text[32768],value[256],record[2048];
    long fd=tfb_open("/dev/treeforge-bootstrap-runtime/etc/security-profile-v1",O_RDONLY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC|O_NONBLOCK);
    if(fd<0)return 0;char extra;int ok=tfb_altos_private_file(fd,256) && tfb_read_exact(fd,profile,256) && tfb_syscall3(SYS_READ,fd,(long)&extra,1)==0;tfb_close(fd);
    if(!ok || !tfb_altos_eq(profile,"TFSEC01\0",8) || !tfb_altos_zero(profile+64,192) ||
        tfb_altos_le(profile+28,4)!=1 || !tfb_kernel_receipt_matches(profile+32))return 0;
    if(!tfb_altos_read_small(TFB_ALTOS_CONTEXT,text,sizeof(text)))return 0;
    fd=tfb_open(TFB_ALTOS_CONTEXT,O_RDONLY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC|O_NONBLOCK);
    if(fd<0)return 0;ok=tfb_altos_private_file(fd,2048);tfb_close(fd);if(!ok)return 0;
    if(!tfb_altos_hash(-1,(unsigned char*)text,tfb_strlen(text),0,hash))return 0;
    const char *magic="TREEFORGE_SECURITY_BOOT_V1\n";usize length=tfb_strlen(magic);memcpy(record,magic,length);
    tfb_altos_hex(value,hash,32);ok=tfb_security_append(record,&length,"storage_context_sha256",value);
    if(!tfb_altos_hash(-1,profile,256,0,hash))ok=0;tfb_altos_hex(value,hash,32);ok=ok&&tfb_security_append(record,&length,"profile_sha256",value);
    tfb_altos_hex(value,profile+32,32);ok=ok&&tfb_security_append(record,&length,"kernel_provider_sha256",value);
    const char *names[]={"carrier_os_version","system_patchlevel","vendor_patchlevel","boot_patchlevel","trusty_build","guard_abi"};
    for(unsigned i=0;i<6;i++){tfb_altos_decimal(value,tfb_altos_le(profile+8+i*4,4));ok=ok&&tfb_security_append(record,&length,names[i],value);}
    if(!tfb_altos_read_small("/proc/sys/kernel/random/boot_id",value,sizeof(value)) || tfb_strlen(value)!=37)ok=0;
    value[36]=0;ok=ok&&tfb_security_append(record,&length,"boot_id",value);
    if(!tfb_altos_read_small("/proc/bootconfig",text,sizeof(text)))ok=0;
    const char *bootkeys[]={"androidboot.slot_suffix","androidboot.vbmeta.digest","androidboot.verifiedbootstate","androidboot.vbmeta.device_state"};
    const char *keys[]={"carrier_slot","carrier_vbmeta_digest","carrier_verified_boot_state","carrier_device_state"};
    for(unsigned i=0;i<4;i++){if(!tfb_security_boot_value(text,bootkeys[i],value,sizeof(value)))ok=0;
        if(i==0 && !tfb_string_equal(value,"_a") && !tfb_string_equal(value,"_b"))ok=0;
        if(i==1 && (tfb_strlen(value)!=64 || !tfb_altos_unhex(hash,value,32)))ok=0;
        ok=ok&&tfb_security_append(record,&length,keys[i],value);}
    if(!ok)return 0;
    const char *temporary="/dev/treeforge-altos/.security-context-v1.tmp";
    tfb_syscall3(SYS_UNLINKAT,AT_FDCWD,(long)temporary,0);
    fd=tfb_syscall4(SYS_OPENAT,AT_FDCWD,(long)temporary,O_WRONLY|O_CREAT|0200|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC,0600);
    if(fd<0)return 0;ok=tfb_write_bytes(fd,(unsigned char*)record,length);tfb_close(fd);
    if(ok)ok=tfb_syscall4(SYS_RENAMEAT,AT_FDCWD,(long)temporary,AT_FDCWD,(long)TFB_SECURITY_CONTEXT)==0;
    if(!ok)tfb_syscall3(SYS_UNLINKAT,AT_FDCWD,(long)temporary,0);return ok;
}
static void tfb_publish_security_context(void) {
    tfb_log("TREEFORGE_SECURITY_HANDOFF_PRODUCER_V1");
    tfb_syscall3(SYS_UNLINKAT,AT_FDCWD,(long)TFB_SECURITY_CONTEXT,0);
    if(tfb_security_produce())tfb_log("security-handoff=public-context-published; guard-unmodified");
    else tfb_log("security-handoff=unavailable; credentials-blocked; ui/adb-retained");
}
