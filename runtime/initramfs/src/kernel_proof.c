/* Current-boot storage compatibility proof. The expected contract is carried in
 * the Owner-signed dispatcher trailer; this is not remote hardware attestation.
 * Called after ADB startup. All failures are non-fatal to Menu/Android/ADB.
 */
#define TFB_KERNEL_RECEIPT "/dev/treeforge-verified-kernel-v1"
#define TFB_KERNEL_TEMP "/dev/.treeforge-verified-kernel-v1.tmp"
static char tfb_kernel_receipt[1024];
static usize tfb_kernel_receipt_bytes;
static unsigned char tfb_kernel_provider[32];
static int tfb_kernel_contains(const char *s,const char *needle) {
    usize n=tfb_strlen(needle),bytes=tfb_strlen(s);for(usize i=0;i+n<=bytes;i++)if(memcmp(s+i,needle,n)==0)return 1;return 0;
}
static int tfb_kernel_hash_prefix(long input,u64 length,unsigned char *result) {
    int output[2],feed[2];if(tfb_syscall2(59,(long)output,TFB_ALTOS_CLOEXEC)<0)return 0;
    if(tfb_syscall2(59,(long)feed,TFB_ALTOS_CLOEXEC)<0){tfb_close(output[0]);tfb_close(output[1]);return 0;}
    long child=tfb_syscall6(SYS_CLONE,TREEFORGE_BOOTSTRAP_SIGCHLD,0,0,0,0,0);
    if(child==0){
        tfb_syscall3(SYS_DUP3,feed[0],0,0);tfb_syscall3(SYS_DUP3,output[1],1,0);
        tfb_close(feed[0]);tfb_close(feed[1]);tfb_close(output[0]);tfb_close(output[1]);
        char *argv[]={(char*)TFB_ALTROOT_LOADER_BUSYBOX,(char*)"sha256sum",0};
        char *env[]={(char*)"PATH=/dev/treeforge-bootstrap-runtime/system/bin",0};
        tfb_syscall3(SYS_EXECVE,(long)argv[0],(long)argv,(long)env);tfb_syscall1(SYS_EXIT,127);for(;;){}
    }
    tfb_close(feed[0]);tfb_close(output[1]);
    if(child<0){tfb_close(feed[1]);tfb_close(output[0]);return 0;}
    int ok=1;unsigned char buffer[4096];
    while(ok && length){usize n=length<sizeof(buffer)?(usize)length:sizeof(buffer);
        ok=tfb_read_exact(input,buffer,n)&&tfb_write_bytes(feed[1],buffer,n);length-=n;}
    tfb_close(feed[1]);char text[100];usize used=0;
    while(ok && used<sizeof(text)){long n=tfb_syscall3(SYS_READ,output[0],(long)(text+used),(long)(sizeof(text)-used));
        if(n==-4)continue;if(n<0){ok=0;break;}if(!n)break;used+=(usize)n;}
    tfb_close(output[0]);int status=0;long waited;
    do{waited=tfb_syscall4(SYS_WAIT4,child,(long)&status,0,0);}while(waited==-4);
    return ok && waited==child && status==0 && used==68 && text[64]==' ' && text[65]==' ' && text[66]=='-' && text[67]=='\n' && tfb_altos_unhex(result,text,32);
}
static int tfb_kernel_live_id(const unsigned char *expected,unsigned n) {
    unsigned char notes[32768];long fd=tfb_open("/sys/kernel/notes",O_RDONLY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC);
    if(fd<0)return 0;usize used=0;int ok=1;
    for(;;){long got=tfb_syscall3(SYS_READ,fd,(long)(notes+used),(long)(sizeof(notes)-used));
        if(got==-4)continue;if(got<0){ok=0;break;}if(!got)break;used+=(usize)got;if(used==sizeof(notes)){ok=0;break;}}
    tfb_close(fd);unsigned found=0;usize p=0;
    while(ok && p<used){if(tfb_altos_zero(notes+p,used-p))break;if(used-p<12)return 0;u64 names=tfb_altos_le(notes+p,4),descs=tfb_altos_le(notes+p+4,4),kind=tfb_altos_le(notes+p+8,4);
        p+=12;u64 namebytes=(names+3)&~3ULL,descbytes=(descs+3)&~3ULL;
        if(namebytes>used-p || descbytes>used-p-namebytes)return 0;
        if(kind==3 && names==4 && tfb_altos_eq(notes+p,"GNU\0",4)){
            if(++found!=1 || descs!=n || !tfb_altos_eq(notes+p+namebytes,expected,n))return 0;}
        p+=(usize)(namebytes+descbytes);}
    return ok && found==1;
}
static long tfb_kernel_boot_device(char slot) {
    if(tfb_realize_block_nodes()!=0)return -1;
    char path[128],text[1024];char wanted[]="PARTNAME=boot_a\n";wanted[14]=slot;
    for(int i=1;i<=128;i++){
        if(tfb_block_make_path(path,sizeof(path),"/sys/class/block/sda",i,"/uevent")!=0)continue;
        if(!tfb_altos_read_small(path,text,sizeof(text)) || !tfb_kernel_contains(text,wanted))continue;
        if(tfb_block_make_path(path,sizeof(path),"/dev/block/sda",i,"")!=0)return -1;
        long fd=tfb_open(path,O_RDONLY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC);
        unsigned long major=0,minor=0;u64 size=0;
        if(tfb_block_device_number(i,&major,&minor)!=0 || !tfb_altos_device(fd,0060000,tfb_runtime_makedev(major,minor)) ||
            tfb_syscall3(SYS_IOCTL,fd,0x80081272,(long)&size)<0 || size!=67108864ULL){tfb_close(fd);return -1;}return fd;
    }return -1;
}
static int tfb_kernel_append(const char *key,const char *value) {
    usize k=tfb_strlen(key),v=tfb_strlen(value);if(tfb_kernel_receipt_bytes+k+v+2>=sizeof(tfb_kernel_receipt))return 0;
    char *p=tfb_kernel_receipt+tfb_kernel_receipt_bytes;memcpy(p,key,k);p+=k;*p++='=';memcpy(p,value,v);p+=v;*p++='\n';
    tfb_kernel_receipt_bytes=(usize)(p-tfb_kernel_receipt);*p=0;return 1;
}
static int tfb_kernel_produce(void) {
    unsigned char contract[512],hash[32];char text[32768];
    long fd=tfb_open("/dev/treeforge-bootstrap-runtime/etc/kernel-contract-v1",O_RDONLY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC);
    if(fd<0)return 0;int ok=tfb_altos_private_file(fd,512)&&tfb_read_exact(fd,contract,512);char extra;
    ok=ok&&tfb_syscall3(SYS_READ,fd,(long)&extra,1)==0;tfb_close(fd);
    if(!ok || !tfb_altos_eq(contract,"TFKERN1\0",8))return 0;
    u64 length=tfb_altos_le(contract+72,8),n=tfb_altos_le(contract+80,4),abi=tfb_altos_le(contract+148,2);
    if(length<4096 || length>67108800 || n<16 || n>64 || abi<1 || abi>127 ||
        !tfb_altos_zero(contract+84+n,(usize)(64-n)) || !tfb_altos_zero(contract+150+abi,(usize)(362-abi)))return 0;
    char uname[390];if(tfb_syscall1(160,(long)uname)<0 || tfb_strlen(uname+130)!=abi || !tfb_altos_eq(uname+130,contract+150,(usize)abi) ||
        !tfb_kernel_live_id(contract+84,(unsigned)n))return 0;
    char slot=0;
    if(tfb_altos_read_small("/proc/bootconfig",text,sizeof(text))){
        if(tfb_kernel_contains(text,"androidboot.slot_suffix = \"_a\"\n"))slot='a';
        if(tfb_kernel_contains(text,"androidboot.slot_suffix = \"_b\"\n")){if(slot)return 0;slot='b';}}
    if(!slot && tfb_altos_read_small("/proc/cmdline",text,sizeof(text))){
        if(tfb_kernel_contains(text,"androidboot.slot_suffix=_a "))slot='a';
        if(tfb_kernel_contains(text,"androidboot.slot_suffix=_b ")){if(slot)return 0;slot='b';}}
    if(!slot)return 0;
    fd=tfb_kernel_boot_device(slot);if(fd<0)return 0;
    ok=tfb_kernel_hash_prefix(fd,length,hash)&&tfb_altos_eq(hash,contract+40,32);tfb_close(fd);if(!ok)return 0;
    if(!tfb_altos_read_small("/proc/sys/kernel/random/boot_id",text,sizeof(text)) || tfb_strlen(text)!=37 || text[36]!='\n')return 0;
    text[36]=0;const char *magic="TREEFORGE_UPDATED_KERNEL_V1\n";tfb_kernel_receipt_bytes=tfb_strlen(magic);memcpy(tfb_kernel_receipt,magic,tfb_kernel_receipt_bytes);
    ok=tfb_kernel_append("boot_id",text);tfb_altos_hex(text,contract+8,32);ok=ok&&tfb_kernel_append("provider_sha256",text);
    tfb_altos_hex(text,contract+40,32);ok=ok&&tfb_kernel_append("boot_payload_sha256",text);
    tfb_altos_hex(text,contract+84,(usize)n);ok=ok&&tfb_kernel_append("build_id",text);
    text[0]=slot;text[1]=0;ok=ok&&tfb_kernel_append("slot",text);
    ok=ok&&tfb_altos_hash(-1,contract,512,0,hash);tfb_altos_hex(text,hash,32);ok=ok&&tfb_kernel_append("contract_sha256",text);
    ok=ok&&tfb_kernel_append("storage_contract_sha256",TFB_ALTOS_ABI_SHA)&&tfb_kernel_append("image_admission_protocol","1");
    if(!ok)return 0;
    tfb_syscall3(35,AT_FDCWD,(long)TFB_KERNEL_TEMP,0);
    fd=tfb_syscall4(SYS_OPENAT,AT_FDCWD,(long)TFB_KERNEL_TEMP,O_WRONLY|O_CREAT|0200/*O_EXCL*/|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC,0600);
    if(fd<0)return 0;ok=tfb_write_bytes(fd,(unsigned char*)tfb_kernel_receipt,tfb_kernel_receipt_bytes);tfb_close(fd);
    if(ok)ok=tfb_syscall4(SYS_RENAMEAT,AT_FDCWD,(long)TFB_KERNEL_TEMP,AT_FDCWD,(long)TFB_KERNEL_RECEIPT)==0;
    if(!ok){tfb_syscall3(35,AT_FDCWD,(long)TFB_KERNEL_TEMP,0);return 0;}
    memcpy(tfb_kernel_provider,contract+8,32);return 1;
}
static void tfb_publish_kernel_proof(void) {
    tfb_log("TREEFORGE_KERNEL_PROOF_PRODUCER_V1");
    tfb_kernel_receipt_bytes=0;tfb_syscall3(35,AT_FDCWD,(long)TFB_KERNEL_RECEIPT,0);
    if(tfb_kernel_produce())tfb_log("current-boot-kernel-proof=verified");
    else {tfb_kernel_receipt_bytes=0;tfb_log("current-boot-kernel-proof=unavailable; menu/adb retained");}
}
static int tfb_kernel_receipt_matches(const unsigned char *provider) {
    if(!tfb_kernel_receipt_bytes || !tfb_altos_eq(provider,tfb_kernel_provider,32))return 0;
    long fd=tfb_open(TFB_KERNEL_RECEIPT,O_RDONLY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC|O_NONBLOCK);char text[1024],extra;
    if(fd<0)return 0;int ok=tfb_altos_private_file(fd,1023)&&tfb_read_exact(fd,(unsigned char*)text,tfb_kernel_receipt_bytes)&&
        tfb_syscall3(SYS_READ,fd,(long)&extra,1)==0&&tfb_altos_eq(text,tfb_kernel_receipt,tfb_kernel_receipt_bytes);tfb_close(fd);return ok;
}
