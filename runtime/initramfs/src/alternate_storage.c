/* TreeForge storage-v1 consumer. Included in the existing freestanding dispatcher.
 * Canonical ABI: contracts/storage-v1; no sibling checkout/runtime dependency.
 * Only boot-control records are writable here. Updated owns layout/root/STATE writes.
 */
#define TFB_ALTOS_ABI_SHA "7405a0c31ac315c16a6e6c2867b29766cc0f0bda3a9fbdbb4d4630e93a5ab28f"
#define TFB_ALTOS_CAP 40000028672ULL
#define TFB_ALTOS_ROOT 4294967296ULL
#define TFB_ALTOS_STATE 8590983168ULL
#define TFB_ALTOS_STATE_BYTES 31407996928ULL
#define TFB_ALTOS_FS_BYTES 31406948352ULL
#define TFB_ALTOS_NOFOLLOW 0100000 /* AArch64, not the host's fcntl ABI. */
#define TFB_ALTOS_CLOEXEC 02000000
#define TFB_ALTOS_CONTEXT "/dev/treeforge-altos/boot-context-v1"
#define TFB_ALTOS_ROOT_NODE "/dev/treeforge-altos-root"
#define TFB_ALTOS_STATE_NODE "/dev/treeforge-altos-state"
#define TFB_ALTOS_STATE_PROBE "/mnt/treeforge-altos-state"
#define TFB_ALTOS_ACK "unencrypted/preserve/treeforge/boot-success-v1"
static long tfb_altos_container=-1, tfb_altos_root_loop=-1, tfb_altos_state_loop=-1;
static unsigned char tfb_altos_head[36864],tfb_altos_tail[36864],tfb_altos_boot[4096],tfb_altos_initial[4096];
static unsigned char tfb_altos_outer[16],tfb_altos_disk[16];
static int tfb_altos_v1=0,tfb_altos_recognized=0,tfb_altos_selected=0,tfb_altos_trial=0,tfb_altos_context_owned=0;
static int tfb_altos_retry_confirmed=0;
static const char *tfb_altos_reason="storage-v1=not-inspected";

static u64 tfb_altos_le(const unsigned char *p,unsigned n) {
    u64 v=0;for(unsigned i=0;i<n;i++)v|=(u64)p[i]<<(8*i);return v;
}
static void tfb_altos_put(unsigned char *p,u64 v,unsigned n) {for(unsigned i=0;i<n;i++)p[i]=(unsigned char)(v>>(8*i));}
static int tfb_altos_eq(const void *x,const void *y,usize n) {return memcmp(x,y,n)==0;}
static int tfb_altos_zero(const unsigned char *p,usize n) {for(usize i=0;i<n;i++)if(p[i])return 0;return 1;}
static u32 tfb_altos_crc(const unsigned char *p,usize n,usize clear,usize count) {
    u32 c=~0U;for(usize i=0;i<n;i++){c^=(i>=clear && i-clear<count)?0:p[i];
        for(unsigned j=0;j<8;j++)c=(c>>1)^(0xedb88320U & (0U-(c&1U)));}return ~c;
}
static int tfb_altos_io(long fd,u64 offset,unsigned char *p,usize n,int write) {
    if(tfb_syscall3(SYS_LSEEK,fd,(long)offset,SEEK_SET)!=(long)offset)return 0;
    for(usize done=0;done<n;){long got=tfb_syscall3(write?SYS_WRITE:SYS_READ,fd,(long)(p+done),(long)(n-done));
        if(got==-4)continue;if(got<=0)return 0;done+=(usize)got;}return 1;
}
static void tfb_altos_hex(char *out,const unsigned char *p,usize n) {
    static const char h[]="0123456789abcdef";for(usize i=0;i<n;i++){out[2*i]=h[p[i]>>4];out[2*i+1]=h[p[i]&15];}out[2*n]=0;
}
static int tfb_altos_unhex(unsigned char *out,const char *p,usize n) {
    for(usize i=0;i<n;i++){unsigned v=0;for(unsigned j=0;j<2;j++){char c=p[2*i+j];
        if(c>='0'&&c<='9')v=(v<<4)+(unsigned)(c-'0');else if(c>='a'&&c<='f')v=(v<<4)+(unsigned)(c-'a'+10);else return 0;}out[i]=(unsigned char)v;}return 1;
}
static usize tfb_altos_decimal(char *out,u64 value) {
    char b[21];usize n=0;do{b[n++]=(char)('0'+value%10);value/=10;}while(value);
    for(usize i=0;i<n;i++)out[i]=b[n-i-1];out[n]=0;return n;
}
static int tfb_altos_number(const char *p,u64 *out) {
    if(!*p || (*p=='0' && p[1] && p[1]!='\n'))return 0;u64 v=0;usize n=0;
    while(*p && *p!='\n'){if(*p<'0'||*p>'9'||++n>20||v>(~0ULL-(unsigned)(*p-'0'))/10)return 0;v=v*10+(unsigned)(*p++-'0');}
    if(*p=='\n')p++;if(*p)return 0;*out=v;return 1;
}
static int tfb_altos_read_small(const char *path,char *p,usize cap) {
    long fd=tfb_open(path,O_RDONLY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC);if(fd<0)return 0;
    usize done=0;while(done+1<cap){long n=tfb_syscall3(SYS_READ,fd,(long)(p+done),(long)(cap-done-1));
        if(n==-4)continue;if(n<0){tfb_close(fd);return 0;}if(!n)break;done+=(usize)n;}
    char extra;long more=tfb_syscall3(SYS_READ,fd,(long)&extra,1);tfb_close(fd);p[done]=0;return done && more==0;
}
static int tfb_altos_sys_number(const char *path,u64 *v) {char p[64];return tfb_altos_read_small(path,p,sizeof(p))&&tfb_altos_number(p,v);}
/* AArch64 asm-generic stat ABI; no libc dependency. */
static int tfb_altos_private_file(long fd,u64 maximum) {
    unsigned char st[128];if(tfb_syscall2(80,fd,(long)st)<0)return 0;
    return (tfb_altos_le(st+16,4)&0170000)==0100000 && !(tfb_altos_le(st+16,4)&0077) &&
        tfb_altos_le(st+24,4)==0 && tfb_altos_le(st+20,4)==1 && tfb_altos_le(st+48,8)>0 && tfb_altos_le(st+48,8)<=maximum;
}
static int tfb_altos_device(long fd,u64 type,u64 device) {
    unsigned char st[128];return fd>=0 && tfb_syscall2(80,fd,(long)st)==0 &&
        (tfb_altos_le(st+16,4)&0170000)==type && tfb_altos_le(st+24,4)==0 && tfb_altos_le(st+32,8)==device;
}
static int tfb_altos_partition_device(long fd) {
    char dev[40];u64 major=0,minor=0;if(!tfb_altos_read_small("/sys/class/block/sda27/dev",dev,sizeof(dev)))return 0;
    char *colon=dev;while(*colon&&*colon!=':')colon++;if(*colon!=':')return 0;*colon++=0;
    return tfb_altos_number(dev,&major)&&tfb_altos_number(colon,&minor)&&major<=4095&&minor<=1048575&&
        tfb_altos_device(fd,0060000,(major<<8)|(minor&255)|((minor&~255ULL)<<12));
}
/* Use the already retained, verified BusyBox crypto applets. No shell or new tool. */
static int tfb_altos_hash(long input,const unsigned char *bytes,usize size,int sha1,unsigned char *result) {
    int output[2],feed[2]={-1,-1};if(tfb_syscall2(59,(long)output,TFB_ALTOS_CLOEXEC)<0)return 0;
    if(bytes && tfb_syscall2(59,(long)feed,TFB_ALTOS_CLOEXEC)<0){tfb_close(output[0]);tfb_close(output[1]);return 0;}
    long child=tfb_syscall6(SYS_CLONE,TREEFORGE_BOOTSTRAP_SIGCHLD,0,0,0,0,0);
    if(child==0){
        tfb_syscall3(SYS_DUP3,bytes?feed[0]:input,0,0);tfb_syscall3(SYS_DUP3,output[1],1,0);
        tfb_close(output[0]);tfb_close(output[1]);if(bytes){tfb_close(feed[0]);tfb_close(feed[1]);}
        char *argv[]={(char*)TFB_ALTROOT_LOADER_BUSYBOX,(char*)(sha1?"sha1sum":"sha256sum"),0};
        char *env[]={(char*)"PATH=/dev/treeforge-bootstrap-runtime/system/bin",0};
        tfb_syscall3(SYS_EXECVE,(long)argv[0],(long)argv,(long)env);tfb_syscall1(SYS_EXIT,127);for(;;){}
    }
    tfb_close(output[1]);int ok=child>0;
    if(bytes){tfb_close(feed[0]);if(ok)ok=tfb_write_bytes(feed[1],bytes,size);tfb_close(feed[1]);}
    if(child<0){tfb_close(output[0]);return 0;}
    char text[100];usize used=0;
    while(ok && used<sizeof(text)){long n=tfb_syscall3(SYS_READ,output[0],(long)(text+used),(long)(sizeof(text)-used));
        if(n==-4)continue;if(n<0){ok=0;break;}if(!n)break;used+=(usize)n;}
    tfb_close(output[0]);int status=0;long waited;
    do{waited=tfb_syscall4(SYS_WAIT4,child,(long)&status,0,0);}while(waited==-4 && child>0);
    usize hex=sha1?40:64;
    return ok && waited==child && status==0 && used==hex+4 && tfb_altos_eq(text+hex,"  -\n",4) && tfb_altos_unhex(result,text,hex/2);
}
static int tfb_altos_header(const unsigned char *h,const unsigned char *entries,usize count,u64 current,u64 other,u64 table,u64 first,u64 last) {
    return tfb_altos_eq(h,"EFI PART",8) && tfb_altos_le(h+8,4)==0x10000 && tfb_altos_le(h+12,4)==92 && !tfb_altos_le(h+20,4) &&
        tfb_altos_crc(h,92,16,4)==tfb_altos_le(h+16,4) && tfb_altos_le(h+24,8)==current && tfb_altos_le(h+32,8)==other &&
        tfb_altos_le(h+40,8)==first && tfb_altos_le(h+48,8)==last && tfb_altos_le(h+72,8)==table &&
        tfb_altos_le(h+80,4)==count && tfb_altos_le(h+84,4)==128 && tfb_altos_crc(entries,count*128,0,0)==tfb_altos_le(h+88,4);
}
static int tfb_altos_name(const unsigned char *p,const char *name) {
    usize length=tfb_strlen(name);for(unsigned i=0;i<36;i++)if(tfb_altos_le(p+56+2*i,2)!=(i<length?(unsigned char)name[i]:0))return 0;return 1;
}
static void tfb_altos_network_guid(unsigned char *out,const unsigned char *in) {
    static const unsigned order[]={3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};for(unsigned i=0;i<16;i++)out[i]=in[order[i]];
}
static int tfb_altos_outer_identity(void) {
    unsigned char p[4096],b[4096],e[3456],f[3456];u64 bytes=0;u32 sector=0;
    memset(p,0,sizeof(p));memset(b,0,sizeof(b));
    long fd=tfb_open("/dev/block/sda",O_RDONLY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC);if(fd<0)return 0;
    int ok=tfb_syscall3(SYS_IOCTL,fd,0x80081272,(long)&bytes)==0 && tfb_syscall3(SYS_IOCTL,fd,0x1268,(long)&sector)==0 &&
        sector==4096 && bytes>=16384 && bytes%4096==0 && bytes<0x7fffffffffffffffULL &&
        tfb_altos_io(fd,4096,p,4096,0) && tfb_altos_io(fd,bytes-4096,b,4096,0);
    u64 first=tfb_altos_le(p+40,8),last=tfb_altos_le(p+48,8),pt=tfb_altos_le(p+72,8),bt=tfb_altos_le(b+72,8);
    ok=ok && first>=3 && first<=last && last<bytes/4096-1 && pt>=2 && pt<first && bt>last && bt<bytes/4096-1 &&
        tfb_altos_io(fd,pt*4096,e,sizeof(e),0) && tfb_altos_io(fd,bt*4096,f,sizeof(f),0) && tfb_altos_eq(e,f,sizeof(e)) &&
        tfb_altos_header(p,e,27,1,bytes/4096-1,pt,first,last) && tfb_altos_header(b,f,27,bytes/4096-1,1,bt,first,last) && tfb_altos_eq(p+40,b+40,32);
    tfb_close(fd);if(!ok)return 0;
    const unsigned char type[16]={0xa1,0x30,0xfb,0xb9,0xb7,0x9e,0x9e,0x43,0x99,0xee,0x4c,0x5e,0x13,0x2d,0x0e,0x46};
    unsigned char *q=e+26*128;u64 begin=tfb_altos_le(q+32,8),end=tfb_altos_le(q+40,8),start=0,size=0,part=0;
    if(!tfb_altos_eq(q,type,16) || !tfb_altos_name(q,"treeforge_os") || tfb_altos_le(q+48,8) || begin<first || end>last || end<begin || end-begin+1!=TFB_ALTOS_CAP/4096)return 0;
    for(unsigned i=0;i<26;i++){unsigned char *v=e+i*128;if(tfb_altos_zero(v,16))continue;
        u64 x=tfb_altos_le(v+32,8),y=tfb_altos_le(v+40,8);if(y<x || !(y<begin || x>end))return 0;}
    unsigned char name[64],hash[20],unique[16];tfb_altos_network_guid(name,p+56);
    static const char label[]="pixel-partitioner:treeforge_os:v1";memcpy(name+16,label,sizeof(label)-1);
    if(tfb_altos_zero(name,16)||!tfb_altos_hash(-1,name,16+sizeof(label)-1,1,hash))return 0;
    hash[6]=(hash[6]&15)|0x50;hash[8]=(hash[8]&63)|0x80;tfb_altos_network_guid(unique,q+16);
    if(!tfb_altos_eq(unique,hash,16))return 0;
    if(!tfb_altos_sys_number("/sys/class/block/sda27/start",&start)||!tfb_altos_sys_number("/sys/class/block/sda27/size",&size)||
       !tfb_altos_sys_number("/sys/class/block/sda27/partition",&part)||part!=27||start!=begin*8||size!=TFB_ALTOS_CAP/512)return 0;
    memcpy(tfb_altos_outer,q+16,16);return 1;
}
static int tfb_altos_descriptor(const unsigned char *p) {
    return tfb_altos_eq(p,"TFALTOS\0",8) && tfb_altos_le(p+8,4)==1 && tfb_altos_le(p+12,4)==4096 && tfb_altos_le(p+16,8)==TFB_ALTOS_CAP &&
        tfb_altos_le(p+24,4)==4096 && !tfb_altos_le(p+28,4) && tfb_altos_eq(p+32,tfb_altos_disk,16) && tfb_altos_eq(p+48,tfb_altos_outer,16) &&
        tfb_altos_zero(p+64,60) && tfb_altos_zero(p+128,3968) && tfb_altos_crc(p,4096,124,4)==tfb_altos_le(p+124,4);
}
static int tfb_altos_layout(void) {
    static const unsigned char root_type[]={0xb2,0x62,0x48,0x2d,0x6b,0x64,0xb8,0x53,0x84,0x06,0x16,0x43,0x40,0xc3,0x68,0xff};
    static const unsigned char state_type[]={0x5c,0x40,0x18,0x86,0x01,0xd0,0xc9,0x51,0x87,0x0d,0x9e,0xa9,0x30,0x91,0x76,0xb5};
    const unsigned char *p=tfb_altos_head,*e=tfb_altos_head+8192,*b=tfb_altos_tail+32768,*f=tfb_altos_tail+16384;
    if(!tfb_altos_zero(p,446)||p[446]||p[450]!=0xee||tfb_altos_le(p+454,4)!=1||tfb_altos_le(p+458,4)!=TFB_ALTOS_CAP/4096-1||
       !tfb_altos_zero(p+462,48)||p[510]!=0x55||p[511]!=0xaa||!tfb_altos_zero(p+512,3584))return 0;
    if(!tfb_altos_header(p+4096,e,128,1,TFB_ALTOS_CAP/4096-1,2,256,(TFB_ALTOS_CAP-1048576)/4096-1)||
       !tfb_altos_header(b,f,128,TFB_ALTOS_CAP/4096-1,1,TFB_ALTOS_CAP/4096-5,256,(TFB_ALTOS_CAP-1048576)/4096-1)||
       !tfb_altos_zero(p+4096+92,4004)||!tfb_altos_zero(b+92,4004)||!tfb_altos_eq(e,f,16384)||!tfb_altos_eq(p+4096+56,b+56,16))return 0;
    memcpy(tfb_altos_disk,p+4096+56,16);if(tfb_altos_zero(tfb_altos_disk,16)||tfb_altos_eq(tfb_altos_disk,tfb_altos_outer,16))return 0;
    if(!tfb_altos_descriptor(p+32768)||!tfb_altos_descriptor(tfb_altos_tail+4096)||!tfb_altos_eq(p+32768,tfb_altos_tail+4096,4096))return 0;
    const char *names[]={"ROOT-A","ROOT-B","STATE"};
    for(unsigned i=0;i<3;i++){const unsigned char *v=e+i*128;u64 offset=1048576ULL+i*TFB_ALTOS_ROOT,bytes=i==2?TFB_ALTOS_STATE_BYTES:TFB_ALTOS_ROOT;
        if(!tfb_altos_eq(v,i==2?state_type:root_type,16)||!tfb_altos_name(v,names[i])||tfb_altos_le(v+48,8)||tfb_altos_zero(v+16,16)||
           tfb_altos_eq(v+16,tfb_altos_disk,16)||tfb_altos_eq(v+16,tfb_altos_outer,16)||tfb_altos_le(v+32,8)!=offset/4096||tfb_altos_le(v+40,8)!=(offset+bytes)/4096-1)return 0;
        for(unsigned j=0;j<i;j++)if(tfb_altos_eq(v+16,e+j*128+16,16))return 0;}
    return tfb_altos_zero(e+384,16384-384);
}
static int tfb_altos_token(const unsigned char *p,usize capacity) {
    usize end=0;while(end<capacity && p[end]){unsigned char c=p[end++];if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
        (c>='0'&&c<='9')||c=='.'||c=='_'||c=='-'||c=='+'))return 0;}
    return end && end<capacity && tfb_altos_zero(p+end,capacity-end);
}
static int tfb_altos_record(const unsigned char *p) {
    if(!tfb_altos_eq(p,"TFBOOT1\0",8)||tfb_altos_le(p+8,4)!=1||tfb_altos_le(p+12,4)!=4096||tfb_altos_crc(p,4096,4092,4)!=tfb_altos_le(p+4092,4)||
       !tfb_altos_le(p+16,8)||tfb_altos_le(p+16,8)>=~0ULL-4||!tfb_altos_eq(p+56,tfb_altos_disk,16)||!tfb_altos_eq(p+72,tfb_altos_outer,16)||tfb_altos_zero(p+88,16)||
       !tfb_altos_le(p+104,4)||tfb_altos_le(p+108,4)>2||tfb_altos_le(p+112,4)>2||tfb_altos_le(p+116,4)>3||tfb_altos_le(p+120,4)>1||
       !tfb_altos_zero(p+124,4)||!tfb_altos_zero(p+224,32)||!tfb_altos_zero(p+1280,4092-1280))return 0;
    for(unsigned i=0;i<2;i++){const unsigned char *v=p+256+i*512;u64 state=tfb_altos_le(v,4),bytes=tfb_altos_le(v+8,8);
        if(state>2||!tfb_altos_zero(v+4,4)||!tfb_altos_zero(v+216,296))return 0;
        if(!state){if(!tfb_altos_zero(v,512))return 0;continue;}
        if(bytes<2048||bytes>TFB_ALTOS_ROOT||tfb_altos_zero(v+16,32)||tfb_altos_zero(v+48,32)||tfb_altos_zero(v+80,32)||
           !tfb_altos_token(v+120,32)||!tfb_altos_token(v+152,64)||!tfb_altos_le(v+112,4)||tfb_altos_le(v+112,4)>tfb_altos_le(v+116,4))return 0;
        if(state==1 && (!tfb_altos_eq(v+80,p+160,32)||tfb_altos_le(v+112,4)>tfb_altos_le(p+104,4)||tfb_altos_le(v+116,4)<tfb_altos_le(p+104,4)))return 0;
    }
    u32 confirmed=(u32)tfb_altos_le(p+108,4),pending=(u32)tfb_altos_le(p+112,4),attempts=(u32)tfb_altos_le(p+116,4);
    if((confirmed && tfb_altos_le(p+256+(confirmed-1)*512,4)!=1)||(pending && (pending==confirmed||tfb_altos_le(p+256+(pending-1)*512,4)!=1)))return 0;
    if(pending ? (attempts==3?!tfb_altos_zero(p+128,32):tfb_altos_zero(p+128,32)) : (attempts || !tfb_altos_zero(p+128,32)))return 0;
    return !tfb_altos_le(p+120,4) || (!confirmed && !pending && tfb_altos_zero(p+256,1024));
}
static int tfb_altos_read_boot(void) {
    unsigned char first[4096],last[4096];if(!tfb_altos_io(tfb_altos_container,65536,first,4096,0)||!tfb_altos_io(tfb_altos_container,TFB_ALTOS_CAP-65536,last,4096,0))return 0;
    int x=tfb_altos_record(first),y=tfb_altos_record(last);if(!x&&!y)return 0;
    if(x&&y&&tfb_altos_le(first+16,8)==tfb_altos_le(last+16,8)&&!tfb_altos_eq(first,last,4096))return 0;
    memcpy(tfb_altos_boot,x&&(!y||tfb_altos_le(first+16,8)>=tfb_altos_le(last+16,8))?first:last,4096);memcpy(tfb_altos_initial,tfb_altos_boot,4096);return 1;
}
static int tfb_altos_commit(void) {
    /* Recheck the exact snapshot; never reset a concurrent/newer operation. */
    unsigned char check[4096],saved[4096],expected[4096];memcpy(saved,tfb_altos_boot,4096);memcpy(expected,tfb_altos_initial,4096);
    if(!tfb_altos_read_boot()||!tfb_altos_eq(tfb_altos_boot,expected,4096)){memcpy(tfb_altos_boot,saved,4096);return 0;}
    memcpy(tfb_altos_boot,saved,4096);tfb_altos_put(tfb_altos_boot+16,tfb_altos_le(tfb_altos_initial+16,8)+1,8);tfb_altos_put(tfb_altos_boot+4092,0,4);tfb_altos_put(tfb_altos_boot+4092,tfb_altos_crc(tfb_altos_boot,4096,0,0),4);
    if(!tfb_altos_record(tfb_altos_boot))return 0;
    for(unsigned i=0;i<2;i++){u64 offset=i?65536:TFB_ALTOS_CAP-65536;
        if(!tfb_altos_io(tfb_altos_container,offset,tfb_altos_boot,4096,1)||tfb_syscall1(SYS_FSYNC,tfb_altos_container)<0||
           !tfb_altos_io(tfb_altos_container,offset,check,4096,0)||!tfb_altos_eq(check,tfb_altos_boot,4096))return 0;}
    memcpy(tfb_altos_initial,tfb_altos_boot,4096);return 1;
}
static int tfb_altos_loop(const char *node,u64 offset,u64 bytes,int readonly) {
    char dev[40];u64 major=0,minor=0;if(!tfb_altos_read_small("/sys/class/misc/loop-control/dev",dev,sizeof(dev)))return -1;
    char *colon=dev;while(*colon&&*colon!=':')colon++;if(*colon!=':')return -1;*colon++=0;
    if(!tfb_altos_number(dev,&major)||!tfb_altos_number(colon,&minor)||major>4095||minor>1048575)return -1;
    const char *control="/dev/treeforge-altos-loop-control";
    long made=tfb_syscall4(SYS_MKNODAT,AT_FDCWD,(long)control,0020000|0600,(long)((major<<8)|(minor&255)|((minor&~255ULL)<<12)));
    if(made<0&&made!=-17)return -1;long ctl=tfb_open(control,O_RDWR|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC);
    if(!tfb_altos_device(ctl,0020000,(major<<8)|(minor&255)|((minor&~255ULL)<<12))){tfb_close(ctl);return -1;}
    long number=tfb_syscall3(SYS_IOCTL,ctl,0x4c82,0);tfb_close(ctl);if(number<0||number>1048575)return -1;
    /* Loop indices are not minors when the kernel reserves partition minors. */
    char path[64];static const char prefix[]="/sys/class/block/loop";
    memcpy(path,prefix,sizeof(prefix)-1);usize length=sizeof(prefix)-1;
    length+=tfb_altos_decimal(path+length,(u64)number);memcpy(path+length,"/dev",5);
    if(!tfb_altos_read_small(path,dev,sizeof(dev)))return -1;
    colon=dev;while(*colon&&*colon!=':')colon++;if(*colon!=':')return -1;*colon++=0;
    if(!tfb_altos_number(dev,&major)||!tfb_altos_number(colon,&minor)||major!=7||minor>1048575)return -1;
    /* Only Bootstrap-owned nodes are created. Refuse collisions instead of replacing them. */
    u64 device=(major<<8)|(minor&255)|((minor&~255ULL)<<12);
    if(tfb_syscall4(SYS_MKNODAT,AT_FDCWD,(long)node,0060000|0600,(long)device)<0)return -1;
    long loop=tfb_open(node,O_RDWR|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC);unsigned char config[304];memset(config,0,sizeof(config));
    tfb_altos_put(config,(u64)tfb_altos_container,4);tfb_altos_put(config+4,4096,4);tfb_altos_put(config+32,offset,8);tfb_altos_put(config+40,bytes,8);tfb_altos_put(config+60,4U|(readonly?1U:0U),4);
    if(!tfb_altos_device(loop,0060000,device)||tfb_syscall3(SYS_IOCTL,loop,0x4c0a,(long)config)<0){tfb_close(loop);tfb_syscall3(SYS_UNLINKAT,AT_FDCWD,(long)node,0);return -1;}
    unsigned char info[232];u64 observed=0;u32 sector=0,ro=0;
    if(tfb_syscall3(SYS_IOCTL,loop,0x4c05,(long)info)<0||tfb_altos_le(info+40,4)!=(u64)number||
       tfb_altos_le(info+24,8)!=offset||tfb_altos_le(info+32,8)!=bytes||
       (tfb_altos_le(info+52,4)&5)!=(u64)(4|(readonly?1:0))||tfb_syscall3(SYS_IOCTL,loop,0x80081272,(long)&observed)<0||observed!=bytes||
       tfb_syscall3(SYS_IOCTL,loop,0x1268,(long)&sector)<0||sector!=4096||tfb_syscall3(SYS_IOCTL,loop,0x125e,(long)&ro)<0||ro!=(u32)readonly){
        tfb_close(loop);tfb_syscall3(SYS_UNLINKAT,AT_FDCWD,(long)node,0);return -1;}
    return (int)loop;
}
static int tfb_altos_state_fs(void) {
    unsigned char s[1024];if(!tfb_altos_io(tfb_altos_container,TFB_ALTOS_STATE+1024,s,sizeof(s),0))return 0;
    u64 blocks=tfb_altos_le(s+4,4);if(tfb_altos_le(s+96,4)&0x80)blocks|=tfb_altos_le(s+336,4)<<32;
    return tfb_altos_le(s+56,2)==0xef53 && tfb_altos_le(s+24,4)==2 && blocks==TFB_ALTOS_FS_BYTES/4096 &&
        (tfb_altos_le(s+96,4)&0x10000) && tfb_altos_eq(s+104,tfb_altos_boot+88,16);
}
static usize tfb_altos_ack(char *text,const unsigned char *boot,unsigned selected) {
    char *p=text;static const char magic[]="TREEFORGE_BOOT_ACK_V1\ngeneration=";memcpy(p,magic,sizeof(magic)-1);p+=sizeof(magic)-1;
    p+=tfb_altos_decimal(p,tfb_altos_le(boot+16,8));memcpy(p,"\nslot=",6);p+=6;p+=tfb_altos_decimal(p,selected);
    const char *keys[]={"\ninstallation_id=","\nattempt_id=","\nimage_sha256=","\nkernel_sha256=","\ndisk_guid="};
    const unsigned char *values[]={boot+24,boot+128,boot+256+(selected-1)*512+16,boot+160,boot+56};
    for(unsigned i=0;i<5;i++){usize n=tfb_strlen(keys[i]);memcpy(p,keys[i],n);p+=n;tfb_altos_hex(p,values[i],i==4?16:32);p+=i==4?32:64;}
    *p++='\n';*p=0;return (usize)(p-text);
}
static long tfb_altos_ack_open(long state) {
    const char *dirs[]={"unencrypted","preserve","treeforge"};long parent=state,owned=-1;
    for(unsigned i=0;i<3;i++){long next=tfb_syscall4(SYS_OPENAT,parent,(long)dirs[i],O_RDONLY|O_DIRECTORY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC,0);
        tfb_close(owned);owned=next;if(next<0)return -1;
        /* Native preserve is root:preserve 0775. The root-only 0700 leaf and
         * private root-owned acknowledgement prevent group members forging it. */
        unsigned char st[128];if(tfb_syscall2(80,next,(long)st)<0||(tfb_altos_le(st+16,4)&0170000)!=0040000||tfb_altos_le(st+24,4)||
            (tfb_altos_le(st+16,4)&(i==1?0002:0022))||(i==2&&(tfb_altos_le(st+16,4)&0777)!=0700)){
            tfb_close(next);return -1;}parent=next;}
    long fd=tfb_syscall4(SYS_OPENAT,parent,(long)"boot-success-v1",O_RDONLY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC|O_NONBLOCK,0);tfb_close(owned);return fd;
}
static int tfb_altos_ack_matches(long state,const char *expected,usize length) {
    long fd=tfb_altos_ack_open(state);char text[1025];if(fd<0)return 0;
    int ok=tfb_altos_private_file(fd,1024)&&tfb_read_exact(fd,(unsigned char*)text,length);char extra;
    ok=ok&&tfb_syscall3(SYS_READ,fd,(long)&extra,1)==0&&tfb_altos_eq(text,expected,length);tfb_close(fd);return ok;
}
static int tfb_altos_kernel(void) {
    return tfb_kernel_receipt_matches(tfb_altos_boot+160);
}

static int tfb_altos_load(int write) {
    tfb_altos_reason="storage-v1=unavailable";tfb_altos_container=tfb_open("/dev/block/sda27",(write?O_RDWR:O_RDONLY)|0200|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC);
    u64 bytes=0;u32 sector=0;if(!tfb_altos_partition_device(tfb_altos_container)||tfb_syscall3(SYS_IOCTL,tfb_altos_container,0x80081272,(long)&bytes)<0||bytes!=TFB_ALTOS_CAP||
        tfb_syscall3(SYS_IOCTL,tfb_altos_container,0x1268,(long)&sector)<0||sector!=4096||!tfb_altos_io(tfb_altos_container,0,tfb_altos_head,sizeof(tfb_altos_head),0))return 0;
    if(!tfb_altos_io(tfb_altos_container,TFB_ALTOS_CAP-sizeof(tfb_altos_tail),tfb_altos_tail,sizeof(tfb_altos_tail),0))return 0;
    tfb_altos_recognized=tfb_altos_eq(tfb_altos_head+32768,"TFALTOS",7)||tfb_altos_eq(tfb_altos_head+4096,"EFI PART",8)||
        tfb_altos_eq(tfb_altos_tail+4096,"TFALTOS",7)||tfb_altos_eq(tfb_altos_tail+32768,"EFI PART",8)||
        (tfb_altos_head[450]==0xee&&tfb_altos_head[510]==0x55&&tfb_altos_head[511]==0xaa);
    /* Legacy raw ext4 is explicit. Corrupt/unknown v1 is never treated as legacy. */
    if(!tfb_altos_recognized && tfb_altos_le(tfb_altos_head+1080,2)==0xef53)return -1;
    tfb_altos_reason="storage-v1=invalid-layout";
    if(tfb_syscall2(32,tfb_altos_container,write?6:5)<0||!tfb_altos_outer_identity()||!tfb_altos_io(tfb_altos_container,TFB_ALTOS_CAP-sizeof(tfb_altos_tail),tfb_altos_tail,sizeof(tfb_altos_tail),0)||!tfb_altos_layout())return 0;
    tfb_altos_reason="storage-v1=invalid-boot-records";if(!tfb_altos_read_boot())return 0;
    tfb_altos_reason="storage-v1=initialization-incomplete";if(tfb_altos_le(tfb_altos_boot+120,4))return 0;
    unsigned pending=(unsigned)tfb_altos_le(tfb_altos_boot+112,4),confirmed=(unsigned)tfb_altos_le(tfb_altos_boot+108,4);
    tfb_altos_selected=pending?(int)pending:(int)confirmed;
    tfb_altos_reason="storage-v1=no-usable-root";if(!tfb_altos_selected)return 0;tfb_altos_v1=1;return 1;
}
static void tfb_altos_cleanup(void) {
    if(tfb_altos_v1){tfb_syscall2(SYS_UMOUNT2,(long)"/mnt/treeforge-altroot/mnt/stateful_partition",TFB_MNT_DETACH);
        tfb_syscall2(SYS_UMOUNT2,(long)TFB_ALTOS_STATE_PROBE,TFB_MNT_DETACH);}
    if(tfb_altos_root_loop>=0){tfb_close(tfb_altos_root_loop);tfb_syscall3(SYS_UNLINKAT,AT_FDCWD,(long)TFB_ALTOS_ROOT_NODE,0);}
    if(tfb_altos_state_loop>=0){tfb_close(tfb_altos_state_loop);tfb_syscall3(SYS_UNLINKAT,AT_FDCWD,(long)TFB_ALTOS_STATE_NODE,0);}
    tfb_close(tfb_altos_container);tfb_altos_container=tfb_altos_root_loop=tfb_altos_state_loop=-1;tfb_altos_v1=tfb_altos_recognized=0;tfb_altos_selected=tfb_altos_trial=0;
    if(tfb_altos_context_owned)tfb_syscall3(SYS_UNLINKAT,AT_FDCWD,(long)TFB_ALTOS_CONTEXT,0);tfb_altos_context_owned=0;
}
/* Probe never changes boot records, STATE, trial count or USB ownership. */
static int tfb_altos_probe(void) {
    int result=tfb_altos_load(0);if(result==1){
        tfb_altroot_identity_clear();const unsigned char *s=tfb_altos_boot+256+(tfb_altos_selected-1)*512;
        tfb_altroot_copy_literal(tfb_menu_state.alternate_os_detected_name,sizeof(tfb_menu_state.alternate_os_detected_name),(const char*)(s+120));
        tfb_altroot_copy_literal(tfb_menu_state.alternate_os_version,sizeof(tfb_menu_state.alternate_os_version),(const char*)(s+152));
        tfb_altroot_copy_literal(tfb_menu_state.alternate_os_build,sizeof(tfb_menu_state.alternate_os_build),tfb_altos_selected==1?"ROOT-A":"ROOT-B");}
    if(!result){tfb_log(tfb_altos_reason);if(tfb_altos_recognized){tfb_altroot_identity_clear();
        tfb_altroot_copy_literal(tfb_menu_state.alternate_os_detected_name,sizeof(tfb_menu_state.alternate_os_detected_name),"Alternate OS (recovery)");
        tfb_altroot_copy_literal(tfb_menu_state.alternate_os_build,sizeof(tfb_menu_state.alternate_os_build),"Storage recovery required");result=1;}}
    tfb_altos_cleanup();return result;
}
static int tfb_altos_verify_admission(void);
static int tfb_altos_confirm_health(void) {
    unsigned pending=(unsigned)tfb_altos_le(tfb_altos_boot+112,4);
    if(pending && tfb_altos_le(tfb_altos_boot+116,4)<3){
        char expected[1024];usize n=tfb_altos_ack(expected,tfb_altos_boot,pending);
        long state=tfb_open(TFB_ALTOS_STATE_PROBE,O_RDONLY|O_DIRECTORY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC);
        int success=state>=0&&tfb_altos_ack_matches(state,expected,n);tfb_close(state);
        if(success && tfb_altos_verify_admission()){
            tfb_altos_put(tfb_altos_boot+108,pending,4);tfb_altos_put(tfb_altos_boot+112,0,4);
            tfb_altos_put(tfb_altos_boot+116,0,4);memset(tfb_altos_boot+128,0,32);
            if(!tfb_altos_commit())return 0;
            tfb_log("storage-v1=previous-trial-confirmed");
        }
    }
    return 1;
}
/* Boot-lifecycle confirmation is separate from read-only Menu inventory. It
 * reconciles only an existing exact acknowledgement, never consumes a trial. */
static void tfb_altos_reconcile_health(void) {
    if(tfb_realize_block_nodes()!=0)return;
    int loaded=tfb_altos_load(1);
    if(loaded==1 && tfb_altos_le(tfb_altos_boot+112,4) && tfb_altos_le(tfb_altos_boot+116,4)<3 &&
       tfb_altos_kernel() && tfb_altos_state_fs()){
        tfb_altos_state_loop=tfb_altos_loop(TFB_ALTOS_STATE_NODE,TFB_ALTOS_STATE,TFB_ALTOS_STATE_BYTES,1);
        if(tfb_altos_state_loop>=0 && tfb_altroot_mkdir(TFB_ALTOS_STATE_PROBE,0700) &&
           tfb_altroot_mount(TFB_ALTOS_STATE_NODE,TFB_ALTOS_STATE_PROBE,"ext4",MS_RDONLY|2|4|8,"noload")>=0){
            if(!tfb_altos_confirm_health())tfb_log("storage-v1=health-confirmation-recovery-required");
        }
    }
    tfb_altos_cleanup();
}
static int tfb_altos_choose_root(void) {
    if(!tfb_altos_confirm_health())return 0;
    unsigned pending=(unsigned)tfb_altos_le(tfb_altos_boot+112,4),confirmed=(unsigned)tfb_altos_le(tfb_altos_boot+108,4);
    if(pending && !tfb_altos_le(tfb_altos_boot+116,4)){
        tfb_altos_put(tfb_altos_boot+256+(pending-1)*512,2,4);tfb_altos_put(tfb_altos_boot+112,0,4);memset(tfb_altos_boot+128,0,32);
        if(!tfb_altos_commit())return 0;pending=0;tfb_log("storage-v1=trials-exhausted");}
    tfb_altos_selected=pending?(int)pending:(int)confirmed;tfb_altos_trial=pending!=0;return tfb_altos_selected!=0;
}
static int tfb_altos_reject_pending(void) {
    if(!tfb_altos_v1||!tfb_altos_trial)return 0;
    tfb_altos_put(tfb_altos_boot+256+(tfb_altos_selected-1)*512,2,4);
    tfb_altos_put(tfb_altos_boot+112,0,4);tfb_altos_put(tfb_altos_boot+116,0,4);memset(tfb_altos_boot+128,0,32);
    if(!tfb_altos_commit())return 0;
    tfb_altos_retry_confirmed=tfb_altos_le(tfb_altos_boot+108,4)!=0;
    tfb_log("storage-v1=pending-root-rejected");return tfb_altos_retry_confirmed;
}
/* Signed root admission is checked before root mapping/pivot. The existing
 * Updated binary supplies its existing libcrypto through the retained linker;
 * this read-only command never enters an executor/storage mutation path.
 */
static int tfb_altos_verify_admission(void) {
    unsigned slot=(unsigned)tfb_altos_selected;unsigned char record[4096],hash[32];u64 count=0;int found=0;
    unsigned char *descriptor=tfb_altos_boot+256+(slot-1)*512;
    for(unsigned copy=0;copy<2;copy++){
        u64 offset=131072ULL+(u64)(slot-1)*4096;if(copy)offset=TFB_ALTOS_CAP-offset-4096;
        if(!tfb_altos_io(tfb_altos_container,offset,record,4096,0))continue;
        count=tfb_altos_le(record+12,4);
        if(!tfb_altos_eq(record,"TFIMG1\0",8)||tfb_altos_le(record+8,4)!=1||count==0||count>3072||
           tfb_altos_crc(record,4096,4092,4)!=tfb_altos_le(record+4092,4)||!tfb_altos_eq(record+16,descriptor+48,32))continue;
        if(tfb_altos_hash(-1,record+64,(usize)count,0,hash)&&tfb_altos_eq(hash,descriptor+48,32)){found=1;break;}
        count=0;
    }
    if(!found || !count || count>3072)return 0;
    /* Independently recheck the selected record after the loop, including when
     * neither copy passed its header/CRC checks. */
    if(!tfb_altos_eq(record,"TFIMG1\0",8)||tfb_altos_le(record+8,4)!=1||
       tfb_altos_crc(record,4096,4092,4)!=tfb_altos_le(record+4092,4)||
       !tfb_altos_hash(-1,record+64,(usize)count,0,hash)||!tfb_altos_eq(hash,descriptor+48,32))return 0;
    /* A failed early linker must not deliver SIGPIPE to the dispatcher. */
    int input[2];if(tfb_syscall4(199/*socketpair*/,1/*AF_UNIX*/,1|TFB_ALTOS_CLOEXEC,0,(long)input)<0)return 0;
    long child=tfb_syscall6(SYS_CLONE,TREEFORGE_BOOTSTRAP_SIGCHLD,0,0,0,0,0);
    if(child==0){
        if(tfb_syscall3(SYS_DUP3,input[0],0,0)<0)tfb_syscall1(SYS_EXIT,126);
        for(int fd=3;fd<1024;fd++)tfb_close(fd);
        char index[2]={(char)('0'+slot),0};
        char *argv[]={(char*)"/dev/treeforge-bootstrap-runtime/system/bin/linker64",
            (char*)"/system_ext/bin/treeforge-updated",(char*)"--verify-storage-admission",index,0};
        char *env[]={(char*)"PATH=/dev/treeforge-bootstrap-runtime/system/bin",
            (char*)"LD_LIBRARY_PATH=/dev/treeforge-bootstrap-runtime/system/lib64:/system_ext/lib64:/system/lib64",
            (char*)"ANDROID_ROOT=/dev/treeforge-bootstrap-runtime/system",0};
        tfb_syscall3(SYS_EXECVE,(long)argv[0],(long)argv,(long)env);tfb_syscall1(SYS_EXIT,127);for(;;){}
    }
    tfb_close(input[0]);if(child<0){tfb_close(input[1]);return 0;}
    unsigned char length[4];tfb_altos_put(length,count,4);
    unsigned char packet[7172];memcpy(packet,tfb_altos_boot,4096);memcpy(packet+4096,length,4);memcpy(packet+4100,record+64,(usize)count);
    usize sent=0,total=4100+(usize)count;int ok=1;
    while(sent<total){long wrote=tfb_syscall6(206/*sendto*/,input[1],(long)(packet+sent),total-sent,0x4000/*MSG_NOSIGNAL*/,0,0);
        if(wrote==-4)continue;if(wrote<=0){ok=0;break;}sent+=(usize)wrote;}
    tfb_close(input[1]);int status=0;long waited=0;
    for(unsigned wait=0;wait<1000;wait++){
        waited=tfb_syscall4(SYS_WAIT4,child,(long)&status,1,0);if(waited==child)return ok&&status==0;
        if(waited<0 && waited!=-4)return 0;tfb_sleep_ms(10);
    }
    tfb_syscall2(129,child,9);do{waited=tfb_syscall4(SYS_WAIT4,child,(long)&status,0,0);}while(waited==-4);return 0;
}

static int tfb_altos_prepare(void) {
    int result=tfb_altos_load(1);if(result!=1)return result;
    tfb_altos_reason="storage-v1=current-boot-kernel-verification-required";if(!tfb_altos_kernel())return 0;
    tfb_altos_reason="storage-v1=STATE-invalid";if(!tfb_altos_state_fs())return 0;
    tfb_altos_state_loop=tfb_altos_loop(TFB_ALTOS_STATE_NODE,TFB_ALTOS_STATE,TFB_ALTOS_STATE_BYTES,0);if(tfb_altos_state_loop<0)return 0;
    if(!tfb_altroot_mkdir(TFB_ALTOS_STATE_PROBE,0700)||tfb_altroot_mount(TFB_ALTOS_STATE_NODE,TFB_ALTOS_STATE_PROBE,"ext4",MS_RDONLY|2|4|8,"noload")<0)return 0;
    tfb_altos_reason="storage-v1=no-compatible-root";if(!tfb_altos_choose_root())return 0;
    tfb_syscall2(SYS_UMOUNT2,(long)TFB_ALTOS_STATE_PROBE,0);
    for(unsigned attempt=0;attempt<2;attempt++){
        unsigned char *slot=tfb_altos_boot+256+(tfb_altos_selected-1)*512;u64 bytes=tfb_altos_le(slot+8,8);
        tfb_altos_reason="storage-v1=Owner-image-admission-rejected";
        if(tfb_altos_verify_admission()){
        tfb_altos_reason="storage-v1=root-mapping-failed";if(bytes%4096)return 0;
        tfb_altos_root_loop=tfb_altos_loop(TFB_ALTOS_ROOT_NODE,1048576ULL+(u64)(tfb_altos_selected-1)*TFB_ALTOS_ROOT,bytes,1);if(tfb_altos_root_loop<0)return 0;
        unsigned char hash[32];tfb_altos_reason="storage-v1=root-hash-mismatch";
        if(!tfb_altos_hash(tfb_altos_root_loop,0,0,0,hash))return 0;
        if(tfb_altos_eq(hash,slot+16,32)){tfb_altos_reason="storage-v1=ready";return 1;}
        }
        if(!tfb_altos_trial)return 0;
        tfb_close(tfb_altos_root_loop);tfb_altos_root_loop=-1;tfb_syscall3(SYS_UNLINKAT,AT_FDCWD,(long)TFB_ALTOS_ROOT_NODE,0);
        tfb_altos_put(slot,2,4);tfb_altos_put(tfb_altos_boot+112,0,4);tfb_altos_put(tfb_altos_boot+116,0,4);memset(tfb_altos_boot+128,0,32);
        if(!tfb_altos_commit())return 0;tfb_altos_selected=(int)tfb_altos_le(tfb_altos_boot+108,4);tfb_altos_trial=0;if(!tfb_altos_selected)return 0;
        tfb_log("storage-v1=bad-pending-root-fallback");
    }return 0;
}
static int tfb_altos_mount_state(void) {
    if(!tfb_altos_v1)return 1;
    return tfb_altroot_mount(TFB_ALTOS_STATE_NODE,"/mnt/treeforge-altroot/mnt/stateful_partition","ext4",2|4|8,"errors=remount-ro")>=0;
}
static int tfb_altos_mountpoints(void) {
    const char *paths[]={"system/bin","dev","proc","sys","config","tmp",".oldroot","mnt/stateful_partition"};
    long root=tfb_open(TFB_ALTROOT_ROOT,O_RDONLY|O_DIRECTORY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC);if(root<0)return 0;
    for(unsigned i=0;i<sizeof(paths)/sizeof(paths[0]);i++){
        long current=root,owned=-1;usize start=0;
        for(usize end=0;;end++)if(paths[i][end]=='/'||!paths[i][end]){
            char name[64];usize n=end-start;if(!n||n>=sizeof(name)){tfb_close(owned);tfb_close(root);return 0;}
            memcpy(name,paths[i]+start,n);name[n]=0;
            long next=tfb_syscall4(SYS_OPENAT,current,(long)name,O_RDONLY|O_DIRECTORY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC,0);
            tfb_close(owned);owned=next;if(next<0){tfb_close(root);return 0;}current=next;
            if(!paths[i][end])break;start=end+1;
        }
        tfb_close(owned);
    }
    tfb_close(root);return 1;
}
static int tfb_altos_context(void) {
    char text[2048],value[65];char *p=text;const unsigned char *slot=tfb_altos_boot+256+(tfb_altos_selected-1)*512;
    const char *magic="TREEFORGE_ALTOS_BOOT_V1\n";usize n=tfb_strlen(magic);memcpy(p,magic,n);p+=n;
    memcpy(p,"contract_sha256=",16);p+=16;memcpy(p,TFB_ALTOS_ABI_SHA,64);p+=64;*p++='\n';
    char boot_id[64];if(!tfb_altos_read_small("/proc/sys/kernel/random/boot_id",boot_id,sizeof(boot_id))||tfb_strlen(boot_id)!=37)return 0;
    memcpy(p,"boot_id=",8);p+=8;memcpy(p,boot_id,37);p+=37;
    const char *keys[]={"generation=","slot=","trial=","state_schema=","image_bytes="};
    u64 numbers[]={tfb_altos_le(tfb_altos_boot+16,8),(u64)tfb_altos_selected,(u64)tfb_altos_trial,tfb_altos_le(tfb_altos_boot+104,4),tfb_altos_le(slot+8,8)};
    for(unsigned i=0;i<5;i++){n=tfb_strlen(keys[i]);memcpy(p,keys[i],n);p+=n;p+=tfb_altos_decimal(p,numbers[i]);*p++='\n';}
    const char *names[]={"installation_id=","attempt_id=","image_sha256=","kernel_sha256=","disk_guid=","outer_guid=","state_uuid="};
    const unsigned char *values[]={tfb_altos_boot+24,tfb_altos_boot+128,slot+16,tfb_altos_boot+160,tfb_altos_boot+56,tfb_altos_boot+72,tfb_altos_boot+88};
    for(unsigned i=0;i<7;i++){n=tfb_strlen(names[i]);memcpy(p,names[i],n);p+=n;tfb_altos_hex(value,values[i],i<4?32:16);n=tfb_strlen(value);memcpy(p,value,n);p+=n;*p++='\n';}
    *p=0;
    long made=tfb_syscall3(SYS_MKDIRAT,AT_FDCWD,(long)"/dev/treeforge-altos",0700);
    if(made<0&&made!=-17)return 0;
    long directory=tfb_open("/dev/treeforge-altos",O_RDONLY|O_DIRECTORY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC);unsigned char st[128];
    if(directory<0||tfb_syscall2(80,directory,(long)st)<0||(tfb_altos_le(st+16,4)&0177777)!=(0040000|0700)||tfb_altos_le(st+24,4)){
        tfb_close(directory);return 0;}
    long fd=tfb_syscall4(SYS_OPENAT,directory,(long)"boot-context-v1",O_WRONLY|O_CREAT|0200|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC,0600);
    tfb_close(directory);
    if(fd<0)return 0;tfb_altos_context_owned=1;int ok=tfb_write_bytes(fd,(unsigned char*)text,(usize)(p-text))&&tfb_syscall1(SYS_FSYNC,fd)==0;tfb_close(fd);return ok;
}
static int tfb_altos_diagnostic_hold(void) {
    static const char expected[]="TREEFORGE_ALTOS_DIAGNOSTIC_HOLD_V1\n";
    long fd=tfb_open("/dev/treeforge-altos/hold-trial-reboot",O_RDONLY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC|O_NONBLOCK);
    if(fd<0)return 0;unsigned char text[sizeof(expected)];
    int ok=tfb_altos_private_file(fd,sizeof(expected)-1)&&tfb_read_exact(fd,text,sizeof(expected)-1);char extra;
    ok=ok&&tfb_syscall3(SYS_READ,fd,(long)&extra,1)==0&&tfb_altos_eq(text,expected,sizeof(expected)-1);tfb_close(fd);return ok;
}
/* A userspace deadline is armed only for a pending trial. It retains the STATE
 * directory descriptor and the existing ADB processes; it never reconfigures USB.
 * Kernel-wide hangs still require hardware watchdog qualification separately.
 */
static int tfb_altos_guardian(void) {
    long state=tfb_open("/mnt/treeforge-altroot/mnt/stateful_partition",O_RDONLY|O_DIRECTORY|TFB_ALTOS_NOFOLLOW|TFB_ALTOS_CLOEXEC);
    if(state<0)return 0;char expected[1024];usize length=tfb_altos_ack(expected,tfb_altos_boot,(unsigned)tfb_altos_selected);
    long child=tfb_syscall6(SYS_CLONE,TREEFORGE_BOOTSTRAP_SIGCHLD,0,0,0,0,0);
    if(child==0){
        tfb_close(tfb_altos_container);tfb_close(tfb_altos_root_loop);tfb_close(tfb_altos_state_loop);
        struct {long seconds,nanoseconds;} now,begin;
        if(tfb_syscall2(113,7,(long)&begin)<0)tfb_syscall1(SYS_EXIT,127);
        int held=0;
        for(;;){if(tfb_altos_ack_matches(state,expected,length)){tfb_log("storage-v1=trial-health-received");tfb_syscall1(SYS_EXIT,0);}
            if(tfb_syscall2(113,7,(long)&now)<0)break;
            if(now.seconds-begin.seconds>=300){
                if(!tfb_altos_diagnostic_hold())break;
                if(!held){tfb_log("storage-v1=trial-reboot-held-for-diagnostics");held=1;}
            }
            tfb_sleep_ms(1000);}
        tfb_log("storage-v1=trial-deadline-expired");tfb_syscall1(SYS_SYNC,0);
        tfb_syscall4(SYS_REBOOT,LINUX_REBOOT_MAGIC1,LINUX_REBOOT_MAGIC2,LINUX_REBOOT_CMD_RESTART,0);
        /* A failed reboot leaves ADB available, rather than tearing down USB. */
        for(;;)tfb_sleep_ms(1000);
    }
    tfb_close(state);return child>0;
}
static int tfb_altos_begin(void) {
    if(!tfb_altos_v1)return 1;
    if(tfb_altos_trial){unsigned char random[32];usize done=0;
        while(done<32){long n=tfb_syscall3(278,(long)(random+done),(long)(32-done),0);if(n==-4)continue;if(n<=0)return 0;done+=(usize)n;}
        if(tfb_altos_zero(random,32))return 0;tfb_altos_put(tfb_altos_boot+116,tfb_altos_le(tfb_altos_boot+116,4)-1,4);memcpy(tfb_altos_boot+128,random,32);
        if(!tfb_altos_commit())return 0;}
    if(!tfb_altos_context()||(tfb_altos_trial&&!tfb_altos_guardian()))return 0;
    tfb_log(tfb_altos_selected==1?"storage-v1=handoff-ROOT-A":"storage-v1=handoff-ROOT-B");return 1;
}
