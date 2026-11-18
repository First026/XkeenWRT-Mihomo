/* Diagnostic only: fixed validator cleanup through the frozen clone3/execveat sequence.
 * Must only run inside the marked no-NIC disposable guest. No libc or host mounts. */
typedef unsigned long u64;
static long call(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10")=d, r8 __asm__("r8")=e, r9 __asm__("r9")=f, out;
    __asm__ volatile("syscall" : "=a"(out) : "a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9) : "rcx","r11","memory"); return out;
}
static int contains(const char *s, int n, const char *v) {
    for (int i=0;i<n;i++) { int j=0; while (v[j] && i+j<n && s[i+j]==v[j]) j++; if (!v[j]) return 1; } return 0;
}
static int marked(const char *path,const char *needle) {
    char b[4096]; long fd=call(257,-100,(long)path,0x80000,0,0,0); if(fd<0)return 0;
    long n=call(0,fd,(long)b,sizeof(b),0,0,0); call(3,fd,0,0,0,0,0); return n>0 && contains(b,n,needle);
}
static void out(const char *s) { int n=0;while(s[n])n++;call(1,1,(long)s,n,0,0,0); }
struct clone_args { u64 flags,pidfd,child_tid,parent_tid,exit_signal,stack,stack_size,tls,set_tid,set_tid_size,cgroup; };
static void run(long argc,char **argv) {
    if(argc!=2 || !marked("/proc/cmdline","xkeenwrt.isolation_lab=1") || !marked("/etc/xkeenwrt-isolation-lab","xkeenwrt-validator-lab-v1\n")) { out("DIAG_CLONE=GUARD\n");return; }
    const char *p=argv[1], *prefix="/sys/fs/cgroup/xkeenwrt/incarnations/"; int i=0;
    for(;prefix[i];i++)if(p[i]!=prefix[i]) {out("DIAG_CLONE=PATH\n");return;}
    for(int j=i;p[j];j++)if(j>240 || !((p[j]>='0'&&p[j]<='9')||(p[j]>='a'&&p[j]<='f')||p[j]=='-')) {out("DIAG_CLONE=PATH\n");return;}
    long cg=call(257,-100,(long)p,0xb0000,0,0,0);
    long exe=call(257,-100,(long)"/usr/libexec/xkeenwrt/xkeenwrt-validate",0xa0000,0,0,0);
    long null=call(257,-100,(long)"/dev/null",0x80002,0,0,0);
    long output=call(257,-100,(long)"/tmp/xk-fd-clone-result",0xa00c1,0600,0,0);
    if(cg<0||exe<0||null<0||output<0) {out("DIAG_CLONE=OPEN\n");return;}
    long parent=call(39,0,0,0,0,0,0);
    struct clone_args ca={.flags=0x200000000UL,.exit_signal=17,.cgroup=(u64)cg};
    long pid=call(435,(long)&ca,sizeof(ca),0,0,0,0);
    if(pid<0) { if(pid==-38)out("DIAG_CLONE=ENOSYS\n");else if(pid==-1)out("DIAG_CLONE=EPERM\n");else if(pid==-22)out("DIAG_CLONE=EINVAL\n");else out("DIAG_CLONE=CLONE_ERROR\n");return; }
    if(!pid) {
        if(call(109,0,0,0,0,0,0)||call(157,1,9,0,0,0,0)||call(110,0,0,0,0,0,0)!=parent)call(60,126,0,0,0,0,0);
        if(call(33,null,0,0,0,0,0)<0||call(33,output,1,0,0,0,0)<0||call(33,null,2,0,0,0,0)<0||call(33,exe,3,0,0,0,0)<0||call(72,3,2,1,0,0,0)<0)call(60,126,0,0,0,0,0);
        struct {u64 cur,max;} limit={16777216,16777216};
        if(call(160,1,(long)&limit,0,0,0,0)||call(436,4,~0U,0,0,0,0))call(60,126,0,0,0,0,0);
        char *a[]={"xkeenwrt-verified-elf","--cleanup",0};char *env[]={"PATH=/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL=C",0};
        call(322,3,(long)"",(long)a,(long)env,0x1000,0);call(60,127,0,0,0,0,0);
    }
    int status=0; if(call(61,pid,(long)&status,0,0,0,0)<0)out("DIAG_CLONE=WAIT\n");
    else if(status==0)out("DIAG_CLONE=EXIT_0\n");else if(status==(126<<8))out("DIAG_CLONE=CHILD_SETUP\n");else if(status==(127<<8))out("DIAG_CLONE=EXEC\n");else out("DIAG_CLONE=CHILD_OTHER\n");
}
__attribute__((noreturn)) void entry(long *stack) { run(stack[0],(char **)(stack+1));call(60,0,0,0,0,0,0);__builtin_unreachable(); }
__asm__(".global _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call entry\n");
