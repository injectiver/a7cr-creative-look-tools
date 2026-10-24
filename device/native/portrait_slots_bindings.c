/* A7CR portrait slots 2/3 only. Derived from QAQLeonard's MIT native menu
 * synchronization sequence and separately audited current-CC A7CR functions.
 * No raw flash, firmware, resource, mount or WBI writes. Each compiled writer
 * changes one selected native base under locks/CAS, requiring global ST.
 */
#define _init portrait_proc_init
#include "probe.c"
#undef _init
#include "patch_manifest.h"

struct PortraitReport {
    u8 magic[8];u32 version,mode;i64 status,pid;u64 base;
    u32 current,after_current,changed,reserved;
    u32 before[18],after[18];u8 boot[64],reserved_tail[8];
};
static struct PortraitReport output;
_Static_assert(sizeof(struct PortraitReport)==272,"Portrait native report ABI");

static i64 read_mem(i64 fd,u64 at,void *buffer,u32 n) {
    i64 got=sc(67,fd,(i64)buffer,n,report.base+at,0,0);
    return got==n?0:(got<0?got:-5);
}

#if WRITE_ALLOWED
_Static_assert((SELECTED_SLOT==2 && SELECTED_INDEX==11)||(SELECTED_SLOT==3 && SELECTED_INDEX==12),"Only new portrait slots");
static i64 sync_selected(u32 value) {
    const u32 index=SELECTED_INDEX,attribute=0x14e9+SELECTED_INDEX;
    u64 context[2],lock;
    ((void(*)(void*))(report.base+0x178fa30))(context);
    ((void(*)(void*))(report.base+0x2e07118))(&lock);
    u32 *values=((u32*(*)(void))(report.base+0x287f1d4))();
    u8 *info=((u8*(*)(void))(report.base+0x287f1e8))();
    u32 current=*((u32*(*)(void))(report.base+0x2869a10))();
    if(values[index]!=EXPECTED_BEFORE || current!=0) {
        ((void(*)(void*))(report.base+0x2e06d24))(&lock);
        ((void(*)(void*))(report.base+0x178fa54))(context);
        return -116;
    }
    u32 *backing=*(u32**)(info+40UL*index+8);
    ((void(*)(u64,u32,void*,const void*,u64))(report.base+0x3683590))(
        context[1],attribute,backing?backing:values+index,&value,4);
    if(backing)*backing=value;
    values[index]=value;
    ((void(*)(u32))(report.base+0x25071b4))(attribute);
    ((void(*)(void*))(report.base+0x2e06d24))(&lock);
    ((void(*)(void*))(report.base+0x178fa54))(context);
    ((void(*)(u32))(report.base+0x25063dc))(0x14e9);
    return 0;
}
#endif

__attribute__((visibility("default"))) void _init(void) {
    portrait_proc_init();
    const u8 magic[]="A7CPR001";for(u32 i=0;i<8;i++)output.magic[i]=magic[i];
    output.version=1;output.mode=WRITE_ALLOWED;output.status=report.status;
    output.pid=report.pid;output.base=report.base;
    if(!output.status && (report.euid||report.cleanup))output.status=-13;
    i64 mem=-1;
    if(!output.status) {mem=op("/proc/self/mem",0);if(mem<0)output.status=mem;}
    for(u32 i=0;i<guard_count&&!output.status;i++) {
        u8 bytes[512];
        if(guards[i].size>sizeof(bytes)) {output.status=-22;break;}
        output.status=read_mem(mem,guards[i].at,bytes,guards[i].size);
        for(u32 j=0;j<guards[i].size&&!output.status;j++)if(bytes[j]!=guards[i].data[j])output.status=-84;
    }
    if(!output.status)output.status=read_mem(mem,0x7e70598,&output.current,4);
    if(!output.status && output.current>17)output.status=-22;
    if(!output.status)output.status=read_mem(mem,0x7eac508,output.before,72);
    for(u32 i=0;i<18&&!output.status;i++)if(output.before[i]>11)output.status=-22;
#if WRITE_ALLOWED
    if(!output.status && (output.before[SELECTED_INDEX]!=EXPECTED_BEFORE || output.current!=0))output.status=-116;
    if(!output.status && output.before[SELECTED_INDEX]!=TARGET_BASE) {
        output.status=sync_selected(TARGET_BASE);
        if(!output.status)output.changed=1U<<SELECTED_INDEX;
    }
#endif
    if(!output.status)output.status=read_mem(mem,0x7eac508,output.after,72);
    if(!output.status)output.status=read_mem(mem,0x7e70598,&output.after_current,4);
    if(!output.status && output.current!=output.after_current)output.status=-84;
    for(u32 i=0;i<18&&!output.status;i++) {
        u32 wanted=output.before[i];
#if WRITE_ALLOWED
        if(i==SELECTED_INDEX)wanted=TARGET_BASE;
#endif
        if(output.after[i]!=wanted)output.status=-84;
    }
    cl(mem);
    i64 n=read_all("/proc/sys/kernel/random/boot_id",output.boot,sizeof(output.boot));
    if(n<0&&!output.status)output.status=n;
    i64 fd=op("/tmp/jiritsu/a7cr.portrait.bindings.result",0x241);
    if(fd>=0) {write_all(fd,&output,sizeof(output));sc(82,fd,0,0,0,0,0);cl(fd);}
}
