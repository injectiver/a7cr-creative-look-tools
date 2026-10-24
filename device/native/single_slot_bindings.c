/* A7CR slot-1 native base synchronization. Derived from QAQLeonard's
 * a7c2-fl23-research v3.0.3 look_bindings.c (MIT); exact A7CR call graph
 * and guarded addresses are independently checked by offline/single_slot_runtime.py.
 * The read-only build has no native setter call path. No program, resources,
 * filesystem mounts or WBI writes; only owned temporary reports are written.
 */
#define _init slot_probe_init
#include "probe.c"
#undef _init
#include "patch_manifest.h"

struct SlotReport {
    u8 magic[8]; u32 version,mode; i64 status,pid; u64 base;
    u32 current,after_current,changed,reserved;
    u32 before[18],after[18]; u8 boot[64],reserved_tail[8];
};
static struct SlotReport output;
_Static_assert(sizeof(struct SlotReport)==272,"Slot report ABI");

static i64 read_mem(i64 fd,u64 at,void *buffer,u32 size) {
    i64 n=sc(67,fd,(i64)buffer,size,report.base+at,0,0);
    return n==size?0:(n<0?n:-5);
}

#if WRITE_ALLOWED
static i64 set_slot1(u32 value) {
    const u32 index=10,attribute=0x14f3;
    u64 context[2],lock;
    ((void(*)(void*))(report.base+0x178fa30))(context);
    ((void(*)(void*))(report.base+0x2e07118))(&lock);
    u32 *values=((u32*(*)(void))(report.base+0x287f1d4))();
    u8 *info=((u8*(*)(void))(report.base+0x287f1e8))();
    u32 current=*((u32*(*)(void))(report.base+0x2869a10))();
    if(values[index]!=EXPECTED_BEFORE || (REQUIRE_CURRENT_ST && current!=0)) {
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
    slot_probe_init();
    const u8 magic[]="A7CSB001";for(u32 i=0;i<8;i++)output.magic[i]=magic[i];
    output.version=1;output.mode=WRITE_ALLOWED;output.status=report.status;
    output.pid=report.pid;output.base=report.base;
    if(!output.status && (report.euid||report.cleanup))output.status=-13;
    i64 mem=-1;
    if(!output.status) {mem=op("/proc/self/mem",0);if(mem<0)output.status=mem;}
    for(u32 i=0;i<guard_count&&!output.status;i++) {
        u8 bytes[512];
        if(guards[i].size>sizeof(bytes)) {output.status=-22;break;}
        output.status=read_mem(mem,guards[i].at,bytes,guards[i].size);
        for(u32 j=0;j<guards[i].size&&!output.status;j++)
            if(bytes[j]!=guards[i].data[j])output.status=-84;
    }
    if(!output.status)output.status=read_mem(mem,0x7e70598,&output.current,4);
    if(!output.status)output.status=read_mem(mem,0x7eac508,output.before,72);
    for(u32 i=0;i<18&&!output.status;i++)if(output.before[i]>11)output.status=-22;
#if WRITE_ALLOWED
    if(!output.status && (output.before[10]!=EXPECTED_BEFORE ||
       (REQUIRE_CURRENT_ST && output.current!=0)))output.status=-116;
    if(!output.status && output.before[10]!=TARGET_BASE) {
        output.status=set_slot1(TARGET_BASE);
        if(!output.status)output.changed=1U<<10;
    }
#endif
    if(!output.status)output.status=read_mem(mem,0x7eac508,output.after,72);
    if(!output.status)output.status=read_mem(mem,0x7e70598,&output.after_current,4);
    if(!output.status && output.current!=output.after_current)output.status=-84;
    for(u32 i=0;i<18&&!output.status;i++) {
        u32 wanted=output.before[i];
#if WRITE_ALLOWED
        if(i==10)wanted=TARGET_BASE;
#endif
        if(output.after[i]!=wanted)output.status=-84;
    }
    cl(mem);
    i64 n=read_all("/proc/sys/kernel/random/boot_id",output.boot,sizeof(output.boot));
    if(n<0&&!output.status)output.status=n;
    i64 fd=op("/tmp/jiritsu/a7cr.slot1.bindings.result",0x241);
    if(fd>=0) {write_all(fd,&output,sizeof(output));sc(82,fd,0,0,0,0,0);cl(fd);}
}
