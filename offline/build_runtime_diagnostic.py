"""Build an A7CR read-only loaded-AP diagnostic, derived from upstream readers.

Only temporary result files are written. No firmware/settings/sysfs mutation.
Build output is separate from all already-installed payloads and manifests.
"""
from __future__ import annotations

import json
from elftools.elf.elffile import ELFFile

from build_native_workers import ROOT, UPSTREAM, compile_worker
from inspect_sources import save_json

OUT = ROOT / "private/runtime-diagnostic"
SPANS = (("converter", 0x3528CEC, 112), ("capabilities", 0x4B2F209, 2),
         ("FL2-menu", 0x59892C8, 2), ("FL3-menu", 0x5989380, 2),
         ("FL2-initial-binding", 0x4B4AB34, 4), ("FL3-initial-binding", 0x4B4AB3C, 4),
         ("FL2-Fade-default", 0x4B3BA94, 4), ("FL3-Fade-default", 0x4B3BA9C, 4))


def build():
    OUT.mkdir(parents=True, exist_ok=True)
    ap_path = ROOT / "private/install/20261020-a7cr-fl23-01/payload/candidate-AP.private.bin"
    spans = []
    with ap_path.open("rb") as stream:
        elf = ELFFile(stream)
        for name, offset, size in SPANS:
            segments = [seg for seg in elf.iter_segments() if seg["p_type"] == "PT_LOAD"
                        and seg["p_offset"] <= offset and offset+size <= seg["p_offset"]+seg["p_filesz"]]
            if len(segments) != 1:
                raise ValueError("Diagnostic window not in one file-backed ELF segment")
            seg = segments[0]
            spans.append({"name": name, "offset": offset, "bytes": size,
                          "virtual_offset": seg["p_vaddr"]+offset-seg["p_offset"]})
    # Reuse the audited proc reader/maps parser, excluding A7C II's numeric
    # model-index read entirely. Body identity is checked by the host first.
    probe = (UPSTREAM / "native/probe.c").read_text().replace("a7c2.", "a7cr.diag.")
    probe = "/* Derived MIT proc reader: AP mappings only; no numeric model probe. */\n"+probe[probe.index("*/")+2:]
    start = probe.index("static void find_model(void)")
    end = probe.index('__attribute__((visibility("default")))', start)
    probe = probe[:start]+"""static void find_mapping(void) {
    u32 begin=0,count=0;
    for(u32 i=0;i<report.maps_len;i++)if(maps[i]=='\\n') {
        u64 start,stop,offset;
        if(app_mapping(begin,i,&start,&stop,&offset) && !offset) {report.base=start;count++;}
        begin=i+1;
    }
    if(count!=1)report.status=-2;
}
"""+probe[end:]
    probe = probe.replace("report.index=0xffffffffU", "report.index=0")
    probe = probe.replace("find_model();", "if(report.euid)report.status=-13;else find_mapping();")
    probe = probe.replace("i64 n=read_all(\"/proc/self/maps\"", "if(report.cleanup)report.status=report.cleanup;\n    i64 n=read_all(\"/proc/self/maps\"")
    (OUT / "probe.c").write_text(probe)
    source = """/* Derived from QAQLeonard/a7c2-fl23-research native readers; MIT.
 * Read-only fixed A7CR spans. No settings, firmware, mount or WBI writes. */
#define _init probe_init
#include "probe.c"
#undef _init
struct Span {u64 file,va;u32 length;};
static const struct Span spans[]={SPANS};
struct Runtime {
    u8 magic[8];u32 version,count;i64 status,euid,pid;u64 base;
    u32 reserved0,reserved1;u8 data[8][2][128];
    u8 image_mode[16],image_dev[32],uptime[128],boot_id[64];
};
_Static_assert(sizeof(struct Runtime)==2344,"A7CR runtime ABI");
static struct Runtime runtime;
static int mapped(u64 address,u32 length,u64 file_offset) {
    u32 begin=0,count=0;
    for(u32 i=0;i<report.maps_len;i++)if(maps[i]=='\\n') {
        u64 start,stop,offset;
        if(app_mapping(begin,i,&start,&stop,&offset) && address>=start && address+length<=stop
           && address>=runtime.base && address-start+offset==file_offset)count++;
        begin=i+1;
    }
    return count==1;
}
static i64 exact_read(i64 fd,u8 *out,u32 size,u64 offset) {
    u32 done=0,retries=0;
    while(done<size) {
        i64 n=sc(67,fd,(i64)(out+done),size-done,offset+done,0,0);
        if(n==-4 && retries++<3)continue;
        if(n<=0 || (u64)n>size-done)return n<0?n:-5;
        done+=(u32)n;
    }
    return 0;
}
__attribute__((visibility("default"))) void _init(void) {
    probe_init();
    const u8 magic[]="A7CRR001";for(u32 i=0;i<8;i++)runtime.magic[i]=magic[i];
    runtime.version=1;runtime.count=8;runtime.status=report.status;runtime.euid=report.euid;
    runtime.pid=report.pid;runtime.base=report.base;
    if(report.cleanup&&!runtime.status)runtime.status=report.cleanup;
    if(!runtime.status) {
        i64 mem=op("/proc/self/mem",0),disk=op("/usr/lib/appFw.so",0);
        if(mem<0||disk<0)runtime.status=mem<0?mem:disk;
        else for(u32 i=0;i<8;i++) {
            u64 va=runtime.base+spans[i].va;
            if(!mapped(va,spans[i].length,spans[i].file)) {runtime.status=-14;break;}
            runtime.status=exact_read(mem,runtime.data[i][0],spans[i].length,va);
            if(runtime.status)break;
            runtime.status=exact_read(disk,runtime.data[i][1],spans[i].length,spans[i].file);
            if(runtime.status)break;
        }
        i64 c=mem>=0?sc(57,mem,0,0,0,0,0):0;if(c&&!runtime.status)runtime.status=c;
        c=disk>=0?sc(57,disk,0,0,0,0,0):0;if(c&&!runtime.status)runtime.status=c;
    }
    i64 n=read_all("/sys/power/image_mode",runtime.image_mode,sizeof(runtime.image_mode));
    if(n<0&&!runtime.status)runtime.status=n;
    n=read_all("/sys/power/image_dev",runtime.image_dev,sizeof(runtime.image_dev));
    if(n<0&&!runtime.status)runtime.status=n;
    n=read_all("/proc/uptime",runtime.uptime,sizeof(runtime.uptime));
    if(n<0&&!runtime.status)runtime.status=n;
    n=read_all("/proc/sys/kernel/random/boot_id",runtime.boot_id,sizeof(runtime.boot_id));
    if(n<0&&!runtime.status)runtime.status=n;
    i64 out=op("/tmp/jiritsu/a7cr.diag.runtime.result",0x241);
    if(out>=0) {write_all(out,&runtime,sizeof(runtime));sc(82,out,0,0,0,0,0);cl(out);}
}
"""
    entries = ",".join("{%dUL,%dUL,%d}" % (s["offset"], s["virtual_offset"], s["bytes"]) for s in spans)
    source = source.replace("{SPANS}", "{"+entries+"}")
    spec = compile_worker(OUT, "runtime-read-only", source)
    if b"/sys/power/image_drop" in (ROOT / spec["file"]).read_bytes():
        raise ValueError("Diagnostic unexpectedly includes a WBI mutation interface")
    result = {"schema": "a7cr-runtime-readonly-worker/1", "worker": spec, "spans": spans,
              "simulation_passed": False, "camera_executed": False,
              "writes_only_owned_temp_results": True, "persistent_camera_writes": False}
    save_json(OUT / "runtime.private.json", result)
    print(json.dumps({"bytes": spec["bytes"], "spans": len(spans), "persistent_camera_writes": False}, indent=2))


if __name__ == "__main__":
    build()
