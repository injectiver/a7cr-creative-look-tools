"""Read one fixed menu resource into an owned, one-byte-padded temp copy.

Original resources, programs, settings, mount and WBI state are never written.
The padding avoids a 512-byte terminal response in the existing Senser reader.
"""
from __future__ import annotations
import json
import sys
from build_native_workers import ROOT,compile_worker,array
from inspect_sources import save_json
sys.path.insert(0,str(ROOT/'device'))
from install_six_luts import Package

OUT=ROOT/'private/lut-install/six-20261020-01/resource-mirror'
FILE='string_croatian_vertical.uxc'


def build():
    p=Package();old,new=p.resources[FILE],p.named_resources[FILE]
    source=r'''/* Read-only source file; exclusively created owned temporary results. */
typedef unsigned long u64;typedef unsigned int u32;typedef long i64;typedef unsigned char u8;
static i64 sc(i64 n,i64 a,i64 b,i64 c,i64 d,i64 e,i64 f) {
 register i64 x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
 register i64 x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
 __asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
static i64 op(const char*p,i64 flags) {return sc(56,-100,(i64)p,flags,0600,0,0);}
static i64 cl(i64*f) {if(*f<0)return 0;i64 v=sc(57,*f,0,0,0,0,0);*f=-1;return v;}
static int same(const u8*a,const u8*b,u32 n) {for(u32 i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
#include "sha256.h"
struct Stat {u64 dev,ino;u32 mode,nlink,uid,gid;u64 rdev,pad1;i64 size;u32 blksize,pad2;u64 blocks,rest[7];};
struct Report {u8 magic[8];u32 version,reserved;i64 status,euid,pid,cleanup;u64 bytes,ino;u8 hash[32];};
_Static_assert(sizeof(struct Stat)==128,"stat ABI");
_Static_assert(sizeof(struct Report)==96,"mirror ABI");
static struct Report r;
static u8 data[524289];
static const u32 sizes[2]=SIZES;
static const u8 hashes[2][32]=HASHES;
static const char source_path[]="/usr/share/app/string_croatian_vertical.uxc";
static const char mirror_path[]="/tmp/jiritsu/a7cr.six.boundary.data";
static const char report_path[]="/tmp/jiritsu/a7cr.six.boundary.result";
static i64 write_all(i64 fd,const u8*p,u32 n) {
 u32 done=0,retry=0;while(done<n) {i64 v=sc(64,fd,(i64)(p+done),n-done,0,0,0);
  if(v==-4&&retry++<3)continue;if(v<=0||(u64)v>n-done)return v<0?v:-5;done+=(u32)v;}return 0;
}
static void work(void) {
 if(r.euid){r.status=-13;return;}
 i64 in=op(source_path,0x20000);if(in<0){r.status=in;return;}
 struct Stat s;r.status=sc(80,in,(i64)&s,0,0,0,0);u32 selected=2;
 if(!r.status) {
  for(u32 i=0;i<2;i++)if(s.size==sizes[i])selected=i;
  if((s.mode&0170000)!=0100000||s.uid!=57285||s.gid!=1000||!s.ino||selected>1)r.status=-22;
 }
 if(!r.status) {
  r.bytes=s.size;r.ino=s.ino;u32 done=0,retry=0;
  while(done<r.bytes) {i64 v=sc(67,in,(i64)(data+done),r.bytes-done,done,0,0);
   if(v==-4&&retry++<3)continue;if(v<=0||(u64)v>r.bytes-done){r.status=v<0?v:-5;break;}done+=(u32)v;}
  if(!r.status) {i64 v=sc(67,in,(i64)(data+r.bytes),1,r.bytes,0,0);if(v)r.status=v<0?v:-27;}
 }
 i64 c=cl(&in);if(!r.status)r.status=c;
 if(r.status)return;
 SHA256 h;sha_init(&h);sha_add(&h,data,r.bytes);sha_end(&h,r.hash);
 if(!same(r.hash,hashes[selected],32)){r.status=-84;return;}
 data[r.bytes]=0xa7;
 i64 out=op(mirror_path,0x200c1);if(out<0){r.status=out;return;}
 r.status=write_all(out,data,r.bytes+1);if(!r.status)r.status=sc(82,out,0,0,0,0,0);
 c=cl(&out);if(!r.status)r.status=c;
}
__attribute__((visibility("default"))) void _init(void) {
 for(u32 i=0;i<8;i++)r.magic[i]=((const u8*)"A7CRM001")[i];r.version=1;
 r.euid=sc(175,0,0,0,0,0,0);r.pid=sc(172,0,0,0,0,0,0);
 r.cleanup=sc(35,-100,(i64)"/tmp/jiritsu/libJit.so",0,0,0,0);
 if(r.cleanup)r.status=r.cleanup;else work();
 i64 out=op(report_path,0x200c1);
 if(out>=0) {write_all(out,(const u8*)&r,sizeof(r));sc(82,out,0,0,0,0,0);cl(&out);}
}
'''
    source=source.replace('SIZES','{'+str(len(old))+','+str(len(new))+'}')
    source=source.replace('HASHES','{'+array(bytes.fromhex(__import__('hashlib').sha256(old).hexdigest()))+','+array(bytes.fromhex(__import__('hashlib').sha256(new).hexdigest()))+'}')
    spec=compile_worker(OUT,'resource-read-only-mirror',source)
    if (spec['bytes']+4)%512==0:raise ValueError('Mirror module itself would hit the response boundary')
    save_json(OUT/'mirror.private.json',dict(schema='a7cr-resource-mirror/1',worker=spec,resource=FILE,
        source_sizes=[len(old),len(new)],simulation_passed=False,persistent_source_writes=False,
        appended_temp_byte=167,camera_executed=False))
    print(json.dumps(dict(bytes=spec['bytes'],source_resource=FILE,persistent_source_writes=False)))


if __name__=='__main__':build()
