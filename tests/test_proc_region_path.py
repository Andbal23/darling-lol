"""Checks for proc_info region-path unexpansion, zero-init, and return sizes."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import test_runtime_compatibility as sources

ROOT = Path(__file__).resolve().parents[1]
PROC_INFO_PATH = 'darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/misc/proc_info.c'


class ProcRegionPathTests(unittest.TestCase):
    def test_patch_unexpands_and_shares_region_helper(self):
        patch = (ROOT / 'patches/xnu.patch').read_text()
        self.assertIn(f'diff --git a/{PROC_INFO_PATH} b/{PROC_INFO_PATH}', patch)
        self.assertIn('find_region_mapping', patch)
        self.assertIn('proc_unexpand_region_path', patch)
        self.assertIn('PROC_PIDREGIONPATHINFO2', patch)
        self.assertIn('PROC_PIDREGIONPATHINFO3', patch)

    @unittest.skipUnless(shutil.which('cc') and shutil.which('patch'), 'C compiler and patch required')
    def test_regionpathinfo_and_regionpath_behavior(self):
        helper = sources.CompatibilityChecks()
        helper.setUp = lambda: None
        src = helper.patched('xnu', PROC_INFO_PATH)

        fn_setup = sources.function(src, '_proc_pidinfo_regionpath_setup')
        fn_unexpand = sources.function(src, 'proc_unexpand_region_path')
        fn_find = sources.function(src, 'find_region_mapping')
        fn_rpi = sources.function(src, '_proc_pidinfo_regionpathinfo')
        fn_rp = sources.function(src, '_proc_pidinfo_regionpath')
        fn_parse = sources.function(src, 'parse_smaps_firstline')

        smaps_sample = (
            "1000-2000 r-xp 00001000 08:01 101 /mock-prefix/Applications/Client.app/Client\n"
            "Size: 4 kB\n"
            "2000-3000 rw-p 00000000 00:00 0 \n"
            "Size: 4 kB\n"
            "3000-4000 rw-p 00000000 00:00 0 [stack]\n"
            "4000-5000 r-xp 00000000 08:02 202 /mock-sdk/System/Library/Frameworks/Core.framework/Core\n"
            "5000-6000 r-xp 00000000 08:03 303 /usr/lib64/host-only.so\n"
        )

        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            smaps_file = base / 'smaps'
            smaps_file.write_text(smaps_sample)

            harness = base / 'check_region.c'
            harness.write_text(f"""
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXPATHLEN 1024
#define BSD_O_RDONLY O_RDONLY
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define SM_PRIVATE 2
#define SM_SHARED 4

struct vchroot_unexpand_args {{ char path[4096]; }};
static int vchroot_unexpand(struct vchroot_unexpand_args* args) {{
    if (strncmp(args->path, "/mock-prefix/", 13) == 0) {{
        memmove(args->path, args->path + 12, strlen(args->path + 12) + 1);
        return 0;
    }}
    if (strncmp(args->path, "/mock-sdk/", 10) == 0) {{
        memmove(args->path, args->path + 9, strlen(args->path + 9) + 1);
        return 0;
    }}
    const char exit_path[] = "/Volumes/SystemRoot";
    size_t len = strlen(args->path);
    memmove(args->path + sizeof(exit_path) - 1, args->path, len + 1);
    memcpy(args->path, exit_path, sizeof(exit_path) - 1);
    return 0;
}}

struct vinfo_stat {{ uint32_t vst_dev; uint64_t vst_ino; }};
struct vnode_info {{ struct vinfo_stat vi_stat; }};
struct vnode_info_path {{ struct vnode_info vip_vi; char vip_path[MAXPATHLEN]; }};
struct proc_regioninfo {{
    uint32_t pri_protection;
    uint32_t pri_share_mode;
    uint64_t pri_offset;
    uint64_t pri_address;
    uint64_t pri_size;
}};
struct proc_regionwithpathinfo {{
    struct proc_regioninfo prp_prinfo;
    struct vnode_info_path prp_vip;
}};
struct proc_regionpath {{
    uint64_t prpo_addr;
    uint64_t prpo_regionlength;
    char prpo_path[MAXPATHLEN];
}};

struct rdline_buffer {{
    char data[8192];
    size_t pos;
    size_t len;
}};
static void _readline_init(struct rdline_buffer* b) {{
    memset(b, 0, sizeof(*b));
}}
static const char* _readline(int fd, struct rdline_buffer* b) {{
    if (b->len == 0) {{
        ssize_t n = read(fd, b->data, sizeof(b->data) - 1);
        if (n <= 0) return NULL;
        b->data[n] = '\\0';
        b->len = (size_t)n;
        b->pos = 0;
    }}
    if (b->pos >= b->len)
        return NULL;
    char* line = b->data + b->pos;
    char* nl = strchr(line, '\\n');
    if (nl) {{
        *nl = '\\0';
        b->pos = (size_t)(nl - b->data) + 1;
    }} else {{
        b->pos = b->len;
    }}
    return line;
}}
static unsigned long long __simple_atoi(const char* s, const char** endp) {{
    char* end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (endp) *endp = end;
    return v;
}}
static unsigned long long __simple_atoi16(const char* s, const char** endp) {{
    char* end = NULL;
    unsigned long long v = strtoull(s, &end, 16);
    if (endp) *endp = end;
    return v;
}}
static int __simple_sprintf(char* dst, const char* fmt, ...) {{
    (void)fmt;
    strcpy(dst, "{smaps_file}");
    return (int)strlen(dst);
}}
static long sys_open_nocancel(const char* path, int flags, unsigned int mode) {{
    (void)mode;
    int fd = open(path, flags);
    return fd < 0 ? -errno : fd;
}}
static int close_internal(int fd) {{ return close(fd); }}

static bool parse_smaps_firstline(
    const char* line, uint64_t* pri_address, uint64_t* pri_size,
    uint32_t* pri_protection, uint32_t* pri_share_mode, uint64_t* pri_offset,
    uint32_t* vst_dev, uint64_t* vst_ino, char* vip_path, unsigned long vip_path_size);

{fn_setup}
{fn_unexpand}
{fn_find}
{fn_rpi}
{fn_rp}
{fn_parse}

int main(void) {{
    struct proc_regionwithpathinfo rpi;
    struct proc_regionpath rp;

    assert(_proc_pidinfo_regionpathinfo(123, 0x1500, NULL, sizeof(rpi)) == -EFAULT);
    assert(_proc_pidinfo_regionpathinfo(123, 0x1500, &rpi, 8) == -ENOSPC);

    // 1. Prefix path unexpands cleanly (no host /mock-prefix/ leak) and returns full struct size.
    memset(&rpi, 0x5a, sizeof(rpi));
    assert(_proc_pidinfo_regionpathinfo(123, 0x1500, &rpi, sizeof(rpi)) == (long)sizeof(rpi));
    assert(rpi.prp_prinfo.pri_address == 0x1000 && rpi.prp_prinfo.pri_size == 0x1000);
    assert(rpi.prp_prinfo.pri_offset == 0x1000);
    assert(rpi.prp_prinfo.pri_protection == (VM_PROT_READ | VM_PROT_EXECUTE));
    assert(strcmp(rpi.prp_vip.vip_path, "/Applications/Client.app/Client") == 0);

    // 2. Anonymous mapping immediately after file-backed mapping must have empty path (no stale leak).
    memset(&rpi, 0x5a, sizeof(rpi));
    assert(_proc_pidinfo_regionpathinfo(123, 0x2200, &rpi, sizeof(rpi)) == (long)sizeof(rpi));
    assert(rpi.prp_prinfo.pri_address == 0x2000 && rpi.prp_vip.vip_path[0] == '\\0');

    // 3. Kernel pseudo-mapping ([stack]) also yields empty path, not "[stack]".
    assert(_proc_pidinfo_regionpath(123, 0x3500, &rp, sizeof(rp)) == (long)sizeof(rp));
    assert(rp.prpo_addr == 0x3000 && rp.prpo_regionlength == 0x1000);
    assert(rp.prpo_path[0] == '\\0');

    // 4. SDK framework mapping and host library mapping both unexpand properly.
    assert(_proc_pidinfo_regionpath(123, 0x4100, &rp, sizeof(rp)) == (long)sizeof(rp));
    assert(strcmp(rp.prpo_path, "/System/Library/Frameworks/Core.framework/Core") == 0);
    assert(_proc_pidinfo_regionpath(123, 0x5100, &rp, sizeof(rp)) == (long)sizeof(rp));
    assert(strcmp(rp.prpo_path, "/Volumes/SystemRoot/usr/lib64/host-only.so") == 0);

    // 5. Missing address returns -ESRCH without overwriting caller buffer.
    memset(&rpi, 0x33, sizeof(rpi));
    assert(_proc_pidinfo_regionpathinfo(123, 0x9999, &rpi, sizeof(rpi)) == -ESRCH);
    assert(((unsigned char*)&rpi)[0] == 0x33);
    assert(_proc_pidinfo_regionpath(123, 0x9999, &rp, sizeof(rp)) == -ESRCH);
    return 0;
}}
""")

            exe = base / 'check_region'
            subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', str(harness), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    unittest.main()
