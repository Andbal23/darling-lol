"""Consistency checks for cpufamily, cachelinesize, L1-L3 sizes, AVX-512, and commpage."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
EMU = 'darling/src/libsystem_kernel/emulation'


def patched_added(patch_name, rel_path):
    patch = (ROOT / 'patches' / f'{patch_name}.patch').read_text()
    section = patch.split(f'diff --git a/{rel_path} b/{rel_path}\n', 1)[1].split('\ndiff --git ', 1)[0]
    return '\n'.join(line[1:] for line in section.splitlines()
                     if line.startswith('+') and not line.startswith('+++'))


def function(source, signature):
    source += '\n'
    start = source.index(signature)
    return source[start:source.index('\n}\n', start) + 3]


class CompatCpuIdentityConsistencyTests(unittest.TestCase):
    def test_commpage_publishes_cpufamily_and_cache_linesize(self):
        patch = (ROOT / 'patches/darling.patch').read_text()
        self.assertIn('_COMM_PAGE_CACHE_LINESIZE', patch)
        self.assertIn('_COMM_PAGE_CPUFAMILY', patch)
        self.assertIn('kCache64', patch)
        self.assertIn('commpage_intel_cpufamily', patch)

    @unittest.skipUnless(shutil.which('cc'), 'C compiler required')
    def test_intel_cpufamily_decoder_matches_xnu(self):
        header = patched_added('xnu', f'{EMU}/include/common/cpu_identity.h')
        ident_src = patched_added('xnu', f'{EMU}/src/common/cpu_identity.c')
        fn_ident = function(ident_src, 'uint32_t darling_intel_cpufamily(')
        caps_hdr = patched_added('darling', 'src/startup/mldr/commpage-cpu-caps.h')

        harness = f"""
#include <assert.h>
#include <stdint.h>
#define k64Bit 0x200
#define kHasMMX 1
#define kHasSSE 2
#define kHasSSE2 4
#define kHasSSE3 8
#define kHasSupplementalSSE3 0x100
#define kHasSSE4_1 0x400
#define kHasSSE4_2 0x800
#define kHasAES 0x1000
#define kHasAVX1_0 0x01000000
#define kHasRDRAND 0x02000000
#define kHasF16C 0x04000000
#define kHasENFSTRG 0x08000000
#define kHasFMA 0x10000000
#define kHasAVX2_0 0x20000000
#define kHasBMI1 0x40000000
#define kHasBMI2 0x80000000
#define kHasRTM (1ULL << 32)
#define kHasHLE (1ULL << 33)
#define kHasADX (1ULL << 34)
#define kHasRDSEED (1ULL << 35)
#define kHasMPX (1ULL << 36)
#define kHasSGX (1ULL << 37)
{caps_hdr}
{header}
{fn_ident}
int main(void) {{
    // Non-Intel vendor must return CPUFAMILY_UNKNOWN (0).
    assert(darling_intel_cpufamily(0, 0x000906eau) == 0u);
    assert(commpage_intel_cpufamily(0, 0x000906eau) == 0u);
    // Non-family-6 Intel also returns 0.
    assert(darling_intel_cpufamily(1, 0x00000f41u) == 0u);
    // Coffee Lake-H i7-9750H (0x906ea) -> CPUFAMILY_INTEL_KABYLAKE (0x0f817246).
    assert(darling_intel_cpufamily(1, 0x000906eau) == 0x0f817246u);
    assert(commpage_intel_cpufamily(1, 0x000906eau) == 0x0f817246u);
    // Skylake, Ice Lake, Haswell spot checks.
    assert(darling_intel_cpufamily(1, 0x000506e3u) == 0x37fc219fu);
    assert(commpage_intel_cpufamily(1, 0x000506e3u) == 0x37fc219fu);
    assert(darling_intel_cpufamily(1, 0x000706e5u) == 0x38435547u);
    assert(commpage_intel_cpufamily(1, 0x000706e5u) == 0x38435547u);
    assert(darling_intel_cpufamily(1, 0x000306c3u) == 0x10b282dcu);
    return 0;
}}
"""
        with tempfile.TemporaryDirectory() as folder:
            src = Path(folder) / 'cpufamily.c'
            exe = Path(folder) / 'cpufamily'
            src.write_text(harness)
            subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)

    @unittest.skipUnless(shutil.which('cc'), 'C compiler required')
    def test_optional_avx512_gate_and_machdep_brand_fallback(self):
        hw = patched_added('xnu', f'{EMU}/src/xnu_syscall/bsd/helper/misc/sysctl_hw.c')
        self.assertIn('optional_compat_handler(avx512f, 7, 1, 16, 0)', hw)
        self.assertIn('handle_optional_avx512vbmi', hw)
        self.assertIn('handle_cpufamily', hw)
        self.assertIn('handle_cachelinesize', hw)
        self.assertIn('handle_l1icachesize', hw)
        self.assertIn('handle_tbfrequency', hw)

        machdep = patched_added('xnu', f'{EMU}/src/xnu_syscall/bsd/helper/misc/sysctl_machdep.c')
        self.assertIn('darling_configured_cpu_brand()', machdep)
        self.assertIn('darling_compat_cpu_identity()->brand', machdep)
        self.assertIn('darling_compat_cpu_identity()->cores', machdep)
        self.assertIn('darling_compat_cpu_identity()->threads', machdep)
        self.assertNotIn('getenv("RCLOL_CPU_BRAND")', machdep)

        fn_opt = function(hw, 'static long optional_feature(')
        harness = f"""
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#define sysctl_handle_size(size) do {{ \\
    if (old == NULL) {{ *oldlen = (size); return 0; }} \\
    else if (*oldlen < (size)) return -EINVAL; \\
    else *oldlen = (size); \\
}} while (0)
static int g_compat = 0;
static int darling_compat_profile_enabled(void) {{ return g_compat; }}
{fn_opt}
int main(void) {{
    int val = 99;
    unsigned long len = sizeof(val);
    g_compat = 1;
    // Any feature disallowed in compat (AVX-512) returns 0 regardless of host CPUID.
    assert(optional_feature(&val, &len, 7, 1, 16, 0) == 0 && len == sizeof(int) && val == 0);
    // Allowed feature probes real CPUID safely (SSE2 always 1 on x86_64; out-of-range leaf -> 0).
    assert(optional_feature(&val, &len, 1, 3, 26, 1) == 0 && val == 1);
    assert(optional_feature(&val, &len, 0x7fffu, 0, 0, 1) == 0 && val == 0);
    return 0;
}}
"""
        with tempfile.TemporaryDirectory() as folder:
            src = Path(folder) / 'opt.c'
            exe = Path(folder) / 'opt'
            src.write_text(harness)
            subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    unittest.main()
