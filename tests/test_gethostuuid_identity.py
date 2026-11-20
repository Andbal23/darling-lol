"""Checks that sys_gethostuuid() aligns with provisioned IOPlatformUUID."""
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest
import uuid

import test_runtime_compatibility as sources

ROOT = Path(__file__).resolve().parents[1]
GETHOSTUUID_PATH = 'darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/misc/gethostuuid.c'


class GetHostUuidIdentityTests(unittest.TestCase):
    def test_patch_reads_platform_plist_and_falls_back_to_machine_id(self):
        patch = (ROOT / 'patches/xnu.patch').read_text()
        self.assertIn(f'diff --git a/{GETHOSTUUID_PATH} b/{GETHOSTUUID_PATH}', patch)
        self.assertIn('IOPlatformUUID', patch)
        self.assertIn('/private/etc/darling-platform.plist', patch)
        self.assertIn('/Volumes/SystemRoot/etc/machine-id', patch)

    @unittest.skipUnless(shutil.which('cc') and shutil.which('patch'), 'C compiler and patch required')
    def test_host_compile_and_behavior(self):
        helper = sources.CompatibilityChecks()
        helper.setUp = lambda: None
        src = helper.patched('xnu', GETHOSTUUID_PATH)

        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            plist_path = base / 'darling-platform.plist'
            machine_id_path = base / 'machine-id'
            include = base / 'include'
            for sub in (
                'darling/emulation/xnu_syscall/bsd/impl/misc',
                'darling/emulation/common',
                'darling/emulation/conversion/errno',
                'darling/emulation/conversion/fcntl',
                'darling/emulation/linux_premigration/linux-syscalls',
                'darling/emulation/xnu_syscall/bsd/impl/fcntl',
                'darling/emulation/xnu_syscall/bsd/impl/unistd',
                'sys',
            ):
                (include / sub).mkdir(parents=True, exist_ok=True)

            (include / 'darling/emulation/xnu_syscall/bsd/impl/misc/gethostuuid.h').write_text(
                'long sys_gethostuuid(unsigned char* uuid_buf, void* timeout);\n'
            )
            (include / 'sys/fcntl.h').write_text('#include <fcntl.h>\n')
            (include / 'sys/errno.h').write_text('#include <errno.h>\n')
            for empty in (
                'darling/emulation/common/base.h',
                'darling/emulation/conversion/errno.h',
                'darling/emulation/linux_premigration/linux-syscalls/linux.h',
            ):
                (include / empty).write_text('/* shim */\n')
            (include / 'darling/emulation/conversion/fcntl/open.h').write_text(
                '#include <fcntl.h>\n#define BSD_O_RDONLY O_RDONLY\n'
            )
            (include / 'darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h').write_text(
                'long sys_open_nocancel(const char* path, int flags, unsigned int mode);\n'
            )
            (include / 'darling/emulation/xnu_syscall/bsd/impl/unistd/read.h').write_text(
                'long sys_read_nocancel(int fd, void* mem, int len);\n'
            )
            (include / 'darling/emulation/xnu_syscall/bsd/impl/unistd/close.h').write_text(
                'int close_internal(int fd);\n'
            )

            patched_c = base / 'gethostuuid.c'
            patched_c.write_text(src)

            expected_uuid = uuid.UUID('12345678-9ABC-4DEF-8123-456789ABCDEF')
            machine_hex = 'deadbeef00112233445566778899aabb'

            harness = base / 'harness.c'
            harness.write_text(f"""
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

long sys_gethostuuid(unsigned char* uuid_buf, void* timeout);

long sys_open_nocancel(const char* path, int flags, unsigned int mode) {{
    (void)mode;
    int fd = open(path, flags);
    return fd < 0 ? -errno : fd;
}}

long sys_read_nocancel(int fd, void* mem, int len) {{
    ssize_t n = read(fd, mem, (size_t)len);
    return n < 0 ? -errno : (long)n;
}}

int close_internal(int fd) {{
    return close(fd);
}}

int main(int argc, char** argv) {{
    unsigned char out[16];
    (void)argc;
    memset(out, 0xaa, sizeof(out));
    assert(sys_gethostuuid(NULL, NULL) == -EFAULT);

    long rc = sys_gethostuuid(out, NULL);
    if (strcmp(argv[1], "expect-ok") == 0) {{
        assert(rc == 0);
        for (int i = 0; i < 16; ++i)
            printf("%02x", out[i]);
        printf("\\n");
        return 0;
    }}
    long want = -ENOENT;
    if (strcmp(argv[1], "expect-enosys") == 0)
        want = -ENOSYS;
    assert(rc == want);
    return 0;
}}
""")

            exe = base / 'test_gethostuuid'
            subprocess.run(
                [
                    'cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-I', str(include),
                    f'-DRCLOL_PLATFORM_PLIST_PATH="{plist_path}"',
                    f'-DRCLOL_MACHINE_ID_PATH="{machine_id_path}"',
                    str(patched_c), str(harness), '-o', str(exe),
                ],
                check=True,
            )

            # 1. Standard plistlib output + machine-id present: plist IOPlatformUUID wins.
            plist_path.write_bytes(plistlib.dumps({
                'IOPlatformSerialNumber': 'SYNTHETIC123',
                'IOPlatformUUID': str(expected_uuid).upper(),
                'provisioning_UDID': str(expected_uuid).upper(),
            }))
            machine_id_path.write_text(machine_hex + '\n')
            got = subprocess.run([str(exe), 'expect-ok'], check=True, capture_output=True, text=True).stdout.strip()
            self.assertEqual(got, expected_uuid.hex)

            # 2. Nested dict IOPlatformUUID and XML comments must not confuse top-level lookup.
            plist_path.write_text(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<plist version="1.0"><dict>\n'
                '  <key>Nested</key><dict><key>IOPlatformUUID</key><string>FFFFFFFF-FFFF-4FFF-8FFF-FFFFFFFFFFFF</string></dict>\n'
                '  <key>IOPlatformUUID</key>\n  <!-- comment -->\n'
                f'  <string>  {str(expected_uuid).lower()}  </string>\n'
                '</dict></plist>\n'
            )
            got = subprocess.run([str(exe), 'expect-ok'], check=True, capture_output=True, text=True).stdout.strip()
            self.assertEqual(got, expected_uuid.hex)

            # 3. All-zero UUID in plist is rejected and falls back cleanly to machine-id.
            plist_path.write_bytes(plistlib.dumps({'IOPlatformUUID': '00000000-0000-0000-0000-000000000000'}))
            got = subprocess.run([str(exe), 'expect-ok'], check=True, capture_output=True, text=True).stdout.strip()
            self.assertEqual(got, machine_hex)

            # 4. Missing plist falls back cleanly to machine-id.
            plist_path.unlink()
            got = subprocess.run([str(exe), 'expect-ok'], check=True, capture_output=True, text=True).stdout.strip()
            self.assertEqual(got, machine_hex)

            # 5. Truncated / non-hex machine-id returns -ENOSYS; missing both returns -ENOENT.
            machine_id_path.write_text('zzzz' * 8)
            subprocess.run([str(exe), 'expect-enosys'], check=True)
            machine_id_path.unlink()
            subprocess.run([str(exe), 'expect-enoent'], check=True)


if __name__ == '__main__':
    unittest.main()
