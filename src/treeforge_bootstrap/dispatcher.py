from __future__ import annotations

import os
from datetime import datetime, timezone

from dataclasses import dataclass
from pathlib import Path
import shutil
import struct
import subprocess
import tomllib

from .framebuffer_provider import (
    load_framebuffer_provider,
)
from .menu_provider import (
    load_menu_provider,
)

from .version import (
    build_date as version_build_date,
    project_version,
    runtime_abi_version,
)

from .menu import (
    MenuAction,
    MenuCondition,
    MenuIcon,
    MenuLabelState,
    MenuPage,
    MenuProfile,
    load_default_profile,
)


class TreeForgeDispatcherError(
    RuntimeError
):
    pass


@dataclass(
    frozen=True,
    slots=True,
)
class TreeForgeDispatcherBuild:
    source_path: Path
    executable_path: Path
    compiler_path: Path
    elf_machine: int
    target_triple: str


class TreeForgeDispatcherBuilder:
    """
    Build TreeForge Bootstrap's early-boot interactive dispatcher.

    The dispatcher first runs as the kernel's initial PID 1 and
    transparently enters the exact preserved canonical Android
    FirstStageMain. TreeForge Bootstrap resumes at the canonical first-stage ->
    selinux_setup transition, after Android has established its
    first-stage kernel-module and /dev environment.

    At that boundary the dispatcher provides the early boot menu and
    then either:

      - continues Android's exact selinux_setup transition;
      - requests a bootloader reboot; or
      - requests a recovery reboot.

    It is deliberately freestanding and uses Linux syscalls directly.
    No Android property service, libc, shell, or AOSP checkout is
    required at runtime or build time.

    Compiler selection is a generic host-provider concern:
      TREEFORGE_BOOTSTRAP_CLANG may explicitly select clang;
      otherwise the first host `clang` on PATH is used.
    """

    ELF_MACHINE_AARCH64 = 183

    _SOURCE = r'''
typedef unsigned long usize;
typedef long ssize;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef int s32;


/*
 * Minimal freestanding memory primitives.
 *
 * Clang may lower aggregate copies/initialization to these routines
 * even for -ffreestanding -nostdlib code. TreeForge Bootstrap therefore owns
 * these tiny compiler-runtime providers rather than depending on libc.
 *
 * Volatile byte accesses intentionally keep these implementations from
 * themselves being rewritten into calls to the same libc primitives.
 */

void *memcpy(
    void *destination,
    const void *source,
    usize count
) {
    volatile unsigned char *output = (
        (volatile unsigned char *)
        destination
    );

    const volatile unsigned char *input = (
        (const volatile unsigned char *)
        source
    );

    for (
        usize index = 0;
        index < count;
        index++
    ) {
        output[index] = input[index];
    }

    return destination;
}


void *memmove(
    void *destination,
    const void *source,
    usize count
) {
    volatile unsigned char *output = (
        (volatile unsigned char *)
        destination
    );

    const volatile unsigned char *input = (
        (const volatile unsigned char *)
        source
    );

    if (
        (usize) output
        <= (usize) input
    ) {
        for (
            usize index = 0;
            index < count;
            index++
        ) {
            output[index] = input[index];
        }
    } else {
        while (count > 0) {
            count--;

            output[count] = input[count];
        }
    }

    return destination;
}


void *memset(
    void *destination,
    int value,
    usize count
) {
    volatile unsigned char *output = (
        (volatile unsigned char *)
        destination
    );

    unsigned char byte = (
        (unsigned char) value
    );

    for (
        usize index = 0;
        index < count;
        index++
    ) {
        output[index] = byte;
    }

    return destination;
}


int memcmp(
    const void *left,
    const void *right,
    usize count
) {
    const volatile unsigned char *left_bytes = (
        (const volatile unsigned char *)
        left
    );

    const volatile unsigned char *right_bytes = (
        (const volatile unsigned char *)
        right
    );

    for (
        usize index = 0;
        index < count;
        index++
    ) {
        if (
            left_bytes[index]
            < right_bytes[index]
        ) {
            return -1;
        }

        if (
            left_bytes[index]
            > right_bytes[index]
        ) {
            return 1;
        }
    }

    return 0;
}

#define SYS_DUP3 24
#define SYS_IOCTL 29
#define SYS_MKNODAT 33
#define SYS_MKDIRAT 34
#define SYS_UNLINKAT 35
#define SYS_RENAMEAT 38
#ifndef SYS_SYMLINKAT
#define SYS_SYMLINKAT 36
#endif
#define SYS_UMOUNT2 39
#define SYS_MOUNT 40
#define SYS_PIVOT_ROOT 41
#define SYS_CHDIR 49
#ifndef SYS_MKNODAT
#define SYS_MKNODAT 33
#endif
#define SYS_OPENAT 56
#define SYS_CLOSE 57
#define SYS_GETDENTS64 61
#define SYS_LSEEK 62
#define SYS_READ 63
#define SYS_WRITE 64
#define SYS_SYNC 81
#define SYS_FSYNC 82
#define SYS_EXIT 93
#define SYS_NANOSLEEP 101
#define SYS_REBOOT 142
#define SYS_MUNMAP 215
#define SYS_EXECVE 221
#define SYS_MMAP 222

#define AT_FDCWD (-100)
#define SEEK_SET 0
#define SEEK_END 2
#define AT_REMOVEDIR 0x200

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_NONBLOCK 04000
#define O_DIRECTORY 040000

#define TFB_MS_BIND 4096UL
#define TFB_MS_REC 16384UL
#define TFB_MS_PRIVATE 262144UL
#define TFB_MNT_DETACH 2
#define TFB_EEXIST 17

#define TREEFORGE_BOOTSTRAP_TRANSITION_FD 99

/*
 * TFB_VENDOR_BOOT_CARRIER_ABI_V1
 *
 * FD99 remains the established Bootstrap dispatcher/runtime
 * transition descriptor.
 *
 * When present, FD98 retains the TreeForge vendor_boot carrier
 * across Android FirstStageMain / FreeRamdisk.
 */
#define TREEFORGE_BOOTSTRAP_VENDOR_BOOT_CARRIER_FD 98
#define TFB_VENDOR_BOOT_CARRIER_PATH \
    "/treeforge/bootstrap-carrier"
#define TFB_VENDOR_BOOT_CARRIER_PROOF_PATH \
    "/dev/treeforge-vendor-boot-carrier-proof"
#define TFB_VENDOR_BOOT_CARRIER_REQUEST_PATH \
    "/dev/treeforge-bootstrap-transaction-v1.request"

/*
 * TreeForge Bootstrap retained carrier ABI v1.
 *
 * Host format:
 *
 *   96-byte header
 *   128-byte fixed records
 *   raw payload area
 *
 * Production accepts:
 *
 *   proof/retained-fd
 *
 * or the strictly sorted pair:
 *
 *   proof/retained-fd
 *   transaction/request-v1
 *
 * FD98 still retains one carrier inode across FreeRamdisk.
 */
#define TFB_VENDOR_BOOT_CARRIER_HEADER_BYTES 96
#define TFB_VENDOR_BOOT_CARRIER_RECORD_BYTES 128
#define TFB_VENDOR_BOOT_CARRIER_SCHEMA 1
#define TFB_VENDOR_BOOT_CARRIER_ENTRY_FILE 1
#define TFB_VENDOR_BOOT_CARRIER_PROOF_BYTES 43
#define TFB_VENDOR_BOOT_CARRIER_REQUEST_BYTES 119
#define PROT_READ 1
#define PROT_WRITE 2

#define MAP_SHARED 1

#define S_IFCHR 0020000
#define S_IFBLK 0060000

/*
 * TFB_PIXEL_PARTITIONER_SERVICE_V1
 *
 * Entering the Pixel Partitioner status page is the explicit authorization
 * boundary for the host-side Pixel Partitioner CLI.
 */
#define TFB_PP_READY_MARKER \
    "/dev/treeforge-bootstrap-pixel-partitioner-ready"

#define TFB_PP_REPROBE_REQUEST \
    "/dev/treeforge-bootstrap-block-reprobe-request"

#define TFB_PP_REPROBE_READY \
    "/dev/treeforge-bootstrap-block-reprobe-ready"

#define TFB_PP_REPROBE_FAILED \
    "/dev/treeforge-bootstrap-block-reprobe-failed"

/*
 * TFB_TARGETED_GPT_REFRESH_V1_1
 *
 * Bootstrap's Android handoff environment already has unrelated
 * partitions in use. A whole-disk BLKRRPART therefore cannot be the
 * runtime contract.
 *
 * Pixel Partitioner changes only the mutable tail:
 *
 *   sda26 = userdata
 *   sda27 = treeforge_os
 *
 * Refresh those entries individually with Linux BLKPG.
 */
#define TFB_BLKPG 0x1269UL

#define TFB_BLKPG_ADD_PARTITION 1
#define TFB_BLKPG_DEL_PARTITION 2
#define TFB_BLKPG_RESIZE_PARTITION 3

#define TFB_GPT_LOGICAL_BLOCK_SIZE 4096ULL
#define TFB_GPT_HEADER_OFFSET 4096ULL
#define TFB_GPT_HEADER_READ_BYTES 92
#define TFB_GPT_ENTRY_READ_BYTES 128

#define TFB_MUTABLE_USERDATA_PARTITION 26
#define TFB_MUTABLE_OS_PARTITION 27

#ifndef SYS_LSEEK
#define SYS_LSEEK 62
#endif

#define TFB_BLOCK_MAX_PARTITIONS 128
#define TFB_BLOCK_PATH_CAPACITY 192
#define TFB_BLOCK_UEVENT_CAPACITY 2048
#define TFB_BLOCK_PARTNAME_CAPACITY 96

/*
 * Bootstrap-owned Android target.
 *
 * This is deliberately independent from the bootloader active slot.
 */
static int tfb_boot_target_slot = 0;

#define MS_RDONLY 1
#define MNT_DETACH 2

#define LINUX_REBOOT_MAGIC1 0xfee1deadUL
#define LINUX_REBOOT_MAGIC2 672274793UL
#define LINUX_REBOOT_CMD_RESTART 0x01234567UL
#define LINUX_REBOOT_CMD_RESTART2 0xa1b2c3d4UL

#define EV_KEY 1
#define EV_ABS 3

#define ABS_MT_SLOT 0x2f
#define ABS_MT_POSITION_X 0x35
#define ABS_MT_POSITION_Y 0x36
#define ABS_MT_TRACKING_ID 0x39

#define TFB_TOUCH_RAW_WIDTH 1600
#define TFB_TOUCH_RAW_HEIGHT 2560
#define TFB_TOUCH_TAP_SLOP 96

/*
 * TFB_LANDSCAPE_MENU_V17
 *
 * Pixel Tablet's physical boot UI is landscape while the retained
 * framebuffer bridge exposes the panel's native 1600x2560 scanout.
 * TreeForge therefore owns a logical 2560x1600 camera-top landscape
 * coordinate system and rotates only its own drawing/touch geometry.
 *
 * No DRM plane rotation or kernel display programming is introduced.
 */
#define TFB_UI_LOGICAL_WIDTH 2560U
#define TFB_UI_LOGICAL_HEIGHT 1600U
#define TFB_UI_MENU_X 1340U
#define TFB_UI_MENU_RIGHT_MARGIN 120U
#define TFB_UI_CONTENT_TOP 300U
#define TFB_UI_CONTENT_BOTTOM 1430U
#define TFB_UI_ROW_GAP 28U

/*
 * TFB_PP_SHARED_PANEL_GEOMETRY_V1
 *
 * Pixel Partitioner is still a normal submenu, but its
 * single Back action is pinned below the live-log panel.
 *
 * tfb_ui_menu_geometry() owns these coordinates so drawing
 * and touchscreen hit-testing consume the same rectangle.
 */
#define TFB_PP_BACK_Y 1235U
#define TFB_PP_BACK_HEIGHT 170U
#define TFB_PP_REFRESH_MS 250U
#define KEY_VOLUMEDOWN 114
#define KEY_VOLUMEUP 115
#define KEY_POWER 116

#define INPUT_COUNT 32

#define MENU_TIMEOUT_MS 10000
#define POLL_INTERVAL_MS 25


struct tfb_timespec {
    long tv_sec;
    long tv_nsec;
};

struct tfb_input_event {
    long tv_sec;
    long tv_usec;
    u16 type;
    u16 code;
    s32 value;
};

struct tfb_linux_dirent64 {
    u64 d_ino;
    long long d_off;
    u16 d_reclen;
    unsigned char d_type;
    char d_name[];
};


#define TF_IOC_NRBITS 8
#define TF_IOC_TYPEBITS 8
#define TF_IOC_SIZEBITS 14

#define TF_IOC_NRSHIFT 0
#define TF_IOC_TYPESHIFT \
    (TF_IOC_NRSHIFT + TF_IOC_NRBITS)
#define TF_IOC_SIZESHIFT \
    (TF_IOC_TYPESHIFT + TF_IOC_TYPEBITS)
#define TF_IOC_DIRSHIFT \
    (TF_IOC_SIZESHIFT + TF_IOC_SIZEBITS)

#define TF_IOC_WRITE 1U
#define TF_IOC_READ 2U

#define TF_IOC(dir, type, nr, size) \
    ( \
        ((unsigned long) (dir) << TF_IOC_DIRSHIFT) \
        | ((unsigned long) (type) << TF_IOC_TYPESHIFT) \
        | ((unsigned long) (nr) << TF_IOC_NRSHIFT) \
        | ((unsigned long) (size) << TF_IOC_SIZESHIFT) \
    )

static long tfb_syscall6(
    long number,
    long a0,
    long a1,
    long a2,
    long a3,
    long a4,
    long a5
) {
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    register long x4 asm("x4") = a4;
    register long x5 asm("x5") = a5;
    register long x8 asm("x8") = number;

    asm volatile(
        "svc 0"
        : "+r"(x0)
        : "r"(x1),
          "r"(x2),
          "r"(x3),
          "r"(x4),
          "r"(x5),
          "r"(x8)
        : "memory"
    );

    return x0;
}

static long tfb_syscall4(
    long number,
    long a0,
    long a1,
    long a2,
    long a3
) {
    return tfb_syscall6(
        number,
        a0,
        a1,
        a2,
        a3,
        0,
        0
    );
}

static long tfb_syscall3(
    long number,
    long a0,
    long a1,
    long a2
) {
    return tfb_syscall6(
        number,
        a0,
        a1,
        a2,
        0,
        0,
        0
    );
}

static long tfb_syscall2(
    long number,
    long a0,
    long a1
) {
    return tfb_syscall6(
        number,
        a0,
        a1,
        0,
        0,
        0,
        0
    );
}

static long tfb_syscall1(
    long number,
    long a0
) {
    return tfb_syscall6(
        number,
        a0,
        0,
        0,
        0,
        0,
        0
    );
}

static usize tfb_strlen(
    const char *value
) {
    usize length = 0;

    while (value[length] != '\0') {
        length++;
    }

    return length;
}


static long tfb_open(
    const char *path,
    long flags
) {
    return tfb_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long) path,
        flags,
        0
    );
}

static void tfb_close(
    long fd
) {
    if (fd >= 0) {
        tfb_syscall1(
            SYS_CLOSE,
            fd
        );
    }
}

static void tfb_write_all(
    long fd,
    const char *value
) {
    if (fd < 0) {
        return;
    }

    usize remaining = tfb_strlen(
        value
    );

    const char *cursor = value;

    while (remaining != 0) {
        long written = tfb_syscall3(
            SYS_WRITE,
            fd,
            (long) cursor,
            (long) remaining
        );

        if (written <= 0) {
            return;
        }

        cursor += written;
        remaining -= (usize) written;
    }
}

static int tfb_write_bytes(
    long fd,
    const unsigned char *value,
    usize size
) {
    if (fd < 0) {
        return 0;
    }

    usize remaining = size;
    const unsigned char *cursor = value;

    while (remaining != 0) {
        long written = tfb_syscall3(
            SYS_WRITE,
            fd,
            (long) cursor,
            (long) remaining
        );

        if (written <= 0) {
            return 0;
        }

        cursor += written;
        remaining -= (usize) written;
    }

    return 1;
}



static long tfb_copy_fd_failure_code = 0;

static const char *tfb_runtime_materialize_failure_stage =
    "NONE";

static const char *tfb_runtime_materialize_failure_path =
    0;

static const char *tfb_runtime_materialize_failure_source_path =
    0;


static const char *tfb_copy_fd_failure_code_name(
    long code
) {
    switch (code) {
        case -4:
            return "EINTR";
        case -5:
            return "EIO";
        case -9:
            return "EBADF FD CLOSED";
        case -11:
            return "EAGAIN";
        case -14:
            return "EFAULT";
        case -21:
            return "EISDIR SOURCE IS DIRECTORY";
        case -22:
            return "EINVAL";
        default:
            return "OTHER READ ERROR";
    }
}


static int tfb_read_exact(
    long fd,
    unsigned char *buffer,
    usize size
) {
    usize remaining = size;
    unsigned char *cursor = buffer;

    while (remaining != 0) {
        long amount = tfb_syscall3(
            SYS_READ,
            fd,
            (long) cursor,
            (long) remaining
        );

        if (amount <= 0) {
            tfb_copy_fd_failure_code = (
                amount < 0
                ? amount
                : -5
            );

            return 0;
        }

        cursor += amount;
        remaining -= (usize) amount;
    }

    return 1;
}


static u32 tfb_u32_le(
    const unsigned char *value
) {
    return (
        ((u32) value[0])
        | ((u32) value[1] << 8)
        | ((u32) value[2] << 16)
        | ((u32) value[3] << 24)
    );
}


static u64 tfb_u64_le(
    const unsigned char *value
) {
    return (
        ((u64) value[0])
        | ((u64) value[1] << 8)
        | ((u64) value[2] << 16)
        | ((u64) value[3] << 24)
        | ((u64) value[4] << 32)
        | ((u64) value[5] << 40)
        | ((u64) value[6] << 48)
        | ((u64) value[7] << 56)
    );
}


static int tfb_magic8_equal(
    const unsigned char *value,
    const char *expected
) {
    for (int index = 0; index < 8; index++) {
        if (
            value[index]
            != (unsigned char) expected[index]
        ) {
            return 0;
        }
    }

    return 1;
}


static int tfb_create_parent_directories(
    const char *path
) {
    if (
        !path
        || path[0] != '/'
    ) {
        return 0;
    }

    char buffer[512];

    usize length = tfb_strlen(
        path
    );

    if (
        length == 0
        || length >= sizeof(buffer)
    ) {
        return 0;
    }

    for (
        usize index = 0;
        index <= length;
        index++
    ) {
        buffer[index] = path[index];
    }

    /*
     * Existing directories are harmless. The final destination open
     * performed by tfb_copy_fd_to_path() is the authoritative test.
     */
    for (
        usize index = 1;
        index < length;
        index++
    ) {
        if (buffer[index] != '/') {
            continue;
        }

        buffer[index] = '\0';

        tfb_syscall3(
            SYS_MKDIRAT,
            AT_FDCWD,
            (long) buffer,
            0755
        );

        buffer[index] = '/';
    }

    return 1;
}


static int tfb_materialize_runtime_bundle(void) {
    /*
     * FD99 is the exact open /init descriptor that has already been
     * proven to survive Android FirstStageMain / FreeRamdisk and the
     * redirected selinux_setup re-entry.
     *
     * The dispatcher ELF carries a deterministic runtime bundle after
     * its ELF payload.  Locate its trailer from EOF, then stream each
     * file directly from FD99 into /dev/treeforge-bootstrap-runtime.
     */
    tfb_runtime_materialize_failure_stage =
        "NONE";

    tfb_runtime_materialize_failure_path =
        0;

    tfb_runtime_materialize_failure_source_path =
        "FD99 SELF BUNDLE";

    tfb_copy_fd_failure_code = 0;

    long trailer_position = tfb_syscall3(
        SYS_LSEEK,
        TREEFORGE_BOOTSTRAP_TRANSITION_FD,
        -16,
        SEEK_END
    );

    if (trailer_position < 0) {
        tfb_runtime_materialize_failure_stage =
            "BUNDLE SEEK END";

        tfb_copy_fd_failure_code =
            trailer_position;

        return 0;
    }

    unsigned char trailer[16];

    if (
        !tfb_read_exact(
            TREEFORGE_BOOTSTRAP_TRANSITION_FD,
            trailer,
            sizeof(trailer)
        )
    ) {
        tfb_runtime_materialize_failure_stage =
            "BUNDLE TRAILER READ";

        return 0;
    }

    if (
        !tfb_magic8_equal(
            trailer,
            "TFRTEND1"
        )
    ) {
        tfb_runtime_materialize_failure_stage =
            "BUNDLE TRAILER MAGIC";

        return 0;
    }

    u64 bundle_size = tfb_u64_le(
        trailer + 8
    );

    if (
        bundle_size < 16
        || bundle_size
            > (u64) trailer_position
    ) {
        tfb_runtime_materialize_failure_stage =
            "BUNDLE SIZE";

        return 0;
    }

    long bundle_start = (
        trailer_position
        - (long) bundle_size
    );

    long bundle_seek = tfb_syscall3(
        SYS_LSEEK,
        TREEFORGE_BOOTSTRAP_TRANSITION_FD,
        bundle_start,
        SEEK_SET
    );

    if (bundle_seek < 0) {
        tfb_runtime_materialize_failure_stage =
            "BUNDLE SEEK START";

        tfb_copy_fd_failure_code =
            bundle_seek;

        return 0;
    }

    unsigned char bundle_header[16];

    if (
        !tfb_read_exact(
            TREEFORGE_BOOTSTRAP_TRANSITION_FD,
            bundle_header,
            sizeof(bundle_header)
        )
    ) {
        tfb_runtime_materialize_failure_stage =
            "BUNDLE HEADER READ";

        return 0;
    }

    if (
        !tfb_magic8_equal(
            bundle_header,
            "TFRTB001"
        )
    ) {
        tfb_runtime_materialize_failure_stage =
            "BUNDLE HEADER MAGIC";

        return 0;
    }

    u32 file_count = tfb_u32_le(
        bundle_header + 8
    );

    if (
        file_count == 0
        || file_count > 256
    ) {
        tfb_runtime_materialize_failure_stage =
            "BUNDLE FILE COUNT";

        return 0;
    }

    static char destination_path[512];

    for (
        u32 index = 0;
        index < file_count;
        index++
    ) {
        unsigned char entry_header[16];

        if (
            !tfb_read_exact(
                TREEFORGE_BOOTSTRAP_TRANSITION_FD,
                entry_header,
                sizeof(entry_header)
            )
        ) {
            tfb_runtime_materialize_failure_stage =
                "ENTRY HEADER READ";

            return 0;
        }

        u32 path_length = tfb_u32_le(
            entry_header
        );

        u32 mode = tfb_u32_le(
            entry_header + 4
        );

        u64 payload_size = tfb_u64_le(
            entry_header + 8
        );

        if (
            path_length == 0
            || path_length
                >= sizeof(destination_path)
            || mode > 0777U
        ) {
            tfb_runtime_materialize_failure_stage =
                "ENTRY METADATA";

            return 0;
        }

        if (
            !tfb_read_exact(
                TREEFORGE_BOOTSTRAP_TRANSITION_FD,
                (unsigned char *)
                    destination_path,
                path_length
            )
        ) {
            tfb_runtime_materialize_failure_stage =
                "ENTRY PATH READ";

            return 0;
        }

        destination_path[path_length] =
            '\0';

        tfb_runtime_materialize_failure_path =
            destination_path;

        if (destination_path[0] != '/') {
            tfb_runtime_materialize_failure_stage =
                "ENTRY PATH INVALID";

            return 0;
        }

        if (
            !tfb_create_parent_directories(
                destination_path
            )
        ) {
            tfb_runtime_materialize_failure_stage =
                "PARENT PATH";

            return 0;
        }

        /*
         * FD99 bundle symlink entry.
         *
         * mode == 0 is reserved by the bundle ABI for a symbolic
         * link.  Its payload is the NUL-terminated link target.
         * Consume that payload here and do not enter the regular-file
         * open/write path below.
         */
        if (mode == 0) {
            static char symlink_target[512];

            if (
                payload_size < 2
                || payload_size
                    > (u64) sizeof(symlink_target)
            ) {
                tfb_runtime_materialize_failure_stage =
                    "SYMLINK PAYLOAD SIZE";

                return 0;
            }

            if (
                !tfb_read_exact(
                    TREEFORGE_BOOTSTRAP_TRANSITION_FD,
                    (unsigned char *)
                        symlink_target,
                    (usize) payload_size
                )
            ) {
                tfb_runtime_materialize_failure_stage =
                    "SYMLINK PAYLOAD READ";

                return 0;
            }

            if (
                symlink_target[
                    (usize) payload_size - 1
                ]
                != '\0'
            ) {
                tfb_runtime_materialize_failure_stage =
                    "SYMLINK TARGET TERMINATOR";

                return 0;
            }

            for (
                usize target_index = 0;
                target_index + 1
                    < (usize) payload_size;
                target_index++
            ) {
                if (
                    symlink_target[target_index]
                    == '\0'
                ) {
                    tfb_runtime_materialize_failure_stage =
                        "SYMLINK TARGET EMBEDDED NUL";

                    return 0;
                }
            }

            /*
             * A stale realization is harmless to remove.  Ignore
             * ENOENT and let symlinkat() be the authoritative result.
             */
            tfb_syscall3(
                SYS_UNLINKAT,
                AT_FDCWD,
                (long) destination_path,
                0
            );

            long symlink_result = tfb_syscall3(
                SYS_SYMLINKAT,
                (long) symlink_target,
                AT_FDCWD,
                (long) destination_path
            );

            if (symlink_result < 0) {
                tfb_runtime_materialize_failure_stage =
                    "SYMLINK CREATE";

                tfb_copy_fd_failure_code =
                    symlink_result;

                return 0;
            }

            continue;
        }

        long destination_fd = tfb_syscall4(
            SYS_OPENAT,
            AT_FDCWD,
            (long) destination_path,
            O_WRONLY
            | O_CREAT
            | O_TRUNC,
            mode
        );

        if (destination_fd < 0) {
            tfb_runtime_materialize_failure_stage =
                "DESTINATION OPEN";

            tfb_copy_fd_failure_code =
                destination_fd;

            return 0;
        }

        u64 remaining = payload_size;
        unsigned char buffer[4096];

        while (remaining != 0) {
            usize requested = (
                remaining
                > (u64) sizeof(buffer)
                ? sizeof(buffer)
                : (usize) remaining
            );

            long amount = tfb_syscall3(
                SYS_READ,
                TREEFORGE_BOOTSTRAP_TRANSITION_FD,
                (long) buffer,
                (long) requested
            );

            if (amount <= 0) {
                tfb_runtime_materialize_failure_stage =
                    "BUNDLE DATA READ";

                tfb_copy_fd_failure_code = (
                    amount < 0
                    ? amount
                    : -5
                );

                tfb_close(
                    destination_fd
                );

                tfb_syscall3(
                    SYS_UNLINKAT,
                    AT_FDCWD,
                    (long) destination_path,
                    0
                );

                return 0;
            }

            if (
                !tfb_write_bytes(
                    destination_fd,
                    buffer,
                    (usize) amount
                )
            ) {
                tfb_runtime_materialize_failure_stage =
                    "DESTINATION WRITE";

                tfb_copy_fd_failure_code =
                    -5;

                tfb_close(
                    destination_fd
                );

                tfb_syscall3(
                    SYS_UNLINKAT,
                    AT_FDCWD,
                    (long) destination_path,
                    0
                );

                return 0;
            }

            remaining -= (
                (u64) amount
            );
        }

        tfb_close(
            destination_fd
        );
    }

    return 1;
}


static void tfb_sleep_ms(
    long milliseconds
) {
    struct tfb_timespec delay;

    delay.tv_sec = (
        milliseconds
        / 1000
    );

    delay.tv_nsec = (
        milliseconds
        % 1000
    ) * 1000000L;

    tfb_syscall2(
        SYS_NANOSLEEP,
        (long) &delay,
        0
    );
}

/*
 * Linux dev_t encoding as used by new_encode_dev().
 *
 * We derive evdev major/minor numbers from sysfs rather than
 * assuming a particular event-node assignment.
 */
static long tfb_tty = -1;
static long tfb_console = -1;
static long tfb_kmsg = -1;

__TREEFORGE_FRAMEBUFFER_PRIMITIVES_SOURCE__



static const char tfb_bootstrap_version[] =
    "__TREEFORGE_BOOTSTRAP_VERSION__";

static const char tfb_boot_menu_version[] =
    "__TREEFORGE_BOOT_MENU_VERSION__";

static const char tfb_version[] =
    "__TREEFORGE_BOOT_MANAGER_VERSION__";

static const char tfb_runtime_abi_version[] =
    "__TREEFORGE_RUNTIME_ABI_VERSION__";

static const char tfb_framebuffer_version[] =
    "__TREEFORGE_FRAMEBUFFER_PROVIDER_VERSION__";

static const char tfb_build_date[] =
    "__TREEFORGE_BUILD_DATE__";


__TREEFORGE_MENU_CORE_SOURCE____TREEFORGE_MENU_UI_SOURCE__static void tfb_output(
    const char *value
) {
    tfb_write_all(
        tfb_tty,
        value
    );

    tfb_write_all(
        tfb_console,
        value
    );
}

static void tfb_log(
    const char *value
) {
    tfb_write_all(
        tfb_kmsg,
        "<6>treeforge_bootstrap: "
    );

    tfb_write_all(
        tfb_kmsg,
        value
    );

    tfb_write_all(
        tfb_kmsg,
        "\n"
    );
}


static void tfb_render(
    const struct tfb_menu_page *page,
    int selected,
    u32 elapsed_ms,
    int timeout_fired
) {
    if (!page) {
        return;
    }

    tfb_output(
        "\033[2J\033[H"
    );

    tfb_output(
        page->title
    );

    tfb_output(
        "\n"
    );

    tfb_output(
        tfb_version
    );

    tfb_output(
        "\n"
    );

    tfb_output(
        page->subtitle
    );

    tfb_output(
        "\n\n"
    );

    int item_count = (
        tfb_menu_visible_count(
            page
        )
    );

    for (
        int index = 0;
        index < item_count;
        index++
    ) {
        const struct tfb_menu_entry
            *entry = (
                tfb_menu_visible_entry(
                    page,
                    index
                )
            );

        if (!entry) {
            continue;
        }

        tfb_output(
            index == selected
            ? "> "
            : "  "
        );

        tfb_output(
            tfb_menu_entry_label(
                entry
            )
        );

        tfb_output(
            "\n"
        );
    }

    tfb_output(
        "\n"
        "Volume Up/Down: navigate\n"
        "Power: select\n\n"
    );

    tfb_output(
        tfb_menu_status_line(
            page,
            elapsed_ms,
            timeout_fired
        )
    );

    tfb_output(
        "\n"
    );

    tfb_fb_render_menu(
        page,
        selected,
        elapsed_ms,
        timeout_fired
    );
}


static void tfb_render_buffered(
    const struct tfb_menu_page *page,
    int selected,
    u32 elapsed_ms,
    int timeout_fired
) {
    int staged = tfb_fb_buffer_begin_full();

    tfb_render(
        page,
        selected,
        elapsed_ms,
        timeout_fired
    );

    tfb_ui_buffer_present_if(staged);
}


static void tfb_fb_draw_management_line(
    const char *value,
    u32 y,
    u32 scale,
    u32 pixel
) {
    u32 line_scale = scale;

    u32 margin = (
        8U * scale
    );

    u32 available_width = (
        tfb_fb_menu_width > margin
        ? tfb_fb_menu_width - margin
        : tfb_fb_menu_width
    );

    while (
        line_scale > 2U
        && tfb_fb_text_width(
            value,
            line_scale
        ) > available_width
    ) {
        line_scale--;
    }

    u32 width = (
        tfb_fb_text_width(
            value,
            line_scale
        )
    );

    u32 x = (
        tfb_fb_menu_width > width
        ? (
            tfb_fb_menu_width
            - width
        ) / 2U
        : 0
    );

    tfb_fb_draw_text(
        x,
        y,
        value,
        line_scale,
        pixel
    );
}


static void tfb_event_path(
    int index,
    char *output
) {
    static const char prefix[] =
        "/dev/input/event";

    int position = 0;

    for (
        int i = 0;
        prefix[i] != '\0';
        i++
    ) {
        output[position++] = (
            prefix[i]
        );
    }

    if (index >= 10) {
        output[position++] = (
            '0'
            + (
                index
                / 10
            )
        );
    }

    output[position++] = (
        '0'
        + (
            index
            % 10
        )
    );

    output[position] = '\0';
}

static void tfb_runtime_sysfs_event_dev_path(
    int index,
    char *output
) {
    static const char prefix[] =
        "/sys/class/input/event";

    static const char suffix[] =
        "/dev";

    int position = 0;

    for (
        int i = 0;
        prefix[i] != '\0';
        i++
    ) {
        output[position++] = prefix[i];
    }

    if (index >= 10) {
        output[position++] = (
            '0'
            + (
                index
                / 10
            )
        );
    }

    output[position++] = (
        '0'
        + (
            index
            % 10
        )
    );

    for (
        int i = 0;
        suffix[i] != '\0';
        i++
    ) {
        output[position++] = suffix[i];
    }

    output[position] = '\0';
}

static unsigned long tfb_runtime_makedev(
    unsigned long major,
    unsigned long minor
) {
    /*
     * Linux userspace dev_t encoding, equivalent to makedev().
     */
    return (
        (minor & 0xffUL)
        | ((major & 0xfffUL) << 8)
        | ((minor & ~0xffUL) << 12)
        | ((major & ~0xfffUL) << 32)
    );
}

static int tfb_runtime_parse_device_number(
    const char *value,
    long length,
    unsigned long *major,
    unsigned long *minor
) {
    unsigned long parsed_major = 0;
    unsigned long parsed_minor = 0;

    int position = 0;
    int major_digits = 0;
    int minor_digits = 0;

    while (
        position < length
        && value[position] >= '0'
        && value[position] <= '9'
    ) {
        parsed_major = (
            parsed_major * 10UL
            + (unsigned long) (
                value[position]
                - '0'
            )
        );

        position++;
        major_digits++;
    }

    if (
        major_digits == 0
        || position >= length
        || value[position] != ':'
    ) {
        return -1;
    }

    position++;

    while (
        position < length
        && value[position] >= '0'
        && value[position] <= '9'
    ) {
        parsed_minor = (
            parsed_minor * 10UL
            + (unsigned long) (
                value[position]
                - '0'
            )
        );

        position++;
        minor_digits++;
    }

    if (minor_digits == 0) {
        return -1;
    }

    *major = parsed_major;
    *minor = parsed_minor;

    return 0;
}

static int tfb_get_event_device_number(
    int index,
    unsigned long *major,
    unsigned long *minor
) {
    char path[64];

    tfb_runtime_sysfs_event_dev_path(
        index,
        path
    );

    long fd = tfb_open(
        path,
        O_RDONLY
    );

    if (fd < 0) {
        return -1;
    }

    char buffer[32];

    long amount = tfb_syscall3(
        SYS_READ,
        fd,
        (long) buffer,
        (long) (
            sizeof(buffer)
            - 1
        )
    );

    tfb_close(
        fd
    );

    if (amount <= 0) {
        return -1;
    }

    buffer[amount] = '\0';

    return tfb_runtime_parse_device_number(
        buffer,
        amount,
        major,
        minor
    );
}

static int tfb_realize_input_nodes(
    int *created_input_directory,
    int *created_nodes,
    int *sysfs_devices_seen
) {
    *created_input_directory = 0;
    *sysfs_devices_seen = 0;

    for (
        int index = 0;
        index < INPUT_COUNT;
        index++
    ) {
        created_nodes[index] = 0;
    }

    /*
     * Android FirstStageMain has already mounted its canonical /dev
     * tmpfs. TreeForge Bootstrap only adds the missing input subdirectory if
     * necessary.
     */
    long mkdir_result = tfb_syscall3(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long) "/dev/input",
        0755
    );

    if (mkdir_result == 0) {
        *created_input_directory = 1;
    } else if (mkdir_result != -17) {
        return -1;
    }

    for (
        int index = 0;
        index < INPUT_COUNT;
        index++
    ) {
        unsigned long major;
        unsigned long minor;

        if (
            tfb_get_event_device_number(
                index,
                &major,
                &minor
            )
            != 0
        ) {
            continue;
        }

        (*sysfs_devices_seen)++;

        char path[32];

        tfb_event_path(
            index,
            path
        );

        long result = tfb_syscall4(
            SYS_MKNODAT,
            AT_FDCWD,
            (long) path,
            S_IFCHR | 0600,
            (long) tfb_runtime_makedev(
                major,
                minor
            )
        );

        if (result == 0) {
            created_nodes[index] = 1;
            continue;
        }

        /*
         * EEXIST means Android already supplied this node.
         */
        if (result == -17) {
            continue;
        }
    }

    return 0;
}

static void tfb_cleanup_realized_input_nodes(
    int created_input_directory,
    int *created_nodes
) {
    for (
        int index = 0;
        index < INPUT_COUNT;
        index++
    ) {
        if (!created_nodes[index]) {
            continue;
        }

        char path[32];

        tfb_event_path(
            index,
            path
        );

        tfb_syscall3(
            SYS_UNLINKAT,
            AT_FDCWD,
            (long) path,
            0
        );

        created_nodes[index] = 0;
    }

    if (created_input_directory) {
        tfb_syscall3(
            SYS_UNLINKAT,
            AT_FDCWD,
            (long) "/dev/input",
            AT_REMOVEDIR
        );
    }
}

static void tfb_close_inputs(
    long *inputs
) {
    for (
        int index = 0;
        index < INPUT_COUNT;
        index++
    ) {
        if (inputs[index] >= 0) {
            tfb_close(
                inputs[index]
            );

            inputs[index] = -1;
        }
    }
}

static int tfb_reboot_to(
    const char *target
) {
    tfb_syscall1(
        SYS_SYNC,
        0
    );

    long result = tfb_syscall4(
        SYS_REBOOT,
        LINUX_REBOOT_MAGIC1,
        LINUX_REBOOT_MAGIC2,
        LINUX_REBOOT_CMD_RESTART2,
        (long) target
    );

    return (
        result == 0
        ? 0
        : -1
    );
}

static int tfb_reboot_system(
    void
) {
    tfb_syscall1(
        SYS_SYNC,
        0
    );

    long result = tfb_syscall4(
        SYS_REBOOT,
        LINUX_REBOOT_MAGIC1,
        LINUX_REBOOT_MAGIC2,
        LINUX_REBOOT_CMD_RESTART,
        0
    );

    return (
        result == 0
        ? 0
        : -1
    );
}


#define SYS_KILL 129
#define SYS_CLONE 220
#ifndef SYS_SETPGID
#define SYS_SETPGID 154
#endif
#define SYS_WAIT4 260

#define TREEFORGE_BOOTSTRAP_SIGKILL 9
#define TREEFORGE_BOOTSTRAP_SIGTERM 15
#define TREEFORGE_BOOTSTRAP_SIGCHLD 17

#define TREEFORGE_BOOTSTRAP_WAIT_WNOHANG 1


#define TREEFORGE_BOOTSTRAP_TRANSITION_FAILURE_PATH \
    "/metadata/treeforge-bootstrap/last-transition-failure"




static int tfb_string_equal(
    const char *left,
    const char *right
) {
    if (!left || !right) {
        return 0;
    }

    while (*left && *right) {
        if (*left != *right) {
            return 0;
        }

        left++;
        right++;
    }

    return (
        *left == 0
        && *right == 0
    );
}


static int tfb_probe_readable_path(
    const char *path
) {
    long fd = tfb_open(
        path,
        O_RDONLY
        | O_NONBLOCK
    );

    if (fd < 0) {
        return 0;
    }

    tfb_close(
        fd
    );

    return 1;
}


static void tfb_create_presence_marker(
    const char *path
) {
    long fd = tfb_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long) path,
        O_WRONLY
        | O_CREAT
        | O_TRUNC,
        0644
    );

    if (fd >= 0) {
        tfb_close(
            fd
        );
    }
}






static void tfb_record_transition_failure(
    const char *reason
) {
    /*
     * Transition diagnostics are TreeForge Bootstrap-owned userspace evidence.
     *
     * /metadata may not be available for failures that occur before
     * Android first stage mounts it, so this path is strictly
     * best-effort and must never become a new boot dependency.
     */
    tfb_syscall3(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long) "/metadata/treeforge-bootstrap",
        0755
    );

    long fd = tfb_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long) TREEFORGE_BOOTSTRAP_TRANSITION_FAILURE_PATH,
        O_WRONLY
        | O_CREAT
        | O_TRUNC,
        0644
    );

    if (fd < 0) {
        return;
    }

    tfb_write_all(
        fd,
        "treeforge-bootstrap-transition-failure-v1\n"
        "reason="
    );

    tfb_write_all(
        fd,
        (
            reason
            ? reason
            : "unknown"
        )
    );

    tfb_write_all(
        fd,
        "\n"
    );

    tfb_close(
        fd
    );

    tfb_syscall1(
        SYS_SYNC,
        0
    );
}


__TREEFORGE_FRAMEBUFFER_TRANSPORT_SOURCE__


static const char *tfb_transition_failure_display_reason(
    const char *reason
) {
    if (!reason) {
        return "UNKNOWN";
    }

    if (
        tfb_string_equal(
            reason,
            "invalid-treeforge-bootstrap-reentry"
        )
    ) {
        return "INVALID REENTRY";
    }

    if (
        tfb_string_equal(
            reason,
            "treeforge-bootstrap-runtime-materialize"
        )
    ) {
        return "RUNTIME MATERIALIZE";
    }

    if (
        tfb_string_equal(
            reason,
            "treeforge-bootstrap-adb-service-clone"
        )
    ) {
        return "ADB SERVICE CLONE";
    }

    if (
        tfb_string_equal(
            reason,
            "transition-fd-open"
        )
    ) {
        return "TRANSITION FD OPEN";
    }

    if (
        tfb_string_equal(
            reason,
            "transition-fd-duplicate"
        )
    ) {
        return "TRANSITION FD DUPLICATE";
    }

    if (
        tfb_string_equal(
            reason,
            "first-stage-exec"
        )
    ) {
        return "FIRST STAGE EXEC";
    }

    if (
        tfb_string_equal(
            reason,
            "bootloader-reboot-returned"
        )
    ) {
        return "BOOTLOADER REBOOT RETURNED";
    }

    if (
        tfb_string_equal(
            reason,
            "android-slot-a-env"
        )
    ) {
        return "ANDROID SLOT A ENV";
    }

    if (
        tfb_string_equal(
            reason,
            "android-slot-a-exec"
        )
    ) {
        return "ANDROID SLOT A EXEC";
    }

    if (
        tfb_string_equal(
            reason,
            "transaction-v2-error"
        )
    ) {
        return "TRANSACTION V2 ERROR";
    }

    return "UNMAPPED FAILURE REASON";
}

static void tfb_render_transition_failure(
    const char *reason
) {
    const char *display_reason = (
        tfb_transition_failure_display_reason(
            reason
        )
    );

    /*
     * Console/TTY path remains useful even if KMS setup fails.
     */
    tfb_output(
        "\033[2J\033[H"
        "TreeForge Bootstrap Boot Failure\n\n"
        "reason="
    );

    tfb_output(
        reason
        ? reason
        : "unknown"
    );

    if (
        reason
        && tfb_string_equal(
            reason,
            "treeforge-bootstrap-runtime-materialize"
        )
    ) {
        tfb_output(
            "\nstage="
        );

        tfb_output(
            tfb_runtime_materialize_failure_stage
        );

        tfb_output(
            "\nerror="
        );

        tfb_output(
            tfb_copy_fd_failure_code_name(
                tfb_copy_fd_failure_code
            )
        );

        tfb_output(
            "\nsource="
        );

        tfb_output(
            tfb_runtime_materialize_failure_source_path
            ? tfb_runtime_materialize_failure_source_path
            : "unknown"
        );

        tfb_output(
            "\ndestination="
        );

        tfb_output(
            tfb_runtime_materialize_failure_path
            ? tfb_runtime_materialize_failure_path
            : "unknown"
        );

        tfb_output(
            "\n"
        );
    }

    tfb_output(
        "\n"
        "HALTED FOR DIAGNOSTICS\n"
        "FORCE REBOOT WHEN DONE\n"
    );

    if (
        !tfb_fb_menu_active
        || tfb_fb_menu_mapped_address < 0
    ) {
        return;
    }

    const u32 background = 0x00000000U;
    const u32 foreground = 0x00ffffffU;

    tfb_fb_fill_rect(
        0,
        0,
        tfb_fb_menu_width,
        tfb_fb_menu_height,
        background
    );

    u32 scale = (
        tfb_fb_menu_width
        / 160U
    );

    u32 height_scale = (
        tfb_fb_menu_height
        / 220U
    );

    if (height_scale < scale) {
        scale = height_scale;
    }

    if (scale < 2U) {
        scale = 2U;
    }

    if (scale > 8U) {
        scale = 8U;
    }

    tfb_fb_draw_management_line(
        "TREEFORGE MENU",
        18U * scale,
        scale,
        foreground
    );

    tfb_fb_draw_management_line(
        "BOOT FAILURE",
        46U * scale,
        scale,
        foreground
    );

    tfb_fb_draw_management_line(
        "REASON",
        76U * scale,
        scale,
        foreground
    );

    tfb_fb_draw_management_line(
        display_reason,
        94U * scale,
        scale,
        foreground
    );

    if (
        reason
        && tfb_string_equal(
            reason,
            "treeforge-bootstrap-runtime-materialize"
        )
    ) {
        tfb_fb_draw_management_line(
            tfb_runtime_materialize_failure_stage,
            112U * scale,
            scale,
            foreground
        );

        tfb_fb_draw_management_line(
            tfb_copy_fd_failure_code_name(
                tfb_copy_fd_failure_code
            ),
            128U * scale,
            scale,
            foreground
        );

        tfb_fb_draw_management_line(
            tfb_runtime_materialize_failure_source_path
            ? tfb_runtime_materialize_failure_source_path
            : "UNKNOWN SOURCE",
            146U * scale,
            scale,
            foreground
        );

        tfb_fb_draw_management_line(
            tfb_runtime_materialize_failure_path
            ? tfb_runtime_materialize_failure_path
            : "UNKNOWN DESTINATION",
            164U * scale,
            scale,
            foreground
        );
    }

    tfb_fb_draw_management_line(
        "HALTED FOR DIAGNOSTICS",
        188U * scale,
        scale,
        foreground
    );

    tfb_fb_draw_management_line(
        "FORCE REBOOT WHEN DONE",
        204U * scale,
        scale,
        foreground
    );
}


__attribute__((noreturn))
static void tfb_transition_failure(
    const char *reason
) {
    /*
     * execve() failure may occur after the ordinary TreeForge Bootstrap kmsg
     * descriptor was deliberately closed for Android handoff.
     * Reopen /dev/kmsg best-effort on the failure-only path so the
     * diagnostic descriptor can never leak into successful Android.
     */
    long failure_kmsg = tfb_kmsg;
    int close_failure_kmsg = 0;

    if (failure_kmsg < 0) {
        failure_kmsg = tfb_open(
            "/dev/kmsg",
            O_WRONLY
            | O_NONBLOCK
        );

        if (failure_kmsg >= 0) {
            close_failure_kmsg = 1;
        }
    }

    tfb_write_all(
        failure_kmsg,
        "TreeForge Bootstrap: transition-failure reason="
    );

    tfb_write_all(
        failure_kmsg,
        (
            reason
            ? reason
            : "unknown"
        )
    );

    tfb_write_all(
        failure_kmsg,
        "\n"
    );

    if (close_failure_kmsg) {
        tfb_close(
            failure_kmsg
        );
    }

    tfb_record_transition_failure(
        reason
    );


    if (!tfb_fb_menu_active) {
        tfb_probe_display_surfaces();
    }

    tfb_render_transition_failure(
        reason
    );

    for (;;) {
        tfb_sleep_ms(
            1000
        );
    }
}


static void tfb_prepare_shell_compat(void) {
    const char *busybox =
        "/dev/treeforge-bootstrap-runtime/system/bin/busybox";

    if (
        !tfb_probe_readable_path(
            busybox
        )
    ) {
        tfb_log(
            "treeforge-bootstrap-shell=busybox-missing"
        );

        return;
    }

    tfb_syscall3(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long) "/bin",
        0755
    );

    tfb_syscall3(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long) "/system",
        0755
    );

    tfb_syscall3(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long) "/system/bin",
        0755
    );

    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long) "/bin/sh",
        0
    );

    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long) "/system/bin/sh",
        0
    );

    long bin_shell = tfb_syscall3(
        SYS_SYMLINKAT,
        (long) busybox,
        AT_FDCWD,
        (long) "/bin/sh"
    );

    long system_shell = tfb_syscall3(
        SYS_SYMLINKAT,
        (long) busybox,
        AT_FDCWD,
        (long) "/system/bin/sh"
    );

    if (
        bin_shell >= 0
        && system_shell >= 0
        && tfb_probe_readable_path(
            "/bin/sh"
        )
        && tfb_probe_readable_path(
            "/system/bin/sh"
        )
    ) {
        tfb_log(
            "treeforge-bootstrap-shell=ready"
        );
    } else {
        tfb_log(
            "treeforge-bootstrap-shell=compat-failed"
        );
    }
}


/*
 * ================================================================
 * TFB_TOUCHSCREEN_MODULE_REALIZATION_V14
 * ================================================================
 *
 * Google FirstStageMain has already mounted the matching tangorpro
 * vendor/vendor_dlkm module tree and realized the common GS201
 * dependency base.
 *
 * Hardware acceptance proved that the remaining cold-boot touch
 * roots are:
 *
 *   goog_usi_stylus.ko
 *   goog_touch_interface.ko
 *   nvt_touch.ko
 *
 * Resolve them from the coherent live /vendor_dlkm module tree using
 * uname -r and the retained TreeForge BusyBox provider. Never duplicate
 * these kernel modules into the Bootstrap runtime.
 *
 * This path is deliberately non-fatal.  Volume Up/Down/Power remain
 * the recovery input path if touchscreen realization fails.
 */

static int tfb_busybox_insmod_if_missing(
    const char *module_state,
    const char *module_path,
    const char *already_log,
    const char *loaded_log,
    const char *failed_log,
    char **envp
) {
    static const char busybox[] =
        "/dev/treeforge-bootstrap-runtime/"
        "system/bin/busybox";

    if (
        tfb_probe_readable_path(
            module_state
        )
    ) {
        tfb_log(
            already_log
        );

        return 1;
    }

    if (
        !tfb_probe_readable_path(
            busybox
        )
    ) {
        tfb_log(
            failed_log
        );

        return 0;
    }

    long child = tfb_syscall6(
        SYS_CLONE,
        TREEFORGE_BOOTSTRAP_SIGCHLD,
        0,
        0,
        0,
        0,
        0
    );

    if (child < 0) {
        tfb_log(
            failed_log
        );

        return 0;
    }

    if (child == 0) {
        char *argv[] = {
            (char *) busybox,
            (char *) "sh",
            (char *) "-c",
            (char *) module_path,
            0
        };

        tfb_syscall3(
            SYS_EXECVE,
            (long) busybox,
            (long) argv,
            (long) envp
        );

        tfb_syscall1(
            SYS_EXIT,
            127
        );

        for (;;) {
        }
    }

    int status = 0;

    long waited = tfb_syscall4(
        SYS_WAIT4,
        child,
        (long) &status,
        0,
        0
    );

    if (
        waited != child
        || status != 0
        || !tfb_probe_readable_path(
            module_state
        )
    ) {
        tfb_log(
            failed_log
        );

        return 0;
    }

    tfb_log(
        loaded_log
    );

    return 1;
}


static int tfb_realize_touchscreen_modules(
    char **envp
) {
    if (
        !tfb_busybox_insmod_if_missing(
            "/sys/module/goog_usi_stylus",
            "exec /dev/treeforge-bootstrap-runtime/system/bin/busybox insmod /vendor_dlkm/lib/modules/goog_usi_stylus.ko",
            "touchscreen module=goog_usi_stylus state=already-loaded",
            "touchscreen module=goog_usi_stylus state=loaded",
            "touchscreen module=goog_usi_stylus state=failed",
            envp
        )
    ) {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-touchscreen-degraded"
        );

        tfb_log(
            "touchscreen realization=degraded"
        );

        return 0;
    }

    if (
        !tfb_busybox_insmod_if_missing(
            "/sys/module/goog_touch_interface",
            "exec /dev/treeforge-bootstrap-runtime/system/bin/busybox insmod /vendor_dlkm/lib/modules/goog_touch_interface.ko",
            "touchscreen module=goog_touch_interface state=already-loaded",
            "touchscreen module=goog_touch_interface state=loaded",
            "touchscreen module=goog_touch_interface state=failed",
            envp
        )
    ) {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-touchscreen-degraded"
        );

        tfb_log(
            "touchscreen realization=degraded"
        );

        return 0;
    }

    if (
        !tfb_busybox_insmod_if_missing(
            "/sys/module/nvt_touch",
            "exec /dev/treeforge-bootstrap-runtime/system/bin/busybox insmod /vendor_dlkm/lib/modules/nvt_touch.ko",
            "touchscreen module=nvt_touch state=already-loaded",
            "touchscreen module=nvt_touch state=loaded",
            "touchscreen module=nvt_touch state=failed",
            envp
        )
    ) {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-touchscreen-degraded"
        );

        tfb_log(
            "touchscreen realization=degraded"
        );

        return 0;
    }

    /*
     * nvt_touch registration/probe is synchronous with insmod, but
     * leave a short deterministic settle window for its input-device
     * publication before tfb_run_menu() scans /sys/class/input.
     */
    tfb_sleep_ms(
        250
    );

    tfb_create_presence_marker(
        "/dev/treeforge-bootstrap-touchscreen-ready"
    );

    tfb_log(
        "touchscreen realization=ready"
    );

    return 1;
}


static void tfb_request_adb_reset(
    void
) {
    if (
        tfb_adb_marker_exists(
            TFB_ADB_RESTARTING
        )
    ) {
        tfb_log(
            "early-menu adb-reset=already-restarting"
        );

        return;
    }

    static const char *errors[] = {
        TFB_ADB_ERROR_B_SESSION,
        TFB_ADB_ERROR_UDC,
        TFB_ADB_ERROR_CONFIGFS,
        TFB_ADB_ERROR_FFS,
        TFB_ADB_ERROR_ADBD,
        TFB_ADB_ERROR_LINK,
        TFB_ADB_ERROR_BIND,
        TFB_ADB_ERROR_UNKNOWN,
        0
    };

    for (
        int index = 0;
        errors[index];
        index++
    ) {
        tfb_syscall3(
            SYS_UNLINKAT,
            AT_FDCWD,
            (long) errors[index],
            0
        );
    }

    /*
     * Publish RESTARTING first so the UI can reflect the request on
     * the next menu-loop redraw even before the service consumes it.
     */
    tfb_create_presence_marker(
        TFB_ADB_RESTARTING
    );

    tfb_create_presence_marker(
        TFB_ADB_RESET_REQUEST
    );

    tfb_log(
        "early-menu adb-reset=requested"
    );
}


static long tfb_adb_service_pid = -1;


static void tfb_start_adb_service(
    char **envp
) {
    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)
            "/dev/treeforge-bootstrap-adb-stop",
        0
    );

    long child = tfb_syscall6(
        SYS_CLONE,
        TREEFORGE_BOOTSTRAP_SIGCHLD,
        0,
        0,
        0,
        0,
        0
    );

    if (child < 0) {
        tfb_transition_failure(
            "treeforge-bootstrap-adb-service-clone"
        );
    }

    if (child == 0) {
        /* TFB_ANDROID_USB_PROCESS_GROUP_V4_1 */
        tfb_syscall2(
            SYS_SETPGID,
            0,
            0
        );

        char *argv[] = {
            (char *)
                "/dev/treeforge-bootstrap-runtime/"
                "treeforge-bootstrap-adb-service",
            0
        };

        tfb_close(
            tfb_tty
        );

        tfb_close(
            tfb_console
        );

        tfb_close(
            tfb_kmsg
        );

        tfb_syscall3(
            SYS_EXECVE,
            (long)
                "/dev/treeforge-bootstrap-runtime/"
                "treeforge-bootstrap-adb-service",
            (long) argv,
            (long) envp
        );

        tfb_syscall1(
            SYS_EXIT,
            127
        );

        for (;;) {
        }
    }

    /* Close the clone/setpgid race from the parent too. */
    tfb_syscall2(
        SYS_SETPGID,
        child,
        child
    );

    tfb_adb_service_pid =
        child;

    tfb_log(
        "treeforge-bootstrap-adb-service=started"
    );
}


static void tfb_stop_adb_service(
    void
) {
    if (
        tfb_adb_service_pid
        <= 0
    ) {
        return;
    }

    tfb_create_presence_marker(
        "/dev/treeforge-bootstrap-adb-stop"
    );

    int status = 0;

    for (
        int attempt = 0;
        attempt < 80;
        attempt++
    ) {
        long result = tfb_syscall4(
            SYS_WAIT4,
            tfb_adb_service_pid,
            (long) &status,
            TREEFORGE_BOOTSTRAP_WAIT_WNOHANG,
            0
        );

        if (
            result
            == tfb_adb_service_pid
        ) {
            tfb_adb_service_pid = -1;
            return;
        }

        tfb_sleep_ms(
            25
        );
    }

    tfb_syscall2(
        SYS_KILL,
        -tfb_adb_service_pid,
        TREEFORGE_BOOTSTRAP_SIGTERM
    );

    for (
        int attempt = 0;
        attempt < 20;
        attempt++
    ) {
        long result = tfb_syscall4(
            SYS_WAIT4,
            tfb_adb_service_pid,
            (long) &status,
            TREEFORGE_BOOTSTRAP_WAIT_WNOHANG,
            0
        );

        if (
            result
            == tfb_adb_service_pid
        ) {
            tfb_adb_service_pid = -1;
            return;
        }

        tfb_sleep_ms(
            25
        );
    }

    tfb_syscall2(
        SYS_KILL,
        -tfb_adb_service_pid,
        TREEFORGE_BOOTSTRAP_SIGKILL
    );

    tfb_syscall4(
        SYS_WAIT4,
        tfb_adb_service_pid,
        (long) &status,
        0,
        0
    );

    tfb_adb_service_pid = -1;
}




static void tfb_release_adb_usb_resources_for_android(
    void
) {
    /*
     * TFB_ANDROID_USB_SURGICAL_RELEASE_V4_2
     *
     * Release only TreeForge's temporary ADB ownership.
     * Android retains ownership of the configfs gadget hierarchy.
     */

    tfb_log(
        "android-usb-handoff=surgical-release-begin"
    );

    long udc_fd = tfb_syscall3(
        SYS_OPENAT,
        AT_FDCWD,
        (long)
            "/config/usb_gadget/g1/UDC",
        O_WRONLY
    );

    if (udc_fd >= 0) {
        static const char empty_udc[] = "\n";

        tfb_syscall3(
            SYS_WRITE,
            udc_fd,
            (long) empty_udc,
            1
        );

        tfb_syscall1(
            SYS_CLOSE,
            udc_fd
        );
    }

    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)
            "/config/usb_gadget/g1/configs/b.1/f1",
        0
    );

    tfb_syscall2(
        SYS_UMOUNT2,
        (long)
            "/dev/usb-ffs/adb",
        MNT_DETACH
    );

    /*
     * Bootstrap created these mountpoints before SELinux setup, so
     * they still carry /dev tmpfs's generic tmpfs context. Leaving
     * the parent behind prevents Android vendor_init from creating
     * its MTP/PTP mountpoints. After detaching our FunctionFS mount,
     * remove only the empty directories so Android can recreate them
     * with its own file contexts. AT_REMOVEDIR preserves any nonempty
     * directory; the configfs gadget object remains intact.
     */
    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)
            "/dev/usb-ffs/adb",
        AT_REMOVEDIR
    );

    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)
            "/dev/usb-ffs",
        AT_REMOVEDIR
    );

    tfb_sleep_ms(
        100
    );

    tfb_log(
        "android-usb-handoff=surgical-release-end"
    );
}

/*
 * ================================================================
 * TFB_ANDROID_TRANSITION_SCREEN_V17_2
 * ================================================================
 *
 * This is intentionally a static handoff frame, not simulated boot
 * progress. TreeForge ceases execution after the Android init exec,
 * so the final frame simply remains in scanout until Android takes
 * display ownership.
 */
static void tfb_ui_draw_transition_centered_text(
    const char *value,
    u32 y,
    u32 scale,
    u32 pixel
) {
    if (
        !value
        || scale == 0
    ) {
        return;
    }

    u32 width = (
        tfb_fb_text_width(
            value,
            scale
        )
    );

    u32 x = (
        TFB_UI_LOGICAL_WIDTH > width
        ? (
            TFB_UI_LOGICAL_WIDTH
            - width
        ) / 2U
        : 0U
    );

    tfb_ui_draw_text(
        x,
        y,
        value,
        scale,
        pixel
    );
}


static void tfb_render_android_transition(
    void
) {
    if (
        !tfb_fb_menu_active
        || tfb_fb_menu_mapped_address < 0
        || !tfb_ui_landscape_supported()
    ) {
        tfb_log(
            "android-transition-screen=unavailable"
        );

        return;
    }

    const u32 background =
        0x00060b12U;

    const u32 panel =
        0x000c1621U;

    const u32 foreground =
        0x00f4f8fbU;

    const u32 dim =
        0x008ca0b0U;

    const u32 accent =
        0x0000d4eeU;

    /*
     * Replace the complete menu with one deliberate handoff frame.
     */
    tfb_ui_fill_rect(
        0U,
        0U,
        TFB_UI_LOGICAL_WIDTH,
        TFB_UI_LOGICAL_HEIGHT,
        background
    );

    /*
     * Subtle central panel keeps visual continuity with the V17 menu.
     */
    tfb_ui_fill_rect(
        500U,
        300U,
        1560U,
        1000U,
        panel
    );

    tfb_ui_outline_rect(
        500U,
        300U,
        1560U,
        1000U,
        4U,
        0x00283d4dU
    );

    tfb_ui_draw_transition_centered_text(
        "TREEFORGE",
        470U,
        8U,
        accent
    );

    tfb_ui_fill_rect(
        820U,
        610U,
        920U,
        4U,
        accent
    );

    tfb_ui_draw_transition_centered_text(
        "STARTING ANDROID",
        690U,
        7U,
        foreground
    );

    tfb_ui_draw_transition_centered_text(
        "SLOT A",
        850U,
        4U,
        accent
    );

    tfb_ui_draw_transition_centered_text(
        "HANDING OFF TO ANDROID",
        970U,
        3U,
        dim
    );

    tfb_log(
        "TFB_ANDROID_TRANSITION_SCREEN_V17_2"
    );
}


static void tfb_menu_cleanup_for_transition(
    long *inputs,
    int created_input_directory,
    int *created_input_nodes
) {

    tfb_stop_adb_service();

    tfb_release_adb_usb_resources_for_android();

    tfb_fb_menu_cleanup();

    tfb_close_inputs(
        inputs
    );

    tfb_cleanup_realized_input_nodes(
        created_input_directory,
        created_input_nodes
    );

    tfb_close(
        tfb_tty
    );

    tfb_tty = -1;

    tfb_close(
        tfb_console
    );

    tfb_console = -1;

    tfb_close(
        tfb_kmsg
    );

    tfb_kmsg = -1;
}



/*
 * ================================================================
 * TFB_LIVE_CONSOLE_V1
 * ================================================================
 *
 * Read-only, on-device diagnostics console.
 *
 * Source:
 *
 *     /dev/kmsg
 *
 * The viewer owns no USB state and performs no ADB operation.
 * TreeForge diagnostics emitted through tfb_log()/persistent kernel
 * logging therefore remain visible even if the host USB session is
 * lost.
 *
 * Controls:
 *
 *     Volume Up    scroll toward older records
 *     Volume Down  scroll toward newer records
 *     Power        return to Maintenance
 *
 * Touch events are deliberately ignored in V1.
 */

#define TFB_LIVE_CONSOLE_LINES 64
#define TFB_LIVE_CONSOLE_LINE_BYTES 192
#define TFB_LIVE_CONSOLE_VISIBLE_LINES 42
#define TFB_LIVE_CONSOLE_SCROLL_STEP 4


static char tfb_live_console_lines[
    TFB_LIVE_CONSOLE_LINES
][
    TFB_LIVE_CONSOLE_LINE_BYTES
];

static int tfb_live_console_count = 0;
static int tfb_live_console_next = 0;


static int tfb_live_console_max_scroll(
    void
) {
    if (
        tfb_live_console_count
        <= TFB_LIVE_CONSOLE_VISIBLE_LINES
    ) {
        return 0;
    }

    return (
        tfb_live_console_count
        - TFB_LIVE_CONSOLE_VISIBLE_LINES
    );
}


static void tfb_live_console_append(
    const char *record,
    int *scroll
) {
    if (!record) {
        return;
    }

    const char *message =
        record;

    /*
     * /dev/kmsg records use:
     *
     *     level,sequence,timestamp,flags;message
     *
     * Display the message payload while retaining the exact kernel
     * text after the metadata separator.
     */
    for (
        int index = 0;
        record[index] != '\0';
        index++
    ) {
        if (
            record[index]
            == ';'
        ) {
            message = (
                &record[index + 1]
            );

            break;
        }
    }

    char *destination = (
        tfb_live_console_lines[
            tfb_live_console_next
        ]
    );

    int position = 0;

    while (
        message[position] != '\0'
        && position
            < TFB_LIVE_CONSOLE_LINE_BYTES
                - 1
    ) {
        char value =
            message[position];

        if (
            value == '\n'
            || value == '\r'
        ) {
            break;
        }

        if (value == '\t') {
            value = ' ';
        }

        if (
            value < 32
            || value > 126
        ) {
            value = '.';
        }

        destination[position] =
            value;

        position++;
    }

    destination[position] = '\0';

    if (position == 0) {
        destination[0] = ' ';
        destination[1] = '\0';
    }

    tfb_live_console_next = (
        tfb_live_console_next
        + 1
    ) % TFB_LIVE_CONSOLE_LINES;

    if (
        tfb_live_console_count
        < TFB_LIVE_CONSOLE_LINES
    ) {
        tfb_live_console_count++;
    }

    /*
     * When the user has scrolled away from the live tail, preserve
     * roughly the same historical viewport as new records arrive.
     */
    if (
        scroll
        && *scroll > 0
    ) {
        int maximum =
            tfb_live_console_max_scroll();

        if (*scroll < maximum) {
            (*scroll)++;
        }
    }
}


static const char *tfb_live_console_line(
    int logical_index
) {
    if (
        logical_index < 0
        || logical_index
            >= tfb_live_console_count
    ) {
        return "";
    }

    int oldest = 0;

    if (
        tfb_live_console_count
        == TFB_LIVE_CONSOLE_LINES
    ) {
        oldest =
            tfb_live_console_next;
    }

    int physical = (
        oldest
        + logical_index
    ) % TFB_LIVE_CONSOLE_LINES;

    return (
        tfb_live_console_lines[
            physical
        ]
    );
}


static void tfb_live_console_render(
    int scroll,
    int kmsg_available
) {
    const u32 background =
        0x00000000U;

    const u32 foreground =
        0x00e8eef2U;

    const u32 dim =
        0x008ca0b0U;

    const u32 accent =
        0x0000d4eeU;

    const u32 green =
        0x004ed87dU;

    const u32 warning =
        0x00e4c45cU;

    if (
        !tfb_fb_menu_active
        || tfb_fb_menu_mapped_address < 0
    ) {
        return;
    }

    if (
        !tfb_ui_landscape_supported()
    ) {
        tfb_fb_fill_rect(
            0,
            0,
            tfb_fb_menu_width,
            tfb_fb_menu_height,
            background
        );

        tfb_fb_draw_text(
            24U,
            24U,
            "TREEFORGE LIVE CONSOLE",
            3U,
            0x00ffffffU
        );

        tfb_fb_draw_text(
            24U,
            72U,
            "LANDSCAPE GEOMETRY UNSUPPORTED",
            2U,
            0x00ffffffU
        );

        return;
    }

    tfb_ui_fill_rect(
        0U,
        0U,
        TFB_UI_LOGICAL_WIDTH,
        TFB_UI_LOGICAL_HEIGHT,
        background
    );

    tfb_ui_draw_text(
        80U,
        48U,
        "TREEFORGE LIVE CONSOLE",
        5U,
        accent
    );

    tfb_ui_draw_text(
        80U,
        108U,
        (
            kmsg_available
            ? (
                tfb_adb_connected()
                ? "KERNEL LOG: LIVE    ADB: CONNECTED"
                : "KERNEL LOG: LIVE    ADB/USB: NOT CONFIGURED"
            )
            : "KERNEL LOG: UNAVAILABLE"
        ),
        3U,
        (
            kmsg_available
            ? (
                tfb_adb_connected()
                ? green
                : warning
            )
            : warning
        )
    );

    tfb_ui_draw_text(
        80U,
        154U,
        (
            scroll == 0
            ? "VIEW: LIVE TAIL"
            : "VIEW: SCROLLED / AUTO-FOLLOW PAUSED"
        ),
        2U,
        dim
    );

    int maximum =
        tfb_live_console_max_scroll();

    if (scroll > maximum) {
        scroll = maximum;
    }

    if (scroll < 0) {
        scroll = 0;
    }

    int end = (
        tfb_live_console_count
        - scroll
    );

    if (end < 0) {
        end = 0;
    }

    int start = (
        end
        - TFB_LIVE_CONSOLE_VISIBLE_LINES
    );

    if (start < 0) {
        start = 0;
    }

    u32 y = 218U;

    for (
        int index = start;
        index < end;
        index++
    ) {
        tfb_ui_draw_text(
            80U,
            y,
            tfb_live_console_line(
                index
            ),
            2U,
            foreground
        );

        y += 29U;
    }

    tfb_ui_fill_rect(
        0U,
        1502U,
        TFB_UI_LOGICAL_WIDTH,
        98U,
        0x00060b12U
    );

    tfb_ui_draw_text(
        80U,
        1530U,
        "VOL UP/DOWN: SCROLL    POWER: BACK",
        3U,
        dim
    );
}


static void tfb_live_console_run(
    long *inputs
) {
    tfb_log(
        "TFB_LIVE_CONSOLE_V1 enter"
    );

    /*
     * Start every visit at the live tail but retain the ring itself so
     * leaving/re-entering the viewer does not erase captured evidence.
     */
    int scroll = 0;
    int redraw = 1;

    long kmsg = tfb_open(
        "/dev/kmsg",
        O_RDONLY
        | O_NONBLOCK
    );

    int kmsg_available = (
        kmsg >= 0
    );

    if (!kmsg_available) {
        tfb_log(
            "TFB_LIVE_CONSOLE_V1 kmsg-open-failed"
        );
    } else {
        tfb_log(
            "TFB_LIVE_CONSOLE_V1 kmsg-open-ok"
        );
    }

    int last_adb_state =
        tfb_adb_connected();

    for (;;) {
        /*
         * Drain a bounded amount of kernel backlog per iteration.
         * A separate /dev/kmsg descriptor has its own reader cursor and
         * does not consume TreeForge's writer descriptor.
         */
        if (kmsg_available) {
            for (
                int record_index = 0;
                record_index < 256;
                record_index++
            ) {
                char record[512];

                long amount = (
                    tfb_syscall3(
                        SYS_READ,
                        kmsg,
                        (long) record,
                        (long) (
                            sizeof(record) - 1
                        )
                    )
                );

                if (amount <= 0) {
                    break;
                }

                record[amount] = '\0';

                tfb_live_console_append(
                    record,
                    &scroll
                );

                redraw = 1;
            }
        }

        int adb_state =
            tfb_adb_connected();

        if (
            adb_state
            != last_adb_state
        ) {
            last_adb_state =
                adb_state;

            redraw = 1;
        }

        if (inputs) {
            for (
                int input_index = 0;
                input_index < INPUT_COUNT;
                input_index++
            ) {
                if (
                    inputs[input_index]
                    < 0
                ) {
                    continue;
                }

                for (;;) {
                    struct tfb_input_event
                        event;

                    long amount = (
                        tfb_syscall3(
                            SYS_READ,
                            inputs[input_index],
                            (long) &event,
                            (long)
                                sizeof(event)
                        )
                    );

                    if (
                        amount
                        != (long)
                            sizeof(event)
                    ) {
                        break;
                    }

                    if (
                        event.type != EV_KEY
                        || event.value != 1
                    ) {
                        continue;
                    }

                    if (
                        event.code
                        == KEY_VOLUMEUP
                    ) {
                        int maximum =
                            tfb_live_console_max_scroll();

                        scroll +=
                            TFB_LIVE_CONSOLE_SCROLL_STEP;

                        if (
                            scroll > maximum
                        ) {
                            scroll =
                                maximum;
                        }

                        redraw = 1;

                        continue;
                    }

                    if (
                        event.code
                        == KEY_VOLUMEDOWN
                    ) {
                        scroll -=
                            TFB_LIVE_CONSOLE_SCROLL_STEP;

                        if (scroll < 0) {
                            scroll = 0;
                        }

                        redraw = 1;

                        continue;
                    }

                    if (
                        event.code
                        != KEY_POWER
                    ) {
                        continue;
                    }

                    if (kmsg >= 0) {
                        tfb_close(
                            kmsg
                        );

                        kmsg = -1;
                    }

                    tfb_log(
                        "TFB_LIVE_CONSOLE_V1 exit"
                    );

                    return;
                }
            }
        }

        if (redraw) {
            tfb_live_console_render(
                scroll,
                kmsg_available
            );

            redraw = 0;
        }

        tfb_sleep_ms(
            POLL_INTERVAL_MS
        );
    }
}




/*
 * ================================================================
 * TFB_ALTROOT_PID1_PIVOT_V1
 * ================================================================
 *
 * Storage-backed same-kernel alternate userspace handoff.
 *
 * Pixel Partitioner owns treeforge_os.  Bootstrap mounts the rootfs,
 * validates the accepted handoff contract, prepares the mount
 * namespace, pivot_root()s into it, detaches the old Android root,
 * and executes the rootfs-native /init as PID 1.
 *
 * No kexec.
 * No GPT changes.
 * No slot mutation.
 * No embedded alternate-root payload.
 */

#define TFB_ALTROOT_ROOT \
    "/mnt/treeforge-altroot"

#define TFB_ALTROOT_STORAGE \
    "/dev/block/by-name/treeforge_os"

#define TFB_ALTROOT_STORAGE_FS \
    "ext4"

#define TFB_ALTROOT_LOADER_BUSYBOX \
    "/dev/treeforge-bootstrap-runtime/system/bin/busybox"

#ifndef TFB_MS_BIND
#define TFB_MS_BIND 4096UL
#endif

#ifndef TFB_MS_REC
#define TFB_MS_REC 16384UL
#endif

#ifndef TFB_MS_PRIVATE
#define TFB_MS_PRIVATE 262144UL
#endif

#ifndef TFB_MNT_DETACH
#define TFB_MNT_DETACH 2
#endif

#ifndef TFB_EEXIST
#define TFB_EEXIST 17
#endif

/*
 * Block realization is implemented later with the Pixel Partitioner
 * block-runtime helpers. Alternate-OS boot uses the same generic
 * realization primitive without activating Pixel Partitioner.
 */
static int tfb_realize_block_nodes(void);


static long tfb_altroot_mount(
    const char *source,
    const char *target,
    const char *filesystem,
    unsigned long flags,
    const char *data
) {
    return tfb_syscall6(
        SYS_MOUNT,
        (long) source,
        (long) target,
        (long) filesystem,
        (long) flags,
        (long) data,
        0
    );
}


static int tfb_altroot_mkdir(
    const char *path,
    long mode
) {
    long result = tfb_syscall3(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long) path,
        mode
    );

    return (
        result >= 0
        || result == -TFB_EEXIST
    );
}


static void tfb_altos_cleanup(void);

static void tfb_altroot_cleanup_partial(
    void
) {
    tfb_altos_cleanup();
    tfb_syscall2(
        SYS_UMOUNT2,
        (long) TFB_ALTROOT_ROOT,
        TFB_MNT_DETACH
    );
}


static const char *tfb_altroot_init_path =
    "/init";


/*
 * TFB_ALTROOT_IDENTITY_V1
 *
 * Read operating-system identity from the OS itself.
 *
 * Supported contracts, in preference order:
 *
 *   /etc/treeforge-release  optional TreeForge extension
 *   /etc/os-release         standard Linux identity
 *   /etc/lsb-release        additional distro/build metadata
 *
 * Missing fields remain empty and are omitted from the UI.
 */
static void tfb_altroot_identity_clear(
    void
) {
    tfb_menu_state
        .alternate_os_detected_name[0] =
        '\0';

    tfb_menu_state
        .alternate_os_version[0] =
        '\0';

    tfb_menu_state
        .alternate_os_build[0] =
        '\0';

    tfb_menu_state
        .alternate_os_milestone[0] =
        '\0';

    tfb_menu_state
        .alternate_os_board[0] =
        '\0';
}


static int tfb_altroot_key_equal(
    const char *data,
    usize begin,
    usize end,
    const char *key
) {
    if (
        !data
        || !key
        || begin >= end
    ) {
        return 0;
    }

    usize position = begin;
    usize key_index = 0;

    while (
        position < end
        && key[key_index] != '\0'
    ) {
        if (
            data[position]
            != key[key_index]
        ) {
            return 0;
        }

        position++;
        key_index++;
    }

    return (
        position == end
        && key[key_index] == '\0'
    );
}


static int tfb_altroot_copy_value(
    const char *data,
    usize begin,
    usize end,
    char *output,
    usize capacity
) {
    if (
        !data
        || !output
        || capacity < 2
    ) {
        return 0;
    }

    while (
        begin < end
        && (
            data[begin] == ' '
            || data[begin] == '\t'
        )
    ) {
        begin++;
    }

    while (
        end > begin
        && (
            data[end - 1] == ' '
            || data[end - 1] == '\t'
        )
    ) {
        end--;
    }

    if (
        end > begin + 1
        && (
            (
                data[begin] == '"'
                && data[end - 1] == '"'
            )
            || (
                data[begin] == '\''
                && data[end - 1] == '\''
            )
        )
    ) {
        begin++;
        end--;
    }

    usize out = 0;

    while (
        begin < end
        && out + 1 < capacity
    ) {
        unsigned char value = (
            (unsigned char)
            data[begin]
        );

        if (
            value < 0x20
            || value > 0x7e
        ) {
            output[0] = '\0';
            return 0;
        }

        output[out++] =
            data[begin++];
    }

    output[out] =
        '\0';

    return out > 0;
}


static int tfb_altroot_read_release_value(
    const char *path,
    const char *key,
    char *output,
    usize capacity
) {
    if (
        !path
        || !key
        || !output
        || capacity < 2
    ) {
        return 0;
    }

    long fd = tfb_open(
        path,
        O_RDONLY
        | O_NONBLOCK
    );

    if (fd < 0) {
        return 0;
    }

    char data[4096];

    long amount = tfb_syscall3(
        SYS_READ,
        fd,
        (long) data,
        sizeof(data) - 1
    );

    tfb_close(
        fd
    );

    if (amount <= 0) {
        return 0;
    }

    usize length =
        (usize) amount;

    if (
        length
        >= sizeof(data)
    ) {
        length =
            sizeof(data) - 1;
    }

    data[length] =
        '\0';

    usize position = 0;

    while (
        position < length
    ) {
        usize line_begin =
            position;

        usize line_end =
            line_begin;

        while (
            line_end < length
            && data[line_end] != '\n'
            && data[line_end] != '\r'
        ) {
            line_end++;
        }

        position =
            line_end;

        while (
            position < length
            && (
                data[position] == '\n'
                || data[position] == '\r'
            )
        ) {
            position++;
        }

        while (
            line_begin < line_end
            && (
                data[line_begin] == ' '
                || data[line_begin] == '\t'
            )
        ) {
            line_begin++;
        }

        if (
            line_begin >= line_end
            || data[line_begin] == '#'
        ) {
            continue;
        }

        usize equal =
            line_begin;

        while (
            equal < line_end
            && data[equal] != '='
        ) {
            equal++;
        }

        if (
            equal >= line_end
        ) {
            continue;
        }

        usize key_end =
            equal;

        while (
            key_end > line_begin
            && (
                data[key_end - 1] == ' '
                || data[key_end - 1] == '\t'
            )
        ) {
            key_end--;
        }

        if (
            !tfb_altroot_key_equal(
                data,
                line_begin,
                key_end,
                key
            )
        ) {
            continue;
        }

        return (
            tfb_altroot_copy_value(
                data,
                equal + 1,
                line_end,
                output,
                capacity
            )
        );
    }

    return 0;
}


static void tfb_altroot_try_release_value(
    const char *path,
    const char *key,
    char *output,
    usize capacity
) {
    if (
        output
        && capacity > 1
        && output[0] == '\0'
    ) {
        tfb_altroot_read_release_value(
            path,
            key,
            output,
            capacity
        );
    }
}


static void tfb_altroot_copy_literal(
    char *output,
    usize capacity,
    const char *value
) {
    if (
        !output
        || capacity < 2
        || !value
    ) {
        return;
    }

    usize index = 0;

    while (
        value[index] != '\0'
        && index + 1 < capacity
    ) {
        output[index] =
            value[index];

        index++;
    }

    output[index] =
        '\0';
}


static void tfb_altroot_collect_identity(
    void
) {
    tfb_altroot_identity_clear();

    static const char treeforge_release[] =
        "/mnt/treeforge-altroot/etc/treeforge-release";

    static const char os_release[] =
        "/mnt/treeforge-altroot/etc/os-release";

    static const char lsb_release[] =
        "/mnt/treeforge-altroot/etc/lsb-release";

    /*
     * Optional TreeForge metadata contract.
     */
    tfb_altroot_try_release_value(
        treeforge_release,
        "TREEFORGE_OS_NAME",
        tfb_menu_state
            .alternate_os_detected_name,
        sizeof(
            tfb_menu_state
                .alternate_os_detected_name
        )
    );

    tfb_altroot_try_release_value(
        treeforge_release,
        "NAME",
        tfb_menu_state
            .alternate_os_detected_name,
        sizeof(
            tfb_menu_state
                .alternate_os_detected_name
        )
    );

    tfb_altroot_try_release_value(
        treeforge_release,
        "TREEFORGE_OS_VERSION",
        tfb_menu_state
            .alternate_os_version,
        sizeof(
            tfb_menu_state
                .alternate_os_version
        )
    );

    tfb_altroot_try_release_value(
        treeforge_release,
        "VERSION",
        tfb_menu_state
            .alternate_os_version,
        sizeof(
            tfb_menu_state
                .alternate_os_version
        )
    );

    tfb_altroot_try_release_value(
        treeforge_release,
        "TREEFORGE_OS_BUILD",
        tfb_menu_state
            .alternate_os_build,
        sizeof(
            tfb_menu_state
                .alternate_os_build
        )
    );

    tfb_altroot_try_release_value(
        treeforge_release,
        "BUILD",
        tfb_menu_state
            .alternate_os_build,
        sizeof(
            tfb_menu_state
                .alternate_os_build
        )
    );

    tfb_altroot_try_release_value(
        treeforge_release,
        "TREEFORGE_OS_MILESTONE",
        tfb_menu_state
            .alternate_os_milestone,
        sizeof(
            tfb_menu_state
                .alternate_os_milestone
        )
    );

    tfb_altroot_try_release_value(
        treeforge_release,
        "MILESTONE",
        tfb_menu_state
            .alternate_os_milestone,
        sizeof(
            tfb_menu_state
                .alternate_os_milestone
        )
    );

    tfb_altroot_try_release_value(
        treeforge_release,
        "TREEFORGE_OS_BOARD",
        tfb_menu_state
            .alternate_os_board,
        sizeof(
            tfb_menu_state
                .alternate_os_board
        )
    );

    tfb_altroot_try_release_value(
        treeforge_release,
        "BOARD",
        tfb_menu_state
            .alternate_os_board,
        sizeof(
            tfb_menu_state
                .alternate_os_board
        )
    );

    /*
     * Standard Linux os-release.
     */
    tfb_altroot_try_release_value(
        os_release,
        "PRETTY_NAME",
        tfb_menu_state
            .alternate_os_detected_name,
        sizeof(
            tfb_menu_state
                .alternate_os_detected_name
        )
    );

    tfb_altroot_try_release_value(
        os_release,
        "NAME",
        tfb_menu_state
            .alternate_os_detected_name,
        sizeof(
            tfb_menu_state
                .alternate_os_detected_name
        )
    );

    tfb_altroot_try_release_value(
        os_release,
        "VERSION",
        tfb_menu_state
            .alternate_os_version,
        sizeof(
            tfb_menu_state
                .alternate_os_version
        )
    );

    tfb_altroot_try_release_value(
        os_release,
        "VERSION_ID",
        tfb_menu_state
            .alternate_os_version,
        sizeof(
            tfb_menu_state
                .alternate_os_version
        )
    );

    tfb_altroot_try_release_value(
        os_release,
        "BUILD_ID",
        tfb_menu_state
            .alternate_os_build,
        sizeof(
            tfb_menu_state
                .alternate_os_build
        )
    );

    /*
     * LSB/ChromiumOS release metadata. These are metadata-key
     * adapters only; no OS identity is assigned by Bootstrap.
     */
    tfb_altroot_try_release_value(
        lsb_release,
        "CHROMEOS_RELEASE_NAME",
        tfb_menu_state
            .alternate_os_detected_name,
        sizeof(
            tfb_menu_state
                .alternate_os_detected_name
        )
    );

    tfb_altroot_try_release_value(
        lsb_release,
        "DISTRIB_DESCRIPTION",
        tfb_menu_state
            .alternate_os_detected_name,
        sizeof(
            tfb_menu_state
                .alternate_os_detected_name
        )
    );

    tfb_altroot_try_release_value(
        lsb_release,
        "DISTRIB_ID",
        tfb_menu_state
            .alternate_os_detected_name,
        sizeof(
            tfb_menu_state
                .alternate_os_detected_name
        )
    );

    tfb_altroot_try_release_value(
        lsb_release,
        "CHROMEOS_RELEASE_VERSION",
        tfb_menu_state
            .alternate_os_version,
        sizeof(
            tfb_menu_state
                .alternate_os_version
        )
    );

    tfb_altroot_try_release_value(
        lsb_release,
        "DISTRIB_RELEASE",
        tfb_menu_state
            .alternate_os_version,
        sizeof(
            tfb_menu_state
                .alternate_os_version
        )
    );

    tfb_altroot_try_release_value(
        lsb_release,
        "CHROMEOS_RELEASE_BUILD_NUMBER",
        tfb_menu_state
            .alternate_os_build,
        sizeof(
            tfb_menu_state
                .alternate_os_build
        )
    );

    tfb_altroot_try_release_value(
        lsb_release,
        "CHROMEOS_RELEASE_CHROME_MILESTONE",
        tfb_menu_state
            .alternate_os_milestone,
        sizeof(
            tfb_menu_state
                .alternate_os_milestone
        )
    );

    tfb_altroot_try_release_value(
        lsb_release,
        "CHROMEOS_RELEASE_BOARD",
        tfb_menu_state
            .alternate_os_board,
        sizeof(
            tfb_menu_state
                .alternate_os_board
        )
    );

    if (
        tfb_menu_state
            .alternate_os_detected_name[0]
        == '\0'
    ) {
        tfb_altroot_copy_literal(
            tfb_menu_state
                .alternate_os_detected_name,
            sizeof(
                tfb_menu_state
                    .alternate_os_detected_name
            ),
            "Unknown OS"
        );
    }
}


static int tfb_kernel_receipt_matches(const unsigned char *provider);
static void tfb_publish_security_context(void);
__TREEFORGE_ALTOS_STORAGE_SOURCE__

/*
 * TFB_ALTROOT_INSTALLED_PROBE_V1
 *
 * Menu inventory must describe the actual storage-backed operating
 * system, not the presence of optional metadata.
 *
 * This probe is deliberately read-only. It realizes the existing
 * kernel block topology, mounts treeforge_os read-only, validates a
 * recognized root contract, then detaches the probe mount.
 */
static int tfb_altroot_installed(
    void
) {
    tfb_altroot_cleanup_partial();

    if (
        tfb_realize_block_nodes()
        != 0
    ) {
        return 0;
    }

    tfb_altroot_mkdir(
        "/mnt",
        0755
    );

    if (
        !tfb_altroot_mkdir(
            TFB_ALTROOT_ROOT,
            0755
        )
    ) {
        return 0;
    }

    int storage_v1 = tfb_altos_probe();
    if (storage_v1 >= 0) return storage_v1;

    if (
        tfb_altroot_mount(
            TFB_ALTROOT_STORAGE,
            TFB_ALTROOT_ROOT,
            TFB_ALTROOT_STORAGE_FS,
            MS_RDONLY,
            0
        ) < 0
    ) {
        return 0;
    }

    int installed = 0;

    /*
     * Legacy/current TreeForge-native root contract.
     */
    if (
        tfb_probe_readable_path(
            "/mnt/treeforge-altroot/init"
        )
        && tfb_probe_readable_path(
            "/mnt/treeforge-altroot/"
            "TREEFORGE_ROOTFS_V1"
        )
    ) {
        installed = 1;
    }

    /*
     * Conventional Linux root contract used by the current
     * ChromiumOS installation.
     */
    if (
        !installed
        && tfb_probe_readable_path(
            "/mnt/treeforge-altroot/sbin/init"
        )
        && tfb_probe_readable_path(
            "/mnt/treeforge-altroot/etc/os-release"
        )
    ) {
        installed = 1;
    }

    if (installed) {
        tfb_altroot_collect_identity();
    } else {
        tfb_altroot_identity_clear();
    }

    tfb_altroot_cleanup_partial();

    return installed;
}


static int tfb_altroot_prepare_once(
    void
) {
    tfb_altroot_cleanup_partial();

    /*
     * Realize the existing kernel-visible block topology locally.
     * This does not modify GPT or partition content and does not
     * activate Pixel Partitioner authorization.
     */
    if (
        tfb_realize_block_nodes()
        != 0
    ) {
        tfb_log(
            "altroot-storage=block-realization-failed"
        );

        return 0;
    }

    tfb_log(
        "altroot-storage=block-realization-ready"
    );

    tfb_altroot_mkdir(
        "/mnt",
        0755
    );

    if (
        !tfb_altroot_mkdir(
            TFB_ALTROOT_ROOT,
            0755
        )
    ) {
        tfb_log(
            "altroot-test=root-mkdir-failed"
        );

        return 0;
    }

    int storage_v1 = tfb_altos_prepare();
    if (storage_v1 == 0) {
        tfb_log(tfb_altos_reason);
        tfb_altroot_cleanup_partial();
        return 0;
    }
    if (storage_v1 < 0) tfb_altos_cleanup();

    /*
     * pivot_root requires new_root itself to be a mount point.
     */
    if (
        tfb_altroot_mount(
            tfb_altos_v1 ? TFB_ALTOS_ROOT_NODE : TFB_ALTROOT_STORAGE,
            TFB_ALTROOT_ROOT,
            TFB_ALTROOT_STORAGE_FS,
            tfb_altos_v1 ? MS_RDONLY : 0,
            tfb_altos_v1 ? "noload" : 0
        ) < 0
    ) {
        tfb_log(
            "altroot-storage=mount-failed"
        );

        if (tfb_altos_v1 && tfb_altos_trial) tfb_altos_reject_pending();
        tfb_altroot_cleanup_partial();

        return 0;
    }

    tfb_log(
        "altroot-storage=mounted"
    );

    /* Never follow an image-provided mountpoint symlink into the retained
     * /dev, USB runtime, old Android root or another container region. */
    if (tfb_altos_v1 && !tfb_altos_mountpoints()) {
        tfb_log("storage-v1=invalid-root-mountpoints");
        if (tfb_altos_trial) tfb_altos_reject_pending();
        tfb_altroot_cleanup_partial();
        return 0;
    }


    const char *directories[] = {
        "/mnt/treeforge-altroot/bin",
        "/mnt/treeforge-altroot/system",
        "/mnt/treeforge-altroot/system/bin",
        "/mnt/treeforge-altroot/dev",
        "/mnt/treeforge-altroot/proc",
        "/mnt/treeforge-altroot/sys",
        "/mnt/treeforge-altroot/config",
        "/mnt/treeforge-altroot/tmp",
        "/mnt/treeforge-altroot/.oldroot",
    };

    for (
        usize index = 0;
        index
            < sizeof(directories)
                / sizeof(directories[0]);
        index++
    ) {
        if (
            !tfb_altos_v1 && !tfb_altroot_mkdir(
                directories[index],
                0755
            )
        ) {
            tfb_log(
                "altroot-test=directory-layout-failed"
            );

            tfb_altroot_cleanup_partial();
            return 0;
        }
    }

    if (
        tfb_altroot_mount(
            "/dev",
            "/mnt/treeforge-altroot/dev",
            0,
            TFB_MS_BIND | TFB_MS_REC,
            0
        ) < 0
    ) {
        tfb_log(
            "altroot-test=dev-bind-failed"
        );

        tfb_altroot_cleanup_partial();
        return 0;
    }

    if (
        tfb_altroot_mount(
            "/proc",
            "/mnt/treeforge-altroot/proc",
            0,
            TFB_MS_BIND | TFB_MS_REC,
            0
        ) < 0
    ) {
        tfb_log(
            "altroot-test=proc-bind-failed"
        );

        tfb_altroot_cleanup_partial();
        return 0;
    }

    if (
        tfb_altroot_mount(
            "/sys",
            "/mnt/treeforge-altroot/sys",
            0,
            TFB_MS_BIND | TFB_MS_REC,
            0
        ) < 0
    ) {
        tfb_log(
            "altroot-test=sys-bind-failed"
        );

        tfb_altroot_cleanup_partial();
        return 0;
    }

    if (
        tfb_altroot_mount(
            "/config",
            "/mnt/treeforge-altroot/config",
            0,
            TFB_MS_BIND | TFB_MS_REC,
            0
        ) < 0
    ) {
        tfb_log(
            "altroot-test=config-bind-failed"
        );

        tfb_altroot_cleanup_partial();
        return 0;
    }

    if (
        tfb_altroot_mount(
            "treeforge-alt-tmp",
            "/mnt/treeforge-altroot/tmp",
            "tmpfs",
            0,
            "mode=1777"
        ) < 0
    ) {
        tfb_log(
            "altroot-test=tmp-mount-failed"
        );

        tfb_altroot_cleanup_partial();
        return 0;
    }

    if (!tfb_altos_mount_state()) {
        tfb_log("storage-v1=STATE-mount-failed");
        tfb_altroot_cleanup_partial();
        return 0;
    }

    /*
     * Storage-backed alternate userspace.
     *
     * Legacy TreeForge diagnostic roots use /init and the
     * TREEFORGE_ROOTFS_V1 ownership marker.
     *
     * Conventional Linux roots, including the current ChromiumOS
     * installation, may expose native PID 1 as /sbin/init.
     *
     * Detection is read-only. Bootstrap must not persistently alter
     * treeforge_os merely to satisfy the handoff contract.
     */
    if (
        tfb_probe_readable_path(
            "/mnt/treeforge-altroot/init"
        )
        && tfb_probe_readable_path(
            "/mnt/treeforge-altroot/"
            "TREEFORGE_ROOTFS_V1"
        )
    ) {
        tfb_altroot_init_path =
            "/init";

        tfb_log(
            "altroot-storage=contract-treeforge-v1"
        );
    } else if (
        tfb_probe_readable_path(
            "/mnt/treeforge-altroot/sbin/init"
        )
        && tfb_probe_readable_path(
            "/mnt/treeforge-altroot/etc/os-release"
        )
    ) {
        tfb_altroot_init_path =
            "/sbin/init";

        tfb_log(
            "altroot-storage=contract-native-sbin-init"
        );
    } else {
        tfb_log(
            "altroot-storage=payload-missing"
        );

        if (tfb_altos_v1 && tfb_altos_trial) tfb_altos_reject_pending();

        tfb_altroot_cleanup_partial();
        return 0;
    }

    tfb_log(
        "altroot-storage=payload-ready"
    );

    /*
     * TreeForge Bootstrap adbd already launches its retained BusyBox
     * directly from /dev/treeforge-bootstrap-runtime. Do not unlink,
     * replace, or otherwise modify the alternate OS's native shells.
     */
    tfb_log(
        "altroot-test=rootfs-shells-preserved"
    );

    tfb_log(
        "altroot-test=native-init-ready"
    );

    tfb_log(
        "altroot-test=prepared"
    );

    return 1;
}


static int tfb_altroot_prepare(void) {
    tfb_altos_retry_confirmed = 0;
    if (tfb_altroot_prepare_once()) return 1;
    if (tfb_altos_retry_confirmed) {
        tfb_altos_retry_confirmed = 0;
        tfb_log("storage-v1=retry-confirmed-root");
        return tfb_altroot_prepare_once();
    }
    return 0;
}


__attribute__((noreturn))
static void tfb_altroot_pivot_and_exec(
    void
) {
    /*
     * Prevent root replacement from propagating outside the active
     * mount namespace.
     */
    if (
        tfb_altroot_mount(
            0,
            "/",
            0,
            TFB_MS_REC | TFB_MS_PRIVATE,
            0
        ) < 0
    ) {
        tfb_transition_failure(
            "altroot-root-private"
        );
    }

    if (
        tfb_syscall1(
            SYS_CHDIR,
            (long) TFB_ALTROOT_ROOT
        ) < 0
    ) {
        tfb_transition_failure(
            "altroot-chdir-newroot"
        );
    }

    tfb_log(
        "altroot-test=pivot-begin"
    );

    if (
        tfb_syscall2(
            SYS_PIVOT_ROOT,
            (long) ".",
            (long) ".oldroot"
        ) < 0
    ) {
        tfb_transition_failure(
            "altroot-pivot-root"
        );
    }

    tfb_syscall1(
        SYS_CHDIR,
        (long) "/"
    );

    /*
     * Remove the old Android root from the visible filesystem tree.
     * No underlying Android partition is modified.
     */
    tfb_syscall2(
        SYS_UMOUNT2,
        (long) "/.oldroot",
        TFB_MNT_DETACH
    );

    tfb_log(
        "altroot-test=payload-exec"
    );

    char *alt_argv[] = {
        (char *) tfb_altroot_init_path,
        0
    };

    char *alt_envp[] = {
        (char *) "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/system/bin",
        (char *) "HOME=/",
        (char *) "TERM=linux",
        0
    };

    tfb_syscall3(
        SYS_EXECVE,
        (long) tfb_altroot_init_path,
        (long) alt_argv,
        (long) alt_envp
    );

    tfb_log(
        "altroot-test=payload-exec-failed"
    );

    for (;;) {
        tfb_sleep_ms(
            1000
        );
    }
}



/*
 * ================================================================
 * TFB_DIAGNOSTIC_PID1_TMPFS_V1
 * ================================================================
 *
 * Permanent Bootstrap-owned diagnostic boot target.
 *
 * This is deliberately independent of treeforge_os.
 *
 * Bootstrap creates a disposable tmpfs root, bind-mounts the retained
 * Linux runtime surfaces, pivots PID 1 into it, detaches the old Android
 * root, then executes the retained static diagnostic /init.
 *
 * The display is transferred through a second already-open descriptor
 * to the accepted TreeForge framebuffer bridge. The diagnostic runtime
 * therefore does not need to recreate or reprobe display hardware.
 *
 * No kexec.
 * No storage write.
 * No GPT mutation.
 * No slot mutation.
 */

#define TFB_DIAGNOSTIC_ROOT \
    "/mnt/treeforge-diagnostic"

#define TFB_DIAGNOSTIC_INIT \
    "/dev/treeforge-bootstrap-runtime/" \
    "system/bin/treeforge-diagnostic-init"

#define TFB_DIAGNOSTIC_BUSYBOX \
    "/dev/treeforge-bootstrap-runtime/" \
    "system/bin/busybox"

#define TFB_DIAGNOSTIC_FB_FD_PATH \
    "/dev/treeforge-bootstrap-diagnostic-fb-fd"


static void tfb_diagnostic_cleanup_partial(
    void
) {
    tfb_syscall2(
        SYS_UMOUNT2,
        (long) TFB_DIAGNOSTIC_ROOT,
        TFB_MNT_DETACH
    );

    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)
            TFB_DIAGNOSTIC_FB_FD_PATH,
        0
    );
}


static int tfb_diagnostic_prepare_root(
    void
) {
    tfb_diagnostic_cleanup_partial();

    tfb_altroot_mkdir(
        "/mnt",
        0755
    );

    if (
        !tfb_altroot_mkdir(
            TFB_DIAGNOSTIC_ROOT,
            0755
        )
    ) {
        tfb_log(
            "diagnostic=root-mkdir-failed"
        );

        return 0;
    }

    if (
        tfb_altroot_mount(
            "treeforge-diagnostic",
            TFB_DIAGNOSTIC_ROOT,
            "tmpfs",
            0,
            "mode=0755"
        ) < 0
    ) {
        tfb_log(
            "diagnostic=root-mount-failed"
        );

        return 0;
    }

    static const char *directories[] = {
        "/mnt/treeforge-diagnostic/bin",
        "/mnt/treeforge-diagnostic/system",
        "/mnt/treeforge-diagnostic/system/bin",
        "/mnt/treeforge-diagnostic/dev",
        "/mnt/treeforge-diagnostic/proc",
        "/mnt/treeforge-diagnostic/sys",
        "/mnt/treeforge-diagnostic/config",
        "/mnt/treeforge-diagnostic/tmp",
        "/mnt/treeforge-diagnostic/.oldroot",
        0
    };

    for (
        int index = 0;
        directories[index];
        index++
    ) {
        if (
            !tfb_altroot_mkdir(
                directories[index],
                (
                    tfb_string_equal(
                        directories[index],
                        "/mnt/treeforge-diagnostic/tmp"
                    )
                    ? 01777
                    : 0755
                )
            )
        ) {
            tfb_log(
                "diagnostic=directory-create-failed"
            );

            tfb_diagnostic_cleanup_partial();
            return 0;
        }
    }

    static const char *bind_sources[] = {
        "/dev",
        "/proc",
        "/sys",
        "/config",
        0
    };

    static const char *bind_targets[] = {
        "/mnt/treeforge-diagnostic/dev",
        "/mnt/treeforge-diagnostic/proc",
        "/mnt/treeforge-diagnostic/sys",
        "/mnt/treeforge-diagnostic/config",
        0
    };

    for (
        int index = 0;
        bind_sources[index];
        index++
    ) {
        if (
            tfb_altroot_mount(
                bind_sources[index],
                bind_targets[index],
                0,
                TFB_MS_BIND
                    | TFB_MS_REC,
                0
            ) < 0
        ) {
            tfb_log(
                "diagnostic=bind-mount-failed"
            );

            tfb_diagnostic_cleanup_partial();
            return 0;
        }
    }

    if (
        tfb_altroot_mount(
            "treeforge-diagnostic-tmp",
            "/mnt/treeforge-diagnostic/tmp",
            "tmpfs",
            0,
            "mode=1777"
        ) < 0
    ) {
        tfb_log(
            "diagnostic=tmp-mount-failed"
        );

        tfb_diagnostic_cleanup_partial();
        return 0;
    }

    long init_link =
        tfb_syscall3(
            SYS_SYMLINKAT,
            (long)
                TFB_DIAGNOSTIC_INIT,
            AT_FDCWD,
            (long)
                "/mnt/"
                "treeforge-diagnostic/"
                "init"
        );

    long bin_shell =
        tfb_syscall3(
            SYS_SYMLINKAT,
            (long)
                TFB_DIAGNOSTIC_BUSYBOX,
            AT_FDCWD,
            (long)
                "/mnt/"
                "treeforge-diagnostic/"
                "bin/sh"
        );

    long system_shell =
        tfb_syscall3(
            SYS_SYMLINKAT,
            (long)
                TFB_DIAGNOSTIC_BUSYBOX,
            AT_FDCWD,
            (long)
                "/mnt/"
                "treeforge-diagnostic/"
                "system/bin/sh"
        );

    if (
        init_link < 0
        || bin_shell < 0
        || system_shell < 0
        || !tfb_probe_readable_path(
            "/mnt/"
            "treeforge-diagnostic/"
            "init"
        )
        || !tfb_probe_readable_path(
            "/mnt/"
            "treeforge-diagnostic/"
            "bin/sh"
        )
        || !tfb_probe_readable_path(
            "/mnt/"
            "treeforge-diagnostic/"
            "system/bin/sh"
        )
    ) {
        tfb_log(
            "diagnostic=runtime-links-failed"
        );

        tfb_diagnostic_cleanup_partial();
        return 0;
    }

    tfb_log(
        "diagnostic=root-ready"
    );

    return 1;
}


static int tfb_diagnostic_prepare_fb_handoff(
    void
) {
    if (!tfb_fb_active) {
        tfb_log(
            "diagnostic=fb-not-active"
        );

        return 0;
    }

    /*
     * Open a second independent file description before the menu's
     * mapping is released. Its read position therefore starts at zero,
     * allowing the diagnostic PID1 to consume the framebuffer ABI.
     */
    long framebuffer_fd =
        tfb_open(
            TFB_FB_DEVICE_PATH,
            O_RDWR
        );

    if (framebuffer_fd < 0) {
        tfb_log(
            "diagnostic=fb-handoff-open-failed"
        );

        return 0;
    }

    long metadata_fd =
        tfb_syscall4(
            SYS_OPENAT,
            AT_FDCWD,
            (long)
                TFB_DIAGNOSTIC_FB_FD_PATH,
            (
                O_WRONLY
                | O_CREAT
                | O_TRUNC
            ),
            0600
        );

    if (metadata_fd < 0) {
        tfb_close(
            framebuffer_fd
        );

        tfb_log(
            "diagnostic=fb-metadata-open-failed"
        );

        return 0;
    }

    int inherited_fd =
        (int) framebuffer_fd;

    long written =
        tfb_syscall3(
            SYS_WRITE,
            metadata_fd,
            (long) &inherited_fd,
            (long)
                sizeof(inherited_fd)
        );

    tfb_close(
        metadata_fd
    );

    if (
        written
        != (long)
            sizeof(inherited_fd)
    ) {
        tfb_close(
            framebuffer_fd
        );

        tfb_syscall3(
            SYS_UNLINKAT,
            AT_FDCWD,
            (long)
                TFB_DIAGNOSTIC_FB_FD_PATH,
            0
        );

        tfb_log(
            "diagnostic=fb-metadata-write-failed"
        );

        return 0;
    }

    /*
     * framebuffer_fd deliberately remains open and non-CLOEXEC.
     * The diagnostic PID1 consumes it after pivot_root + execve.
     */
    tfb_log(
        "diagnostic=fb-handoff-ready"
    );

    return 1;
}


__attribute__((noreturn))
static void tfb_diagnostic_pivot_and_exec(
    void
) {
    if (
        tfb_altroot_mount(
            0,
            "/",
            0,
            TFB_MS_REC
                | TFB_MS_PRIVATE,
            0
        ) < 0
    ) {
        tfb_transition_failure(
            "diagnostic-root-private"
        );
    }

    if (
        tfb_syscall1(
            SYS_CHDIR,
            (long)
                TFB_DIAGNOSTIC_ROOT
        ) < 0
    ) {
        tfb_transition_failure(
            "diagnostic-chdir-newroot"
        );
    }

    tfb_log(
        "diagnostic=pivot-begin"
    );

    if (
        tfb_syscall2(
            SYS_PIVOT_ROOT,
            (long) ".",
            (long) ".oldroot"
        ) < 0
    ) {
        tfb_transition_failure(
            "diagnostic-pivot-root"
        );
    }

    tfb_syscall1(
        SYS_CHDIR,
        (long) "/"
    );

    tfb_syscall2(
        SYS_UMOUNT2,
        (long) "/.oldroot",
        TFB_MNT_DETACH
    );

    tfb_log(
        "diagnostic=pid1-exec"
    );

    char *diagnostic_argv[] = {
        (char *) "/init",
        0
    };

    char *diagnostic_envp[] = {
        (char *)
            "PATH=/bin:/system/bin",
        (char *) "HOME=/",
        (char *) "TERM=linux",
        0
    };

    tfb_syscall3(
        SYS_EXECVE,
        (long) "/init",
        (long) diagnostic_argv,
        (long) diagnostic_envp
    );

    tfb_log(
        "diagnostic=pid1-exec-failed"
    );

    for (;;) {
        tfb_sleep_ms(
            1000
        );
    }
}


static void tfb_menu_execute_action(
    int action,
    long *inputs,
    int created_input_directory,
    int *created_input_nodes
) {

    if (
        action
        == TFB_ACTION_BOOT_DIAGNOSTICS
    ) {
        tfb_log(
            "early-menu action=boot_diagnostics"
        );

        tfb_menu_status =
            "PREPARING TREEFORGE DIAGNOSTICS";

        if (
            !tfb_diagnostic_prepare_root()
        ) {
            tfb_menu_status =
                "DIAGNOSTIC ROOT PREP FAILED";

            tfb_log(
                "diagnostic=prepare-root-failed"
            );

            return;
        }

        if (
            !tfb_diagnostic_prepare_fb_handoff()
        ) {
            tfb_menu_status =
                "DIAGNOSTIC DISPLAY HANDOFF FAILED";

            tfb_log(
                "diagnostic=prepare-fb-failed"
            );

            tfb_diagnostic_cleanup_partial();
            return;
        }

        /*
         * Diagnostics becomes the active same-kernel userspace owner.
         * Preserve the historical alternate-root marker as a
         * compatibility signal for Bootstrap-owned ADB supervision.
         */
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-diagnostic-active"
        );

        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-altroot-active"
        );

        /*
         * The second framebuffer descriptor above survives this cleanup.
         * This releases only the Boot Manager's own mapping/descriptor.
         */
        tfb_fb_menu_cleanup();

        tfb_close_inputs(
            inputs
        );

        tfb_diagnostic_pivot_and_exec();
    }


    if (
        action
        == TFB_ACTION_BOOT_ALTERNATE_OS
    ) {
        tfb_log(
            "early-menu action=boot_alternate_os"
        );

        tfb_menu_status =
            "PREPARING ALTERNATE OS";

        if (
            !tfb_altroot_prepare()
        ) {
            tfb_menu_status =
                "ALTERNATE OS PREP FAILED";

            tfb_log(
                "altroot-storage=prepare-failed"
            );

            return;
        }

        /* Finish v1 publication before releasing Menu's display/input. A
         * failed preparation returns to Menu with the existing ADB alive. */
        if (!tfb_altos_begin()) {
            tfb_menu_status = "ALTERNATE OS BOOT RECORD ERROR";
            tfb_log("storage-v1=attempt-publication-failed");
            tfb_altroot_cleanup_partial();
            return;
        }

        tfb_publish_security_context();

        /*
         * The graphical menu is about to disappear permanently.
         * Publish the retained alternate-root ownership marker before
         * releasing display/input. ADB + USB deliberately remain alive
         * across the same-kernel root transition.
         */
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-altroot-active"
        );

        tfb_fb_menu_cleanup();

        tfb_close_inputs(
            inputs
        );

        tfb_altroot_pivot_and_exec();
    }

    tfb_log(
        tfb_menu_action_name(
            action
        )
    );


    if (
        action
        == TFB_ACTION_NOT_IMPLEMENTED
    ) {
        tfb_menu_status =
            "NOT IMPLEMENTED - SEE SECONDARY LINE";

        tfb_log(
            "early-menu action=not_implemented-explicit"
        );

        return;
    }


    if (
        action
        == TFB_ACTION_RESTART_ADB_USB
    ) {
        tfb_log(
            "early-menu action=restart_adb_usb"
        );

        tfb_request_adb_reset();

        tfb_menu_status =
            "ADB / USB RESTART REQUESTED";

        return;
    }

    if (
        action
        == TFB_ACTION_LIVE_CONSOLE
    ) {
        tfb_log(
            "early-menu action=live_console"
        );

        tfb_live_console_run(
            inputs
        );

        tfb_menu_status =
            "LIVE CONSOLE CLOSED";

        return;
    }

    if (
        action
        == TFB_ACTION_SET_BOOT_TARGET_SLOT_A
    ) {
        tfb_boot_target_slot = 0;

        tfb_menu_status = (
            tfb_boot_target_slot == 0
            ? "BOOT TARGET: SLOT A"
            : "BOOT TARGET ERROR"
        );

        tfb_log(
            "boot-target=slot-a"
        );

        return;
    }

    if (
        action
        == TFB_ACTION_SET_BOOT_TARGET_SLOT_B
    ) {
        tfb_boot_target_slot = 1;

        tfb_menu_status = (
            tfb_boot_target_slot == 1
            ? "BOOT TARGET: SLOT B"
            : "BOOT TARGET ERROR"
        );

        tfb_log(
            "boot-target=slot-b"
        );

        /*
         * No bootloader active-slot mutation occurs here.
         *
         * The later Bootstrap-owned cross-slot handoff consumes this
         * state instead.
         */
        return;
    }

    if (
        action
        == TFB_ACTION_BOOT_ANDROID_SLOT_A
    ) {
        tfb_log(
            "early-menu action="
            "boot_android_slot_a"
        );

        tfb_render_android_transition();

        tfb_menu_cleanup_for_transition(
            inputs,
            created_input_directory,
            created_input_nodes
        );

        if (!tfb_runtime_envp) {
            tfb_transition_failure(
                "android-slot-a-env"
            );
        }

        char *android_argv[] = {
            (char *)
                "/system/bin/init",
            (char *)
                "selinux_setup",
            0
        };

        tfb_syscall3(
            SYS_EXECVE,
            (long)
                "/system/bin/init",
            (long)
                android_argv,
            (long)
                tfb_runtime_envp
        );

        tfb_transition_failure(
            "android-slot-a-exec"
        );
    }

    if (
        action
        == TFB_ACTION_REBOOT_SYSTEM
    ) {
        tfb_log(
            "early-menu action=reboot_system"
        );

        tfb_menu_cleanup_for_transition(
            inputs,
            created_input_directory,
            created_input_nodes
        );

        tfb_reboot_system();

        tfb_transition_failure(
            "system-reboot-returned"
        );
    }


    if (
        action
        == TFB_ACTION_REBOOT_BOOTLOADER
    ) {
        tfb_log(
            "early-menu action=reboot_bootloader"
        );

        tfb_menu_cleanup_for_transition(
            inputs,
            created_input_directory,
            created_input_nodes
        );

        tfb_reboot_to(
            "bootloader"
        );

        tfb_transition_failure(
            "bootloader-reboot-returned"
        );
    }

    /*
     * Android Slot B and the configured alternate OS deliberately
     * remain visible placeholders until their independent handoff
     * contracts are implemented and hardware accepted.
     */
    tfb_menu_status =
        "ACTION NOT IMPLEMENTED";

    tfb_log(
        "early-menu action=not-implemented"
    );
}




/*
 * ================================================================
 * TFB_TOUCH_MENU_NAVIGATION_V16
 * ================================================================
 *
 * The accepted NVT touchscreen reports native portrait coordinates:
 *
 *   X: 0..1599
 *   Y: 0..2559
 *
 * No swap or inversion is required.
 *
 * Input-device identity is discovered dynamically through sysfs.
 * Never hard-code /dev/input/event2.
 *
 * Touch deliberately shares the exact same menu activation path as
 * KEY_POWER.  Volume Up/Down/Power remain fully functional.
 */

struct tfb_touch_state {
    int slot;
    int active;

    int have_x;
    int have_y;

    int raw_x;
    int raw_y;

    int start_set;
    int start_x;
    int start_y;

    int pressed_row;
    int canceled;
};


__TREEFORGE_MENU_TOUCH_SOURCE__static int tfb_block_make_path(
    char *output,
    usize capacity,
    const char *prefix,
    int partition,
    const char *suffix
) {
    if (
        !output
        || !prefix
        || !suffix
        || capacity < 2
        || partition < 0
    ) {
        return -1;
    }

    usize position = 0;

    for (
        usize index = 0;
        prefix[index] != '\0';
        index++
    ) {
        if (
            position + 1
            >= capacity
        ) {
            return -1;
        }

        output[position++] =
            prefix[index];
    }

    if (partition > 0) {
        char digits[16];
        int count = 0;

        unsigned int value =
            (unsigned int)
                partition;

        do {
            if (
                count
                >= (int)
                    sizeof(digits)
            ) {
                return -1;
            }

            digits[count++] = (
                (char) (
                    '0'
                    + (
                        value
                        % 10U
                    )
                )
            );

            value /= 10U;

        } while (value != 0U);

        while (count > 0) {
            count--;

            if (
                position + 1
                >= capacity
            ) {
                return -1;
            }

            output[position++] =
                digits[count];
        }
    }

    for (
        usize index = 0;
        suffix[index] != '\0';
        index++
    ) {
        if (
            position + 1
            >= capacity
        ) {
            return -1;
        }

        output[position++] =
            suffix[index];
    }

    output[position] = '\0';

    return 0;
}


static long tfb_block_read_text(
    const char *path,
    char *buffer,
    usize capacity
) {
    if (
        !path
        || !buffer
        || capacity < 2
    ) {
        return -1;
    }

    long fd = tfb_open(
        path,
        O_RDONLY
    );

    if (fd < 0) {
        return fd;
    }

    long amount = tfb_syscall3(
        SYS_READ,
        fd,
        (long) buffer,
        (long) (
            capacity - 1
        )
    );

    tfb_close(
        fd
    );

    if (amount < 0) {
        return amount;
    }

    buffer[amount] = '\0';

    return amount;
}


static int tfb_block_device_number(
    int partition,
    unsigned long *major,
    unsigned long *minor
) {
    char path[
        TFB_BLOCK_PATH_CAPACITY
    ];

    if (
        tfb_block_make_path(
            path,
            sizeof(path),
            "/sys/class/block/sda",
            partition,
            "/dev"
        )
        != 0
    ) {
        return -1;
    }

    char value[32];

    long amount = tfb_block_read_text(
        path,
        value,
        sizeof(value)
    );

    if (amount <= 0) {
        return -1;
    }

    return tfb_runtime_parse_device_number(
        value,
        amount,
        major,
        minor
    );
}


static int tfb_block_partname(
    int partition,
    char *output,
    usize capacity
) {
    if (
        partition <= 0
        || !output
        || capacity < 2
    ) {
        return -1;
    }

    char path[
        TFB_BLOCK_PATH_CAPACITY
    ];

    if (
        tfb_block_make_path(
            path,
            sizeof(path),
            "/sys/class/block/sda",
            partition,
            "/uevent"
        )
        != 0
    ) {
        return -1;
    }

    char uevent[
        TFB_BLOCK_UEVENT_CAPACITY
    ];

    long amount = tfb_block_read_text(
        path,
        uevent,
        sizeof(uevent)
    );

    if (amount <= 0) {
        return -1;
    }

    static const char prefix[] =
        "PARTNAME=";

    for (
        long position = 0;
        position < amount;
        position++
    ) {
        if (
            position > 0
            && uevent[
                position - 1
            ] != '\n'
        ) {
            continue;
        }

        int match = 1;

        for (
            usize index = 0;
            prefix[index] != '\0';
            index++
        ) {
            if (
                position
                    + (long) index
                    >= amount
                || uevent[
                    position
                    + (long) index
                ]
                    != prefix[index]
            ) {
                match = 0;
                break;
            }
        }

        if (!match) {
            continue;
        }

        long source = (
            position
            + (long) (
                sizeof(prefix)
                - 1
            )
        );

        usize destination = 0;

        while (
            source < amount
            && uevent[source]
                != '\0'
            && uevent[source]
                != '\n'
            && uevent[source]
                != '\r'
        ) {
            if (
                destination + 1
                >= capacity
                || uevent[source]
                    == '/'
            ) {
                return -1;
            }

            output[
                destination++
            ] = uevent[
                source++
            ];
        }

        if (destination == 0) {
            return -1;
        }

        output[destination] =
            '\0';

        return 0;
    }

    return -1;
}


static int tfb_realize_block_node(
    int partition
) {
    unsigned long major = 0;
    unsigned long minor = 0;

    if (
        tfb_block_device_number(
            partition,
            &major,
            &minor
        )
        != 0
    ) {
        return -1;
    }

    char node[
        TFB_BLOCK_PATH_CAPACITY
    ];

    if (
        tfb_block_make_path(
            node,
            sizeof(node),
            "/dev/block/sda",
            partition,
            ""
        )
        != 0
    ) {
        return -1;
    }

    long result = tfb_syscall4(
        SYS_MKNODAT,
        AT_FDCWD,
        (long) node,
        S_IFBLK | 0600,
        (long) tfb_runtime_makedev(
            major,
            minor
        )
    );

    /*
     * EEXIST is idempotent success.
     */
    if (
        result != 0
        && result != -17
    ) {
        return -1;
    }

    if (partition == 0) {
        result = tfb_syscall4(
            SYS_MKNODAT, AT_FDCWD,
            (long) "/dev/block/treeforge_updated_gpt",
            S_IFBLK | 0400,
            (long) tfb_runtime_makedev(major, minor)
        );
        return (result == 0 || result == -17) ? 0 : -1;
    }

    char partname[
        TFB_BLOCK_PARTNAME_CAPACITY
    ];

    if (
        tfb_block_partname(
            partition,
            partname,
            sizeof(partname)
        )
        != 0
    ) {
        /*
         * A valid block node without PARTNAME remains usable.
         */
        return 0;
    }

    char link[
        TFB_BLOCK_PATH_CAPACITY
    ];

    static const char prefix[] =
        "/dev/block/by-name/";

    usize position = 0;

    for (
        usize index = 0;
        prefix[index] != '\0';
        index++
    ) {
        if (
            position + 1
            >= sizeof(link)
        ) {
            return -1;
        }

        link[position++] =
            prefix[index];
    }

    for (
        usize index = 0;
        partname[index] != '\0';
        index++
    ) {
        if (
            position + 1
            >= sizeof(link)
        ) {
            return -1;
        }

        link[position++] =
            partname[index];
    }

    link[position] = '\0';

    result = tfb_syscall3(
        SYS_SYMLINKAT,
        (long) node,
        AT_FDCWD,
        (long) link
    );

    /*
     * Existing by-name aliases are accepted.
     */
    if (
        result != 0
        && result != -17
    ) {
        return -1;
    }

    return 0;
}


static int tfb_realize_block_nodes(
    void
) {
    long result = tfb_syscall3(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long) "/dev/block",
        0755
    );

    if (
        result != 0
        && result != -17
    ) {
        return -1;
    }

    result = tfb_syscall3(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long)
            "/dev/block/by-name",
        0755
    );

    if (
        result != 0
        && result != -17
    ) {
        return -1;
    }

    /*
     * Whole physical UFS disk.
     */
    if (
        tfb_realize_block_node(
            0
        )
        != 0
    ) {
        return -1;
    }

    int failures = 0;

    for (
        int partition = 1;
        partition
            < TFB_BLOCK_MAX_PARTITIONS;
        partition++
    ) {
        char sysfs_path[
            TFB_BLOCK_PATH_CAPACITY
        ];

        if (
            tfb_block_make_path(
                sysfs_path,
                sizeof(sysfs_path),
                "/sys/class/block/sda",
                partition,
                "/dev"
            )
            != 0
        ) {
            failures++;
            continue;
        }

        long probe = tfb_open(
            sysfs_path,
            O_RDONLY
        );

        if (probe < 0) {
            continue;
        }

        tfb_close(
            probe
        );

        if (
            tfb_realize_block_node(
                partition
            )
            != 0
        ) {
            failures++;
        }
    }

    return (
        failures == 0
        ? 0
        : -1
    );
}


static void tfb_pp_remove_marker(
    const char *path
) {
    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long) path,
        0
    );
}


static int tfb_pp_write_marker(
    const char *path
) {
    long fd = tfb_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long) path,
        O_WRONLY
            | O_CREAT
            | O_TRUNC,
        0644
    );

    if (fd < 0) {
        return 0;
    }

    tfb_write_all(
        fd,
        "1\n"
    );

    tfb_close(
        fd
    );

    return 1;
}



static int tfb_pp_write_text(
    const char *path,
    const char *text
) {
    long fd;

    if (
        !path
        || !text
    ) {
        return 0;
    }

    fd = tfb_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long) path,
        O_WRONLY
            | O_CREAT
            | O_TRUNC,
        0644
    );

    if (fd < 0) {
        return 0;
    }

    tfb_write_all(
        fd,
        text
    );

    tfb_close(
        fd
    );

    return 1;
}


static int tfb_pixel_partitioner_page(
    const struct tfb_menu_page *page
) {
    return (
        page
        && page->title
        && tfb_string_equal(
            page->title,
            "Pixel Partitioner"
        )
    );
}


static void tfb_pixel_partitioner_deactivate(
    void
) {
    tfb_pp_remove_marker(
        TFB_PP_READY_MARKER
    );

    tfb_pp_remove_marker(
        TFB_PP_REPROBE_REQUEST
    );

    tfb_pp_remove_marker(
        TFB_PP_REPROBE_READY
    );

    tfb_pp_remove_marker(
        TFB_PP_REPROBE_FAILED
    );


    tfb_pp_remove_marker(
        "/dev/treeforge-bootstrap-pixel-partitioner-status"
    );

    tfb_pp_remove_marker(
        "/dev/treeforge-bootstrap-pixel-partitioner-log"
    );

    tfb_log(
        "pixel-partitioner-service=inactive"
    );
}


static int tfb_pixel_partitioner_activate(
    void
) {
    tfb_pixel_partitioner_deactivate();

    if (
        tfb_realize_block_nodes()
        != 0
    ) {
        tfb_log(
            "pixel-partitioner-block-devices=failed"
        );

        return 0;
    }

    if (
        !tfb_pp_write_marker(
            TFB_PP_READY_MARKER
        )
    ) {
        tfb_log(
            "pixel-partitioner-ready-marker=failed"
        );

        return 0;
    }

    if (
        !tfb_pp_write_text(
            "/dev/treeforge-bootstrap-pixel-partitioner-status",
            "Waiting for Pixel Partitioner host"
        )
    ) {
        tfb_log(
            "pixel-partitioner-status-file=failed"
        );
    }

    if (
        !tfb_pp_write_text(
            "/dev/treeforge-bootstrap-pixel-partitioner-log",
            "PASS|Bootstrap maintenance runtime\n"
            "PASS|Pixel Partitioner authorized\n"
            "RUNNING|Waiting for host transaction\n"
        )
    ) {
        tfb_log(
            "pixel-partitioner-log-file=failed"
        );
    }


    tfb_log(
        "pixel-partitioner-block-devices=ready"
    );

    tfb_log(
        "pixel-partitioner-service=ready"
    );

    return 1;
}


/*
 * TFB_PIXEL_PARTITIONER_GPT_REPROBE_V1_1
 *
 * The external marker protocol intentionally keeps the "reprobe"
 * name for compatibility.
 *
 * Internally this is a targeted GPT tail refresh:
 *
 *   sda26 -> resize userdata to the geometry now stored in GPT
 *   sda27 -> add/resize/delete treeforge_os to match GPT
 *
 * Unrelated live Android partitions are never dropped or rescanned.
 */

struct tfb_blkpg_partition {
    long long start;
    long long length;
    int pno;
    char devname[64];
    char volname[64];
};


struct tfb_blkpg_ioctl_arg {
    int op;
    int flags;
    int datalen;
    void *data;
};


struct tfb_gpt_partition_target {
    int present;

    unsigned long long
        start_bytes;

    unsigned long long
        length_bytes;

    char name[
        TFB_BLOCK_PARTNAME_CAPACITY
    ];
};


static unsigned int tfb_read_le32(
    const unsigned char *value
) {
    return (
        ((unsigned int) value[0])
        | (
            ((unsigned int) value[1])
            << 8
        )
        | (
            ((unsigned int) value[2])
            << 16
        )
        | (
            ((unsigned int) value[3])
            << 24
        )
    );
}


static unsigned long long
tfb_read_le64(
    const unsigned char *value
) {
    unsigned long long result = 0;

    for (
        int index = 7;
        index >= 0;
        index--
    ) {
        result <<= 8;

        result |= (
            (unsigned long long)
                value[index]
        );
    }

    return result;
}


static int tfb_block_read_exact_at(
    long fd,
    unsigned long long offset,
    unsigned char *buffer,
    usize amount
) {
    if (
        fd < 0
        || !buffer
    ) {
        return -1;
    }

    long seek = tfb_syscall3(
        SYS_LSEEK,
        fd,
        (long) offset,
        0
    );

    if (
        seek
        != (long) offset
    ) {
        return -1;
    }

    usize done = 0;

    while (done < amount) {
        long received = tfb_syscall3(
            SYS_READ,
            fd,
            (long) (
                buffer + done
            ),
            (long) (
                amount - done
            )
        );

        if (received <= 0) {
            return -1;
        }

        done += (
            (usize) received
        );
    }

    return 0;
}


static int tfb_gpt_decode_name(
    const unsigned char *entry,
    char *output,
    usize capacity
) {
    if (
        !entry
        || !output
        || capacity < 2
    ) {
        return -1;
    }

    usize destination = 0;

    for (
        int index = 0;
        index < 36;
        index++
    ) {
        unsigned char low = (
            entry[
                56
                + (index * 2)
            ]
        );

        unsigned char high = (
            entry[
                57
                + (index * 2)
            ]
        );

        if (
            low == 0
            && high == 0
        ) {
            break;
        }

        /*
         * Current tangorpro GPT names are ASCII.
         *
         * Reject anything that cannot safely become a by-name
         * component.
         */
        if (
            high != 0
            || low < 0x20
            || low == '/'
            || destination + 1
                >= capacity
        ) {
            return -1;
        }

        output[destination++] =
            (char) low;
    }

    if (destination == 0) {
        return -1;
    }

    output[destination] = '\0';

    return 0;
}


static int tfb_gpt_read_partition_target(
    long fd,
    int partition,
    struct tfb_gpt_partition_target
        *target
) {
    if (
        fd < 0
        || partition <= 0
        || !target
    ) {
        return -1;
    }

    target->present = 0;
    target->start_bytes = 0;
    target->length_bytes = 0;
    target->name[0] = '\0';

    unsigned char header[
        TFB_GPT_HEADER_READ_BYTES
    ];

    if (
        tfb_block_read_exact_at(
            fd,
            TFB_GPT_HEADER_OFFSET,
            header,
            sizeof(header)
        )
        != 0
    ) {
        return -1;
    }

    static const unsigned char
        signature[8] = {
            'E',
            'F',
            'I',
            ' ',
            'P',
            'A',
            'R',
            'T'
        };

    for (
        int index = 0;
        index < 8;
        index++
    ) {
        if (
            header[index]
            != signature[index]
        ) {
            return -1;
        }
    }

    unsigned long long
        entries_lba = (
            tfb_read_le64(
                header + 72
            )
        );

    unsigned int entry_count = (
        tfb_read_le32(
            header + 80
        )
    );

    unsigned int entry_size = (
        tfb_read_le32(
            header + 84
        )
    );

    if (
        entry_size
            < TFB_GPT_ENTRY_READ_BYTES
        || entry_size > 4096U
        || entries_lba == 0
    ) {
        return -1;
    }

    /*
     * TFB_GPT_OPTIONAL_OUTSIDE_ARRAY_ABSENT_V1_1
     *
     * Stock tangorpro currently declares exactly 26 GPT entries.
     * treeforge_os will become partition 27 only after the storage
     * split expands the GPT.
     *
     * A requested partition number beyond the current entry array
     * therefore means "not present yet", not malformed GPT.
     *
     * Required callers still fail closed by checking target->present.
     */
    if (
        (unsigned int) partition
            > entry_count
    ) {
        tfb_log(
            "pixel-partitioner-gpt=outside-entry-array-absent"
        );

        return 0;
    }

    unsigned long long
        entry_offset = (
            (
                entries_lba
                * TFB_GPT_LOGICAL_BLOCK_SIZE
            )
            + (
                (
                    (unsigned long long)
                        (partition - 1)
                )
                * (
                    (unsigned long long)
                        entry_size
                )
            )
        );

    unsigned char entry[
        TFB_GPT_ENTRY_READ_BYTES
    ];

    if (
        tfb_block_read_exact_at(
            fd,
            entry_offset,
            entry,
            sizeof(entry)
        )
        != 0
    ) {
        return -1;
    }

    int type_present = 0;

    for (
        int index = 0;
        index < 16;
        index++
    ) {
        if (entry[index] != 0) {
            type_present = 1;
            break;
        }
    }

    if (!type_present) {
        return 0;
    }

    unsigned long long
        first_lba = (
            tfb_read_le64(
                entry + 32
            )
        );

    unsigned long long
        last_lba = (
            tfb_read_le64(
                entry + 40
            )
        );

    if (
        last_lba < first_lba
        || first_lba
            > (
                18446744073709551615ULL
                / TFB_GPT_LOGICAL_BLOCK_SIZE
            )
        || (
            last_lba
            - first_lba
            + 1ULL
        )
            > (
                18446744073709551615ULL
                / TFB_GPT_LOGICAL_BLOCK_SIZE
            )
    ) {
        return -1;
    }

    if (
        tfb_gpt_decode_name(
            entry,
            target->name,
            sizeof(target->name)
        )
        != 0
    ) {
        return -1;
    }

    target->present = 1;

    target->start_bytes = (
        first_lba
        * TFB_GPT_LOGICAL_BLOCK_SIZE
    );

    target->length_bytes = (
        (
            last_lba
            - first_lba
            + 1ULL
        )
        * TFB_GPT_LOGICAL_BLOCK_SIZE
    );

    return 0;
}


static int tfb_sysfs_partition_exists(
    int partition
) {
    char path[
        TFB_BLOCK_PATH_CAPACITY
    ];

    if (
        tfb_block_make_path(
            path,
            sizeof(path),
            "/sys/class/block/sda",
            partition,
            "/dev"
        )
        != 0
    ) {
        return 0;
    }

    long fd = tfb_open(
        path,
        O_RDONLY
    );

    if (fd < 0) {
        return 0;
    }

    tfb_close(
        fd
    );

    return 1;
}


static long tfb_blkpg_operation(
    long disk_fd,
    int operation,
    int partition,
    unsigned long long start_bytes,
    unsigned long long length_bytes
) {
    struct tfb_blkpg_partition
        target = {0};

    target.start = (
        (long long)
            start_bytes
    );

    target.length = (
        (long long)
            length_bytes
    );

    target.pno = partition;

    struct tfb_blkpg_ioctl_arg
        request = {0};

    request.op = operation;

    request.datalen = (
        (int) sizeof(target)
    );

    request.data = &target;

    return tfb_syscall3(
        SYS_IOCTL,
        disk_fd,
        TFB_BLKPG,
        (long) &request
    );
}


static void tfb_log_blkpg_failure(
    long result
) {
    if (result == -16) {
        tfb_log(
            "pixel-partitioner-blkpg=ebusy"
        );
        return;
    }

    if (result == -22) {
        tfb_log(
            "pixel-partitioner-blkpg=einval"
        );
        return;
    }

    if (result == -13) {
        tfb_log(
            "pixel-partitioner-blkpg=eacces"
        );
        return;
    }

    if (result == -6) {
        tfb_log(
            "pixel-partitioner-blkpg=enxio"
        );
        return;
    }

    tfb_log(
        "pixel-partitioner-blkpg=other-error"
    );
}


static int tfb_block_create_gpt_alias(
    int partition,
    const char *name
) {
    if (
        partition <= 0
        || !name
        || !name[0]
    ) {
        return -1;
    }

    char node[
        TFB_BLOCK_PATH_CAPACITY
    ];

    if (
        tfb_block_make_path(
            node,
            sizeof(node),
            "/dev/block/sda",
            partition,
            ""
        )
        != 0
    ) {
        return -1;
    }

    char link[
        TFB_BLOCK_PATH_CAPACITY
    ];

    static const char prefix[] =
        "/dev/block/by-name/";

    usize position = 0;

    for (
        usize index = 0;
        prefix[index] != '\0';
        index++
    ) {
        if (
            position + 1
            >= sizeof(link)
        ) {
            return -1;
        }

        link[position++] =
            prefix[index];
    }

    for (
        usize index = 0;
        name[index] != '\0';
        index++
    ) {
        if (
            name[index] == '/'
            || position + 1
                >= sizeof(link)
        ) {
            return -1;
        }

        link[position++] =
            name[index];
    }

    link[position] = '\0';

    long result = tfb_syscall3(
        SYS_SYMLINKAT,
        (long) node,
        AT_FDCWD,
        (long) link
    );

    if (
        result != 0
        && result != -17
    ) {
        return -1;
    }

    return 0;
}


static void tfb_remove_treeforge_os_nodes(
    void
) {
    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)
            "/dev/block/by-name/treeforge_os",
        0
    );

    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)
            "/dev/block/sda27",
        0
    );
}


static int tfb_refresh_one_gpt_partition(
    long disk_fd,
    int partition,
    const struct tfb_gpt_partition_target
        *target
) {
    if (
        disk_fd < 0
        || partition <= 0
        || !target
    ) {
        return -1;
    }

    int exists = (
        tfb_sysfs_partition_exists(
            partition
        )
    );

    if (!target->present) {
        if (!exists) {
            if (
                partition
                == TFB_MUTABLE_OS_PARTITION
            ) {
                tfb_remove_treeforge_os_nodes();
            }

            return 0;
        }

        /*
         * Only the optional treeforge_os entry is allowed to
         * disappear.
         */
        if (
            partition
            != TFB_MUTABLE_OS_PARTITION
        ) {
            return -1;
        }

        long result = tfb_blkpg_operation(
            disk_fd,
            TFB_BLKPG_DEL_PARTITION,
            partition,
            0,
            0
        );

        if (result != 0) {
            tfb_log_blkpg_failure(
                result
            );

            return -1;
        }

        tfb_log(
            "pixel-partitioner-blkpg=delete-sda27-ok"
        );

        tfb_remove_treeforge_os_nodes();

        return 0;
    }

    int operation = (
        exists
        ? TFB_BLKPG_RESIZE_PARTITION
        : TFB_BLKPG_ADD_PARTITION
    );

    long result = tfb_blkpg_operation(
        disk_fd,
        operation,
        partition,
        target->start_bytes,
        target->length_bytes
    );

    if (result != 0) {
        tfb_log_blkpg_failure(
            result
        );

        return -1;
    }

    if (
        operation
        == TFB_BLKPG_ADD_PARTITION
    ) {
        tfb_log(
            "pixel-partitioner-blkpg=add-ok"
        );
    } else {
        tfb_log(
            "pixel-partitioner-blkpg=resize-ok"
        );
    }

    return 0;
}


static int tfb_reprobe_block_partitions(
    void
) {
    long fd = tfb_open(
        "/dev/block/sda",
        O_RDONLY
    );

    if (fd < 0) {
        return -1;
    }

    struct tfb_gpt_partition_target
        userdata;

    struct tfb_gpt_partition_target
        alternate_os;

    int result = (
        tfb_gpt_read_partition_target(
            fd,
            TFB_MUTABLE_USERDATA_PARTITION,
            &userdata
        )
    );

    if (
        result != 0
        || !userdata.present
        || !tfb_string_equal(
            userdata.name,
            "userdata"
        )
    ) {
        tfb_close(fd);

        tfb_log(
            "pixel-partitioner-gpt=userdata-invalid"
        );

        return -1;
    }

    result = (
        tfb_gpt_read_partition_target(
            fd,
            TFB_MUTABLE_OS_PARTITION,
            &alternate_os
        )
    );

    if (result != 0) {
        tfb_close(fd);

        tfb_log(
            "pixel-partitioner-gpt=sda27-invalid"
        );

        return -1;
    }

    if (
        alternate_os.present
        && !tfb_string_equal(
            alternate_os.name,
            "treeforge_os"
        )
    ) {
        tfb_close(fd);

        tfb_log(
            "pixel-partitioner-gpt=sda27-name-invalid"
        );

        return -1;
    }

    tfb_log(
        "pixel-partitioner-gpt-refresh=targeted-blkpg"
    );

    if (
        tfb_refresh_one_gpt_partition(
            fd,
            TFB_MUTABLE_USERDATA_PARTITION,
            &userdata
        )
        != 0
    ) {
        tfb_close(fd);

        return -1;
    }

    if (
        tfb_refresh_one_gpt_partition(
            fd,
            TFB_MUTABLE_OS_PARTITION,
            &alternate_os
        )
        != 0
    ) {
        tfb_close(fd);

        return -1;
    }

    tfb_close(fd);

    /*
     * BLKPG updates the kernel table synchronously, but allow sysfs
     * and the partition-device view to settle before realizing /dev.
     */
    for (
        int attempt = 0;
        attempt < 20;
        attempt++
    ) {
        int os_exists = (
            tfb_sysfs_partition_exists(
                TFB_MUTABLE_OS_PARTITION
            )
        );

        if (
            os_exists
            == alternate_os.present
        ) {
            if (
                tfb_realize_block_nodes()
                == 0
            ) {
                if (
                    tfb_block_create_gpt_alias(
                        TFB_MUTABLE_USERDATA_PARTITION,
                        userdata.name
                    )
                    != 0
                ) {
                    return -1;
                }

                if (
                    alternate_os.present
                    && tfb_block_create_gpt_alias(
                        TFB_MUTABLE_OS_PARTITION,
                        alternate_os.name
                    )
                        != 0
                ) {
                    return -1;
                }

                tfb_log(
                    "pixel-partitioner-gpt-refresh=ready"
                );

                return 0;
            }
        }

        tfb_sleep_ms(
            50
        );
    }

    tfb_log(
        "pixel-partitioner-gpt-refresh=settle-timeout"
    );

    return -1;
}


static void tfb_pixel_partitioner_service(
    const struct tfb_menu_page *page,
    int *redraw
) {
    if (
        !tfb_pixel_partitioner_page(
            page
        )
    ) {
        return;
    }

    long request = tfb_open(
        TFB_PP_REPROBE_REQUEST,
        O_RDONLY
    );

    if (request < 0) {
        return;
    }

    tfb_close(
        request
    );

    tfb_pp_remove_marker(
        TFB_PP_REPROBE_REQUEST
    );

    tfb_pp_remove_marker(
        TFB_PP_REPROBE_READY
    );

    tfb_pp_remove_marker(
        TFB_PP_REPROBE_FAILED
    );

    if (
        tfb_reprobe_block_partitions()
        == 0
    ) {
        tfb_pp_write_marker(
            TFB_PP_REPROBE_READY
        );

        tfb_menu_status =
            "PARTITION TABLE REFRESHED";

        tfb_log(
            "pixel-partitioner-reprobe=ready"
        );

    } else {
        tfb_pp_write_marker(
            TFB_PP_REPROBE_FAILED
        );

        tfb_menu_status =
            "PARTITION REPROBE FAILED";

        tfb_log(
            "pixel-partitioner-reprobe=failed"
        );
    }

    if (redraw) {
        *redraw |=
            TFB_REDRAW_STATUS;
    }
}


/*
 * TFB_VENDOR_BOOT_CARRIER_ABI_V1
 *
 * FD98 is a sequential retained carrier descriptor.  All header,
 * record, and payload bytes are consumed from that one descriptor
 * after Android FirstStageMain / FreeRamdisk.
 */
static int tfb_carrier_read_exact(
    unsigned char *buffer,
    long size
) {
    long offset = 0;

    while (offset < size) {
        long amount = tfb_syscall3(
            SYS_READ,
            TREEFORGE_BOOTSTRAP_VENDOR_BOOT_CARRIER_FD,
            (long) (
                buffer + offset
            ),
            size - offset
        );

        if (amount <= 0) {
            return 0;
        }

        offset += amount;
    }

    return 1;
}


static unsigned int tfb_carrier_le32(
    const unsigned char *value
) {
    return (
        ((unsigned int) value[0])
        | (
            ((unsigned int) value[1])
            << 8
        )
        | (
            ((unsigned int) value[2])
            << 16
        )
        | (
            ((unsigned int) value[3])
            << 24
        )
    );
}


static unsigned long long tfb_carrier_le64(
    const unsigned char *value
) {
    unsigned long long result = 0;
    int index;

    for (index = 7; index >= 0; index--) {
        result <<= 8;
        result |= (
            (unsigned long long)
            value[index]
        );
    }

    return result;
}


static int tfb_carrier_all_zero(
    const unsigned char *value,
    long size
) {
    long index;

    for (index = 0; index < size; index++) {
        if (value[index] != 0) {
            return 0;
        }
    }

    return 1;
}


static int tfb_carrier_magic_matches(
    const unsigned char *header
) {
    static const unsigned char magic[8] = {
        'T', 'F', 'B', 'C',
        'A', 'R', '0', '1'
    };

    int index;

    for (index = 0; index < 8; index++) {
        if (header[index] != magic[index]) {
            return 0;
        }
    }

    return 1;
}


static int tfb_carrier_name_matches(
    const unsigned char *record,
    const unsigned char *name,
    long name_bytes
) {
    if (
        !record
        || !name
        || name_bytes <= 0
        || name_bytes >= 64
    ) {
        return 0;
    }

    long index;

    for (index = 0; index < name_bytes; index++) {
        if (record[index] != name[index]) {
            return 0;
        }
    }

    if (record[name_bytes] != 0) {
        return 0;
    }

    return tfb_carrier_all_zero(
        record + name_bytes + 1,
        64 - name_bytes - 1
    );
}


static int tfb_carrier_proof_name_matches(
    const unsigned char *record
) {
    static const unsigned char name[] =
        "proof/retained-fd";

    return tfb_carrier_name_matches(
        record,
        name,
        (long) sizeof(name) - 1
    );
}


static int tfb_carrier_request_name_matches(
    const unsigned char *record
) {
    static const unsigned char name[] =
        "transaction/request-v1";

    return tfb_carrier_name_matches(
        record,
        name,
        (long) sizeof(name) - 1
    );
}


static int tfb_carrier_record_matches(
    const unsigned char *record,
    const unsigned char *name,
    long name_bytes,
    unsigned int expected_mode,
    unsigned long long expected_offset,
    unsigned long long expected_bytes
) {
    if (
        !tfb_carrier_name_matches(
            record,
            name,
            name_bytes
        )
        || tfb_carrier_le32(
            record + 64
        )
            != TFB_VENDOR_BOOT_CARRIER_ENTRY_FILE
        || tfb_carrier_le32(
            record + 68
        )
            != expected_mode
        || tfb_carrier_le64(
            record + 72
        )
            != expected_offset
        || tfb_carrier_le64(
            record + 80
        )
            != expected_bytes
        || !tfb_carrier_all_zero(
            record + 120,
            8
        )
    ) {
        return 0;
    }

    return 1;
}


static int tfb_carrier_transaction_request_valid(
    const unsigned char *request
) {
    static const unsigned char prefix[] =
        "TREEFORGE_BOOTSTRAP_TRANSACTION_V1\nid=";

    static const unsigned char suffix[] =
        "\noperation=proof\n";

    long prefix_bytes = (
        (long) sizeof(prefix)
        - 1
    );

    long suffix_bytes = (
        (long) sizeof(suffix)
        - 1
    );

    if (
        TFB_VENDOR_BOOT_CARRIER_REQUEST_BYTES
        != (
            prefix_bytes
            + 64
            + suffix_bytes
        )
    ) {
        return 0;
    }

    long index;

    for (index = 0; index < prefix_bytes; index++) {
        if (request[index] != prefix[index]) {
            return 0;
        }
    }

    for (index = 0; index < 64; index++) {
        unsigned char value =
            request[
                prefix_bytes
                + index
            ];

        if (
            !(
                (
                    value >= '0'
                    && value <= '9'
                )
                || (
                    value >= 'a'
                    && value <= 'f'
                )
            )
        ) {
            return 0;
        }
    }

    long suffix_offset =
        prefix_bytes
        + 64;

    for (index = 0; index < suffix_bytes; index++) {
        if (
            request[
                suffix_offset
                + index
            ]
            != suffix[index]
        ) {
            return 0;
        }
    }

    return 1;
}


static int tfb_carrier_publish_file(
    const char *path,
    const unsigned char *payload,
    long payload_bytes
) {
    long output = tfb_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long) path,
        (
            O_WRONLY
            | O_CREAT
            | O_TRUNC
        ),
        0644
    );

    if (output < 0) {
        return 0;
    }

    long offset = 0;

    while (offset < payload_bytes) {
        long written = tfb_syscall3(
            SYS_WRITE,
            output,
            (long) (
                payload
                + offset
            ),
            payload_bytes
                - offset
        );

        if (written <= 0) {
            tfb_close(
                output
            );

            return 0;
        }

        offset += written;
    }

    tfb_close(
        output
    );

    return 1;
}


/*
 * TFB_VENDOR_BOOT_CARRIER_ABI_V1
 *
 * FD98 refers to /treeforge/bootstrap-carrier opened by initial
 * Bootstrap PID1 before Android FirstStageMain tears down the
 * original ramdisk namespace.
 *
 * Validate the first production carrier container structurally:
 *
 *   magic           TFBCAR01
 *   schema          1
 *   header bytes    96
 *   record bytes    128
 *   entries         1
 *   table offset    96
 *   payload offset  224
 *
 * Then locate the single proof/retained-fd record, require its
 * canonical layout and publish its exact 43-byte payload into /dev.
 *
 * The complete vendor_boot image is already authenticated by the
 * Owner AVB graph. SHA-256 validation of the container table and
 * entry payload remains a separate dispatcher hardening step.
 */
static int tfb_vendor_boot_carrier_fd_available(
    void
) {
    unsigned char probe = 0;

    return (
        tfb_syscall3(
            SYS_READ,
            TREEFORGE_BOOTSTRAP_VENDOR_BOOT_CARRIER_FD,
            (long) &probe,
            0
        )
        == 0
    );
}


static int tfb_publish_vendor_boot_carrier_proof(
    void
) {
    unsigned char header[
        TFB_VENDOR_BOOT_CARRIER_HEADER_BYTES
    ];

    unsigned char records[
        2
    ][
        TFB_VENDOR_BOOT_CARRIER_RECORD_BYTES
    ];

    unsigned char proof[
        TFB_VENDOR_BOOT_CARRIER_PROOF_BYTES
    ];

    unsigned char request[
        TFB_VENDOR_BOOT_CARRIER_REQUEST_BYTES
    ];

    unsigned char trailing;

    if (
        !tfb_carrier_read_exact(
            header,
            TFB_VENDOR_BOOT_CARRIER_HEADER_BYTES
        )
    ) {
        return 0;
    }

    if (
        !tfb_carrier_magic_matches(
            header
        )
    ) {
        return 0;
    }

    unsigned int schema =
        tfb_carrier_le32(
            header + 8
        );

    unsigned int header_bytes =
        tfb_carrier_le32(
            header + 12
        );

    unsigned int record_bytes =
        tfb_carrier_le32(
            header + 16
        );

    unsigned int entry_count =
        tfb_carrier_le32(
            header + 20
        );

    unsigned long long table_offset =
        tfb_carrier_le64(
            header + 24
        );

    unsigned long long payload_offset =
        tfb_carrier_le64(
            header + 32
        );

    unsigned long long total_bytes =
        tfb_carrier_le64(
            header + 40
        );

    if (
        schema
            != TFB_VENDOR_BOOT_CARRIER_SCHEMA
        || header_bytes
            != TFB_VENDOR_BOOT_CARRIER_HEADER_BYTES
        || record_bytes
            != TFB_VENDOR_BOOT_CARRIER_RECORD_BYTES
        || (
            entry_count != 1
            && entry_count != 2
        )
        || table_offset
            != TFB_VENDOR_BOOT_CARRIER_HEADER_BYTES
        || payload_offset
            != (
                TFB_VENDOR_BOOT_CARRIER_HEADER_BYTES
                + (
                    (
                        unsigned long long
                    ) entry_count
                    * TFB_VENDOR_BOOT_CARRIER_RECORD_BYTES
                )
            )
        || !tfb_carrier_all_zero(
            header + 80,
            16
        )
    ) {
        return 0;
    }

    unsigned int index;

    for (
        index = 0;
        index < entry_count;
        index++
    ) {
        if (
            !tfb_carrier_read_exact(
                records[index],
                TFB_VENDOR_BOOT_CARRIER_RECORD_BYTES
            )
        ) {
            return 0;
        }
    }

    static const unsigned char proof_name[] =
        "proof/retained-fd";

    if (
        !tfb_carrier_record_matches(
            records[0],
            proof_name,
            (long) sizeof(proof_name) - 1,
            0444,
            payload_offset,
            TFB_VENDOR_BOOT_CARRIER_PROOF_BYTES
        )
    ) {
        return 0;
    }

    int request_present = (
        entry_count == 2
    );

    unsigned long long request_offset = (
        payload_offset
        + TFB_VENDOR_BOOT_CARRIER_PROOF_BYTES
    );

    if (request_present) {
        static const unsigned char request_name[] =
            "transaction/request-v1";

        if (
            !tfb_carrier_record_matches(
                records[1],
                request_name,
                (long) sizeof(request_name) - 1,
                0644,
                request_offset,
                TFB_VENDOR_BOOT_CARRIER_REQUEST_BYTES
            )
        ) {
            return 0;
        }
    }

    unsigned long long expected_total = (
        payload_offset
        + TFB_VENDOR_BOOT_CARRIER_PROOF_BYTES
    );

    if (request_present) {
        expected_total += (
            TFB_VENDOR_BOOT_CARRIER_REQUEST_BYTES
        );
    }

    if (total_bytes != expected_total) {
        return 0;
    }

    if (
        !tfb_carrier_read_exact(
            proof,
            TFB_VENDOR_BOOT_CARRIER_PROOF_BYTES
        )
    ) {
        return 0;
    }

    if (request_present) {
        if (
            !tfb_carrier_read_exact(
                request,
                TFB_VENDOR_BOOT_CARRIER_REQUEST_BYTES
            )
            || !tfb_carrier_transaction_request_valid(
                request
            )
        ) {
            return 0;
        }
    }

    /*
     * Exact total length: after consuming all declared payloads
     * there must be no additional byte in the retained carrier.
     */
    long extra = tfb_syscall3(
        SYS_READ,
        TREEFORGE_BOOTSTRAP_VENDOR_BOOT_CARRIER_FD,
        (long) &trailing,
        1
    );

    if (extra != 0) {
        return 0;
    }

    if (
        !tfb_carrier_publish_file(
            TFB_VENDOR_BOOT_CARRIER_PROOF_PATH,
            proof,
            TFB_VENDOR_BOOT_CARRIER_PROOF_BYTES
        )
    ) {
        return 0;
    }

    if (
        request_present
        && !tfb_carrier_publish_file(
            TFB_VENDOR_BOOT_CARRIER_REQUEST_PATH,
            request,
            TFB_VENDOR_BOOT_CARRIER_REQUEST_BYTES
        )
    ) {
        return 0;
    }

    return 1;
}



/*
 * ================================================================
 * TFB_TRANSACTION_V2_BOOTSTRAP_R1
 * ================================================================
 *
 * Bootstrap-owned Transaction ABI v2 execution.
 *
 * Durable state:
 *
 *   /metadata/treeforge-bootstrap/transaction-v2.pending
 *   /metadata/treeforge-bootstrap/transaction-v2.pending.tmp
 *   /metadata/treeforge-bootstrap/transaction-v2.running
 *   /metadata/treeforge-bootstrap/transaction-v2.result
 *   /metadata/treeforge-bootstrap/transaction-v2.result.tmp
 *
 * R1 accepts exactly the Android-origin Bootstrap proof request.
 *
 * Normal path:
 *
 *   pending -> running -> result/continuation -> Android A
 *
 * Crash recovery:
 *
 *   running alone
 *       recovery-required; never replay
 *
 *   running + matching continuation result
 *       retire running and return to Android
 *
 *   matching continuation result alone
 *       return to Android without replay
 *
 * Stale temporary files, malformed records, mixed live slots,
 * ownership violations, or unsupported operations fail closed.
 *
 * No Menu API owns transaction state.
 * No Pixel Partitioner runtime participation.
 * No transactiond socket access.
 * No shell execution.
 */

#define TFB_TRANSACTION_V2_TEXT_MAX 1024
#define TFB_TRANSACTION_V2_ID_LENGTH 64
#define TFB_TRANSACTION_V2_ENOENT 2

static const char
tfb_transaction_v2_pending_path[] =
    "/metadata/treeforge-bootstrap/"
    "transaction-v2.pending";

static const char
tfb_transaction_v2_pending_temp_path[] =
    "/metadata/treeforge-bootstrap/"
    "transaction-v2.pending.tmp";

static const char
tfb_transaction_v2_running_path[] =
    "/metadata/treeforge-bootstrap/"
    "transaction-v2.running";

static const char
tfb_transaction_v2_result_path[] =
    "/metadata/treeforge-bootstrap/"
    "transaction-v2.result";

static const char
tfb_transaction_v2_result_temp_path[] =
    "/metadata/treeforge-bootstrap/"
    "transaction-v2.result.tmp";


enum tfb_transaction_v2_file_status {
    TFB_TX_FILE_MISSING = 0,
    TFB_TX_FILE_VALID = 1,
    TFB_TX_FILE_INVALID = 2,
    TFB_TX_FILE_ERROR = 3,
};


static int tfb_transaction_v2_lower_hex(
    char value
) {
    return (
        (
            value >= '0'
            && value <= '9'
        )
        || (
            value >= 'a'
            && value <= 'f'
        )
    );
}


static int tfb_transaction_v2_match_literal(
    const char **cursor,
    const char *literal
) {
    if (
        !cursor
        || !*cursor
        || !literal
    ) {
        return 0;
    }

    while (*literal != '\0') {
        if (**cursor != *literal) {
            return 0;
        }

        (*cursor)++;
        literal++;
    }

    return 1;
}


static int tfb_transaction_v2_parse_id(
    const char **cursor,
    char id[
        TFB_TRANSACTION_V2_ID_LENGTH
        + 1
    ]
) {
    if (
        !cursor
        || !*cursor
        || !id
    ) {
        return 0;
    }

    for (
        usize index = 0;
        index
            < TFB_TRANSACTION_V2_ID_LENGTH;
        index++
    ) {
        char value = (*cursor)[index];

        if (
            !tfb_transaction_v2_lower_hex(
                value
            )
        ) {
            return 0;
        }

        id[index] = value;
    }

    id[
        TFB_TRANSACTION_V2_ID_LENGTH
    ] = '\0';

    *cursor +=
        TFB_TRANSACTION_V2_ID_LENGTH;

    return 1;
}


static int
tfb_transaction_v2_parse_proof_request(
    const char *text,
    char id[
        TFB_TRANSACTION_V2_ID_LENGTH
        + 1
    ]
) {
    if (
        !text
        || !id
    ) {
        return 0;
    }

    const char *cursor = text;

    if (
        !tfb_transaction_v2_match_literal(
            &cursor,
            "TREEFORGE_TRANSACTION_V2\n"
            "id="
        )
        || !tfb_transaction_v2_parse_id(
            &cursor,
            id
        )
        || !tfb_transaction_v2_match_literal(
            &cursor,
            "\n"
            "step=0\n"
            "origin=android\n"
            "consumer=bootstrap\n"
            "operation=proof\n"
            "phase=request\n"
            "payload_type=none\n"
            "payload_ref=-\n"
            "payload_sha256=-\n"
            "target=none\n"
            "return_target=android_a\n"
            "status=ready\n"
            "result=-\n"
        )
    ) {
        return 0;
    }

    return *cursor == '\0';
}


static int
tfb_transaction_v2_parse_proof_continuation(
    const char *text,
    char id[
        TFB_TRANSACTION_V2_ID_LENGTH
        + 1
    ]
) {
    if (
        !text
        || !id
    ) {
        return 0;
    }

    const char *cursor = text;

    if (
        !tfb_transaction_v2_match_literal(
            &cursor,
            "TREEFORGE_TRANSACTION_V2\n"
            "id="
        )
        || !tfb_transaction_v2_parse_id(
            &cursor,
            id
        )
        || !tfb_transaction_v2_match_literal(
            &cursor,
            "\n"
            "step=1\n"
            "origin=android\n"
            "consumer=android\n"
            "operation=proof\n"
            "phase=continuation\n"
            "payload_type=none\n"
            "payload_ref=-\n"
            "payload_sha256=-\n"
            "target=none\n"
            "return_target=android_a\n"
            "status=ready\n"
            "result=proof_bootstrap_pass\n"
        )
    ) {
        return 0;
    }

    return *cursor == '\0';
}


static enum tfb_transaction_v2_file_status
tfb_transaction_v2_read_text(
    const char *path,
    char *buffer,
    usize capacity
) {
    if (
        !path
        || !buffer
        || capacity < 2
    ) {
        return TFB_TX_FILE_ERROR;
    }

    long fd = tfb_open(
        path,
        O_RDONLY
    );

    if (
        fd
        == -TFB_TRANSACTION_V2_ENOENT
    ) {
        return TFB_TX_FILE_MISSING;
    }

    if (fd < 0) {
        return TFB_TX_FILE_ERROR;
    }

    usize offset = 0;

    while (
        offset + 1 < capacity
    ) {
        long amount = tfb_syscall3(
            SYS_READ,
            fd,
            (long) (
                buffer
                + offset
            ),
            (long) (
                capacity
                - offset
                - 1
            )
        );

        if (amount == 0) {
            break;
        }

        if (amount < 0) {
            tfb_close(fd);
            return TFB_TX_FILE_ERROR;
        }

        for (
            long index = 0;
            index < amount;
            index++
        ) {
            if (
                buffer[
                    offset
                    + (usize) index
                ] == '\0'
            ) {
                tfb_close(fd);
                return TFB_TX_FILE_INVALID;
            }
        }

        offset += (usize) amount;
    }

    if (
        offset + 1
        >= capacity
    ) {
        char extra = 0;

        long amount = tfb_syscall3(
            SYS_READ,
            fd,
            (long) &extra,
            1
        );

        if (amount < 0) {
            tfb_close(fd);
            return TFB_TX_FILE_ERROR;
        }

        if (amount > 0) {
            tfb_close(fd);
            return TFB_TX_FILE_INVALID;
        }
    }

    tfb_close(fd);

    if (offset == 0) {
        return TFB_TX_FILE_INVALID;
    }

    buffer[offset] = '\0';

    return TFB_TX_FILE_VALID;
}


static int tfb_transaction_v2_path_presence(
    const char *path
) {
    long fd = tfb_open(
        path,
        O_RDONLY
    );

    if (fd >= 0) {
        tfb_close(fd);
        return 1;
    }

    if (
        fd
        == -TFB_TRANSACTION_V2_ENOENT
    ) {
        return 0;
    }

    return -1;
}


static int tfb_transaction_v2_write_piece(
    long fd,
    const char *value
) {
    if (
        fd < 0
        || !value
    ) {
        return 0;
    }

    usize remaining =
        tfb_strlen(
            value
        );

    const char *cursor =
        value;

    while (remaining != 0) {
        long amount = tfb_syscall3(
            SYS_WRITE,
            fd,
            (long) cursor,
            (long) remaining
        );

        if (amount <= 0) {
            return 0;
        }

        cursor += amount;
        remaining -=
            (usize) amount;
    }

    return 1;
}


static void tfb_transaction_v2_unlink_temp(
    const char *path
) {
    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long) path,
        0
    );
}


static int
tfb_transaction_v2_write_continuation_temp(
    const char id[
        TFB_TRANSACTION_V2_ID_LENGTH
        + 1
    ]
) {
    if (!id) {
        return 0;
    }

    long fd = tfb_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long)
            tfb_transaction_v2_result_temp_path,
        O_WRONLY
            | O_CREAT
            | O_TRUNC,
        0644
    );

    if (fd < 0) {
        return 0;
    }

    int ok = (
        tfb_transaction_v2_write_piece(
            fd,
            "TREEFORGE_TRANSACTION_V2\n"
            "id="
        )
        && tfb_transaction_v2_write_piece(
            fd,
            id
        )
        && tfb_transaction_v2_write_piece(
            fd,
            "\n"
            "step=1\n"
            "origin=android\n"
            "consumer=android\n"
            "operation=proof\n"
            "phase=continuation\n"
            "payload_type=none\n"
            "payload_ref=-\n"
            "payload_sha256=-\n"
            "target=none\n"
            "return_target=android_a\n"
            "status=ready\n"
            "result=proof_bootstrap_pass\n"
        )
    );

    if (
        ok
        && tfb_syscall1(
            SYS_FSYNC,
            fd
        ) < 0
    ) {
        ok = 0;
    }

    tfb_close(fd);

    if (!ok) {
        tfb_transaction_v2_unlink_temp(
            tfb_transaction_v2_result_temp_path
        );

        return 0;
    }

    return 1;
}


static int tfb_transaction_v2_rename(
    const char *from,
    const char *to
) {
    return (
        tfb_syscall4(
            SYS_RENAMEAT,
            AT_FDCWD,
            (long) from,
            AT_FDCWD,
            (long) to
        ) >= 0
    );
}


static int tfb_transaction_v2_unlink(
    const char *path
) {
    return (
        tfb_syscall3(
            SYS_UNLINKAT,
            AT_FDCWD,
            (long) path,
            0
        ) >= 0
    );
}


static void tfb_transaction_v2_sync(
    void
) {
    tfb_syscall1(
        SYS_SYNC,
        0
    );
}


__attribute__((noreturn))
static void tfb_transaction_v2_fail(
    const char *detail
) {
    tfb_log(
        detail
            ? detail
            : "transaction-v2=unknown-error"
    );

    tfb_transition_failure(
        "transaction-v2-error"
    );
}


__attribute__((noreturn))
static void
tfb_transaction_v2_handoff_android(
    void
) {
    if (!tfb_runtime_envp) {
        tfb_transaction_v2_fail(
            "transaction-v2=android-env-missing"
        );
    }

    tfb_log(
        "transaction-v2=handoff-android-a"
    );

    /*
     * Transaction interception runs before tfb_run_menu().
     * No menu input set and no TreeForge ADB service have been
     * acquired yet. Close the ordinary Bootstrap diagnostics FDs
     * before continuing through Android's accepted selinux_setup
     * handoff.
     */
    tfb_close(
        tfb_tty
    );
    tfb_tty = -1;

    tfb_close(
        tfb_console
    );
    tfb_console = -1;

    tfb_close(
        tfb_kmsg
    );
    tfb_kmsg = -1;

    char *android_argv[] = {
        (char *)
            "/system/bin/init",
        (char *)
            "selinux_setup",
        0
    };

    tfb_syscall3(
        SYS_EXECVE,
        (long)
            "/system/bin/init",
        (long)
            android_argv,
        (long)
            tfb_runtime_envp
    );

    tfb_transition_failure(
        "android-slot-a-exec"
    );
}


static void tfb_transaction_v2_pre_menu(
    void
) {
    int pending_temp =
        tfb_transaction_v2_path_presence(
            tfb_transaction_v2_pending_temp_path
        );

    int result_temp =
        tfb_transaction_v2_path_presence(
            tfb_transaction_v2_result_temp_path
        );

    if (
        pending_temp != 0
        || result_temp != 0
    ) {
        tfb_transaction_v2_fail(
            "transaction-v2=stale-temp"
        );
    }

    char pending_text[
        TFB_TRANSACTION_V2_TEXT_MAX
    ];

    char running_text[
        TFB_TRANSACTION_V2_TEXT_MAX
    ];

    char result_text[
        TFB_TRANSACTION_V2_TEXT_MAX
    ];

    enum tfb_transaction_v2_file_status
        pending_status =
            tfb_transaction_v2_read_text(
                tfb_transaction_v2_pending_path,
                pending_text,
                sizeof(pending_text)
            );

    enum tfb_transaction_v2_file_status
        running_status =
            tfb_transaction_v2_read_text(
                tfb_transaction_v2_running_path,
                running_text,
                sizeof(running_text)
            );

    enum tfb_transaction_v2_file_status
        result_status =
            tfb_transaction_v2_read_text(
                tfb_transaction_v2_result_path,
                result_text,
                sizeof(result_text)
            );

    if (
        pending_status
            == TFB_TX_FILE_ERROR
        || running_status
            == TFB_TX_FILE_ERROR
        || result_status
            == TFB_TX_FILE_ERROR
    ) {
        tfb_transaction_v2_fail(
            "transaction-v2=state-io-error"
        );
    }

    if (
        pending_status
            == TFB_TX_FILE_INVALID
        || running_status
            == TFB_TX_FILE_INVALID
        || result_status
            == TFB_TX_FILE_INVALID
    ) {
        tfb_transaction_v2_fail(
            "transaction-v2=malformed-record"
        );
    }

    /*
     * Recover only the ABI-v2 state explicitly permitted:
     *
     *     running + matching result
     *
     * The proof operation itself is never replayed.
     */
    if (
        running_status
        == TFB_TX_FILE_VALID
    ) {
        if (
            pending_status
            == TFB_TX_FILE_VALID
        ) {
            tfb_transaction_v2_fail(
                "transaction-v2=running-pending-conflict"
            );
        }

        char running_id[
            TFB_TRANSACTION_V2_ID_LENGTH
            + 1
        ];

        if (
            !tfb_transaction_v2_parse_proof_request(
                running_text,
                running_id
            )
        ) {
            tfb_transaction_v2_fail(
                "transaction-v2=running-invalid"
            );
        }

        if (
            result_status
            == TFB_TX_FILE_MISSING
        ) {
            tfb_transaction_v2_fail(
                "transaction-v2=running-recovery-required"
            );
        }

        char result_id[
            TFB_TRANSACTION_V2_ID_LENGTH
            + 1
        ];

        if (
            !tfb_transaction_v2_parse_proof_continuation(
                result_text,
                result_id
            )
            || !tfb_string_equal(
                running_id,
                result_id
            )
        ) {
            tfb_transaction_v2_fail(
                "transaction-v2=recovery-result-mismatch"
            );
        }

        if (
            !tfb_transaction_v2_unlink(
                tfb_transaction_v2_running_path
            )
        ) {
            tfb_transaction_v2_fail(
                "transaction-v2=recovery-retire-running-failed"
            );
        }

        tfb_transaction_v2_sync();

        tfb_log(
            "transaction-v2=recovered-published-continuation"
        );

        tfb_transaction_v2_handoff_android();
    }

    /*
     * A continuation already durably published for Android is not
     * replayed. Return directly to its consumer.
     */
    if (
        result_status
        == TFB_TX_FILE_VALID
    ) {
        if (
            pending_status
            == TFB_TX_FILE_VALID
        ) {
            tfb_transaction_v2_fail(
                "transaction-v2=result-pending-conflict"
            );
        }

        char result_id[
            TFB_TRANSACTION_V2_ID_LENGTH
            + 1
        ];

        if (
            !tfb_transaction_v2_parse_proof_continuation(
                result_text,
                result_id
            )
        ) {
            tfb_transaction_v2_fail(
                "transaction-v2=result-not-bootstrap-proof-continuation"
            );
        }

        tfb_log(
            "transaction-v2=continuation-already-published"
        );

        tfb_transaction_v2_handoff_android();
    }

    if (
        pending_status
        == TFB_TX_FILE_MISSING
    ) {
        /*
         * No transaction: preserve the exact existing Bootstrap
         * menu path.
         */
        return;
    }

    char transaction_id[
        TFB_TRANSACTION_V2_ID_LENGTH
        + 1
    ];

    if (
        !tfb_transaction_v2_parse_proof_request(
            pending_text,
            transaction_id
        )
    ) {
        tfb_transaction_v2_fail(
            "transaction-v2=pending-unsupported-or-invalid"
        );
    }

    /*
     * Claim:
     *
     *     pending -> running
     *
     * renameat is the ownership boundary. A lone running record is
     * never treated as executable on a later boot.
     */
    if (
        !tfb_transaction_v2_rename(
            tfb_transaction_v2_pending_path,
            tfb_transaction_v2_running_path
        )
    ) {
        tfb_transaction_v2_fail(
            "transaction-v2=claim-rename-failed"
        );
    }

    tfb_transaction_v2_sync();

    char claimed_text[
        TFB_TRANSACTION_V2_TEXT_MAX
    ];

    char claimed_id[
        TFB_TRANSACTION_V2_ID_LENGTH
        + 1
    ];

    if (
        tfb_transaction_v2_read_text(
            tfb_transaction_v2_running_path,
            claimed_text,
            sizeof(claimed_text)
        )
            != TFB_TX_FILE_VALID
        || !tfb_transaction_v2_parse_proof_request(
            claimed_text,
            claimed_id
        )
        || !tfb_string_equal(
            transaction_id,
            claimed_id
        )
    ) {
        tfb_transaction_v2_fail(
            "transaction-v2=claim-verification-failed"
        );
    }

    tfb_log(
        "transaction-v2=proof-claimed"
    );

    /*
     * Bounded Bootstrap-side proof:
     *
     * Reaching this exact post-FirstStageMain point proves Bootstrap
     * has survived the Android first-stage transition, /metadata is
     * available, the canonical request is readable, and ownership
     * was atomically claimed by Bootstrap.
     *
     * Publish the Android continuation before retiring running.
     */
    if (
        !tfb_transaction_v2_write_continuation_temp(
            transaction_id
        )
    ) {
        tfb_transaction_v2_fail(
            "transaction-v2=result-temp-write-failed"
        );
    }

    if (
        !tfb_transaction_v2_rename(
            tfb_transaction_v2_result_temp_path,
            tfb_transaction_v2_result_path
        )
    ) {
        tfb_transaction_v2_fail(
            "transaction-v2=result-publish-rename-failed"
        );
    }

    tfb_transaction_v2_sync();

    char published_text[
        TFB_TRANSACTION_V2_TEXT_MAX
    ];

    char published_id[
        TFB_TRANSACTION_V2_ID_LENGTH
        + 1
    ];

    if (
        tfb_transaction_v2_read_text(
            tfb_transaction_v2_result_path,
            published_text,
            sizeof(published_text)
        )
            != TFB_TX_FILE_VALID
        || !tfb_transaction_v2_parse_proof_continuation(
            published_text,
            published_id
        )
        || !tfb_string_equal(
            transaction_id,
            published_id
        )
    ) {
        tfb_transaction_v2_fail(
            "transaction-v2=result-verification-failed"
        );
    }

    /*
     * result is durable first. Only now retire the running marker.
     * If power is lost before this unlink, the next Bootstrap boot
     * sees running + matching result and performs recovery without
     * replaying the proof.
     */
    if (
        !tfb_transaction_v2_unlink(
            tfb_transaction_v2_running_path
        )
    ) {
        tfb_transaction_v2_fail(
            "transaction-v2=retire-running-failed"
        );
    }

    tfb_transaction_v2_sync();

    tfb_log(
        "transaction-v2=proof-continuation-published"
    );

    tfb_transaction_v2_handoff_android();
}


/* TFB_TRANSACTION_V2_BOOTSTRAP_R1_END */


__TREEFORGE_KERNEL_PROOF_SOURCE__
__TREEFORGE_SECURITY_HANDOFF_SOURCE__
__TREEFORGE_MENU_CONTROLLER_SOURCE__static void tfb_main(
    long argc,
    char **argv,
    char **envp
) {
    /*
     * Second invocation:
     *
     * Google FirstStageMain completed the proven tangorpro early
     * hardware/module boundary and redirected its selinux_setup exec
     * back to the inherited TreeForge Bootstrap FD99 image.
     */
    if (argc > 1) {
        if (
            !argv[1]
            || !tfb_string_equal(
                argv[1],
                "selinux_setup"
            )
        ) {
            tfb_transition_failure(
                "invalid-treeforge-bootstrap-reentry"
            );
        }

        tfb_kmsg = tfb_open(
            "/dev/kmsg",
            O_WRONLY
            | O_NONBLOCK
        );

        tfb_tty = tfb_open(
            "/dev/tty0",
            O_WRONLY
            | O_NONBLOCK
        );

        tfb_console = tfb_open(
            "/dev/console",
            O_WRONLY
            | O_NONBLOCK
        );

        if (
            tfb_vendor_boot_carrier_fd_available()
        ) {
            int vendor_boot_carrier_proof =
                tfb_publish_vendor_boot_carrier_proof();

            tfb_close(
                TREEFORGE_BOOTSTRAP_VENDOR_BOOT_CARRIER_FD
            );

            if (vendor_boot_carrier_proof) {
                tfb_log(
                    "vendor-boot-carrier-proof=pass"
                );
            } else {
                tfb_log(
                    "vendor-boot-carrier-proof=failed"
                );
            }
        } else {
            tfb_log(
                "vendor-boot-carrier=absent"
            );
        }

        if (
            !tfb_materialize_runtime_bundle()
        ) {
            tfb_transition_failure(
                "treeforge-bootstrap-runtime-materialize"
            );
        }

        tfb_log(
            "treeforge-bootstrap-runtime=materialized"
        );

        /*
         * The complete retained runtime now exists under /dev.
         * The inherited dispatcher FD is no longer needed.
         */
        tfb_close(
            TREEFORGE_BOOTSTRAP_TRANSITION_FD
        );

        tfb_runtime_envp =
            envp;

        /*
         * Transaction ABI v2 is Bootstrap-owned and runs before any
         * normal Boot Manager/menu initialization.
         */
        tfb_transaction_v2_pre_menu();

        tfb_menu_load_runtime_state();


        /*
         * TFB_TOUCHSCREEN_MODULE_REALIZATION_V14
         *
         * The matching vendor module tree is already mounted by
         * Google first-stage. Realize the three remaining touch
         * roots before tfb_run_menu() performs its existing generic
         * /sys/class/input/event* -> /dev/input/event* realization.
         *
         * Failure is intentionally non-fatal: hardware-key menu
         * control remains available.
         */
        tfb_realize_touchscreen_modules(
            envp
        );

        /*
         * Do not alter Android's live /bin or /system/bin namespace.
         * TreeForge's standalone ADB runtime is fully self-contained
         * under /dev/treeforge-bootstrap-runtime.
         */
        tfb_start_adb_service(
            envp
        );

        /* Reconcile only a prior exact health receipt, once per boot. ADB is
         * already running; Menu inventory itself remains strictly read-only. */
        tfb_publish_kernel_proof();
        tfb_altos_reconcile_health();
        tfb_menu_load_runtime_state();

        tfb_run_menu();
    }

    /*
     * Initial invocation from the kernel.
     *
     * FD99 carries this dispatcher and the appended TreeForge Bootstrap
     * runtime bundle through Google's proven FirstStageMain boundary.
     *
     * When an explicit transaction carrier exists, FD98 carries its
     * open file description across FreeRamdisk.
     */
    long self_fd = tfb_open(
        "/init",
        O_RDONLY
    );

    if (self_fd < 0) {
        tfb_transition_failure(
            "transition-fd-open"
        );
    }

    if (
        self_fd
        != TREEFORGE_BOOTSTRAP_TRANSITION_FD
    ) {
        long duplicated = tfb_syscall3(
            SYS_DUP3,
            self_fd,
            TREEFORGE_BOOTSTRAP_TRANSITION_FD,
            0
        );

        if (duplicated < 0) {
            tfb_close(
                self_fd
            );

            tfb_transition_failure(
                "transition-fd-duplicate"
            );
        }

        tfb_close(
            self_fd
        );
    }

    /*
     * TFB_VENDOR_BOOT_CARRIER_ABI_V1
     *
     * If an explicit transaction carrier exists, open it while the
     * original ramdisk namespace is still visible and retain its
     * file description independently on FD98.
     */
    /*
     * FD98 is reserved by Bootstrap. Close any unrelated inherited
     * descriptor before optionally retaining the transaction carrier.
     */
    tfb_close(
        TREEFORGE_BOOTSTRAP_VENDOR_BOOT_CARRIER_FD
    );

    long vendor_boot_carrier_fd = tfb_open(
        TFB_VENDOR_BOOT_CARRIER_PATH,
        O_RDONLY
    );

    if (
        vendor_boot_carrier_fd >= 0
        && vendor_boot_carrier_fd
        != TREEFORGE_BOOTSTRAP_VENDOR_BOOT_CARRIER_FD
    ) {
        long carrier_duplicated =
            tfb_syscall3(
                SYS_DUP3,
                vendor_boot_carrier_fd,
                TREEFORGE_BOOTSTRAP_VENDOR_BOOT_CARRIER_FD,
                0
            );

        if (carrier_duplicated < 0) {
            tfb_close(
                vendor_boot_carrier_fd
            );

            tfb_transition_failure(
                "vendor-boot-carrier-fd-duplicate"
            );
        }

        tfb_close(
            vendor_boot_carrier_fd
        );
    }

    char *first_stage_argv[] = {
        (char *) "/init",
        0
    };

    tfb_syscall3(
        SYS_EXECVE,
        (long)
            "/init.treeforge-bootstrap-first-stage",
        (long) first_stage_argv,
        (long) envp
    );

    tfb_transition_failure(
        "first-stage-exec"
    );
}

__attribute__((used, noreturn))
static void tfb_entry(
    usize *initial_stack
) {
    long argc = (
        (long) initial_stack[0]
    );

    char **argv = (
        (char **) (
            initial_stack
            + 1
        )
    );

    char **envp = (
        argv
        + argc
        + 1
    );

    tfb_main(
        argc,
        argv,
        envp
    );
}

__attribute__((naked, noreturn))
void _start(void) {
    __asm__ volatile(
        "mov x0, sp\n"
        "b tfb_entry\n"
    );
}

'''

    @classmethod
    def _elf_machine(
        cls,
        data: bytes,
    ) -> int:
        if (
            not isinstance(
                data,
                bytes,
            )
            or len(data) < 20
        ):
            raise TreeForgeDispatcherError(
                "canonical init payload is too small to be ELF"
            )

        if data[:4] != b"\x7fELF":
            raise TreeForgeDispatcherError(
                "canonical init payload is not ELF"
            )

        if data[4] != 2:
            raise TreeForgeDispatcherError(
                "TreeForge Bootstrap early dispatcher currently requires "
                "a canonical ELF64 init"
            )

        if data[5] != 1:
            raise TreeForgeDispatcherError(
                "TreeForge Bootstrap early dispatcher currently requires "
                "a little-endian canonical init"
            )

        return struct.unpack_from(
            "<H",
            data,
            18,
        )[0]

    @staticmethod
    def _compiler() -> Path:
        explicit = os.environ.get(
            "TREEFORGE_BOOTSTRAP_CLANG"
        )

        if explicit:
            candidate = (
                Path(explicit)
                .expanduser()
                .resolve()
            )

            if not candidate.is_file():
                raise TreeForgeDispatcherError(
                    "TREEFORGE_BOOTSTRAP_CLANG does not reference an existing file: "
                    f"{candidate}"
                )

            return candidate

        discovered = shutil.which(
            "clang"
        )

        if discovered is None:
            raise TreeForgeDispatcherError(
                "TreeForge Bootstrap early dispatcher requires clang. "
                "Install clang or set TREEFORGE_BOOTSTRAP_CLANG."
            )

        return Path(
            discovered
        ).resolve()

    @staticmethod
    def _c_string(
        value: str,
    ) -> str:
        return (
            '"'
            + value
            .replace(
                "\\",
                "\\\\",
            )
            .replace(
                '"',
                '\\"',
            )
            + '"'
        )

    @classmethod
    def _menu_c_source(
        cls,
        profile: MenuProfile,
    ) -> str:
        if not isinstance(
            profile,
            MenuProfile,
        ):
            raise TypeError(
                "profile must be a MenuProfile"
            )

        action_names = {
            None:
                "TFB_ACTION_NONE",

            MenuAction.BOOT_ANDROID_SLOT_A:
                "TFB_ACTION_BOOT_ANDROID_SLOT_A",

            MenuAction.BOOT_ANDROID_SLOT_B:
                "TFB_ACTION_BOOT_ANDROID_SLOT_B",

            MenuAction.BOOT_ALTERNATE_OS:
                "TFB_ACTION_BOOT_ALTERNATE_OS",

            MenuAction.BOOT_DIAGNOSTICS:
                "TFB_ACTION_BOOT_DIAGNOSTICS",

            MenuAction.BOOT_ROOTED_ANDROID:
                "TFB_ACTION_BOOT_ROOTED_ANDROID",

            MenuAction.INSTALL_ROOT:
                "TFB_ACTION_INSTALL_ROOT",

            MenuAction.UNINSTALL_ROOT:
                "TFB_ACTION_UNINSTALL_ROOT",

            MenuAction.TOGGLE_ROOT_PERSISTENCE:
                "TFB_ACTION_TOGGLE_ROOT_PERSISTENCE",

            MenuAction.REBOOT_SYSTEM:
                "TFB_ACTION_REBOOT_SYSTEM",

            MenuAction.REBOOT_BOOTLOADER:
                "TFB_ACTION_REBOOT_BOOTLOADER",

            MenuAction.REBOOT_RECOVERY:
                "TFB_ACTION_REBOOT_RECOVERY",

            MenuAction.SET_BOOT_TARGET_SLOT_A:
                "TFB_ACTION_SET_BOOT_TARGET_SLOT_A",

            MenuAction.SET_BOOT_TARGET_SLOT_B:
                "TFB_ACTION_SET_BOOT_TARGET_SLOT_B",

            MenuAction.LIVE_CONSOLE:
                "TFB_ACTION_LIVE_CONSOLE",

            MenuAction.RESTART_ADB_USB:
                "TFB_ACTION_RESTART_ADB_USB",

            MenuAction.NOT_IMPLEMENTED:
                "TFB_ACTION_NOT_IMPLEMENTED",

            MenuAction.BACK:
                "TFB_ACTION_BACK",
        }

        condition_names = {
            MenuCondition.ALWAYS:
                "TFB_CONDITION_ALWAYS",

            MenuCondition.FULL_AB:
                "TFB_CONDITION_FULL_AB",

            MenuCondition.ALTERNATE_OS_CONFIGURED:
                "TFB_CONDITION_ALTERNATE_OS_CONFIGURED",

            MenuCondition.ROOT_INSTALLED:
                "TFB_CONDITION_ROOT_INSTALLED",

            MenuCondition.ROOT_NOT_INSTALLED:
                "TFB_CONDITION_ROOT_NOT_INSTALLED",
        }

        label_state_names = {
            MenuLabelState.NONE:
                "TFB_LABEL_STATE_NONE",

            MenuLabelState.ROOT_PERSISTENCE:
                "TFB_LABEL_STATE_ROOT_PERSISTENCE",

            MenuLabelState.ALTERNATE_OS_NAME:
                "TFB_LABEL_STATE_ALTERNATE_OS_NAME",
        }

        icon_names = {
            MenuIcon.NONE:
                "TFB_MENU_ICON_NONE",

            MenuIcon.ANDROID:
                "TFB_MENU_ICON_ANDROID",

            MenuIcon.RECOVERY:
                "TFB_MENU_ICON_RECOVERY",

            MenuIcon.MAINTENANCE:
                "TFB_MENU_ICON_MAINTENANCE",

            MenuIcon.ALTERNATE_OS:
                "TFB_MENU_ICON_ALTERNATE_OS",

            MenuIcon.ROOT:
                "TFB_MENU_ICON_ROOT",

            MenuIcon.PIXEL_PARTITIONER:
                "TFB_MENU_ICON_PIXEL_PARTITIONER",

            MenuIcon.BOOTLOADER:
                "TFB_MENU_ICON_BOOTLOADER",

            MenuIcon.BACK:
                "TFB_MENU_ICON_BACK",
        }

        def symbol(
            page: MenuPage,
        ) -> str:
            profile_name = (
                profile.profile_id
                .replace(
                    "-",
                    "_",
                )
            )

            page_name = (
                page.page_id
                .replace(
                    "-",
                    "_",
                )
            )

            return (
                "tfb_profile_"
                + profile_name
                + "_"
                + page_name
            )

        emitted: set[str] = set()
        blocks: list[str] = []

        def emit(
            page: MenuPage,
        ) -> None:
            page_symbol = symbol(
                page
            )

            if page_symbol in emitted:
                return

            for entry in page.entries:
                if entry.submenu is not None:
                    emit(
                        entry.submenu
                    )

            entry_symbol = (
                page_symbol
                + "_entries"
            )

            lines = [
                "static const struct tfb_menu_entry",
                f"{entry_symbol}[] = {{",
            ]

            for entry in page.entries:
                submenu = (
                    "0"
                    if entry.submenu is None
                    else (
                        "&"
                        + symbol(
                            entry.submenu
                        )
                    )
                )

                lines.extend(
                    (
                        "    {",
                        (
                            "        "
                            + cls._c_string(
                                entry.label
                            )
                            + ","
                        ),
                        (
                            "        "
                            + cls._c_string(
                                entry.description
                            )
                            + ","
                        ),
                        (
                            "        "
                            + icon_names[
                                entry.icon
                            ]
                            + ","
                        ),
                        (
                            "        "
                            + action_names[
                                entry.action
                            ]
                            + ","
                        ),
                        (
                            "        "
                            + submenu
                            + ","
                        ),
                        (
                            "        "
                            + condition_names[
                                entry.visible_if
                            ]
                            + ","
                        ),
                        (
                            "        "
                            + label_state_names[
                                entry.label_state
                            ]
                        ),
                        "    },",
                    )
                )

            lines.append(
                "};"
            )

            default_index = next(
                index
                for index, entry
                in enumerate(
                    page.entries
                )
                if (
                    entry.entry_id
                    == page.default_entry
                )
            )

            timeout_action = (
                action_names[
                    page.timeout_action
                ]
            )

            lines.extend(
                (
                    "",
                    (
                        "static const struct "
                        "tfb_menu_page "
                        + page_symbol
                        + " = {"
                    ),
                    (
                        "    "
                        + cls._c_string(
                            page.title
                        )
                        + ","
                    ),
                    (
                        "    "
                        + cls._c_string(
                            page.subtitle
                        )
                        + ","
                    ),
                    (
                        "    "
                        + str(
                            page.timeout_ms
                        )
                        + "U,"
                    ),
                    (
                        "    "
                        + timeout_action
                        + ","
                    ),
                    (
                        "    "
                        + str(
                            default_index
                        )
                        + ","
                    ),
                    (
                        "    "
                        + entry_symbol
                        + ","
                    ),
                    (
                        "    (int) (sizeof("
                        + entry_symbol
                        + ") / sizeof("
                        + entry_symbol
                        + "[0]))"
                    ),
                    "};",
                )
            )

            blocks.append(
                "\n".join(
                    lines
                )
            )

            emitted.add(
                page_symbol
            )

        emit(
            profile.root
        )

        root_symbol = symbol(
            profile.root
        )

        blocks.append(
            "\n".join(
                (
                    (
                        "static const char "
                        "tfb_menu_profile_marker[] = "
                        '"TREEFORGE_MENU_PROFILE_V1";'
                    ),
                    (
                        "static const char "
                        "tfb_menu_profile_id[] = "
                        + cls._c_string(
                            profile.profile_id
                        )
                        + ";"
                    ),
                    "",
                    (
                        "static const struct "
                        "tfb_menu_page *"
                    ),
                    "tfb_menu_root_page(void) {",
                    (
                        "    return &"
                        + root_symbol
                        + ";"
                    ),
                    "}",
                )
            )
        )

        return "\n\n".join(
            blocks
        )

    @classmethod
    def build(
        cls,
        *,
        canonical_init: bytes,
        output_root: Path,
        runtime_bundle: bytes = b"",
        menu_profile: MenuProfile | None = None,
    ) -> TreeForgeDispatcherBuild:
        if not isinstance(
            runtime_bundle,
            bytes,
        ):
            raise TypeError(
                "runtime_bundle must be bytes"
            )

        if (
            len(runtime_bundle) < 32
            or runtime_bundle[:8]
            != b"TFRTB001"
            or runtime_bundle[-16:-8]
            != b"TFRTEND1"
        ):
            raise TreeForgeDispatcherError(
                "invalid TreeForge Bootstrap "
                "FD99 runtime bundle"
            )

        declared_bundle_size = (
            int.from_bytes(
                runtime_bundle[-8:],
                "little",
            )
        )

        if (
            declared_bundle_size
            != len(runtime_bundle) - 16
        ):
            raise TreeForgeDispatcherError(
                "TreeForge Bootstrap FD99 "
                "bundle trailer size mismatch"
            )

        if not isinstance(
            output_root,
            Path,
        ):
            raise TypeError(
                "output_root must be a pathlib.Path"
            )

        menu_provider = (
            load_menu_provider()
        )

        if menu_profile is None:
            menu_profile = (
                load_default_profile()
            )

        if not isinstance(
            menu_profile,
            MenuProfile,
        ):
            raise TypeError(
                "menu_profile must be a MenuProfile"
            )

        menu_source = (
            cls._menu_c_source(
                menu_profile
            )
        )

        framebuffer_provider = (
            load_framebuffer_provider()
        )

        machine = cls._elf_machine(
            canonical_init
        )

        if (
            machine
            != cls.ELF_MACHINE_AARCH64
        ):
            raise TreeForgeDispatcherError(
                "TreeForge Bootstrap dispatcher "
                "does not support canonical "
                f"ELF machine {machine}"
            )

        compiler = cls._compiler()

        output_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        source_path = (
            output_root
            / "treeforge-bootstrap-dispatch.c"
        )

        executable_path = (
            output_root
            / "treeforge-bootstrap-dispatch"
        )

        bootstrap_placeholder = (
            "__TREEFORGE_BOOTSTRAP_VERSION__"
        )

        boot_menu_placeholder = (
            "__TREEFORGE_BOOT_MENU_VERSION__"
        )

        placeholder = (
            "__TREEFORGE_BOOT_MANAGER_VERSION__"
        )

        runtime_abi_placeholder = (
            "__TREEFORGE_RUNTIME_ABI_VERSION__"
        )

        framebuffer_placeholder = (
            "__TREEFORGE_FRAMEBUFFER_PROVIDER_VERSION__"
        )

        build_date_placeholder = (
            "__TREEFORGE_BUILD_DATE__"
        )

        for (
            version_placeholder,
            label,
        ) in (
            (
                bootstrap_placeholder,
                "TreeForge Bootstrap",
            ),
            (
                boot_menu_placeholder,
                "TreeForge Boot Menu",
            ),
            (
                placeholder,
                "TreeForge Boot Manager",
            ),
            (
                runtime_abi_placeholder,
                "TreeForge Runtime ABI",
            ),
            (
                framebuffer_placeholder,
                "TreeForge Framebuffer",
            ),
            (
                build_date_placeholder,
                "TreeForge build date",
            ),
        ):
            if (
                cls._SOURCE.count(
                    version_placeholder
                )
                != 1
            ):
                raise TreeForgeDispatcherError(
                    label
                    + " version placeholder is not unique"
                )

        framebuffer_primitives_placeholder = (
            "__TREEFORGE_FRAMEBUFFER_PRIMITIVES_SOURCE__"
        )

        framebuffer_transport_placeholder = (
            "__TREEFORGE_FRAMEBUFFER_TRANSPORT_SOURCE__"
        )

        for framebuffer_source_placeholder in (
            framebuffer_primitives_placeholder,
            framebuffer_transport_placeholder,
        ):
            if (
                cls._SOURCE.count(
                    framebuffer_source_placeholder
                )
                != 1
            ):
                raise TreeForgeDispatcherError(
                    "TreeForge framebuffer provider "
                    "source placeholder is not unique"
                )

        menu_source_placeholders = (
            ("__TREEFORGE_MENU_CORE_SOURCE__", menu_provider.core_source),
            ("__TREEFORGE_MENU_UI_SOURCE__", menu_provider.ui_source),
            ("__TREEFORGE_MENU_TOUCH_SOURCE__", menu_provider.touch_source),
            ("__TREEFORGE_MENU_CONTROLLER_SOURCE__", menu_provider.controller_source),
        )

        for menu_source_placeholder, _menu_provider_source in menu_source_placeholders:
            if cls._SOURCE.count(menu_source_placeholder) != 1:
                raise TreeForgeDispatcherError(
                    "TreeForge menu provider source placeholder is not unique: "
                    + menu_source_placeholder
                )

        profile_placeholder = (
            "__TREEFORGE_MENU_PROFILE__"
        )

        if menu_provider.core_source.count(profile_placeholder) != 1:
            raise TreeForgeDispatcherError(
                "TreeForge Menu profile placeholder is not unique in menu provider"
            )

        source_date_epoch = (
            os.environ.get(
                "SOURCE_DATE_EPOCH"
            )
        )

        if source_date_epoch:
            try:
                build_timestamp = int(
                    source_date_epoch
                )
            except ValueError as error:
                raise TreeForgeDispatcherError(
                    "invalid SOURCE_DATE_EPOCH"
                ) from error

            build_date = (
                datetime.fromtimestamp(
                    build_timestamp,
                    tz=timezone.utc,
                )
                .strftime("%Y-%m-%d")
            )
        else:
            build_date = (
                version_build_date()
            )

        generated_source = (
            cls._SOURCE
            .replace(
                "__TREEFORGE_KERNEL_PROOF_SOURCE__",
                (Path(__file__).resolve().parents[2] / "runtime/initramfs/src/kernel_proof.c").read_text(encoding="utf-8"),
            ).replace(
                "__TREEFORGE_SECURITY_HANDOFF_SOURCE__",
                (Path(__file__).resolve().parents[2] / "runtime/initramfs/src/security_handoff.c").read_text(encoding="utf-8"),
            ).replace(
                "__TREEFORGE_ALTOS_STORAGE_SOURCE__",
                (Path(__file__).resolve().parents[2] / "runtime/initramfs/src/alternate_storage.c").read_text(encoding="utf-8"),
                1,
            )
            .replace(
                framebuffer_primitives_placeholder,
                framebuffer_provider.primitives_source,
                1,
            )
            .replace(
                framebuffer_transport_placeholder,
                framebuffer_provider.transport_source,
                1,
            )
            .replace(
                "__TREEFORGE_MENU_CORE_SOURCE__",
                menu_provider.core_source,
                1,
            )
            .replace(
                "__TREEFORGE_MENU_UI_SOURCE__",
                menu_provider.ui_source,
                1,
            )
            .replace(
                "__TREEFORGE_MENU_TOUCH_SOURCE__",
                menu_provider.touch_source,
                1,
            )
            .replace(
                "__TREEFORGE_MENU_CONTROLLER_SOURCE__",
                menu_provider.controller_source,
                1,
            )
            .replace(
                bootstrap_placeholder,
                project_version(),
                1,
            )
            .replace(
                boot_menu_placeholder,
                menu_provider.version,
                1,
            )
            .replace(
                placeholder,
                menu_provider.boot_manager_version,
                1,
            )
            .replace(
                runtime_abi_placeholder,
                runtime_abi_version(),
                1,
            )
            .replace(
                framebuffer_placeholder,
                framebuffer_provider.version,
                1,
            )
            .replace(
                build_date_placeholder,
                build_date,
                1,
            )
            .replace(
                profile_placeholder,
                menu_source,
                1,
            )
        )

        source_path.write_text(
            generated_source,
            encoding="utf-8",
        )

        executable_path.unlink(
            missing_ok=True
        )

        command = (
            str(compiler),
            "--target=aarch64-linux-gnu",
            "-Os",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-pic",
            "-nostdlib",
            "-static",
            "-fuse-ld=lld",
            "-Wl,-e,_start",
            "-Wl,--build-id=none",
            "-Wl,-z,max-page-size=4096",
            str(source_path),
            "-o",
            str(executable_path),
        )

        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        if completed.returncode != 0:
            raise TreeForgeDispatcherError(
                "unable to build TreeForge Bootstrap "
                "dispatcher:\n"
                + completed.stderr.decode(
                    "utf-8",
                    errors="replace",
                )
            )

        executable = (
            executable_path.read_bytes()
        )

        if (
            cls._elf_machine(
                executable
            )
            != machine
        ):
            raise TreeForgeDispatcherError(
                "TreeForge Bootstrap dispatcher "
                "architecture mismatch"
            )

        executable = (
            executable
            + runtime_bundle
        )

        executable_path.write_bytes(
            executable
        )

        executable_path.chmod(
            0o755
        )

        return TreeForgeDispatcherBuild(
            source_path=source_path,
            executable_path=executable_path,
            compiler_path=compiler,
            elf_machine=machine,
            target_triple="aarch64-linux-gnu",
        )


__all__ = (
    "TreeForgeDispatcherBuild",
    "TreeForgeDispatcherBuilder",
    "TreeForgeDispatcherError",
)
