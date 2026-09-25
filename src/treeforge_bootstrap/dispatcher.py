from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import shutil
import struct
import subprocess
import tomllib

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
#define PROT_READ 1
#define PROT_WRITE 2

#define MAP_SHARED 1

#define S_IFCHR 0020000
#define S_IFBLK 0060000

/*
 * TFB_PIXEL_PARTITIONER_SERVICE_V1
 *
 * Entering the Pixel Partitioner submenu is the explicit authorization
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

/*
 * Retained TreeForge Bootstrap framebuffer menu session.
 *
 * The framebuffer bridge itself still uses the native DRM mode
 * coordinates exactly as exposed by the kernel. TreeForge V17 adds
 * a software-only logical landscape presentation layer above this
 * raw transport; no DRM plane rotation is requested.
 */
static int tfb_fb_menu_active = 0;


static long tfb_fb_menu_mapped_address = -1;
static u64 tfb_fb_menu_mapped_size = 0;

static u32 tfb_fb_menu_width = 0;
static u32 tfb_fb_menu_height = 0;
static u32 tfb_fb_menu_pitch = 0;





/*
 * TREEFORGE_BOOTSTRAP_FB_CONSUMER_V1
 *
 * Early-menu transport for the read-only GS201 framebuffer bridge.
 *
 * The kernel owns discovery/validation of the already-scanning
 * bootloader framebuffer. Userspace only:
 *
 *   - realizes the misc node if Android ueventd has not done so yet;
 *   - reads the fixed ABI-v1 description;
 *   - mmaps the already-live linear 32-bit scanout;
 *   - points the existing menu renderer at that mapping;
 *   - seals the bridge before final OS handoff.
 *
 * No DECON/DPP/DRM programming is performed by this path.
 */
#define TFB_FB_DEVICE_PATH \
    "/dev/treeforge_bootstrap_fb"

#define TFB_FB_SYSFS_DEV_PATH \
    "/sys/class/misc/treeforge_bootstrap_fb/dev"

#define TFB_FB_ABI_VERSION 1U

#define TFB_FB_FLAG_LINEAR \
    (1U << 0)

#define TFB_FB_FLAG_WRITE_COMBINE \
    (1U << 1)

#define TFB_FB_REQUIRED_FLAGS \
    ( \
        TFB_FB_FLAG_LINEAR \
        | TFB_FB_FLAG_WRITE_COMBINE \
    )

/*
 * Linux generic _IO('P', 0x01).
 */
#define TFB_FB_IOCTL_SEAL 0x5001UL

struct tfb_fb_info {
    u32 abi_version;
    u32 hw_format;

    u32 width;
    u32 height;

    u32 source_width;
    u32 source_height;

    u32 source_x;
    u32 source_y;

    u32 stride;
    u32 bytes_per_pixel;

    u32 dpp_index;
    u32 flags;

    u64 framebuffer_bytes;
    u64 mmap_bytes;
};

typedef char tfb_fb_info_size_check[
    sizeof(struct tfb_fb_info) == 64
    ? 1
    : -1
];

static long tfb_fb_fd = -1;
static int tfb_fb_active = 0;
static int tfb_fb_created_node = 0;


static void tfb_fb_fill_rect(
    u32 x,
    u32 y,
    u32 width,
    u32 height,
    u32 pixel
) {
    if (
        !tfb_fb_menu_active
        || tfb_fb_menu_mapped_address < 0
        || x >= tfb_fb_menu_width
        || y >= tfb_fb_menu_height
    ) {
        return;
    }

    if (
        width
        > tfb_fb_menu_width - x
    ) {
        width = (
            tfb_fb_menu_width - x
        );
    }

    if (
        height
        > tfb_fb_menu_height - y
    ) {
        height = (
            tfb_fb_menu_height - y
        );
    }

    volatile unsigned char *base = (
        (volatile unsigned char *)
        (usize) tfb_fb_menu_mapped_address
    );

    for (
        u32 row_index = 0;
        row_index < height;
        row_index++
    ) {
        volatile u32 *row = (
            (volatile u32 *)
            (
                base
                + (
                    (usize) (
                        y + row_index
                    )
                    * (usize) tfb_fb_menu_pitch
                )
            )
        );

        for (
            u32 column = 0;
            column < width;
            column++
        ) {
            row[
                x + column
            ] = pixel;
        }
    }
}


static unsigned char tfb_fb_glyph_row(
    char character,
    int row
) {
    if (row < 0 || row > 6) {
        return 0;
    }

    /*
     * The bring-up UI does not require distinct lowercase glyphs.
     * Folding lowercase into the complete uppercase alphabet keeps
     * paths and diagnostic text readable without duplicating font data.
     */
    if (
        character >= 'a'
        && character <= 'z'
    ) {
        character = (
            character
            - 'a'
            + 'A'
        );
    }

#define TF_GLYPH(a,b,c,d,e,f,g) \
    ((const unsigned char[7]) { \
        (a),(b),(c),(d),(e),(f),(g) \
    })[row]

    switch (character) {
        case 'A': return TF_GLYPH(0x0E,0x11,0x11,0x1F,0x11,0x11,0x11);
        case 'B': return TF_GLYPH(0x1E,0x11,0x11,0x1E,0x11,0x11,0x1E);
        case 'C': return TF_GLYPH(0x0E,0x11,0x10,0x10,0x10,0x11,0x0E);
        case 'D': return TF_GLYPH(0x1E,0x11,0x11,0x11,0x11,0x11,0x1E);
        case 'E': return TF_GLYPH(0x1F,0x10,0x10,0x1E,0x10,0x10,0x1F);
        case 'F': return TF_GLYPH(0x1F,0x10,0x10,0x1E,0x10,0x10,0x10);
        case 'G': return TF_GLYPH(0x0E,0x11,0x10,0x17,0x11,0x11,0x0F);
        case 'H': return TF_GLYPH(0x11,0x11,0x11,0x1F,0x11,0x11,0x11);
        case 'I': return TF_GLYPH(0x0E,0x04,0x04,0x04,0x04,0x04,0x0E);
        case 'J': return TF_GLYPH(0x07,0x02,0x02,0x02,0x12,0x12,0x0C);
        case 'K': return TF_GLYPH(0x11,0x12,0x14,0x18,0x14,0x12,0x11);
        case 'L': return TF_GLYPH(0x10,0x10,0x10,0x10,0x10,0x10,0x1F);
        case 'M': return TF_GLYPH(0x11,0x1B,0x15,0x15,0x11,0x11,0x11);
        case 'N': return TF_GLYPH(0x11,0x19,0x15,0x13,0x11,0x11,0x11);
        case 'O': return TF_GLYPH(0x0E,0x11,0x11,0x11,0x11,0x11,0x0E);
        case 'P': return TF_GLYPH(0x1E,0x11,0x11,0x1E,0x10,0x10,0x10);
        case 'Q': return TF_GLYPH(0x0E,0x11,0x11,0x11,0x15,0x12,0x0D);
        case 'R': return TF_GLYPH(0x1E,0x11,0x11,0x1E,0x14,0x12,0x11);
        case 'S': return TF_GLYPH(0x0F,0x10,0x10,0x0E,0x01,0x01,0x1E);
        case 'T': return TF_GLYPH(0x1F,0x04,0x04,0x04,0x04,0x04,0x04);
        case 'U': return TF_GLYPH(0x11,0x11,0x11,0x11,0x11,0x11,0x0E);
        case 'V': return TF_GLYPH(0x11,0x11,0x11,0x11,0x11,0x0A,0x04);
        case 'W': return TF_GLYPH(0x11,0x11,0x11,0x15,0x15,0x15,0x0A);
        case 'X': return TF_GLYPH(0x11,0x11,0x0A,0x04,0x0A,0x11,0x11);
        case 'Y': return TF_GLYPH(0x11,0x11,0x0A,0x04,0x04,0x04,0x04);
        case 'Z': return TF_GLYPH(0x1F,0x01,0x02,0x04,0x08,0x10,0x1F);

        case '0': return TF_GLYPH(0x0E,0x11,0x13,0x15,0x19,0x11,0x0E);
        case '1': return TF_GLYPH(0x04,0x0C,0x04,0x04,0x04,0x04,0x0E);
        case '2': return TF_GLYPH(0x0E,0x11,0x01,0x02,0x04,0x08,0x1F);
        case '3': return TF_GLYPH(0x1E,0x01,0x01,0x0E,0x01,0x01,0x1E);
        case '4': return TF_GLYPH(0x02,0x06,0x0A,0x12,0x1F,0x02,0x02);
        case '5': return TF_GLYPH(0x1F,0x10,0x10,0x1E,0x01,0x01,0x1E);
        case '6': return TF_GLYPH(0x0E,0x10,0x10,0x1E,0x11,0x11,0x0E);
        case '7': return TF_GLYPH(0x1F,0x01,0x02,0x04,0x08,0x08,0x08);
        case '8': return TF_GLYPH(0x0E,0x11,0x11,0x0E,0x11,0x11,0x0E);
        case '9': return TF_GLYPH(0x0E,0x11,0x11,0x0F,0x01,0x01,0x0E);

        case '/': return TF_GLYPH(0x01,0x02,0x02,0x04,0x08,0x08,0x10);
        case '\\': return TF_GLYPH(0x10,0x08,0x08,0x04,0x02,0x02,0x01);
        case '-': return TF_GLYPH(0x00,0x00,0x00,0x1F,0x00,0x00,0x00);
        case '_': return TF_GLYPH(0x00,0x00,0x00,0x00,0x00,0x00,0x1F);
        case '.': return TF_GLYPH(0x00,0x00,0x00,0x00,0x00,0x06,0x06);
        case ':': return TF_GLYPH(0x00,0x04,0x04,0x00,0x04,0x04,0x00);
        case '=': return TF_GLYPH(0x00,0x1F,0x00,0x1F,0x00,0x00,0x00);
        case '+': return TF_GLYPH(0x00,0x04,0x04,0x1F,0x04,0x04,0x00);
        case '%': return TF_GLYPH(0x19,0x1A,0x04,0x04,0x08,0x0B,0x13);
        case '^': return TF_GLYPH(0x04,0x0A,0x11,0x00,0x00,0x00,0x00);
        case '(': return TF_GLYPH(0x02,0x04,0x08,0x08,0x08,0x04,0x02);
        case ')': return TF_GLYPH(0x08,0x04,0x02,0x02,0x02,0x04,0x08);
        case '[': return TF_GLYPH(0x0E,0x08,0x08,0x08,0x08,0x08,0x0E);
        case ']': return TF_GLYPH(0x0E,0x02,0x02,0x02,0x02,0x02,0x0E);
        case ' ': return 0;

        default:
            /*
             * Unknown characters are intentionally visible rather than
             * silently disappearing from diagnostic output.
             */
            return TF_GLYPH(
                0x1F,
                0x11,
                0x01,
                0x02,
                0x04,
                0x00,
                0x04
            );
    }

#undef TF_GLYPH
}


static void tfb_fb_draw_char(
    u32 x,
    u32 y,
    char value,
    u32 scale,
    u32 pixel
) {
    for (
        int row = 0;
        row < 7;
        row++
    ) {
        unsigned char bits = (
            tfb_fb_glyph_row(
                value,
                row
            )
        );

        for (
            int column = 0;
            column < 5;
            column++
        ) {
            if (
                bits
                & (
                    1U
                    << (
                        4 - column
                    )
                )
            ) {
                tfb_fb_fill_rect(
                    x + (
                        (u32) column
                        * scale
                    ),
                    y + (
                        (u32) row
                        * scale
                    ),
                    scale,
                    scale,
                    pixel
                );
            }
        }
    }
}


static u32 tfb_fb_text_width(
    const char *value,
    u32 scale
) {
    usize length = (
        tfb_strlen(
            value
        )
    );

    if (length == 0) {
        return 0;
    }

    return (
        ((u32) length * 6U * scale)
        - scale
    );
}


static void tfb_fb_draw_text(
    u32 x,
    u32 y,
    const char *value,
    u32 scale,
    u32 pixel
) {
    u32 cursor = x;

    for (
        usize index = 0;
        value[index] != '\0';
        index++
    ) {
        if (value[index] != ' ') {
            tfb_fb_draw_char(
                cursor,
                y,
                value[index],
                scale,
                pixel
            );
        }

        cursor += (
            6U * scale
        );
    }
}



static const char tfb_version[] =
    "V__TREEFORGE_BOOTSTRAP_VERSION__";


#define TFB_ACTION_NONE 0
#define TFB_ACTION_BOOT_ANDROID_SLOT_A 1
#define TFB_ACTION_BOOT_ANDROID_SLOT_B 2
#define TFB_ACTION_BOOT_ALTERNATE_OS 3
#define TFB_ACTION_BOOT_ROOTED_ANDROID 4
#define TFB_ACTION_INSTALL_ROOT 5
#define TFB_ACTION_UNINSTALL_ROOT 6
#define TFB_ACTION_TOGGLE_ROOT_PERSISTENCE 7
#define TFB_ACTION_REBOOT_BOOTLOADER 8
#define TFB_ACTION_REBOOT_RECOVERY 9
#define TFB_ACTION_BACK 10
#define TFB_ACTION_SET_BOOT_TARGET_SLOT_A 11
#define TFB_ACTION_SET_BOOT_TARGET_SLOT_B 12
#define TFB_ACTION_LIVE_CONSOLE 13
#define TFB_ACTION_RESTART_ADB_USB 14
#define TFB_ACTION_NOT_IMPLEMENTED 15
#define TFB_ACTION_BOOT_DIAGNOSTICS 16

#define TFB_CONDITION_ALWAYS 0
#define TFB_CONDITION_FULL_AB 1
#define TFB_CONDITION_ALTERNATE_OS_CONFIGURED 2
#define TFB_CONDITION_ROOT_INSTALLED 3
#define TFB_CONDITION_ROOT_NOT_INSTALLED 4

#define TFB_LABEL_STATE_NONE 0
#define TFB_LABEL_STATE_ROOT_PERSISTENCE 1
#define TFB_LABEL_STATE_ALTERNATE_OS_NAME 2

#define TFB_MENU_ICON_NONE 0
#define TFB_MENU_ICON_ANDROID 1
#define TFB_MENU_ICON_RECOVERY 2
#define TFB_MENU_ICON_MAINTENANCE 3
#define TFB_MENU_ICON_ALTERNATE_OS 4
#define TFB_MENU_ICON_ROOT 5
#define TFB_MENU_ICON_PIXEL_PARTITIONER 6
#define TFB_MENU_ICON_BOOTLOADER 7
#define TFB_MENU_ICON_BACK 8

#define TFB_MENU_STACK_DEPTH 4


struct tfb_menu_page;


struct tfb_menu_entry {
    const char *label;
    const char *description;
    int icon;
    int action;
    const struct tfb_menu_page *submenu;
    int condition;
    int label_state;
};


struct tfb_menu_page {
    const char *title;
    const char *subtitle;
    u32 timeout_ms;
    int timeout_action;
    int default_entry_index;
    const struct tfb_menu_entry *entries;
    int entry_count;
};


struct tfb_menu_runtime_state {
    int full_ab;
    int alternate_os_configured;
    char alternate_os_name[64];
    int root_installed;
    int root_persistence_enabled;
};


static struct tfb_menu_runtime_state
tfb_menu_state = {
    0,
    0,
    "Alternate OS",
    0,
    0,
};


static const char *tfb_menu_status = 0;

static char **tfb_runtime_envp = 0;


__TREEFORGE_MENU_PROFILE__



static int tfb_menu_read_state_text(
    const char *path,
    char *buffer,
    usize capacity
) {
    if (
        !path
        || !buffer
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

    if (amount <= 0) {
        return 0;
    }

    usize length = (
        (usize) amount
    );

    if (length >= capacity) {
        length = capacity - 1;
    }

    buffer[length] = '\0';

    for (
        usize index = 0;
        index < length;
        index++
    ) {
        unsigned char value = (
            (unsigned char)
            buffer[index]
        );

        if (
            value == '\n'
            || value == '\r'
        ) {
            buffer[index] = '\0';
            length = index;
            break;
        }

        if (
            value < 0x20
            || value > 0x7e
        ) {
            buffer[0] = '\0';
            return 0;
        }
    }

    return length > 0;
}


/*
 * TFB_FULL_AB_GEOMETRY_DETECTION_V17_1A
 *
 * Current release support is explicitly tangorpro. Its canonical
 * factory GPT places super at sda25 with 16,662,528 512-byte
 * sectors. TreeForge Full A/B grows that physical partition.
 *
 * Keep the metadata marker as an explicit affirmative contract,
 * but do not require it for a converted device.
 */
#define TFB_TANGORPRO_STOCK_SUPER_SECTORS 16662528ULL


static int tfb_ui_read_u64(
    const char *path,
    u64 *output
);


static void tfb_menu_load_runtime_state(
    void
) {
    int full_ab_by_marker = 0;

    long full_ab = tfb_open(
        "/metadata/treeforge-bootstrap/full-ab",
        O_RDONLY
        | O_NONBLOCK
    );

    if (full_ab >= 0) {
        full_ab_by_marker = 1;

        tfb_close(
            full_ab
        );
    }

    u64 super_sectors = 0;

    int full_ab_by_geometry = (
        tfb_ui_read_u64(
            "/sys/class/block/sda25/size",
            &super_sectors
        )
        && super_sectors
            > TFB_TANGORPRO_STOCK_SUPER_SECTORS
    );

    tfb_menu_state.full_ab = (
        full_ab_by_marker
        || full_ab_by_geometry
    );

    char alternate_name[64];

    if (
        tfb_menu_read_state_text(
            "/metadata/treeforge-bootstrap/"
            "alternate-os-name",
            alternate_name,
            sizeof(alternate_name)
        )
    ) {
        usize index = 0;

        while (
            alternate_name[index] != '\0'
            && index
                < sizeof(
                    tfb_menu_state
                    .alternate_os_name
                ) - 1
        ) {
            tfb_menu_state
                .alternate_os_name[index] =
                alternate_name[index];

            index++;
        }

        tfb_menu_state
            .alternate_os_name[index] =
            '\0';

        tfb_menu_state
            .alternate_os_configured = 1;
    } else {
        static const char fallback[] =
            "Alternate OS";

        usize index = 0;

        while (
            fallback[index] != '\0'
            && index
                < sizeof(
                    tfb_menu_state
                    .alternate_os_name
                ) - 1
        ) {
            tfb_menu_state
                .alternate_os_name[index] =
                fallback[index];

            index++;
        }

        tfb_menu_state
            .alternate_os_name[index] =
            '\0';

        tfb_menu_state
            .alternate_os_configured = 0;
    }
}


static int tfb_menu_condition_visible(
    int condition
) {
    if (
        condition
        == TFB_CONDITION_ALWAYS
    ) {
        return 1;
    }

    if (
        condition
        == TFB_CONDITION_FULL_AB
    ) {
        return (
            tfb_menu_state
            .full_ab
            != 0
        );
    }

    if (
        condition
        == TFB_CONDITION_ALTERNATE_OS_CONFIGURED
    ) {
        return (
            tfb_menu_state
            .alternate_os_configured
            != 0
        );
    }

    if (
        condition
        == TFB_CONDITION_ROOT_INSTALLED
    ) {
        return (
            tfb_menu_state
            .root_installed
            != 0
        );
    }

    if (
        condition
        == TFB_CONDITION_ROOT_NOT_INSTALLED
    ) {
        return (
            tfb_menu_state
            .root_installed
            == 0
        );
    }

    return 0;
}



static int tfb_menu_visible_count(
    const struct tfb_menu_page *page
) {
    if (!page) {
        return 0;
    }

    int count = 0;

    for (
        int index = 0;
        index < page->entry_count;
        index++
    ) {
        if (
            tfb_menu_condition_visible(
                page->entries[
                    index
                ].condition
            )
        ) {
            count++;
        }
    }

    return count;
}


static const struct tfb_menu_entry *
tfb_menu_visible_entry(
    const struct tfb_menu_page *page,
    int visible_index
) {
    if (
        !page
        || visible_index < 0
    ) {
        return 0;
    }

    int visible = 0;

    for (
        int index = 0;
        index < page->entry_count;
        index++
    ) {
        const struct tfb_menu_entry *entry = (
            &page->entries[
                index
            ]
        );

        if (
            !tfb_menu_condition_visible(
                entry->condition
            )
        ) {
            continue;
        }

        if (
            visible
            == visible_index
        ) {
            return entry;
        }

        visible++;
    }

    return 0;
}


static int tfb_menu_default_selection(
    const struct tfb_menu_page *page
) {
    if (!page) {
        return 0;
    }

    int visible = 0;

    for (
        int index = 0;
        index < page->entry_count;
        index++
    ) {
        const struct tfb_menu_entry *entry = (
            &page->entries[
                index
            ]
        );

        if (
            !tfb_menu_condition_visible(
                entry->condition
            )
        ) {
            continue;
        }

        if (
            index
            == page->default_entry_index
        ) {
            return visible;
        }

        visible++;
    }

    return 0;
}


static int tfb_menu_move_selection(
    const struct tfb_menu_page *page,
    int selected,
    int delta
) {
    int count = (
        tfb_menu_visible_count(
            page
        )
    );

    if (count <= 0) {
        return 0;
    }

    if (
        selected < 0
        || selected >= count
    ) {
        selected = 0;
    }

    selected += delta;

    while (selected < 0) {
        selected += count;
    }

    while (selected >= count) {
        selected -= count;
    }

    return selected;
}


static const char *tfb_menu_entry_label(
    const struct tfb_menu_entry *entry
) {

    if (
        entry->label_state
        == TFB_LABEL_STATE_ALTERNATE_OS_NAME
    ) {
        return (
            tfb_menu_state
            .alternate_os_name
        );
    }


    if (!entry) {
        return "";
    }

    if (
        entry->label_state
        != TFB_LABEL_STATE_ROOT_PERSISTENCE
    ) {
        return entry->label;
    }

    static char state_label[96];

    usize position = 0;

    while (
        entry->label[
            position
        ] != '\0'
        && position < 88
    ) {
        state_label[
            position
        ] = entry->label[
            position
        ];

        position++;
    }

    const char *suffix = (
        tfb_menu_state
        .root_persistence_enabled
        ? " [ON]"
        : " [OFF]"
    );

    usize suffix_index = 0;

    while (
        suffix[
            suffix_index
        ] != '\0'
        && position < 95
    ) {
        state_label[
            position
        ] = suffix[
            suffix_index
        ];

        position++;
        suffix_index++;
    }

    state_label[
        position
    ] = '\0';

    return state_label;
}


static const char *tfb_menu_action_name(
    int action
) {
    if (
        action
        == TFB_ACTION_BOOT_ANDROID_SLOT_A
    ) {
        return "boot_android_slot_a";
    }

    if (
        action
        == TFB_ACTION_BOOT_ANDROID_SLOT_B
    ) {
        return "boot_android_slot_b";
    }

    if (
        action
        == TFB_ACTION_BOOT_ALTERNATE_OS
    ) {
        return "boot_alternate_os";
    }

    if (
        action
        == TFB_ACTION_BOOT_DIAGNOSTICS
    ) {
        return "boot_diagnostics";
    }

    if (
        action
        == TFB_ACTION_BOOT_ROOTED_ANDROID
    ) {
        return "boot_rooted_android";
    }

    if (
        action
        == TFB_ACTION_INSTALL_ROOT
    ) {
        return "install_root";
    }

    if (
        action
        == TFB_ACTION_UNINSTALL_ROOT
    ) {
        return "uninstall_root";
    }

    if (
        action
        == TFB_ACTION_TOGGLE_ROOT_PERSISTENCE
    ) {
        return "toggle_root_persistence";
    }

    if (
        action
        == TFB_ACTION_REBOOT_BOOTLOADER
    ) {
        return "reboot_bootloader";
    }

    if (
        action
        == TFB_ACTION_REBOOT_RECOVERY
    ) {
        return "reboot_recovery";
    }

    if (
        action
        == TFB_ACTION_SET_BOOT_TARGET_SLOT_A
    ) {
        return "set_boot_target_slot_a";
    }

    if (
        action
        == TFB_ACTION_SET_BOOT_TARGET_SLOT_B
    ) {
        return "set_boot_target_slot_b";
    }

    if (
        action
        == TFB_ACTION_LIVE_CONSOLE
    ) {
        return "live_console";
    }

    if (
        action
        == TFB_ACTION_RESTART_ADB_USB
    ) {
        return "restart_adb_usb";
    }

    if (
        action
        == TFB_ACTION_NOT_IMPLEMENTED
    ) {
        return "not_implemented";
    }

    if (
        action
        == TFB_ACTION_BACK
    ) {
        return "back";
    }

    return "none";
}




static int tfb_adb_connected(
    void
) {
    long ready = tfb_open(
        "/dev/treeforge-bootstrap-adb-ready",
        O_RDONLY
        | O_NONBLOCK
    );

    if (ready < 0) {
        return 0;
    }

    tfb_close(
        ready
    );

    long fd = tfb_open(
        "/sys/class/udc/"
        "11210000.dwc3/state",
        O_RDONLY
        | O_NONBLOCK
    );

    if (fd < 0) {
        return 0;
    }

    char state[32];

    long amount = tfb_syscall3(
        SYS_READ,
        fd,
        (long) state,
        (long) (
            sizeof(state) - 1
        )
    );

    tfb_close(
        fd
    );

    if (amount <= 0) {
        return 0;
    }

    state[amount] = '\0';

    static const char configured[] =
        "configured";

    for (
        usize index = 0;
        configured[index] != '\0';
        index++
    ) {
        if (
            index >= (usize) amount
            || state[index]
                != configured[index]
        ) {
            return 0;
        }
    }

    return 1;
}


/*
 * TFB_ADB_MANUAL_RESET_V1
 *
 * Retained early-userspace control/status markers shared by the
 * menu dispatcher and standalone ADB service.
 */
#define TFB_ADB_RESET_REQUEST \
    "/dev/treeforge-bootstrap-adb-reset"

#define TFB_ADB_RESTARTING \
    "/dev/treeforge-bootstrap-adb-restarting"

#define TFB_ADB_ERROR_B_SESSION \
    "/dev/treeforge-bootstrap-adb-error-b-session"

#define TFB_ADB_ERROR_UDC \
    "/dev/treeforge-bootstrap-adb-error-udc"

#define TFB_ADB_ERROR_CONFIGFS \
    "/dev/treeforge-bootstrap-adb-error-configfs"

#define TFB_ADB_ERROR_FFS \
    "/dev/treeforge-bootstrap-adb-error-ffs"

#define TFB_ADB_ERROR_ADBD \
    "/dev/treeforge-bootstrap-adb-error-adbd"

#define TFB_ADB_ERROR_LINK \
    "/dev/treeforge-bootstrap-adb-error-link"

#define TFB_ADB_ERROR_BIND \
    "/dev/treeforge-bootstrap-adb-error-bind"

#define TFB_ADB_ERROR_UNKNOWN \
    "/dev/treeforge-bootstrap-adb-error-unknown"


static int tfb_adb_marker_exists(
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


static int tfb_adb_display_state(
    void
) {
    if (
        tfb_adb_marker_exists(
            TFB_ADB_RESTARTING
        )
    ) {
        return 2;
    }

    if (
        tfb_adb_marker_exists(
            TFB_ADB_ERROR_B_SESSION
        )
    ) {
        return 10;
    }

    if (
        tfb_adb_marker_exists(
            TFB_ADB_ERROR_UDC
        )
    ) {
        return 11;
    }

    if (
        tfb_adb_marker_exists(
            TFB_ADB_ERROR_CONFIGFS
        )
    ) {
        return 12;
    }

    if (
        tfb_adb_marker_exists(
            TFB_ADB_ERROR_FFS
        )
    ) {
        return 13;
    }

    if (
        tfb_adb_marker_exists(
            TFB_ADB_ERROR_ADBD
        )
    ) {
        return 14;
    }

    if (
        tfb_adb_marker_exists(
            TFB_ADB_ERROR_LINK
        )
    ) {
        return 15;
    }

    if (
        tfb_adb_marker_exists(
            TFB_ADB_ERROR_BIND
        )
    ) {
        return 16;
    }

    if (
        tfb_adb_marker_exists(
            TFB_ADB_ERROR_UNKNOWN
        )
    ) {
        return 17;
    }

    /*
     * READY remains tied to the existing complete connection
     * predicate: TreeForge ready marker plus configured UDC.
     */
    if (tfb_adb_connected()) {
        return 1;
    }

    return 0;
}


static const char *tfb_adb_display_text(
    void
) {
    int state =
        tfb_adb_display_state();

    if (state == 1) {
        return "READY";
    }

    if (state == 2) {
        return "RESTARTING";
    }

    if (state == 10) {
        return "ERROR B_SESSION";
    }

    if (state == 11) {
        return "ERROR UDC";
    }

    if (state == 12) {
        return "ERROR CONFIGFS";
    }

    if (state == 13) {
        return "ERROR FFS";
    }

    if (state == 14) {
        return "ERROR ADBD";
    }

    if (state == 15) {
        return "ERROR LINK";
    }

    if (state == 16) {
        return "ERROR BIND";
    }

    if (state == 17) {
        return "ERROR UNKNOWN";
    }

    return "OFFLINE";
}


static const char *tfb_menu_status_line(
    const struct tfb_menu_page *page,
    u32 elapsed_ms,
    int timeout_fired
) {
    if (tfb_menu_status) {
        return tfb_menu_status;
    }

    if (
        !page
        || page->timeout_ms == 0
        || timeout_fired
    ) {
        return "WAITING FOR SELECTION";
    }

    static char line[48];

    static const char prefix[] =
        "AUTO ACTION IN ";

    usize position = 0;

    while (
        prefix[position] != '\0'
        && position < 40
    ) {
        line[position] =
            prefix[position];

        position++;
    }

    u32 remaining_ms = (
        page->timeout_ms
        > elapsed_ms
        ? page->timeout_ms
            - elapsed_ms
        : 0
    );

    u32 seconds = (
        remaining_ms
        + 999U
    ) / 1000U;

    if (seconds > 99U) {
        seconds = 99U;
    }

    if (seconds >= 10U) {
        line[position++] = (
            (char) (
                '0'
                + (
                    seconds / 10U
                )
            )
        );
    }

    line[position++] = (
        (char) (
            '0'
            + (
                seconds % 10U
            )
        )
    );

    line[position++] = 'S';
    line[position] = '\0';

    return line;
}



/*
 * TFB_LANDSCAPE_MENU_RENDERER_V17
 *
 * Everything below is a TreeForge-owned software presentation layer.
 * tfb_fb_fill_rect() remains the raw 1600x2560 framebuffer primitive.
 */

struct tfb_ui_menu_geometry {
    u32 x;
    u32 y;
    u32 width;
    u32 row_height;
    u32 row_gap;
    int item_count;
};


/*
 * TFB_V2_STRING_EQUAL_FORWARD_DECL
 *
 * The V2 menu renderer now needs tfb_string_equal() before its
 * existing implementation later in this translation unit.
 *
 * Declaration only. The single canonical implementation remains
 * unchanged.
 */
static int tfb_string_equal(
    const char *,
    const char *
);


static int tfb_ui_landscape_supported(
    void
) {
    return (
        tfb_fb_menu_width
            == TFB_UI_LOGICAL_HEIGHT
        && tfb_fb_menu_height
            == TFB_UI_LOGICAL_WIDTH
    );
}


static void tfb_ui_fill_rect(
    u32 x,
    u32 y,
    u32 width,
    u32 height,
    u32 pixel
) {
    if (
        !tfb_ui_landscape_supported()
        || width == 0
        || height == 0
        || x >= TFB_UI_LOGICAL_WIDTH
        || y >= TFB_UI_LOGICAL_HEIGHT
    ) {
        return;
    }

    if (
        width
        > TFB_UI_LOGICAL_WIDTH - x
    ) {
        width =
            TFB_UI_LOGICAL_WIDTH - x;
    }

    if (
        height
        > TFB_UI_LOGICAL_HEIGHT - y
    ) {
        height =
            TFB_UI_LOGICAL_HEIGHT - y;
    }

    /*
     * Logical camera-top landscape -> native portrait scanout.
     *
     * This is a 90-degree clockwise TreeForge UI transform.
     */
    u32 raw_x =
        y;

    u32 raw_y = (
        TFB_UI_LOGICAL_WIDTH
        - x
        - width
    );

    tfb_fb_fill_rect(
        raw_x,
        raw_y,
        height,
        width,
        pixel
    );
}


static void tfb_ui_outline_rect(
    u32 x,
    u32 y,
    u32 width,
    u32 height,
    u32 thickness,
    u32 pixel
) {
    if (
        thickness == 0
        || width < thickness * 2U
        || height < thickness * 2U
    ) {
        return;
    }

    tfb_ui_fill_rect(
        x,
        y,
        width,
        thickness,
        pixel
    );

    tfb_ui_fill_rect(
        x,
        y + height - thickness,
        width,
        thickness,
        pixel
    );

    tfb_ui_fill_rect(
        x,
        y,
        thickness,
        height,
        pixel
    );

    tfb_ui_fill_rect(
        x + width - thickness,
        y,
        thickness,
        height,
        pixel
    );
}


static void tfb_ui_draw_char(
    u32 x,
    u32 y,
    char value,
    u32 scale,
    u32 pixel
) {

    /*
     * TFB_BOOT_MANAGER_V2E_GLYPH_COVERAGE_V1
     *
     * Normalize lowercase runtime strings into the built-in
     * uppercase 5x7 font and explicitly provide punctuation used by
     * kernel releases, partition names and menu/status strings.
     */
    if (
        value >= 'a'
        && value <= 'z'
    ) {
        value = (
            char
        ) (
            value - 'a' + 'A'
        );
    }

    if (value == '.') {
        tfb_ui_fill_rect(
            x + 2U * scale,
            y + 6U * scale,
            scale,
            scale,
            pixel
        );
        return;
    }

    if (value == ',') {
        tfb_ui_fill_rect(
            x + 2U * scale,
            y + 5U * scale,
            scale,
            scale,
            pixel
        );

        tfb_ui_fill_rect(
            x + scale,
            y + 6U * scale,
            scale,
            scale,
            pixel
        );
        return;
    }

    if (value == ':') {
        tfb_ui_fill_rect(
            x + 2U * scale,
            y + 2U * scale,
            scale,
            scale,
            pixel
        );

        tfb_ui_fill_rect(
            x + 2U * scale,
            y + 5U * scale,
            scale,
            scale,
            pixel
        );
        return;
    }

    if (value == '-') {
        tfb_ui_fill_rect(
            x,
            y + 3U * scale,
            5U * scale,
            scale,
            pixel
        );
        return;
    }

    if (value == '_') {
        tfb_ui_fill_rect(
            x,
            y + 6U * scale,
            5U * scale,
            scale,
            pixel
        );
        return;
    }

    if (value == '+') {
        tfb_ui_fill_rect(
            x,
            y + 3U * scale,
            5U * scale,
            scale,
            pixel
        );

        tfb_ui_fill_rect(
            x + 2U * scale,
            y + scale,
            scale,
            5U * scale,
            pixel
        );
        return;
    }

    if (value == '=') {
        tfb_ui_fill_rect(
            x,
            y + 2U * scale,
            5U * scale,
            scale,
            pixel
        );

        tfb_ui_fill_rect(
            x,
            y + 4U * scale,
            5U * scale,
            scale,
            pixel
        );
        return;
    }

    if (value == '/') {
        for (
            u32 index = 0;
            index < 5U;
            index++
        ) {
            tfb_ui_fill_rect(
                x
                    + (
                        4U - index
                    ) * scale,
                y
                    + (
                        index + 1U
                    ) * scale,
                scale,
                scale,
                pixel
            );
        }

        return;
    }

    if (value == '%') {
        tfb_ui_fill_rect(
            x,
            y + scale,
            2U * scale,
            2U * scale,
            pixel
        );

        tfb_ui_fill_rect(
            x + 3U * scale,
            y + 4U * scale,
            2U * scale,
            2U * scale,
            pixel
        );

        for (
            u32 index = 0;
            index < 5U;
            index++
        ) {
            tfb_ui_fill_rect(
                x
                    + (
                        4U - index
                    ) * scale,
                y
                    + (
                        index + 1U
                    ) * scale,
                scale,
                scale,
                pixel
            );
        }

        return;
    }

    if (value == '^') {
        tfb_ui_fill_rect(
            x + 2U * scale,
            y,
            scale,
            scale,
            pixel
        );

        tfb_ui_fill_rect(
            x + scale,
            y + scale,
            scale,
            scale,
            pixel
        );

        tfb_ui_fill_rect(
            x + 3U * scale,
            y + scale,
            scale,
            scale,
            pixel
        );
        return;
    }

    for (
        int row = 0;
        row < 7;
        row++
    ) {
        unsigned char bits = (
            tfb_fb_glyph_row(
                value,
                row
            )
        );

        for (
            int column = 0;
            column < 5;
            column++
        ) {
            if (
                bits
                & (
                    1U
                    << (
                        4
                        - column
                    )
                )
            ) {
                tfb_ui_fill_rect(
                    x
                        + (
                            (u32) column
                            * scale
                        ),
                    y
                        + (
                            (u32) row
                            * scale
                        ),
                    scale,
                    scale,
                    pixel
                );
            }
        }
    }
}


static void tfb_ui_draw_text(
    u32 x,
    u32 y,
    const char *value,
    u32 scale,
    u32 pixel
) {
    if (
        !value
        || scale == 0
    ) {
        return;
    }

    u32 cursor =
        x;

    for (
        usize index = 0;
        value[index] != '\0';
        index++
    ) {
        if (
            value[index]
            != ' '
        ) {
            tfb_ui_draw_char(
                cursor,
                y,
                value[index],
                scale,
                pixel
            );
        }

        cursor +=
            6U * scale;
    }
}


static void tfb_ui_draw_text_fit(
    u32 x,
    u32 y,
    const char *value,
    u32 maximum_width,
    u32 preferred_scale,
    u32 minimum_scale,
    u32 pixel
) {
    if (!value) {
        return;
    }

    u32 scale =
        preferred_scale;

    while (
        scale > minimum_scale
        && tfb_fb_text_width(
            value,
            scale
        ) > maximum_width
    ) {
        scale--;
    }

    tfb_ui_draw_text(
        x,
        y,
        value,
        scale,
        pixel
    );
}


static int tfb_ui_marker_exists(
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


static int tfb_ui_read_u64(
    const char *path,
    u64 *output
) {
    char buffer[48];

    if (
        !output
        || !tfb_menu_read_state_text(
            path,
            buffer,
            sizeof(buffer)
        )
    ) {
        return 0;
    }

    u64 value = 0;
    int seen = 0;

    for (
        usize index = 0;
        buffer[index] != '\0';
        index++
    ) {
        char c =
            buffer[index];

        if (
            c < '0'
            || c > '9'
        ) {
            return 0;
        }

        seen = 1;

        value = (
            value * 10ULL
            + (u64) (
                c - '0'
            )
        );
    }

    if (!seen) {
        return 0;
    }

    *output =
        value;

    return 1;
}


static void tfb_ui_u64_text(
    u64 value,
    char *output,
    usize capacity
) {
    if (
        !output
        || capacity < 2
    ) {
        return;
    }

    char reverse[32];
    usize count = 0;

    do {
        reverse[count++] = (
            (char) (
                '0'
                + (
                    value
                    % 10ULL
                )
            )
        );

        value /=
            10ULL;

    } while (
        value > 0
        && count
            < sizeof(reverse)
    );

    usize position = 0;

    while (
        count > 0
        && position + 1
            < capacity
    ) {
        output[position++] =
            reverse[--count];
    }

    output[position] =
        '\0';
}


static void tfb_ui_append(
    char *buffer,
    usize capacity,
    const char *suffix
) {
    if (
        !buffer
        || !suffix
        || capacity < 2
    ) {
        return;
    }

    usize position =
        tfb_strlen(
            buffer
        );

    for (
        usize index = 0;
        suffix[index] != '\0'
        && position + 1
            < capacity;
        index++
    ) {
        buffer[position++] =
            suffix[index];
    }

    buffer[position] =
        '\0';
}


/*
 * TFB_BOOTCONFIG_SLOT_DETECTION_V17_1A
 *
 * Modern Pixel boot parameters live in /proc/bootconfig, e.g.
 *
 *     androidboot.slot_suffix = "_a"
 *
 * Keep /proc/cmdline as a compatibility fallback.
 */
static int tfb_ui_file_contains(
    const char *path,
    const char *needle
) {
    if (
        !path
        || !needle
        || needle[0] == '\0'
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

    usize matched = 0;
    char buffer[512];

    for (;;) {
        long amount = tfb_syscall3(
            SYS_READ,
            fd,
            (long) buffer,
            (long) sizeof(buffer)
        );

        if (amount <= 0) {
            break;
        }

        for (
            long index = 0;
            index < amount;
            index++
        ) {
            char value =
                buffer[index];

            if (
                value
                == needle[matched]
            ) {
                matched++;

                if (
                    needle[matched]
                    == '\0'
                ) {
                    tfb_close(
                        fd
                    );

                    return 1;
                }

                continue;
            }

            matched = (
                value == needle[0]
                ? 1U
                : 0U
            );
        }
    }

    tfb_close(
        fd
    );

    return 0;
}


static const char *tfb_ui_boot_slot(
    void
) {
    if (
        tfb_ui_file_contains(
            "/proc/bootconfig",
            "androidboot.slot_suffix = \"_a\""
        )
        || tfb_ui_file_contains(
            "/proc/bootconfig",
            "androidboot.slot_suffix=\"_a\""
        )
    ) {
        return "A";
    }

    if (
        tfb_ui_file_contains(
            "/proc/bootconfig",
            "androidboot.slot_suffix = \"_b\""
        )
        || tfb_ui_file_contains(
            "/proc/bootconfig",
            "androidboot.slot_suffix=\"_b\""
        )
    ) {
        return "B";
    }

    /*
     * Compatibility fallback for platforms that still expose
     * androidboot.slot_suffix directly in the kernel command line.
     */
    if (
        tfb_ui_file_contains(
            "/proc/cmdline",
            "androidboot.slot_suffix=_a"
        )
    ) {
        return "A";
    }

    if (
        tfb_ui_file_contains(
            "/proc/cmdline",
            "androidboot.slot_suffix=_b"
        )
    ) {
        return "B";
    }

    return "UNKNOWN";
}


static int tfb_ui_menu_geometry(
    const struct tfb_menu_page *page,
    struct tfb_ui_menu_geometry *geometry
) {
    if (
        !page
        || !geometry
    ) {
        return 0;
    }

    int item_count = (
        tfb_menu_visible_count(
            page
        )
    );

    if (item_count <= 0) {
        return 0;
    }

    /*
     * TFB_BOOT_MANAGER_V2E_PARTITION_GEOMETRY_V1
     *
     * Partition Information is primarily a data viewer.
     * Its single actionable Back card remains fixed at the bottom.
     */
    if (
        page->title
        && tfb_string_equal(
            page->title,
            "Partition Information"
        )
    ) {
        geometry->x =
            TFB_UI_MENU_X;

        geometry->y =
            1320U;

        geometry->width = (
            TFB_UI_LOGICAL_WIDTH
            - TFB_UI_MENU_X
            - TFB_UI_MENU_RIGHT_MARGIN
        );

        geometry->row_height =
            96U;

        geometry->row_gap =
            0U;

        geometry->item_count =
            item_count;

        return 1;
    }


    /*
     * TFB_BOOT_MANAGER_V2_HOME_GEOMETRY
     *
     * Home has six logical entries but five visual rows because
     * Resume and Boot Options share the first row.
     */
    int layout_count =
        item_count;

    if (
        page->title
        && tfb_string_equal(
            page->title,
            "Home"
        )
        && item_count > 1
    ) {
        layout_count =
            item_count - 1;
    }

    u32 width = (
        TFB_UI_LOGICAL_WIDTH
        - TFB_UI_MENU_X
        - TFB_UI_MENU_RIGHT_MARGIN
    );

    u32 usable_height = (
        TFB_UI_CONTENT_BOTTOM
        - TFB_UI_CONTENT_TOP
    );

    u32 gaps = (
        layout_count > 1
        ? TFB_UI_ROW_GAP
            * (u32) (
                layout_count - 1
            )
        : 0
    );

    u32 row_height = (
        usable_height > gaps
        ? (
            usable_height
            - gaps
        ) / (u32) layout_count
        : 96U
    );

    if (row_height > 180U) {
        row_height = 180U;
    }

    if (row_height < 96U) {
        row_height = 96U;
    }

    u32 total_height = (
        row_height
        * (u32) layout_count
        + gaps
    );

    u32 y = (
        TFB_UI_CONTENT_TOP
        + (
            usable_height
                > total_height
            ? (
                usable_height
                - total_height
            ) / 2U
            : 0
        )
    );

    geometry->x =
        TFB_UI_MENU_X;

    geometry->y =
        y;

    geometry->width =
        width;

    geometry->row_height =
        row_height;

    geometry->row_gap =
        TFB_UI_ROW_GAP;

    geometry->item_count =
        item_count;

    return 1;
}


static void tfb_ui_draw_kv(
    u32 x,
    u32 y,
    const char *label,
    const char *value,
    u32 label_pixel,
    u32 value_pixel
) {
    tfb_ui_draw_text(
        x,
        y,
        label,
        3U,
        label_pixel
    );

    tfb_ui_draw_text_fit(
        x + 410U,
        y,
        value,
        550U,
        3U,
        2U,
        value_pixel
    );
}


static void tfb_ui_draw_boot_state(
    u32 x,
    u32 y,
    const char *label,
    const char *state,
    u32 state_pixel
) {
    tfb_ui_draw_text(
        x,
        y,
        label,
        3U,
        0x00dbe7efU
    );

    tfb_ui_draw_text_fit(
        x + 570U,
        y,
        state,
        390U,
        3U,
        2U,
        state_pixel
    );
}




/*
 * ================================================================
 * TFB_DIRTY_REGION_REDRAW_V17_1C
 * ================================================================
 *
 * The framebuffer bridge exposes a directly mapped scanout.
 * Repainting the complete 1600x2560 surface for every key or touch
 * event causes a visible flash.
 *
 * Full redraw remains correct for initial display and page changes.
 * Stable-page changes repaint only their affected logical regions.
 */

#define TFB_REDRAW_FULL       0x01
#define TFB_REDRAW_SELECTION  0x02
#define TFB_REDRAW_STATUS     0x04
#define TFB_REDRAW_ADB        0x08


/*
 * TFB_BOOT_MANAGER_V2_HOME_CARDS
 *
 * Home keeps the canonical menu-selection model but presents
 * Resume and Boot Options on one visual row.
 *
 * No legacy letter/icon badge box is rendered.
 */
static int tfb_ui_home_page(
    const struct tfb_menu_page *page
) {
    return (
        page
        && page->title
        && tfb_string_equal(
            page->title,
            "Home"
        )
    );
}


static void tfb_ui_draw_settings_glyph(
    u32 x,
    u32 y,
    u32 size,
    int active
) {
    const u32 accent =
        0x0000c7d9U;

    const u32 foreground =
        0x00dbe7efU;

    u32 pixel = (
        active
            ? accent
            : foreground
    );

    if (size < 72U) {
        return;
    }

    u32 cx =
        x + size / 2U;

    u32 cy =
        y + size / 2U;

    /*
     * Simple framebuffer-native settings glyph.
     *
     * This intentionally does not depend on a Unicode
     * gear character existing in the built-in font.
     */
    tfb_ui_outline_rect(
        cx - 23U,
        cy - 23U,
        46U,
        46U,
        5U,
        pixel
    );

    tfb_ui_fill_rect(
        cx - 6U,
        cy - 39U,
        12U,
        13U,
        pixel
    );

    tfb_ui_fill_rect(
        cx - 6U,
        cy + 26U,
        12U,
        13U,
        pixel
    );

    tfb_ui_fill_rect(
        cx - 39U,
        cy - 6U,
        13U,
        12U,
        pixel
    );

    tfb_ui_fill_rect(
        cx + 26U,
        cy - 6U,
        13U,
        12U,
        pixel
    );

    tfb_ui_fill_rect(
        cx - 6U,
        cy - 6U,
        12U,
        12U,
        pixel
    );
}


static void tfb_fb_render_menu_card(
    const struct tfb_menu_page *page,
    int index,
    int active
) {
    if (
        !page
        || index < 0
    ) {
        return;
    }

    struct tfb_ui_menu_geometry geometry;

    if (
        !tfb_ui_menu_geometry(
            page,
            &geometry
        )
        || index >= geometry.item_count
    ) {
        return;
    }

    const u32 card =
        0x00121f2cU;

    const u32 card_selected =
        0x00182736U;

    const u32 border =
        0x00243a4aU;

    const u32 accent =
        0x0000c7d9U;

    const u32 foreground =
        0x00dbe7efU;

    const u32 dim =
        0x008696a3U;

    u32 card_x =
        geometry.x;

    u32 card_width =
        geometry.width;

    u32 visual_row =
        (u32) index;

    int settings_card = 0;

    /*
     * Home:
     *
     *   index 0 = Resume
     *   index 1 = settings square
     *   index 2 = Pixel Partitioner
     *   index 3 = Reboot
     *   index 4 = Maintenance
     *   index 5 = Future Features
     */
    if (
        tfb_ui_home_page(
            page
        )
    ) {
        if (index == 0) {
            card_width = (
                geometry.width
                - geometry.row_height
                - geometry.row_gap
            );

            visual_row = 0U;
        } else if (index == 1) {
            settings_card = 1;

            card_x = (
                geometry.x
                + geometry.width
                - geometry.row_height
            );

            card_width =
                geometry.row_height;

            visual_row = 0U;
        } else {
            visual_row =
                (u32) (index - 1);
        }
    }

    u32 row_y = (
        geometry.y
        + visual_row
            * (
                geometry.row_height
                + geometry.row_gap
            )
    );

    tfb_ui_fill_rect(
        card_x,
        row_y,
        card_width,
        geometry.row_height,
        active
            ? card_selected
            : card
    );

    tfb_ui_outline_rect(
        card_x,
        row_y,
        card_width,
        geometry.row_height,
        active
            ? 4U
            : 2U,
        active
            ? accent
            : border
    );

    if (active) {
        tfb_ui_fill_rect(
            card_x,
            row_y,
            18U,
            geometry.row_height,
            accent
        );
    }

    /*
     * Boot Options is intentionally presented only as
     * the settings square on Home.
     */
    if (settings_card) {
        tfb_ui_draw_settings_glyph(
            card_x,
            row_y,
            geometry.row_height,
            active
        );

        return;
    }

    const struct tfb_menu_entry
        *entry = (
            tfb_menu_visible_entry(
                page,
                index
            )
        );

    if (!entry) {
        return;
    }

    const char *label = (
        tfb_menu_entry_label(
            entry
        )
    );

    const char *description = (
        entry->description
            ? entry->description
            : ""
    );

    /*
     * There is deliberately no call to
     * tfb_ui_draw_menu_icon() here.
     *
     * That removes the old letter/icon boxes.
     */
    u32 text_x =
        card_x + 48U;

    u32 text_width = (
        card_width > 96U
            ? card_width - 96U
            : card_width
    );

    tfb_ui_draw_text_fit(
        text_x,
        row_y + 38U,
        label,
        text_width,
        5U,
        3U,
        active
            ? accent
            : foreground
    );

    tfb_ui_draw_text_fit(
        text_x,
        row_y + 102U,
        description,
        text_width,
        3U,
        2U,
        dim
    );
}


static void tfb_fb_render_selection_delta(
    const struct tfb_menu_page *page,
    int old_selected,
    int new_selected
) {
    if (
        !page
        || old_selected == new_selected
    ) {
        return;
    }

    tfb_fb_render_menu_card(
        page,
        old_selected,
        0
    );

    tfb_fb_render_menu_card(
        page,
        new_selected,
        1
    );
}


static void tfb_fb_render_status_region(
    const struct tfb_menu_page *page,
    u32 elapsed_ms,
    int timeout_fired
) {
    if (!page) {
        return;
    }

    struct tfb_ui_menu_geometry
        geometry;

    if (
        !tfb_ui_menu_geometry(
            page,
            &geometry
        )
    ) {
        return;
    }

    const u32 background =
        0x00060b12U;

    const u32 dim =
        0x008ca0b0U;

    /*
     * Clear only the footer/status strip.
     */
    tfb_ui_fill_rect(
        geometry.x,
        1468U,
        geometry.width,
        76U,
        background
    );

    tfb_ui_draw_text_fit(
        geometry.x,
        1490U,
        tfb_menu_status_line(
            page,
            elapsed_ms,
            timeout_fired
        ),
        geometry.width,
        3U,
        2U,
        dim
    );
}


static void tfb_fb_render_adb_region(
    void
) {
    /*
     * TFB_BOOT_MANAGER_V2_TOP_ADB
     *
     * Persistent top status:
     *
     *   battery  Touch []  ADB []  VOL -  VOL +  POWER
     *
     * Keep this area isolated so the retained dirty-region ADB
     * redraw never repaints the menu or left information panel.
     */
    const u32 x =
        1605U;

    const u32 y =
        92U;

    const u32 background =
        0x00060b12U;

    const u32 dim =
        0x008696a3U;

    const u32 green =
        0x004bd37bU;

    const u32 warning =
        0x00e4c45cU;

    tfb_ui_fill_rect(
        x - 10U,
        y - 8U,
        135U,
        42U,
        background
    );

    tfb_ui_draw_text(
        x,
        y,
        "ADB",
        3U,
        dim
    );

    int adb_state =
        tfb_adb_display_state();

    tfb_ui_fill_rect(
        x + 75U,
        y + 5U,
        16U,
        16U,
        adb_state == 1
            ? green
            : warning
    );
}



/*
 * ================================================================
 * TFB_BOOT_MANAGER_V2E_INFORMATION_V1
 * ================================================================
 *
 * Read-only runtime information.
 *
 * Bootstrap owns live facts such as partition presence/size,
 * current slot and bootconfig state.
 *
 * Pixel Partitioner may later overlay installer provenance without
 * changing the viewer's runtime structure.
 */


static int tfb_ui_bootconfig_value(
    const char *key,
    char *output,
    usize capacity
) {
    if (
        !key
        || !output
        || capacity < 2
    ) {
        return 0;
    }

    char buffer[16384];

    long descriptor = tfb_open(
        "/proc/bootconfig",
        O_RDONLY
    );

    if (descriptor < 0) {
        return 0;
    }

    long amount = tfb_syscall3(
        SYS_READ,
        descriptor,
        (long) buffer,
        sizeof(buffer) - 1U
    );

    tfb_close(
        descriptor
    );

    if (amount <= 0) {
        return 0;
    }

    buffer[amount] =
        '\0';

    usize key_length = 0;

    while (
        key[key_length] != '\0'
    ) {
        key_length++;
    }

    usize cursor = 0;

    while (
        cursor < (usize) amount
    ) {
        usize line_start =
            cursor;

        usize line_end =
            line_start;

        while (
            line_end < (usize) amount
            && buffer[line_end] != '\n'
        ) {
            line_end++;
        }

        int matches = 1;

        if (
            line_end - line_start
            < key_length
        ) {
            matches = 0;
        }

        if (matches) {
            for (
                usize index = 0;
                index < key_length;
                index++
            ) {
                if (
                    buffer[
                        line_start + index
                    ] != key[index]
                ) {
                    matches = 0;
                    break;
                }
            }
        }

        if (matches) {
            usize position = (
                line_start
                + key_length
            );

            while (
                position < line_end
                && (
                    buffer[position] == ' '
                    || buffer[position] == '\t'
                )
            ) {
                position++;
            }

            if (
                position < line_end
                && buffer[position] == '='
            ) {
                position++;
            }

            while (
                position < line_end
                && (
                    buffer[position] == ' '
                    || buffer[position] == '\t'
                )
            ) {
                position++;
            }

            if (
                position < line_end
                && buffer[position] == '"'
            ) {
                position++;
            }

            usize out = 0;

            while (
                position < line_end
                && out + 1U < capacity
                && buffer[position] != '"'
                && buffer[position] != '\r'
            ) {
                output[out++] =
                    buffer[position++];
            }

            output[out] =
                '\0';

            return out > 0;
        }

        cursor = (
            line_end < (usize) amount
            ? line_end + 1U
            : line_end
        );
    }

    return 0;
}


static void tfb_ui_draw_field(
    u32 x,
    u32 y,
    u32 width,
    const char *label,
    const char *value,
    u32 label_pixel,
    u32 value_pixel
) {
    tfb_ui_draw_text_fit(
        x,
        y,
        label,
        width,
        2U,
        1U,
        label_pixel
    );

    tfb_ui_draw_text_fit(
        x,
        y + 30U,
        value,
        width,
        3U,
        1U,
        value_pixel
    );
}


struct tfb_ui_partition_row {
    const char *name;
    const char *primary_path;
    const char *fallback_path;
    const char *role;
};


static const struct
tfb_ui_partition_row
tfb_ui_partition_rows[] = {
    {
        "boot_a",
        "/dev/block/by-name/boot_a",
        0,
        "TreeForge Kernel"
    },
    {
        "init_boot_a",
        "/dev/block/by-name/init_boot_a",
        0,
        "Boot Manager"
    },
    {
        "vendor_boot_a",
        "/dev/block/by-name/vendor_boot_a",
        0,
        "Android Support"
    },
    {
        "vendor_kernel_boot_a",
        "/dev/block/by-name/vendor_kernel_boot_a",
        0,
        "Android Support"
    },
    {
        "dtbo_a",
        "/dev/block/by-name/dtbo_a",
        0,
        "Android Support"
    },
    {
        "pvmfw_a",
        "/dev/block/by-name/pvmfw_a",
        0,
        "Android Support"
    },
    {
        "vbmeta_a",
        "/dev/block/by-name/vbmeta_a",
        0,
        "AVB Root"
    },
    {
        "vbmeta_system_a",
        "/dev/block/by-name/vbmeta_system_a",
        0,
        "AVB System"
    },
    {
        "vbmeta_vendor_a",
        "/dev/block/by-name/vbmeta_vendor_a",
        0,
        "AVB Vendor"
    },
    {
        "system_a",
        "/dev/block/mapper/system_a",
        "/dev/block/by-name/system_a",
        "Android Logical"
    },
    {
        "system_dlkm_a",
        "/dev/block/mapper/system_dlkm_a",
        "/dev/block/by-name/system_dlkm_a",
        "Android Logical"
    },
    {
        "system_ext_a",
        "/dev/block/mapper/system_ext_a",
        "/dev/block/by-name/system_ext_a",
        "Android Logical"
    },
    {
        "product_a",
        "/dev/block/mapper/product_a",
        "/dev/block/by-name/product_a",
        "Android Logical"
    },
    {
        "vendor_a",
        "/dev/block/mapper/vendor_a",
        "/dev/block/by-name/vendor_a",
        "Android Logical"
    },
    {
        "vendor_dlkm_a",
        "/dev/block/mapper/vendor_dlkm_a",
        "/dev/block/by-name/vendor_dlkm_a",
        "Android Logical"
    },
    {
        "TREEFORGE OS",
        "/dev/block/sda27",
        0,
        "TreeForge Storage"
    },
};


static int tfb_ui_partition_bytes(
    const char *path,
    u64 *bytes
) {
    if (
        !path
        || !bytes
    ) {
        return 0;
    }

    long descriptor = tfb_open(
        path,
        O_RDONLY
        | O_NONBLOCK
    );

    if (descriptor < 0) {
        return 0;
    }

    long end = tfb_syscall3(
        SYS_LSEEK,
        descriptor,
        0,
        2
    );

    tfb_close(
        descriptor
    );

    if (end <= 0) {
        return 0;
    }

    *bytes = (
        (u64) end
    );

    return 1;
}


static void tfb_ui_partition_size_text(
    const struct tfb_ui_partition_row *row,
    char *output,
    usize capacity
) {
    if (
        !row
        || !output
        || capacity < 2
    ) {
        return;
    }

    u64 bytes = 0;

    int available = (
        tfb_ui_partition_bytes(
            row->primary_path,
            &bytes
        )
    );

    if (
        !available
        && row->fallback_path
    ) {
        available = (
            tfb_ui_partition_bytes(
                row->fallback_path,
                &bytes
            )
        );
    }

    /*
     * TFB_PARTITION_VIEWER_SYSFS_FALLBACK_V1
     *
     * treeforge_os can exist in the kernel block topology before
     * /dev/block/sda27 is materialized. The information viewer is
     * read-only, so sysfs is sufficient authority for presence/size.
     */
    if (
        !available
        && row->primary_path
        && tfb_string_equal(
            row->primary_path,
            "/dev/block/sda27"
        )
    ) {
        u64 sectors = 0;

        if (
            tfb_ui_read_u64(
                "/sys/class/block/sda27/size",
                &sectors
            )
            && sectors > 0
            && sectors
                <= (
                    (~0ULL)
                    / 512ULL
                )
        ) {
            bytes = (
                sectors
                * 512ULL
            );

            available = 1;
        }
    }

    if (!available) {
        static const char missing[] =
            "MISSING";

        usize index = 0;

        while (
            missing[index] != '\0'
            && index + 1U < capacity
        ) {
            output[index] =
                missing[index];

            index++;
        }

        output[index] =
            '\0';

        return;
    }

    if (
        bytes
        >= 1024ULL * 1024ULL
    ) {
        tfb_ui_u64_text(
            (
                bytes
                + 512ULL * 1024ULL
            )
            / (
                1024ULL * 1024ULL
            ),
            output,
            capacity
        );

        tfb_ui_append(
            output,
            capacity,
            " MiB"
        );

        return;
    }

    tfb_ui_u64_text(
        (
            bytes + 512ULL
        ) / 1024ULL,
        output,
        capacity
    );

    tfb_ui_append(
        output,
        capacity,
        " KiB"
    );
}


static int tfb_ui_partition_page(
    const struct tfb_menu_page *page
) {
    return (
        page
        && page->title
        && tfb_string_equal(
            page->title,
            "Partition Information"
        )
    );
}


static void tfb_ui_render_partition_information(
    const struct tfb_ui_menu_geometry *geometry
) {
    if (!geometry) {
        return;
    }

    const u32 foreground =
        0x00dbe7efU;

    const u32 dim =
        0x00758a99U;

    const u32 accent =
        0x0000c7d9U;

    tfb_ui_draw_text(
        geometry->x,
        318U,
        "ACTIVE SLOT",
        2U,
        dim
    );

    tfb_ui_draw_text(
        geometry->x + 190U,
        318U,
        tfb_ui_boot_slot(),
        3U,
        accent
    );

    tfb_ui_draw_text(
        geometry->x + 350U,
        318U,
        "READ ONLY LIVE VIEW",
        2U,
        dim
    );

    const int count = (
        (int) (
            sizeof(
                tfb_ui_partition_rows
            )
            / sizeof(
                tfb_ui_partition_rows[0]
            )
        )
    );

    const int per_column =
        8;

    u32 column_width = (
        geometry->width / 2U
    );

    for (
        int index = 0;
        index < count;
        index++
    ) {
        int column = (
            index / per_column
        );

        int row_index = (
            index % per_column
        );

        u32 x = (
            geometry->x
            + 12U
            + (
                (u32) column
                * column_width
            )
        );

        u32 y = (
            370U
            + (
                (u32) row_index
                * 108U
            )
        );

        char size_text[32];

        size_text[0] =
            '\0';

        tfb_ui_partition_size_text(
            &tfb_ui_partition_rows[
                index
            ],
            size_text,
            sizeof(size_text)
        );

        tfb_ui_draw_text_fit(
            x,
            y,
            tfb_ui_partition_rows[
                index
            ].name,
            column_width - 35U,
            3U,
            2U,
            foreground
        );

        tfb_ui_draw_text_fit(
            x,
            y + 36U,
            size_text,
            150U,
            2U,
            1U,
            accent
        );

        tfb_ui_draw_text_fit(
            x + 165U,
            y + 36U,
            tfb_ui_partition_rows[
                index
            ].role,
            column_width - 205U,
            2U,
            1U,
            dim
        );
    }
}


static void tfb_fb_render_menu(
    const struct tfb_menu_page *page,
    int selected,
    u32 elapsed_ms,
    int timeout_fired
) {
    if (
        !tfb_fb_menu_active
        || tfb_fb_menu_mapped_address < 0
        || !page
    ) {
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

    const u32 border =
        0x00283d4dU;

    const u32 accent =
        0x0000d4eeU;

    const u32 green =
        0x004ed87dU;

    const u32 warning =
        0x00e4c45cU;

    /*
     * Keep an explicit degraded fallback rather than ever attempting
     * a guessed transform on an unknown framebuffer geometry.
     */
    if (
        !tfb_ui_landscape_supported()
    ) {
        tfb_fb_fill_rect(
            0,
            0,
            tfb_fb_menu_width,
            tfb_fb_menu_height,
            0x00000000U
        );

        tfb_fb_draw_text(
            24U,
            24U,
            "TREEFORGE LANDSCAPE GEOMETRY UNSUPPORTED",
            3U,
            0x00ffffffU
        );

        return;
    }

    tfb_fb_fill_rect(
        0,
        0,
        tfb_fb_menu_width,
        tfb_fb_menu_height,
        background
    );

    /*
     * Header.
     */
    tfb_ui_draw_text(
        110U,
        72U,
        "TREEFORGE",
        8U,
        accent
    );

    tfb_ui_draw_text(
        110U,
        150U,
        "BOOT MANAGER",
        5U,
        foreground
    );

    /*
     * TFB_BOOT_MANAGER_V2F_HEADER_IDENTITY_V1
     *
     * Keep runtime identity directly with the TreeForge header.
     */
    tfb_ui_draw_text(
        110U,
        210U,
        "BOOTSTRAP",
        3U,
        dim
    );

    tfb_ui_draw_text_fit(
        310U,
        210U,
        tfb_version,
        220U,
        4U,
        3U,
        foreground
    );

    char kernel_release[128] =
        "UNKNOWN";

    tfb_menu_read_state_text(
        "/proc/sys/kernel/osrelease",
        kernel_release,
        sizeof(kernel_release)
    );

    tfb_ui_draw_text(
        110U,
        258U,
        "KERNEL",
        3U,
        dim
    );

    tfb_ui_draw_text_fit(
        255U,
        258U,
        kernel_release,
        1030U,
        3U,
        2U,
        foreground
    );

    /*
     * Pixel Tablet physical controls live on the top-right edge.
     * The arrows point toward the real buttons.
     */
    tfb_ui_draw_text(
        1840U,
        28U,
        "^",
        5U,
        accent
    );

    tfb_ui_draw_text(
        2040U,
        28U,
        "^",
        5U,
        accent
    );

    tfb_ui_draw_text(
        2295U,
        28U,
        "^",
        5U,
        accent
    );

    /*
     * TFB_BOOT_MANAGER_V2_TOP_STATUS
     *
     * Locked order:
     *
     *   86%      Touch []   ADB []      VOL -   VOL +   POWER
     *
     * Battery is read on full redraw. ADB retains its own dirty
     * redraw helper.
     */
    char top_battery_value[32] =
        "--%";

    u64 top_capacity = 0;

    if (
        tfb_ui_read_u64(
            "/sys/class/power_supply/battery/capacity",
            &top_capacity
        )
    ) {
        top_battery_value[0] =
            '\0';

        tfb_ui_u64_text(
            top_capacity,
            top_battery_value,
            sizeof(top_battery_value)
        );

        tfb_ui_append(
            top_battery_value,
            sizeof(top_battery_value),
            "%"
        );
    }

    tfb_ui_draw_text_fit(
        1300U,
        92U,
        top_battery_value,
        100U,
        3U,
        2U,
        foreground
    );

    tfb_ui_draw_text(
        1425U,
        92U,
        "TOUCH",
        3U,
        dim
    );

    tfb_ui_fill_rect(
        1547U,
        97U,
        16U,
        16U,
        tfb_ui_marker_exists(
            "/dev/treeforge-bootstrap-touchscreen-ready"
        )
            ? green
            : warning
    );

    tfb_fb_render_adb_region();

    tfb_ui_draw_text(
        1780U,
        92U,
        "VOL -",
        3U,
        foreground
    );

    tfb_ui_draw_text(
        1970U,
        92U,
        "VOL +",
        3U,
        foreground
    );

    tfb_ui_draw_text(
        2230U,
        92U,
        "POWER",
        3U,
        foreground
    );

    /*
     * Left information panel.
     *
     * TFB_BOOT_MANAGER_V2F_LEFT_PANEL_GEOMETRY_V1
     */
    const u32 left_x =
        80U;

    const u32 left_y =
        310U;

    const u32 left_width =
        1180U;

    const u32 left_height =
        1120U;

    tfb_ui_fill_rect(
        left_x,
        left_y,
        left_width,
        left_height,
        panel
    );

    tfb_ui_outline_rect(
        left_x,
        left_y,
        left_width,
        left_height,
        4U,
        border
    );

    u32 ix =
        left_x + 45U;
    const u32 info_width =
        250U;

    const u32 info_gap =
        22U;

    const u32 c0 =
        ix;

    const u32 c1 = (
        c0
        + info_width
        + info_gap
    );

    const u32 c2 = (
        c1
        + info_width
        + info_gap
    );

    const u32 c3 = (
        c2
        + info_width
        + info_gap
    );

    char storage_value[32] =
        "UNKNOWN";

    u64 storage_sectors = 0;

    if (
        tfb_ui_read_u64(
            "/sys/block/sda/size",
            &storage_sectors
        )
    ) {
        tfb_ui_u64_text(
            (
                storage_sectors
                * 512ULL
                + 500000000ULL
            )
            / 1000000000ULL,
            storage_value,
            sizeof(storage_value)
        );

        tfb_ui_append(
            storage_value,
            sizeof(storage_value),
            " GB"
        );
    }

    char avb_state[32] =
        "UNKNOWN";

    tfb_ui_bootconfig_value(
        "androidboot.verifiedbootstate",
        avb_state,
        sizeof(avb_state)
    );

    char device_state[32] =
        "UNKNOWN";

    tfb_ui_bootconfig_value(
        "androidboot.vbmeta.device_state",
        device_state,
        sizeof(device_state)
    );

    /*
     * DEVICE
     */
    tfb_ui_draw_text(
        ix,
        left_y + 40U,
        "DEVICE",
        4U,
        accent
    );

    u32 device_row_1 =
        left_y + 95U;

    tfb_ui_draw_field(
        c0,
        device_row_1,
        info_width,
        "MODEL",
        "PIXEL TABLET",
        dim,
        foreground
    );

    tfb_ui_draw_field(
        c1,
        device_row_1,
        info_width,
        "SOC",
        "GS201",
        dim,
        foreground
    );

    tfb_ui_draw_field(
        c2,
        device_row_1,
        info_width,
        "MEMORY",
        "8 GB",
        dim,
        foreground
    );

    tfb_ui_draw_field(
        c3,
        device_row_1,
        info_width,
        "STORAGE",
        storage_value,
        dim,
        foreground
    );

    u32 device_row_2 =
        left_y + 205U;

    tfb_ui_draw_field(
        c0,
        device_row_2,
        info_width,
        "BOARD",
        "TANGORPRO",
        dim,
        foreground
    );

    tfb_ui_draw_field(
        c1,
        device_row_2,
        info_width,
        "ACTIVE SLOT",
        tfb_ui_boot_slot(),
        dim,
        foreground
    );

    tfb_ui_draw_field(
        c2,
        device_row_2,
        info_width,
        "AVB",
        avb_state,
        dim,
        foreground
    );

    tfb_ui_draw_field(
        c3,
        device_row_2,
        info_width,
        "DEVICE STATE",
        device_state,
        dim,
        foreground
    );

    /*
     * BOOT INVENTORY
     */
    u32 inventory_y =
        left_y + 340U;

    tfb_ui_draw_text(
        ix,
        inventory_y,
        "BOOT INVENTORY",
        4U,
        accent
    );

    inventory_y +=
        65U;

    tfb_ui_draw_boot_state(
        ix,
        inventory_y,
        "ANDROID A",
        "WORKING",
        green
    );

    inventory_y +=
        65U;

    tfb_ui_draw_boot_state(
        ix,
        inventory_y,
        "ANDROID B",
        tfb_menu_state.full_ab
            ? "INSTALLED - HANDOFF PENDING"
            : "VIRTUAL A/B",
        tfb_menu_state.full_ab
            ? warning
            : dim
    );

    inventory_y +=
        65U;

    tfb_ui_draw_boot_state(
        ix,
        inventory_y,
        "ALTERNATE OS",
        tfb_menu_state
            .alternate_os_configured
            ? tfb_menu_state
                .alternate_os_name
            : "NOT INSTALLED",
        tfb_menu_state
            .alternate_os_configured
            ? green
            : dim
    );

    inventory_y +=
        65U;

    tfb_ui_draw_boot_state(
        ix,
        inventory_y,
        "RECOVERY",
        "NOT IMPLEMENTED",
        dim
    );

    inventory_y +=
        65U;

    tfb_ui_draw_boot_state(
        ix,
        inventory_y,
        "ROOT",
        "NOT IMPLEMENTED",
        dim
    );

    /*
     * SYSTEM
     */
    u32 system_y =
        left_y + 775U;

    tfb_ui_draw_text(
        ix,
        system_y,
        "SYSTEM",
        4U,
        accent
    );

    u32 system_row_1 =
        system_y + 60U;

    tfb_ui_draw_field(
        c0,
        system_row_1,
        info_width,
        "BOOT MANAGER",
        "V2E",
        dim,
        foreground
    );

    tfb_ui_draw_field(
        c1,
        system_row_1,
        info_width,
        "RUNTIME ABI",
        "V1",
        dim,
        foreground
    );

    tfb_ui_draw_field(
        c2,
        system_row_1,
        info_width,
        "AUTOBOOT",
        "10 SEC",
        dim,
        foreground
    );

    tfb_ui_draw_field(
        c3,
        system_row_1,
        info_width,
        "INPUT CANCEL",
        "ENABLED",
        dim,
        green
    );

    u32 system_row_2 =
        system_y + 145U;

    tfb_ui_draw_field(
        c0,
        system_row_2,
        info_width,
        "DISPLAY",
        "FB BRIDGE V1",
        dim,
        foreground
    );

    tfb_ui_draw_field(
        c1,
        system_row_2,
        info_width,
        "A/B MODE",
        tfb_menu_state.full_ab
            ? "FULL A/B"
            : "VIRTUAL A/B",
        dim,
        foreground
    );

    tfb_ui_draw_field(
        c2,
        system_row_2,
        info_width,
        "PARTITIONS",
        "LIVE READ ONLY",
        dim,
        green
    );

    tfb_ui_draw_field(
        c3,
        system_row_2,
        info_width,
        "ROOT",
        "NOT IMPLEMENTED",
        dim,
        foreground
    );

    u32 system_row_3 =
        system_y + 230U;

    tfb_ui_draw_field(
        c0,
        system_row_3,
        info_width,
        "ANDROID HANDOFF",
        "WORKING",
        dim,
        green
    );

    tfb_ui_draw_field(
        c1,
        system_row_3,
        info_width,
        "BOOTLOADER",
        "WORKING",
        dim,
        green
    );

    tfb_ui_draw_field(
        c2,
        system_row_3,
        info_width,
        "LIVE LOGGER",
        "WORKING",
        dim,
        green
    );

    tfb_ui_draw_field(
        c3,
        system_row_3,
        info_width,
        "ADB RESET",
        "WORKING",
        dim,
        green
    );


    /*
     * Right menu panel.
     */
    struct tfb_ui_menu_geometry geometry;

    if (
        !tfb_ui_menu_geometry(
            page,
            &geometry
        )
    ) {
        tfb_ui_draw_text(
            TFB_UI_MENU_X,
            420U,
            "NO MENU ENTRIES",
            5U,
            warning
        );

        return;
    }

    tfb_ui_draw_text_fit(
        geometry.x,
        205U,
        page->title,
        geometry.width,
        6U,
        3U,
        foreground
    );

    tfb_ui_draw_text_fit(
        geometry.x,
        260U,
        page->subtitle,
        geometry.width,
        3U,
        2U,
        dim
    );

    if (
        tfb_ui_partition_page(
            page
        )
    ) {
        tfb_ui_render_partition_information(
            &geometry
        );
    }


    for (
        int index = 0;
        index < geometry.item_count;
        index++
    ) {
        tfb_fb_render_menu_card(
            page,
            index,
            index == selected
        );
    }


    tfb_fb_render_status_region(
        page,
        elapsed_ms,
        timeout_fired
    );



}


static void tfb_output(
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


static int tfb_fb_parse_dev_number(
    const char *buffer,
    usize length,
    u32 *major_out,
    u32 *minor_out
) {
    if (
        !buffer
        || !major_out
        || !minor_out
        || length == 0
    ) {
        return 0;
    }

    usize index = 0;
    u32 major_value = 0;
    u32 minor_value = 0;
    int major_digits = 0;
    int minor_digits = 0;

    while (
        index < length
        && buffer[index] >= '0'
        && buffer[index] <= '9'
    ) {
        u32 digit = (
            (u32) (
                buffer[index] - '0'
            )
        );

        if (major_value > 4095U) {
            return 0;
        }

        major_value = (
            major_value * 10U
            + digit
        );

        major_digits = 1;
        index++;
    }

    if (
        !major_digits
        || index >= length
        || buffer[index] != ':'
    ) {
        return 0;
    }

    index++;

    while (
        index < length
        && buffer[index] >= '0'
        && buffer[index] <= '9'
    ) {
        u32 digit = (
            (u32) (
                buffer[index] - '0'
            )
        );

        if (minor_value > 1048575U) {
            return 0;
        }

        minor_value = (
            minor_value * 10U
            + digit
        );

        minor_digits = 1;
        index++;
    }

    if (!minor_digits) {
        return 0;
    }

    if (
        major_value == 0
        || major_value > 4095U
        || minor_value > 1048575U
    ) {
        return 0;
    }

    *major_out = major_value;
    *minor_out = minor_value;

    return 1;
}


static unsigned long tfb_fb_encode_dev(
    u32 major_value,
    u32 minor_value
) {
    /*
     * Linux new_encode_dev() layout.
     *
     * The current misc minor is small, but use the complete encoding
     * rather than relying on the legacy 8:8 representation.
     */
    return (
        (unsigned long) (
            minor_value & 0xffU
        )
        | (
            (unsigned long) major_value
            << 8
        )
        | (
            (unsigned long) (
                minor_value & ~0xffU
            )
            << 12
        )
    );
}


static void tfb_fb_remove_created_node(void) {
    if (!tfb_fb_created_node) {
        return;
    }

    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long) TFB_FB_DEVICE_PATH,
        0
    );

    tfb_fb_created_node = 0;
}


static int tfb_fb_realize_node(void) {
    /*
     * If a device manager has already materialized the node, leave it
     * entirely alone.
     */
    long existing = tfb_open(
        TFB_FB_DEVICE_PATH,
        O_RDWR
    );

    if (existing >= 0) {
        tfb_close(
            existing
        );

        return 1;
    }

    long sysfs_fd = tfb_open(
        TFB_FB_SYSFS_DEV_PATH,
        O_RDONLY
        | O_NONBLOCK
    );

    if (sysfs_fd < 0) {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-fb-sysfs-missing"
        );

        return 0;
    }

    char value[32];

    long amount = tfb_syscall3(
        SYS_READ,
        sysfs_fd,
        (long) value,
        (long) sizeof(value)
    );

    tfb_close(
        sysfs_fd
    );

    if (amount <= 0) {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-fb-sysfs-read-failed"
        );

        return 0;
    }

    u32 major_value = 0;
    u32 minor_value = 0;

    if (
        !tfb_fb_parse_dev_number(
            value,
            (usize) amount,
            &major_value,
            &minor_value
        )
    ) {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-fb-dev-number-invalid"
        );

        return 0;
    }

    unsigned long encoded = (
        tfb_fb_encode_dev(
            major_value,
            minor_value
        )
    );

    long result = tfb_syscall4(
        SYS_MKNODAT,
        AT_FDCWD,
        (long) TFB_FB_DEVICE_PATH,
        S_IFCHR | 0600,
        (long) encoded
    );

    /*
     * Even if mknodat raced with another creator, opening the node is
     * the authoritative result.
     */
    long verify = tfb_open(
        TFB_FB_DEVICE_PATH,
        O_RDWR
    );

    if (verify < 0) {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-fb-node-failed"
        );

        return 0;
    }

    tfb_close(
        verify
    );

    if (result == 0) {
        tfb_fb_created_node = 1;

        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-fb-node-created"
        );
    } else {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-fb-node-existing"
        );
    }

    return 1;
}


static int tfb_fb_read_info(
    long fd,
    struct tfb_fb_info *info
) {
    if (
        fd < 0
        || !info
    ) {
        return 0;
    }

    unsigned char *cursor = (
        (unsigned char *) info
    );

    usize remaining = (
        sizeof(*info)
    );

    while (remaining != 0) {
        long amount = tfb_syscall3(
            SYS_READ,
            fd,
            (long) cursor,
            (long) remaining
        );

        if (amount <= 0) {
            return 0;
        }

        cursor += amount;
        remaining -= (usize) amount;
    }

    return 1;
}


static int tfb_fb_validate_info(
    const struct tfb_fb_info *info
) {
    if (!info) {
        return 0;
    }

    if (
        info->abi_version
        != TFB_FB_ABI_VERSION
    ) {
        return 0;
    }

    if (
        info->bytes_per_pixel != 4U
        || info->hw_format > 7U
        || info->dpp_index >= 16U
    ) {
        return 0;
    }

    if (
        info->flags
        != TFB_FB_REQUIRED_FLAGS
    ) {
        return 0;
    }

    if (
        info->width == 0
        || info->height == 0
        || info->width > 8192U
        || info->height > 8192U
    ) {
        return 0;
    }

    /*
     * V1 userspace intentionally accepts only a full-surface scanout.
     *
     * The kernel ABI can describe a sub-rectangle, but the existing
     * renderer assumes origin 0,0. Refuse rather than guess.
     */
    if (
        info->source_x != 0U
        || info->source_y != 0U
        || info->source_width != info->width
        || info->source_height != info->height
    ) {
        return 0;
    }

    if (
        info->stride
        < info->width
        * info->bytes_per_pixel
    ) {
        return 0;
    }

    u64 expected_bytes = (
        (u64) info->stride
        * (u64) info->source_height
    );

    if (
        info->framebuffer_bytes
        != expected_bytes
    ) {
        return 0;
    }

    if (
        info->mmap_bytes
        < info->framebuffer_bytes
        || info->mmap_bytes == 0
        || info->mmap_bytes > 67108864ULL
        || (
            info->mmap_bytes
            & 4095ULL
        ) != 0
    ) {
        return 0;
    }

    return 1;
}


static int tfb_fb_begin(void) {
    if (tfb_fb_active) {
        return 1;
    }

    if (!tfb_fb_realize_node()) {
        return 0;
    }

    long fd = tfb_open(
        TFB_FB_DEVICE_PATH,
        O_RDWR
    );

    if (fd < 0) {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-fb-open-failed"
        );

        tfb_fb_remove_created_node();

        return 0;
    }

    struct tfb_fb_info info;

    if (
        !tfb_fb_read_info(
            fd,
            &info
        )
    ) {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-fb-info-read-failed"
        );

        tfb_close(
            fd
        );

        tfb_fb_remove_created_node();

        return 0;
    }

    if (!tfb_fb_validate_info(&info)) {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-fb-info-invalid"
        );

        tfb_close(
            fd
        );

        tfb_fb_remove_created_node();

        return 0;
    }

    long mapped_address = tfb_syscall6(
        SYS_MMAP,
        0,
        (long) info.mmap_bytes,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        fd,
        0
    );

    if (mapped_address < 0) {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-fb-mmap-failed"
        );

        tfb_close(
            fd
        );

        tfb_fb_remove_created_node();

        return 0;
    }

    /*
     * Reuse the existing renderer state.
     *
     * The renderer already understands:
     *   - mapped base address;
     *   - visible width/height;
     *   - driver/kernel supplied row pitch.
     */
    tfb_fb_fd = fd;
    tfb_fb_active = 1;

    tfb_fb_menu_active = 1;
    tfb_fb_menu_mapped_address = (
        mapped_address
    );
    tfb_fb_menu_mapped_size = (
        info.mmap_bytes
    );
    tfb_fb_menu_width = (
        info.width
    );
    tfb_fb_menu_height = (
        info.height
    );
    tfb_fb_menu_pitch = (
        info.stride
    );

    tfb_create_presence_marker(
        "/dev/treeforge-bootstrap-fb-info-ok"
    );

    tfb_create_presence_marker(
        "/dev/treeforge-bootstrap-fb-mmap-ok"
    );

    tfb_create_presence_marker(
        "/dev/treeforge-bootstrap-fb-menu-active"
    );

    tfb_log(
        "treeforge-bootstrap-fb menu-active"
    );

    return 1;
}


static void tfb_fb_cleanup(void) {
    if (!tfb_fb_active) {
        return;
    }

    if (
        tfb_fb_menu_mapped_address >= 0
        && tfb_fb_menu_mapped_size != 0
    ) {
        tfb_syscall2(
            SYS_MUNMAP,
            tfb_fb_menu_mapped_address,
            (long) tfb_fb_menu_mapped_size
        );
    }

    tfb_close(
        tfb_fb_fd
    );

    tfb_fb_remove_created_node();

    tfb_fb_fd = -1;
    tfb_fb_active = 0;

    tfb_fb_menu_active = 0;
    tfb_fb_menu_mapped_address = -1;
    tfb_fb_menu_mapped_size = 0;

    tfb_fb_menu_width = 0;
    tfb_fb_menu_height = 0;
    tfb_fb_menu_pitch = 0;

    tfb_create_presence_marker(
        "/dev/treeforge-bootstrap-fb-cleanup"
    );
}


static void tfb_fb_menu_cleanup(void) {
    /*
     * The renderer uses the tfb_fb_* internal state
     * names, while display ownership is exclusively the TreeForge
     * Bootstrap framebuffer bridge.
     */
    if (tfb_fb_active) {
        tfb_fb_cleanup();
    }
}

static void tfb_probe_display_surfaces(void) {
    /*
     * TREEFORGE_BOOTSTRAP_FB_BRIDGE_ONLY_V1
     *
     * Hardware acceptance proved the GS201 bootloader framebuffer
     * bridge as the canonical TreeForge Bootstrap early-display path.
     *
     * Do not program DRM/KMS here and do not fall back to the legacy
     * TreeForge Bootstrap framebuffer realization path.
     */
    if (tfb_fb_begin()) {
        tfb_create_presence_marker(
            "/dev/treeforge-bootstrap-fb-primary"
        );

        return;
    }

    tfb_create_presence_marker(
        "/dev/treeforge-bootstrap-fb-required-failed"
    );

    tfb_log(
        "treeforge-bootstrap-fb required-failed"
    );
}


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
 * Realize them from /vendor/lib/modules with the retained TreeForge
 * BusyBox provider.  Never duplicate these kernel modules into the
 * Bootstrap runtime.
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
        || !tfb_probe_readable_path(
            module_path
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
            (char *) "insmod",
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
            "/vendor/lib/modules/goog_usi_stylus.ko",
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
            "/vendor/lib/modules/goog_touch_interface.ko",
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
            "/vendor/lib/modules/nvt_touch.ko",
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


static void tfb_altroot_cleanup_partial(
    void
) {
    tfb_syscall2(
        SYS_UMOUNT2,
        (long) TFB_ALTROOT_ROOT,
        TFB_MNT_DETACH
    );
}


static int tfb_altroot_prepare(
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

    /*
     * pivot_root requires new_root itself to be a mount point.
     */
    if (
        tfb_altroot_mount(
            TFB_ALTROOT_STORAGE,
            TFB_ALTROOT_ROOT,
            TFB_ALTROOT_STORAGE_FS,
            0,
            0
        ) < 0
    ) {
        tfb_log(
            "altroot-storage=mount-failed"
        );

        return 0;
    }

    tfb_log(
        "altroot-storage=mounted"
    );

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
            !tfb_altroot_mkdir(
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

    /*
     * Storage-backed alternate userspace V1.
     *
     * Pixel Partitioner owns treeforge_os. The alternate rootfs is
     * already provisioned there. Bootstrap requires only the native
     * PID 1 and the rootfs ownership marker.
     */
    if (
        !tfb_probe_readable_path(
            "/mnt/treeforge-altroot/init"
        )
        || !tfb_probe_readable_path(
            "/mnt/treeforge-altroot/"
            "TREEFORGE_ROOTFS_V1"
        )
    ) {
        tfb_log(
            "altroot-storage=payload-missing"
        );

        tfb_altroot_cleanup_partial();
        return 0;
    }

    tfb_log(
        "altroot-storage=payload-ready"
    );

    /*
     * Preserve the accepted diagnostic ADB shell compatibility used by
     * the existing storage-backed canary. The alternate PID 1 remains
     * completely native; BusyBox stays in Bootstrap's retained /dev
     * runtime and is not part of the alternate rootfs payload.
     */
    const char *diagnostic_busybox =
        TFB_ALTROOT_LOADER_BUSYBOX;

    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)
            "/mnt/treeforge-altroot/bin/sh",
        0
    );

    tfb_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)
            "/mnt/treeforge-altroot/system/bin/sh",
        0
    );

    long alt_bin_shell =
        tfb_syscall3(
            SYS_SYMLINKAT,
            (long) diagnostic_busybox,
            AT_FDCWD,
            (long)
                "/mnt/treeforge-altroot/bin/sh"
        );

    long alt_system_shell =
        tfb_syscall3(
            SYS_SYMLINKAT,
            (long) diagnostic_busybox,
            AT_FDCWD,
            (long)
                "/mnt/treeforge-altroot/system/bin/sh"
        );

    if (
        alt_bin_shell < 0
        || alt_system_shell < 0
        || !tfb_probe_readable_path(
            "/mnt/treeforge-altroot/bin/sh"
        )
        || !tfb_probe_readable_path(
            "/mnt/treeforge-altroot/system/bin/sh"
        )
    ) {
        tfb_log(
            "altroot-test=diagnostic-shell-compat-failed"
        );

        tfb_altroot_cleanup_partial();
        return 0;
    }

    tfb_log(
        "altroot-test=diagnostic-shell-compat-ready"
    );

    tfb_log(
        "altroot-test=native-init-ready"
    );

    tfb_log(
        "altroot-test=prepared"
    );

    return 1;
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
        (char *) "/init",
        0
    };

    char *alt_envp[] = {
        (char *) "PATH=/bin:/system/bin",
        (char *) "HOME=/",
        (char *) "TERM=linux",
        0
    };

    tfb_syscall3(
        SYS_EXECVE,
        (long) "/init",
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


static void tfb_touch_reset_state(
    struct tfb_touch_state *state
) {
    if (!state) {
        return;
    }

    state->slot = 0;
    state->active = 0;

    state->have_x = 0;
    state->have_y = 0;

    state->raw_x = 0;
    state->raw_y = 0;

    state->start_set = 0;
    state->start_x = 0;
    state->start_y = 0;

    state->pressed_row = -1;
    state->canceled = 0;
}


static int tfb_touch_abs_int(
    int value
) {
    return (
        value < 0
        ? -value
        : value
    );
}


static void tfb_runtime_sysfs_event_name_path(
    int index,
    char *output
) {
    static const char prefix[] =
        "/sys/class/input/event";

    static const char suffix[] =
        "/device/name";

    int position = 0;

    for (
        int i = 0;
        prefix[i] != '\0';
        i++
    ) {
        output[position++] =
            prefix[i];
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
        output[position++] =
            suffix[i];
    }

    output[position] = '\0';
}


static int tfb_input_is_touchscreen(
    int index
) {
    char path[80];

    tfb_runtime_sysfs_event_name_path(
        index,
        path
    );

    long fd = tfb_open(
        path,
        O_RDONLY
    );

    if (fd < 0) {
        return 0;
    }

    char name[64];

    long amount = tfb_syscall3(
        SYS_READ,
        fd,
        (long) name,
        (long) (
            sizeof(name)
            - 1
        )
    );

    tfb_close(
        fd
    );

    if (amount <= 0) {
        return 0;
    }

    while (
        amount > 0
        && (
            name[amount - 1] == '\n'
            || name[amount - 1] == '\r'
        )
    ) {
        amount--;
    }

    name[amount] = '\0';

    return tfb_string_equal(
        name,
        "NVTCapacitiveTouchScreen"
    );
}



static int tfb_menu_touch_row(
    const struct tfb_menu_page *page,
    int raw_x,
    int raw_y
) {
    if (
        !page
        || !tfb_fb_menu_active
        || !tfb_ui_landscape_supported()
        || raw_x < 0
        || raw_x >= TFB_TOUCH_RAW_WIDTH
        || raw_y < 0
        || raw_y >= TFB_TOUCH_RAW_HEIGHT
    ) {
        return -1;
    }

    struct tfb_ui_menu_geometry geometry;

    if (
        !tfb_ui_menu_geometry(
            page,
            &geometry
        )
    ) {
        return -1;
    }

    /*
     * Inverse of the renderer's clockwise
     * logical-landscape transform.
     *
     * raw panel:  1600 x 2560
     * logical UI: 2560 x 1600
     */
    u32 logical_x = (
        TFB_UI_LOGICAL_WIDTH
        - 1U
        - (
            (u32) (
                (
                    (unsigned long) raw_y
                    * (unsigned long)
                        TFB_UI_LOGICAL_WIDTH
                )
                / (unsigned long)
                    TFB_TOUCH_RAW_HEIGHT
            )
        )
    );

    u32 logical_y = (
        (u32) (
            (
                (unsigned long) raw_x
                * (unsigned long)
                    TFB_UI_LOGICAL_HEIGHT
            )
            / (unsigned long)
                TFB_TOUCH_RAW_WIDTH
        )
    );

    if (
        logical_x < geometry.x
        || logical_x
            >= geometry.x
                + geometry.width
    ) {
        return -1;
    }

    u32 step = (
        geometry.row_height
        + geometry.row_gap
    );

    /*
     * Home's first visual row contains two independently
     * selectable entries:
     *
     *   Resume       -> index 0
     *   settings     -> index 1
     */
    if (
        tfb_ui_home_page(
            page
        )
        && geometry.item_count >= 2
    ) {
        u32 first_y =
            geometry.y;

        if (
            logical_y >= first_y
            && logical_y
                < first_y
                    + geometry.row_height
        ) {
            u32 settings_x = (
                geometry.x
                + geometry.width
                - geometry.row_height
            );

            u32 resume_end = (
                settings_x
                > geometry.row_gap
                    ? settings_x
                        - geometry.row_gap
                    : settings_x
            );

            if (
                logical_x >= settings_x
            ) {
                return 1;
            }

            if (
                logical_x < resume_end
            ) {
                return 0;
            }

            /*
             * Gap between Resume and settings.
             */
            return -1;
        }

        for (
            int index = 2;
            index < geometry.item_count;
            index++
        ) {
            u32 visual_row =
                (u32) (index - 1);

            u32 row_y = (
                geometry.y
                + visual_row * step
            );

            if (
                logical_y >= row_y
                && logical_y
                    < row_y
                        + geometry.row_height
            ) {
                return index;
            }
        }

        return -1;
    }

    /*
     * All other pages retain the original one-entry-per-row
     * hit-test model.
     */
    for (
        int index = 0;
        index < geometry.item_count;
        index++
    ) {
        u32 row_y = (
            geometry.y
            + (u32) index * step
        );

        if (
            logical_y >= row_y
            && logical_y
                < row_y
                    + geometry.row_height
        ) {
            return index;
        }
    }

    return -1;
}


/*
 * Return values:
 *
 *   0 = event is not handled by touch
 *   1 = touch event consumed, no UI change
 *   2 = row selected/highlight changed
 *   3 = completed tap should activate selection
 */
static int tfb_touch_process_event(
    struct tfb_touch_state *state,
    const struct tfb_menu_page *page,
    const struct tfb_input_event *event,
    int *selected
) {
    if (
        !state
        || !event
        || !selected
        || event->type != EV_ABS
    ) {
        return 0;
    }

    if (
        event->code
        == ABS_MT_SLOT
    ) {
        state->slot =
            event->value;

        return 1;
    }

    /*
     * The menu intentionally consumes only the primary contact.
     * Additional fingers never activate menu entries.
     */
    if (state->slot != 0) {
        return 1;
    }

    if (
        event->code
        == ABS_MT_TRACKING_ID
    ) {
        if (event->value >= 0) {
            state->active = 1;

            state->have_x = 0;
            state->have_y = 0;

            state->start_set = 0;
            state->pressed_row = -1;
            state->canceled = 0;

            return 1;
        }

        if (!state->active) {
            return 1;
        }

        int release_row = -1;

        if (
            state->have_x
            && state->have_y
        ) {
            release_row = (
                tfb_menu_touch_row(
                    page,
                    state->raw_x,
                    state->raw_y
                )
            );
        }

        int activate = (
            state->start_set
            && !state->canceled
            && state->pressed_row >= 0
            && release_row
                == state->pressed_row
            && tfb_touch_abs_int(
                state->raw_x
                - state->start_x
            )
                <= TFB_TOUCH_TAP_SLOP
            && tfb_touch_abs_int(
                state->raw_y
                - state->start_y
            )
                <= TFB_TOUCH_TAP_SLOP
        );

        state->active = 0;
        state->have_x = 0;
        state->have_y = 0;
        state->start_set = 0;
        state->pressed_row = -1;
        state->canceled = 0;

        return (
            activate
            ? 3
            : 1
        );
    }

    if (!state->active) {
        return 1;
    }

    if (
        event->code
        == ABS_MT_POSITION_X
    ) {
        state->raw_x =
            event->value;

        state->have_x = 1;
    } else if (
        event->code
        == ABS_MT_POSITION_Y
    ) {
        state->raw_y =
            event->value;

        state->have_y = 1;
    } else {
        return 1;
    }

    if (
        state->have_x
        && state->have_y
        && !state->start_set
    ) {
        state->start_x =
            state->raw_x;

        state->start_y =
            state->raw_y;

        state->start_set = 1;

        state->pressed_row = (
            tfb_menu_touch_row(
                page,
                state->raw_x,
                state->raw_y
            )
        );

        if (
            state->pressed_row
            >= 0
        ) {
            *selected =
                state->pressed_row;

            return 2;
        }

        /*
         * A contact that begins outside a menu row can never become
         * an activating tap merely by moving onto one later.
         */
        state->canceled = 1;

        return 1;
    }

    if (
        state->have_x
        && state->have_y
        && state->start_set
        && !state->canceled
    ) {
        int current_row = (
            tfb_menu_touch_row(
                page,
                state->raw_x,
                state->raw_y
            )
        );

        if (
            tfb_touch_abs_int(
                state->raw_x
                - state->start_x
            )
                > TFB_TOUCH_TAP_SLOP
            || tfb_touch_abs_int(
                state->raw_y
                - state->start_y
            )
                > TFB_TOUCH_TAP_SLOP
            || current_row
                != state->pressed_row
        ) {
            /*
             * Cancellation is sticky for this contact. Returning to
             * the original row before release must not reactivate it.
             */
            state->canceled = 1;
        }
    }

    return 1;
}


/*
 * One canonical menu-selection execution path.
 *
 * KEY_POWER and a completed touchscreen tap both arrive here.
 */

/*
 * ================================================================
 * TFB_PIXEL_PARTITIONER_BLOCK_RUNTIME_V1
 * ================================================================
 *
 * Reuse the existing Bootstrap device-node infrastructure:
 *
 *   tfb_runtime_parse_device_number()
 *   tfb_runtime_makedev()
 *   SYS_MKNODAT
 *   SYS_SYMLINKAT
 *
 * BusyBox remains completely outside device realization.
 */

static int tfb_block_make_path(
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
        return 0;
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


static void tfb_menu_activate_selected(
    const struct tfb_menu_page **page,
    const struct tfb_menu_page **page_stack,
    int *stack_depth,
    int *selected,
    u32 *elapsed_ms,
    int *timeout_fired,
    int *redraw,
    long *inputs,
    int created_input_directory,
    int *created_input_nodes
) {
    if (
        !page
        || !*page
        || !page_stack
        || !stack_depth
        || !selected
        || !elapsed_ms
        || !timeout_fired
        || !redraw
    ) {
        return;
    }

    const struct tfb_menu_entry
        *entry = (
            tfb_menu_visible_entry(
                *page,
                *selected
            )
        );

    if (!entry) {
        tfb_menu_status =
            "INVALID SELECTION";

        *redraw |=
            TFB_REDRAW_STATUS;

        return;
    }

    if (
        entry->submenu
    ) {
        if (
            *stack_depth
            >= TFB_MENU_STACK_DEPTH
        ) {
            tfb_menu_status =
                "SUBMENU DEPTH LIMIT";

            *redraw |=
                TFB_REDRAW_STATUS;

            return;
        }

        /*
         * TFB_PIXEL_PARTITIONER_MENU_SCOPE_V1
         */
        if (
            tfb_pixel_partitioner_page(
                entry->submenu
            )
            && !tfb_pixel_partitioner_activate()
        ) {
            tfb_menu_status =
                "PIXEL PARTITIONER UNAVAILABLE";

            *redraw |=
                TFB_REDRAW_STATUS;

            return;
        }

        page_stack[
            *stack_depth
        ] = entry->submenu;

        (*stack_depth)++;

        *page =
            entry->submenu;

        *selected = (
            tfb_menu_default_selection(
                *page
            )
        );

        tfb_menu_status = (
            tfb_pixel_partitioner_page(
                *page
            )
            ? "PIXEL PARTITIONER READY"
            : 0
        );

        *elapsed_ms = 0;
        *timeout_fired = 0;

        tfb_log(
            "early-menu submenu=enter"
        );

        *redraw |=
            TFB_REDRAW_FULL;

        return;
    }

    if (
        entry->action
        == TFB_ACTION_BACK
    ) {
        if (
            *stack_depth > 1
        ) {
            if (
                tfb_pixel_partitioner_page(
                    *page
                )
            ) {
                tfb_pixel_partitioner_deactivate();
            }

            (*stack_depth)--;

            *page = (
                page_stack[
                    *stack_depth - 1
                ]
            );

            *selected = (
                tfb_menu_default_selection(
                    *page
                )
            );

            tfb_menu_status = 0;

            tfb_log(
                "early-menu submenu=back"
            );

            *redraw |=
                TFB_REDRAW_FULL;
        } else {
            tfb_menu_status =
                "ALREADY AT MAIN MENU";

            *redraw |=
                TFB_REDRAW_STATUS;
        }

        return;
    }

    tfb_menu_execute_action(
        entry->action,
        inputs,
        created_input_directory,
        created_input_nodes
    );

    /*
     * Transition actions never return.  Live Console does return, but
     * it owns the full framebuffer while active and therefore requires
     * a complete menu repaint.
     */
    if (
        entry->action
        == TFB_ACTION_LIVE_CONSOLE
    ) {
        *redraw |=
            TFB_REDRAW_FULL;
    } else {
        *redraw |=
            TFB_REDRAW_STATUS;
    }
}


__attribute__((noreturn))
static void tfb_run_menu(void) {
    int created_input_directory = 0;

    int created_input_nodes[
        INPUT_COUNT
    ];

    int sysfs_devices_seen = 0;

    int last_adb_display_state = -1;

    tfb_realize_input_nodes(
        &created_input_directory,
        created_input_nodes,
        &sysfs_devices_seen
    );

    long inputs[
        INPUT_COUNT
    ];

    int touch_inputs[
        INPUT_COUNT
    ];

    struct tfb_touch_state
        touch_states[
            INPUT_COUNT
        ];

    for (
        int index = 0;
        index < INPUT_COUNT;
        index++
    ) {
        inputs[index] = -1;
        touch_inputs[index] = 0;

        tfb_touch_reset_state(
            &touch_states[index]
        );
    }

    long marker = tfb_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long)
            "/dev/treeforge-bootstrap-early-menu",
        O_WRONLY
        | O_CREAT
        | O_TRUNC,
        0644
    );

    if (marker >= 0) {
        tfb_write_all(
            marker,
            "treeforge-bootstrap-early-menu-v1\n"
        );

        tfb_close(
            marker
        );
    }

    tfb_probe_display_surfaces();

    if (
        sysfs_devices_seen
        > 0
    ) {
        tfb_log(
            "early-menu input-sysfs=present"
        );
    } else {
        tfb_log(
            "early-menu input-sysfs=absent"
        );
    }

    for (
        int index = 0;
        index < INPUT_COUNT;
        index++
    ) {
        char event_path[32];

        tfb_event_path(
            index,
            event_path
        );

        inputs[index] = tfb_open(
            event_path,
            O_RDONLY
            | O_NONBLOCK
        );

        if (
            inputs[index]
            < 0
        ) {
            continue;
        }

        touch_inputs[index] = (
            tfb_input_is_touchscreen(
                index
            )
        );

        tfb_touch_reset_state(
            &touch_states[index]
        );

        /*
         * Drain stale key state before displaying the live menu.
         */
        for (;;) {
            struct tfb_input_event
                event;

            long amount = (
                tfb_syscall3(
                    SYS_READ,
                    inputs[index],
                    (long) &event,
                    (long) sizeof(event)
                )
            );

            if (
                amount
                != (long)
                    sizeof(event)
            ) {
                break;
            }
        }
    }

    const struct tfb_menu_page
        *page_stack[
            TFB_MENU_STACK_DEPTH
        ];

    int stack_depth = 1;

    page_stack[0] = (
        tfb_menu_root_page()
    );

    const struct tfb_menu_page
        *page = page_stack[0];

    int selected = (
        tfb_menu_default_selection(
            page
        )
    );

    u32 elapsed_ms = 0;
    int timeout_fired = 0;

    /*
     * TFB_AUTOBOOT_CANCEL_ON_INTERACTION_V1
     *
     * Once the user deliberately interacts with the boot manager,
     * automatic boot is disabled for the remainder of this menu
     * session.
     *
     * This state is intentionally independent from timeout_fired.
     * Submenu navigation may reset page-local timeout bookkeeping;
     * it must never re-arm autoboot after user interaction.
     */
    int autoboot_canceled = 0;

    tfb_menu_status = 0;

    tfb_log(
        tfb_menu_profile_marker
    );

    tfb_log(
        tfb_menu_profile_id
    );

    tfb_log(
        "early-menu begin"
    );

    tfb_render(
        page,
        selected,
        elapsed_ms,
        timeout_fired
    );

    int rendered_selected =
        selected;

    last_adb_display_state =
        tfb_adb_display_state();

    tfb_log(
        "TFB_DIRTY_REGION_REDRAW_V17_1C"
    );

    for (;;) {
        int redraw = 0;

        for (
            int index = 0;
            index < INPUT_COUNT;
            index++
        ) {
            if (
                inputs[index]
                < 0
            ) {
                char event_path[32];

                tfb_event_path(
                    index,
                    event_path
                );

                inputs[index] = (
                    tfb_open(
                        event_path,
                        O_RDONLY
                        | O_NONBLOCK
                    )
                );

                if (
                    inputs[index]
                    >= 0
                ) {
                    touch_inputs[index] = (
                        tfb_input_is_touchscreen(
                            index
                        )
                    );

                    tfb_touch_reset_state(
                        &touch_states[index]
                    );

                    for (;;) {
                        struct tfb_input_event
                            event;

                        long amount = (
                            tfb_syscall3(
                                SYS_READ,
                                inputs[index],
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
                    }

                    continue;
                }
            }

            if (
                inputs[index]
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
                        inputs[index],
                        (long) &event,
                        (long) sizeof(event)
                    )
                );

                if (
                    amount
                    != (long)
                        sizeof(event)
                ) {
                    if (
                        amount < 0
                        && amount != -11
                    ) {
                        tfb_close(
                            inputs[index]
                        );

                        inputs[index] =
                            -1;
                    }

                    break;
                }

                if (
                    touch_inputs[index]
                    && event.type == EV_ABS
                ) {
                    if (
                        event.code
                            == ABS_MT_TRACKING_ID
                        && event.value >= 0
                    ) {
                        if (!autoboot_canceled) {
                            autoboot_canceled = 1;

                            tfb_log(
                                "early-menu autoboot=canceled input=touch"
                            );
                        }

                        elapsed_ms = 0;
                        tfb_menu_status = 0;

                        redraw |=
                            TFB_REDRAW_STATUS;
                    }

                    int touch_result = (
                        tfb_touch_process_event(
                            &touch_states[index],
                            page,
                            &event,
                            &selected
                        )
                    );

                    if (touch_result != 0) {
                        elapsed_ms = 0;
                        tfb_menu_status = 0;
                    }

                    if (touch_result == 2) {
                        tfb_log(
                            "early-menu touch=select"
                        );

                        redraw |= (
                            TFB_REDRAW_SELECTION
                            | TFB_REDRAW_STATUS
                        );

                        continue;
                    }

                    if (touch_result == 3) {
                        tfb_log(
                            "early-menu touch=activate"
                        );

                        tfb_menu_activate_selected(
                            &page,
                            page_stack,
                            &stack_depth,
                            &selected,
                            &elapsed_ms,
                            &timeout_fired,
                            &redraw,
                            inputs,
                            created_input_directory,
                            created_input_nodes
                        );

                        continue;
                    }

                    if (touch_result != 0) {
                        continue;
                    }
                }

                if (
                    event.type != EV_KEY
                    || event.value != 1
                ) {
                    continue;
                }

                if (
                    event.code == KEY_VOLUMEUP
                    || event.code == KEY_VOLUMEDOWN
                    || event.code == KEY_POWER
                ) {
                    if (!autoboot_canceled) {
                        autoboot_canceled = 1;

                        tfb_log(
                            "early-menu autoboot=canceled input=button"
                        );
                    }

                    elapsed_ms = 0;
                    tfb_menu_status = 0;

                    redraw |=
                        TFB_REDRAW_STATUS;
                }

                if (
                    event.code
                    == KEY_VOLUMEUP
                ) {
                    tfb_log(
                        "early-menu key=volume_up"
                    );

                    selected = (
                        tfb_menu_move_selection(
                            page,
                            selected,
                            -1
                        )
                    );

                    redraw |= (
                        TFB_REDRAW_SELECTION
                        | TFB_REDRAW_STATUS
                    );

                    continue;
                }

                if (
                    event.code
                    == KEY_VOLUMEDOWN
                ) {
                    tfb_log(
                        "early-menu key=volume_down"
                    );

                    selected = (
                        tfb_menu_move_selection(
                            page,
                            selected,
                            1
                        )
                    );

                    redraw |= (
                        TFB_REDRAW_SELECTION
                        | TFB_REDRAW_STATUS
                    );

                    continue;
                }

                if (
                    event.code
                    != KEY_POWER
                ) {
                    continue;
                }

                tfb_log(
                    "early-menu key=power"
                );

                tfb_menu_activate_selected(
                    &page,
                    page_stack,
                    &stack_depth,
                    &selected,
                    &elapsed_ms,
                    &timeout_fired,
                    &redraw,
                    inputs,
                    created_input_directory,
                    created_input_nodes
                );
            }
        }

        if (
            page->timeout_ms != 0
            && !timeout_fired
            && !autoboot_canceled
        ) {
            if (
                elapsed_ms
                + POLL_INTERVAL_MS
                >= page->timeout_ms
            ) {
                elapsed_ms =
                    page->timeout_ms;

                timeout_fired = 1;

                tfb_log(
                    "early-menu timeout"
                );

                tfb_menu_execute_action(
                    page->timeout_action,
                    inputs,
                    created_input_directory,
                    created_input_nodes
                );

                redraw |=
                    TFB_REDRAW_STATUS;
            } else {
                u32 previous_second = (
                    elapsed_ms
                    / 1000U
                );

                elapsed_ms +=
                    POLL_INTERVAL_MS;

                if (
                    elapsed_ms
                    / 1000U
                    != previous_second
                ) {
                    redraw |=
                        TFB_REDRAW_STATUS;
                }
            }
        }

        tfb_pixel_partitioner_service(
            page,
            &redraw
        );

        int adb_display_state =
            tfb_adb_display_state();

        if (
            adb_display_state
            != last_adb_display_state
        ) {
            last_adb_display_state =
                adb_display_state;

            redraw |=
                TFB_REDRAW_ADB;
        }

        if (
            redraw
            & TFB_REDRAW_FULL
        ) {
            tfb_render(
                page,
                selected,
                elapsed_ms,
                (
                    timeout_fired
                    || autoboot_canceled
                )
            );

            rendered_selected =
                selected;
        } else {
            if (
                redraw
                & TFB_REDRAW_SELECTION
            ) {
                tfb_fb_render_selection_delta(
                    page,
                    rendered_selected,
                    selected
                );

                rendered_selected =
                    selected;
            }

            if (
                redraw
                & TFB_REDRAW_STATUS
            ) {
                tfb_fb_render_status_region(
                    page,
                    elapsed_ms,
                    (
                        timeout_fired
                        || autoboot_canceled
                    )
                );
            }

            if (
                redraw
                & TFB_REDRAW_ADB
            ) {
                tfb_fb_render_adb_region();
            }
        }

        tfb_sleep_ms(
            POLL_INTERVAL_MS
        );
    }
}


__attribute__((noreturn))
static void tfb_main(
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

        tfb_run_menu();
    }

    /*
     * Initial invocation from the kernel.
     *
     * FD99 is the only retained descriptor. It carries this dispatcher
     * and the appended TreeForge Bootstrap runtime bundle through Google's
     * currently proven FirstStageMain boundary.
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

    @staticmethod
    def _project_version() -> str:
        # TreeForge Bootstrap owns this dispatcher independently
        # from the TreeForge Bootstrap repository.
        return "1.0"



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

        placeholder = (
            "__TREEFORGE_BOOTSTRAP_VERSION__"
        )

        if (
            cls._SOURCE.count(
                placeholder
            )
            != 1
        ):
            raise TreeForgeDispatcherError(
                "TreeForge Bootstrap version "
                "placeholder is not unique"
            )

        profile_placeholder = (
            "__TREEFORGE_MENU_PROFILE__"
        )

        if (
            cls._SOURCE.count(
                profile_placeholder
            )
            != 1
        ):
            raise TreeForgeDispatcherError(
                "TreeForge Menu profile "
                "placeholder is not unique"
            )

        generated_source = (
            cls._SOURCE
            .replace(
                placeholder,
                cls._project_version(),
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
