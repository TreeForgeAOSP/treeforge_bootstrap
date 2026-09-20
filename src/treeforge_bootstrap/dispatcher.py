from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import shutil
import struct
import subprocess
import tomllib


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

#define PIXEL_PARTITIONER_TRANSITION_FD 99
#define PROT_READ 1
#define PROT_WRITE 2

#define MAP_SHARED 1

#define S_IFCHR 0020000

#define MS_RDONLY 1
#define MNT_DETACH 2

#define LINUX_REBOOT_MAGIC1 0xfee1deadUL
#define LINUX_REBOOT_MAGIC2 672274793UL
#define LINUX_REBOOT_CMD_RESTART 0x01234567UL
#define LINUX_REBOOT_CMD_RESTART2 0xa1b2c3d4UL

#define EV_KEY 1
#define KEY_VOLUMEDOWN 114
#define KEY_VOLUMEUP 115
#define KEY_POWER 116

#define INPUT_COUNT 32

#define MENU_TIMEOUT_MS 10000
#define POLL_INTERVAL_MS 25


struct pp_timespec {
    long tv_sec;
    long tv_nsec;
};

struct pp_input_event {
    long tv_sec;
    long tv_usec;
    u16 type;
    u16 code;
    s32 value;
};

struct pp_linux_dirent64 {
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

static long pp_syscall6(
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

static long pp_syscall4(
    long number,
    long a0,
    long a1,
    long a2,
    long a3
) {
    return pp_syscall6(
        number,
        a0,
        a1,
        a2,
        a3,
        0,
        0
    );
}

static long pp_syscall3(
    long number,
    long a0,
    long a1,
    long a2
) {
    return pp_syscall6(
        number,
        a0,
        a1,
        a2,
        0,
        0,
        0
    );
}

static long pp_syscall2(
    long number,
    long a0,
    long a1
) {
    return pp_syscall6(
        number,
        a0,
        a1,
        0,
        0,
        0,
        0
    );
}

static long pp_syscall1(
    long number,
    long a0
) {
    return pp_syscall6(
        number,
        a0,
        0,
        0,
        0,
        0,
        0
    );
}

static usize pp_strlen(
    const char *value
) {
    usize length = 0;

    while (value[length] != '\0') {
        length++;
    }

    return length;
}


static long pp_open(
    const char *path,
    long flags
) {
    return pp_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long) path,
        flags,
        0
    );
}

static void pp_close(
    long fd
) {
    if (fd >= 0) {
        pp_syscall1(
            SYS_CLOSE,
            fd
        );
    }
}

static void pp_write_all(
    long fd,
    const char *value
) {
    if (fd < 0) {
        return;
    }

    usize remaining = pp_strlen(
        value
    );

    const char *cursor = value;

    while (remaining != 0) {
        long written = pp_syscall3(
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

static int pp_write_bytes(
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
        long written = pp_syscall3(
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



static long pp_copy_fd_failure_code = 0;

static const char *pp_runtime_materialize_failure_stage =
    "NONE";

static const char *pp_runtime_materialize_failure_path =
    0;

static const char *pp_runtime_materialize_failure_source_path =
    0;


static const char *pp_copy_fd_failure_code_name(
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


static int pp_read_exact(
    long fd,
    unsigned char *buffer,
    usize size
) {
    usize remaining = size;
    unsigned char *cursor = buffer;

    while (remaining != 0) {
        long amount = pp_syscall3(
            SYS_READ,
            fd,
            (long) cursor,
            (long) remaining
        );

        if (amount <= 0) {
            pp_copy_fd_failure_code = (
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


static u32 pp_u32_le(
    const unsigned char *value
) {
    return (
        ((u32) value[0])
        | ((u32) value[1] << 8)
        | ((u32) value[2] << 16)
        | ((u32) value[3] << 24)
    );
}


static u64 pp_u64_le(
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


static int pp_magic8_equal(
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


static int pp_create_parent_directories(
    const char *path
) {
    if (
        !path
        || path[0] != '/'
    ) {
        return 0;
    }

    char buffer[512];

    usize length = pp_strlen(
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
     * performed by pp_copy_fd_to_path() is the authoritative test.
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

        pp_syscall3(
            SYS_MKDIRAT,
            AT_FDCWD,
            (long) buffer,
            0755
        );

        buffer[index] = '/';
    }

    return 1;
}


static int pp_materialize_runtime_bundle(void) {
    /*
     * FD99 is the exact open /init descriptor that has already been
     * proven to survive Android FirstStageMain / FreeRamdisk and the
     * redirected selinux_setup re-entry.
     *
     * The dispatcher ELF carries a deterministic runtime bundle after
     * its ELF payload.  Locate its trailer from EOF, then stream each
     * file directly from FD99 into /dev/pixel-partitioner-runtime.
     */
    pp_runtime_materialize_failure_stage =
        "NONE";

    pp_runtime_materialize_failure_path =
        0;

    pp_runtime_materialize_failure_source_path =
        "FD99 SELF BUNDLE";

    pp_copy_fd_failure_code = 0;

    long trailer_position = pp_syscall3(
        SYS_LSEEK,
        PIXEL_PARTITIONER_TRANSITION_FD,
        -16,
        SEEK_END
    );

    if (trailer_position < 0) {
        pp_runtime_materialize_failure_stage =
            "BUNDLE SEEK END";

        pp_copy_fd_failure_code =
            trailer_position;

        return 0;
    }

    unsigned char trailer[16];

    if (
        !pp_read_exact(
            PIXEL_PARTITIONER_TRANSITION_FD,
            trailer,
            sizeof(trailer)
        )
    ) {
        pp_runtime_materialize_failure_stage =
            "BUNDLE TRAILER READ";

        return 0;
    }

    if (
        !pp_magic8_equal(
            trailer,
            "TFRTEND1"
        )
    ) {
        pp_runtime_materialize_failure_stage =
            "BUNDLE TRAILER MAGIC";

        return 0;
    }

    u64 bundle_size = pp_u64_le(
        trailer + 8
    );

    if (
        bundle_size < 16
        || bundle_size
            > (u64) trailer_position
    ) {
        pp_runtime_materialize_failure_stage =
            "BUNDLE SIZE";

        return 0;
    }

    long bundle_start = (
        trailer_position
        - (long) bundle_size
    );

    long bundle_seek = pp_syscall3(
        SYS_LSEEK,
        PIXEL_PARTITIONER_TRANSITION_FD,
        bundle_start,
        SEEK_SET
    );

    if (bundle_seek < 0) {
        pp_runtime_materialize_failure_stage =
            "BUNDLE SEEK START";

        pp_copy_fd_failure_code =
            bundle_seek;

        return 0;
    }

    unsigned char bundle_header[16];

    if (
        !pp_read_exact(
            PIXEL_PARTITIONER_TRANSITION_FD,
            bundle_header,
            sizeof(bundle_header)
        )
    ) {
        pp_runtime_materialize_failure_stage =
            "BUNDLE HEADER READ";

        return 0;
    }

    if (
        !pp_magic8_equal(
            bundle_header,
            "TFRTB001"
        )
    ) {
        pp_runtime_materialize_failure_stage =
            "BUNDLE HEADER MAGIC";

        return 0;
    }

    u32 file_count = pp_u32_le(
        bundle_header + 8
    );

    if (
        file_count == 0
        || file_count > 256
    ) {
        pp_runtime_materialize_failure_stage =
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
            !pp_read_exact(
                PIXEL_PARTITIONER_TRANSITION_FD,
                entry_header,
                sizeof(entry_header)
            )
        ) {
            pp_runtime_materialize_failure_stage =
                "ENTRY HEADER READ";

            return 0;
        }

        u32 path_length = pp_u32_le(
            entry_header
        );

        u32 mode = pp_u32_le(
            entry_header + 4
        );

        u64 payload_size = pp_u64_le(
            entry_header + 8
        );

        if (
            path_length == 0
            || path_length
                >= sizeof(destination_path)
            || mode > 0777U
        ) {
            pp_runtime_materialize_failure_stage =
                "ENTRY METADATA";

            return 0;
        }

        if (
            !pp_read_exact(
                PIXEL_PARTITIONER_TRANSITION_FD,
                (unsigned char *)
                    destination_path,
                path_length
            )
        ) {
            pp_runtime_materialize_failure_stage =
                "ENTRY PATH READ";

            return 0;
        }

        destination_path[path_length] =
            '\0';

        pp_runtime_materialize_failure_path =
            destination_path;

        if (destination_path[0] != '/') {
            pp_runtime_materialize_failure_stage =
                "ENTRY PATH INVALID";

            return 0;
        }

        if (
            !pp_create_parent_directories(
                destination_path
            )
        ) {
            pp_runtime_materialize_failure_stage =
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
                pp_runtime_materialize_failure_stage =
                    "SYMLINK PAYLOAD SIZE";

                return 0;
            }

            if (
                !pp_read_exact(
                    PIXEL_PARTITIONER_TRANSITION_FD,
                    (unsigned char *)
                        symlink_target,
                    (usize) payload_size
                )
            ) {
                pp_runtime_materialize_failure_stage =
                    "SYMLINK PAYLOAD READ";

                return 0;
            }

            if (
                symlink_target[
                    (usize) payload_size - 1
                ]
                != '\0'
            ) {
                pp_runtime_materialize_failure_stage =
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
                    pp_runtime_materialize_failure_stage =
                        "SYMLINK TARGET EMBEDDED NUL";

                    return 0;
                }
            }

            /*
             * A stale realization is harmless to remove.  Ignore
             * ENOENT and let symlinkat() be the authoritative result.
             */
            pp_syscall3(
                SYS_UNLINKAT,
                AT_FDCWD,
                (long) destination_path,
                0
            );

            long symlink_result = pp_syscall3(
                SYS_SYMLINKAT,
                (long) symlink_target,
                AT_FDCWD,
                (long) destination_path
            );

            if (symlink_result < 0) {
                pp_runtime_materialize_failure_stage =
                    "SYMLINK CREATE";

                pp_copy_fd_failure_code =
                    symlink_result;

                return 0;
            }

            continue;
        }

        long destination_fd = pp_syscall4(
            SYS_OPENAT,
            AT_FDCWD,
            (long) destination_path,
            O_WRONLY
            | O_CREAT
            | O_TRUNC,
            mode
        );

        if (destination_fd < 0) {
            pp_runtime_materialize_failure_stage =
                "DESTINATION OPEN";

            pp_copy_fd_failure_code =
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

            long amount = pp_syscall3(
                SYS_READ,
                PIXEL_PARTITIONER_TRANSITION_FD,
                (long) buffer,
                (long) requested
            );

            if (amount <= 0) {
                pp_runtime_materialize_failure_stage =
                    "BUNDLE DATA READ";

                pp_copy_fd_failure_code = (
                    amount < 0
                    ? amount
                    : -5
                );

                pp_close(
                    destination_fd
                );

                pp_syscall3(
                    SYS_UNLINKAT,
                    AT_FDCWD,
                    (long) destination_path,
                    0
                );

                return 0;
            }

            if (
                !pp_write_bytes(
                    destination_fd,
                    buffer,
                    (usize) amount
                )
            ) {
                pp_runtime_materialize_failure_stage =
                    "DESTINATION WRITE";

                pp_copy_fd_failure_code =
                    -5;

                pp_close(
                    destination_fd
                );

                pp_syscall3(
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

        pp_close(
            destination_fd
        );
    }

    return 1;
}


static void pp_sleep_ms(
    long milliseconds
) {
    struct pp_timespec delay;

    delay.tv_sec = (
        milliseconds
        / 1000
    );

    delay.tv_nsec = (
        milliseconds
        % 1000
    ) * 1000000L;

    pp_syscall2(
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
static long pp_tty = -1;
static long pp_console = -1;
static long pp_kmsg = -1;

/*
 * Retained TreeForge Bootstrap framebuffer menu session.
 *
 * The framebuffer uses the native DRM mode coordinates exactly as
 * exposed by the kernel. No rotation or orientation policy is
 * applied here.
 */
static int pp_fb_menu_active = 0;


static long pp_fb_menu_mapped_address = -1;
static u64 pp_fb_menu_mapped_size = 0;

static u32 pp_fb_menu_width = 0;
static u32 pp_fb_menu_height = 0;
static u32 pp_fb_menu_pitch = 0;





/*
 * PIXEL_PARTITIONER_FB_CONSUMER_V1
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
#define PP_FB_DEVICE_PATH \
    "/dev/pixel_partitioner_fb"

#define PP_FB_SYSFS_DEV_PATH \
    "/sys/class/misc/pixel_partitioner_fb/dev"

#define PP_FB_ABI_VERSION 1U

#define PP_FB_FLAG_LINEAR \
    (1U << 0)

#define PP_FB_FLAG_WRITE_COMBINE \
    (1U << 1)

#define PP_FB_REQUIRED_FLAGS \
    ( \
        PP_FB_FLAG_LINEAR \
        | PP_FB_FLAG_WRITE_COMBINE \
    )

/*
 * Linux generic _IO('P', 0x01).
 */
#define PP_FB_IOCTL_SEAL 0x5001UL

struct pp_fb_info {
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

typedef char pp_fb_info_size_check[
    sizeof(struct pp_fb_info) == 64
    ? 1
    : -1
];

static long pp_fb_fd = -1;
static int pp_fb_active = 0;
static int pp_fb_created_node = 0;


static void pp_fb_fill_rect(
    u32 x,
    u32 y,
    u32 width,
    u32 height,
    u32 pixel
) {
    if (
        !pp_fb_menu_active
        || pp_fb_menu_mapped_address < 0
        || x >= pp_fb_menu_width
        || y >= pp_fb_menu_height
    ) {
        return;
    }

    if (
        width
        > pp_fb_menu_width - x
    ) {
        width = (
            pp_fb_menu_width - x
        );
    }

    if (
        height
        > pp_fb_menu_height - y
    ) {
        height = (
            pp_fb_menu_height - y
        );
    }

    volatile unsigned char *base = (
        (volatile unsigned char *)
        (usize) pp_fb_menu_mapped_address
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
                    * (usize) pp_fb_menu_pitch
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


static unsigned char pp_fb_glyph_row(
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


static void pp_fb_draw_char(
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
            pp_fb_glyph_row(
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
                pp_fb_fill_rect(
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


static u32 pp_fb_text_width(
    const char *value,
    u32 scale
) {
    usize length = (
        pp_strlen(
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


static void pp_fb_draw_text(
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
            pp_fb_draw_char(
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



static const char pp_version[] =
    "V__PIXEL_PARTITIONER_VERSION__";


/*
 * PIXEL_PARTITIONER_STANDALONE_POLICY_V1
 *
 * Hardware implementation is inherited from the proven TreeForge Bootstrap
 * dispatcher.  The visible policy is standalone TreeForge Bootstrap.
 */

static int pp_menu_item_count(void) {
    return 1;
}

static const char *pp_menu_item(
    int index
) {
    static const char *items[1] = {
        "REBOOT BOOTLOADER",
    };

    if (
        index < 0
        || index >= pp_menu_item_count()
    ) {
        return "";
    }

    return items[index];
}


static const char *pp_countdown_line(void) {
    return "WAITING FOR SELECTION";
}


static void pp_fb_render_menu(
    int selected
) {
    if (
        !pp_fb_menu_active
        || pp_fb_menu_mapped_address < 0
    ) {
        return;
    }

    const u32 background = 0x00000000U;
    const u32 foreground = 0x00ffffffU;
    const u32 inactive = 0x00282828U;

    pp_fb_fill_rect(
        0,
        0,
        pp_fb_menu_width,
        pp_fb_menu_height,
        background
    );

    u32 scale = (
        pp_fb_menu_width
        / 160U
    );

    u32 height_scale = (
        pp_fb_menu_height
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

    static const char title[] =
        "TREEFORGE MENU";

    static const char subtitle[] =
        "STANDALONE MAINTENANCE";

    u32 title_width = (
        pp_fb_text_width(
            title,
            scale
        )
    );

    u32 title_x = (
        pp_fb_menu_width > title_width
        ? (
            pp_fb_menu_width
            - title_width
        ) / 2U
        : 0
    );

    u32 subtitle_width = (
        pp_fb_text_width(
            subtitle,
            scale
        )
    );

    u32 subtitle_x = (
        pp_fb_menu_width > subtitle_width
        ? (
            pp_fb_menu_width
            - subtitle_width
        ) / 2U
        : 0
    );

    int item_count =
        pp_menu_item_count();

    u32 row_height =
        13U * scale;

    u32 row_gap =
        4U * scale;

    u32 total_rows = (
        row_height
        * (u32) item_count
        + row_gap
        * (u32) (
            item_count - 1
        )
    );

    u32 rows_y = (
        pp_fb_menu_height > total_rows
        ? (
            pp_fb_menu_height
            - total_rows
        ) / 2U
        : 0
    );

    u32 title_y = (
        rows_y > 42U * scale
        ? rows_y - 42U * scale
        : scale
    );

    pp_fb_draw_text(
        title_x,
        title_y,
        title,
        scale,
        foreground
    );

    u32 version_width = (
        pp_fb_text_width(
            pp_version,
            scale
        )
    );

    u32 version_x = (
        pp_fb_menu_width > version_width
        ? (
            pp_fb_menu_width
            - version_width
        ) / 2U
        : 0
    );

    pp_fb_draw_text(
        version_x,
        title_y + 10U * scale,
        pp_version,
        scale,
        foreground
    );

    pp_fb_draw_text(
        subtitle_x,
        title_y + 20U * scale,
        subtitle,
        scale,
        foreground
    );

    u32 box_x =
        pp_fb_menu_width / 10U;

    u32 box_width = (
        pp_fb_menu_width
        - box_x * 2U
    );

    for (
        int index = 0;
        index < item_count;
        index++
    ) {
        u32 row_y = (
            rows_y
            + (
                (u32) index
                * (
                    row_height
                    + row_gap
                )
            )
        );

        int active = (
            index == selected
        );

        pp_fb_fill_rect(
            box_x,
            row_y,
            box_width,
            row_height,
            active
            ? foreground
            : inactive
        );

        const char *item =
            pp_menu_item(index);

        u32 item_scale =
            scale;

        u32 available_width = (
            box_width > 4U * scale
            ? box_width - 4U * scale
            : box_width
        );

        while (
            item_scale > 2U
            && pp_fb_text_width(
                item,
                item_scale
            ) > available_width
        ) {
            item_scale--;
        }

        u32 text_width = (
            pp_fb_text_width(
                item,
                item_scale
            )
        );

        u32 text_x = (
            pp_fb_menu_width > text_width
            ? (
                pp_fb_menu_width
                - text_width
            ) / 2U
            : box_x
        );

        u32 glyph_height =
            7U * item_scale;

        u32 text_y = (
            row_y
            + (
                row_height > glyph_height
                ? (
                    row_height
                    - glyph_height
                ) / 2U
                : 0
            )
        );

        pp_fb_draw_text(
            text_x,
            text_y,
            item,
            item_scale,
            active
            ? background
            : foreground
        );
    }

    const char *status =
        pp_countdown_line();

    u32 status_scale =
        scale;

    while (
        status_scale > 2U
        && pp_fb_text_width(
            status,
            status_scale
        ) > box_width
    ) {
        status_scale--;
    }

    u32 status_width = (
        pp_fb_text_width(
            status,
            status_scale
        )
    );

    u32 status_x = (
        pp_fb_menu_width > status_width
        ? (
            pp_fb_menu_width
            - status_width
        ) / 2U
        : 0
    );

    u32 status_y = (
        rows_y
        + total_rows
        + 12U * scale
    );

    if (
        status_y
        + 7U * status_scale
        < pp_fb_menu_height
    ) {
        pp_fb_draw_text(
            status_x,
            status_y,
            status,
            status_scale,
            foreground
        );
    }
}

static void pp_output(
    const char *value
) {
    pp_write_all(
        pp_tty,
        value
    );

    pp_write_all(
        pp_console,
        value
    );
}

static void pp_log(
    const char *value
) {
    pp_write_all(
        pp_kmsg,
        "<6>pixel_partitioner: "
    );

    pp_write_all(
        pp_kmsg,
        value
    );

    pp_write_all(
        pp_kmsg,
        "\n"
    );
}


static void pp_render(
    int selected
) {
    pp_output(
        "\033[2J\033[H"
        "TreeForge Bootstrap\n"
    );

    pp_output(
        pp_version
    );

    pp_output(
        "\n\n"
        "STANDALONE MAINTENANCE\n\n"
    );

    int item_count =
        pp_menu_item_count();

    for (
        int index = 0;
        index < item_count;
        index++
    ) {
        pp_output(
            index == selected
            ? "> "
            : "  "
        );

        pp_output(
            pp_menu_item(
                index
            )
        );

        pp_output(
            "\n"
        );
    }

    pp_output(
        "\n"
        "Volume Up/Down: navigate\n"
        "Power: select\n\n"
    );

    pp_output(
        pp_countdown_line()
    );

    pp_output(
        "\n"
    );

    pp_fb_render_menu(
        selected
    );
}

static void pp_fb_draw_management_line(
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
        pp_fb_menu_width > margin
        ? pp_fb_menu_width - margin
        : pp_fb_menu_width
    );

    while (
        line_scale > 2U
        && pp_fb_text_width(
            value,
            line_scale
        ) > available_width
    ) {
        line_scale--;
    }

    u32 width = (
        pp_fb_text_width(
            value,
            line_scale
        )
    );

    u32 x = (
        pp_fb_menu_width > width
        ? (
            pp_fb_menu_width
            - width
        ) / 2U
        : 0
    );

    pp_fb_draw_text(
        x,
        y,
        value,
        line_scale,
        pixel
    );
}


static void pp_event_path(
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

static void pp_runtime_sysfs_event_dev_path(
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

static unsigned long pp_runtime_makedev(
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

static int pp_runtime_parse_device_number(
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

static int pp_get_event_device_number(
    int index,
    unsigned long *major,
    unsigned long *minor
) {
    char path[64];

    pp_runtime_sysfs_event_dev_path(
        index,
        path
    );

    long fd = pp_open(
        path,
        O_RDONLY
    );

    if (fd < 0) {
        return -1;
    }

    char buffer[32];

    long amount = pp_syscall3(
        SYS_READ,
        fd,
        (long) buffer,
        (long) (
            sizeof(buffer)
            - 1
        )
    );

    pp_close(
        fd
    );

    if (amount <= 0) {
        return -1;
    }

    buffer[amount] = '\0';

    return pp_runtime_parse_device_number(
        buffer,
        amount,
        major,
        minor
    );
}

static int pp_realize_input_nodes(
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
    long mkdir_result = pp_syscall3(
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
            pp_get_event_device_number(
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

        pp_event_path(
            index,
            path
        );

        long result = pp_syscall4(
            SYS_MKNODAT,
            AT_FDCWD,
            (long) path,
            S_IFCHR | 0600,
            (long) pp_runtime_makedev(
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

static void pp_cleanup_realized_input_nodes(
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

        pp_event_path(
            index,
            path
        );

        pp_syscall3(
            SYS_UNLINKAT,
            AT_FDCWD,
            (long) path,
            0
        );

        created_nodes[index] = 0;
    }

    if (created_input_directory) {
        pp_syscall3(
            SYS_UNLINKAT,
            AT_FDCWD,
            (long) "/dev/input",
            AT_REMOVEDIR
        );
    }
}

static void pp_close_inputs(
    long *inputs
) {
    for (
        int index = 0;
        index < INPUT_COUNT;
        index++
    ) {
        if (inputs[index] >= 0) {
            pp_close(
                inputs[index]
            );

            inputs[index] = -1;
        }
    }
}

static int pp_reboot_to(
    const char *target
) {
    pp_syscall1(
        SYS_SYNC,
        0
    );

    long result = pp_syscall4(
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
#define SYS_WAIT4 260

#define PIXEL_PARTITIONER_SIGKILL 9
#define PIXEL_PARTITIONER_SIGCHLD 17

#define PIXEL_PARTITIONER_WAIT_WNOHANG 1


#define PIXEL_PARTITIONER_TRANSITION_FAILURE_PATH \
    "/metadata/pixel-partitioner/last-transition-failure"




static int pp_string_equal(
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


static int pp_probe_readable_path(
    const char *path
) {
    long fd = pp_open(
        path,
        O_RDONLY
        | O_NONBLOCK
    );

    if (fd < 0) {
        return 0;
    }

    pp_close(
        fd
    );

    return 1;
}


static void pp_create_presence_marker(
    const char *path
) {
    long fd = pp_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long) path,
        O_WRONLY
        | O_CREAT
        | O_TRUNC,
        0644
    );

    if (fd >= 0) {
        pp_close(
            fd
        );
    }
}


static void pp_record_transition_failure(
    const char *reason
) {
    /*
     * Transition diagnostics are TreeForge Bootstrap-owned userspace evidence.
     *
     * /metadata may not be available for failures that occur before
     * Android first stage mounts it, so this path is strictly
     * best-effort and must never become a new boot dependency.
     */
    pp_syscall3(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long) "/metadata/pixel-partitioner",
        0755
    );

    long fd = pp_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long) PIXEL_PARTITIONER_TRANSITION_FAILURE_PATH,
        O_WRONLY
        | O_CREAT
        | O_TRUNC,
        0644
    );

    if (fd < 0) {
        return;
    }

    pp_write_all(
        fd,
        "pixel-partitioner-transition-failure-v1\n"
        "reason="
    );

    pp_write_all(
        fd,
        (
            reason
            ? reason
            : "unknown"
        )
    );

    pp_write_all(
        fd,
        "\n"
    );

    pp_close(
        fd
    );

    pp_syscall1(
        SYS_SYNC,
        0
    );
}


static int pp_fb_parse_dev_number(
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


static unsigned long pp_fb_encode_dev(
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


static void pp_fb_remove_created_node(void) {
    if (!pp_fb_created_node) {
        return;
    }

    pp_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long) PP_FB_DEVICE_PATH,
        0
    );

    pp_fb_created_node = 0;
}


static int pp_fb_realize_node(void) {
    /*
     * If a device manager has already materialized the node, leave it
     * entirely alone.
     */
    long existing = pp_open(
        PP_FB_DEVICE_PATH,
        O_RDWR
    );

    if (existing >= 0) {
        pp_close(
            existing
        );

        return 1;
    }

    long sysfs_fd = pp_open(
        PP_FB_SYSFS_DEV_PATH,
        O_RDONLY
        | O_NONBLOCK
    );

    if (sysfs_fd < 0) {
        pp_create_presence_marker(
            "/dev/pixel-partitioner-fb-sysfs-missing"
        );

        return 0;
    }

    char value[32];

    long amount = pp_syscall3(
        SYS_READ,
        sysfs_fd,
        (long) value,
        (long) sizeof(value)
    );

    pp_close(
        sysfs_fd
    );

    if (amount <= 0) {
        pp_create_presence_marker(
            "/dev/pixel-partitioner-fb-sysfs-read-failed"
        );

        return 0;
    }

    u32 major_value = 0;
    u32 minor_value = 0;

    if (
        !pp_fb_parse_dev_number(
            value,
            (usize) amount,
            &major_value,
            &minor_value
        )
    ) {
        pp_create_presence_marker(
            "/dev/pixel-partitioner-fb-dev-number-invalid"
        );

        return 0;
    }

    unsigned long encoded = (
        pp_fb_encode_dev(
            major_value,
            minor_value
        )
    );

    long result = pp_syscall4(
        SYS_MKNODAT,
        AT_FDCWD,
        (long) PP_FB_DEVICE_PATH,
        S_IFCHR | 0600,
        (long) encoded
    );

    /*
     * Even if mknodat raced with another creator, opening the node is
     * the authoritative result.
     */
    long verify = pp_open(
        PP_FB_DEVICE_PATH,
        O_RDWR
    );

    if (verify < 0) {
        pp_create_presence_marker(
            "/dev/pixel-partitioner-fb-node-failed"
        );

        return 0;
    }

    pp_close(
        verify
    );

    if (result == 0) {
        pp_fb_created_node = 1;

        pp_create_presence_marker(
            "/dev/pixel-partitioner-fb-node-created"
        );
    } else {
        pp_create_presence_marker(
            "/dev/pixel-partitioner-fb-node-existing"
        );
    }

    return 1;
}


static int pp_fb_read_info(
    long fd,
    struct pp_fb_info *info
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
        long amount = pp_syscall3(
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


static int pp_fb_validate_info(
    const struct pp_fb_info *info
) {
    if (!info) {
        return 0;
    }

    if (
        info->abi_version
        != PP_FB_ABI_VERSION
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
        != PP_FB_REQUIRED_FLAGS
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


static int pp_fb_begin(void) {
    if (pp_fb_active) {
        return 1;
    }

    if (!pp_fb_realize_node()) {
        return 0;
    }

    long fd = pp_open(
        PP_FB_DEVICE_PATH,
        O_RDWR
    );

    if (fd < 0) {
        pp_create_presence_marker(
            "/dev/pixel-partitioner-fb-open-failed"
        );

        pp_fb_remove_created_node();

        return 0;
    }

    struct pp_fb_info info;

    if (
        !pp_fb_read_info(
            fd,
            &info
        )
    ) {
        pp_create_presence_marker(
            "/dev/pixel-partitioner-fb-info-read-failed"
        );

        pp_close(
            fd
        );

        pp_fb_remove_created_node();

        return 0;
    }

    if (!pp_fb_validate_info(&info)) {
        pp_create_presence_marker(
            "/dev/pixel-partitioner-fb-info-invalid"
        );

        pp_close(
            fd
        );

        pp_fb_remove_created_node();

        return 0;
    }

    long mapped_address = pp_syscall6(
        SYS_MMAP,
        0,
        (long) info.mmap_bytes,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        fd,
        0
    );

    if (mapped_address < 0) {
        pp_create_presence_marker(
            "/dev/pixel-partitioner-fb-mmap-failed"
        );

        pp_close(
            fd
        );

        pp_fb_remove_created_node();

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
    pp_fb_fd = fd;
    pp_fb_active = 1;

    pp_fb_menu_active = 1;
    pp_fb_menu_mapped_address = (
        mapped_address
    );
    pp_fb_menu_mapped_size = (
        info.mmap_bytes
    );
    pp_fb_menu_width = (
        info.width
    );
    pp_fb_menu_height = (
        info.height
    );
    pp_fb_menu_pitch = (
        info.stride
    );

    pp_create_presence_marker(
        "/dev/pixel-partitioner-fb-info-ok"
    );

    pp_create_presence_marker(
        "/dev/pixel-partitioner-fb-mmap-ok"
    );

    pp_create_presence_marker(
        "/dev/pixel-partitioner-fb-menu-active"
    );

    pp_log(
        "pixel-partitioner-fb menu-active"
    );

    return 1;
}


static void pp_fb_cleanup(void) {
    if (!pp_fb_active) {
        return;
    }

    if (
        pp_fb_menu_mapped_address >= 0
        && pp_fb_menu_mapped_size != 0
    ) {
        pp_syscall2(
            SYS_MUNMAP,
            pp_fb_menu_mapped_address,
            (long) pp_fb_menu_mapped_size
        );
    }

    pp_close(
        pp_fb_fd
    );

    pp_fb_remove_created_node();

    pp_fb_fd = -1;
    pp_fb_active = 0;

    pp_fb_menu_active = 0;
    pp_fb_menu_mapped_address = -1;
    pp_fb_menu_mapped_size = 0;

    pp_fb_menu_width = 0;
    pp_fb_menu_height = 0;
    pp_fb_menu_pitch = 0;

    pp_create_presence_marker(
        "/dev/pixel-partitioner-fb-cleanup"
    );
}


static void pp_fb_menu_cleanup(void) {
    /*
     * The renderer still uses the historical pp_fb_* internal state
     * names, but display ownership is now exclusively the Pixel
     * Partitioner framebuffer bridge.
     */
    if (pp_fb_active) {
        pp_fb_cleanup();
    }
}

static void pp_probe_display_surfaces(void) {
    /*
     * PIXEL_PARTITIONER_FB_BRIDGE_ONLY_V1
     *
     * Hardware acceptance proved the GS201 bootloader framebuffer
     * bridge as the canonical TreeForge Bootstrap early-display path.
     *
     * Do not program DRM/KMS here and do not fall back to the legacy
     * TreeForge Bootstrap framebuffer realization path.
     */
    if (pp_fb_begin()) {
        pp_create_presence_marker(
            "/dev/pixel-partitioner-fb-primary"
        );

        return;
    }

    pp_create_presence_marker(
        "/dev/pixel-partitioner-fb-required-failed"
    );

    pp_log(
        "pixel-partitioner-fb required-failed"
    );
}


static const char *pp_transition_failure_display_reason(
    const char *reason
) {
    if (!reason) {
        return "UNKNOWN";
    }

    if (
        pp_string_equal(
            reason,
            "invalid-pixel-partitioner-reentry"
        )
    ) {
        return "INVALID REENTRY";
    }

    if (
        pp_string_equal(
            reason,
            "pixel-partitioner-runtime-materialize"
        )
    ) {
        return "RUNTIME MATERIALIZE";
    }

    if (
        pp_string_equal(
            reason,
            "pixel-partitioner-adb-service-clone"
        )
    ) {
        return "ADB SERVICE CLONE";
    }

    if (
        pp_string_equal(
            reason,
            "transition-fd-open"
        )
    ) {
        return "TRANSITION FD OPEN";
    }

    if (
        pp_string_equal(
            reason,
            "transition-fd-duplicate"
        )
    ) {
        return "TRANSITION FD DUPLICATE";
    }

    if (
        pp_string_equal(
            reason,
            "first-stage-exec"
        )
    ) {
        return "FIRST STAGE EXEC";
    }

    if (
        pp_string_equal(
            reason,
            "bootloader-reboot-returned"
        )
    ) {
        return "BOOTLOADER REBOOT RETURNED";
    }

    return "UNMAPPED FAILURE REASON";
}

static void pp_render_transition_failure(
    const char *reason
) {
    const char *display_reason = (
        pp_transition_failure_display_reason(
            reason
        )
    );

    /*
     * Console/TTY path remains useful even if KMS setup fails.
     */
    pp_output(
        "\033[2J\033[H"
        "TreeForge Bootstrap Boot Failure\n\n"
        "reason="
    );

    pp_output(
        reason
        ? reason
        : "unknown"
    );

    if (
        reason
        && pp_string_equal(
            reason,
            "pixel-partitioner-runtime-materialize"
        )
    ) {
        pp_output(
            "\nstage="
        );

        pp_output(
            pp_runtime_materialize_failure_stage
        );

        pp_output(
            "\nerror="
        );

        pp_output(
            pp_copy_fd_failure_code_name(
                pp_copy_fd_failure_code
            )
        );

        pp_output(
            "\nsource="
        );

        pp_output(
            pp_runtime_materialize_failure_source_path
            ? pp_runtime_materialize_failure_source_path
            : "unknown"
        );

        pp_output(
            "\ndestination="
        );

        pp_output(
            pp_runtime_materialize_failure_path
            ? pp_runtime_materialize_failure_path
            : "unknown"
        );

        pp_output(
            "\n"
        );
    }

    pp_output(
        "\n"
        "HALTED FOR DIAGNOSTICS\n"
        "FORCE REBOOT WHEN DONE\n"
    );

    if (
        !pp_fb_menu_active
        || pp_fb_menu_mapped_address < 0
    ) {
        return;
    }

    const u32 background = 0x00000000U;
    const u32 foreground = 0x00ffffffU;

    pp_fb_fill_rect(
        0,
        0,
        pp_fb_menu_width,
        pp_fb_menu_height,
        background
    );

    u32 scale = (
        pp_fb_menu_width
        / 160U
    );

    u32 height_scale = (
        pp_fb_menu_height
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

    pp_fb_draw_management_line(
        "TREEFORGE MENU",
        18U * scale,
        scale,
        foreground
    );

    pp_fb_draw_management_line(
        "BOOT FAILURE",
        46U * scale,
        scale,
        foreground
    );

    pp_fb_draw_management_line(
        "REASON",
        76U * scale,
        scale,
        foreground
    );

    pp_fb_draw_management_line(
        display_reason,
        94U * scale,
        scale,
        foreground
    );

    if (
        reason
        && pp_string_equal(
            reason,
            "pixel-partitioner-runtime-materialize"
        )
    ) {
        pp_fb_draw_management_line(
            pp_runtime_materialize_failure_stage,
            112U * scale,
            scale,
            foreground
        );

        pp_fb_draw_management_line(
            pp_copy_fd_failure_code_name(
                pp_copy_fd_failure_code
            ),
            128U * scale,
            scale,
            foreground
        );

        pp_fb_draw_management_line(
            pp_runtime_materialize_failure_source_path
            ? pp_runtime_materialize_failure_source_path
            : "UNKNOWN SOURCE",
            146U * scale,
            scale,
            foreground
        );

        pp_fb_draw_management_line(
            pp_runtime_materialize_failure_path
            ? pp_runtime_materialize_failure_path
            : "UNKNOWN DESTINATION",
            164U * scale,
            scale,
            foreground
        );
    }

    pp_fb_draw_management_line(
        "HALTED FOR DIAGNOSTICS",
        188U * scale,
        scale,
        foreground
    );

    pp_fb_draw_management_line(
        "FORCE REBOOT WHEN DONE",
        204U * scale,
        scale,
        foreground
    );
}


__attribute__((noreturn))
static void pp_transition_failure(
    const char *reason
) {
    /*
     * execve() failure may occur after the ordinary TreeForge Bootstrap kmsg
     * descriptor was deliberately closed for Android handoff.
     * Reopen /dev/kmsg best-effort on the failure-only path so the
     * diagnostic descriptor can never leak into successful Android.
     */
    long failure_kmsg = pp_kmsg;
    int close_failure_kmsg = 0;

    if (failure_kmsg < 0) {
        failure_kmsg = pp_open(
            "/dev/kmsg",
            O_WRONLY
            | O_NONBLOCK
        );

        if (failure_kmsg >= 0) {
            close_failure_kmsg = 1;
        }
    }

    pp_write_all(
        failure_kmsg,
        "TreeForge Bootstrap: transition-failure reason="
    );

    pp_write_all(
        failure_kmsg,
        (
            reason
            ? reason
            : "unknown"
        )
    );

    pp_write_all(
        failure_kmsg,
        "\n"
    );

    if (close_failure_kmsg) {
        pp_close(
            failure_kmsg
        );
    }

    pp_record_transition_failure(
        reason
    );


    if (!pp_fb_menu_active) {
        pp_probe_display_surfaces();
    }

    pp_render_transition_failure(
        reason
    );

    for (;;) {
        pp_sleep_ms(
            1000
        );
    }
}


static void pp_prepare_shell_compat(void) {
    const char *busybox =
        "/dev/pixel-partitioner-runtime/system/bin/busybox";

    if (
        !pp_probe_readable_path(
            busybox
        )
    ) {
        pp_log(
            "pixel-partitioner-shell=busybox-missing"
        );

        return;
    }

    pp_syscall3(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long) "/bin",
        0755
    );

    pp_syscall3(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long) "/system",
        0755
    );

    pp_syscall3(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long) "/system/bin",
        0755
    );

    pp_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long) "/bin/sh",
        0
    );

    pp_syscall3(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long) "/system/bin/sh",
        0
    );

    long bin_shell = pp_syscall3(
        SYS_SYMLINKAT,
        (long) busybox,
        AT_FDCWD,
        (long) "/bin/sh"
    );

    long system_shell = pp_syscall3(
        SYS_SYMLINKAT,
        (long) busybox,
        AT_FDCWD,
        (long) "/system/bin/sh"
    );

    if (
        bin_shell >= 0
        && system_shell >= 0
        && pp_probe_readable_path(
            "/bin/sh"
        )
        && pp_probe_readable_path(
            "/system/bin/sh"
        )
    ) {
        pp_log(
            "pixel-partitioner-shell=ready"
        );
    } else {
        pp_log(
            "pixel-partitioner-shell=compat-failed"
        );
    }
}


static void pp_start_adb_service(
    char **envp
) {
    long child = pp_syscall6(
        SYS_CLONE,
        PIXEL_PARTITIONER_SIGCHLD,
        0,
        0,
        0,
        0,
        0
    );

    if (child < 0) {
        pp_transition_failure(
            "pixel-partitioner-adb-service-clone"
        );
    }

    if (child == 0) {
        char *argv[] = {
            (char *)
                "/dev/pixel-partitioner-runtime/"
                "pixel-partitioner-adb-service",
            0
        };

        pp_close(
            pp_tty
        );

        pp_close(
            pp_console
        );

        pp_close(
            pp_kmsg
        );

        pp_syscall3(
            SYS_EXECVE,
            (long)
                "/dev/pixel-partitioner-runtime/"
                "pixel-partitioner-adb-service",
            (long) argv,
            (long) envp
        );

        pp_syscall1(
            SYS_EXIT,
            127
        );

        for (;;) {
        }
    }

    pp_log(
        "pixel-partitioner-adb-service=started"
    );
}


__attribute__((noreturn))
static void pp_run_menu(void) {
    int created_input_directory = 0;

    int created_input_nodes[
        INPUT_COUNT
    ];

    int sysfs_devices_seen = 0;

    pp_realize_input_nodes(
        &created_input_directory,
        created_input_nodes,
        &sysfs_devices_seen
    );

    long inputs[
        INPUT_COUNT
    ];

    for (
        int index = 0;
        index < INPUT_COUNT;
        index++
    ) {
        inputs[index] = -1;
    }

    long marker = pp_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long)
            "/dev/pixel-partitioner-early-menu",
        O_WRONLY
        | O_CREAT
        | O_TRUNC,
        0644
    );

    if (marker >= 0) {
        pp_write_all(
            marker,
            "pixel-partitioner-early-menu-v1\n"
        );

        pp_close(
            marker
        );
    }

    pp_probe_display_surfaces();

    if (sysfs_devices_seen > 0) {
        pp_log(
            "early-menu input-sysfs=present"
        );
    } else {
        pp_log(
            "early-menu input-sysfs=absent"
        );
    }

    for (
        int index = 0;
        index < INPUT_COUNT;
        index++
    ) {
        char event_path[32];

        pp_event_path(
            index,
            event_path
        );

        inputs[index] = pp_open(
            event_path,
            O_RDONLY
            | O_NONBLOCK
        );

        if (inputs[index] < 0) {
            continue;
        }

        for (;;) {
            struct pp_input_event event;

            long amount = pp_syscall3(
                SYS_READ,
                inputs[index],
                (long) &event,
                (long) sizeof(event)
            );

            if (
                amount
                != (long) sizeof(event)
            ) {
                break;
            }
        }
    }

    int selected = 0;

    pp_log(
        "early-menu begin"
    );

    pp_render(
        selected
    );

    for (;;) {
        for (
            int index = 0;
            index < INPUT_COUNT;
            index++
        ) {
            if (inputs[index] < 0) {
                char event_path[32];

                pp_event_path(
                    index,
                    event_path
                );

                inputs[index] = pp_open(
                    event_path,
                    O_RDONLY
                    | O_NONBLOCK
                );

                if (inputs[index] >= 0) {
                    for (;;) {
                        struct pp_input_event event;

                        long amount = pp_syscall3(
                            SYS_READ,
                            inputs[index],
                            (long) &event,
                            (long) sizeof(event)
                        );

                        if (
                            amount
                            != (long) sizeof(event)
                        ) {
                            break;
                        }
                    }

                    continue;
                }
            }

            if (inputs[index] < 0) {
                continue;
            }

            for (;;) {
                struct pp_input_event event;

                long amount = pp_syscall3(
                    SYS_READ,
                    inputs[index],
                    (long) &event,
                    (long) sizeof(event)
                );

                if (
                    amount
                    != (long) sizeof(event)
                ) {
                    if (
                        amount < 0
                        && amount != -11
                    ) {
                        pp_close(
                            inputs[index]
                        );

                        inputs[index] = -1;
                    }

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
                    pp_log(
                        "early-menu key=volume_up"
                    );

                    selected = 0;

                    pp_render(
                        selected
                    );

                    continue;
                }

                if (
                    event.code
                    == KEY_VOLUMEDOWN
                ) {
                    pp_log(
                        "early-menu key=volume_down"
                    );

                    selected = 0;

                    pp_render(
                        selected
                    );

                    continue;
                }

                if (
                    event.code
                    != KEY_POWER
                ) {
                    continue;
                }

                pp_log(
                    "early-menu key=power"
                );

                pp_log(
                    "early-menu action=bootloader"
                );

                /*
                 * Reboot is the only current standalone action.
                 * Do not seal the framebuffer bridge here.
                 */
                pp_fb_menu_cleanup();

                pp_close_inputs(
                    inputs
                );

                pp_cleanup_realized_input_nodes(
                    created_input_directory,
                    created_input_nodes
                );

                pp_close(
                    pp_tty
                );
                pp_tty = -1;

                pp_close(
                    pp_console
                );
                pp_console = -1;

                pp_close(
                    pp_kmsg
                );
                pp_kmsg = -1;

                pp_reboot_to(
                    "bootloader"
                );

                pp_transition_failure(
                    "bootloader-reboot-returned"
                );
            }
        }

        pp_sleep_ms(
            POLL_INTERVAL_MS
        );
    }
}


__attribute__((noreturn))
static void pp_main(
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
            || !pp_string_equal(
                argv[1],
                "selinux_setup"
            )
        ) {
            pp_transition_failure(
                "invalid-pixel-partitioner-reentry"
            );
        }

        pp_kmsg = pp_open(
            "/dev/kmsg",
            O_WRONLY
            | O_NONBLOCK
        );

        pp_tty = pp_open(
            "/dev/tty0",
            O_WRONLY
            | O_NONBLOCK
        );

        pp_console = pp_open(
            "/dev/console",
            O_WRONLY
            | O_NONBLOCK
        );

        if (
            !pp_materialize_runtime_bundle()
        ) {
            pp_transition_failure(
                "pixel-partitioner-runtime-materialize"
            );
        }

        pp_log(
            "pixel-partitioner-runtime=materialized"
        );

        /*
         * The complete retained runtime now exists under /dev.
         * The inherited dispatcher FD is no longer needed.
         */
        pp_close(
            PIXEL_PARTITIONER_TRANSITION_FD
        );

        pp_prepare_shell_compat();

        pp_start_adb_service(
            envp
        );

        pp_run_menu();
    }

    /*
     * Initial invocation from the kernel.
     *
     * FD99 is the only retained descriptor. It carries this dispatcher
     * and the appended TreeForge Bootstrap runtime bundle through Google's
     * currently proven FirstStageMain boundary.
     */
    long self_fd = pp_open(
        "/init",
        O_RDONLY
    );

    if (self_fd < 0) {
        pp_transition_failure(
            "transition-fd-open"
        );
    }

    if (
        self_fd
        != PIXEL_PARTITIONER_TRANSITION_FD
    ) {
        long duplicated = pp_syscall3(
            SYS_DUP3,
            self_fd,
            PIXEL_PARTITIONER_TRANSITION_FD,
            0
        );

        if (duplicated < 0) {
            pp_close(
                self_fd
            );

            pp_transition_failure(
                "transition-fd-duplicate"
            );
        }

        pp_close(
            self_fd
        );
    }

    char *first_stage_argv[] = {
        (char *) "/init",
        0
    };

    pp_syscall3(
        SYS_EXECVE,
        (long)
            "/init.pixel-partitioner-first-stage",
        (long) first_stage_argv,
        (long) envp
    );

    pp_transition_failure(
        "first-stage-exec"
    );
}

__attribute__((used, noreturn))
static void pp_entry(
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

    pp_main(
        argc,
        argv,
        envp
    );
}

__attribute__((naked, noreturn))
void _start(void) {
    __asm__ volatile(
        "mov x0, sp\n"
        "b pp_entry\n"
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
            / "pixel-partitioner-dispatch.c"
        )

        executable_path = (
            output_root
            / "pixel-partitioner-dispatch"
        )

        placeholder = (
            "__PIXEL_PARTITIONER_VERSION__"
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

        generated_source = (
            cls._SOURCE.replace(
                placeholder,
                cls._project_version(),
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
                "unable to build Pixel "
                "Partitioner dispatcher:\n"
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
