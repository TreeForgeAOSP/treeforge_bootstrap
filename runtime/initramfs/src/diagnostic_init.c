/*
 * TreeForge Bootstrap permanent diagnostic PID 1.
 *
 * Bootstrap v1.0b3 diagnostic target.
 *
 * Freestanding AArch64 userspace:
 *   - no libc
 *   - no Android framework
 *   - no treeforge_os dependency
 *   - retained Bootstrap ADB remains independent
 *   - framebuffer transport is inherited from the already-open
 *     TreeForge kernel framebuffer bridge
 */

typedef unsigned long usize;
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;

#define SYS_OPENAT 56
#define SYS_CLOSE 57
#define SYS_READ 63
#define SYS_WRITE 64
#define SYS_NANOSLEEP 101
#define SYS_MUNMAP 215
#define SYS_MMAP 222

#define AT_FDCWD (-100)

#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1

#define TF_FB_ABI_VERSION 1U

#define TF_FB_FLAG_LINEAR \
    (1U << 0)

#define TF_FB_FLAG_WRITE_COMBINE \
    (1U << 1)

#define TF_FB_REQUIRED_FLAGS \
    ( \
        TF_FB_FLAG_LINEAR \
        | TF_FB_FLAG_WRITE_COMBINE \
    )

struct tf_timespec {
    long tv_sec;
    long tv_nsec;
};

struct tf_fb_info {
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

typedef char tf_fb_info_size_check[
    sizeof(struct tf_fb_info) == 64
    ? 1
    : -1
];


static long tf_syscall1(
    long number,
    long arg0
) {
    register long x0 __asm__("x0") =
        arg0;

    register long x8 __asm__("x8") =
        number;

    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x8)
        : "memory"
    );

    return x0;
}


static long tf_syscall2(
    long number,
    long arg0,
    long arg1
) {
    register long x0 __asm__("x0") =
        arg0;

    register long x1 __asm__("x1") =
        arg1;

    register long x8 __asm__("x8") =
        number;

    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1),
          "r"(x8)
        : "memory"
    );

    return x0;
}


static long tf_syscall3(
    long number,
    long arg0,
    long arg1,
    long arg2
) {
    register long x0 __asm__("x0") =
        arg0;

    register long x1 __asm__("x1") =
        arg1;

    register long x2 __asm__("x2") =
        arg2;

    register long x8 __asm__("x8") =
        number;

    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1),
          "r"(x2),
          "r"(x8)
        : "memory"
    );

    return x0;
}


static long tf_syscall4(
    long number,
    long arg0,
    long arg1,
    long arg2,
    long arg3
) {
    register long x0 __asm__("x0") =
        arg0;

    register long x1 __asm__("x1") =
        arg1;

    register long x2 __asm__("x2") =
        arg2;

    register long x3 __asm__("x3") =
        arg3;

    register long x8 __asm__("x8") =
        number;

    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1),
          "r"(x2),
          "r"(x3),
          "r"(x8)
        : "memory"
    );

    return x0;
}


static long tf_syscall6(
    long number,
    long arg0,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5
) {
    register long x0 __asm__("x0") =
        arg0;

    register long x1 __asm__("x1") =
        arg1;

    register long x2 __asm__("x2") =
        arg2;

    register long x3 __asm__("x3") =
        arg3;

    register long x4 __asm__("x4") =
        arg4;

    register long x5 __asm__("x5") =
        arg5;

    register long x8 __asm__("x8") =
        number;

    __asm__ volatile(
        "svc #0"
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


static usize tf_strlen(
    const char *value
) {
    usize length = 0;

    while (value[length]) {
        length++;
    }

    return length;
}


static void tf_write_all(
    long fd,
    const char *value
) {
    usize length =
        tf_strlen(value);

    usize offset = 0;

    while (offset < length) {
        long amount = tf_syscall3(
            SYS_WRITE,
            fd,
            (long) (
                value + offset
            ),
            (long) (
                length - offset
            )
        );

        if (amount <= 0) {
            return;
        }

        offset +=
            (usize) amount;
    }
}


static void tf_kmsg(
    const char *value
) {
    long fd = tf_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long) "/dev/kmsg",
        O_WRONLY,
        0
    );

    if (fd < 0) {
        return;
    }

    tf_write_all(
        fd,
        value
    );

    tf_syscall1(
        SYS_CLOSE,
        fd
    );
}


static int tf_read_exact(
    long fd,
    void *buffer,
    usize length
) {
    usize offset = 0;

    while (offset < length) {
        long amount = tf_syscall3(
            SYS_READ,
            fd,
            (long) (
                (u8 *) buffer
                + offset
            ),
            (long) (
                length
                - offset
            )
        );

        if (amount <= 0) {
            return 0;
        }

        offset +=
            (usize) amount;
    }

    return 1;
}


static void tf_publish_ready(
    void
) {
    long fd = tf_syscall4(
        SYS_OPENAT,
        AT_FDCWD,
        (long)
            "/TREEFORGE_DIAGNOSTIC_PID1_OK",
        (
            O_WRONLY
            | O_CREAT
            | O_TRUNC
        ),
        0644
    );

    if (fd < 0) {
        tf_kmsg(
            "TREEFORGE_DIAGNOSTIC_"
            "READY_FILE_FAILED=1\n"
        );

        return;
    }

    tf_write_all(
        fd,
        "TREEFORGE_DIAGNOSTIC_PID1_READY=1\n"
        "PID=1\n"
        "INIT=/init\n"
        "ROOT=tmpfs\n"
        "DISPLAY=treeforge_bootstrap_fb\n"
    );

    tf_syscall1(
        SYS_CLOSE,
        fd
    );
}


static int tf_validate_fb_info(
    const struct tf_fb_info *info
) {
    if (
        info->abi_version
        != TF_FB_ABI_VERSION
    ) {
        return 0;
    }

    if (
        info->bytes_per_pixel
        != 4U
    ) {
        return 0;
    }

    if (
        info->flags
        != TF_FB_REQUIRED_FLAGS
    ) {
        return 0;
    }

    if (
        info->width == 0U
        || info->height == 0U
        || info->width > 8192U
        || info->height > 8192U
    ) {
        return 0;
    }

    if (
        info->source_x != 0U
        || info->source_y != 0U
        || info->source_width
            != info->width
        || info->source_height
            != info->height
    ) {
        return 0;
    }

    if (
        info->stride
        < info->width * 4U
    ) {
        return 0;
    }

    if (
        info->framebuffer_bytes
        != (
            (u64) info->stride
            * (u64) info->source_height
        )
    ) {
        return 0;
    }

    if (
        info->mmap_bytes
            < info->framebuffer_bytes
        || info->mmap_bytes == 0U
    ) {
        return 0;
    }

    return 1;
}


struct tf_canvas {
    volatile u8 *base;

    u32 raw_width;
    u32 raw_height;
    u32 pitch;

    u32 logical_width;
    u32 logical_height;

    int landscape;
};


static void tf_raw_pixel(
    struct tf_canvas *canvas,
    u32 x,
    u32 y,
    u32 color
) {
    if (
        x >= canvas->raw_width
        || y >= canvas->raw_height
    ) {
        return;
    }

    volatile u32 *pixel = (
        (volatile u32 *) (
            canvas->base
            + (
                (usize) y
                * canvas->pitch
            )
            + (
                (usize) x
                * 4U
            )
        )
    );

    *pixel =
        color;
}


static void tf_pixel(
    struct tf_canvas *canvas,
    u32 x,
    u32 y,
    u32 color
) {
    if (
        x >= canvas->logical_width
        || y >= canvas->logical_height
    ) {
        return;
    }

    if (!canvas->landscape) {
        tf_raw_pixel(
            canvas,
            x,
            y,
            color
        );

        return;
    }

    /*
     * Same logical camera-top landscape orientation used by the
     * TreeForge Boot Manager.
     */
    u32 raw_x =
        y;

    u32 raw_y = (
        canvas->raw_height
        - 1U
        - x
    );

    tf_raw_pixel(
        canvas,
        raw_x,
        raw_y,
        color
    );
}


static void tf_fill_rect(
    struct tf_canvas *canvas,
    u32 x,
    u32 y,
    u32 width,
    u32 height,
    u32 color
) {
    if (
        x >= canvas->logical_width
        || y >= canvas->logical_height
    ) {
        return;
    }

    if (
        width
        > canvas->logical_width - x
    ) {
        width =
            canvas->logical_width - x;
    }

    if (
        height
        > canvas->logical_height - y
    ) {
        height =
            canvas->logical_height - y;
    }

    for (
        u32 row = 0;
        row < height;
        row++
    ) {
        for (
            u32 column = 0;
            column < width;
            column++
        ) {
            tf_pixel(
                canvas,
                x + column,
                y + row,
                color
            );
        }
    }
}


static u8 tf_glyph_row(
    char character,
    u32 row
) {
    if (row >= 7U) {
        return 0U;
    }

#define TF_GLYPH(a,b,c,d,e,f,g) \
    do { \
        static const u8 rows[7] = { \
            a,b,c,d,e,f,g \
        }; \
        return rows[row]; \
    } while (0)

    switch (character) {
        case 'A':
            TF_GLYPH(
                14,17,17,31,17,17,17
            );

        case 'B':
            TF_GLYPH(
                30,17,17,30,17,17,30
            );

        case 'C':
            TF_GLYPH(
                14,17,16,16,16,17,14
            );

        case 'D':
            TF_GLYPH(
                30,17,17,17,17,17,30
            );

        case 'E':
            TF_GLYPH(
                31,16,16,30,16,16,31
            );

        case 'F':
            TF_GLYPH(
                31,16,16,30,16,16,16
            );

        case 'G':
            TF_GLYPH(
                14,17,16,23,17,17,15
            );

        case 'H':
            TF_GLYPH(
                17,17,17,31,17,17,17
            );

        case 'I':
            TF_GLYPH(
                31,4,4,4,4,4,31
            );

        case 'J':
            TF_GLYPH(
                7,2,2,2,18,18,12
            );

        case 'K':
            TF_GLYPH(
                17,18,20,24,20,18,17
            );

        case 'L':
            TF_GLYPH(
                16,16,16,16,16,16,31
            );

        case 'M':
            TF_GLYPH(
                17,27,21,21,17,17,17
            );

        case 'N':
            TF_GLYPH(
                17,25,21,19,17,17,17
            );

        case 'O':
            TF_GLYPH(
                14,17,17,17,17,17,14
            );

        case 'P':
            TF_GLYPH(
                30,17,17,30,16,16,16
            );

        case 'Q':
            TF_GLYPH(
                14,17,17,17,21,18,13
            );

        case 'R':
            TF_GLYPH(
                30,17,17,30,20,18,17
            );

        case 'S':
            TF_GLYPH(
                15,16,16,14,1,1,30
            );

        case 'T':
            TF_GLYPH(
                31,4,4,4,4,4,4
            );

        case 'U':
            TF_GLYPH(
                17,17,17,17,17,17,14
            );

        case 'V':
            TF_GLYPH(
                17,17,17,17,17,10,4
            );

        case 'W':
            TF_GLYPH(
                17,17,17,21,21,21,10
            );

        case 'X':
            TF_GLYPH(
                17,17,10,4,10,17,17
            );

        case 'Y':
            TF_GLYPH(
                17,17,10,4,4,4,4
            );

        case 'Z':
            TF_GLYPH(
                31,1,2,4,8,16,31
            );

        case '0':
            TF_GLYPH(
                14,17,19,21,25,17,14
            );

        case '1':
            TF_GLYPH(
                4,12,4,4,4,4,14
            );

        case '2':
            TF_GLYPH(
                14,17,1,2,4,8,31
            );

        case '3':
            TF_GLYPH(
                30,1,1,14,1,1,30
            );

        case '4':
            TF_GLYPH(
                2,6,10,18,31,2,2
            );

        case '5':
            TF_GLYPH(
                31,16,16,30,1,1,30
            );

        case '6':
            TF_GLYPH(
                14,16,16,30,17,17,14
            );

        case '7':
            TF_GLYPH(
                31,1,2,4,8,8,8
            );

        case '8':
            TF_GLYPH(
                14,17,17,14,17,17,14
            );

        case '9':
            TF_GLYPH(
                14,17,17,15,1,1,14
            );

        case ':':
            TF_GLYPH(
                0,4,4,0,4,4,0
            );

        case '-':
            TF_GLYPH(
                0,0,0,31,0,0,0
            );

        case '/':
            TF_GLYPH(
                1,2,2,4,8,8,16
            );

        case '.':
            TF_GLYPH(
                0,0,0,0,0,6,6
            );

        default:
            return 0U;
    }

#undef TF_GLYPH
}


static void tf_draw_char(
    struct tf_canvas *canvas,
    u32 x,
    u32 y,
    char character,
    u32 scale,
    u32 color
) {
    for (
        u32 row = 0;
        row < 7U;
        row++
    ) {
        u8 bits =
            tf_glyph_row(
                character,
                row
            );

        for (
            u32 column = 0;
            column < 5U;
            column++
        ) {
            if (
                bits
                & (
                    1U
                    << (
                        4U - column
                    )
                )
            ) {
                tf_fill_rect(
                    canvas,
                    x + column * scale,
                    y + row * scale,
                    scale,
                    scale,
                    color
                );
            }
        }
    }
}


static void tf_draw_text(
    struct tf_canvas *canvas,
    u32 x,
    u32 y,
    const char *value,
    u32 scale,
    u32 color
) {
    u32 cursor =
        x;

    while (*value) {
        tf_draw_char(
            canvas,
            cursor,
            y,
            *value,
            scale,
            color
        );

        cursor +=
            6U * scale;

        value++;
    }
}


static void tf_u32_decimal(
    u32 value,
    char *output
) {
    char temporary[11];

    u32 count = 0;

    if (value == 0U) {
        output[0] = '0';
        output[1] = '\0';
        return;
    }

    while (
        value != 0U
        && count < 10U
    ) {
        temporary[count++] = (
            (char) (
                '0'
                + (
                    value
                    % 10U
                )
            )
        );

        value /= 10U;
    }

    for (
        u32 index = 0;
        index < count;
        index++
    ) {
        output[index] = (
            temporary[
                count
                - 1U
                - index
            ]
        );
    }

    output[count] =
        '\0';
}


static void tf_render_static(
    struct tf_canvas *canvas
) {
    const u32 background =
        0x00000000U;

    const u32 foreground =
        0x00e8eef2U;

    const u32 accent =
        0x0000d4eeU;

    const u32 green =
        0x004ed87dU;

    tf_fill_rect(
        canvas,
        0,
        0,
        canvas->logical_width,
        canvas->logical_height,
        background
    );

    tf_draw_text(
        canvas,
        120,
        120,
        "TREEFORGE DIAGNOSTIC",
        7,
        accent
    );

    tf_draw_text(
        canvas,
        120,
        230,
        "BOOTSTRAP B3 CANARY",
        4,
        foreground
    );

    tf_draw_text(
        canvas,
        120,
        390,
        "PID 1 ACTIVE",
        4,
        green
    );

    tf_draw_text(
        canvas,
        120,
        470,
        "ROOT TMPFS",
        4,
        foreground
    );

    tf_draw_text(
        canvas,
        120,
        550,
        "ADB HANDOFF RETAINED",
        4,
        foreground
    );

    tf_draw_text(
        canvas,
        120,
        630,
        "DISPLAY FRAMEBUFFER BRIDGE",
        4,
        foreground
    );

    tf_draw_text(
        canvas,
        120,
        710,
        "ALT OS STORAGE SEPARATE",
        4,
        foreground
    );

    tf_draw_text(
        canvas,
        120,
        870,
        "HEARTBEAT",
        4,
        foreground
    );
}


static int tf_begin_display(
    struct tf_canvas *canvas
) {
    int framebuffer_fd =
        -1;

    long metadata_fd =
        tf_syscall4(
            SYS_OPENAT,
            AT_FDCWD,
            (long)
                "/dev/"
                "treeforge-bootstrap-"
                "diagnostic-fb-fd",
            O_RDONLY,
            0
        );

    if (
        metadata_fd < 0
        || !tf_read_exact(
            metadata_fd,
            &framebuffer_fd,
            sizeof(
                framebuffer_fd
            )
        )
    ) {
        if (metadata_fd >= 0) {
            tf_syscall1(
                SYS_CLOSE,
                metadata_fd
            );
        }

        tf_kmsg(
            "TREEFORGE_DIAGNOSTIC_"
            "FB_FD_FAILED=1\n"
        );

        return 0;
    }

    tf_syscall1(
        SYS_CLOSE,
        metadata_fd
    );

    if (framebuffer_fd < 0) {
        tf_kmsg(
            "TREEFORGE_DIAGNOSTIC_"
            "FB_FD_INVALID=1\n"
        );

        return 0;
    }

    struct tf_fb_info info;

    if (
        !tf_read_exact(
            framebuffer_fd,
            &info,
            sizeof(info)
        )
    ) {
        tf_kmsg(
            "TREEFORGE_DIAGNOSTIC_"
            "FB_INFO_FAILED=1\n"
        );

        return 0;
    }

    if (
        !tf_validate_fb_info(
            &info
        )
    ) {
        tf_kmsg(
            "TREEFORGE_DIAGNOSTIC_"
            "FB_INFO_INVALID=1\n"
        );

        return 0;
    }

    long mapped =
        tf_syscall6(
            SYS_MMAP,
            0,
            (long)
                info.mmap_bytes,
            PROT_READ
                | PROT_WRITE,
            MAP_SHARED,
            framebuffer_fd,
            0
        );

    if (mapped < 0) {
        tf_kmsg(
            "TREEFORGE_DIAGNOSTIC_"
            "FB_MMAP_FAILED=1\n"
        );

        return 0;
    }

    canvas->base = (
        (volatile u8 *)
        (usize) mapped
    );

    canvas->raw_width =
        info.width;

    canvas->raw_height =
        info.height;

    canvas->pitch =
        info.stride;

    canvas->landscape = (
        info.height > info.width
        ? 1
        : 0
    );

    canvas->logical_width = (
        canvas->landscape
        ? info.height
        : info.width
    );

    canvas->logical_height = (
        canvas->landscape
        ? info.width
        : info.height
    );

    tf_kmsg(
        "TREEFORGE_DIAGNOSTIC_"
        "FB_ACTIVE=1\n"
    );

    return 1;
}


__attribute__((noreturn))
void _start(
    void
) {
    tf_kmsg(
        "TREEFORGE_DIAGNOSTIC_INIT_ENTERED=1\n"
        "TREEFORGE_DIAGNOSTIC_NATIVE_PID1_V1=1\n"
    );

    tf_publish_ready();

    struct tf_canvas canvas;

    int display_ready =
        tf_begin_display(
            &canvas
        );

    if (display_ready) {
        tf_render_static(
            &canvas
        );
    }

    u32 heartbeat = 0;

    struct tf_timespec pause = {
        .tv_sec = 1,
        .tv_nsec = 0,
    };

    for (;;) {
        if (display_ready) {
            const u32 background =
                0x00000000U;

            const u32 green =
                0x004ed87dU;

            const u32 dim =
                0x006b7780U;

            char number[11];

            tf_u32_decimal(
                heartbeat,
                number
            );

            tf_fill_rect(
                &canvas,
                520,
                850,
                760,
                120,
                background
            );

            tf_draw_text(
                &canvas,
                520,
                870,
                number,
                4,
                green
            );

            tf_fill_rect(
                &canvas,
                1320,
                860,
                64,
                64,
                (
                    heartbeat & 1U
                    ? green
                    : dim
                )
            );
        }

        heartbeat++;

        tf_syscall2(
            SYS_NANOSLEEP,
            (long) &pause,
            0
        );
    }
}
