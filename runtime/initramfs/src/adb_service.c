typedef unsigned long usize;
typedef long i64;

/*
 * ================================================================
 * TFB_FREESTANDING_MEMORY_ABI_V1
 *
 * This PID1 is linked with -nostdlib.
 *
 * Clang is allowed to lower ordinary C aggregate copies to the
 * conventional memcpy/memset/memmove ABI even when the source itself
 * never calls libc.
 *
 * Keep these implementations deliberately primitive and volatile so
 * the optimizer cannot turn their loops back into calls to themselves.
 * ================================================================
 */

__attribute__((used, noinline))
void *memcpy(
    void *destination,
    const void *source,
    unsigned long count
) {
    volatile unsigned char *dst =
        (volatile unsigned char *)destination;

    const volatile unsigned char *src =
        (const volatile unsigned char *)source;

    for (
        unsigned long index = 0;
        index < count;
        ++index
    ) {
        dst[index] = src[index];
    }

    return destination;
}


/*
 * ============================================================
 * TFB_ONEPASS_RUNTIME_V1
 * Native tangorpro bring-up runtime ABI
 * ============================================================
 */

#ifndef SYS_UMOUNT2
#define SYS_UMOUNT2 39
#endif

#ifndef SYS_FACCESSAT
#define SYS_FACCESSAT 48
#endif

#ifndef SYS_SYNC
#define SYS_SYNC 81
#endif

#ifndef SYS_KILL
#define SYS_KILL 129
#endif

#ifndef SYS_REBOOT
#define SYS_REBOOT 142
#endif

#ifndef SYS_CLONE
#define SYS_CLONE 220
#endif

#ifndef SYS_WAIT4
#define SYS_WAIT4 260
#endif

#ifndef SYS_SYMLINKAT
#define SYS_SYMLINKAT 36
#endif

#ifndef SYS_UNLINKAT
#define SYS_UNLINKAT 35
#endif

#ifndef O_NONBLOCK
#define O_NONBLOCK 04000
#endif

#define TFB_SIGCHLD 17
#define TFB_WAIT_WNOHANG 1

#define TFB_SIGTERM 15
#define TFB_SIGKILL 9

#define TFB_MNT_DETACH 2

#define TFB_EV_KEY 1
#define TFB_KEY_VOLUMEDOWN 114
#define TFB_KEY_VOLUMEUP 115
#define TFB_KEY_POWER 116

#define TFB_INPUT_COUNT 32

#define TFB_REBOOT_MAGIC1 0xfee1deadUL
#define TFB_REBOOT_MAGIC2 672274793UL
#define TFB_REBOOT_CMD_RESTART2 0xA1B2C3D4UL



#define SYS_DUP3 24
#define SYS_MOUNT 40
#define SYS_OPENAT 56
#define SYS_CLOSE 57
#define SYS_GETDENTS64 61
#define SYS_READ 63
#define SYS_WRITE 64
#define SYS_NANOSLEEP 101
#define SYS_EXECVE 221
#define SYS_FINIT_MODULE 273

#ifndef SYS_MKNODAT
#define SYS_MKNODAT 33
#endif

#ifndef SYS_MKDIRAT
#define SYS_MKDIRAT 34
#endif

#ifndef TFB_S_IFCHR
#define TFB_S_IFCHR 0020000
#endif

#ifndef SYS_UNLINKAT
#define SYS_UNLINKAT 35
#endif

#ifndef SYS_SYMLINKAT
#define SYS_SYMLINKAT 36
#endif

#ifndef SYS_EXIT
#define SYS_EXIT 93
#endif

#ifndef SYS_CLONE
#define SYS_CLONE 220
#endif

#define TFB_SIGCHLD 17


#define AT_FDCWD -100
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2



struct timespec {
    i64 tv_sec;
    i64 tv_nsec;
};


struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};


static long sys6(
    long n,
    long a0,
    long a1,
    long a2,
    long a3,
    long a4,
    long a5
) {
    register long x0
        __asm__("x0") = a0;

    register long x1
        __asm__("x1") = a1;

    register long x2
        __asm__("x2") = a2;

    register long x3
        __asm__("x3") = a3;

    register long x4
        __asm__("x4") = a4;

    register long x5
        __asm__("x5") = a5;

    register long x8
        __asm__("x8") = n;

    __asm__ volatile(
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


static usize slen(
    const char *s
) {
    usize n = 0;

    while (s[n]) {
        ++n;
    }

    return n;
}


static void write_text(
    const char *s
) {
    sys6(
        SYS_WRITE,
        1,
        (long)s,
        (long)slen(s),
        0,
        0,
        0
    );
}


static void write_line(
    const char *s
) {
    write_text(s);
    write_text("\n");
}


/*
 * ============================================================
 * TFB_V6B_DEV_RUNTIME
 *
 * This kernel does not provide a usable devtmpfs filesystem.
 *
 * Build the minimal early /dev namespace the same way Android's
 * first-stage environment does conceptually: tmpfs plus explicit
 * essential character devices.
 *
 * Dynamic input/DRM device realization remains a later concern.
 * FunctionFS creates its own endpoint files after it is mounted.
 * ============================================================
 */

static long tfb_v6b_dev_mount_rc = -9999;
static long tfb_v6b_devpts_mount_rc = -9999;


static void setup_console(
    void
) {
    long fd = sys6(
        SYS_OPENAT,
        AT_FDCWD,
        (long)"/dev/console",
        O_RDWR,
        0,
        0,
        0
    );

    if (fd < 0) {
        return;
    }

    if (fd != 0) {
        sys6(
            SYS_DUP3,
            fd,
            0,
            0,
            0,
            0,
            0
        );
    }

    if (fd != 1) {
        sys6(
            SYS_DUP3,
            fd,
            1,
            0,
            0,
            0,
            0
        );
    }

    if (fd != 2) {
        sys6(
            SYS_DUP3,
            fd,
            2,
            0,
            0,
            0,
            0
        );
    }

    if (fd > 2) {
        sys6(
            SYS_CLOSE,
            fd,
            0,
            0,
            0,
            0,
            0
        );
    }
}


static void mount_one(
    const char *source,
    const char *target,
    const char *type
) {
    long rc = sys6(
        SYS_MOUNT,
        (long)source,
        (long)target,
        (long)type,
        0,
        0,
        0
    );

    write_text(
        "mount "
    );

    write_text(
        target
    );

    if (rc == 0) {
        write_line(
            " : OK"
        );
    } else {
        write_line(
            " : WARN"
        );
    }
}


static usize buffer_append_text(
    char *buffer,
    usize capacity,
    usize used,
    const char *text
) {
    usize i = 0;

    while (text[i]) {
        if (used + 1 >= capacity) {
            break;
        }

        buffer[used++] = text[i++];
    }

    buffer[used] = 0;

    return used;
}


static usize buffer_append_long(
    char *buffer,
    usize capacity,
    usize used,
    long value
) {
    char digits[32];
    usize count = 0;
    unsigned long magnitude;

    if (value < 0) {
        if (used + 1 < capacity) {
            buffer[used++] = '-';
        }

        magnitude = (
            (unsigned long)(
                -(value + 1)
            )
            + 1
        );
    } else {
        magnitude = (
            (unsigned long)value
        );
    }

    do {
        digits[count++] = (
            (char)(
                '0'
                + magnitude % 10
            )
        );

        magnitude /= 10;
    } while (
        magnitude
        && count < sizeof(digits)
    );

    while (count > 0) {
        if (used + 1 >= capacity) {
            break;
        }

        buffer[used++] = (
            digits[--count]
        );
    }

    buffer[used] = 0;

    return used;
}


static void persistent_write_path(
    const char *path,
    const char *message
) {
    long fd = sys6(
        SYS_OPENAT,
        AT_FDCWD,
        (long)path,
        O_WRONLY,
        0,
        0,
        0
    );

    if (fd < 0) {
        return;
    }

    sys6(
        SYS_WRITE,
        fd,
        (long)message,
        (long)slen(message),
        0,
        0,
        0
    );

    sys6(
        SYS_WRITE,
        fd,
        (long)"\n",
        1,
        0,
        0,
        0
    );

    sys6(
        SYS_CLOSE,
        fd,
        0,
        0,
        0,
        0,
        0
    );
}


static void persistent_line(
    const char *message
) {
    /*
     * Keep two independent persistent paths.
     *
     * pmsg0 gives us a userspace pmsg record when available.
     * kmsg feeds the printk/console path, which this kernel
     * already persists through console-ramoops.
     */
    persistent_write_path(
        "/dev/pmsg0",
        message
    );

    persistent_write_path(
        "/dev/kmsg",
        message
    );
}


static void persistent_rc(
    const char *prefix,
    long rc
) {
    char buffer[256];
    usize used = 0;

    buffer[0] = 0;

    used = buffer_append_text(
        buffer,
        sizeof(buffer),
        used,
        prefix
    );

    buffer_append_long(
        buffer,
        sizeof(buffer),
        used,
        rc
    );

    persistent_line(
        buffer
    );
}


/*
 * ================================================================
 * TFB_BRINGUP_WATCHDOG_POLICY_V6
 *
 * TFB_EARLY_MODULE_RUNTIME_V6
 *
 * The custom initramfs now carries a curated dependency closure
 * sourced from the frozen tangorpro vendor_dlkm.img.
 *
 * s3c2410_wdt.ko is intentionally allowed.  PID1 realizes it and
 * its modules.dep dependencies synchronously before creating the
 * USB/input module worker.  This directly tests ownership of the
 * inherited GS201 APC/cluster watchdog instead of merely assuming
 * the module exists in early userspace.
 * ================================================================
 */

/*
 * ================================================================
 * TFB_BRINGUP_RUNTIME_V2
 *
 * GS201 module policy:
 *   - dependency aware
 *   - honor modules.blocklist during bulk population
 *   - critical bring-up workers remain independent of bulk loading
 * ================================================================
 */

/*
 * ============================================================
 * TreeForge Bootstrap-native ADB USB bring-up
 * ============================================================
 *
 * This implementation belongs to the TreeForge Bootstrap lab PID1.
 *
 * It does not depend on Android init, Android properties,
 * Recovery, TreeForge Bootstrap, or a pre-existing gadget.
 */

static int tfb_mkdir(
    const char *path,
    long mode
) {
    long rc = sys6(
        SYS_MKDIRAT,
        AT_FDCWD,
        (long)path,
        mode,
        0,
        0,
        0
    );

    /*
     * EEXIST is idempotent success.
     */
    return (
        rc == 0
        || rc == -17
    );
}


static int tfb_mount_fs(
    const char *source,
    const char *target,
    const char *filesystem
) {
    long rc = sys6(
        SYS_MOUNT,
        (long)source,
        (long)target,
        (long)filesystem,
        0,
        0,
        0
    );

    /*
     * EBUSY means it is already mounted.
     */
    return (
        rc == 0
        || rc == -16
    );
}


static int tfb_write_file(
    const char *path,
    const char *value
) {
    long fd = sys6(
        SYS_OPENAT,
        AT_FDCWD,
        (long)path,
        O_WRONLY,
        0,
        0,
        0
    );

    if (fd < 0) {
        persistent_rc(
            "TFB_ADB_WRITE_OPEN rc=",
            fd
        );

        return 0;
    }

    usize total = slen(value);
    usize offset = 0;

    while (offset < total) {
        long written = sys6(
            SYS_WRITE,
            fd,
            (long)(
                value + offset
            ),
            total - offset,
            0,
            0,
            0
        );

        if (written <= 0) {
            persistent_rc(
                "TFB_ADB_WRITE rc=",
                written
            );

            sys6(
                SYS_CLOSE,
                fd,
                0,
                0,
                0,
                0,
                0
            );

            return 0;
        }

        offset += (
            (usize)written
        );
    }

    sys6(
        SYS_CLOSE,
        fd,
        0,
        0,
        0,
        0,
        0
    );

    return 1;
}


static long tfb_adbd_pid = -1;


static int tfb_path_exists(
    const char *path
) {
    long rc = sys6(
        SYS_FACCESSAT,
        AT_FDCWD,
        (long)path,
        0,
        0,
        0,
        0
    );

    return rc == 0;
}


/*
 * TFB_ADB_CHILD_LIVENESS_V19
 *
 * wait4(..., WNOHANG) has three materially different outcomes:
 *
 *   0       child is still running
 *   pid     child exited and was reaped
 *   < 0     wait itself failed
 *
 * V18 treated every non-zero return as child death.  A transient
 * wait4 error could therefore tear down the complete USB gadget even
 * though adbd was still alive.
 *
 * For a negative wait result, probe the PID with kill(pid, 0).
 * ESRCH (-3 from the raw syscall ABI) means the process is gone.
 * Any other result is non-destructive: preserve the running gadget
 * and allow the next supervisor iteration to reassess it.
 */
static int tfb_child_alive(
    long pid
) {
    if (pid <= 0) {
        return 0;
    }

    int status = 0;

    long rc = sys6(
        SYS_WAIT4,
        pid,
        (long)&status,
        TFB_WAIT_WNOHANG,
        0,
        0,
        0
    );

    if (rc == 0) {
        return 1;
    }

    if (rc == pid) {
        return 0;
    }

    persistent_rc(
        "TFB_ADB_CHILD_WAIT4_UNEXPECTED rc=",
        rc
    );

    if (rc < 0) {
        long probe = sys6(
            SYS_KILL,
            pid,
            0,
            0,
            0,
            0,
            0
        );

        persistent_rc(
            "TFB_ADB_CHILD_PID_PROBE rc=",
            probe
        );

        /*
         * Raw Linux syscall ABI:
         *
         *   -ESRCH == -3
         *
         * Only proven process absence is allowed to initiate the
         * destructive runtime-loss recovery path.
         */
        if (probe == -3) {
            return 0;
        }

        persistent_line(
            "TFB_ADB_CHILD_WAIT_ERROR_ASSUME_ALIVE"
        );

        return 1;
    }

    /*
     * wait4(pid, ...) should never return another positive PID.
     * Fail closed with respect to the child, while preserving a
     * marker explaining the anomalous result.
     */
    persistent_line(
        "TFB_ADB_CHILD_WAIT4_UNEXPECTED_POSITIVE"
    );

    return 0;
}


static int tfb_adbd_alive(
    void
) {
    if (!tfb_child_alive(tfb_adbd_pid)) {
        if (tfb_adbd_pid > 0) {
            persistent_rc(
                "TFB_ADB_CHILD_EXIT pid=",
                tfb_adbd_pid
            );
        }

        tfb_adbd_pid = -1;

        return 0;
    }

    return 1;
}


static void tfb_stop_adbd(
    void
) {
    if (tfb_adbd_pid <= 0) {
        return;
    }

    sys6(
        SYS_KILL,
        tfb_adbd_pid,
        TFB_SIGTERM,
        0,
        0,
        0,
        0
    );

    struct timespec pause = {
        .tv_sec = 0,
        .tv_nsec = 25000000
    };

    for (int attempt = 0; attempt < 20; ++attempt) {
        if (!tfb_child_alive(tfb_adbd_pid)) {
            tfb_adbd_pid = -1;
            return;
        }

        sys6(
            SYS_NANOSLEEP,
            (long)&pause,
            0,
            0,
            0,
            0,
            0
        );
    }

    sys6(
        SYS_KILL,
        tfb_adbd_pid,
        TFB_SIGKILL,
        0,
        0,
        0,
        0
    );

    int status = 0;

    sys6(
        SYS_WAIT4,
        tfb_adbd_pid,
        (long)&status,
        TFB_WAIT_WNOHANG,
        0,
        0,
        0
    );

    tfb_adbd_pid = -1;
}


static long tfb_start_adbd(
    void
) {
    persistent_line(
        "TFB_ADB_DAEMON_START"
    );

    long child = sys6(
        SYS_CLONE,
        TFB_SIGCHLD,
        0,
        0,
        0,
        0,
        0
    );

    if (child < 0) {
        persistent_rc(
            "TFB_ADB_CLONE rc=",
            child
        );

        return -1;
    }

    if (child == 0) {
        /*
         * The TreeForge Bootstrap bridge retains this complete dynamic
         * runtime through Android FirstStageMain / FreeRamdisk
         * and materializes it below /dev/treeforge-bootstrap-runtime.
         *
         * Invoke the retained linker directly so this adbd does
         * not depend on the Android system partition's linker or
         * shared-library population.
         */
        char *argv[] = {
            (char *)
                "/dev/treeforge-bootstrap-runtime/system/bin/linker64",
            (char *)
                "/dev/treeforge-bootstrap-runtime/system/bin/"
                "treeforge-bootstrap-adbd",
            0
        };

        char *envp[] = {
            (char *)"HOME=/",
            (char *)
                "PATH=/dev/treeforge-bootstrap-runtime/system/bin:"
                "/bin:/sbin",
            (char *)
                "LD_LIBRARY_PATH="
                "/dev/treeforge-bootstrap-runtime/system/lib64",
            (char *)
                "ANDROID_ROOT="
                "/dev/treeforge-bootstrap-runtime/system",
            (char *)"TMPDIR=/tmp",
            0
        };

        sys6(
            SYS_EXECVE,
            (long)
                "/dev/treeforge-bootstrap-runtime/system/bin/linker64",
            (long)argv,
            (long)envp,
            0,
            0,
            0
        );

        /*
         * execve() returning is a hard launch failure.
         */
        sys6(
            93,
            127,
            0,
            0,
            0,
            0,
            0
        );

        for (;;) {
        }
    }

    tfb_adbd_pid = child;

    persistent_rc(
        "TFB_ADB_CHILD pid=",
        child
    );

    return child;
}


static int tfb_wait_tangorpro_udc(
    void
) {
    static const char *path =
        "/sys/class/udc/11210000.dwc3";

    struct timespec pause = {
        .tv_sec = 0,
        .tv_nsec = 25000000
    };

    /*
     * Keep each retry bounded.
     *
     * The supervisor retries indefinitely, so a missing controller
     * never permanently disables ADB and never blocks the rescue menu.
     */
    for (int attempt = 0; attempt < 40; ++attempt) {
        if (tfb_path_exists(path)) {
            persistent_line(
                "TFB_UDC_READY name=11210000.dwc3"
            );

            return 1;
        }

        sys6(
            SYS_NANOSLEEP,
            (long)&pause,
            0,
            0,
            0,
            0,
            0
        );
    }

    persistent_line(
        "TFB_UDC_NOT_READY name=11210000.dwc3"
    );

    return 0;
}


static void tfb_remove_file(
    const char *path
);

static void tfb_adb_teardown(
    void
) {

    tfb_remove_file(
        "/dev/treeforge-bootstrap-adb-ready"
    );

    tfb_remove_file(
        "/run/treeforge-bootstrap-display-modules-ready"
    );

    persistent_line(
        "TFB_ADB_TEARDOWN_BEGIN"
    );

    /*
     * If the gadget is currently bound, detach it before changing
     * the FunctionFS relationship.
     *
     * configfs accepts a newline as the empty UDC value on this
     * platform.
     */
    if (
        tfb_path_exists(
            "/config/usb_gadget/g1/UDC"
        )
    ) {
        tfb_write_file(
            "/config/usb_gadget/g1/UDC",
            "\n"
        );
    }

    sys6(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)
            "/config/usb_gadget/g1/configs/b.1/f1",
        0,
        0,
        0,
        0
    );

    tfb_stop_adbd();

    sys6(
        SYS_UMOUNT2,
        (long)"/dev/usb-ffs/adb",
        TFB_MNT_DETACH,
        0,
        0,
        0,
        0
    );

    /*
     * TREEFORGE_ANDROID_ADB_FUNCTION_CLEANUP_V2
     *
     * TreeForge owns the ffs.adb function instance used by
     * the boot menu.  After disconnecting the gadget, removing
     * the configuration link, stopping TreeForge adbd, and
     * detaching TreeForge's FunctionFS mount, remove that
     * configfs function instance as well.
     *
     * Android GS201 early-boot recreates ffs.adb and mounts its
     * own FunctionFS instance.
     */
    long function_remove_rc = sys6(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)
            "/config/usb_gadget/g1/"
            "functions/ffs.adb",
        0x200, /* AT_REMOVEDIR */
        0,
        0,
        0
    );

    persistent_rc(
        "TFB_ADB_FUNCTION_INSTANCE_REMOVE rc=",
        function_remove_rc
    );


    /*
     * TREEFORGE_ANDROID_GADGET_ROOT_PRESERVE_V4
     *
     * Same-kernel Android handoff must preserve the configfs g1 gadget
     * object itself.
     *
     * Android's USB configfs implementation keeps a kernel-global
     * android_device pointer associated with the first gadget object.
     * Destroying g1 leaves that pointer referring to the destroyed
     * device.  Android can then recreate the configfs directory while
     * create_function_device() still uses the stale parent device when
     * creating MIDI/audio-source function devices.
     *
     * TreeForge therefore releases only the state it actively owns:
     *
     *   - UDC binding
     *   - configuration symlink
     *   - TreeForge adbd
     *   - TreeForge FunctionFS mount
     *   - functions/ffs.adb
     *
     * Those releases happen above.
     *
     * Keep g1 plus its default configfs groups alive so Android adopts
     * the existing gadget object and repopulates it instead of
     * destroying and recreating the kernel-side gadget parent.
     */
    persistent_line(
        "TFB_ADB_GADGET_ROOT_PRESERVED"
    );

    persistent_line(
        "TFB_ADB_TEARDOWN_END"
    );
}


static int tfb_wait_functionfs_runtime(
    void
) {
    struct timespec pause = {
        .tv_sec = 0,
        .tv_nsec = 25000000
    };

    for (int attempt = 0; attempt < 100; ++attempt) {
        if (!tfb_adbd_alive()) {
            persistent_line(
                "TFB_ADB_DAEMON_DIED_BEFORE_FUNCTIONFS"
            );

            return 0;
        }

        if (
            tfb_path_exists(
                "/dev/usb-ffs/adb/ep1"
            )
            && tfb_path_exists(
                "/dev/usb-ffs/adb/ep2"
            )
        ) {
            persistent_line(
                "TFB_ADB_FUNCTIONFS_ENDPOINTS_READY"
            );

            return 1;
        }

        sys6(
            SYS_NANOSLEEP,
            (long)&pause,
            0,
            0,
            0,
            0,
            0
        );
    }

    persistent_line(
        "TFB_ADB_FUNCTIONFS_TIMEOUT"
    );

    return 0;
}



#ifndef SYS_IOCTL
#define SYS_IOCTL 29
#endif

#ifndef SYS_MMAP
#define SYS_MMAP 222
#endif

#ifndef SYS_MUNMAP
#define SYS_MUNMAP 215
#endif

#ifndef O_CREAT
#define O_CREAT 0100
#endif

#ifndef O_TRUNC
#define O_TRUNC 01000
#endif

#define TFB_PROT_READ  1
#define TFB_PROT_WRITE 2
#define TFB_MAP_SHARED 1

#define TFB_MODULE_WORKER_USB_INPUT  1

#define TFB_MODULE_WORKER_DISPLAY    2
#define TFB_MODULE_WORKER_FULL       3


static int tfb_touch_file(
    const char *path
) {
    long fd = sys6(
        SYS_OPENAT,
        AT_FDCWD,
        (long)path,
        O_WRONLY | O_CREAT | O_TRUNC,
        0644,
        0,
        0
    );

    if (fd < 0) {
        return 0;
    }

    static const char value[] = "1\n";

    long rc = sys6(
        SYS_WRITE,
        fd,
        (long)value,
        sizeof(value) - 1,
        0,
        0,
        0
    );

    sys6(
        SYS_CLOSE,
        fd,
        0,
        0,
        0,
        0,
        0
    );

    return rc == (long)(sizeof(value) - 1);
}


static void tfb_remove_file(
    const char *path
) {
    sys6(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)path,
        0,
        0,
        0,
        0
    );
}


/*
 * TFB_V6C_PID1_WATCHDOG_BIND_CHECK
 *
 * Module insertion alone does not prove that the GS201 watchdog
 * platform device matched and registered.
 */
/*
 * ------------------------------------------------------------------
 * Minimal native DRM rescue presentation.
 *
 * This is deliberately independent of Android/libdrm.
 * It uses generic DRM UAPI dumb-buffer + connector/CRTC discovery.
 * ------------------------------------------------------------------
 */

typedef unsigned int tfb_u32;
typedef unsigned short tfb_u16;
typedef unsigned long long tfb_u64;


struct tfb_drm_modeinfo {
    tfb_u32 clock;

    tfb_u16 hdisplay;
    tfb_u16 hsync_start;
    tfb_u16 hsync_end;
    tfb_u16 htotal;
    tfb_u16 hskew;

    tfb_u16 vdisplay;
    tfb_u16 vsync_start;
    tfb_u16 vsync_end;
    tfb_u16 vtotal;
    tfb_u16 vscan;

    tfb_u32 vrefresh;
    tfb_u32 flags;
    tfb_u32 type;

    char name[32];
};


struct tfb_drm_card_res {
    tfb_u64 fb_id_ptr;
    tfb_u64 crtc_id_ptr;
    tfb_u64 connector_id_ptr;
    tfb_u64 encoder_id_ptr;

    tfb_u32 count_fbs;
    tfb_u32 count_crtcs;
    tfb_u32 count_connectors;
    tfb_u32 count_encoders;

    tfb_u32 min_width;
    tfb_u32 max_width;
    tfb_u32 min_height;
    tfb_u32 max_height;
};


struct tfb_drm_connector {
    tfb_u64 encoders_ptr;
    tfb_u64 modes_ptr;
    tfb_u64 props_ptr;
    tfb_u64 prop_values_ptr;

    tfb_u32 count_modes;
    tfb_u32 count_props;
    tfb_u32 count_encoders;

    tfb_u32 encoder_id;
    tfb_u32 connector_id;
    tfb_u32 connector_type;
    tfb_u32 connector_type_id;
    tfb_u32 connection;

    tfb_u32 mm_width;
    tfb_u32 mm_height;
    tfb_u32 subpixel;
    tfb_u32 pad;
};


struct tfb_drm_encoder {
    tfb_u32 encoder_id;
    tfb_u32 encoder_type;
    tfb_u32 crtc_id;
    tfb_u32 possible_crtcs;
    tfb_u32 possible_clones;
};


struct tfb_drm_crtc {
    tfb_u64 set_connectors_ptr;

    tfb_u32 count_connectors;
    tfb_u32 crtc_id;
    tfb_u32 fb_id;
    tfb_u32 x;
    tfb_u32 y;
    tfb_u32 gamma_size;
    tfb_u32 mode_valid;

    struct tfb_drm_modeinfo mode;
};


struct tfb_drm_create_dumb {
    tfb_u32 height;
    tfb_u32 width;
    tfb_u32 bpp;
    tfb_u32 flags;
    tfb_u32 handle;
    tfb_u32 pitch;
    tfb_u64 size;
};


struct tfb_drm_map_dumb {
    tfb_u32 handle;
    tfb_u32 pad;
    tfb_u64 offset;
};


struct tfb_drm_fb2 {
    tfb_u32 fb_id;
    tfb_u32 width;
    tfb_u32 height;
    tfb_u32 pixel_format;
    tfb_u32 flags;

    tfb_u32 handles[4];
    tfb_u32 pitches[4];
    tfb_u32 offsets[4];

    tfb_u64 modifier[4];
};


#define TFB_IOC_NRBITS    8
#define TFB_IOC_TYPEBITS  8
#define TFB_IOC_SIZEBITS 14

#define TFB_IOC_NRSHIFT    0
#define TFB_IOC_TYPESHIFT  8
#define TFB_IOC_SIZESHIFT 16
#define TFB_IOC_DIRSHIFT  30

#define TFB_IOC_WRITE 1U
#define TFB_IOC_READ  2U

#define TFB_IOC(dir,type,nr,size) \
    ( \
        ((unsigned long)(dir)  << TFB_IOC_DIRSHIFT) \
        | ((unsigned long)(type) << TFB_IOC_TYPESHIFT) \
        | ((unsigned long)(nr)   << TFB_IOC_NRSHIFT) \
        | ((unsigned long)(size) << TFB_IOC_SIZESHIFT) \
    )

#define TFB_DRM_IOWR(nr,type) \
    TFB_IOC( \
        TFB_IOC_READ | TFB_IOC_WRITE, \
        'd', \
        nr, \
        sizeof(type) \
    )

#define TFB_DRM_GETRESOURCES \
    TFB_DRM_IOWR(0xA0, struct tfb_drm_card_res)

#define TFB_DRM_SETCRTC \
    TFB_DRM_IOWR(0xA2, struct tfb_drm_crtc)

#define TFB_DRM_GETENCODER \
    TFB_DRM_IOWR(0xA6, struct tfb_drm_encoder)

#define TFB_DRM_GETCONNECTOR \
    TFB_DRM_IOWR(0xA7, struct tfb_drm_connector)

#define TFB_DRM_CREATE_DUMB \
    TFB_DRM_IOWR(0xB2, struct tfb_drm_create_dumb)

#define TFB_DRM_MAP_DUMB \
    TFB_DRM_IOWR(0xB3, struct tfb_drm_map_dumb)

#define TFB_DRM_ADDFB2 \
    TFB_DRM_IOWR(0xB8, struct tfb_drm_fb2)

#define TFB_DRM_CONNECTED 1
#define TFB_DRM_MODE_PREFERRED (1U << 3)

#define TFB_DRM_FORMAT_XRGB8888 0x34325258U


static int tfb_drm_menu_active = 0;


/*
 * TFB_USB_ONLY_BRINGUP_V5
 *
 * GS201 device-session activation normally belongs to Android's
 * USB policy. This initramfs owns it directly.
 */
static int tfb_enable_gs201_usb_device_session(
    void
) {
    const char *path = (
        "/sys/devices/platform/11210000.usb/"
        "dwc3_exynos_otg_b_sess"
    );

    if (!tfb_path_exists(path)) {
        persistent_line(
            "TFB_GS201_USB_B_SESS_NOT_READY"
        );

        return 0;
    }

    if (
        !tfb_write_file(
            path,
            "1"
        )
    ) {
        persistent_line(
            "TFB_GS201_USB_B_SESS_WRITE_FAILED"
        );

        return 0;
    }

    persistent_line(
        "TFB_GS201_USB_B_SESS_ENABLED"
    );

    return 1;
}


static int tfb_setup_adb_usb(
    void
) {
    persistent_line(
        "TFB_ADB_BEGIN"
    );

    /*
     * TFB_POST_FIRST_STAGE_ADB_SERVICE_V1
     *
     * Platform/module readiness is now established by canonical
     * Google FirstStageMain before the TreeForge Bootstrap bridge launches
     * this service.  Gadget realization therefore has no dependency
     * on the obsolete V7 module-worker marker.
     */
    persistent_line(
        "TFB_ADB_POST_FIRST_STAGE_PLATFORM_READY"
    );

    /*
     * Make repeated attempts deterministic before rebuilding
     * the gadget.
     */
    tfb_adb_teardown();

    /*
     * GS201 device-session activation is mandatory.  V6B ignored
     * this return value; V6C requires success.
     */
    if (
        !tfb_enable_gs201_usb_device_session()
    ) {
        persistent_line(
            "TFB_V6C_ADB_B_SESS_FAILED"
        );

        return 0;
    }

    persistent_line(
        "TFB_V6C_ADB_B_SESS_READY"
    );

    if (!tfb_wait_tangorpro_udc()) {
        persistent_line(
            "TFB_V6C_ADB_UDC_WAIT_FAILED"
        );

        return 0;
    }

    persistent_line(
        "TFB_V6C_ADB_UDC_READY"
    );

    if (
        !tfb_mkdir(
            "/config",
            0755
        )
        || !tfb_mount_fs(
            "none",
            "/config",
            "configfs"
        )
    ) {
        persistent_line(
            "TFB_ADB_CONFIGFS_FAILED"
        );

        return 0;
    }

    static const char *directories[] = {
        "/config/usb_gadget",
        "/config/usb_gadget/g1",
        "/config/usb_gadget/g1/strings",
        "/config/usb_gadget/g1/strings/0x409",
        "/config/usb_gadget/g1/configs",
        "/config/usb_gadget/g1/configs/b.1",
        "/config/usb_gadget/g1/configs/b.1/strings",
        "/config/usb_gadget/g1/configs/b.1/strings/0x409",
        "/config/usb_gadget/g1/functions",
        "/config/usb_gadget/g1/functions/ffs.adb",
        0
    };

    for (int index = 0; directories[index]; ++index) {
        if (
            !tfb_mkdir(
                directories[index],
                0755
            )
        ) {
            persistent_line(
                "TFB_ADB_CONFIGFS_MKDIR_FAILED"
            );

            tfb_adb_teardown();

            return 0;
        }
    }

    if (
        !tfb_write_file(
            "/config/usb_gadget/g1/idVendor",
            "0x18d1"
        )
        || !tfb_write_file(
            "/config/usb_gadget/g1/idProduct",
            "0x4ee7"
        )
        || !tfb_write_file(
            "/config/usb_gadget/g1/"
            "strings/0x409/manufacturer",
            "TreeForge"
        )
        || !tfb_write_file(
            "/config/usb_gadget/g1/"
            "strings/0x409/product",
            "TreeForge Bootstrap"
        )
        || !tfb_write_file(
            "/config/usb_gadget/g1/"
            "strings/0x409/serialnumber",
            "treeforge-tangorpro"
        )
        || !tfb_write_file(
            "/config/usb_gadget/g1/"
            "configs/b.1/strings/0x409/configuration",
            "ADB"
        )
    ) {
        persistent_line(
            "TFB_ADB_IDENTITY_FAILED"
        );

        tfb_adb_teardown();

        return 0;
    }

    if (
        !tfb_mkdir(
            "/dev/usb-ffs",
            0755
        )
        || !tfb_mkdir(
            "/dev/usb-ffs/adb",
            0755
        )
        || !tfb_mount_fs(
            "adb",
            "/dev/usb-ffs/adb",
            "functionfs"
        )
    ) {
        persistent_line(
            "TFB_ADB_FUNCTIONFS_MOUNT_FAILED"
        );

        tfb_adb_teardown();

        return 0;
    }

    persistent_line(
        "TFB_ADB_FUNCTIONFS_MOUNTED"
    );

    if (tfb_start_adbd() <= 0) {
        persistent_line(
            "TFB_ADB_DAEMON_FAILED"
        );

        tfb_adb_teardown();

        return 0;
    }

    if (!tfb_wait_functionfs_runtime()) {
        tfb_adb_teardown();

        return 0;
    }

    static const char *function_link =
        "/config/usb_gadget/g1/configs/b.1/f1";

    sys6(
        SYS_UNLINKAT,
        AT_FDCWD,
        (long)function_link,
        0,
        0,
        0,
        0
    );

    /*
     * This absolute configfs object target is intentional.
     *
     * We proved on the hardware that the superficially equivalent
     * ../../functions/ffs.adb target is rejected by configfs.
     */
    long link_rc = sys6(
        SYS_SYMLINKAT,
        (long)
            "/config/usb_gadget/g1/functions/ffs.adb",
        AT_FDCWD,
        (long)function_link,
        0,
        0,
        0
    );

    if (link_rc < 0) {
        persistent_rc(
            "TFB_ADB_FUNCTION_LINK rc=",
            link_rc
        );

        tfb_adb_teardown();

        return 0;
    }

    persistent_line(
        "TFB_ADB_FUNCTION_LINKED"
    );

    if (!tfb_adbd_alive()) {
        persistent_line(
            "TFB_ADB_DAEMON_DIED_BEFORE_BIND"
        );

        tfb_adb_teardown();

        return 0;
    }

    if (
        !tfb_write_file(
            "/config/usb_gadget/g1/UDC",
            "11210000.dwc3"
        )
    ) {
        persistent_line(
            "TFB_ADB_UDC_BIND_FAILED"
        );

        tfb_adb_teardown();

        return 0;
    }

    struct timespec settle = {
        .tv_sec = 0,
        .tv_nsec = 100000000
    };

    sys6(
        SYS_NANOSLEEP,
        (long)&settle,
        0,
        0,
        0,
        0,
        0
    );

    if (!tfb_adbd_alive()) {
        persistent_line(
            "TFB_ADB_DAEMON_DIED_AFTER_BIND"
        );

        tfb_adb_teardown();

        return 0;
    }

    tfb_touch_file(
        "/dev/treeforge-bootstrap-adb-ready"
    );

    persistent_line(
        "TFB_ADB_READY"
    );

    write_line(
        "ADB STATUS : READY"
    );

    return 1;
}





struct tfb_input_event {
    long tv_sec;
    long tv_usec;
    unsigned short type;
    unsigned short code;
    int value;
};


static long tfb_rescue_pid = -1;


/*
 * TFB_ADB_STEADY_STATE_PROCESS_LIVENESS_V18
 *
 * adbd may remain alive after the physical USB cable is removed.
 * Supervising only the child PID therefore cannot detect a dead USB
 * transport.
 *
 * The GS201 UDC publishes the physical session state at:
 *
 *     /sys/class/udc/11210000.dwc3/state
 *
 * We react only to the explicit "not attached" state.  Transitional
 * states such as powered/default/address/configured/suspended remain
 * valid and must not cause gadget churn.
 */
static int tfb_text_equal(
    const char *left,
    const char *right
) {
    if (!left || !right) {
        return 0;
    }

    while (
        *left != '\0'
        && *right != '\0'
    ) {
        if (*left != *right) {
            return 0;
        }

        left++;
        right++;
    }

    return (
        *left == '\0'
        && *right == '\0'
    );
}


static int tfb_read_small_text(
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

    long fd = sys6(
        SYS_OPENAT,
        AT_FDCWD,
        (long) path,
        O_RDONLY
        | O_NONBLOCK,
        0,
        0,
        0
    );

    if (fd < 0) {
        return 0;
    }

    long amount = sys6(
        SYS_READ,
        fd,
        (long) buffer,
        (long) (
            capacity - 1
        ),
        0,
        0,
        0
    );

    sys6(
        SYS_CLOSE,
        fd,
        0,
        0,
        0,
        0,
        0
    );

    if (amount <= 0) {
        return 0;
    }

    usize length =
        (usize) amount;

    if (length >= capacity) {
        length =
            capacity - 1;
    }

    buffer[length] =
        '\0';

    while (
        length > 0
        && (
            buffer[length - 1]
                == '\n'
            || buffer[length - 1]
                == '\r'
            || buffer[length - 1]
                == ' '
            || buffer[length - 1]
                == '\t'
        )
    ) {
        length--;

        buffer[length] =
            '\0';
    }

    return length > 0;
}


static void tfb_supervise_adb_service(
    int adb_ready
) {
    struct timespec pause = {
        .tv_sec = 0,
        .tv_nsec = 25000000
    };

    int retry_ticks = 0;

    persistent_line(
        "TFB_ADB_SERVICE_SUPERVISOR_BEGIN"
    );

    for (;;) {
        if (
            tfb_path_exists(
                "/dev/treeforge-bootstrap-adb-stop"
            )
        ) {
            persistent_line(
                "TFB_ADB_SERVICE_STOP_REQUEST"
            );

            tfb_adb_teardown();

            persistent_line(
                "TFB_ADB_SERVICE_STOPPED"
            );

            sys6(
                SYS_EXIT,
                0,
                0,
                0,
                0,
                0,
                0
            );

            for (;;) {
            }
        }

        if (
            adb_ready
            && !tfb_adbd_alive()
        ) {
            persistent_line(
                "TFB_ADB_SERVICE_RUNTIME_LOST"
            );

            tfb_adb_teardown();

            adb_ready = 0;
            retry_ticks = 0;
        }

        if (!adb_ready) {
            ++retry_ticks;

            /*
             * Retry immediately on service entry and then every
             * two seconds after a failed attempt.
             */
            if (
                retry_ticks == 1
                || retry_ticks >= 80
            ) {
                retry_ticks = 1;

                persistent_line(
                    "TFB_ADB_SERVICE_RETRY"
                );

                adb_ready = (
                    tfb_setup_adb_usb()
                );

                persistent_rc(
                    "TFB_ADB_SERVICE_SETUP_RESULT value=",
                    adb_ready
                );
            }
        }

        sys6(
            SYS_NANOSLEEP,
            (long)&pause,
            0,
            0,
            0,
            0,
            0
        );
    }
}


/*
 * ================================================================
 * CROS V7 -- exact GS201 first-stage platform realization
 * ================================================================
 *
 * V6 proved that selected-module realization is not equivalent to
 * the actual tangorpro first-stage contract.
 *
 * V7 consumes the exact frozen vendor_kernel_boot.modules.load
 * produced by the coherent source-built kernel family.
 */


/*
 * Linux dev_t encoding used by mknodat().
 */
/*
 * pmsg uses a dynamically allocated character-device major.
 *
 * Do not hard-code the stock-A observation (252:0).  Read the
 * kernel's actual allocation from sysfs on every boot.
 */
/*
 * Read the exact staged modules.load and realize every entry
 * sequentially.  Dependencies are still inserted first according
 * to modules.dep, matching normal modprobe semantics.
 */
void _start(
    void
) {
    /*
     * Post-FirstStageMain ADB service.
     *
     * Google first-stage already owns platform module realization
     * and /dev creation.  Do not recreate the V7 module worker,
     * rescue UI, or standalone early-device runtime here.
     */
    tfb_mkdir(
        "/run",
        0755
    );

    tfb_mkdir(
        "/tmp",
        01777
    );

    mount_one(
        "proc",
        "/proc",
        "proc"
    );

    mount_one(
        "sysfs",
        "/sys",
        "sysfs"
    );

    mount_one(
        "tmpfs",
        "/run",
        "tmpfs"
    );

    mount_one(
        "tmpfs",
        "/tmp",
        "tmpfs"
    );

    setup_console();

    persistent_line(
        "TREEFORGE_BOOTSTRAP_ADB_SERVICE_BEGIN"
    );

    int adb_ready = (
        tfb_setup_adb_usb()
    );

    persistent_rc(
        "TFB_ADB_SERVICE_INITIAL_RESULT value=",
        adb_ready
    );

    tfb_supervise_adb_service(
        adb_ready
    );

    for (;;) {
    }

}
