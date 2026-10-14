from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil

from .canonical_initramfs import ensure_canonical_provider
from .external_providers import (
    ensure_declared_external_providers,
)

from .framebuffer_provider import (
    configure_framebuffer_provider_override,
    load_framebuffer_provider,
)
from .menu_provider import (
    configure_menu_provider_override,
    load_menu_provider,
)

from .kernel_provider import (
    configure_kernel_provider_override,
    ensure_kernel_reconstruction_provider,
)

from .development_overrides import (
    TreeForgeDevelopmentOverrideError,
    activate as activate_development_provider,
    remove as remove_development_provider,
)

from .paths import (
    OUT,
    PROVIDERS,
    REPOSITORY_ROOT,
    WORK,
)

from .runtime import (
    build_runtime,
    verify_frozen_runtime,
    verify_runtime,
)

from .provider import (
    package_provider,
    verify_provider,
)

from .image import (
    build_image,
    verify_image,
)

from .avb_graph import (
    realize_family,
)

from .avb_keyset import (
    load_avb_keyset,
)

from .hardware import hardware_preflight
from .interactive import interactive
from .paths import BUILD_PROFILE


class TreeForgeBootstrapBuildError(
    RuntimeError
):
    pass


CANONICAL_PROVIDER = (
    PROVIDERS
    / "google"
    / "tangorpro"
    / "android-15"
    / "init_boot.ramdisk.cpio"
)

ADBD_PROVIDER_ROOT = (
    PROVIDERS
    / "external"
    / "treeforge-bootstrap-adbd"
    / "android-15.0.0_r36-arm64"
    / "rootfs"
)

EXPECTED_CANONICAL_SHA256 = (
    "d9a027e3c06dc096cfb92e15251329c9"
    "6f1d69e38954c2d0758da520b1f3078f"
)


def _sha256(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for block in iter(
            lambda: stream.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def _clang() -> Path:
    from .host_providers import ensure_clang

    return ensure_clang()

def doctor() -> None:
    ensure_canonical_provider()

    ensure_declared_external_providers()

    if not CANONICAL_PROVIDER.is_file():
        raise TreeForgeBootstrapBuildError(
            "canonical Google provider missing: "
            f"{CANONICAL_PROVIDER}"
        )

    actual = _sha256(
        CANONICAL_PROVIDER
    )

    if actual != EXPECTED_CANONICAL_SHA256:
        raise TreeForgeBootstrapBuildError(
            "canonical provider identity changed: "
            f"{actual}"
        )

    if not ADBD_PROVIDER_ROOT.is_dir():
        raise TreeForgeBootstrapBuildError(
            "treeforge-bootstrap-adbd provider "
            "rootfs missing: "
            f"{ADBD_PROVIDER_ROOT}"
        )

    adbd = (
        ADBD_PROVIDER_ROOT
        / "system"
        / "bin"
        / "treeforge-bootstrap-adbd"
    )

    if not adbd.is_file():
        raise TreeForgeBootstrapBuildError(
            "treeforge-bootstrap-adbd binary "
            f"missing: {adbd}"
        )

    if (
        _sha256(adbd)
        != "625fbc447f0f1f9490aa0b72f88dd34f0f7e84c93fe80484288336acda28d53a"
    ):
        raise TreeForgeBootstrapBuildError(
            "treeforge-bootstrap-adbd "
            "provider identity changed"
        )

    clang = _clang()

    from .host_providers import ensure_host_tool

    mkbootimg = ensure_host_tool("mkbootimg")
    unpack_bootimg = ensure_host_tool("unpack_bootimg")
    avbtool = ensure_host_tool("avbtool")

    lz4 = shutil.which(
        "lz4"
    )

    if lz4 is None:
        raise TreeForgeBootstrapBuildError(
            "lz4 is unavailable"
        )

    print("TreeForge Bootstrap Doctor")
    print("==========================")
    print()
    print(f"Repository:         {REPOSITORY_ROOT}")
    print(f"Canonical provider: {CANONICAL_PROVIDER}")
    print(f"Canonical SHA256:   {actual}")
    print(f"ADB provider:       {ADBD_PROVIDER_ROOT}")
    print(f"Clang:              {clang}")
    print(f"Mkbootimg:          {mkbootimg}")
    print(f"Unpack bootimg:     {unpack_bootimg}")
    print(f"AVBTool:            {avbtool}")
    print(f"LZ4:                {Path(lz4).resolve()}")
    print(f"Work:               {WORK}")
    print(f"Output:             {OUT}")
    print()
    print("SIGNED_IMAGE=NO")
    print("DEVICE_ACCESS_REQUIRED=NO")
    print("TREEFORGE_BOOTSTRAP_DOCTOR=PASS")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="treeforge-bootstrap"
    )

    parser.add_argument(
        "command",
        nargs="?",
        choices=(
            "doctor",
            "build",
            "verify",
            "verify-frozen-runtime",
            "package",
            "verify-provider",
            "package-development",
            "verify-development-provider",
            "image",
            "verify-image",
            "realize-family",
            "hardware-preflight",
        ),
    )

    parser.add_argument(
        "--input-family",
        type=Path,
        help=(
            "Complete Pixel Partitioner "
            "device-backup family consumed "
            "by realize-family."
        ),
    )

    parser.add_argument(
        "--output-family",
        type=Path,
        help=(
            "Optional explicit output directory "
            "for realize-family."
        ),
    )

    parser.add_argument(
        "--source-init-boot",
        type=Path,
        help=(
            "Existing init_boot image whose AVB contract "
            "is inherited by standalone image realization."
        ),
    )

    parser.add_argument(
        "--source-vbmeta",
        type=Path,
        help=(
            "Existing root vbmeta image defining the current "
            "boot/init_boot child AVB trust identity."
        ),
    )

    parser.add_argument(
        "--avb-key",
        type=Path,
        help=(
            "Explicit unlocked RSA-2048 child private key "
            "for boot/init_boot. Key lifecycle belongs to "
            "the downstream consumer."
        ),
    )

    parser.add_argument(
        "--parent-vbmeta-key",
        type=Path,
        help=(
            "Private key matching the existing "
            "root vbmeta identity, used only when "
            "boot/init_boot trust must be rewritten."
        ),
    )

    parser.add_argument(
        "--avb-keyset",
        type=Path,
        help=(
            "Manifest-backed AVB keyset "
            "directory or keyset.json used "
            "by realize-family."
        ),
    )

    parser.add_argument(
        "--dev-provider-kernel",
        nargs="?",
        const="",
        metavar="PATH",
        help=(
            "Use the remembered local Kernel "
            "development provider, or validate "
            "and remember PATH."
        ),
    )

    parser.add_argument(
        "--dev-provider-kernel-remove",
        action="store_true",
        help=(
            "Forget the remembered local Kernel "
            "development provider."
        ),
    )

    parser.add_argument(
        "--dev-provider-framebuffer",
        nargs="?",
        const="",
        metavar="PATH",
        help=(
            "Use the remembered local Framebuffer "
            "development provider, or validate "
            "and remember PATH."
        ),
    )

    parser.add_argument(
        "--dev-provider-framebuffer-remove",
        action="store_true",
        help=(
            "Forget the remembered local Framebuffer "
            "development provider."
        ),
    )

    parser.add_argument(
        "--dev-provider-menu",
        nargs="?",
        const="",
        metavar="PATH",
        help=(
            "Use the remembered local Menu "
            "development provider, or validate "
            "and remember PATH."
        ),
    )

    parser.add_argument(
        "--dev-provider-menu-remove",
        action="store_true",
        help=(
            "Forget the remembered local Menu "
            "development provider."
        ),
    )

    parser.add_argument(
        "--profile",
        choices=("treeforge-default", "treeforge-chromiumos"),
        default=BUILD_PROFILE,
    )

    parser.add_argument(
        "--transaction-request",
        type=Path,
        help=(
            "Optional canonical TreeForge Bootstrap "
            "transaction request file consumed only "
            "by realize-family and embedded as "
            "vendor_boot transaction/request-v1."
        ),
    )

    args = parser.parse_args()

    if args.profile != BUILD_PROFILE:
        parser.error("Build-profile mismatch")

    removal_requested = False

    for name, requested, remove_flag in (
        (
            "kernel",
            args.dev_provider_kernel,
            args.dev_provider_kernel_remove,
        ),
        (
            "framebuffer",
            args.dev_provider_framebuffer,
            args.dev_provider_framebuffer_remove,
        ),
        (
            "menu",
            args.dev_provider_menu,
            args.dev_provider_menu_remove,
        ),
    ):
        if (
            remove_flag
            and requested is not None
        ):
            parser.error(
                f"--dev-provider-{name} and "
                f"--dev-provider-{name}-remove "
                "are mutually exclusive"
            )

        if remove_flag:
            removal_requested = True

            try:
                existed = (
                    remove_development_provider(
                        name
                    )
                )
            except TreeForgeDevelopmentOverrideError as error:
                parser.error(
                    str(error)
                )

            print(
                "DEVELOPMENT_PROVIDER_REMOVED_"
                + name.upper()
                + "="
                + (
                    "YES"
                    if existed
                    else "NO"
                )
            )

    kernel_path = None
    framebuffer_path = None
    menu_path = None

    kernel_provider = None
    framebuffer_provider = None
    menu_provider = None

    try:
        if args.dev_provider_kernel is not None:
            def validate_kernel(
                candidate: Path,
            ):
                configure_kernel_provider_override(
                    candidate
                )

                return (
                    ensure_kernel_reconstruction_provider()
                )

            (
                kernel_path,
                kernel_provider,
            ) = activate_development_provider(
                "kernel",
                args.dev_provider_kernel,
                prompt_label=(
                    "Kernel development provider path"
                ),
                validator=validate_kernel,
            )

        if (
            args.dev_provider_framebuffer
            is not None
        ):
            def validate_framebuffer(
                candidate: Path,
            ):
                configure_framebuffer_provider_override(
                    candidate
                )

                return (
                    load_framebuffer_provider()
                )

            (
                framebuffer_path,
                framebuffer_provider,
            ) = activate_development_provider(
                "framebuffer",
                args.dev_provider_framebuffer,
                prompt_label=(
                    "Framebuffer development "
                    "provider path"
                ),
                validator=validate_framebuffer,
            )

        if args.dev_provider_menu is not None:
            def validate_menu(
                candidate: Path,
            ):
                configure_menu_provider_override(
                    candidate
                )

                return load_menu_provider()

            (
                menu_path,
                menu_provider,
            ) = activate_development_provider(
                "menu",
                args.dev_provider_menu,
                prompt_label=(
                    "Menu development provider path"
                ),
                validator=validate_menu,
            )

    except (
        TreeForgeDevelopmentOverrideError,
        Exception,
    ) as error:
        parser.error(
            str(error)
        )

    development_runtime = (
        framebuffer_path is not None
        or menu_path is not None
    )

    development_kernel = (
        kernel_path is not None
    )

    if (
        development_runtime
        or development_kernel
    ):
        if args.profile != "treeforge-default":
            parser.error(
                "development provider overrides "
                "currently support "
                "treeforge-default only"
            )

    if development_runtime:
        allowed = {
            "doctor",
            "build",
            "verify",
            "image",
            "verify-image",
            "realize-family",
        }

        if args.command not in allowed:
            parser.error(
                "Framebuffer/Menu development "
                "providers are valid only for "
                "doctor/build/verify/image/"
                "verify-image/realize-family"
            )

    if development_kernel:
        allowed = {
            "doctor",
            "image",
            "verify-image",
            "realize-family",
        }

        if args.command not in allowed:
            parser.error(
                "Kernel development provider is "
                "valid only for doctor/image/"
                "verify-image/realize-family"
            )

    if kernel_path is not None:
        print(
            "KERNEL_PROVIDER_MODE="
            "development-local"
        )
        print(
            "KERNEL_PROVIDER_ROOT="
            + str(kernel_path)
        )
        print(
            "KERNEL_PROVIDER_VERSION="
            + str(
                kernel_provider["release"]
            )
        )

    if framebuffer_path is not None:
        print(
            "FRAMEBUFFER_PROVIDER_MODE="
            "development-local"
        )
        print(
            "FRAMEBUFFER_PROVIDER_ROOT="
            + str(framebuffer_path)
        )
        print(
            "FRAMEBUFFER_PROVIDER_VERSION="
            + framebuffer_provider.version
        )

    if menu_path is not None:
        print(
            "MENU_PROVIDER_MODE="
            "development-local"
        )
        print(
            "MENU_PROVIDER_ROOT="
            + str(menu_path)
        )
        print(
            "MENU_PROVIDER_VERSION="
            + menu_provider.version
        )

    if (
        args.command is None
        and removal_requested
    ):
        return

    if args.profile == "treeforge-chromiumos":
        if args.command not in (
            "doctor", "build", "verify", "image", "verify-image"
        ):
            parser.error(
                "ChromiumOS supports runtime and standalone "
                "init_boot development commands only"
            )

    if args.command is None:
        interactive()
        return

    if args.command == "doctor":
        doctor()
    elif args.command == "build":
        build_runtime()
        verify_runtime()

        if (
            BUILD_PROFILE
            == "treeforge-default"
        ):
            from .development_provider import (
                package_development_provider,
            )

            package_development_provider()
    elif args.command == "verify":
        verify_runtime()
    elif args.command == "verify-frozen-runtime":
        verify_frozen_runtime()
    elif args.command == "package":
        package_provider()
        from .realizer_provider import package_realizer_provider
        package_realizer_provider()
    elif args.command == "verify-provider":
        verify_provider()
        from .realizer_provider import verify_realizer_provider
        verify_realizer_provider()
    elif args.command == "package-development":
        from .development_provider import (
            package_development_provider,
        )
        package_development_provider()
    elif args.command == "verify-development-provider":
        from .development_provider import (
            verify_development_provider,
        )
        verify_development_provider()
    elif args.command == "image":
        if BUILD_PROFILE == "treeforge-chromiumos":
            from .chromiumos_init_boot import build
            build()
        else:
            if development_runtime:
                build_runtime()
                verify_runtime()

            if (
                args.avb_key is None
                or args.source_init_boot is None
                or args.source_vbmeta is None
            ):
                parser.error(
                    "image requires --avb-key, "
                    "--source-init-boot, and --source-vbmeta"
                )

            build_image(
                source_init_boot=(
                    args.source_init_boot
                ),
                source_vbmeta=(
                    args.source_vbmeta
                ),
                signing_key=(
                    args.avb_key
                ),
                development_runtime=(
                    development_runtime
                ),
            )
    elif args.command == "verify-image":
        if BUILD_PROFILE == "treeforge-chromiumos":
            from .chromiumos_init_boot import verify
            verify()
        else:
            if (
                args.avb_key is None
                or args.source_init_boot is None
                or args.source_vbmeta is None
            ):
                parser.error(
                    "verify-image requires --avb-key, "
                    "--source-init-boot, and --source-vbmeta"
                )

            verify_image(
                source_init_boot=(
                    args.source_init_boot
                ),
                source_vbmeta=(
                    args.source_vbmeta
                ),
                signing_key=(
                    args.avb_key
                ),
                development_runtime=(
                    development_runtime
                ),
            )
    elif args.command == "realize-family":
        if args.input_family is None:
            parser.error(
                "realize-family requires "
                "--input-family PATH"
            )

        if development_runtime:
            build_runtime()
            verify_runtime()

        if (
            args.avb_keyset is not None
            and (
                args.avb_key is not None
                or args.parent_vbmeta_key
                is not None
            )
        ):
            parser.error(
                "--avb-keyset is mutually "
                "exclusive with --avb-key and "
                "--parent-vbmeta-key"
            )

        keyset = None

        resolved_avb_key = (
            args.avb_key
        )

        resolved_parent_key = (
            args.parent_vbmeta_key
        )

        if args.avb_keyset is not None:
            keyset = load_avb_keyset(
                args.avb_keyset
            )

            resolved_avb_key = (
                keyset
                .boot_chain_private_key
            )

            resolved_parent_key = (
                keyset
                .root_vbmeta_private_key
            )

            print(
                "AVB_KEYSET_ID="
                + keyset.keyset_id
            )

            print(
                "AVB_KEYSET_MANIFEST_SHA256="
                + keyset.manifest_sha256
            )

            print(
                "AVB_KEYSET_BOOT_CHAIN_PUBLIC_KEY_SHA1="
                + keyset.boot_chain_public_key_sha1
            )

            print(
                "AVB_KEYSET_ROOT_PUBLIC_KEY_SHA1="
                + keyset.root_vbmeta_public_key_sha1
            )

            print(
                "AVB_KEYSET_VERIFY=PASS"
            )

        transaction_request = None

        if args.transaction_request is not None:
            transaction_request_path = (
                args.transaction_request
                .expanduser()
                .resolve()
            )

            if not transaction_request_path.is_file():
                parser.error(
                    "--transaction-request does not "
                    "exist or is not a regular file: "
                    f"{transaction_request_path}"
                )

            transaction_request = (
                transaction_request_path
                .read_bytes()
            )

            if len(transaction_request) != 119:
                parser.error(
                    "--transaction-request must be "
                    "exactly 119 bytes; got "
                    f"{len(transaction_request)}"
                )

            print(
                "TRANSACTION_REQUEST="
                f"{transaction_request_path}"
            )
            print(
                "TRANSACTION_REQUEST_BYTES="
                f"{len(transaction_request)}"
            )
            print(
                "TRANSACTION_REQUEST_SHA256="
                f"{_sha256(transaction_request_path)}"
            )

        realize_family(
            args.input_family,
            output_family=(
                args.output_family
            ),
            avb_key=(
                resolved_avb_key
            ),
            parent_vbmeta_key=(
                resolved_parent_key
            ),
            keyset_id=(
                keyset.keyset_id
                if keyset is not None
                else None
            ),
            keyset_manifest_sha256=(
                keyset.manifest_sha256
                if keyset is not None
                else None
            ),
            development_runtime=(
                development_runtime
            ),
            transaction_request=transaction_request,
        )
    else:
        hardware_preflight()


if __name__ == "__main__":
    main()
