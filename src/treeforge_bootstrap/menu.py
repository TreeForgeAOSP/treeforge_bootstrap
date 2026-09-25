from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path
import re
from typing import Any

from .paths import PROJECT_ROOT


class TreeForgeMenuError(ValueError):
    pass


class ABMode(str, Enum):
    VIRTUAL = "virtual_ab"
    FULL = "full_ab"


class MenuAction(str, Enum):
    BOOT_ANDROID_SLOT_A = "boot_android_slot_a"
    BOOT_ANDROID_SLOT_B = "boot_android_slot_b"
    BOOT_ALTERNATE_OS = "boot_alternate_os"
    BOOT_ROOTED_ANDROID = "boot_rooted_android"
    INSTALL_ROOT = "install_root"
    UNINSTALL_ROOT = "uninstall_root"
    TOGGLE_ROOT_PERSISTENCE = "toggle_root_persistence"
    REBOOT_BOOTLOADER = "reboot_bootloader"
    REBOOT_RECOVERY = "reboot_recovery"
    SET_BOOT_TARGET_SLOT_A = "set_boot_target_slot_a"
    SET_BOOT_TARGET_SLOT_B = "set_boot_target_slot_b"
    LIVE_CONSOLE = "live_console"
    RESTART_ADB_USB = "restart_adb_usb"
    NOT_IMPLEMENTED = "not_implemented"
    BACK = "back"


class MenuCondition(str, Enum):
    ALWAYS = "always"
    FULL_AB = "full_ab"
    ALTERNATE_OS_CONFIGURED = "alternate_os_configured"
    ROOT_INSTALLED = "root_installed"
    ROOT_NOT_INSTALLED = "root_not_installed"


class MenuLabelState(str, Enum):
    NONE = "none"
    ROOT_PERSISTENCE = "root_persistence"
    ALTERNATE_OS_NAME = "alternate_os_name"


class MenuIcon(str, Enum):
    NONE = "none"
    ANDROID = "android"
    RECOVERY = "recovery"
    MAINTENANCE = "maintenance"
    ALTERNATE_OS = "alternate-os"
    ROOT = "root"
    PIXEL_PARTITIONER = "pixel-partitioner"
    BOOTLOADER = "bootloader"
    BACK = "back"


@dataclass(
    frozen=True,
    slots=True,
)
class MenuRuntimeState:
    ab_mode: ABMode = ABMode.VIRTUAL
    alternate_os_configured: bool = False
    alternate_os_name: str = "Alternate OS"
    root_installed: bool = False
    root_persistence_enabled: bool = False


@dataclass(
    frozen=True,
    slots=True,
)
class MenuEntry:
    entry_id: str
    label: str
    action: MenuAction | None
    submenu: MenuPage | None
    visible_if: MenuCondition
    label_state: MenuLabelState
    description: str = "Menu option"
    icon: MenuIcon = MenuIcon.NONE


@dataclass(
    frozen=True,
    slots=True,
)
class MenuPage:
    page_id: str
    title: str
    subtitle: str
    default_entry: str
    timeout_ms: int
    timeout_action: MenuAction | None
    entries: tuple[MenuEntry, ...]


@dataclass(
    frozen=True,
    slots=True,
)
class MenuProfile:
    schema: int
    profile_id: str
    root: MenuPage


DEFAULT_PROFILE_PATH = (
    PROJECT_ROOT
    / "profiles"
    / "treeforge-default.json"
)


_ID_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9-]{0,47}$"
)

_MAX_DEPTH = 4
_MAX_ENTRIES = 8
_MAX_TIMEOUT_MS = 60000


def _text(
    value: object,
    *,
    field: str,
    maximum: int,
) -> str:
    if not isinstance(
        value,
        str,
    ):
        raise TreeForgeMenuError(
            f"{field} must be a string"
        )

    if not value:
        raise TreeForgeMenuError(
            f"{field} must not be empty"
        )

    if len(value) > maximum:
        raise TreeForgeMenuError(
            f"{field} exceeds {maximum} characters"
        )

    if any(
        ord(character) < 0x20
        or ord(character) > 0x7e
        for character in value
    ):
        raise TreeForgeMenuError(
            f"{field} must be printable ASCII"
        )

    return value


def _identifier(
    value: object,
    *,
    field: str,
) -> str:
    text = _text(
        value,
        field=field,
        maximum=48,
    )

    if not _ID_PATTERN.fullmatch(
        text
    ):
        raise TreeForgeMenuError(
            f"{field} is not a valid menu identifier: "
            f"{text!r}"
        )

    return text


def _enum(
    enum_type: type[Enum],
    value: object,
    *,
    field: str,
):
    if not isinstance(
        value,
        str,
    ):
        raise TreeForgeMenuError(
            f"{field} must be a string"
        )

    try:
        return enum_type(
            value
        )
    except ValueError as error:
        allowed = ", ".join(
            member.value
            for member in enum_type
        )

        raise TreeForgeMenuError(
            f"{field} has unsupported value "
            f"{value!r}; expected one of: {allowed}"
        ) from error


def _known_keys(
    value: dict[str, Any],
    allowed: set[str],
    *,
    field: str,
) -> None:
    unknown = (
        set(value)
        - allowed
    )

    if unknown:
        raise TreeForgeMenuError(
            f"{field} contains unsupported keys: "
            + ", ".join(
                sorted(unknown)
            )
        )


def _condition_visible(
    condition: MenuCondition,
    state: MenuRuntimeState,
) -> bool:
    if condition is MenuCondition.ALWAYS:
        return True

    if (
        condition
        is MenuCondition.FULL_AB
    ):
        return state.ab_mode is ABMode.FULL

    if (
        condition
        is MenuCondition.ALTERNATE_OS_CONFIGURED
    ):
        return state.alternate_os_configured

    if (
        condition
        is MenuCondition.ROOT_INSTALLED
    ):
        return state.root_installed

    if (
        condition
        is MenuCondition.ROOT_NOT_INSTALLED
    ):
        return not state.root_installed

    raise TreeForgeMenuError(
        f"unhandled menu condition: {condition.value}"
    )


def display_label(
    entry: MenuEntry,
    state: MenuRuntimeState,
) -> str:
    if (
        entry.label_state
        is MenuLabelState.ROOT_PERSISTENCE
    ):
        suffix = (
            "ON"
            if state.root_persistence_enabled
            else "OFF"
        )

        return (
            entry.label
            + " ["
            + suffix
            + "]"
        )

    if (
        entry.label_state
        is MenuLabelState.ALTERNATE_OS_NAME
    ):
        name = state.alternate_os_name

        if (
            isinstance(name, str)
            and name
            and len(name) <= 64
            and all(
                0x20 <= ord(character) <= 0x7e
                for character in name
            )
        ):
            return name

        return entry.label

    return entry.label


def visible_entries(
    page: MenuPage,
    state: MenuRuntimeState,
) -> tuple[MenuEntry, ...]:
    return tuple(
        entry
        for entry in page.entries
        if _condition_visible(
            entry.visible_if,
            state,
        )
    )


def default_selection(
    page: MenuPage,
    state: MenuRuntimeState,
) -> int:
    entries = visible_entries(
        page,
        state,
    )

    if not entries:
        raise TreeForgeMenuError(
            f"menu page {page.page_id!r} "
            "contains no visible entries"
        )

    for index, entry in enumerate(
        entries
    ):
        if (
            entry.entry_id
            == page.default_entry
        ):
            return index

    return 0


def move_selection(
    page: MenuPage,
    state: MenuRuntimeState,
    selected: int,
    delta: int,
) -> int:
    entries = visible_entries(
        page,
        state,
    )

    if not entries:
        raise TreeForgeMenuError(
            f"menu page {page.page_id!r} "
            "contains no visible entries"
        )

    if selected < 0:
        selected = 0

    if selected >= len(entries):
        selected = (
            len(entries) - 1
        )

    return (
        selected + delta
    ) % len(entries)


def selected_entry(
    page: MenuPage,
    state: MenuRuntimeState,
    selected: int,
) -> MenuEntry:
    entries = visible_entries(
        page,
        state,
    )

    if (
        selected < 0
        or selected >= len(entries)
    ):
        raise TreeForgeMenuError(
            f"selection {selected} is outside "
            f"page {page.page_id!r}"
        )

    return entries[
        selected
    ]


def _parse_entry(
    value: object,
    *,
    depth: int,
    seen_ids: set[str],
) -> MenuEntry:
    if not isinstance(
        value,
        dict,
    ):
        raise TreeForgeMenuError(
            "menu entry must be an object"
        )

    _known_keys(
        value,
        {
            "id",
            "label",
            "description",
            "icon",
            "action",
            "submenu",
            "visible_if",
            "label_state",
        },
        field="menu entry",
    )

    entry_id = _identifier(
        value.get("id"),
        field="entry.id",
    )

    if entry_id in seen_ids:
        raise TreeForgeMenuError(
            f"duplicate menu identifier: {entry_id}"
        )

    seen_ids.add(
        entry_id
    )

    label = _text(
        value.get("label"),
        field=f"{entry_id}.label",
        maximum=64,
    )

    description = _text(
        value.get(
            "description",
            label,
        ),
        field=f"{entry_id}.description",
        maximum=96,
    )

    icon = _enum(
        MenuIcon,
        value.get(
            "icon",
            MenuIcon.NONE.value,
        ),
        field=f"{entry_id}.icon",
    )

    action_value = value.get(
        "action"
    )

    submenu_value = value.get(
        "submenu"
    )

    if (
        action_value is None
        and submenu_value is None
    ):
        raise TreeForgeMenuError(
            f"{entry_id} must define action or submenu"
        )

    if (
        action_value is not None
        and submenu_value is not None
    ):
        raise TreeForgeMenuError(
            f"{entry_id} cannot define both "
            "action and submenu"
        )

    action = (
        None
        if action_value is None
        else _enum(
            MenuAction,
            action_value,
            field=f"{entry_id}.action",
        )
    )

    submenu = (
        None
        if submenu_value is None
        else _parse_page(
            submenu_value,
            depth=depth + 1,
            seen_ids=seen_ids,
        )
    )

    visible_if = _enum(
        MenuCondition,
        value.get(
            "visible_if",
            MenuCondition.ALWAYS.value,
        ),
        field=f"{entry_id}.visible_if",
    )

    label_state = _enum(
        MenuLabelState,
        value.get(
            "label_state",
            MenuLabelState.NONE.value,
        ),
        field=f"{entry_id}.label_state",
    )

    if (
        label_state
        is MenuLabelState.ROOT_PERSISTENCE
        and action
        is not MenuAction.TOGGLE_ROOT_PERSISTENCE
    ):
        raise TreeForgeMenuError(
            f"{entry_id} uses root_persistence "
            "label state without toggle_root_persistence"
        )

    return MenuEntry(
        entry_id=entry_id,
        label=label,
        action=action,
        submenu=submenu,
        visible_if=visible_if,
        label_state=label_state,
        description=description,
        icon=icon,
    )


def _parse_page(
    value: object,
    *,
    depth: int,
    seen_ids: set[str],
) -> MenuPage:
    if depth > _MAX_DEPTH:
        raise TreeForgeMenuError(
            "menu nesting exceeds supported depth"
        )

    if not isinstance(
        value,
        dict,
    ):
        raise TreeForgeMenuError(
            "menu page must be an object"
        )

    _known_keys(
        value,
        {
            "id",
            "title",
            "subtitle",
            "default_entry",
            "timeout_ms",
            "timeout_action",
            "entries",
        },
        field="menu page",
    )

    page_id = _identifier(
        value.get("id"),
        field="page.id",
    )

    if page_id in seen_ids:
        raise TreeForgeMenuError(
            f"duplicate menu identifier: {page_id}"
        )

    seen_ids.add(
        page_id
    )

    title = _text(
        value.get("title"),
        field=f"{page_id}.title",
        maximum=48,
    )

    subtitle = _text(
        value.get(
            "subtitle",
            "TreeForge Bootstrap",
        ),
        field=f"{page_id}.subtitle",
        maximum=64,
    )

    default_entry = _identifier(
        value.get("default_entry"),
        field=f"{page_id}.default_entry",
    )

    timeout_ms = value.get(
        "timeout_ms",
        0,
    )

    if (
        not isinstance(
            timeout_ms,
            int,
        )
        or isinstance(
            timeout_ms,
            bool,
        )
        or timeout_ms < 0
        or timeout_ms > _MAX_TIMEOUT_MS
    ):
        raise TreeForgeMenuError(
            f"{page_id}.timeout_ms must be "
            f"0..{_MAX_TIMEOUT_MS}"
        )

    timeout_action_value = value.get(
        "timeout_action"
    )

    timeout_action = (
        None
        if timeout_action_value is None
        else _enum(
            MenuAction,
            timeout_action_value,
            field=f"{page_id}.timeout_action",
        )
    )

    if (
        timeout_ms == 0
        and timeout_action is not None
    ):
        raise TreeForgeMenuError(
            f"{page_id} has timeout_action "
            "with timeout disabled"
        )

    if (
        timeout_ms > 0
        and timeout_action is None
    ):
        raise TreeForgeMenuError(
            f"{page_id} enables timeout without "
            "timeout_action"
        )

    raw_entries = value.get(
        "entries"
    )

    if (
        not isinstance(
            raw_entries,
            list,
        )
        or not raw_entries
    ):
        raise TreeForgeMenuError(
            f"{page_id}.entries must be "
            "a non-empty array"
        )

    if len(raw_entries) > _MAX_ENTRIES:
        raise TreeForgeMenuError(
            f"{page_id} exceeds "
            f"{_MAX_ENTRIES} entries"
        )

    entries = tuple(
        _parse_entry(
            entry,
            depth=depth,
            seen_ids=seen_ids,
        )
        for entry in raw_entries
    )

    entry_ids = {
        entry.entry_id
        for entry in entries
    }

    if default_entry not in entry_ids:
        raise TreeForgeMenuError(
            f"{page_id}.default_entry "
            f"{default_entry!r} does not exist"
        )

    return MenuPage(
        page_id=page_id,
        title=title,
        subtitle=subtitle,
        default_entry=default_entry,
        timeout_ms=timeout_ms,
        timeout_action=timeout_action,
        entries=entries,
    )


def parse_profile_dict(
    value: object,
) -> MenuProfile:
    if not isinstance(
        value,
        dict,
    ):
        raise TreeForgeMenuError(
            "menu profile must be an object"
        )

    _known_keys(
        value,
        {
            "schema",
            "profile_id",
            "root",
        },
        field="menu profile",
    )

    schema = value.get(
        "schema"
    )

    if schema != 1:
        raise TreeForgeMenuError(
            f"unsupported menu profile schema: {schema!r}"
        )

    profile_id = _identifier(
        value.get("profile_id"),
        field="profile_id",
    )

    seen_ids = {
        profile_id,
    }

    root = _parse_page(
        value.get("root"),
        depth=0,
        seen_ids=seen_ids,
    )

    return MenuProfile(
        schema=schema,
        profile_id=profile_id,
        root=root,
    )


def load_profile(
    path: Path,
) -> MenuProfile:
    if not isinstance(
        path,
        Path,
    ):
        raise TypeError(
            "path must be pathlib.Path"
        )

    if not path.is_file():
        raise TreeForgeMenuError(
            f"menu profile is missing: {path}"
        )

    try:
        value = json.loads(
            path.read_text()
        )
    except json.JSONDecodeError as error:
        raise TreeForgeMenuError(
            f"invalid menu profile JSON: {path}: {error}"
        ) from error

    return parse_profile_dict(
        value
    )


def load_default_profile() -> MenuProfile:
    return load_profile(
        DEFAULT_PROFILE_PATH
    )
