# Copyright 2026 Gregor Sprint
# SPDX-License-Identifier: GPL-3.0-or-later
import hashlib
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

import pmb.helpers.cli
from pmb import main
from pmb.commands.image import (
    BOOT_PARTITIONS,
    boot_chain,
    build_boot_images,
    export_images,
    load_recipe,
    pinned_checkout,
    read_boot_layout,
    read_public_key,
    sha,
    verify_boot_images,
    verify_layout,
)
from pmb.core import Chroot, Config
from pmb.core.context import Context
from pmb.helpers.cli import ask as real_ask
from pmb.helpers.exceptions import NonBugError
from pmb.parse import get_parser
from pmb.types import PmbArgs


@pytest.fixture
def recipe(tmp_path: Path) -> Path:
    path = tmp_path / "image.yaml"
    path.write_text("""device: nothing-asteroids
soc: sm7635
profile: server
kernel:
  repo: NothingOSS/android_kernel_msm-6.1_nothing_sm7635
  branch: sm7635/v/mr
  commit: d5f5f965fd0b478eaf4eb63fd984c5a4a92135a7
packages: [device-nothing-asteroids, linux-omnipha-nothing-sm7635, openssh]
flash:
  method: fastboot
  header_version: 4
  pagesize: 4096
  partitions: [boot, vendor_boot, dtbo, vbmeta, userdata]
  userdata:
    filesystem: f2fs
    encryption: metadata
""")
    return path


def test_parser_requires_headless_inputs() -> None:
    parser = get_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["image", "image.yaml"])
    args = parser.parse_args(
        [
            "image",
            "image.yaml",
            "--non-interactive",
            "--profile",
            "server",
            "--ssh-pubkey",
            "key.pub",
            "--ports",
            "ports",
            "--ports-revision",
            "a" * 40,
            "--aports-revision",
            "b" * 40,
            "--output",
            "output",
        ]
    )
    assert args.non_interactive and args.profile == "server"
    assert args.ssh_pubkey == Path("key.pub")


def test_actual_recipe_fails_closed(recipe: Path) -> None:
    with pytest.raises(NonBugError, match="metadata encryption"):
        load_recipe(recipe, "server")
    with pytest.raises(NonBugError, match="--profile"):
        load_recipe(recipe, "console-ui")
    text = recipe.read_text().replace("encryption: metadata", "encryption: none")
    recipe.write_text(text)
    with pytest.raises(NonBugError, match="dtbo/vbmeta"):
        load_recipe(recipe, "server")
    recipe.write_text(text.replace("dtbo, vbmeta, ", ""))
    with pytest.raises(NonBugError, match="init_boot"):
        load_recipe(recipe, "server")


def test_reject_malformed_recipe(recipe: Path) -> None:
    recipe.write_text("!!python/object/apply:os.system ['true']")
    with pytest.raises(NonBugError, match=r"Cannot read image\.yaml"):
        load_recipe(recipe, "server")


def test_validate_public_key(tmp_path: Path) -> None:
    path = tmp_path / "key.pub"
    path.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    with pytest.raises(NonBugError, match="public key"):
        read_public_key(path)
    path.write_text("ssh-ed25519 YWJj bogus\n")
    with pytest.raises(NonBugError, match="public key"):
        read_public_key(path)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / "key")], check=True
    )
    read_public_key(tmp_path / "key.pub")


def test_pinned_checkout(monkeypatch: Any, tmp_path: Path) -> None:
    revision = "a" * 40
    dirty = False

    def check_output(command: list[str], **_kwargs: Any) -> str:
        return (
            "M file"
            if dirty and "status" in command
            else revision
            if "rev-parse" in command
            else ""
        )

    monkeypatch.setattr(subprocess, "check_output", check_output)
    pinned_checkout(tmp_path, revision)
    dirty = True
    with pytest.raises(NonBugError, match="clean checkout"):
        pinned_checkout(tmp_path, revision)
    with pytest.raises(NonBugError, match="full pinned"):
        pinned_checkout(tmp_path, "main")


def test_export_hashes_file_bytes(monkeypatch: Any, tmp_path: Path) -> None:
    native = tmp_path / "native"
    boot = tmp_path / "rootfs" / "boot"
    (native / "home/pmos/rootfs").mkdir(parents=True)
    boot.mkdir(parents=True)
    (native / "home/pmos/rootfs/test.img").write_bytes(b"root image")
    (boot / "boot.img").write_bytes(b"boot image")
    monkeypatch.setattr(Chroot, "native", lambda: native)
    monkeypatch.setattr(Chroot, "rootfs", lambda _device: boot.parent)
    output = tmp_path / "output"
    export_images("test", ["boot", "userdata"], output)
    assert (output / "SHA256SUMS").read_text().splitlines() == [
        f"{hashlib.sha256(b'root image').hexdigest()}  test.img",
        f"{hashlib.sha256(b'boot image').hexdigest()}  boot.img",
    ]
    assert (output / "test.img").read_bytes() == b"root image"
    with pytest.raises(NonBugError, match="empty"):
        export_images("test", ["boot", "userdata"], output)


def test_headless_prompts_fail_closed(monkeypatch: Any) -> None:
    context = Context(Config())
    context.non_interactive = True
    monkeypatch.setattr("pmb.helpers.cli.get_context", lambda: context)
    with pytest.raises(RuntimeError, match="Prompt required"):
        real_ask("Select a device")
    with pytest.raises(RuntimeError, match="Confirmation required"):
        pmb.helpers.cli.confirm("Overwrite disk?")


def test_missing_artifact_has_no_output(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(Chroot, "native", lambda: tmp_path)
    monkeypatch.setattr(Chroot, "rootfs", lambda _device: tmp_path)
    output = tmp_path / "output"
    with pytest.raises(NonBugError, match="Image artifacts missing"):
        export_images("test", ["boot", "userdata"], output)
    assert not output.exists()


def test_boot_chain_parser_requires_manifest() -> None:
    parser = get_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["boot_chain", "image.yaml"])
    args = parser.parse_args(
        [
            "boot_chain",
            "image.yaml",
            "--layout-manifest",
            "layout.json",
            "--input-dir",
            "inputs",
            "--output",
            "output",
        ]
    )
    assert args.layout_manifest == Path("layout.json")
    assert args.input_dir == Path("inputs")


def test_boot_chain_missing_manifest_fails_before_output(tmp_path: Path) -> None:
    recipe = tmp_path / "image.yaml"
    recipe.write_text("device: nothing-asteroids\n")
    directory = tmp_path / "inputs"
    directory.mkdir()
    output = tmp_path / "output"
    with pytest.raises(NonBugError, match="missing recipe, manifest"):
        boot_chain(
            PmbArgs(
                image_yaml=recipe,
                layout_manifest=tmp_path / "missing.json",
                input_dir=directory,
                image_output=output,
            )
        )
    assert not output.exists()


def test_boot_chain_cli_fails_without_config_or_pmaports(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    recipe = tmp_path / "image.yaml"
    recipe.write_text("device: nothing-asteroids\n")
    directory = tmp_path / "inputs"
    directory.mkdir()
    monkeypatch.setattr(
        "sys.argv",
        [
            "pmbootstrap",
            "boot_chain",
            str(recipe),
            "--layout-manifest",
            str(tmp_path / "missing.json"),
            "--input-dir",
            str(directory),
            "--output",
            str(tmp_path / "output"),
        ],
    )
    assert main() == 2
    assert "missing recipe, manifest" in capsys.readouterr().err
    assert not (tmp_path / "output").exists()


def test_boot_chain_requires_per_input_provenance(tmp_path: Path) -> None:
    recipe = tmp_path / "image.yaml"
    recipe.write_text(
        "device: nothing-asteroids\nprofile: server\nflash:\n  method: fastboot\n"
        "  header_version: 4\n  pagesize: 4096\n  slots: ab\n"
        "  partitions: [boot, vendor_boot, dtbo, vbmeta, userdata]\n"
        "  vbmeta: disable-verification\n  userdata:\n    filesystem: f2fs\n    encryption: metadata\n"
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    directory = tmp_path / "inputs"
    directory.mkdir()
    with pytest.raises(NonBugError, match="per-input hashed/provenance"):
        read_boot_layout(recipe, manifest, directory)


def synthetic_fdt(index: int) -> bytes:
    return b"\xd0\x0d\xfe\xed" + struct.pack(">I", 40) + bytes([index]) * 32


def synthetic_dtbo() -> tuple[bytes, list[bytes]]:
    entries = [synthetic_fdt(i) for i in range(76)]
    table = bytearray(32 + 76 * 32)
    offset = len(table)
    for index, entry in enumerate(entries):
        struct.pack_into(">II", table, 32 + index * 32, len(entry), offset)
        table.extend(entry)
        offset += len(entry)
    struct.pack_into(">8I", table, 0, 0xD7B7AB1E, len(table), 32, 32, 76, 32, 4096, 0)
    return bytes(table), entries


def synthetic_layout() -> tuple[dict[str, Any], dict[str, bytes]]:
    dtbs = [synthetic_fdt(i) for i in range(20)]
    dtbo, overlays = synthetic_dtbo()
    data = {
        "kernel": b"\x1f\x8bkernel",
        "generic_ramdisk": b"\x1f\x8bgeneric",
        "vendor_ramdisk": b"\x1f\x8bvendor",
        "dtbs": b"".join(dtbs),
        "dtbo": dtbo,
        "bootconfig": b"androidboot.hardware=qcom\n".ljust(175, b"\n"),
    }
    manifest = {
        "headers": {
            "boot_cmdline": "",
            "init_boot_cmdline": "",
            "vendor_cmdline": "bootconfig",
            "kernel_offset": 0x8000,
            "ramdisk_offset": 0x1000000,
            "tags_offset": 0x100,
            "dtb_offset": 0x1F00000,
            "os_version": 0,
        },
        "partition_sizes": dict.fromkeys(BOOT_PARTITIONS, 1024 * 1024),
        "dtb_sha256": [sha(entry) for entry in dtbs],
        "dtbo_sha256": [sha(entry) for entry in overlays],
    }
    return manifest, data


def test_header_v4_synthetic_bytes_and_slot_a_hashes(tmp_path: Path) -> None:
    manifest, data = synthetic_layout()
    images = build_boot_images(manifest, data)
    verify_boot_images(manifest, data, images)
    assert struct.unpack_from("<II", images["boot"], 8) == (len(data["kernel"]), 0)
    assert struct.unpack_from("<II", images["init_boot"], 8) == (0, len(data["generic_ramdisk"]))
    assert (
        images["vendor_boot"][4096 : 4096 + len(data["vendor_ramdisk"])] == data["vendor_ramdisk"]
    )
    assert images["vbmeta"][:4] == b"AVB0"
    assert struct.unpack_from(">I", images["vbmeta"], 120)[0] == 2
    output = tmp_path / "output"
    output.mkdir()
    for name, blob in images.items():
        (output / f"{name}.img").write_bytes(blob)
    sums = [
        f"{hashlib.sha256((output / f'{name}.img').read_bytes()).hexdigest()}  {name}.img"
        for name in BOOT_PARTITIONS
    ]
    assert len(set(sums)) == 5
    assert all(name.endswith(".img") for name in (line.split("  ")[1] for line in sums))


@pytest.mark.parametrize(
    "name,offset,value,message",
    [
        ("boot", 40, 3, "header v4"),
        ("init_boot", 12, 0, "header contents"),
        ("vendor_boot", 2116, 2, "ramdisk table"),
        ("vendor_boot", 2124, 0, "ramdisk table"),
        ("vbmeta", 120, 0, "AVB0 flags=2"),
    ],
)
def test_boot_chain_rejects_corrupt_outputs(
    name: str, offset: int, value: int, message: str
) -> None:
    manifest, data = synthetic_layout()
    images = build_boot_images(manifest, data)
    bad = bytearray(images[name])
    struct.pack_into(">I" if name == "vbmeta" else "<I", bad, offset, value)
    images[name] = bytes(bad)
    with pytest.raises(NonBugError, match=message):
        verify_boot_images(manifest, data, images)


def test_boot_chain_rejects_partition_bound() -> None:
    manifest, data = synthetic_layout()
    manifest["partition_sizes"]["vendor_boot"] = 4096
    with pytest.raises(NonBugError, match="vendor_boot_a exceeds"):
        verify_boot_images(manifest, data, build_boot_images(manifest, data))


def test_dtb_index_9_requires_pinned_stock_bytes(monkeypatch: Any) -> None:
    manifest, data = synthetic_layout()
    vendor = bytearray(4096 + 4096 + len(data["dtbs"]))
    vendor[:8] = b"VNDRBOOT"
    struct.pack_into("<II", vendor, 8, 4, 4096)
    struct.pack_into("<I", vendor, 24, 9)
    struct.pack_into("<I", vendor, 2096, 2128)
    struct.pack_into("<I", vendor, 2100, len(data["dtbs"]))
    vendor[8192:] = data["dtbs"]
    data["stock_vendor_boot"] = bytes(vendor)
    data["stock_dtbo"] = data["dtbo"]
    data["stock_boot"] = build_boot_images(manifest, data)["boot"]
    data["stock_init_boot"] = build_boot_images(manifest, data)["init_boot"]
    monkeypatch.setattr("pmb.commands.image.verify_stock_avb", lambda _data: None)
    monkeypatch.setattr("pmb.commands.image.stock_bootconfig", lambda _vendor: data["bootconfig"])
    monkeypatch.setattr(
        subprocess, "run", lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0)
    )
    verify_layout(manifest, data)
    bad = bytearray(data["dtbs"])
    bad[9 * 40 + 9] ^= 1
    data["dtbs"] = bytes(bad)
    manifest["dtb_sha256"][9] = sha(synthetic_fdt(9))
    with pytest.raises(NonBugError, match="DTB index 9 SHA-256"):
        verify_layout(manifest, data)
    manifest["dtb_sha256"][9] = sha(data["dtbs"][9 * 40 : 10 * 40])
    with pytest.raises(NonBugError, match="DTB index 9 SHA-256"):
        verify_layout(manifest, data)


def test_ordered_dtbo_entries_cannot_be_swapped(monkeypatch: Any) -> None:
    manifest, data = synthetic_layout()
    vendor = bytearray(4096 + 4096 + len(data["dtbs"]))
    vendor[:8] = b"VNDRBOOT"
    struct.pack_into("<II", vendor, 8, 4, 4096)
    struct.pack_into("<I", vendor, 24, 9)
    struct.pack_into("<I", vendor, 2096, 2128)
    struct.pack_into("<I", vendor, 2100, len(data["dtbs"]))
    vendor[8192:] = data["dtbs"]
    data["stock_vendor_boot"] = bytes(vendor)
    data["stock_dtbo"] = data["dtbo"]
    data["stock_boot"] = build_boot_images(manifest, data)["boot"]
    data["stock_init_boot"] = build_boot_images(manifest, data)["init_boot"]
    monkeypatch.setattr("pmb.commands.image.verify_stock_avb", lambda _data: None)
    monkeypatch.setattr("pmb.commands.image.stock_bootconfig", lambda _vendor: data["bootconfig"])
    monkeypatch.setattr(
        subprocess, "run", lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0)
    )
    verify_layout(manifest, data)
    bad = bytearray(data["dtbo"])
    first, second = bad[32:64], bad[64:96]
    bad[32:64], bad[64:96] = second, first
    data["dtbo"] = bytes(bad)
    with pytest.raises(NonBugError, match="DTBO entry 0 SHA-256"):
        verify_layout(manifest, data)
