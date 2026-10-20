# Copyright 2026 Gregor Sprint
# SPDX-License-Identifier: GPL-3.0-or-later
import hashlib
import subprocess
from pathlib import Path
from typing import Any

import pytest

import pmb.helpers.cli
from pmb.commands.image import export_images, image, load_recipe, pinned_checkout, read_public_key
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
    with pytest.raises(NonBugError, match="metadata-encrypted userdata cannot be built offline"):
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


@pytest.mark.parametrize("encryption", ["metadata", "luks", "unrecognized"])
def test_reject_unprovisioned_userdata(recipe: Path, encryption: str) -> None:
    text = recipe.read_text().replace("encryption: metadata", f"encryption: {encryption}")
    recipe.write_text(text)
    with pytest.raises(NonBugError, match="userdata"):
        load_recipe(recipe, "server")


def test_reject_missing_metadata_prerequisites(recipe: Path) -> None:
    text = recipe.read_text().replace(
        "partitions: [boot, vendor_boot, dtbo, vbmeta, userdata]",
        "partitions: [boot, vendor_boot, userdata, metadata]",
    )
    recipe.write_text(text)
    with pytest.raises(NonBugError, match="boot-time, device-bound key management"):
        load_recipe(recipe, "server")
    recipe.write_text(text.replace("userdata, metadata", "userdata"))
    with pytest.raises(NonBugError, match="separate metadata partition"):
        load_recipe(recipe, "server")
    recipe.write_text(text.replace("encryption: metadata", "encryption: none"))
    with pytest.raises(NonBugError, match="dtbo/vbmeta"):
        load_recipe(recipe, "server")


def test_metadata_rejection_precedes_any_build(
    monkeypatch: Any, tmp_path: Path, recipe: Path
) -> None:
    config = Config()
    config.work = tmp_path / "unused-work"
    monkeypatch.setattr("pmb.commands.image.get_context", lambda: Context(config))
    args = PmbArgs()
    args.config = tmp_path / "new-config"
    args.image_yaml = recipe
    args.profile = "server"
    with pytest.raises(NonBugError, match="metadata-encrypted userdata"):
        image(args)
    assert not config.work.exists()
    assert not args.config.exists()


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
