# Copyright 2026 Gregor Sprint
# SPDX-License-Identifier: GPL-3.0-or-later
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from pmb.commands.image import stage_ports
from pmb.helpers.exceptions import NonBugError


def test_stage_ports_creates_discoverable_packages(monkeypatch: Any, tmp_path: Path) -> None:
    ports = tmp_path / "ports"
    aports = tmp_path / "aports"
    source = ports / "devices/nothing-asteroids"
    source.mkdir(parents=True)
    aports.mkdir()

    def run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "clone" in command:
            shutil.copytree(aports, Path(command[-1]))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", run)
    (aports / "pmaports.cfg").write_text("[pmaports]\n")
    (source / "APKBUILD").write_text('pkgname=device-nothing-asteroids\ndepends="linux-kernel"\n')
    (source / "deviceinfo").write_text(
        'deviceinfo_codename="nothing-asteroids"\ndeviceinfo_flash_method="fastboot"\ndeviceinfo_header_version="2"\ndeviceinfo_flash_pagesize="4096"\n'
    )
    (source / "modules-initfs").write_text("ufs_qcom\n")
    (source / "APKBUILD.linux-kernel").write_text(
        'pkgname=linux-kernel\n_vendor_commit="'
        + "a" * 40
        + '"\nsource="https://github.com/example/kernel/archive/$_vendor_commit.tar.gz fix.patch config-kernel.aarch64"\n'
    )
    (source / "fix.patch").write_text("patch")
    (source / "config-kernel.aarch64").write_text("config")
    subprocess.run(["git", "-C", str(ports), "add", "devices"], check=True)
    recipe = {
        "device": "nothing-asteroids",
        "packages": ["device-nothing-asteroids", "linux-kernel", "openssh"],
        "kernel": {"commit": "a" * 40, "repo": "example/kernel", "branch": "stable"},
        "flash": {"header_version": 2, "pagesize": 4096},
    }
    work = tmp_path / "work"
    stage = stage_ports(ports, aports, work, recipe)
    device = stage / "device/downstream/device-nothing-asteroids"
    kernel = stage / "device/downstream/linux-kernel"
    assert (device / "APKBUILD").is_file()
    assert (device / "deviceinfo").is_file()
    assert (kernel / "APKBUILD").is_file()
    assert (kernel / "fix.patch").is_file()
    assert (kernel / "config-kernel.aarch64").is_file()
    (source / "fix.patch").unlink()
    with pytest.raises(NonBugError, match="Invalid omnipha/ports input"):
        stage_ports(ports, aports, tmp_path / "second-work", recipe)
