# Copyright 2026 Gregor Sprint
# SPDX-License-Identifier: GPL-3.0-or-later
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

import pmb.config
import pmb.config.pmaports
from pmb.commands.install import install
from pmb.core import Chroot
from pmb.core.config import ServiceManagerConfig
from pmb.core.context import get_context
from pmb.helpers import logging
from pmb.helpers.exceptions import NonBugError
from pmb.types import PmbArgs

REVISION = re.compile(r"[0-9a-f]{40}\Z")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+_.-]*\Z")
KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
}


def field(data: Any, key: str, kind: type) -> Any:
    if not isinstance(data, dict) or not isinstance(data.get(key), kind):
        raise NonBugError(f"image.yaml: expected {key} to be {kind.__name__}")
    return data[key]


def load_recipe(path: Path, profile: str) -> dict[str, Any]:
    try:
        recipe = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exception:
        raise NonBugError(f"Cannot read image.yaml: {exception}") from exception
    device = field(recipe, "device", str)
    soc = field(recipe, "soc", str)
    if not PACKAGE.fullmatch(device) or not PACKAGE.fullmatch(soc):
        raise NonBugError("image.yaml: invalid device or SoC")
    if field(recipe, "profile", str) != profile:
        raise NonBugError("--profile must match image.yaml profile")
    kernel = field(recipe, "kernel", dict)
    for name in ("repo", "branch"):
        if not field(kernel, name, str):
            raise NonBugError(f"image.yaml: kernel.{name} must not be empty")
    if not REVISION.fullmatch(field(kernel, "commit", str)):
        raise NonBugError("image.yaml: kernel.commit must be a full pinned SHA-1")
    packages = field(recipe, "packages", list)
    if not packages or any(not isinstance(p, str) or not PACKAGE.fullmatch(p) for p in packages):
        raise NonBugError("image.yaml: packages must contain package names")
    if f"device-{device}" not in packages or "openssh" not in packages:
        raise NonBugError("image.yaml: device package and openssh are required")
    if len([package for package in packages if package.startswith("linux-")]) != 1:
        raise NonBugError("image.yaml: exactly one pinned kernel package is required")
    flash = field(recipe, "flash", dict)
    if field(flash, "method", str) != "fastboot":
        raise NonBugError("image.yaml: only fastboot images are supported")
    if type(flash.get("header_version")) is not int or type(flash.get("pagesize")) is not int:
        raise NonBugError("image.yaml: header_version and pagesize must be integers")
    if flash["header_version"] not in (0, 1, 2, 3, 4) or flash["pagesize"] not in (
        2048,
        4096,
        8192,
        16384,
    ):
        raise NonBugError("image.yaml: invalid boot image geometry")
    partitions = field(flash, "partitions", list)
    if not partitions or any(
        not isinstance(p, str) or not PACKAGE.fullmatch(p) for p in partitions
    ):
        raise NonBugError("image.yaml: invalid flash partitions")
    if (
        "userdata" not in partitions
        or "boot" not in partitions
        or len(set(partitions)) != len(partitions)
    ):
        raise NonBugError(
            "image.yaml: boot and userdata partitions are required without duplicates"
        )
    userdata = field(flash, "userdata", dict)
    if field(userdata, "filesystem", str) not in ("ext4", "f2fs"):
        raise NonBugError("image.yaml: unsupported userdata filesystem")
    if field(userdata, "encryption", str) != "none":
        raise NonBugError(
            "image.yaml: metadata encryption is not supported by pmbootstrap; cannot build a flashable image"
        )
    if set(partitions) - {"boot", "vendor_boot", "userdata"}:
        raise NonBugError(
            "image.yaml: dtbo/vbmeta and other flash partitions cannot be generated safely"
        )
    if flash["header_version"] >= 4:
        raise NonBugError(
            "image.yaml: header v4 requires an init_boot image, which pmbootstrap cannot generate"
        )
    if (flash["header_version"] >= 3) != ("vendor_boot" in partitions):
        raise NonBugError("image.yaml: vendor_boot partition must match the boot header version")
    firmware = recipe.get("firmware", {})
    if (
        not isinstance(firmware, dict)
        or firmware.get("source", "none") != "none"
        or set(firmware) - {"source"}
    ):
        raise NonBugError("image.yaml: external firmware sources are not supported")
    if "slots" in flash or "vbmeta" in flash:
        raise NonBugError("image.yaml: slot and vbmeta policies are not supported")
    allowed = {"device", "soc", "profile", "kernel", "packages", "flash", "firmware"}
    if (
        set(recipe) - allowed
        or set(flash) - {"method", "header_version", "pagesize", "partitions", "userdata"}
        or set(kernel) - {"repo", "branch", "commit"}
        or set(userdata) - {"filesystem", "encryption"}
    ):
        raise NonBugError("image.yaml: unsupported fields")
    return recipe


def read_public_key(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise NonBugError("--ssh-pubkey must be a regular, small public-key file")
    try:
        lines = path.read_text(encoding="ascii").splitlines()
        parts = lines[0].split() if len(lines) == 1 else []
        if len(parts) < 2 or parts[0] not in KEY_TYPES:
            raise NonBugError("--ssh-pubkey is not a single valid SSH public key")
        subprocess.run(
            ["ssh-keygen", "-l", "-f", str(path)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, UnicodeError, subprocess.CalledProcessError) as exception:
        raise NonBugError("--ssh-pubkey is not a single valid SSH public key") from exception


def pinned_checkout(path: Path, revision: str) -> None:
    if not REVISION.fullmatch(revision):
        raise NonBugError("Expected a full pinned git revision")
    try:
        actual = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
        dirty = subprocess.check_output(
            ["git", "-C", str(path), "status", "--porcelain", "--untracked-files=all"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exception:
        raise NonBugError(f"Not a git checkout: {path}") from exception
    if actual != revision or dirty:
        raise NonBugError(f"Expected clean checkout at {revision}: {path}")


def tracked_input(ports: Path, file: Path) -> Path:
    if (
        not file.is_relative_to(ports)
        or file.is_symlink()
        or not file.is_file()
        or file.stat().st_size > 2 * 1024 * 1024
    ):
        raise NonBugError(f"Invalid omnipha/ports input: {file}")
    relative = file.relative_to(ports)
    result = subprocess.run(
        ["git", "-C", str(ports), "ls-files", "--error-unmatch", "--", str(relative)],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise NonBugError(f"Untracked omnipha/ports input: {relative}")
    return file


def stage_ports(ports: Path, aports: Path, work: Path, recipe: dict[str, Any]) -> Path:
    device = recipe["device"]
    source = ports / "devices" / device
    if (ports / "devices").is_symlink() or source.is_symlink() or not source.is_dir():
        raise NonBugError("Invalid omnipha/ports device directory")
    kernel = next((p for p in recipe["packages"] if p.startswith("linux-")), None)
    if kernel is None:
        raise NonBugError("image.yaml: a pinned linux-* package is required")
    kernel_apkbuild = source / f"APKBUILD.{kernel}"
    for file in (
        source / "APKBUILD",
        kernel_apkbuild,
        source / "deviceinfo",
        source / "modules-initfs",
    ):
        tracked_input(ports, file)
    deviceinfo = (source / "deviceinfo").read_text(encoding="utf-8")
    flash = recipe["flash"]
    for line in (
        f'deviceinfo_codename="{device}"',
        'deviceinfo_flash_method="fastboot"',
        f'deviceinfo_header_version="{flash["header_version"]}"',
        f'deviceinfo_flash_pagesize="{flash["pagesize"]}"',
    ):
        if line not in deviceinfo:
            raise NonBugError(f"omnipha/ports deviceinfo differs from image.yaml: {line}")
    contents = kernel_apkbuild.read_text(encoding="utf-8")
    device_apkbuild = (source / "APKBUILD").read_text(encoding="utf-8")
    if not re.search(rf"(?m)^pkgname=device-{re.escape(device)}$", device_apkbuild):
        raise NonBugError("omnipha/ports device APKBUILD has a different package name")
    direct_name = re.search(rf"(?m)^pkgname={re.escape(kernel)}$", contents)
    flavor_name = "pkgname=linux-$_flavor" in contents and f'_flavor="{kernel[6:]}"' in contents
    if not direct_name and not flavor_name:
        raise NonBugError("omnipha/ports kernel APKBUILD has a different package name")
    if kernel not in device_apkbuild:
        raise NonBugError("omnipha/ports device does not depend on the pinned kernel")
    if not re.search(rf'(?m)^_vendor_commit="{recipe["kernel"]["commit"]}"$', contents):
        raise NonBugError("image.yaml kernel commit differs from the kernel APKBUILD")
    repo = recipe["kernel"]["repo"]
    if f"https://github.com/{repo}/archive/$_vendor_commit.tar.gz" not in contents:
        raise NonBugError("image.yaml kernel source differs from the kernel APKBUILD")
    target = work / "cache_git" / "image-aports"
    if target.exists():
        raise NonBugError(f"Refusing to overwrite staged pmaports: {target}")
    for package in (f"device-{device}", kernel):
        if list((aports / "device").glob(f"*/{package}")):
            raise NonBugError(f"Pinned pmaports already contains {package}")
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "--quiet", "--no-local", str(aports), str(target)], check=True)
    device_target = target / "device" / "downstream" / f"device-{device}"
    kernel_target = target / "device" / "downstream" / kernel
    (target / "device" / "downstream").mkdir(parents=True, exist_ok=True)
    device_target.mkdir()
    kernel_target.mkdir(parents=True)
    for name in ("APKBUILD", "deviceinfo", "modules-initfs"):
        shutil.copyfile(tracked_input(ports, source / name), device_target / name)
    shutil.copyfile(tracked_input(ports, kernel_apkbuild), kernel_target / "APKBUILD")
    for name in set(re.findall(r"[\w.-]+\.(?:patch|aarch64)", contents)):
        shutil.copyfile(tracked_input(ports, source / name), kernel_target / name)
    return target


def export_images(device: str, partitions: list[str], output: Path) -> None:
    sources = {"userdata": Chroot.native() / f"home/pmos/rootfs/{device}.img"}
    boot = Chroot.rootfs(device) / "boot"
    sources.update({p: boot / f"{p}.img" for p in partitions if p != "userdata"})
    missing = [
        p for p, source in sources.items() if not source.is_file() or not source.stat().st_size
    ]
    if missing:
        raise NonBugError(f"Image artifacts missing: {', '.join(missing)}")
    if output.exists() and any(output.iterdir()):
        raise NonBugError("--output must be empty")
    output.mkdir(parents=True, exist_ok=True)
    sums = []
    for partition, source in sources.items():
        name = f"{device}.img" if partition == "userdata" else source.name
        dest = output / name
        sha = hashlib.sha256()
        with source.open("rb") as infile, dest.open("xb") as outfile:
            while block := infile.read(1024 * 1024):
                outfile.write(block)
                sha.update(block)
        sums.append(f"{sha.hexdigest()}  {name}\n")
    (output / "SHA256SUMS").write_text("".join(sums), encoding="ascii")
    logging.info(f"Images and SHA256SUMS written to {output}")


def image(args: PmbArgs) -> None:
    config = get_context().config
    if args.config == pmb.config.defaults["config"] or args.config.exists():
        raise NonBugError("image requires -c NEW_CONFIG; existing configs are not overwritten")
    recipe = load_recipe(args.image_yaml, args.profile)
    read_public_key(args.ssh_pubkey)
    ports = args.ports.resolve(strict=True)
    aports = config.aports.resolve(strict=True)
    work = config.work.resolve()
    output = args.image_output.resolve()
    if (
        work.exists()
        or work.is_relative_to(aports)
        or work.is_relative_to(ports)
        or args.config.resolve().is_relative_to(aports)
        or args.config.resolve().is_relative_to(ports)
    ):
        raise NonBugError("image requires a new, isolated work directory and config")
    if (
        output.is_relative_to(aports)
        or output.is_relative_to(ports)
        or output.is_relative_to(work)
        or work.is_relative_to(output)
    ):
        raise NonBugError("--output must be outside input repositories and work directory")
    if output.exists() and any(output.iterdir()):
        raise NonBugError("--output must be empty")
    pinned_checkout(ports, args.ports_revision)
    pinned_checkout(aports, args.aports_revision)
    device = recipe["device"]
    work.mkdir(parents=True)
    (work / "version").write_text(f"{pmb.config.work_version}\n")
    stage = stage_ports(ports, aports, work, recipe)
    os.environ["PMB_CHANNELS_CFG"] = str(stage / "channels.cfg")
    config.work = work
    config.aports = stage
    config.device = device
    config.ui = "none"
    config.service_manager = ServiceManagerConfig.OPENRC
    config.kernel = "none"
    config.extra_packages = ",".join(dict.fromkeys(recipe["packages"]))
    config.mirrors["pmaports"] = "none"
    config.ssh_keys = True
    config.ssh_key_glob = str(args.ssh_pubkey.resolve())
    pmb.config.save(args.config, config)
    pmb.config.pmaports.read_config()
    install(
        add="",
        android_recovery_zip=False,
        cipher="aes-xts-plain64",
        cmdline=None,
        filesystem=recipe["flash"]["userdata"]["filesystem"],
        full_disk_encryption=False,
        disk=None,
        install_base=True,
        install_cgpt=False,
        install_local_pkgs=True,
        install_recommends=True,
        iter_time="200",
        no_fde=False,
        no_firewall=False,
        no_image=False,
        no_reboot=False,
        no_sshd=False,
        partition=None,
        password="",
        recovery_flash_kernel=True,
        recovery_install_partition="system",
        resume=False,
        rsync=False,
        sector_size=recipe["flash"]["pagesize"],
        single_partition=True,
        sparse=None,
        split=False,
        verbose=args.verbose,
        zap=False,
    )
    export_images(device, recipe["flash"]["partitions"], output)
