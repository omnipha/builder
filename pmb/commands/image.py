# Copyright 2026 Gregor Sprint
# SPDX-License-Identifier: GPL-3.0-or-later
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
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


STOCK_SHA256 = {
    "stock_boot": "197aff11679301ca4a2d6f74dfcb942c3543ac9d41628e4e2116af0bdb706d4d",
    "stock_init_boot": "baa33fd43c3da1d9f3358ced9249c42abecc704fc5707a5241ea69e77c1e3193",
    "stock_vendor_boot": "237259404601045205715a71b88016744c73729d4513349cfe90c754b0dc1253",
    "stock_dtbo": "759813dbfd94f4a4124b08afb2c9ef85f1f9afb7cdca9829be2558ffde13c992",
    "stock_vbmeta": "cc1926d2aa8e9c12df6a469111bf87f1e61e70022b84626fabcd014ae33cdffe",
}
BOOT_INPUTS = {
    "kernel",
    "generic_ramdisk",
    "vendor_ramdisk",
    "dtbs",
    "dtbo",
    "bootconfig",
    "stock_boot",
    "stock_init_boot",
    "stock_vendor_boot",
    "stock_dtbo",
    "stock_vbmeta",
}

BOOT_PARTITIONS = ("boot", "init_boot", "vendor_boot", "dtbo", "vbmeta")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
INPUT_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]*\Z")


def require_layout(condition: bool, message: str) -> None:
    if not condition:
        raise NonBugError(f"boot layout: {message}")


def u32(blob: bytes, offset: int, byteorder: str = "<") -> int:
    require_layout(offset + 4 <= len(blob), "truncated structure")
    return struct.unpack_from(f"{byteorder}I", blob, offset)[0]


def aligned(size: int, page: int = 4096) -> int:
    return (size + page - 1) // page * page


def payload(blob: bytes, start: int, size: int) -> bytes:
    require_layout(start + size <= len(blob), "truncated payload")
    return blob[start : start + size]


def fdt_entries(blob: bytes, count: int) -> list[bytes]:
    entries = []
    offset = 0
    for index in range(count):
        require_layout(payload(blob, offset, 4) == b"\xd0\x0d\xfe\xed", f"DTB index {index} magic")
        size = u32(blob, offset + 4, ">")
        require_layout(size >= 40, f"DTB index {index} size")
        entries.append(payload(blob, offset, size))
        offset += size
    require_layout(offset == len(blob), "DTB count or trailing bytes differ")
    return entries


def dtbo_entries(blob: bytes) -> list[bytes]:
    require_layout(payload(blob, 0, 4) == b"\xd7\xb7\xab\x1e", "DTBO table magic")
    total, header, entry_size, count, offset, page, version = struct.unpack_from(
        ">7I", payload(blob, 4, 28)
    )
    require_layout(
        total <= len(blob)
        and total >= 32
        and header == 32
        and entry_size == 32
        and count == 76
        and offset == 32
        and page == 4096
        and version == 0
        and offset + count * entry_size <= total,
        "DTBO table geometry (76 ordered entries, v0, 4096-byte pages) differs",
    )
    entries = []
    for index in range(count):
        size, start = struct.unpack_from(">II", blob, offset + index * entry_size)
        require_layout(
            size >= 40 and start >= offset + count * entry_size and start + size <= total,
            f"DTBO entry {index} bounds",
        )
        entry = payload(blob, start, size)
        require_layout(
            entry[:4] == b"\xd0\x0d\xfe\xed" and u32(entry, 4, ">") == size,
            f"DTBO entry {index} FDT size",
        )
        entries.append(entry)
    return entries


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def read_boot_layout(
    recipe_path: Path, manifest_path: Path, directory: Path
) -> tuple[dict[str, Any], dict[str, bytes]]:
    try:
        recipe = yaml.safe_load(recipe_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError, ValueError) as exception:
        raise NonBugError(
            f"boot layout: cannot read image.yaml or boot-layout manifest: {exception}"
        ) from exception
    require_layout(
        field(recipe, "device", str) == "nothing-asteroids"
        and field(recipe, "profile", str) == "server",
        "expected nothing-asteroids server recipe",
    )
    flash = field(recipe, "flash", dict)
    require_layout(
        flash.get("method") == "fastboot"
        and type(flash.get("header_version")) is int
        and flash.get("header_version") == 4
        and type(flash.get("pagesize")) is int
        and flash.get("pagesize") == 4096
        and flash.get("slots") == "ab"
        and flash.get("vbmeta") == "disable-verification"
        and flash.get("partitions") == ["boot", "vendor_boot", "dtbo", "vbmeta", "userdata"]
        and field(flash, "userdata", dict).get("filesystem") == "f2fs"
        and field(flash, "userdata", dict).get("encryption") == "metadata",
        "recipe requires A/B header v4, metadata-encrypted userdata and disable-verification",
    )
    require_layout(
        type(manifest) is dict
        and set(manifest)
        == {
            "version",
            "device",
            "slot",
            "recipe_sha256",
            "inputs",
            "dtb_sha256",
            "dtbo_sha256",
            "dtb_index",
            "dtbo_index",
            "headers",
            "partition_sizes",
        },
        "missing or unsupported per-input hashed/provenance boot-layout manifest",
    )
    require_layout(
        type(manifest["version"]) is int
        and type(manifest["dtb_index"]) is int
        and type(manifest["dtbo_index"]) is int
        and manifest["version"] == 1
        and manifest["device"] == recipe["device"]
        and type(manifest["recipe_sha256"]) is str
        and manifest["recipe_sha256"] == sha(recipe_path.read_bytes())
        and manifest["slot"] == "a"
        and manifest["dtb_index"] == 9
        and manifest["dtbo_index"] == 65,
        "slot-A DTB 9 / DTBO 65 selection differs",
    )
    sizes = manifest["partition_sizes"]
    require_layout(
        type(sizes) is dict
        and set(sizes) == set(BOOT_PARTITIONS)
        and all(
            type(value) is int and 4096 <= value <= 128 * 1024 * 1024 and value % 4096 == 0
            for value in sizes.values()
        ),
        "missing or invalid slot-A partition bounds",
    )
    for key, count in (("dtb_sha256", 20), ("dtbo_sha256", 76)):
        hashes = manifest[key]
        require_layout(
            type(hashes) is list
            and len(hashes) == count
            and all(type(value) is str and SHA256.fullmatch(value) for value in hashes),
            f"missing ordered {key} per-entry hashes",
        )
    headers = manifest["headers"]
    require_layout(
        type(headers) is dict
        and set(headers)
        == {
            "boot_cmdline",
            "init_boot_cmdline",
            "vendor_cmdline",
            "kernel_offset",
            "ramdisk_offset",
            "tags_offset",
            "dtb_offset",
            "os_version",
        },
        "missing pinned header fields",
    )
    for key in ("boot_cmdline", "init_boot_cmdline", "vendor_cmdline"):
        require_layout(
            type(headers[key]) is str
            and headers[key].isascii()
            and "\x00" not in headers[key]
            and len(headers[key]) < (2048 if key == "vendor_cmdline" else 1536),
            f"invalid {key}",
        )
    for key, value in (
        ("kernel_offset", 0x8000),
        ("ramdisk_offset", 0x1000000),
        ("tags_offset", 0x100),
        ("dtb_offset", 0x1F00000),
        ("os_version", 0),
    ):
        require_layout(
            type(headers[key]) is int and headers[key] == value,
            f"{key} differs from verified stock header geometry",
        )
    inputs = manifest["inputs"]
    require_layout(
        type(inputs) is dict and set(inputs) == BOOT_INPUTS,
        "missing required kernel, ramdisks, DTBs, DTBO, bootconfig or stock references",
    )
    data = {}
    for key in sorted(BOOT_INPUTS):
        entry = inputs[key]
        require_layout(
            type(entry) is dict and set(entry) == {"file", "sha256", "provenance", "verification"},
            f"{key} needs file, SHA-256, provenance and verification method",
        )
        name = entry["file"]
        require_layout(
            type(name) is str
            and INPUT_NAME.fullmatch(name) is not None
            and name not in (".", "..")
            and type(entry["sha256"]) is str
            and SHA256.fullmatch(entry["sha256"]) is not None
            and all(
                type(entry[k]) is str and len(entry[k].strip()) >= 12
                for k in ("provenance", "verification")
            ),
            f"{key} has unsafe filename, hash or missing provenance/verification",
        )
        source = directory / name
        require_layout(
            not source.is_symlink()
            and source.is_file()
            and 0 < source.stat().st_size < 128 * 1024 * 1024,
            f"{key} missing or unsafe input",
        )
        data[key] = source.read_bytes()
        require_layout(sha(data[key]) == entry["sha256"], f"{key} SHA-256 mismatch")
    require_layout(
        len({entry["file"] for entry in inputs.values()}) == len(BOOT_INPUTS),
        "boot inputs must use distinct files",
    )
    for key, digest in STOCK_SHA256.items():
        require_layout(
            sha(data[key]) == digest, f"{key} reference differs from #10 verifier SHA-256"
        )
    return manifest, data


def stock_avb_descriptors(blob: bytes) -> list[tuple[int, bytes]]:
    require_layout(payload(blob, 0, 4) == b"AVB0", "stock AVB0 header missing")
    auth, aux = struct.unpack_from(">QQ", blob, 12)
    offset, length = struct.unpack_from(">QQ", blob, 96)
    require_layout(
        offset + length <= aux and 256 + auth + aux <= len(blob), "stock AVB metadata out of bounds"
    )
    start = 256 + auth + offset
    end = start + length
    descriptors = []
    while start < end:
        require_layout(start + 16 <= end, "stock AVB descriptor header truncated")
        tag, size = struct.unpack_from(">QQ", blob, start)
        require_layout(size > 0 and start + 16 + size <= end, "stock AVB descriptor truncated")
        descriptors.append((tag, blob[start + 16 : start + 16 + size]))
        start += 16 + size
    return descriptors


def stock_avb_hashes(blob: bytes) -> dict[bytes, tuple[int, bytes, bytes]]:
    hashes = {}
    for tag, body in stock_avb_descriptors(blob):
        if tag != 2:
            continue
        require_layout(len(body) >= 116, "stock AVB hash descriptor truncated")
        size = struct.unpack_from(">Q", body)[0]
        name_len, salt_len, digest_len, flags = struct.unpack_from(">IIII", body, 40)
        require_layout(
            body[8:40].split(b"\0", 1)[0] == b"sha256"
            and digest_len == 32
            and flags == 0
            and 116 + name_len + salt_len + digest_len <= len(body),
            "stock AVB hash descriptor format differs",
        )
        name = body[116 : 116 + name_len]
        require_layout(name not in hashes, "duplicate stock AVB hash descriptor")
        hashes[name] = (
            size,
            body[116 + name_len : 116 + name_len + salt_len],
            body[116 + name_len + salt_len : 116 + name_len + salt_len + digest_len],
        )
    return hashes


def verify_stock_avb(data: dict[str, bytes]) -> None:
    root = stock_avb_hashes(data["stock_vbmeta"])
    require_layout(
        set(root) == {b"dtbo", b"init_boot", b"vendor_boot"},
        "stock vbmeta must hash dtbo/init_boot/vendor_boot",
    )
    chains = [body for tag, body in stock_avb_descriptors(data["stock_vbmeta"]) if tag == 4]
    require_layout(
        any(
            len(body) >= 84
            and struct.unpack_from(">I", body, 4)[0] == 4
            and body[76:80] == b"boot"
            and struct.unpack_from(">I", body)[0] == 3
            for body in chains
        ),
        "stock vbmeta must chain boot at rollback location 3",
    )
    for name in ("boot", "init_boot", "vendor_boot"):
        stock = data[f"stock_{name}"]
        footer = payload(stock, len(stock) - 64, 64)
        require_layout(footer[:4] == b"AVBf", f"stock {name} AVB footer missing")
        original, offset, size = struct.unpack_from(">QQQ", footer, 12)
        require_layout(
            original == offset and offset + size <= len(stock) - 64,
            f"stock {name} AVB footer bounds differ",
        )
        embedded = stock_avb_hashes(payload(stock, offset, size))
        require_layout(name.encode() in embedded, f"stock {name} embedded hash missing")
        length, salt, digest = embedded[name.encode()]
        require_layout(
            length == original and hashlib.sha256(salt + stock[:length]).digest() == digest,
            f"stock {name} AVB hash differs from footer",
        )
        if name != "boot":
            require_layout(
                root[name.encode()] == embedded[name.encode()],
                f"stock vbmeta {name} hash differs from embedded descriptor",
            )
    size, salt, digest = root[b"dtbo"]
    require_layout(
        size <= len(data["stock_dtbo"])
        and hashlib.sha256(salt + data["stock_dtbo"][:size]).digest() == digest,
        "stock vbmeta dtbo hash differs",
    )


def stock_bootconfig(vendor: bytes) -> bytes:
    start = 4096 + aligned(u32(vendor, 24)) + aligned(u32(vendor, 2100))
    require_layout(
        u32(vendor, 2112) == 108
        and u32(vendor, 2116) == 1
        and u32(vendor, 2120) == 108
        and u32(vendor, 2124) == 175,
        "stock vendor ramdisk table or bootconfig differs",
    )
    require_layout(
        payload(vendor, start, 108) == struct.pack("<III", u32(vendor, 24), 0, 1) + bytes(96),
        "stock vendor PLATFORM ramdisk table differs",
    )
    return payload(vendor, start + 4096, 175)


def verify_layout(manifest: dict[str, Any], data: dict[str, bytes]) -> None:
    stock_vendor = data["stock_vendor_boot"]
    require_layout(
        payload(stock_vendor, 0, 8) == b"VNDRBOOT"
        and u32(stock_vendor, 8) == 4
        and u32(stock_vendor, 12) == 4096
        and u32(stock_vendor, 2096) == 2128,
        "stock vendor_boot header v4 differs",
    )
    dtb_start = 4096 + aligned(u32(stock_vendor, 24))
    stock_dtbs = fdt_entries(payload(stock_vendor, dtb_start, u32(stock_vendor, 2100)), 20)
    built_dtbs = fdt_entries(data["dtbs"], 20)
    for index, (stock, built, digest) in enumerate(
        zip(stock_dtbs, built_dtbs, manifest["dtb_sha256"], strict=True)
    ):
        require_layout(
            sha(stock) == sha(built) == digest,
            f"DTB index {index} SHA-256 differs from pinned stock overlay set",
        )
    stock_overlays = dtbo_entries(data["stock_dtbo"])
    overlays = dtbo_entries(data["dtbo"])
    for index, (entry, digest) in enumerate(zip(overlays, manifest["dtbo_sha256"], strict=True)):
        require_layout(sha(entry) == digest, f"DTBO entry {index} SHA-256 mismatch")
    require_layout(
        data["dtbo"] == data["stock_dtbo"] and overlays[65] == stock_overlays[65],
        "DTBO table or entry 65 differs from pinned stock overlay set",
    )
    with tempfile.TemporaryDirectory(prefix="boot-layout-") as temporary:
        base = Path(temporary) / "base.dtb"
        overlay = Path(temporary) / "overlay.dtbo"
        base.write_bytes(built_dtbs[9])
        overlay.write_bytes(overlays[65])
        try:
            result = subprocess.run(
                [
                    "fdtoverlay",
                    "-i",
                    str(base),
                    "-o",
                    str(Path(temporary) / "combined.dtb"),
                    str(overlay),
                ],
                capture_output=True,
                check=False,
            )
        except OSError as exception:
            raise NonBugError(
                "boot layout: fdtoverlay required to verify stock DTBO 65"
            ) from exception
        require_layout(
            result.returncode == 0, "stock DTBO entry 65 does not apply to vendor DTB index 9"
        )
    for key in ("kernel", "generic_ramdisk", "vendor_ramdisk"):
        require_layout(data[key][:2] == b"\x1f\x8b", f"{key} must be gzip-compressed")
    for key in ("stock_boot", "stock_init_boot"):
        stock = data[key]
        require_layout(
            stock[:8] == b"ANDROID!"
            and u32(stock, 40) == 4
            and u32(stock, 20) == 1584
            and u32(stock, 16) == 0,
            f"{key} stock header v4 / OS version differs",
        )
    require_layout(
        u32(data["stock_boot"], 12) == 0
        and u32(data["stock_init_boot"], 8) == 0
        and u32(data["stock_init_boot"], 12) > 0,
        "generic ramdisk must live in init_boot, not boot",
    )
    verify_stock_avb(data)
    require_layout(
        data["bootconfig"] == stock_bootconfig(stock_vendor),
        "vendor bootconfig differs from verified stock bootconfig",
    )


def padded(blob: bytes) -> bytes:
    return blob + bytes(aligned(len(blob)) - len(blob))


def boot_header(kernel: bytes, ramdisk: bytes, cmdline: str) -> bytes:
    header = (
        b"ANDROID!"
        + struct.pack("<IIII", len(kernel), len(ramdisk), 0, 1584)
        + bytes(16)
        + struct.pack("<I", 4)
        + cmdline.encode().ljust(1536, b"\0")
        + struct.pack("<I", 0)
    )
    return padded(header) + padded(kernel) + padded(ramdisk)


def build_boot_images(manifest: dict[str, Any], data: dict[str, bytes]) -> dict[str, bytes]:
    headers = manifest["headers"]
    kernel, generic, vendor = (data[key] for key in ("kernel", "generic_ramdisk", "vendor_ramdisk"))
    vendor_header = (
        b"VNDRBOOT"
        + struct.pack(
            "<IIIII", 4, 4096, headers["kernel_offset"], headers["ramdisk_offset"], len(vendor)
        )
        + headers["vendor_cmdline"].encode().ljust(2048, b"\0")
        + struct.pack("<I", headers["tags_offset"])
        + bytes(16)
        + struct.pack(
            "<IIQIIII",
            2128,
            len(data["dtbs"]),
            headers["dtb_offset"],
            108,
            1,
            108,
            len(data["bootconfig"]),
        )
    )
    table = struct.pack("<III", len(vendor), 0, 1) + bytes(96)
    vbmeta = bytearray(4096)
    vbmeta[:4] = b"AVB0"
    struct.pack_into(">II", vbmeta, 4, 1, 0)
    struct.pack_into(">I", vbmeta, 120, 2)
    vbmeta[128 : 128 + len(b"omnipha-unsigned")] = b"omnipha-unsigned"
    return {
        "boot": boot_header(kernel, b"", headers["boot_cmdline"]),
        "init_boot": boot_header(b"", generic, headers["init_boot_cmdline"]),
        "vendor_boot": (
            padded(vendor_header)
            + padded(vendor)
            + padded(data["dtbs"])
            + padded(table)
            + data["bootconfig"]
        ),
        "dtbo": data["dtbo"],
        "vbmeta": bytes(vbmeta),
    }


def verify_boot_images(
    manifest: dict[str, Any], data: dict[str, bytes], images: dict[str, bytes]
) -> None:
    require_layout(set(images) == set(BOOT_PARTITIONS), "missing output partition")
    for name in BOOT_PARTITIONS:
        require_layout(
            0 < len(images[name]) <= manifest["partition_sizes"][name],
            f"{name}_a exceeds pinned partition bound",
        )
    for name, kernel, ramdisk in (
        ("boot", data["kernel"], b""),
        ("init_boot", b"", data["generic_ramdisk"]),
    ):
        image = images[name]
        require_layout(
            payload(image, 0, 8) == b"ANDROID!"
            and u32(image, 40) == 4
            and u32(image, 20) == 1584
            and u32(image, 16) == 0
            and u32(image, 1580) == 0,
            f"{name} header v4 / OS version differs",
        )
        require_layout(
            u32(image, 8) == len(kernel)
            and u32(image, 12) == len(ramdisk)
            and payload(image, 44, 1536).split(b"\0", 1)[0]
            == manifest["headers"][f"{name}_cmdline"].encode(),
            f"{name} header contents differ",
        )
        require_layout(
            payload(image, 4096, len(kernel)) == kernel
            and payload(image, 4096 + aligned(len(kernel)), len(ramdisk)) == ramdisk
            and len(image) == 4096 + aligned(len(kernel)) + aligned(len(ramdisk)),
            f"{name} payload or padding differs",
        )
    vendor = images["vendor_boot"]
    ramdisk = data["vendor_ramdisk"]
    require_layout(
        payload(vendor, 0, 8) == b"VNDRBOOT"
        and u32(vendor, 8) == 4
        and u32(vendor, 12) == 4096
        and u32(vendor, 16) == 0x8000
        and u32(vendor, 20) == 0x1000000
        and u32(vendor, 24) == len(ramdisk)
        and u32(vendor, 2076) == 0x100
        and u32(vendor, 2096) == 2128
        and u32(vendor, 2100) == len(data["dtbs"])
        and struct.unpack_from("<Q", vendor, 2104)[0] == 0x1F00000
        and (u32(vendor, 2112), u32(vendor, 2116), u32(vendor, 2120)) == (108, 1, 108)
        and u32(vendor, 2124) == len(data["bootconfig"])
        and len(data["bootconfig"]) == 175,
        "vendor_boot header v4 geometry / ramdisk table differs",
    )
    require_layout(
        payload(vendor, 28, 2048).split(b"\0", 1)[0]
        == manifest["headers"]["vendor_cmdline"].encode(),
        "vendor cmdline differs",
    )
    dtb_start = 4096 + aligned(len(ramdisk))
    table_start = dtb_start + aligned(len(data["dtbs"]))
    require_layout(
        payload(vendor, 4096, len(ramdisk)) == ramdisk
        and payload(vendor, dtb_start, len(data["dtbs"])) == data["dtbs"]
        and payload(vendor, table_start, 108) == struct.pack("<III", len(ramdisk), 0, 1) + bytes(96)
        and payload(vendor, table_start + 4096, len(data["bootconfig"])) == data["bootconfig"]
        and len(vendor) == table_start + 4096 + len(data["bootconfig"]),
        "vendor_boot DTB order, PLATFORM ramdisk or bootconfig differs",
    )
    require_layout(images["dtbo"] == data["dtbo"], "DTBO table differs")
    for name in ("boot", "init_boot", "vendor_boot"):
        require_layout(images[name][-64:-60] != b"AVBf", f"{name} must not reuse stock AVB footer")
    vbmeta = images["vbmeta"]
    require_layout(
        len(vbmeta) == 4096
        and vbmeta[:4] == b"AVB0"
        and struct.unpack_from(">II", vbmeta, 4) == (1, 0)
        and all(byte == 0 for byte in vbmeta[12:120])
        and u32(vbmeta, 120, ">") == 2
        and all(byte == 0 for byte in vbmeta[124:128])
        and vbmeta[128 : 128 + len(b"omnipha-unsigned")] == b"omnipha-unsigned"
        and all(byte == 0 for byte in vbmeta[128 + len(b"omnipha-unsigned") :]),
        "vbmeta must be unsigned AVB0 flags=2 without descriptors or keys",
    )


def boot_chain(args: PmbArgs) -> None:
    root = Path(__file__).resolve().parents[2]
    try:
        directory = args.input_dir.resolve(strict=True)
        recipe = args.image_yaml.resolve(strict=True)
        manifest_path = args.layout_manifest.resolve(strict=True)
    except OSError as exception:
        raise NonBugError(
            f"boot layout: missing recipe, manifest or input directory: {exception}"
        ) from exception
    output = args.image_output.resolve()
    for path in (recipe, manifest_path, directory, output):
        if path.is_relative_to(root):
            raise NonBugError("boot layout: inputs and artifacts must stay outside this repository")
    if (
        output.is_relative_to(directory)
        or directory.is_relative_to(output)
        or output.exists()
        or not output.parent.is_dir()
        or output.is_symlink()
    ):
        raise NonBugError("boot layout: output must be new and outside input directory")
    manifest, data = read_boot_layout(recipe, manifest_path, directory)
    verify_layout(manifest, data)
    images = build_boot_images(manifest, data)
    verify_boot_images(manifest, data, images)
    with tempfile.TemporaryDirectory(prefix="boot-chain-", dir=output.parent) as temp:
        staged = Path(temp)
        sums = []
        for name in BOOT_PARTITIONS:
            filename = f"{name}.img"
            (staged / filename).write_bytes(images[name])
            sums.append(f"{sha(images[name])}  {filename}\n")
        (staged / "SHA256SUMS").write_text("".join(sums), encoding="ascii")
        (staged / "partition-map.json").write_text(
            json.dumps({name: f"{name}_a" for name in BOOT_PARTITIONS}, sort_keys=True) + "\n",
            encoding="ascii",
        )
        staged.rename(output)
    logging.info(f"Validated slot-A-only boot images and byte-level SHA256SUMS written to {output}")
