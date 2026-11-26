"""Restore the verified stock game inputs for the eFootball update guest."""

import hashlib
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
from zipfile import ZipFile


def extract_apks(archive_path, destination, expected):
    with ZipFile(archive_path) as archive:
        for entry in archive.infolist():
            relative = PurePosixPath("apks", PurePosixPath(entry.filename).name)
            if not entry.is_dir() and relative in expected:
                with archive.open(entry) as source, (destination / relative).open("xb") as target:
                    shutil.copyfileobj(source, target)


def extract_packs(destination, expected):
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
        for entry in archive:
            _, separator, suffix = entry.name.partition("/assetpacks/")
            if not separator or not entry.isfile():
                continue
            parts = PurePosixPath(suffix).parts
            if parts[1:3] != ("311010001", "311010001"):
                continue
            relative = PurePosixPath("verified-packs", parts[0], "311010101", *parts[2:])
            if relative in expected:
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(entry) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)


def verify(destination, expected):
    actual = set()
    for path in destination.rglob("*"):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise ValueError(f"Unexpected cache entry {path.relative_to(destination)}")
        if path.is_file():
            relative = path.relative_to(destination)
            actual.add(relative)
            with path.open("rb") as data:
                digest = hashlib.file_digest(data, "sha256").hexdigest()
            if digest != expected.get(relative):
                raise ValueError(f"Checksum mismatch or unexpected file {relative}")
    missing = expected.keys() - actual
    if missing:
        raise ValueError(f"Missing cache file {min(missing)}")
    print(f"Verified {len(actual)} stock APK and asset files")


def main():
    mode, cache_path, manifest_path, *arguments = sys.argv[1:]
    destination = Path(cache_path)
    expected = {}
    for line in Path(manifest_path).read_text().splitlines():
        digest, name = line.split()
        expected[PurePosixPath(name)] = digest

    if mode == "extract":
        (destination / "apks").mkdir(parents=True)
        extract_apks(arguments[0], destination, expected)
        extract_packs(destination, expected)
    elif mode != "verify":
        raise ValueError(f"Unknown mode {mode}")
    verify(destination, expected)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, tarfile.TarError) as error:
        sys.exit(str(error))
