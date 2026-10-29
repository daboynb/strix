#!/usr/bin/env python3
"""Extract a bundle tarball only if every member is safe.

Usage: python3 -I tar_safe_extract.py <bundle.tar.gz> <dest-dir> <allowed-top-dir>...

Fails (exit 1) on absolute paths, '..' components, entries outside the allowed
top-level directories, device/fifo members, and symlinks/hardlinks whose target
resolves outside the archive root. Extraction then uses the stdlib 'tar' filter
(the 'data' filter of some 3.10/3.11 backports misjudges relative symlinks).
"""
import os
import posixpath
import sys
import tarfile


def check(members, allowed):
    errors = []
    for m in members:
        name = m.name
        parts = name.split("/")
        if name.startswith("/") or ".." in parts:
            errors.append(f"unsafe path: {name}")
            continue
        if parts[0] not in allowed:
            errors.append(f"unexpected top-level entry: {name}")
        if not (m.isfile() or m.isdir() or m.issym() or m.islnk()):
            errors.append(f"unsupported member type: {name}")
        if m.issym() or m.islnk():
            target = m.linkname
            if target.startswith("/"):
                errors.append(f"absolute link target: {name} -> {target}")
                continue
            base = posixpath.dirname(name) if m.issym() else ""
            resolved = posixpath.normpath(posixpath.join(base, target))
            if resolved == ".." or resolved.startswith("../"):
                errors.append(f"link escapes archive: {name} -> {target}")
    return errors


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    bundle, dest, allowed = sys.argv[1], sys.argv[2], set(sys.argv[3:])
    with tarfile.open(bundle, "r:gz") as tar:
        members = tar.getmembers()
        errors = check(members, allowed)
        if errors:
            for e in errors[:50]:
                print(f"FAIL: {e}", file=sys.stderr)
            sys.exit(f"FAIL: {len(errors)} unsafe tar member(s) in {bundle}")
        os.makedirs(dest, exist_ok=True)
        tar.extractall(dest, filter="tar")
    print(f"PASS: {len(members)} members, no traversal, extracted to {dest}")


if __name__ == "__main__":
    main()
