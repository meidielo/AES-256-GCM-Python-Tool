"""Generate release SBOM, checksums, and local provenance metadata.

The output is a reviewability aid for tagged educational releases. It is not a
cryptographic certification, a SLSA attestation, or a production-vault claim.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parents[1]


def run_git(args: list[str], fallback: str = "") -> str:
    try:
        return subprocess.check_output(
            ["git", *args],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        if os.environ.get("RELEASE_ARTIFACTS_DEBUG"):
            print(f"git {' '.join(args)} failed: {exc}", file=sys.stderr)
        return fallback


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_project_metadata() -> dict[str, str]:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_block = re.search(r"(?ms)^\[project\]\s*(.*?)(?:^\[|\Z)", pyproject)
    if not project_block:
        raise RuntimeError("pyproject.toml is missing a [project] section")

    def get_string(key: str) -> str:
        match = re.search(rf'(?m)^{re.escape(key)}\s*=\s*"([^"]+)"', project_block.group(1))
        if not match:
            raise RuntimeError(f"pyproject.toml [project] is missing {key}")
        return match.group(1)

    return {
        "name": get_string("name"),
        "version": get_string("version"),
    }


def parse_requirement(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("-r "):
        return None
    name = re.split(r"\s*(?:===|==|~=|>=|<=|>|<|!=|\[)", stripped, maxsplit=1)[0].strip()
    if not name:
        return None
    return name, stripped


def requirement_components() -> list[dict[str, object]]:
    components: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    sources = [
        ("requirements.txt", "runtime"),
        ("requirements-dev.txt", "development-or-build"),
    ]

    for file_name, scope in sources:
        path = ROOT / file_name
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            parsed = parse_requirement(line)
            if not parsed:
                continue
            name, requirement = parsed
            key = (name.lower(), scope)
            if key in seen:
                continue
            seen.add(key)
            components.append(
                {
                    "type": "library",
                    "bom-ref": f"pkg:pypi/{name.lower()}",
                    "name": name,
                    "purl": f"pkg:pypi/{name.lower()}",
                    "properties": [
                        {"name": "aes-secure-vault:requirement", "value": requirement},
                        {"name": "aes-secure-vault:dependency-scope", "value": scope},
                    ],
                }
            )

    return sorted(components, key=lambda item: (str(item["name"]).lower(), json.dumps(item)))


def posix_relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def collect_subjects(extra_files: list[Path]) -> list[dict[str, object]]:
    dist_files = sorted((ROOT / "dist").glob("*")) if (ROOT / "dist").exists() else []
    files = [
        ROOT / "pyproject.toml",
        ROOT / "requirements.txt",
        ROOT / "requirements-dev.txt",
        ROOT / "README.md",
        ROOT / "LICENSE",
        ROOT / "secure_vault.py",
        ROOT / "test_secure_vault.py",
        *dist_files,
        *extra_files,
    ]
    existing_files = [path for path in files if path.exists() and path.is_file()]
    return [
        {
            "path": posix_relative(path),
            "sha256": sha256(path),
            "bytes": path.stat().st_size,
        }
        for path in existing_files
    ]


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-tag", action="store_true", help="fail unless HEAD is exactly tagged")
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="fail unless the git worktree is clean",
    )
    args = parser.parse_args()

    metadata = read_project_metadata()
    commit = run_git(["rev-parse", "HEAD"], "unknown")
    short_commit = run_git(["rev-parse", "--short", "HEAD"], "unknown")
    branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"], "unknown")
    tag = run_git(["describe", "--tags", "--exact-match", "HEAD"], "")
    status = run_git(["status", "--porcelain"], "")
    dirty = bool(status)

    if args.require_tag and not tag:
        print("release artifacts require HEAD to match a git tag", file=sys.stderr)
        return 1
    if (args.require_clean or args.require_tag) and dirty:
        print("release artifacts require a clean worktree", file=sys.stderr)
        return 1

    release_id = tag or f"{metadata['version']}-{short_commit}"
    out_dir = ROOT / "release-artifacts" / release_id
    out_dir.mkdir(parents=True, exist_ok=True)

    generated_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    root_ref = f"pkg:pypi/{metadata['name']}@{metadata['version']}"
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": generated_at,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "tools/generate_release_artifacts.py",
                        "version": "1",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": metadata["name"],
                "version": metadata["version"],
                "purl": root_ref,
            },
        },
        "components": requirement_components(),
        "properties": [
            {
                "name": "aes-secure-vault:release-boundary",
                "value": "Educational authenticated-encryption tool. SBOM is release transparency, not production vault certification.",
            }
        ],
    }

    sbom_path = out_dir / f"{metadata['name']}-{metadata['version']}.sbom.cdx.json"
    write_json(sbom_path, sbom)

    provenance_path = out_dir / f"{metadata['name']}-{metadata['version']}.provenance.local.json"
    subjects = collect_subjects([sbom_path])
    provenance = {
        "predicateType": "https://mdpstudio.com.au/provenance/local-build/v1",
        "generatedAt": generated_at,
        "subject": {
            "name": metadata["name"],
            "version": metadata["version"],
            "releaseId": release_id,
            "git": {
                "commit": commit,
                "branch": branch,
                "tag": tag or None,
                "dirty": dirty,
            },
        },
        "build": {
            "python": sys.version.split()[0],
            "commands": [
                "python -m pip install -r requirements-dev.txt",
                "python -m pytest test_secure_vault.py -v",
                "python -m build",
                "python tools/generate_release_artifacts.py --require-tag --require-clean",
            ],
        },
        "owaspMapping": [
            {
                "id": "OWASP Top 10:2025 A03",
                "control": "Software supply chain inventory through SBOM generation.",
                "url": "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
            },
            {
                "id": "OWASP Top 10:2025 A08",
                "control": "Release integrity through checksum artifacts and provenance metadata.",
                "url": "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/",
            },
        ],
        "releaseBoundary": "This provenance statement is unsigned local build metadata. It does not claim SLSA compliance, compliance readiness, or production-grade cryptography.",
        "subjects": subjects,
    }
    write_json(provenance_path, provenance)

    checksum_targets = sorted(
        [ROOT / item["path"] for item in subjects] + [provenance_path],
        key=lambda item: item.relative_to(ROOT).as_posix(),
    )
    checksum_path = out_dir / f"{metadata['name']}-{metadata['version']}.sha256"
    checksum_path.write_text(
        "\n".join(f"{sha256(path)}  {posix_relative(path)}" for path in checksum_targets) + "\n",
        encoding="utf-8",
    )

    print(f"Release artifacts written to {posix_relative(out_dir)}")
    print(f"- {posix_relative(sbom_path)}")
    print(f"- {posix_relative(provenance_path)}")
    print(f"- {posix_relative(checksum_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
