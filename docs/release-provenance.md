# Release Provenance and SBOM Checklist

AES Secure Vault is an educational and portfolio tool, not production vault
software. Release artifacts improve package reviewability, but they do not
certify the package as compliance-ready or production-grade cryptography.

This checklist addresses OWASP Top 10:2025 A03 Software Supply Chain Failures
and A08 Software or Data Integrity Failures by producing:

- A CycloneDX JSON SBOM generated from the project metadata and requirements
- A SHA-256 checksum manifest for source files and built distribution files
- An unsigned local provenance statement with git commit, tag, build commands,
  Python version, OWASP mapping, and release boundary

## Release Checklist

Run from a clean checkout:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest test_secure_vault.py -v
python -m build
git tag v1.1.0
python tools/generate_release_artifacts.py --require-tag --require-clean
```

If the tag already exists, verify that `git describe --tags --exact-match HEAD`
prints the intended release tag before generating artifacts.

The generated files are written to:

```text
release-artifacts/<tag-or-version-commit>/
```

Expected files:

```text
aes-secure-vault-1.1.0.sbom.cdx.json
aes-secure-vault-1.1.0.provenance.local.json
aes-secure-vault-1.1.0.sha256
```

## GitHub and PyPI Release Upload

Attach the three generated files to the matching GitHub release. If the package
is also published to PyPI, keep the GitHub release linked from the PyPI project
URL so reviewers can find the SBOM and checksums.

Use release-note wording like:

```text
This release publishes SBOM, checksum, and local provenance artifacts for
reviewability. AES Secure Vault remains an educational authenticated-encryption
tool and is not production vault software.
```

Do not describe the SBOM or checksum file as a security certification.

## Verify an Artifact

After downloading a release artifact set:

```bash
sha256sum -c aes-secure-vault-1.1.0.sha256
```

On Windows PowerShell, verify a single file with:

```powershell
Get-FileHash .\aes-secure-vault-1.1.0.sbom.cdx.json -Algorithm SHA256
```
