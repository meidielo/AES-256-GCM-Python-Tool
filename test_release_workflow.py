from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_release_workflow_exists() -> None:
    text = workflow_text()

    assert "name: Release" in text
    assert "python -m build" in text
    assert "tools/generate_release_artifacts.py --require-tag --require-clean" in text
    assert "gh release upload" in text
    assert "gh release create" in text


def test_release_workflow_attests_artifacts() -> None:
    text = workflow_text()

    assert "id-token: write" in text
    assert "attestations: write" in text
    assert "actions/attest@v4" in text
    assert "subject-path:" in text
    assert "${{ github.workspace }}/dist/*" in text
    assert "release-artifacts/${{ steps.release-id.outputs.release_id }}/*" in text


def test_pypi_publish_is_trusted_publishing_only() -> None:
    text = workflow_text()

    assert "pypa/gh-action-pypi-publish@release/v1" in text
    assert "environment:" in text
    assert "name: pypi" in text
    assert "trusted_publisher_configured" in text
    assert "inputs.publish_to_pypi == true" in text
    assert "https://api.github.com/repos/${GITHUB_REPOSITORY}/environments/pypi" in text
    assert "password:" not in text
    assert "PYPI_API_TOKEN" not in text
    assert "__token__" not in text


def test_pypi_publish_requires_manual_tagged_run() -> None:
    text = workflow_text()

    assert "github.event_name == 'workflow_dispatch' && inputs.publish_to_pypi == true" in text
    assert 'if [[ "${GITHUB_REF}" != refs/tags/v* ]]; then' in text
    assert "PyPI publishing is allowed only from a v* tag" in text
