"""Promote a verified Actions artifact; keep private evidence out of public assets."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import urllib.parse
import urllib.request
import zipfile

stage = Path("staging")
stage.mkdir(exist_ok=True)


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


if "--verify-upload" in sys.argv:
    receipt = json.loads((stage / "upload-receipt.json").read_text())
    context = json.loads((stage / "context.json").read_text())
    version = context["version"]
    assert receipt["draft"] and receipt["prerelease"]
    expected_names = {
        f"Melogen.Desktop.Setup-{version}-x64.exe",
        f"verification-{version}-windows.json",
    }
    assert {asset["name"] for asset in receipt["assets"]} == expected_names
    for asset in receipt["assets"]:
        file = stage / asset["name"]
        assert asset["state"] == "uploaded"
        assert asset["size"] == file.stat().st_size
        assert asset["digest"] == "sha256:" + digest(file)
    print("release_asset_digests_verified")
    raise SystemExit(0)

context = json.loads(os.environ["VERIFICATION_CONTEXT"])
version = context["version"]
assert re.fullmatch(r"\d+\.\d+\.\d+", version)
for name in ("source_commit", "source_head", "source_tree", "integrated_main_commit"):
    assert re.fullmatch(r"[a-f0-9]{40}", context[name])
assert re.fullmatch(r"[a-f0-9]{64}", context["archive_sha256"])
assert context["source_ci_conclusion"] == "success"
assert context["integrated_tree_equals_build_tree"] is True
backend = context["backend"]
assert re.fullmatch(r"[a-f0-9]{40}", backend["source_commit"])
for check in (
    "zero_credit_rejection", "ultra_tool_roundtrip",
    "image_generation", "wallet_reconciliation", "duplicate_request",
    "synthetic_account_cleanup",
):
    assert backend["verification"][check] == "passed", check
assert backend["verification"]["encrypted_reasoning_replay"] in {"passed", "not_emitted"}

# The short-lived URL grants read access to this artifact only. No cross-repository
# account credential is sent to the runner, and the URL is never printed or saved.
url = os.environ["SIGNED_ARTIFACT_URL"]
parsed = urllib.parse.urlsplit(url)
assert parsed.scheme == "https" and parsed.hostname.endswith(".blob.core.windows.net")
archive_path = stage / "candidate.zip"
try:
    with urllib.request.urlopen(url, timeout=60) as response, archive_path.open("wb") as file:
        shutil.copyfileobj(response, file, 1024 * 1024)
except Exception as error:
    raise RuntimeError("Artifact transfer failed: " + type(error).__name__) from None
assert digest(archive_path) == context["archive_sha256"], "Artifact archive digest mismatch"

release_root = "electron-app/release/"
evidence_root = release_root + f"evidence-{version}/"
with zipfile.ZipFile(archive_path) as archive:
    candidate = json.loads(archive.read(evidence_root + "candidate.json"))
    installation = json.loads(archive.read(release_root + "windows-install-smoke.json").decode("utf-8-sig"))
    assert candidate["version"] == version and candidate["platform"] == "win32"
    assert candidate["arch"] == "x64" and candidate["status"] == "candidate_verified"
    assert candidate["source"]["commit"] == context["source_commit"]
    assert candidate["source"]["dirty"] is False
    expected_checks = {
        "root-tests", "desktop-tests", "typecheck", "strict-resources", "installer",
        "package-crt", "package-smoke", "package-graph", "source-ui", "package-media",
        "package-melody-cpu", "package-native", "package-ui",
    }
    assert {check["name"] for check in candidate["checks"]} == expected_checks
    for check in candidate["checks"]:
        assert check["status"] == "passed", check["name"]
        assert hashlib.sha256(archive.read(evidence_root + check["log"])).hexdigest() == check["log_sha256"]
    assert hashlib.sha256(archive.read(evidence_root + "source-files.json")).hexdigest() == candidate["source"]["file_manifest_sha256"]
    assert installation["status"] == "passed" and installation["version"] == version
    assert installation["candidate"]["installer_sha256"] == candidate["artifact"]["sha256"]
    checks = {check["name"]: check for check in installation["checks"]}
    assert set(checks) == {"clean", "clean-uninstall", "upgrade", "upgrade-uninstall"}
    assert all(check["status"] == "passed" for check in checks.values())
    for name in ("clean", "upgrade"):
        assert checks[name]["asar_sha256"] == candidate["artifact"]["asar_sha256"]
    assert checks["clean"]["exe_sha256"] == checks["upgrade"]["exe_sha256"]
    installer = stage / f"Melogen.Desktop.Setup-{version}-x64.exe"
    with archive.open(release_root + f"Melogen Desktop-Setup-{version}-x64.exe") as source, installer.open("wb") as output:
        shutil.copyfileobj(source, output, 1024 * 1024)

assert installer.stat().st_size == candidate["artifact"]["bytes"]
assert digest(installer) == candidate["artifact"]["sha256"]
with installer.open("rb") as file:
    assert file.read(2) == b"MZ"
verification = {
    "schema_version": 1,
    "version": version, "platform": "win32", "arch": "x64",
    "release_tag": f"v{version}-windows", "channel": "public-preview",
    **{key: context[key] for key in (
        "source_commit", "source_head", "source_tree", "integrated_main_commit",
        "integrated_tree_equals_build_tree", "source_ci_run", "source_ci_conclusion",
        "archive_sha256",
    )},
    "artifact": {**candidate["artifact"], "file": installer.name},
    "signature": {"authenticode_verified": all(item["Status"] == 0 for item in candidate["signatures"])},
    "checks": [{key: check[key] for key in ("name", "status", "log_sha256")} for check in candidate["checks"]],
    "installation": {
        "status": installation["status"], "completed_at": installation["completed_at"],
        "upgrade_source_version": installation["upgrade_source"]["version"],
        "checks": [{"name": name, "status": check["status"]} for name, check in checks.items()],
        "asar_sha256": candidate["artifact"]["asar_sha256"],
    },
    "backend": backend,
    "verification_limits": [
        "Unsigned public preview; not promoted to the stable update feed.",
        "No manual music-quality listening or full signed-in desktop cloud workflow.",
        "Backend paid canary validates service-level usage, settlement, and replay.",
        "No macOS packaging or release change.",
    ],
}
if backend["verification"]["encrypted_reasoning_replay"] == "not_emitted":
    verification["verification_limits"].append(
        "Encrypted continuation replay passed regression tests; this bounded production canary did not emit an encrypted reasoning item."
    )
(stage / f"verification-{version}-windows.json").write_text(json.dumps(verification, indent=2) + "\n")
(stage / "context.json").write_text(json.dumps(context))
(stage / "release-notes.md").write_text(
    f"Windows x64 {version} public preview.\n\n"
    "- Adds the Fast and Ultra built-in model tiers.\n"
    "- Adds image generation with PNG preview/export and durable task recovery.\n"
    "- Settles credits from actual usage and provides the upgrade entry when credits are insufficient.\n\n"
    "Full CI candidate checks, clean installation, upgrade from the pinned "
    f"{installation['upgrade_source']['version']} baseline, and uninstall passed. "
    "Backend tool continuation, image generation, duplicate-request protection, and actual credit settlement passed a bounded production canary. "
    "See the attached verification JSON for exact hashes and scope.\n\n"
    "This is an unsigned public preview; Windows may show an unrecognized-publisher warning. "
    "It does not promote the stable update feed or replace a macOS release. "
    "Manual music-quality listening and a complete signed-in desktop cloud workflow are outside this verification.\n"
)
print(json.dumps({"candidate_verified": True, "version": version, "artifact": verification["artifact"]}))
