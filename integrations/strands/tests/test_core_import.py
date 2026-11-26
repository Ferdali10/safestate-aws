"""Verify that safestate_core resolves to the shared Core via symlink, not a vendored copy."""
from __future__ import annotations

import os
from pathlib import Path

import safestate_core


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SHARED_CORE = REPO_ROOT / "core" / "safestate_core"
STRANDS_DIR = Path(__file__).resolve().parent.parent
LOCAL_LINK = STRANDS_DIR / "safestate_core"


class TestCoreImportResolution:
    def test_local_safestate_core_is_symlink_not_copy(self):
        assert LOCAL_LINK.is_symlink(), (
            f"{LOCAL_LINK} exists but is not a symlink — the Core must not be copied"
        )

    def test_symlink_resolves_to_shared_core(self):
        resolved = LOCAL_LINK.resolve()
        assert resolved == SHARED_CORE, (
            f"Symlink resolves to {resolved}, expected {SHARED_CORE}"
        )

    def test_imported_core_matches_shared_directory(self):
        core_path = Path(safestate_core.__file__).resolve().parent
        assert core_path == SHARED_CORE, (
            f"safestate_core imported from {core_path}, expected {SHARED_CORE}"
        )

    def test_all_core_modules_importable(self):
        modules = [
            "actions", "approvals", "audit", "controls", "execution",
            "interfaces", "models", "policy", "recovery", "service", "validation",
        ]
        for name in modules:
            mod = __import__(f"safestate_core.{name}")
            submod = getattr(mod, name)
            mod_path = Path(submod.__file__).resolve()
            assert str(SHARED_CORE) in str(mod_path), (
                f"safestate_core.{name} loaded from {mod_path}, not from shared Core"
            )

    def test_key_classes_available(self):
        from safestate_core import (
            ActionType,
            ExecutionGateway,
            JsonlAuditSink,
            SimulatedAWSExecutor,
            AuditedDecisionService,
            DefaultDecisionService,
            ApprovalService,
        )
        from safestate_core.policy import DeterministicPolicyEngine
        from safestate_core.recovery import InMemoryExecutionJournal

        assert DeterministicPolicyEngine is not None
        assert InMemoryExecutionJournal is not None


class TestRuntimeImportWithoutPytestPath:
    """Verify imports work via the symlink alone, without pytest pythonpath assistance."""

    def test_direct_python_import(self):
        import subprocess
        result = subprocess.run(
            [
                str(STRANDS_DIR / ".venv" / "bin" / "python"), "-c",
                "import os; os.chdir(r'" + str(STRANDS_DIR) + "'); "
                "import safestate_core; "
                "from pathlib import Path; "
                "print(Path(safestate_core.__file__).resolve().parent)"
            ],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, f"Import failed: {result.stderr}"
        imported_path = Path(result.stdout.strip())
        assert imported_path == SHARED_CORE

    def test_adapter_importable_without_pythonpath(self):
        import subprocess
        result = subprocess.run(
            [
                str(STRANDS_DIR / ".venv" / "bin" / "python"), "-c",
                "import sys; sys.path.insert(0, r'" + str(STRANDS_DIR) + "'); "
                "from safestate_adapter import SafeStateRuntime; "
                "print('OK')"
            ],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, f"Adapter import failed: {result.stderr}"
        assert "OK" in result.stdout
