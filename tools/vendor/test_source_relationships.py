from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify


class SourceRelationshipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.component = copy.deepcopy(json.loads(verify.LOCK.read_text())["components"][0])
        self.name = self.component["name"]
        self.relationship = json.loads(
            (verify.ROOT / "deps/source-relationships" / f"{self.name}.json").read_text()
        )
        self.path = self.root / "deps/source-relationships" / f"{self.name}.json"
        self.path.parent.mkdir(parents=True)
        (self.root / ".gitmodules").write_text((verify.ROOT / ".gitmodules").read_text())
        series = self.root / self.relationship["series"]
        series.parent.mkdir(parents=True)
        series.write_text("\n".join(Path(item["path"]).name for item in self.component["patches"]) + "\n")

    def verify(self) -> None:
        self.path.write_text(json.dumps(self.relationship))
        with patch.object(verify, "ROOT", self.root):
            verify.verify_relationships({"components": [self.component]})

    def test_matches_offline_without_submodule_checkout(self) -> None:
        self.verify()

    def test_rejects_obsolete_materialization_path(self) -> None:
        self.relationship["materialization"] = "vendor/dae/ebpfinbound"
        with self.assertRaisesRegex(RuntimeError, "differs from vendor lock"):
            self.verify()

    def test_rejects_changed_source_pin(self) -> None:
        self.relationship["source"]["commit"] = "0" * 40
        with self.assertRaisesRegex(RuntimeError, "differs from vendor lock"):
            self.verify()

    def test_rejects_changed_remote(self) -> None:
        self.relationship["source"]["url"] = "https://example.invalid/unapproved.git"
        with self.assertRaisesRegex(RuntimeError, "remote differs"):
            self.verify()

    def test_rejects_reordered_patches(self) -> None:
        self.component["patches"].reverse()
        with self.assertRaisesRegex(RuntimeError, "patch order differs"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
