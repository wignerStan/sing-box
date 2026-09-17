from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

import materialize
import verify


class VendorDigestPortabilityTests(unittest.TestCase):
    def test_symlink_mode_is_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target").write_text("payload\n", encoding="utf-8")
            os.symlink("target", root / "link")

            materialized_digest, materialized_entries = materialize.tree_digest(root)
            verified_digest, verified_entries = verify.tree_sha256(root)

            self.assertEqual(materialized_digest, verified_digest)
            self.assertEqual(len(materialized_entries), verified_entries)
            record = next(item for item in materialized_entries if item["path"] == "link")
            self.assertEqual(record["kind"], "symlink")
            self.assertEqual(record["mode"], "0777")
            self.assertEqual(record["size"], len("target".encode("utf-8")))

    def test_symlink_target_changes_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "first").write_text("same\n", encoding="utf-8")
            (root / "second").write_text("same\n", encoding="utf-8")
            os.symlink("first", root / "link")
            first, _ = materialize.tree_digest(root)
            (root / "link").unlink()
            os.symlink("second", root / "link")
            second, _ = materialize.tree_digest(root)
            self.assertNotEqual(first, second)

    def test_metadata_can_be_excluded_from_projection_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "modules.txt").write_text("module\n", encoding="utf-8")
            (root / "README.md").write_text("first\n", encoding="utf-8")
            first, _ = materialize.tree_digest(root, excluded={"README.md"})
            (root / "README.md").write_text("second\n", encoding="utf-8")
            second, _ = materialize.tree_digest(root, excluded={"README.md"})
            self.assertEqual(first, second)

    def test_repository_metadata_is_stripped_with_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = root / "example" / ".gitmodules"
            metadata.parent.mkdir()
            raw = b'[submodule "fixture"]\n\tpath = fixture\n'
            metadata.write_bytes(raw)

            receipt = materialize.strip_repository_metadata(root)

            self.assertFalse(metadata.exists())
            self.assertEqual(
                receipt,
                [
                    {
                        "path": "example/.gitmodules",
                        "kind": "file",
                        "size": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                ],
            )

    def test_all_repository_metadata_names_are_stripped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in materialize.REPOSITORY_METADATA_NAMES:
                (root / name).write_text(name + "\n", encoding="utf-8")

            receipt = materialize.strip_repository_metadata(root)

            self.assertEqual(
                {item["path"] for item in receipt},
                materialize.REPOSITORY_METADATA_NAMES,
            )
            for name in materialize.REPOSITORY_METADATA_NAMES:
                self.assertFalse((root / name).exists())

    def test_repository_metadata_receipt_rejects_other_files(self) -> None:
        projection = {
            "excluded_repository_metadata": [
                {
                    "path": "example/.gitkeep",
                    "kind": "file",
                    "size": 0,
                    "sha256": "0" * 64,
                }
            ]
        }
        with self.assertRaises(RuntimeError):
            verify.validate_excluded_repository_metadata(projection)


if __name__ == "__main__":
    unittest.main(verbosity=2)
