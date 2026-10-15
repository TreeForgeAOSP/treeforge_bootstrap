from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = (
    ROOT
    / "src"
    / "treeforge_bootstrap"
    / "image.py"
)
KERNEL_PROVIDER = (
    ROOT
    / "src"
    / "treeforge_bootstrap"
    / "kernel_provider.py"
)


def _function(
    tree: ast.Module,
    name: str,
) -> ast.FunctionDef:
    for node in tree.body:
        if (
            isinstance(node, ast.FunctionDef)
            and node.name == name
        ):
            return node

    raise AssertionError(
        f"function missing: {name}"
    )


def _names(node: ast.AST) -> set[str]:
    return {
        item.id
        for item in ast.walk(node)
        if isinstance(item, ast.Name)
    }


class KernelProviderResolutionBoundaryTests(
    unittest.TestCase
):
    def test_image_consumer_has_no_production_kernel_freeze(
        self,
    ) -> None:
        text = IMAGE.read_text(
            encoding="utf-8"
        )
        tree = ast.parse(text)

        for name in (
            "build_image",
            "verify_image",
            "_expected_metadata",
        ):
            used = _names(
                _function(
                    tree,
                    name,
                )
            )

            self.assertNotIn(
                "EXPECTED_KERNEL_BYTES",
                used,
            )
            self.assertNotIn(
                "EXPECTED_KERNEL_SHA256",
                used,
            )

    def test_production_freeze_remains_in_provider_resolver(
        self,
    ) -> None:
        text = KERNEL_PROVIDER.read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "EXPECTED_KERNEL_BYTES",
            text,
        )
        self.assertIn(
            "EXPECTED_KERNEL_SHA256",
            text,
        )
        self.assertIn(
            "_verify_development_provider_contract",
            text,
        )
        self.assertIn(
            'metadata.get("boot_sha256")',
            text,
        )

    def test_image_metadata_uses_resolved_provider_sha(
        self,
    ) -> None:
        text = IMAGE.read_text(
            encoding="utf-8"
        )
        tree = ast.parse(text)
        function = _function(
            tree,
            "_expected_metadata",
        )
        source = ast.get_source_segment(
            text,
            function,
        )

        self.assertIsNotNone(source)
        self.assertIn(
            "_sha256(ensure_bootstrap_kernel())",
            source,
        )


if __name__ == "__main__":
    unittest.main()
