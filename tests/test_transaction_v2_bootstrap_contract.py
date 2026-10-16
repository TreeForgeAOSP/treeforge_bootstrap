from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

DISPATCHER = (
    ROOT
    / "src"
    / "treeforge_bootstrap"
    / "dispatcher.py"
)

RUNTIME = (
    ROOT
    / "src"
    / "treeforge_bootstrap"
    / "runtime.py"
)


class BootstrapTransactionV2ContractTest(
    unittest.TestCase
):
    def test_component_version_split(self) -> None:
        version = (
            ROOT
            / "VERSION"
        ).read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "TREEFORGE_BOOTSTRAP_VERSION=v1.0b2",
            version,
        )

        self.assertIn(
            "TREEFORGE_RUNTIME_ABI_VERSION=v1.0b1",
            version,
        )

    def test_transaction_owned_by_bootstrap(self) -> None:
        source = DISPATCHER.read_text(
            encoding="utf-8"
        )

        required = (
            "TFB_TRANSACTION_V2_BOOTSTRAP_R1",
            (
                "/metadata/treeforge-bootstrap/"
                "transaction-v2.pending"
            ),
            (
                "/metadata/treeforge-bootstrap/"
                "transaction-v2.running"
            ),
            (
                "/metadata/treeforge-bootstrap/"
                "transaction-v2.result"
            ),
            "TREEFORGE_TRANSACTION_V2",
            "proof_bootstrap_pass",
            "tfb_transaction_v2_pre_menu();",
        )

        for marker in required:
            self.assertIn(
                marker,
                source,
            )

    def test_pre_menu_order(self) -> None:
        source = DISPATCHER.read_text(
            encoding="utf-8"
        )

        runtime_env = source.index(
            "tfb_runtime_envp ="
        )

        transaction = source.index(
            "tfb_transaction_v2_pre_menu();",
            runtime_env,
        )

        menu_state = source.index(
            "tfb_menu_load_runtime_state();",
            runtime_env,
        )

        menu = source.index(
            "tfb_run_menu();",
            menu_state,
        )

        self.assertLess(
            runtime_env,
            transaction,
        )

        self.assertLess(
            transaction,
            menu_state,
        )

        self.assertLess(
            menu_state,
            menu,
        )

    def test_transaction_lane_has_no_broker_or_shell(self) -> None:
        source = DISPATCHER.read_text(
            encoding="utf-8"
        )

        begin = source.index(
            "TFB_TRANSACTION_V2_BOOTSTRAP_R1"
        )

        end = source.index(
            "TFB_TRANSACTION_V2_BOOTSTRAP_R1_END"
        )

        transaction = source[
            begin:end
        ]

        forbidden = (
            "/dev/socket/treeforge_transactiond",
            "TFTX2",
            "system(",
            "popen(",
            "/system/bin/sh",
        )

        for marker in forbidden:
            self.assertNotIn(
                marker,
                transaction,
            )

    def test_crash_safe_publish_order_is_encoded(self) -> None:
        source = DISPATCHER.read_text(
            encoding="utf-8"
        )

        begin = source.index(
            "static void tfb_transaction_v2_pre_menu"
        )

        end = source.index(
            "TFB_TRANSACTION_V2_BOOTSTRAP_R1_END",
            begin,
        )

        transaction = source[
            begin:end
        ]

        publish = transaction.index(
            "tfb_transaction_v2_result_temp_path"
        )

        retire = transaction.rindex(
            "tfb_transaction_v2_running_path"
        )

        self.assertLess(
            publish,
            retire,
        )

        self.assertIn(
            "running-recovery-required",
            transaction,
        )

        self.assertIn(
            "recovered-published-continuation",
            transaction,
        )

    def test_runtime_artifact_requires_transaction_markers(
        self,
    ) -> None:
        runtime = RUNTIME.read_text(
            encoding="utf-8"
        )

        for marker in (
            (
                'b"/metadata/treeforge-bootstrap/'
                'transaction-v2.pending"'
            ),
            'b"proof_bootstrap_pass"',
        ):
            self.assertIn(
                marker,
                runtime,
            )


if __name__ == "__main__":
    unittest.main()
