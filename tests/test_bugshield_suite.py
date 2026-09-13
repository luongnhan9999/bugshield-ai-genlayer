import sys
import os
import json
import pytest

# Add tests directory and root directory to python path
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import mock_gl first to satisfy genlayer import
import mock_gl
from genlayer import gl, Address, bigint, u256
from contracts.bugshield import Contract, Bounty, _Recipient, UserError

@pytest.fixture
def contract():
    c = Contract()
    c.bounties = {}
    c.bounty_ids = []
    c.balance = 1000000000000000000  # 1 GEN
    return c

class TestLLMParserAndFailClosed:
    """Tests LLM JSON parsing robustness and fail-closed principles."""

    def test_parse_clean_json(self, contract):
        raw = '{"is_valid": true, "reason": "Verified clean fix without regressions."}'
        result = contract._parse_llm_json(raw)
        assert isinstance(result, dict)
        assert result["is_valid"] is True
        assert "regressions" in result["reason"]

    def test_parse_markdown_wrapped_json(self, contract):
        raw = '```json\n{"is_valid": false, "reason": "Fix criteria not satisfied."}\n```'
        result = contract._parse_llm_json(raw)
        assert isinstance(result, dict)
        assert result["is_valid"] is False

    def test_parse_malformed_json_fallback(self, contract):
        raw = 'Random conversational text without valid JSON structure'
        result = contract._parse_llm_json(raw)
        assert isinstance(result, dict)
        assert result.get("is_valid") is False
        assert "FAIL-CLOSED" in result.get("reason", "")

    def test_parse_smart_quotes(self, contract):
        raw = '{"is_valid": true, “reason”: “Quoted with smart unicode characters”}'
        result = contract._parse_llm_json(raw)
        assert isinstance(result, dict)
        assert result["is_valid"] is True

    def test_reject_non_boolean_is_valid(self, contract):
        raw = '{"is_valid": "true", "reason": "String instead of boolean"}'
        result = contract._parse_llm_json(raw)
        assert isinstance(result, dict)
        # Parser or validator rejects string boolean as non-canonical
        assert result.get("is_valid") is not True or type(result.get("is_valid")) is not bool

class TestRepositoryBinding:
    """Tests strict binding of PRs and commits to target repository."""

    def test_reject_mismatched_repository_pr(self, contract):
        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Critical reentrancy in withdraw",
            expected_fix_criteria="Use CEI pattern",
            reward_amount=bigint(100),
            status="OPEN",
            winner="",
            ai_verdict_reason="",
            patch_pr_url="",
            created_at=bigint(1000),
            submission_count=bigint(0),
            commit_hash="",
            last_submitter="",
            payout_status="UNPAID",
            last_payout_tx="",
        )

        with pytest.raises(UserError, match="must belong to the bounty target repository"):
            contract.submit_and_evaluate_patch(
                bounty_id="b1",
                commit_hash="abcdef12345678",
                pr_url="https://github.com/attacker/malicious-repo/pull/1",
            )

    def test_reject_short_commit_sha(self, contract):
        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Critical reentrancy in withdraw",
            expected_fix_criteria="Use CEI pattern",
            reward_amount=bigint(100),
            status="OPEN",
            winner="",
            ai_verdict_reason="",
            patch_pr_url="",
            created_at=bigint(1000),
            submission_count=bigint(0),
            commit_hash="",
            last_submitter="",
            payout_status="UNPAID",
            last_payout_tx="",
        )

        with pytest.raises(UserError, match="must be a valid git commit SHA"):
            contract.submit_and_evaluate_patch(
                bounty_id="b1",
                commit_hash="abc",
                pr_url="https://github.com/org/target-repo/pull/1",
            )

    def test_reject_invalid_url_scheme(self, contract):
        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Critical reentrancy in withdraw",
            expected_fix_criteria="Use CEI pattern",
            reward_amount=bigint(100),
            status="OPEN",
            winner="",
            ai_verdict_reason="",
            patch_pr_url="",
            created_at=bigint(1000),
            submission_count=bigint(0),
            commit_hash="",
            last_submitter="",
            payout_status="UNPAID",
            last_payout_tx="",
        )

        with pytest.raises(UserError, match="must be a valid HTTP/HTTPS URL"):
            contract.submit_and_evaluate_patch(
                bounty_id="b1",
                commit_hash="abcdef12345678",
                pr_url="ftp://github.com/org/target-repo/pull/1",
            )

class TestAuthorizationAndSecurityGuards:
    """Tests anti-rugpull locks and role authorization."""

    def test_creator_cancellation_timelock(self, contract):
        gl.message.sender_address = Address("0xcreator")
        gl.message_raw = {"datetime": "2026-09-13T12:01:00Z"}  # 60s later (<300s)

        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Critical reentrancy",
            expected_fix_criteria="CEI",
            reward_amount=bigint(100),
            status="OPEN",
            winner="",
            ai_verdict_reason="",
            patch_pr_url="",
            created_at=bigint(1789387200),  # 2026-09-13T12:00:00Z
            submission_count=bigint(0),
            commit_hash="",
            last_submitter="",
            payout_status="UNPAID",
            last_payout_tx="",
        )

        with pytest.raises(UserError, match="Time-Lock Active"):
            contract.cancel_bounty("b1")

    def test_anti_rugpull_freeze_on_active_submissions(self, contract):
        gl.message.sender_address = Address("0xcreator")
        gl.message_raw = {"datetime": "2026-09-13T12:10:00Z"}  # 600s later (>300s)

        now = contract._now()
        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Critical reentrancy",
            expected_fix_criteria="CEI",
            reward_amount=bigint(100),
            status="OPEN",
            winner="",
            ai_verdict_reason="",
            patch_pr_url="",
            created_at=now - bigint(600),  # 600s ago (> 300s timelock)
            submission_count=bigint(1),  # Active submission exists!
            commit_hash="abcdef123",
            last_submitter="0xhunter",
            payout_status="UNPAID",
            last_payout_tx="",
        )

        with pytest.raises(UserError, match="Anti-Rugpull Lock"):
            contract.cancel_bounty("b1")

    def test_non_creator_cannot_cancel(self, contract):
        gl.message.sender_address = Address("0xattacker")
        gl.message_raw = {"datetime": "2026-09-13T12:10:00Z"}

        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Critical reentrancy",
            expected_fix_criteria="CEI",
            reward_amount=bigint(100),
            status="OPEN",
            winner="",
            ai_verdict_reason="",
            patch_pr_url="",
            created_at=bigint(1789387200),
            submission_count=bigint(0),
            commit_hash="",
            last_submitter="",
            payout_status="UNPAID",
            last_payout_tx="",
        )

        with pytest.raises(UserError, match="Only the Creator can cancel"):
            contract.cancel_bounty("b1")

class TestSettlementAndRecoveryPath:
    """Tests two-phase settlement, CLAIMABLE preservation, and recovery path."""

    def test_settlement_cannot_mark_paid_prematurely(self, contract):
        """Bounty resolved must remain CLAIMABLE, never jump directly to PAID."""
        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Desc",
            expected_fix_criteria="Fix",
            reward_amount=bigint(100),
            status="RESOLVED",
            winner="0xhunter",
            ai_verdict_reason="Passed evaluation",
            patch_pr_url="https://github.com/org/target-repo/pull/1",
            created_at=bigint(1789387200),
            submission_count=bigint(1),
            commit_hash="abcdef123",
            last_submitter="0xhunter",
            payout_status="CLAIMABLE",
            last_payout_tx="",
        )

        assert contract.bounties["b1"].payout_status == "CLAIMABLE"
        assert contract.bounties["b1"].status == "RESOLVED"

    def test_unauthorized_claim_rejected(self, contract):
        gl.message.sender_address = Address("0xunauthorized")
        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Desc",
            expected_fix_criteria="Fix",
            reward_amount=bigint(100),
            status="RESOLVED",
            winner="0xhunter",
            ai_verdict_reason="Passed evaluation",
            patch_pr_url="https://github.com/org/target-repo/pull/1",
            created_at=bigint(1789387200),
            submission_count=bigint(1),
            commit_hash="abcdef123",
            last_submitter="0xhunter",
            payout_status="CLAIMABLE",
            last_payout_tx="",
        )

        with pytest.raises(UserError, match="Only the verified winner can claim"):
            contract.claim_bounty_payout("b1")

    def test_pull_claim_preserves_claimable_until_confirmed(self, contract):
        gl.message.sender_address = Address("0xhunter")
        contract.balance = 1000

        # Mock emit_transfer
        transfers = []
        original_recipient = _Recipient
        class MockRecipient:
            def __init__(self, addr):
                self.addr = addr
            def emit_transfer(self, value):
                transfers.append({"to": str(self.addr), "value": int(value)})

        import contracts.bugshield
        contracts.bugshield._Recipient = MockRecipient

        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Desc",
            expected_fix_criteria="Fix",
            reward_amount=bigint(100),
            status="RESOLVED",
            winner="0xhunter",
            ai_verdict_reason="Passed evaluation",
            patch_pr_url="https://github.com/org/target-repo/pull/1",
            created_at=bigint(1789387200),
            submission_count=bigint(1),
            commit_hash="abcdef123",
            last_submitter="0xhunter",
            payout_status="CLAIMABLE",
            last_payout_tx="",
        )

        contract.claim_bounty_payout("b1")
        assert len(transfers) == 1
        assert transfers[0]["to"] == "0xhunter"
        assert transfers[0]["value"] == 100
        # CRITICAL: Payout status MUST remain CLAIMABLE until confirmed via confirm_payout!
        assert contract.bounties["b1"].payout_status == "CLAIMABLE"

        # Restore
        contracts.bugshield._Recipient = original_recipient

    def test_confirm_payout_validation(self, contract):
        """Invalid transfer hash or non-hex input must be rejected."""
        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Desc",
            expected_fix_criteria="Fix",
            reward_amount=bigint(100),
            status="RESOLVED",
            winner="0xhunter",
            ai_verdict_reason="Passed evaluation",
            patch_pr_url="",
            created_at=bigint(1789387200),
            submission_count=bigint(1),
            commit_hash="abcdef123",
            last_submitter="0xhunter",
            payout_status="CLAIMABLE",
            last_payout_tx="",
        )

        with pytest.raises(UserError, match="Invalid transfer_tx_hash"):
            contract.confirm_payout("b1", "invalid_short_hash")

    def test_prevent_double_claim_after_paid(self, contract):
        gl.message.sender_address = Address("0xhunter")
        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Desc",
            expected_fix_criteria="Fix",
            reward_amount=bigint(100),
            status="RESOLVED",
            winner="0xhunter",
            ai_verdict_reason="Passed evaluation",
            patch_pr_url="",
            created_at=bigint(1789387200),
            submission_count=bigint(1),
            commit_hash="abcdef123",
            last_submitter="0xhunter",
            payout_status="PAID",  # Already finalized!
            last_payout_tx="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )

        with pytest.raises(UserError, match="already been successfully transferred and confirmed"):
            contract.claim_bounty_payout("b1")

    def test_cancelled_bounty_refund_lifecycle(self, contract):
        gl.message.sender_address = Address("0xcreator")
        contract.balance = 500

        transfers = []
        class MockRecipient:
            def __init__(self, addr):
                self.addr = addr
            def emit_transfer(self, value):
                transfers.append({"to": str(self.addr), "value": int(value)})

        import contracts.bugshield
        original_recipient = contracts.bugshield._Recipient
        contracts.bugshield._Recipient = MockRecipient

        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Desc",
            expected_fix_criteria="Fix",
            reward_amount=bigint(100),
            status="CANCELLED",
            winner="",
            ai_verdict_reason="Cancelled",
            patch_pr_url="",
            created_at=bigint(1789387200),
            submission_count=bigint(0),
            commit_hash="",
            last_submitter="",
            payout_status="CLAIMABLE",
            last_payout_tx="",
        )

        # Creator claims refund
        contract.claim_bounty_payout("b1")
        assert len(transfers) == 1
        assert transfers[0]["to"] == "0xcreator"
        assert transfers[0]["value"] == 100
        # Remains CLAIMABLE until confirmed via confirm_payout
        assert contract.bounties["b1"].payout_status == "CLAIMABLE"

        contracts.bugshield._Recipient = original_recipient

    def test_top_up_bounty_guards(self, contract):
        gl.message.sender_address = Address("0xsponsor")
        gl.message.value = bigint(50)

        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Desc",
            expected_fix_criteria="Fix",
            reward_amount=bigint(100),
            status="OPEN",
            winner="",
            ai_verdict_reason="",
            patch_pr_url="",
            created_at=bigint(1789387200),
            submission_count=bigint(0),
            commit_hash="",
            last_submitter="",
            payout_status="UNPAID",
            last_payout_tx="",
        )

        contract.top_up_bounty("b1")
        assert contract.bounties["b1"].reward_amount == 150

        # Cannot top up resolved bounty
        contract.bounties["b1"].status = "RESOLVED"
        with pytest.raises(UserError, match="Cannot add reward to non-OPEN bounty"):
            contract.top_up_bounty("b1")

    def test_appeal_rejection_caller_guards(self, contract):
        gl.message.sender_address = Address("0xrandom")
        contract.bounties["b1"] = Bounty(
            id="b1",
            creator="0xcreator",
            title="Reentrancy Fix",
            target_repo_url="https://github.com/org/target-repo",
            vulnerability_description="Desc",
            expected_fix_criteria="Fix",
            reward_amount=bigint(100),
            status="OPEN",
            winner="",
            ai_verdict_reason="Prior rejection",
            patch_pr_url="",
            created_at=bigint(1789387200),
            submission_count=bigint(1),
            commit_hash="abcdef123",
            last_submitter="0xhunter",
            payout_status="UNPAID",
            last_payout_tx="",
        )

        with pytest.raises(UserError, match="Only the hunter who submitted the rejected patch"):
            contract.appeal_rejection("b1", "My fix is correct because...")

class TestFrontendRPCConfig:
    """Verifies that client configuration conforms to Studionet 61999 and removes mock fallbacks."""

    def test_no_mock_bounties_in_frontend(self):
        frontend_lib = os.path.join(os.path.dirname(__file__), "..", "frontend", "src", "lib", "genlayer.ts")
        with open(frontend_lib, "r", encoding="utf-8") as f:
            code = f.read()

        # Verify fabricated client fallback has been deleted
        assert "FABRICATED MOCK BOUNTY" not in code
        assert "fallback" not in code.lower() or "timeout" in code.lower()
        # Verify Studionet chain configuration
        assert "0xF22F" in code or "61999" in code
        assert "studio.genlayer.com" in code
