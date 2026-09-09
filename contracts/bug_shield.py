# v0.2.17
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass
import json
import datetime

@allow_storage
@dataclass
class Bounty:
    id: str
    creator: str
    title: str
    target_repo_url: str
    vulnerability_description: str
    expected_fix_criteria: str
    reward_amount: bigint
    status: str  # "OPEN", "RESOLVED", "CANCELLED"
    winner: str
    ai_verdict_reason: str
    patch_pr_url: str
    created_at: bigint
    submission_count: bigint
    commit_hash: str  # Bound immutable git commit SHA


class Contract(gl.Contract):
    bounties: TreeMap[str, Bounty]
    bounty_ids: DynArray[str]
    owner: str

    def __init__(self):
        # GenVM automatically allocates memory for TreeMap & DynArray
        self.owner = str(gl.message.sender_address).lower()

    def _now(self) -> bigint:
        s = gl.message_raw["datetime"]
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return bigint(int(datetime.datetime.fromisoformat(s).timestamp()))

    def _parse_llm_json(self, response) -> dict:
        """Robust JSON parser to handle LLM markdown formatting issues"""
        if isinstance(response, dict):
            return response
        try:
            text = str(response).strip()
            if text.startswith("```json"):
                text = text[7:]
            elif text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()
            
            try:
                return json.loads(text)
            except Exception:
                pass

            try:
                cleaned = text.replace("'", '"').replace("True", "true").replace("False", "false")
                return json.loads(cleaned)
            except Exception:
                pass

            import re
            is_valid = True
            if "false" in text.lower():
                is_valid = False
            
            reason_match = re.search(r'"reason"\s*:\s*"([^"]+)"', text)
            if not reason_match:
                reason_match = re.search(r"'reason'\s*:\s*'([^']+)'", text)
            
            reason = reason_match.group(1) if reason_match else text[:200]
            return {"is_valid": is_valid, "reason": reason}
        except Exception as e:
            return {"is_valid": False, "reason": "Failed to parse JSON: " + str(e)}

    @gl.public.write.payable
    def create_bounty(
        self,
        bounty_id: str,
        title: str,
        target_repo_url: str,
        vulnerability_description: str,
        expected_fix_criteria: str,
    ) -> None:
        """
        CREATOR PROTECTION:
        - Requires positive escrow lock.
        - Records immutable block timestamp for time-lock protection.
        """
        amount = gl.message.value
        if amount <= bigint(0):
            raise UserError("Escrow reward amount must be greater than 0")

        if bounty_id in self.bounties:
            raise UserError("Bounty ID already exists")

        current_time = self._now()

        self.bounty_ids.append(bounty_id)
        self.bounties[bounty_id] = Bounty(
            id=bounty_id,
            creator=str(gl.message.sender_address).lower(),
            title=title,
            target_repo_url=target_repo_url,
            vulnerability_description=vulnerability_description,
            expected_fix_criteria=expected_fix_criteria,
            reward_amount=amount,
            status="OPEN",
            winner="",
            ai_verdict_reason="Awaiting Submissions",
            patch_pr_url="",
            created_at=current_time,
            submission_count=bigint(0),
            commit_hash="",
        )

    @gl.public.write
    def submit_and_evaluate_patch(
        self,
        bounty_id: str,
        commit_hash: str,
        pr_url: str,
    ) -> None:
        """
        GROUNDED VALIDATOR CONSENSUS & FAIL-CLOSED ESCROW:
        - Fetches authentic git commit diff directly from GitHub via gl.nondet.web.get.
        - Binds an immutable git commit hash to the on-chain bounty state.
        - Strictly fails closed without releasing escrow if the authentic diff cannot be fetched or if outputs are malformed.
        """
        if bounty_id not in self.bounties:
            raise UserError("Bounty not found")
        bounty = self.bounties[bounty_id]

        if bounty.status != "OPEN":
            raise UserError("Bounty is not OPEN for submissions")

        clean_commit = commit_hash.strip().lower()
        if len(clean_commit) < 7:
            raise UserError("Invalid commit_hash: must be a valid git commit SHA (minimum 7 characters).")

        clean_pr = pr_url.strip()
        if not clean_pr.startswith("http://") and not clean_pr.startswith("https://"):
            raise UserError("Invalid pr_url: must be a valid HTTP/HTTPS URL.")

        hunter = str(gl.message.sender_address).lower()
        title_str = str(bounty.title)
        repo_url = str(bounty.target_repo_url).strip().rstrip("/")
        vuln_desc = str(bounty.vulnerability_description)
        criteria = str(bounty.expected_fix_criteria)

        # Derive authoritative commit diff endpoints directly from repo & commit SHA
        commit_diff_url = f"{repo_url}/commit/{clean_commit}.diff"
        pr_diff_url = f"{clean_pr.rstrip('/')}.diff" if "/pull/" in clean_pr else commit_diff_url

        def leader_fn():
            # 1. STRICT FAIL-CLOSED WEB FETCH: Ground evaluation strictly in real repo/commit diff
            diff_text = ""
            fetch_error = ""

            for target_url in [commit_diff_url, pr_diff_url]:
                try:
                    res = gl.nondet.web.get(target_url)
                    body_bytes = res.body if hasattr(res, "body") else (res if isinstance(res, (bytes, bytearray)) else str(res).encode("utf-8"))
                    text = body_bytes.decode("utf-8", errors="replace")
                    # Verify it's an authentic diff and not an HTML 404/login error page
                    if text and "<!doctype html" not in text.lower() and "<html" not in text.lower():
                        diff_text = text
                        break
                except Exception as e:
                    fetch_error = str(e)

            # STRICT FAIL-CLOSED: Absolutely NO pasted code fallback allowed
            if not diff_text or len(diff_text.strip()) < 15:
                return {
                    "is_valid": False,
                    "reason": f"FAIL-CLOSED: Could not fetch authentic git diff for commit {clean_commit}. Web fetch error: {fetch_error or 'HTTP 404 / Invalid Diff'}"
                }

            # 2. CONSTRUCT GROUNDED LLM AUDIT PROMPT
            prompt = f"""
            SYSTEM INSTRUCTION (STRICT SECURITY BOUNDARY - FAIL CLOSED):
            You are an elite, independent AI consensus security auditor for BugShield AI on GenLayer.
            Evaluate whether the authentic git commit patch below fully and accurately resolves the target vulnerability.

            [REPOSITORY & COMMIT CONTEXT]
            - Target Repository: {repo_url}
            - Bound Git Commit SHA: {clean_commit}
            - Pull Request URL: {clean_pr}

            [VULNERABILITY SPECIFICATION]
            - Title: {title_str}
            - Vulnerability Description: {vuln_desc}
            - Expected Fix Criteria: {criteria}

            [AUTHENTIC GIT COMMIT DIFF (GROUND TRUTH)]
            {diff_text[:6000]}

            [AUDIT RULES]
            1. Ground your decision STRICTLY on the authentic git diff above.
            2. The patch MUST completely resolve the described vulnerability and meet all acceptance criteria without introducing new flaws.
            3. FAIL-CLOSED: If the diff does not resolve the issue, is incomplete, or introduces regressions, return is_valid: false.
            4. Return ONLY a valid JSON object in this exact format:
            {{"is_valid": true, "reason": "Concise technical reason explaining how the diff satisfies criteria"}}
            OR
            {{"is_valid": false, "reason": "Specific technical explanation of why the diff fails to resolve the issue"}}
            """

            try:
                llm_res = gl.nondet.exec_prompt(prompt, response_format="json")
                text_res = llm_res.content if hasattr(llm_res, "content") else str(llm_res)
                parsed = self._parse_llm_json(text_res)

                # Strict fail-closed structure check
                if not isinstance(parsed, dict) or "is_valid" not in parsed:
                    return {"is_valid": False, "reason": "FAIL-CLOSED: Validator output was malformed."}
                return parsed
            except Exception as e:
                return {"is_valid": False, "reason": f"FAIL-CLOSED: LLM execution failed: {str(e)}"}

        def validator_fn(leader_res) -> bool:
            if not isinstance(leader_res, gl.vm.Return):
                return False

            leader_data = leader_res.calldata if hasattr(leader_res, "calldata") else leader_res
            if not isinstance(leader_data, dict):
                leader_data = self._parse_llm_json(str(leader_data))

            # FAIL-CLOSED: Reject if leader returned malformed data
            if not isinstance(leader_data, dict) or "is_valid" not in leader_data:
                return False

            mine_data = leader_fn()
            if not isinstance(mine_data, dict) or "is_valid" not in mine_data:
                return False

            v_leader = bool(leader_data.get("is_valid", False))
            v_mine = bool(mine_data.get("is_valid", False))
            return v_leader == v_mine

        # Execute GenLayer non-deterministic consensus block
        result = gl.vm.run_nondet(leader_fn, validator_fn)
        if not isinstance(result, dict):
            result = self._parse_llm_json(str(result))

        bounty.submission_count += bigint(1)
        sub_count = int(bounty.submission_count)

        # FAIL-CLOSED: Malformed outputs strictly default to rejection without releasing escrow
        if not isinstance(result, dict) or "is_valid" not in result or not isinstance(result["is_valid"], bool):
            bounty.status = "OPEN"
            bounty.ai_verdict_reason = f"[Submission #{sub_count}] REJECTED (FAIL-CLOSED): Consensus output was malformed."
            self.bounties[bounty_id] = bounty
            return

        is_valid = result["is_valid"]
        reason = str(result.get("reason", "No detailed reason provided")).strip()

        # ESCROW RELEASE: Only released if is_valid is STRICTLY True and reason is provided
        if is_valid is True and len(reason) > 5:
            bounty.status = "RESOLVED"
            bounty.winner = hunter
            bounty.commit_hash = clean_commit
            bounty.patch_pr_url = clean_pr
            bounty.ai_verdict_reason = f"[Submission #{sub_count}] PASSED (Commit: {clean_commit[:7]}): {reason}"
            self.bounties[bounty_id] = bounty

            # Escrow Payout directly to Hunter via emit_transfer
            gl.get_contract_at(Address(hunter)).emit_transfer(value=u256(bounty.reward_amount))
        else:
            bounty.status = "OPEN"
            bounty.ai_verdict_reason = f"[Submission #{sub_count}] REJECTED (Commit: {clean_commit[:7]}): {reason}"
            self.bounties[bounty_id] = bounty

    @gl.public.write
    def cancel_bounty(self, bounty_id: str) -> None:
        """
        HUNTER PROTECTION (ANTI-FRONTRUNNING CANCEL):
        - Enforces 300s (5-minute) time-lock from creation timestamp before Creator can cancel.
        - Protects Hunters from Creator snatching patch code and cancelling immediately.
        """
        if bounty_id not in self.bounties:
            raise UserError("Bounty not found")
        bounty = self.bounties[bounty_id]

        if str(gl.message.sender_address).lower() != bounty.creator.lower():
            raise UserError("Only the Creator can cancel")

        if bounty.status != "OPEN":
            raise UserError("Bounty is not OPEN for cancellation")

        current_time = self._now()
        if current_time < bounty.created_at + bigint(300):
            if bounty.submission_count > bigint(0):
                raise UserError("Bounty escrow is time-locked (5 minutes) to protect security hunters under active evaluation.")
            raise UserError("Bounty escrow is time-locked. Please wait 5 minutes after creation to cancel.")

        bounty.status = "CANCELLED"
        bounty.ai_verdict_reason = f"Cancelled by creator after lock expiration ({int(bounty.submission_count)} submission attempts). Escrow refunded."
        self.bounties[bounty_id] = bounty

        # Escrow Refund to Creator via emit_transfer
        gl.get_contract_at(Address(bounty.creator)).emit_transfer(value=u256(bounty.reward_amount))

    @gl.public.view
    def get_bounty(self, bounty_id: str) -> str:
        """View returns JSON string for easiest compatibility with genlayer-js / Studio"""
        if bounty_id not in self.bounties:
            raise UserError("Bounty not found")
        b = self.bounties[bounty_id]
        return json.dumps({
            "id": b.id,
            "creator": b.creator,
            "title": b.title,
            "target_repo_url": b.target_repo_url,
            "vulnerability_description": b.vulnerability_description,
            "expected_fix_criteria": b.expected_fix_criteria,
            "reward_amount": str(b.reward_amount),
            "status": b.status,
            "winner": b.winner,
            "ai_verdict_reason": b.ai_verdict_reason,
            "patch_pr_url": b.patch_pr_url,
            "commit_hash": getattr(b, "commit_hash", ""),
            "created_at": str(b.created_at),
            "submission_count": str(b.submission_count),
        })

    @gl.public.view
    def get_all_bounties(self) -> str:
        """Return a JSON array of all bounties for easy frontend fetching"""
        all_items = []
        for i in range(len(self.bounty_ids)):
            bid = self.bounty_ids[i]
            b = self.bounties[bid]
            all_items.append({
                "id": b.id,
                "creator": b.creator,
                "title": b.title,
                "target_repo_url": b.target_repo_url,
                "reward_amount": str(b.reward_amount),
                "status": b.status,
                "winner": b.winner,
                "ai_verdict_reason": b.ai_verdict_reason,
                "commit_hash": getattr(b, "commit_hash", ""),
                "created_at": str(b.created_at),
                "submission_count": str(b.submission_count),
            })
        return json.dumps(all_items)
