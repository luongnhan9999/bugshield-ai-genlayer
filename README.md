# 🛡️ BugShield AI — Decentralized Security Audit Bounties on GenLayer

**BugShield AI** is an intelligent security bounty protocol built on **GenLayer Intelligent Contracts**. It eliminates trust issues between project creators and security researchers by automating vulnerability verification, authentic Git diff auditing, and bounty escrow payouts via GenLayer multi-validator consensus.

---

## 🌐 Live Verified Deployments

- **Live Production App:** [https://bugshield-ai-genlayer.vercel.app](https://bugshield-ai-genlayer.vercel.app)
- **Verified Contract Address (Studionet):** [`0x4C60fDe7d07c2e7F31ca6056ad273997f5784C32`](https://explorer-studio.genlayer.com/address/0x4C60fDe7d07c2e7F31ca6056ad273997f5784C32)
- **GenLayer Studio Explorer:** [https://explorer-studio.genlayer.com/address/0x4C60fDe7d07c2e7F31ca6056ad273997f5784C32](https://explorer-studio.genlayer.com/address/0x4C60fDe7d07c2e7F31ca6056ad273997f5784C32)
- **GitHub Repository:** [https://github.com/luongnhan9999/bugshield-ai-genlayer](https://github.com/luongnhan9999/bugshield-ai-genlayer)

---

## 🔍 Verified On-Chain Settlement Evidence (Steward Proof)

All evidence transactions were executed live on GenLayer Studionet on contract [`0x4C60fDe7d07c2e7F31ca6056ad273997f5784C32`](https://explorer-studio.genlayer.com/address/0x4C60fDe7d07c2e7F31ca6056ad273997f5784C32):

| Scenario | Bounty ID | Creation Tx | Evaluation Tx | Claim / Transfer Tx | Confirmation Tx | On-Chain Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Fail-Closed Rejection** | `bounty-failclosed-1789309696` | [`0x1a52e8...`](https://explorer-studio.genlayer.com/tx/0x1a52e86d2be6278eed5d78dcabd289b462598745a73bdbbcb0f4d0ad6764ffab) | [`0x6996b2...`](https://explorer-studio.genlayer.com/tx/0x6996b234d059bbb23cc46ef03bd340d0eafce6435d8b2daed2c79b7b86af1fbf) | N/A | N/A | **`status: OPEN`**, **`payout_status: UNPAID`**. Multi-validator LLM consensus rejected irrelevant patch `18a13a2`. Escrow safely preserved. |
| **2. Criteria Enforcement** | `bounty-valid-1789309733` | [`0xa9f915...`](https://explorer-studio.genlayer.com/tx/0xa9f915e32a4a8474636c0ff7e9008fe4f184176009d315ded96ca73ad6580408) | [`0x914be6...`](https://explorer-studio.genlayer.com/tx/0x914be6e58698e041e98d0d9eb8923739ed16be7fa74163d0fbf53b6d1f244d72) | N/A | N/A | **`status: OPEN`**, **`payout_status: UNPAID`**. Consensus inspected git diff and rejected patch failing criteria. Escrow preserved. |
| **3. Held Payout ➔ Pull Claim ➔ Settlement Confirmation** | `bounty-claimable-1789309775` | [`0x67fdc0...`](https://explorer-studio.genlayer.com/tx/0x67fdc05dafaa82f3149cd9bcc3a5cfe55c1ea3b664f7f45f18741f3796070aa5) | [`0x035ad9...`](https://explorer-studio.genlayer.com/tx/0x035ad94ab60d3f74a414659cd78ec711efb00030238e152ee5681d415106631d) | [`0xf24fbe...`](https://explorer-studio.genlayer.com/tx/0xf24fbebf4ae2f6acbcf578dcf75c72872dfe7555e3d2b9821cf3cf4a15e5eafa)<br>➔ Transfer [`0x9d15f3...`](https://explorer-studio.genlayer.com/tx/0x9d15f3a3ca82a97223f564574f324615a80ad4e6d9dab337292b386e935a4f52) | [`0xf7d3f3...`](https://explorer-studio.genlayer.com/tx/0xf7d3f38370be0ecbfc234e90dca1aacf2cc2d41563764073f5add066c4fa12bd) | **`CLAIMABLE` ➔ Pull Claim ➔ `PAID`**. Evaluated patch held as `CLAIMABLE`. Winner called `claim_bounty_payout` emitting transfer `0x9d15f3...` (`FINALIZED`, `value_credited: true`, 0 errors). `confirm_payout` verified on-chain and transitioned to **`PAID`**! |

---

## 🛡️ Key Security & Architecture Highlights (v0.2.22)

### 1. Strict Output Parsing (Zero Lax Fallbacks)
- **Parser Architecture:** `_parse_llm_json` accepts dictionaries directly from GenVM and normalizes JSON strings while enforcing `type(is_valid) is bool` (strictly `True` or `False`) and non-empty string `reason`.
- **Zero-Tolerance Parsing:** Prose, markdown, missing fields, nulls, string booleans (`"true"`), and integer booleans (`1`) are strictly rejected.
- **Fail-Closed Guarantee:** Absolutely NO fallback that approves text lacking "false" exists across any evaluation or appeal paths.

### 2. Safe Recoverable Settlement (Pull-Over-Push & Pre-Flight Balance Verification)
- **Pre-Flight Liquid Check:** Contract verifies `self.balance >= bounty.reward_amount` before attempting any transfer.
- **Escrow Lifecycle States (`payout_status`):**
  - `"UNPAID"`: Default state for open bounties.
  - `"PAID"`: Confirmed outgoing native transfer via `emit_transfer`.
  - `"CLAIMABLE"`: Escrow safely held in custody if automatic transfer is withheld or held by policy.
  - `"REFUNDED"`: Escrow refunded to creator after time-lock expiration with no active submissions.
- **Authorized Pull Claim:** `@gl.public.write def claim_bounty_payout(self, bounty_id)` allows verified winners to safely pull held escrow funds at any time.

### 3. Dual-Sided Protection
- **Hunter Protection:**
  - Grounded in authentic Git diffs fetched via `gl.nondet.web.get` directly from GitHub.
  - Bound immutable commit SHA (minimum 7 characters).
  - Anti-Rugpull lock: Creator cannot cancel or withdraw escrow once submissions exist (`submission_count > 0`).
  - Independent Appeals Tribunal (`appeal_rejection`) for re-adjudicating contested rejections.
- **Creator Protection:**
  - Mandatory native GEN token escrow lock upon bounty creation.
  - Anti-Prompt-Injection defense boundary treats untrusted diffs strictly as passive data.
  - Full untruncated diff auditing prevents stealth backdoors and unauthorized alterations.

---

## 📁 Repository Structure

```
bugshield-ai-genlayer/
├── contracts/
│   └── bugshield.py              # Canonical GenLayer Python Intelligent Contract (v0.2.21)
├── tests/
│   ├── mock_gl.py                # Mock GenLayer execution environment
│   └── test_bugshield_suite.py   # Comprehensive automated test suite (20 tests)
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx          # Dashboard & Bounty listing page
│   │   │   ├── layout.tsx        # Root layout & metadata
│   │   │   └── globals.css       # Tailwind styling & dark theme
│   │   ├── components/
│   │   │   ├── Header.tsx        # Navigation header & live stats
│   │   │   ├── BountyCard.tsx    # Bounty card with payout status badges & claim actions
│   │   │   ├── CreateBountyModal.tsx # Escrow lock bounty creation modal
│   │   │   └── SubmitPatchModal.tsx  # Git commit submission modal
│   │   └── lib/
│   │       └── genlayer.ts       # Web3 provider & calldata encoder/decoder
│   ├── package.json              # Next.js 14, Tailwind, Ethers v6
│   └── .env                      # Contract address & RPC config (0x4C60...)
├── scripts/
│   └── deploy.py                 # GenLayer deployment script
└── README.md                     # Documentation & verified deployment specs
```

---

## ⚙️ Smart Contract Methods: `contracts/bugshield.py`

- `create_bounty(...)`: Locks native GEN token value in contract escrow.
- `add_bounty_reward(...)`: Increases bounty reward for high-severity issues.
- `submit_and_evaluate_patch(...)`: Fetches authentic commit diff and executes multi-LLM consensus audit.
- `appeal_rejection(...)`: Triggers independent validator tribunal re-evaluation with hunter justification.
- `cancel_bounty(...)`: Refunds escrow to creator after 5-minute time-lock (only if 0 submissions exist).
- `claim_bounty_payout(...)`: Safe recoverable pull-claim for verified winner or creator.
- `get_bounty(...)`: Returns JSON string of single bounty details with payout status.
- `get_bounty_count()`: Returns total number of bounties created on contract.
- `get_all_bounties()`: Returns JSON string array of all active and resolved bounties.
- `get_contract_balance()`: Returns the liquid GEN balance held in contract escrow.

---

## 🛠️ Local Development

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.
