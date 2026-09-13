# 🛡️ BugShield AI — Decentralized Security Audit Bounties on GenLayer

**BugShield AI** is an intelligent security bounty protocol built on **GenLayer Intelligent Contracts**. It eliminates trust issues between project creators and security researchers by automating vulnerability verification, authentic Git diff auditing, and bounty escrow payouts via GenLayer multi-validator consensus.

---

## 🌐 Live Verified Deployments

- **Live Production App:** [https://bugshield-ai-genlayer.vercel.app](https://bugshield-ai-genlayer.vercel.app)
- **Verified Contract Address (Studionet):** [`0x498010a312055f830f30c3F0c75f0cA8Ab6aE5B2`](https://explorer-studio.genlayer.com/address/0x498010a312055f830f30c3F0c75f0cA8Ab6aE5B2)
- **GenLayer Studio Explorer:** [https://explorer-studio.genlayer.com/address/0x498010a312055f830f30c3F0c75f0cA8Ab6aE5B2](https://explorer-studio.genlayer.com/address/0x498010a312055f830f30c3F0c75f0cA8Ab6aE5B2)
- **GitHub Repository:** [https://github.com/luongnhan9999/bugshield-ai-genlayer](https://github.com/luongnhan9999/bugshield-ai-genlayer)

---

## 🔍 Verified On-Chain Settlement Evidence (Steward Proof)

All evidence transactions were executed live on GenLayer Studionet on contract [`0x498010a312055f830f30c3F0c75f0cA8Ab6aE5B2`](https://explorer-studio.genlayer.com/address/0x498010a312055f830f30c3F0c75f0cA8Ab6aE5B2):

| Scenario | Bounty ID | Creation Tx | Evaluation Tx | Claim / Transfer Tx | Repeat Claim Prevention Tx | On-Chain Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Fail-Closed Rejection** | `bounty-failclosed-1789323001` | [`0x1c3f2d...`](https://explorer-studio.genlayer.com/tx/0x1c3f2dc35cfeedd04a3622ffd7425db00e7229cdd73a628dc11873323d5b2d1b) | [`0xd4bd1a...`](https://explorer-studio.genlayer.com/tx/0xd4bd1a0bef518305bbeafa2f8578db164272fa21ee52f98b24df915160b89cc7) | N/A | N/A | **`status: OPEN`**, **`payout_status: UNPAID`**. Multi-validator LLM consensus rejected irrelevant patch `18a13a2`. Escrow safely preserved. |
| **2. Held Payout Evaluation** | `bounty-pull-1789323105` | [`0x571fec...`](https://explorer-studio.genlayer.com/tx/0x571fec4d40799ebff73ac2f43d890662d5e528d345f38d1638a4f930e0491ff5) | [`0x3adfbdd...`](https://explorer-studio.genlayer.com/tx/0x3adfbdd5be299bdf71b36666bdfa911b9d8ce5ea95d1e182ae76a7db52a36440) | N/A | N/A | **`status: RESOLVED`**, **`payout_status: CLAIMABLE`**. Valid commit `42711b3` approved by consensus; escrow safely held as `CLAIMABLE`. |
| **3. Pull Claim ➔ Repeat Claim Lock** | `bounty-pull-1789323105` | (above) | (above) | [`0xc86262...`](https://explorer-studio.genlayer.com/tx/0xc86262152b4150d8b7b87b3e97d0b2ba796693b5eea1cc5c5534536cfd90f0a9)<br>➔ Child Transfer [`0xecfae2...`](https://explorer-studio.genlayer.com/tx/0xecfae2f5e277105bad07ca5cba89de73640bc3674b34d677cf0034b7bc584c43) | [`0x493914...`](https://explorer-studio.genlayer.com/tx/0x493914a4d9031809e336199e5772d0be84ad517deecca3632e7ca0ea6cba8fa8) | **LOCKED**. Winner called `claim_bounty_payout`, status locked to **`PAYOUT_PENDING`**, emitted native transfer `0xecfae2...` (`FINALIZED`, `value_credited: true`). Duplicate claim attempt reverted on-chain with `UserError("A payout attempt is already pending resolution")`! |

---

## 🛡️ Key Security & Architecture Highlights (v0.2.23)

### 1. Strict Output Parsing (Zero Normalization & Fail-Closed)
- **Zero-Normalization JSON Parser:** Direct `json.loads` parsing only. Rejects markdown fences (````json`), smart quotes, single quotes, and Python booleans without normalization.
- **Fail-Closed Guarantee:** Explicit boolean `is_valid` (true/false) and non-empty string `reason` required. Rejects string booleans (`"true"`), integers (`1`), nulls, or truncated objects.

### 2. Payout Lifecycle, Duplicate Claim Prevention & Linkage Verification
- **Escrow Lifecycle States (`payout_status`):**
  - `"UNPAID"`: Default state for open bounties.
  - `"CLAIMABLE"`: Escrow safely held in contract custody.
  - `"PAYOUT_PENDING"`: Native outbound transfer emitted; locked against duplicate claims.
  - `"PAID"`: Outbound transfer verified via on-chain parent-child linkage.
  - `"REFUNDED"`: Creator refund verified on-chain.
- **Duplicate Claim Lock:** Emitting transfer locks status to `PAYOUT_PENDING`. Repeat claims revert immediately.
- **Parent-Child Linkage & Anti-Replay:** `confirm_payout` queries RPC to verify child transfer `triggered_by` originates from parent contract call referencing matching `bounty_id`, and records hash in `confirmed_transfers`.
- **Fail-Safe Recovery (`resolve_failed_payout`):** Allows unlocking `PAYOUT_PENDING` back to `CLAIMABLE` if on-chain child transaction fails.

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
