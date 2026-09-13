# 🛡️ BugShield AI — Decentralized Security Audit Bounties on GenLayer

**BugShield AI** is an intelligent security bounty protocol built on **GenLayer Intelligent Contracts**. It eliminates trust issues between project creators and security researchers by automating vulnerability verification, authentic Git diff auditing, and bounty escrow payouts via GenLayer multi-validator consensus.

---

## 🌐 Live Verified Deployments

- **Live Production App:** [https://bugshield-ai-genlayer.vercel.app](https://bugshield-ai-genlayer.vercel.app)
- **Verified Contract Address (Studionet):** [`0xe0BB5E58A841e5038AcE79791Cf22B66074eC742`](https://explorer-studio.genlayer.com/address/0xe0BB5E58A841e5038AcE79791Cf22B66074eC742)
- **GenLayer Studio Explorer:** [https://explorer-studio.genlayer.com/address/0xe0BB5E58A841e5038AcE79791Cf22B66074eC742](https://explorer-studio.genlayer.com/address/0xe0BB5E58A841e5038AcE79791Cf22B66074eC742)
- **GitHub Repository:** [https://github.com/luongnhan9999/bugshield-ai-genlayer](https://github.com/luongnhan9999/bugshield-ai-genlayer)

---

## 🔍 Verified On-Chain Settlement Evidence (Steward Proof)

All evidence transactions were executed live on GenLayer Studionet on contract [`0xe0BB5E58A841e5038AcE79791Cf22B66074eC742`](https://explorer-studio.genlayer.com/address/0xe0BB5E58A841e5038AcE79791Cf22B66074eC742):

| Scenario | Bounty ID | Creation Tx | Evaluation Tx | Claim Tx | On-Chain Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Fail-Closed Rejection** | `bounty-failclosed-1789272672` | [`0x5700fd...`](https://explorer-studio.genlayer.com/tx/0x5700fd1a8b0bff078193590a8c3df30fe23f99c7f88c002b4c52396fb7d2de8b) | [`0xfdd631...`](https://explorer-studio.genlayer.com/tx/0xfdd63195a5044c1817407551d2a37236a5e5eff214517f1405234890f81df00e) | N/A | **`status: OPEN`**, **`payout_status: UNPAID`**. Multi-validator LLM consensus rejected irrelevant patch `18a13a2`. Escrow safely preserved. |
| **2. Confirmed Outgoing Transfer** | `bounty-instant-paid-1789272705` | [`0xac348c...`](https://explorer-studio.genlayer.com/tx/0xac348c7acb01f0f6e7a0eb8ff660c5ce1b0990d5b80f6cac1b2ab61049524c50) | [`0xede70c...`](https://explorer-studio.genlayer.com/tx/0xede70c23a90418aa1e8da79ef0394982aece93e8a1b12cfd34498cf7b62844a7) | N/A | **`status: RESOLVED`**, **`payout_status: PAID`**. Consensus approved authentic commit `42711b3`, verified liquid balance, emitted transfer. |
| **3. Failed/Held Transfer & Claim Recovery** | `bounty-claimable-1789272767` | [`0xc54fe5...`](https://explorer-studio.genlayer.com/tx/0xc54fe527e8aafee2679db09693d8487234f1e091ff887dd8eb384d37d9a6ed56) | [`0xc6555c...`](https://explorer-studio.genlayer.com/tx/0xc6555c72bc2b27d2c8e35704d67dbb0c7b49af9264c81a25ffd0fa14cf96d9a5) | [`0x623cfa...`](https://explorer-studio.genlayer.com/tx/0x623cfa6ffb7b29f703a6780a661720d4c9479060110311df095f78dcd93c3e59) | **`CLAIMABLE` ➔ `PAID`**. Evaluated patch held as `CLAIMABLE` (escrow withheld). Authorized winner called `claim_bounty_payout`, transferred escrow, transitioned to `PAID`. |

---

## 🛡️ Key Security & Architecture Highlights (v0.2.20)

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
│   ├── bugshield.py              # Canonical GenLayer Python Intelligent Contract (v0.2.20)
│   └── bug_shield.py             # Synced Intelligent Contract
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
│   └── .env                      # Contract address & RPC config (0xe0BB...)
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
