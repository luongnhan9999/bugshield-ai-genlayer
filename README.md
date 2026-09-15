# 🛡️ BugShield AI — Decentralized Security Audit Bounties on GenLayer

**BugShield AI** is an intelligent security bounty protocol built on **GenLayer Intelligent Contracts**. It eliminates trust issues between project creators and security researchers by automating vulnerability verification, authentic Git diff auditing, and bounty escrow payouts via GenLayer multi-validator consensus.

---

## 🌐 Live Verified Deployments

- **Live Production App:** [https://bugshield-ai-genlayer.vercel.app](https://bugshield-ai-genlayer.vercel.app)
- **Verified Contract Address (Studionet):** [`0x493855D7A2C3F79ee0E57af4a40c72f857761B90`](https://explorer-studio.genlayer.com/address/0x493855D7A2C3F79ee0E57af4a40c72f857761B90)
- **GenLayer Studio Explorer:** [https://explorer-studio.genlayer.com/address/0x493855D7A2C3F79ee0E57af4a40c72f857761B90](https://explorer-studio.genlayer.com/address/0x493855D7A2C3F79ee0E57af4a40c72f857761B90)
- **GitHub Repository:** [https://github.com/luongnhan9999/bugshield-ai-genlayer](https://github.com/luongnhan9999/bugshield-ai-genlayer)

---

## 🔍 Verified On-Chain Settlement Evidence (Steward Proof)

All evidence transactions were executed live on GenLayer Studionet on contract [`0x493855D7A2C3F79ee0E57af4a40c72f857761B90`](https://explorer-studio.genlayer.com/address/0x493855D7A2C3F79ee0E57af4a40c72f857761B90):

| Scenario | Bounty ID | Creation & Eval Txs | Claim / Transfer Tx | Guard Reversion Tx (Proof) | Binding & Finalization Tx | Verified Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Fail-Closed Rejection** | `bounty-failclosed-1789449718` | Create: [`0xefa363...`](https://explorer-studio.genlayer.com/tx/0xefa363adb23cc75b76469056158c95acea4ea3b82de0d1f61900104b18161545)<br>Eval: [`0xf5503b...`](https://explorer-studio.genlayer.com/tx/0xf5503b721ffd909593fca73ea9e8b2930ec1e8c59c6ff19f70afb135921d9b33) | N/A | N/A | N/A | **`status: OPEN`**, **`payout_status: UNPAID`**. Multi-validator LLM consensus rejected irrelevant patch `18a13a2`. Escrow safely preserved. |
| **2. Held Payout Evaluation** | `bounty-pull-1789449718` | Create: [`0x023795...`](https://explorer-studio.genlayer.com/tx/0x0237950d0b3c0bd90e6ff5783526917b268de65d6eaefcfe3d35d89deff5f499)<br>Eval: [`0x26a172...`](https://explorer-studio.genlayer.com/tx/0x26a172cd085a6c0d8e2482082addb62531851b86fdd1c74864056825a876b31e) | N/A | N/A | N/A | **`status: RESOLVED`**, **`payout_status: CLAIMABLE`**. Valid commit `42711b3` approved by consensus; escrow safely held as `CLAIMABLE`. |
| **3. Duplicate Claim Lock** | `bounty-pull-1789449718` | (above) | Claim: [`0x10778c...`](https://explorer-studio.genlayer.com/tx/0x10778c6842019f1aab0184db02d6b35b6afcb5321264fc20bcf9762c7cd2d94c)<br>➔ Child: [`0xcc241f...`](https://explorer-studio.genlayer.com/tx/0xcc241f5f39f604a4d4123694912fc429e8a424716ac70c01636b057262e34b83) | Reverted: [`0x98a53e...`](https://explorer-studio.genlayer.com/tx/0x98a53efa4e6bb39fa67be654c34688cbffd9b904cfe1bc9c885a274237f29bc0) | N/A | **LOCKED**. Winner called `claim_bounty_payout`, status locked to `PAYOUT_PENDING`. Duplicate claim attempt reverted on-chain with `UserError("A payout attempt is already pending resolution")`. |
| **4. Unbound Confirm Blocked** | `bounty-pull-1789449718` | (above) | (above) | Reverted: [`0x8fdc0e...`](https://explorer-studio.genlayer.com/tx/0x8fdc0e18e613e24eb28d40306f91431c63e47d0fe754a8cd2ffd1896ef757a19) | N/A | **REJECTED (Fail-Closed)**. Caller attempted `confirm_payout` without prior binding. Contract reverted on-chain with `UserError("No transfer hash bound to this bounty. Call bind_pending_transfer first")`. |
| **5. Settlement Binding & Finalization** | `bounty-pull-1789449718` | (above) | (above) | N/A | Bind: [`0xe75fad...`](https://explorer-studio.genlayer.com/tx/0xe75fad062ee65526f88c04d80f671b73cb61b7022b2262c5005053866a6f2988)<br>Confirm: [`0xafb5ef...`](https://explorer-studio.genlayer.com/tx/0xafb5efba20921e67a26f56864a911024da3ad7a6e9883bf15daba2c875730ead) | **`payout_status: PAID`**. `bind_pending_transfer` verified child transfer and stored hash in `pending_payout_hash`. `confirm_payout` verified mandatory parent-child linkage and finalized settlement to `PAID`! |

---

## 🛡️ Key Security & Architecture Highlights (v0.2.24)

### 1. Strict Output Parsing (Zero Normalization & Fail-Closed)
- **Zero-Normalization JSON Parser:** Direct `json.loads` parsing only. Rejects markdown fences (````json`), smart quotes, single quotes, and Python booleans without normalization.
- **Fail-Closed Guarantee:** Explicit boolean `is_valid` (true/false) and non-empty string `reason` required. Rejects string booleans (`"true"`), integers (`1`), nulls, or truncated objects.

### 2. Payout Lifecycle, Settlement Binding & Linkage Verification (v0.2.24)
- **Escrow Lifecycle States (`payout_status`):**
  - `"UNPAID"`: Default state for open bounties.
  - `"CLAIMABLE"`: Escrow safely held in contract custody.
  - `"PAYOUT_PENDING"`: Native outbound transfer emitted; locked against duplicate claims.
  - `"PAID"`: Outbound transfer verified via on-chain parent-child linkage.
  - `"REFUNDED"`: Creator refund verified on-chain.
- **Duplicate Claim Lock:** Emitting transfer locks status to `PAYOUT_PENDING`. Repeat claims revert immediately on-chain with `UserError`.
- **Settlement Binding (`bind_pending_transfer`):** Because `emit_transfer()` is an asynchronous GenVM primitive that does not return the child hash at execution time, the winner discovers the child hash from `triggered_transactions` and calls `bind_pending_transfer()`. Contract consensus verifies the child transfer is `FINALIZED` and has parent linkage metadata before binding it to `bounty.pending_payout_hash`.
- **Mandatory Parent-Child Linkage (`confirm_payout`):** Unbound confirmation attempts revert immediately. Confirmation enforces fail-closed verification: child transfer MUST contain `triggered_by` metadata linking back to the contract transaction referencing the `bounty_id`. Anti-replay prevents reuse of hashes across bounties.
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
-- `add_bounty_reward(...)`: Increases bounty reward for high-severity issues.
+- `top_up_bounty(...)`: Increases bounty reward for high-severity issues.
 - `submit_and_evaluate_patch(...)`: Fetches authentic commit diff and executes multi-LLM consensus audit.
 - `appeal_rejection(...)`: Triggers independent validator tribunal re-evaluation with hunter justification.
 - `cancel_bounty(...)`: Refunds escrow to creator after 5-minute time-lock (only if 0 submissions exist).
 - `claim_bounty_payout(...)`: Safe recoverable pull-claim for verified winner or creator (locks to `PAYOUT_PENDING`).
+- `bind_pending_transfer(...)`: Consensus-verified binding of child transfer tx hash to `pending_payout_hash`.
+- `confirm_payout(...)`: Finalizes settlement to `PAID` via mandatory parent-child linkage verification and anti-replay.
+- `resolve_failed_payout(...)`: Fail-safe recovery unlocking `PAYOUT_PENDING` back to `CLAIMABLE` if child transfer fails.
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
