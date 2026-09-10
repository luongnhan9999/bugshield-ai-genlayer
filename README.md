# 🛡️ BugShield AI — Decentralized Security Audit Bounties on GenLayer

**BugShield AI** is an intelligent security bounty protocol built on **GenLayer Intelligent Contracts**. It eliminates trust issues between project creators and security researchers by automating vulnerability verification, authentic Git diff auditing, and bounty escrow payouts via GenLayer multi-validator consensus.

---

## 🌐 Live Verified Deployments

- **Live Production App:** [https://bugshield-ai-genlayer.vercel.app](https://bugshield-ai-genlayer.vercel.app)
- **Verified Contract Address (Studionet):** [`0xCe74ac620e4fb5EcbDE78814746C0C551219f146`](https://explorer-studio.genlayer.com/address/0xCe74ac620e4fb5EcbDE78814746C0C551219f146)
- **GenLayer Studio Explorer:** [https://explorer-studio.genlayer.com/address/0xCe74ac620e4fb5EcbDE78814746C0C551219f146](https://explorer-studio.genlayer.com/address/0xCe74ac620e4fb5EcbDE78814746C0C551219f146)
- **GitHub Repository:** [https://github.com/luongnhan9999/bugshield-ai-genlayer](https://github.com/luongnhan9999/bugshield-ai-genlayer)

---

## 🛡️ Key Security & Architecture Highlights (v0.2.18)

### 1. Strict Output Parsing (Zero Lax Fallbacks)
- **Parser Architecture:** `_parse_llm_json` requires strict JSON with `type(is_valid) is bool` (strictly `True` or `False`) and non-empty string `reason`.
- **Zero-Tolerance Parsing:** Prose, markdown, pseudo-JSON, truncated JSON, missing fields, nulls, string booleans (`"true"`), and integer booleans (`1`) are strictly rejected.
- **Fail-Closed Guarantee:** Absolutely NO fallback that approves text lacking "false" exists across any evaluation or appeal paths.

### 2. Atomic & Recoverable Settlement
- **Payout Tracking:** Escrow lifecycle is explicitly tracked with `payout_status`:
  - `"UNPAID"`: Default state for open bounties.
  - `"PAID"`: Confirmed on-chain native transfer via `emit_transfer`.
  - `"CLAIMABLE"`: Escrow safely held in contract if automatic push transfer requires manual pull.
  - `"REFUNDED"`: Creator refund upon time-lock expiration with no active submissions.
- **Pull-over-Push Claim Method:** `@gl.public.write def claim_bounty_payout(self, bounty_id)` allows the verified winner or creator to atomically claim their funds.

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
│   ├── bugshield.py              # Canonical GenLayer Python Intelligent Contract (v0.2.18)
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
│   └── .env                      # Contract address & RPC config (0xCe74ac...)
├── scripts/
│   └── deploy.py                 # GenLayer deployment script
└── README.md                     # Documentation & verified deployment specs
```

---

## ⚙️ Smart Contract Methods: `contracts/bugshield.py`

- `create_bounty(...)`: Locks native GEN token value in contract escrow.
- `top_up_bounty(...)`: Increases bounty reward for high-severity issues.
- `submit_and_evaluate_patch(...)`: Fetches authentic commit diff and executes multi-LLM consensus audit.
- `appeal_rejection(...)`: Triggers independent validator tribunal re-evaluation with hunter justification.
- `cancel_bounty(...)`: Refunds escrow to creator after 5-minute time-lock (only if 0 submissions exist).
- `claim_bounty_payout(...)`: Recoverable pull-claim for verified winner or creator.
- `get_bounty(...)`: Returns JSON string of single bounty details with payout status.
- `get_all_bounties()`: Returns JSON string array of all active and resolved bounties.

---

## 🛠️ Local Development

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.
