# 🛡️ BugShield AI — Decentralized Security Audit Bounties on GenLayer Testnet

**BugShield AI** is an intelligent security bounty platform built on **GenLayer**. It enables Web3 projects to post smart contract vulnerability bounties backed by native token escrows. When security hunters submit code patches and GitHub Pull Requests, GenLayer Validators execute on-chain LLM consensus prompts (`gl.exec_prompt`) to independently audit the patch code and automatically disburse rewards upon validation.

---

## 🌐 Live App & Smart Contract

- **Live App:** [https://bugshield-ai-genlayer.vercel.app](https://bugshield-ai-genlayer.vercel.app)
- **Deployed Contract (Studionet):** [`0x21Cf1E82bFE4B1777bD3359F9fE8Eb47c972ca85`](https://genlayer-explorer.vercel.app/address/0x21Cf1E82bFE4B1777bD3359F9fE8Eb47c972ca85)
- **GenLayer Block Explorer:** [https://genlayer-explorer.vercel.app/address/0x21Cf1E82bFE4B1777bD3359F9fE8Eb47c972ca85](https://genlayer-explorer.vercel.app/address/0x21Cf1E82bFE4B1777bD3359F9fE8Eb47c972ca85)

---

## 🚀 Key Features

- **On-Chain Native Escrow:** Bounty creators lock rewards in GenLayer Intelligent Contracts.
- **Validator AI Consensus Audit:** GenLayer's decentralized VM executes multi-validator LLM prompts to audit submitted patch diffs against vulnerability acceptance criteria.
- **Automatic Reward Payouts:** If the AI consensus validates the patch, escrow tokens are automatically transferred to the hunter's Web3 address.
- **AI Reasoning Inspector:** Clear technical breakdown log explaining validator verdict decisions for approved or rejected patches.
- **Web3 Wallet Integration:** Seamless connection to MetaMask or GenLayer compatible Web3 wallets (Chain ID: `61999`, RPC: `https://testnet-rpc.genlayer.com`).

---

## 📁 Repository Structure

```
bugshield-ai-genlayer/
├── contracts/
│   └── bug_shield.py              # GenLayer Python Intelligent Contract
├── scripts/
│   ├── deploy.py                  # Deploy script to GenLayer Testnet
│   └── interact.py                # Test script for bounty & PR submission
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx           # Dashboard & Bounty listing page
│   │   │   ├── layout.tsx         # Root layout & meta settings
│   │   │   └── globals.css        # Tailwind styling & dark theme
│   │   ├── components/
│   │   │   ├── Header.tsx         # Navigation header & statistics bar
│   │   │   ├── BountyCard.tsx     # Card component & AI Reasoning Inspector
│   │   │   ├── CreateBountyModal.tsx  # Create bounty modal form
│   │   │   └── SubmitPatchModal.tsx  # Submit patch modal with AI auditor loading state
│   │   └── lib/
│   │       └── genlayer.ts        # RPC connector & Web3 wallet helper
│   ├── package.json               # Dependencies (Next.js 14, Tailwind, Lucide)
│   └── .env                       # Contract address & RPC config
├── genlayer.config.json           # GenLayer Testnet RPC configuration
└── README.md                      # Documentation & deployment guide
```

---

## ⚙️ Smart Contract: `contracts/bug_shield.py`

The contract is written in Python for the GenLayer VM:
- Address: `0x21Cf1E82bFE4B1777bD3359F9fE8Eb47c972ca85`
- Explorer: `https://genlayer-explorer.vercel.app/address/0x21Cf1E82bFE4B1777bD3359F9fE8Eb47c972ca85`
- `create_bounty(...)`: Locks native token value in contract escrow.
- `submit_and_evaluate_patch(...)`: Triggers `gl.exec_prompt(audit_prompt)` across GenLayer validators.
- `cancel_bounty(...)`: Refunds escrow to creator after time-lock expiry.

---

## 🛠️ Local Development Setup

### 1. Requirements
- Node.js 18+ & npm
- Python 3.10+

### 2. Run Frontend Locally
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:3000` in your browser.

---

## 🚰 GenLayer Testnet Faucet & Token Guide

1. Network RPC: `https://testnet-rpc.genlayer.com`
2. Chain ID: `61999`
3. Native Symbol: `GEN`
4. Faucet URL: [https://faucet.genlayer.com](https://faucet.genlayer.com)
