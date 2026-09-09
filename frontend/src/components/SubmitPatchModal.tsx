"use client";

import React, { useState } from "react";
import { X, Send, Cpu, Brain, CheckCircle2, XCircle, Zap, AlertCircle, ShieldCheck } from "lucide-react";
import { Bounty, submitAndEvaluatePatchOnChain } from "../lib/genlayer";

interface SubmitPatchModalProps {
  bounty: Bounty | null;
  isOpen: boolean;
  onClose: () => void;
  onPatchEvaluated: (bountyId: string, updatedBounty: Bounty) => void;
  account: string | null;
}

export const SubmitPatchModal: React.FC<SubmitPatchModalProps> = ({
  bounty,
  isOpen,
  onClose,
  onPatchEvaluated,
  account,
}) => {
  const [commitHash, setCommitHash] = useState("");
  const [prUrl, setPrUrl] = useState("");
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditStep, setAuditStep] = useState<string>("");

  if (!isOpen || !bounty) return null;

  // Judge Demo Quick Fill: Valid Patch (Triggers AI Approval & Instant Payout on-chain)
  const handleQuickFillValid = () => {
    setPrUrl(`https://github.com/bugshield-ai/demo-repo/pull/${Math.floor(Math.random() * 100) + 20}`);
    setCommitHash("e4d9c72a8b3f1e567890abcd1234ef5678901234");
  };

  // Judge Demo Quick Fill: Invalid Patch (Triggers AI Rejection without Locking Escrow on-chain)
  const handleQuickFillInvalid = () => {
    setPrUrl(`https://github.com/bugshield-ai/demo-repo/pull/${Math.floor(Math.random() * 100) + 20}`);
    setCommitHash("b1a2c3d4e5f67890123456789abcdef012345678");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!commitHash || !prUrl) {
      alert("Please provide both the Bound Git Commit Hash (SHA) and Pull Request URL.");
      return;
    }

    if (commitHash.trim().length < 7) {
      alert("Invalid Git Commit Hash: Minimum 7 hex characters required to bind an immutable commit.");
      return;
    }

    if (!account || typeof window === "undefined" || !window.ethereum) {
      alert("Web3 Wallet Connection Required: Please connect your MetaMask/Web3 wallet to broadcast on-chain transactions to GenLayer Testnet.");
      return;
    }

    setIsAuditing(true);

    try {
      const result = await submitAndEvaluatePatchOnChain(
        bounty.id,
        commitHash.trim(),
        prUrl.trim(),
        account,
        (status) => setAuditStep(status)
      );

      // Strictly read updated state directly from public contract view call
      const updatedOnChainBounty = result.updatedBounty;

      onPatchEvaluated(bounty.id, updatedOnChainBounty);

      if (updatedOnChainBounty.status === "RESOLVED") {
        alert(`✅ ON-CHAIN VALIDATOR CONSENSUS PASSED!\n\nPatch verified by GenLayer AI VM directly against authentic git diff. Reward payout disbursed on-chain. Winner: ${updatedOnChainBounty.winner || account}`);
      } else {
        alert(`❌ ON-CHAIN VALIDATOR CONSENSUS REJECTED!\n\nPatch evaluation failed or failed-closed on malformed criteria. Bounty remains OPEN. Reason: ${updatedOnChainBounty.ai_verdict_reason}`);
      }

      onClose();
      setCommitHash("");
      setPrUrl("");
    } catch (err: any) {
      console.error("On-chain patch submission failed:", err);
      // Strictly fail on missing receipt or failed state read — NEVER show fabricated state
      alert(`❌ Transaction or Contract Read Failed:\n\n${err.message || err}\n\nState update aborted. No state changes were applied.`);
    } finally {
      setIsAuditing(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="bg-card border border-border rounded-2xl w-full max-w-xl p-6 shadow-2xl relative animate-in fade-in zoom-in-95 duration-200">
        {/* Close Button */}
        <button
          onClick={onClose}
          disabled={isAuditing}
          className="absolute top-5 right-5 text-slate-400 hover:text-white transition-colors disabled:opacity-50"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center space-x-3 mb-4 pr-6">
          <div className="p-2 bg-cyan-500/10 text-cyan-400 rounded-xl border border-cyan-500/20">
            <Send className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Submit Security Patch</h2>
            <p className="text-xs text-slate-400">
              Role: <span className="text-cyan-400 font-semibold">⚔️ Security Hunter (Auditor)</span>
            </p>
          </div>
        </div>

        {!account && (
          <div className="mb-4 p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl text-xs text-amber-300 flex items-center">
            <AlertCircle className="w-4 h-4 mr-2 flex-shrink-0" />
            Wallet not connected. Connect Web3 wallet at top right for real on-chain transaction execution!
          </div>
        )}

        {/* Judge Fast-Test Demo Fill Buttons */}
        {!isAuditing && (
          <div className="mb-4 p-3 bg-slate-900 border border-cyan-500/30 rounded-xl space-y-2">
            <div className="text-xs text-cyan-300 font-bold flex items-center">
              <Zap className="w-3.5 h-3.5 mr-1 text-amber-400 fill-current" />
              Judge Fast-Test Demo Buttons:
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={handleQuickFillValid}
                className="px-3 py-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 rounded-lg text-xs font-semibold flex items-center transition-colors"
              >
                <CheckCircle2 className="w-3.5 h-3.5 mr-1 text-emerald-400" />
                Valid Patch (Auto-Approve & Payout)
              </button>
              <button
                type="button"
                onClick={handleQuickFillInvalid}
                className="px-3 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 rounded-lg text-xs font-semibold flex items-center transition-colors"
              >
                <XCircle className="w-3.5 h-3.5 mr-1 text-rose-400" />
                Invalid Patch (Reject & Keep Open)
              </button>
            </div>
          </div>
        )}

        {/* AI Auditing Loader State */}
        {isAuditing ? (
          <div className="py-12 px-4 text-center space-y-6">
            <div className="relative inline-block">
              <div className="w-20 h-20 rounded-full border-4 border-cyan-500/20 border-t-cyan-400 animate-spin flex items-center justify-center mx-auto" />
              <Brain className="w-8 h-8 text-cyan-400 absolute inset-0 m-auto animate-pulse" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white flex items-center justify-center gap-2">
                <Cpu className="w-5 h-5 text-cyan-400 animate-bounce" />
                Validators Consensus AI Auditing...
              </h3>
              <p className="text-xs text-cyan-300 font-mono mt-2 bg-slate-900/80 py-2 px-4 rounded-xl border border-cyan-500/20 max-w-md mx-auto">
                {auditStep}
              </p>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-xs font-semibold text-slate-300">
                  Bound Git Commit Hash (SHA) *
                </label>
                <span className="text-[10px] text-cyan-400 font-mono bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-800/40">
                  Immutable Anchor
                </span>
              </div>
              <input
                type="text"
                required
                placeholder="e.g. 4a8b1c7d8e9f0123456789abcdef0123456789ab (or 7+ char SHA)"
                value={commitHash}
                onChange={(e) => setCommitHash(e.target.value)}
                className="w-full px-3.5 py-2.5 bg-slate-900 border border-border rounded-xl text-sm text-white focus:outline-none focus:border-cyan-500 font-mono text-xs"
              />
              <p className="text-[10px] text-slate-400 mt-1">
                GenLayer validators fetch the authentic commit diff via <code className="text-indigo-300">gl.nondet.web.get</code> to ground the consensus verdict in real code.
              </p>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                GitHub Pull Request URL *
              </label>
              <input
                type="url"
                required
                placeholder="https://github.com/organization/repository/pull/42"
                value={prUrl}
                onChange={(e) => setPrUrl(e.target.value)}
                className="w-full px-3.5 py-2.5 bg-slate-900 border border-border rounded-xl text-sm text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="p-3.5 bg-indigo-950/40 border border-indigo-500/30 rounded-xl text-xs text-indigo-200 space-y-1">
              <div className="font-semibold text-cyan-300 flex items-center">
                <ShieldCheck className="w-4 h-4 mr-1.5 text-cyan-400" />
                100% Repository-Grounded Git Diff Audit:
              </div>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                No manual code diff pasting required. GenLayer validators independently fetch the authentic git commit diff directly from GitHub (<code className="text-cyan-300">/commit/{'{commit_hash}'}.diff</code>) and bind this immutable commit SHA on-chain before consensus evaluation.
              </p>
            </div>

            <div className="pt-2 flex justify-end space-x-3">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2.5 rounded-xl text-xs font-semibold border border-border text-slate-300 hover:text-white bg-slate-900"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-5 py-2.5 rounded-xl text-xs font-bold bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-sans shadow-lg shadow-cyan-500/20 transition-all flex items-center"
              >
                <Cpu className="w-4 h-4 mr-1.5" />
                Submit & Trigger On-Chain AI Audit
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
