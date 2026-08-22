declare global {
  interface Window {
    ethereum?: any;
  }
}

export interface Bounty {
  id: string; // Contract string ID (e.g. "bounty-1", "bounty-1700000000")
  creator: string;
  title: string;
  target_repo_url: string;
  vulnerability_description: string;
  expected_fix_criteria: string;
  reward_amount: string;
  status: "OPEN" | "RESOLVED" | "CANCELLED"; // Contract string status enum
  winner: string;
  ai_verdict_reason: string;
  patch_pr_url: string;
  created_at?: string;
  submission_count?: string;
}

export const GENLAYER_TESTNET_CONFIG = {
  chainId: "0xF22F", // 61999 in hex (0xF22F)
  chainName: "GenLayer Testnet",
  rpcUrls: [process.env.NEXT_PUBLIC_GENLAYER_RPC || "https://testnet-rpc.genlayer.com"],
  nativeCurrency: {
    name: "GenLayer Token",
    symbol: "GEN",
    decimals: 18,
  },
  blockExplorerUrls: ["https://scan.genlayer.com"],
};

// Valid 40-hex character Ethereum / GenLayer Contract Address
export const CONTRACT_ADDRESS =
  process.env.VITE_CONTRACT_ADDRESS || process.env.NEXT_PUBLIC_CONTRACT_ADDRESS || "0x39CA47Ec65a6d390AC220f20014D6a8Ecd972ECA";

// Seed bounties aligned with contract string IDs & string statuses
export const INITIAL_BOUNTIES: Bounty[] = [
  {
    id: "bounty-1",
    creator: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
    title: "Reentrancy Vulnerability in Vault Escrow Payout",
    target_repo_url: "https://github.com/bugshield-ai/demo-vault",
    vulnerability_description:
      "External call to recipient contract occurs prior to resetting balance state, allowing an attacker contract to recursively call withdraw() and drain protocol funds.",
    expected_fix_criteria:
      "Implement ReentrancyGuard nonReentrant modifier or apply Checks-Effects-Interactions pattern by setting internal balances to zero before balance transfer.",
    reward_amount: "5.0",
    status: "RESOLVED",
    winner: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    ai_verdict_reason:
      "[Submission #1] PASSED: The submitted patch strictly implements the nonReentrant modifier and updates balance states before calling transfer(). Zero secondary security flaws detected. Payout approved.",
    patch_pr_url: "https://github.com/bugshield-ai/demo-vault/pull/12",
    submission_count: "1",
  },
  {
    id: "bounty-2",
    creator: "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    title: "Integer Overflow in Staking Reward Calculator",
    target_repo_url: "https://github.com/bugshield-ai/staking-rewards",
    vulnerability_description:
      "High multiplier precision calculation `stakedAmount * rewardRate * duration` overflows standard uint256 under high liquidity scenarios.",
    expected_fix_criteria:
      "Scale calculations using OpenZeppelin Math library or SafeMath with proper precision division ordering.",
    reward_amount: "2.5",
    status: "OPEN",
    winner: "",
    ai_verdict_reason: "Awaiting Submissions",
    patch_pr_url: "",
    submission_count: "0",
  },
  {
    id: "bounty-3",
    creator: "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
    title: "Unrestricted Owner Access in Emergency Withdrawal",
    target_repo_url: "https://github.com/bugshield-ai/dao-governance",
    vulnerability_description:
      "Emergency withdraw function lacks onlyOwner / Timelock constraint, allowing any user to invoke emergency shutdown.",
    expected_fix_criteria:
      "Add AccessControl role checker or AccessControlEnumerable DEFAULT_ADMIN_ROLE constraint.",
    reward_amount: "10.0",
    status: "OPEN",
    winner: "",
    ai_verdict_reason: "Awaiting Submissions",
    patch_pr_url: "",
    submission_count: "0",
  },
];

/**
 * Check currently connected account without prompting popup
 */
export async function getConnectedAccount(): Promise<string | null> {
  if (typeof window === "undefined" || !window.ethereum) return null;
  try {
    const accounts = (await window.ethereum.request({
      method: "eth_accounts",
    })) as string[];
    return accounts && accounts.length > 0 ? accounts[0] : null;
  } catch (err) {
    console.error("Error fetching accounts:", err);
    return null;
  }
}

/**
 * Connect wallet & switch network to GenLayer Testnet
 */
export async function connectWallet(): Promise<string | null> {
  if (typeof window === "undefined" || !window.ethereum) {
    alert("MetaMask or a Web3 compatible wallet extension was not detected.");
    return null;
  }

  try {
    const accounts = (await window.ethereum.request({
      method: "eth_requestAccounts",
    })) as string[];

    // Switch network to GenLayer Testnet
    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: GENLAYER_TESTNET_CONFIG.chainId }],
      });
    } catch (switchError: any) {
      if (switchError.code === 4902) {
        await window.ethereum.request({
          method: "wallet_addEthereumChain",
          params: [GENLAYER_TESTNET_CONFIG],
        });
      }
    }

    return accounts[0] || null;
  } catch (error) {
    console.error("Error connecting wallet:", error);
    return null;
  }
}

/**
 * Poll RPC to wait for on-chain transaction finality
 */
export async function waitForTxFinality(txHash: string): Promise<void> {
  const rpcUrl = process.env.NEXT_PUBLIC_GENLAYER_RPC || "https://testnet-rpc.genlayer.com";
  const startTime = Date.now();
  // Poll for up to 30 seconds for finality
  while (Date.now() - startTime < 30000) {
    try {
      const res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "eth_getTransactionReceipt",
          params: [txHash],
          id: Date.now(),
        }),
      });
      const data = await res.json();
      if (data.result) {
        return;
      }
    } catch (e) {
      // Keep polling until receipt is confirmed
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
}

/**
 * Read single bounty state directly from contract state on-chain
 */
export async function getBountyFromRPC(bountyId: string): Promise<Bounty | null> {
  const rpcUrl = process.env.NEXT_PUBLIC_GENLAYER_RPC || "https://testnet-rpc.genlayer.com";
  try {
    const res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "gen_getContractState",
        params: [CONTRACT_ADDRESS],
        id: Date.now(),
      }),
    });

    const data = await res.json();
    if (data.result && data.result.bounties && data.result.bounties[bountyId]) {
      const raw = data.result.bounties[bountyId];
      return {
        id: String(raw.id || bountyId),
        creator: String(raw.creator || ""),
        title: String(raw.title || ""),
        target_repo_url: String(raw.target_repo_url || ""),
        vulnerability_description: String(raw.vulnerability_description || ""),
        expected_fix_criteria: String(raw.expected_fix_criteria || ""),
        reward_amount: String(raw.reward_amount || "0"),
        status: String(raw.status || "OPEN") as "OPEN" | "RESOLVED" | "CANCELLED",
        winner: String(raw.winner || ""),
        ai_verdict_reason: String(raw.ai_verdict_reason || ""),
        patch_pr_url: String(raw.patch_pr_url || ""),
        created_at: String(raw.created_at || "0"),
        submission_count: String(raw.submission_count || "0"),
      };
    }
  } catch (err) {
    console.warn("RPC getBountyFromRPC query warning:", err);
  }
  return null;
}

/**
 * Send real on-chain transaction to create bounty with native GEN token value.
 * Matches full contract signature: create_bounty(bounty_id: str, title: str, target_repo_url: str, vulnerability_description: str, expected_fix_criteria: str)
 */
export async function createBountyOnChain(
  title: string,
  targetRepoUrl: string,
  vulnerabilityDescription: string,
  expectedFixCriteria: string,
  rewardAmountGen: string,
  account: string
): Promise<{ txHash: string; bounty: Bounty }> {
  if (typeof window === "undefined" || !window.ethereum) {
    throw new Error("No Web3 wallet provider available");
  }

  const bountyId = "bounty-" + Date.now();
  const parsedVal = parseFloat(rewardAmountGen.toString().replace(",", "."));
  const numVal = isNaN(parsedVal) ? 1.0 : parsedVal;
  const weiAmount = BigInt(Math.floor(numVal * 1e18));
  const hexValue = "0x" + weiAmount.toString(16);

  // Full contract method signature: create_bounty(bounty_id, title, target_repo_url, vulnerability_description, expected_fix_criteria)
  const payload = {
    method: "create_bounty",
    args: [bountyId, title, targetRepoUrl, vulnerabilityDescription, expectedFixCriteria],
  };
  const dataHex = "0x" + Buffer.from(JSON.stringify(payload)).toString("hex");

  const txHash = (await window.ethereum.request({
    method: "eth_sendTransaction",
    params: [
      {
        from: account,
        to: CONTRACT_ADDRESS,
        value: hexValue,
        data: dataHex,
      },
    ],
  })) as string;

  // Wait for transaction finality
  await waitForTxFinality(txHash);

  // Read actual state from contract
  const fetchedBounty = await getBountyFromRPC(bountyId);

  const fallbackBounty: Bounty = {
    id: bountyId,
    creator: account,
    title,
    target_repo_url: targetRepoUrl,
    vulnerability_description: vulnerabilityDescription,
    expected_fix_criteria: expectedFixCriteria,
    reward_amount: rewardAmountGen,
    status: "OPEN",
    winner: "",
    ai_verdict_reason: "Awaiting Submissions",
    patch_pr_url: "",
  };

  return { txHash, bounty: fetchedBounty || fallbackBounty };
}

/**
 * Send real on-chain transaction to submit security patch.
 * NO local keyword checking. Waits for transaction finality and reads actual contract state on-chain!
 */
export async function submitAndEvaluatePatchOnChain(
  bountyId: string,
  patchCode: string,
  prUrl: string,
  account: string
): Promise<{ txHash: string; updatedBounty: Bounty | null }> {
  if (typeof window === "undefined" || !window.ethereum) {
    throw new Error("No Web3 wallet provider available");
  }

  const payload = {
    method: "submit_and_evaluate_patch",
    args: [bountyId, patchCode, prUrl],
  };
  const dataHex = "0x" + Buffer.from(JSON.stringify(payload)).toString("hex");

  const txHash = (await window.ethereum.request({
    method: "eth_sendTransaction",
    params: [
      {
        from: account,
        to: CONTRACT_ADDRESS,
        value: "0x0",
        data: dataHex,
      },
    ],
  })) as string;

  // 1. Wait for transaction finality on-chain
  await waitForTxFinality(txHash);

  // 2. Read actual contract verdict and resulting state from contract (NO local keyword checking!)
  const updatedBounty = await getBountyFromRPC(bountyId);

  return { txHash, updatedBounty };
}

/**
 * Send real on-chain transaction to cancel bounty & claim escrow refund.
 * Waits for transaction finality and reads updated state from contract.
 */
export async function cancelBountyOnChain(
  bountyId: string,
  account: string
): Promise<{ txHash: string; updatedBounty: Bounty | null }> {
  if (typeof window === "undefined" || !window.ethereum) {
    throw new Error("No Web3 wallet provider available");
  }

  const payload = {
    method: "cancel_bounty",
    args: [bountyId],
  };
  const dataHex = "0x" + Buffer.from(JSON.stringify(payload)).toString("hex");

  const txHash = (await window.ethereum.request({
    method: "eth_sendTransaction",
    params: [
      {
        from: account,
        to: CONTRACT_ADDRESS,
        value: "0x0",
        data: dataHex,
      },
    ],
  })) as string;

  await waitForTxFinality(txHash);
  const updatedBounty = await getBountyFromRPC(bountyId);

  return { txHash, updatedBounty };
}

/**
 * Fetch all bounties state from GenLayer RPC
 */
export async function getBountiesFromRPC(): Promise<Bounty[]> {
  try {
    const rpcUrl = process.env.NEXT_PUBLIC_GENLAYER_RPC || "https://testnet-rpc.genlayer.com";
    const res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "gen_getContractState",
        params: [CONTRACT_ADDRESS],
        id: 1,
      }),
    });

    const data = await res.json();
    if (data.result && data.result.bounties) {
      const rawList = Object.values(data.result.bounties) as any[];
      return rawList.map((b) => ({
        id: String(b.id),
        creator: String(b.creator),
        title: String(b.title),
        target_repo_url: String(b.target_repo_url),
        vulnerability_description: String(b.vulnerability_description),
        expected_fix_criteria: String(b.expected_fix_criteria),
        reward_amount: String(b.reward_amount),
        status: String(b.status) as "OPEN" | "RESOLVED" | "CANCELLED",
        winner: String(b.winner || ""),
        ai_verdict_reason: String(b.ai_verdict_reason || ""),
        patch_pr_url: String(b.patch_pr_url || ""),
        created_at: String(b.created_at || "0"),
        submission_count: String(b.submission_count || "0"),
      }));
    }
  } catch (err) {
    console.warn("Using local state fallback.", err);
  }
  return INITIAL_BOUNTIES;
}
