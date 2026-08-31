import { encodeRlp, toUtf8Bytes, hexlify, AbiCoder } from "ethers";

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
  process.env.VITE_CONTRACT_ADDRESS || process.env.NEXT_PUBLIC_CONTRACT_ADDRESS || "0x6741441ecd264949E38eDc9620B101fe427f3f69";

export const INITIAL_BOUNTIES: Bounty[] = [];

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
 * Helper to encode function call data into GenVM-compatible RLP payload
 */
export function getEncodedViewData(functionName: string, args: any[]): string {
  const methodParamsAsString = JSON.stringify(args);
  const data = [
    hexlify(toUtf8Bytes(functionName)),
    hexlify(toUtf8Bytes(methodParamsAsString))
  ];
  return encodeRlp(data);
}

/**
 * Helper to decode string value returned from standard eth_call
 */
export function decodeRpcString(hexResult: string): string {
  try {
    const decoded = AbiCoder.defaultAbiCoder().decode(["string"], hexResult);
    return decoded[0];
  } catch (e: any) {
    const cleanHex = hexResult.startsWith("0x") ? hexResult.slice(2) : hexResult;
    return Buffer.from(cleanHex, "hex").toString("utf8");
  }
}

/**
 * Executes a read-only View contract call using standard eth_call via RPC
 */
export async function ethCallViewOnChain(functionName: string, args: any[]): Promise<string> {
  const rpcUrl = process.env.NEXT_PUBLIC_GENLAYER_RPC || "https://testnet-rpc.genlayer.com";
  const encodedData = getEncodedViewData(functionName, args);

  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "eth_call",
      params: [
        {
          to: CONTRACT_ADDRESS,
          data: encodedData,
        },
        "latest",
      ],
      id: Date.now(),
    }),
  });

  const data = await res.json();
  if (data.error) {
    throw new Error(`RPC view call failed for ${functionName}: ${data.error.message || JSON.stringify(data.error)}`);
  }
  if (!data.result) {
    throw new Error(`RPC view call returned empty result for function ${functionName}`);
  }

  return decodeRpcString(data.result);
}

/**
 * Poll RPC to wait for on-chain transaction finality receipt.
 * Fails explicitly if transaction receipt is missing or execution reverted.
 */
export async function waitForTxFinality(txHash: string): Promise<any> {
  const rpcUrl = process.env.NEXT_PUBLIC_GENLAYER_RPC || "https://testnet-rpc.genlayer.com";
  const startTime = Date.now();
  
  while (Date.now() - startTime < 120000) {
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
        if (data.result.status === "0x0" || data.result.status === 0) {
          throw new Error(`Transaction execution reverted on-chain (Tx: ${txHash})`);
        }
        return data.result;
      }
    } catch (e: any) {
      if (e.message && e.message.includes("reverted")) {
        throw e;
      }
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`Transaction finality receipt timed out on-chain (Tx: ${txHash})`);
}

/**
 * Demonstrated public contract call: Reads contract state directly from get_bounty method.
 * Fails explicitly if on-chain read fails.
 */
export async function getBountyFromRPC(bountyId: string): Promise<Bounty> {
  const jsonStr = await ethCallViewOnChain("get_bounty", [bountyId]);
  const raw = JSON.parse(jsonStr);
  if (!raw || !raw.id) {
    throw new Error(`Failed to parse bounty details for ID "${bountyId}" from contract view output.`);
  }
  return {
    id: String(raw.id),
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

/**
 * Send real on-chain transaction to create bounty with native GEN token value.
 * Matches full contract signature: create_bounty(bounty_id: str, title: str, target_repo_url: str, vulnerability_description: str, expected_fix_criteria: str)
 * Fails explicitly on missing receipt or failed contract state read. Never fabricates state on failure.
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

  if (!txHash) {
    throw new Error("On-chain transaction creation request was rejected or failed to broadcast.");
  }

  // 1. Wait for transaction finality on-chain (fails on missing/reverted receipt)
  await waitForTxFinality(txHash);

  // 2. Read actual state from contract via public contract view call (fails if read fails)
  const fetchedBounty = await getBountyFromRPC(bountyId);

  return { txHash, bounty: fetchedBounty };
}

/**
 * Send real on-chain transaction to submit security patch.
 * NO local keyword checking. Waits for transaction finality and reads actual contract state on-chain!
 * Fails explicitly on missing receipt or failed contract state read. Never fabricates state on failure.
 */
export async function submitAndEvaluatePatchOnChain(
  bountyId: string,
  patchCode: string,
  prUrl: string,
  account: string
): Promise<{ txHash: string; updatedBounty: Bounty }> {
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

  if (!txHash) {
    throw new Error("On-chain transaction patch submission request was rejected or failed to broadcast.");
  }

  // 1. Wait for transaction finality on-chain (fails on missing/reverted receipt)
  await waitForTxFinality(txHash);

  // 2. Read actual contract verdict and resulting state directly from public contract view call
  const updatedBounty = await getBountyFromRPC(bountyId);

  return { txHash, updatedBounty };
}

/**
 * Send real on-chain transaction to cancel bounty & claim escrow refund.
 * Waits for transaction finality and reads updated state from contract. Fails on error.
 */
export async function cancelBountyOnChain(
  bountyId: string,
  account: string
): Promise<{ txHash: string; updatedBounty: Bounty }> {
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

  if (!txHash) {
    throw new Error("On-chain cancellation transaction request was rejected or failed to broadcast.");
  }

  await waitForTxFinality(txHash);
  const updatedBounty = await getBountyFromRPC(bountyId);

  return { txHash, updatedBounty };
}

/**
 * Demonstrated public contract call: Reads all bounties from contract using get_all_bounties method.
 * Fails explicitly on error. Never falls back to mock data on read failure.
 */
export async function getBountiesFromRPC(): Promise<Bounty[]> {
  const jsonStr = await ethCallViewOnChain("get_all_bounties", []);
  const rawList = JSON.parse(jsonStr) as any[];
  if (!Array.isArray(rawList)) {
    throw new Error("RPC response from get_all_bounties is not a valid list.");
  }
  return rawList.map((b) => ({
    id: String(b.id),
    creator: String(b.creator),
    title: String(b.title),
    target_repo_url: String(b.target_repo_url),
    vulnerability_description: String(b.vulnerability_description || ""),
    expected_fix_criteria: String(b.expected_fix_criteria || ""),
    reward_amount: String(b.reward_amount),
    status: String(b.status) as "OPEN" | "RESOLVED" | "CANCELLED",
    winner: String(b.winner || ""),
    ai_verdict_reason: String(b.ai_verdict_reason || ""),
    patch_pr_url: String(b.patch_pr_url || ""),
    created_at: String(b.created_at || "0"),
    submission_count: String(b.submission_count || "0"),
  }));
}
