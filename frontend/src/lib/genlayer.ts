import { encodeRlp, AbiCoder, formatEther } from "ethers";

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
  commit_hash?: string;
  created_at?: string;
  submission_count?: string;
}

export const GENLAYER_TESTNET_CONFIG = {
  chainId: "0xF22F", // 61999 in hex (0xF22F)
  chainName: "GenLayer Testnet",
  rpcUrls: [process.env.NEXT_PUBLIC_GENLAYER_RPC || "https://studio.genlayer.com/api"],
  nativeCurrency: {
    name: "GenLayer Token",
    symbol: "GEN",
    decimals: 18,
  },
  blockExplorerUrls: ["https://scan.genlayer.com"],
};

// Target Intelligent Contract Address
export const CONTRACT_ADDRESS =
  process.env.VITE_CONTRACT_ADDRESS || process.env.NEXT_PUBLIC_CONTRACT_ADDRESS || "0x44e0Cf896c434B57F1439A1d1699C27A50AD87D0";

// GenLayer Consensus Main Contract (transactions are submitted here to trigger validator consensus)
export const CONSENSUS_MAIN_CONTRACT = "0x0000000000000000000000000000000000000000";

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
 * Format raw token reward amount from wei (1e18) to human-readable GEN (e.g. 1, 3.5, 15)
 */
export function formatRewardAmount(rawAmount: string | number): string {
  if (!rawAmount) return "0";
  try {
    const str = String(rawAmount).trim();
    if (str.length > 12) {
      const formatted = formatEther(str);
      const num = parseFloat(formatted);
      return isNaN(num) ? formatted : num.toString();
    }
    return str;
  } catch {
    return String(rawAmount);
  }
}

// -------------------------------------------------------------
// GenLayer Native Calldata Encoder & Decoder (Pure TypeScript)
// -------------------------------------------------------------
const BITS_IN_TYPE = 3;
const TYPE_SPECIAL = 0;
const TYPE_PINT = 1;
const TYPE_NINT = 2;
const TYPE_BYTES = 3;
const TYPE_STR = 4;
const TYPE_ARR = 5;
const TYPE_MAP = 6;

function appendUleb128(mem: number[], i: number | bigint): void {
  let val = BigInt(i);
  if (val === 0n) {
    mem.push(0);
    return;
  }
  while (val > 0n) {
    let cur = Number(val & 0x7fn);
    val = val >> 7n;
    if (val > 0n) cur |= 0x80;
    mem.push(cur);
  }
}

export function encodeCalldata(x: any): Buffer {
  const mem: number[] = [];

  function impl(b: any): void {
    if (b === null || b === undefined) {
      mem.push(0);
    } else if (b === false) {
      mem.push(1 << BITS_IN_TYPE);
    } else if (b === true) {
      mem.push(2 << BITS_IN_TYPE);
    } else if (typeof b === "number" || typeof b === "bigint") {
      let n = BigInt(b);
      if (n >= 0n) {
        appendUleb128(mem, (n << 3n) | BigInt(TYPE_PINT));
      } else {
        n = -n - 1n;
        appendUleb128(mem, (n << 3n) | BigInt(TYPE_NINT));
      }
    } else if (typeof b === "string") {
      const bts = Buffer.from(b, "utf8");
      appendUleb128(mem, (BigInt(bts.length) << 3n) | BigInt(TYPE_STR));
      for (let i = 0; i < bts.length; i++) mem.push(bts[i]);
    } else if (Array.isArray(b)) {
      appendUleb128(mem, (BigInt(b.length) << 3n) | BigInt(TYPE_ARR));
      for (const item of b) impl(item);
    } else if (typeof b === "object") {
      const keys = Object.keys(b).sort();
      appendUleb128(mem, (BigInt(keys.length) << 3n) | BigInt(TYPE_MAP));
      for (const k of keys) {
        const bts = Buffer.from(k, "utf8");
        appendUleb128(mem, bts.length);
        for (let i = 0; i < bts.length; i++) mem.push(bts[i]);
        impl(b[k]);
      }
    } else {
      throw new Error("Unsupported calldata type: " + typeof b);
    }
  }

  impl(x);
  return Buffer.from(mem);
}

function readUleb128(buf: Uint8Array, state: { offset: number }): number {
  let ret = 0n;
  let off = 0n;
  while (true) {
    const m = BigInt(buf[state.offset++]);
    ret = ret | ((m & 0x7fn) << off);
    off += 7n;
    if ((m & 0x80n) === 0n) break;
  }
  return Number(ret);
}

export function decodeCalldata(buf: Uint8Array): any {
  const state = { offset: 0 };

  function impl(): any {
    const code = readUleb128(buf, state);
    const typ = code & 0x7;
    if (typ === TYPE_SPECIAL) {
      if (code === 0) return null;
      if (code === 8) return false;
      if (code === 16) return true;
      throw new Error("Unknown special: " + code);
    }
    const val = code >> 3;
    if (typ === TYPE_PINT) return val;
    if (typ === TYPE_NINT) return -val - 1;
    if (typ === TYPE_BYTES) {
      const bts = buf.subarray(state.offset, state.offset + val);
      state.offset += val;
      return bts;
    }
    if (typ === TYPE_STR) {
      const strBytes = buf.subarray(state.offset, state.offset + val);
      state.offset += val;
      return Buffer.from(strBytes).toString("utf8");
    }
    if (typ === TYPE_ARR) {
      const arr = [];
      for (let i = 0; i < val; i++) arr.push(impl());
      return arr;
    }
    if (typ === TYPE_MAP) {
      const obj: Record<string, any> = {};
      for (let i = 0; i < val; i++) {
        const kLen = readUleb128(buf, state);
        const key = Buffer.from(buf.subarray(state.offset, state.offset + kLen)).toString("utf8");
        state.offset += kLen;
        obj[key] = impl();
      }
      return obj;
    }
    throw new Error("Unsupported type: " + typ);
  }

  return impl();
}

/**
 * Encodes GenLayer Consensus addTransaction call
 */
export function encodeAddTransaction(
  sender: string,
  recipient: string,
  numValidators: number,
  maxRotations: number,
  txDataRlp: string
): string {
  const selector = "0x27241a99";
  const abiCoder = AbiCoder.defaultAbiCoder();
  const encodedParams = abiCoder.encode(
    ["address", "address", "uint256", "uint256", "bytes"],
    [sender, recipient, numValidators, maxRotations, txDataRlp]
  );
  return selector + encodedParams.slice(2);
}

/**
 * Executes a read-only View contract call using native gen_call via GenLayer RPC
 */
export async function ethCallViewOnChain(functionName: string, args: any[] = []): Promise<string> {
  const calldataBytes = encodeCalldata({ method: functionName, args });
  const serializedData = encodeRlp([calldataBytes, "0x00"]);

  const endpoints = [
    process.env.NEXT_PUBLIC_GENLAYER_RPC,
    "https://studio.genlayer.com/api",
    "https://testnet-rpc.genlayer.com",
  ].filter(Boolean) as string[];

  let lastError: any = null;

  for (const rpcUrl of endpoints) {
    try {
      const res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: Date.now(),
          method: "gen_call",
          params: [
            {
              type: "read",
              to: CONTRACT_ADDRESS,
              from: "0x0000000000000000000000000000000000000000",
              data: serializedData,
              transaction_hash_variant: "latest-nonfinal",
            },
          ],
        }),
      });

      const json = await res.json();
      if (json.error) {
        lastError = json.error;
        continue;
      }

      if (json.result) {
        const rawHex = json.result.startsWith("0x") ? json.result.slice(2) : json.result;
        const decoded = decodeCalldata(Buffer.from(rawHex, "hex"));
        if (typeof decoded === "string") {
          return decoded;
        }
        return JSON.stringify(decoded);
      }
    } catch (e: any) {
      lastError = e;
    }
  }

  throw new Error(`RPC gen_call failed for ${functionName}: ${lastError?.message || JSON.stringify(lastError)}`);
}

/**
 * Poll RPC to wait for on-chain transaction confirmation and consensus finality.
 */
export async function waitForTxFinality(txHash: string): Promise<any> {
  const startTime = Date.now();
  const endpoints = [
    process.env.NEXT_PUBLIC_GENLAYER_RPC,
    "https://studio.genlayer.com/api",
  ].filter(Boolean) as string[];

  while (Date.now() - startTime < 120000) {
    if (typeof window !== "undefined" && window.ethereum) {
      try {
        const receipt = await window.ethereum.request({
          method: "eth_getTransactionReceipt",
          params: [txHash],
        });
        if (receipt) {
          if (receipt.status === "0x0" || receipt.status === 0) {
            throw new Error(`Transaction execution reverted on-chain (Tx: ${txHash})`);
          }
          return receipt;
        }
      } catch (e: any) {
        if (e.message && e.message.includes("reverted")) {
          throw e;
        }
      }
    }

    for (const rpcUrl of endpoints) {
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
        if (data && data.result) {
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
    }

    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`Transaction finality receipt timed out on-chain (Tx: ${txHash})`);
}

/**
 * Reads single bounty directly from get_bounty method.
 */
export async function getBountyFromRPC(bountyId: string): Promise<Bounty> {
  const jsonStr = await ethCallViewOnChain("get_bounty", [bountyId]);
  const raw = typeof jsonStr === "object" ? jsonStr : JSON.parse(jsonStr);
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
    reward_amount: formatRewardAmount(raw.reward_amount || "0"),
    status: String(raw.status || "OPEN") as "OPEN" | "RESOLVED" | "CANCELLED",
    winner: String(raw.winner || ""),
    ai_verdict_reason: String(raw.ai_verdict_reason || ""),
    patch_pr_url: String(raw.patch_pr_url || ""),
    commit_hash: String(raw.commit_hash || ""),
    created_at: String(raw.created_at || "0"),
    submission_count: String(raw.submission_count || "0"),
  };
}

/**
 * Send real on-chain transaction to create bounty with native GEN token value.
 */
export async function createBountyOnChain(
  title: string,
  targetRepoUrl: string,
  vulnerabilityDescription: string,
  expectedFixCriteria: string,
  rewardAmountGen: string,
  account: string,
  onStatusChange?: (status: string) => void
): Promise<{ txHash: string; bounty: Bounty }> {
  if (typeof window === "undefined" || !window.ethereum) {
    throw new Error("No Web3 wallet provider available");
  }

  const bountyId = "bounty-" + Date.now();
  const parsedVal = parseFloat(rewardAmountGen.toString().replace(",", "."));
  const numVal = isNaN(parsedVal) ? 1.0 : parsedVal;
  const weiAmount = BigInt(Math.floor(numVal * 1e18));
  const hexValue = "0x" + weiAmount.toString(16);

  const calldataBytes = encodeCalldata({
    method: "create_bounty",
    args: [bountyId, title, targetRepoUrl, vulnerabilityDescription, expectedFixCriteria],
  });
  const txDataRlp = encodeRlp([calldataBytes, "0x"]);
  const callData = encodeAddTransaction(account, CONTRACT_ADDRESS, 5, 3, txDataRlp);

  onStatusChange?.("Step 1/3: Prompting MetaMask for real on-chain transaction approval...");

  const txHash = (await window.ethereum.request({
    method: "eth_sendTransaction",
    params: [
      {
        from: account,
        to: CONSENSUS_MAIN_CONTRACT,
        value: hexValue,
        data: callData,
      },
    ],
  })) as string;

  if (!txHash) {
    throw new Error("On-chain transaction creation request was rejected or failed to broadcast.");
  }

  onStatusChange?.(`Step 2/3: Transaction broadcasted (${txHash.slice(0, 10)}...)! GenLayer Validators processing consensus...`);

  await waitForTxFinality(txHash);

  onStatusChange?.("Step 3/3: Transaction confirmed! Reading on-chain contract state...");

  // Poll until the bounty appears on-chain in the contract (waiting for consensus block)
  let fetchedBounty: Bounty | null = null;
  const pollStart = Date.now();
  while (Date.now() - pollStart < 45000) {
    try {
      fetchedBounty = await getBountyFromRPC(bountyId);
      if (fetchedBounty && fetchedBounty.id === bountyId) {
        break;
      }
    } catch {
      // not yet visible in state, wait for consensus
    }
    await new Promise((r) => setTimeout(r, 3000));
  }

  if (!fetchedBounty) {
    fetchedBounty = {
      id: bountyId,
      creator: account,
      title: title,
      target_repo_url: targetRepoUrl,
      vulnerability_description: vulnerabilityDescription,
      expected_fix_criteria: expectedFixCriteria,
      reward_amount: formatRewardAmount(weiAmount.toString()),
      status: "OPEN",
      winner: "",
      ai_verdict_reason: "Awaiting Submissions",
      patch_pr_url: "",
      created_at: String(Math.floor(Date.now() / 1000)),
      submission_count: "0",
    };
  }

  return { txHash, bounty: fetchedBounty };
}

/**
 * Send real on-chain transaction to submit security patch.
 */
export async function submitAndEvaluatePatchOnChain(
  bountyId: string,
  commitHash: string,
  prUrl: string,
  account: string,
  onStatusChange?: (status: string) => void
): Promise<{ txHash: string; updatedBounty: Bounty }> {
  if (typeof window === "undefined" || !window.ethereum) {
    throw new Error("No Web3 wallet provider available");
  }

  const calldataBytes = encodeCalldata({
    method: "submit_and_evaluate_patch",
    args: [bountyId, commitHash, prUrl],
  });
  const txDataRlp = encodeRlp([calldataBytes, "0x"]);
  const callData = encodeAddTransaction(account, CONTRACT_ADDRESS, 5, 3, txDataRlp);

  onStatusChange?.("Step 1/3: Prompting MetaMask for On-Chain Patch Transaction Approval...");

  const txHash = (await window.ethereum.request({
    method: "eth_sendTransaction",
    params: [
      {
        from: account,
        to: CONSENSUS_MAIN_CONTRACT,
        value: "0x0",
        data: callData,
      },
    ],
  })) as string;

  if (!txHash) {
    throw new Error("On-chain transaction patch submission request was rejected or failed to broadcast.");
  }

  onStatusChange?.(`Step 2/3: Transaction broadcasted (${txHash.slice(0, 10)}...)! GenLayer Validators fetching authentic commit diff & evaluating consensus...`);

  await waitForTxFinality(txHash);

  onStatusChange?.("Step 3/3: Consensus evaluated! Reading confirmed on-chain verdict & state...");

  // Wait 10 seconds for validators to finish execution and state update
  await new Promise((r) => setTimeout(r, 10000));
  const updatedBounty = await getBountyFromRPC(bountyId);

  return { txHash, updatedBounty };
}

/**
 * Send real on-chain transaction to cancel bounty & claim escrow refund.
 */
export async function cancelBountyOnChain(
  bountyId: string,
  account: string
): Promise<{ txHash: string; updatedBounty: Bounty }> {
  if (typeof window === "undefined" || !window.ethereum) {
    throw new Error("No Web3 wallet provider available");
  }

  const calldataBytes = encodeCalldata({
    method: "cancel_bounty",
    args: [bountyId],
  });
  const txDataRlp = encodeRlp([calldataBytes, "0x"]);
  const callData = encodeAddTransaction(account, CONTRACT_ADDRESS, 5, 3, txDataRlp);

  const txHash = (await window.ethereum.request({
    method: "eth_sendTransaction",
    params: [
      {
        from: account,
        to: CONSENSUS_MAIN_CONTRACT,
        value: "0x0",
        data: callData,
      },
    ],
  })) as string;

  if (!txHash) {
    throw new Error("On-chain cancellation transaction request was rejected or failed to broadcast.");
  }

  await waitForTxFinality(txHash);
  await new Promise((r) => setTimeout(r, 5000));
  const updatedBounty = await getBountyFromRPC(bountyId);

  return { txHash, updatedBounty };
}

/**
 * Reads all bounties from contract using get_all_bounties method.
 */
export async function getBountiesFromRPC(): Promise<Bounty[]> {
  const jsonStr = await ethCallViewOnChain("get_all_bounties", []);
  const rawList = (typeof jsonStr === "object" ? jsonStr : JSON.parse(jsonStr)) as any[];
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
    reward_amount: formatRewardAmount(b.reward_amount || "0"),
    status: String(b.status) as "OPEN" | "RESOLVED" | "CANCELLED",
    winner: String(b.winner || ""),
    ai_verdict_reason: String(b.ai_verdict_reason || ""),
    patch_pr_url: String(b.patch_pr_url || ""),
    commit_hash: String(b.commit_hash || ""),
    created_at: String(b.created_at || "0"),
    submission_count: String(b.submission_count || "0"),
  }));
}
