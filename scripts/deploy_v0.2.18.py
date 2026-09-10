import sys
import os
import json
from genlayer_py import create_client, studionet
from genlayer_py.accounts.account import create_account
from genlayer_py.types import TransactionStatus

def main():
    rpc_url = os.environ.get("GENLAYER_RPC_URL", "https://studio.genlayer.com/api")
    private_key = os.environ.get("DEPLOYER_PRIVATE_KEY", "")
    if not private_key:
        print("Please set DEPLOYER_PRIVATE_KEY environment variable.")
        return

    print("================================================================================")
    print("[DEPLOY] Deploying Upgraded BugShield AI Contract v0.2.18 to GenLayer...")
    print("================================================================================")

    account = create_account(private_key)
    print(f"Deployer Address: {account.address}")

    client = create_client(chain=studionet, endpoint=rpc_url, account=account)

    contract_path = r"c:\Users\Admin\Documents\genlayer\BugShield AI\contracts\bugshield.py"
    with open(contract_path, "r", encoding="utf-8") as f:
        contract_code = f.read()

    print(f"Submitting contract deployment transaction ({len(contract_code)} bytes)...")
    tx_hash = client.deploy_contract(
        code=contract_code,
        args=[]
    )
    print(f"Transaction Submitted! Hash: {tx_hash}")

    print("Waiting for on-chain consensus finality...")
    receipt = client.wait_for_transaction_receipt(tx_hash, status=TransactionStatus.FINALIZED)

    contract_address = receipt.get("contract_address") or receipt.get("address")
    print("\n================================================================================")
    print(f"[SUCCESS] BugShield Contract v0.2.18 Deployed!")
    print(f"Contract Address: {contract_address}")
    print(f"Transaction Hash: {tx_hash}")
    print(f"Receipt Status: {receipt.get('status')}")
    print("================================================================================\n")

    output_info = {
        "contract_address": contract_address,
        "deploy_tx_hash": tx_hash,
        "deployer": account.address,
        "status": receipt.get("status")
    }
    with open(r"c:\Users\Admin\Documents\genlayer\BugShield AI\deployed_contract.json", "w") as out_f:
        json.dump(output_info, out_f, indent=2)

if __name__ == "__main__":
    main()
