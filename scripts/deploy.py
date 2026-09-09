import os
import sys
from genlayer_py import create_client, testnet_asimov
from genlayer_py.accounts.account import create_account
from genlayer_py.types import TransactionStatus

def main():
    rpc_url = os.getenv("GENLAYER_RPC_URL", "https://rpc-asimov.genlayer.com")
    private_key = os.getenv("GENLAYER_PRIVATE_KEY")

    if not private_key:
        print("[ERROR] Please provide GENLAYER_PRIVATE_KEY in your environment.")
        print("Usage: GENLAYER_PRIVATE_KEY=0x... python scripts/deploy.py")
        sys.exit(1)

    account = create_account(private_key)
    print(f"Deployer Address: {account.address}")
    print(f"Connecting to GenLayer Asimov Testnet ({rpc_url})...")
    
    client = create_client(chain=testnet_asimov, endpoint=rpc_url, account=account)

    contract_path = os.path.join(os.path.dirname(__file__), "..", "contracts", "bugshield.py")
    with open(contract_path, "r", encoding="utf-8") as f:
        contract_code = f.read()

    print("Deploying BugShield Intelligent Contract directly on-chain...")
    tx_hash = client.deploy_contract(
        code=contract_code,
        account=account,
        args=[]
    )
    print(f"Deployment Transaction Submitted! Hash: {tx_hash}")

    print("Waiting for on-chain validator consensus and finality...")
    receipt = client.wait_for_transaction_receipt(
        transaction_hash=tx_hash,
        status=TransactionStatus.FINALIZED
    )

    contract_address = receipt.get("contract_address") or receipt.get("address")
    print(f"[SUCCESS] BugShield Intelligent Contract Deployed Successfully!")
    print(f"On-Chain Contract Address: {contract_address}")
    print(f"Transaction Receipt Status: {receipt.get('status')}")

if __name__ == "__main__":
    main()
