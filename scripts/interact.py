import os
import sys
import json
from genlayer_py import create_client, testnet_asimov
from genlayer_py.accounts.account import create_account

def main():
    contract_address = os.getenv("NEXT_PUBLIC_CONTRACT_ADDRESS")
    rpc_url = os.getenv("GENLAYER_RPC_URL", "https://rpc-asimov.genlayer.com")
    private_key = os.getenv("GENLAYER_PRIVATE_KEY")

    if not contract_address:
        print("[ERROR] NEXT_PUBLIC_CONTRACT_ADDRESS is required.")
        sys.exit(1)

    print(f"Target Contract: {contract_address}")
    print(f"Network: GenLayer Asimov Testnet ({rpc_url})")

    account = create_account(private_key) if private_key else None
    client = create_client(chain=testnet_asimov, endpoint=rpc_url, account=account)

    print("\nReading active bounties on-chain...")
    try:
        bounties_raw = client.read_contract(
            address=contract_address,
            function_name="get_all_bounties",
            args=[]
        )
        bounties = json.loads(bounties_raw) if isinstance(bounties_raw, str) else bounties_raw
        print(f"Active bounties found: {len(bounties)}")
        print(json.dumps(bounties, indent=2))
    except Exception as e:
        print(f"Failed to read contract: {e}")

if __name__ == "__main__":
    main()
