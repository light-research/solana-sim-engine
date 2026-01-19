"""Transaction Analyzer for smart cloning."""

import base64
from typing import List, Set
from solders.transaction import VersionedTransaction
from solders.pubkey import Pubkey

# Common system programs that don't need cloning (usually built-in)
# But for safety in a local test validator, we might want to let the validator handle these
SYSTEM_PROGRAMS = {
    "11111111111111111111111111111111",  # System Program
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # Token Program
    "atoken11111111111111111111111111111111",  # SPL Associated Token Account Program
    "ComputeBudget111111111111111111111111111111",  # Compute Budget
}

def get_accounts_from_tx(tx_base64: str) -> List[str]:
    """
    Extract all unique account keys from a base64 encoded transaction.
    
    Args:
        tx_base64: Base64 encoded transaction string
        
    Returns:
        List of base58 encoded public keys to clone
    """
    try:
        tx_bytes = base64.b64decode(tx_base64)
        tx = VersionedTransaction.from_bytes(tx_bytes)
        
        account_keys: Set[str] = set()
        
        # Get static account keys
        for key in tx.message.account_keys:
            key_str = str(key)
            if key_str not in SYSTEM_PROGRAMS:
                account_keys.add(key_str)
                
        # Versioned transactions might have address table lookups
        # Ideally we'd resolve these too, but for Jupiter swaps usually 
        # the main accounts are in the static list or we rely on RPC to resolving them 
        # in a real environment. For cloning, we'll start with static keys.
        # Note: If Jupiter uses ALT (Address Lookup Tables), we are missing those accounts here.
        # However, resolving ALTs requires an RPC call to fetch the table.
        # For a v1 POC, let's see if static keys are sufficient or if we need to fetch ALTs.
        
        return list(account_keys)
        
    except Exception as e:
        print(f"Error parsing transaction: {e}")
        return []
