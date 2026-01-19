"""
Transaction Builder: Converts scenario steps to real Solana transactions.
"""

import json
import struct
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from base64 import b64encode, b64decode

# Use solders for Solana primitives if available
try:
    from solders.keypair import Keypair
    from solders.pubkey import Pubkey
    from solders.instruction import Instruction, AccountMeta
    from solders.transaction import Transaction
    from solders.message import Message
    from solders.hash import Hash
    SOLDERS_AVAILABLE = True
except ImportError:
    SOLDERS_AVAILABLE = False

from ..analysis.models import ProgramAnalysis, InstructionSpec
from ..fuzzing.models import ScenarioStep


@dataclass
class TestWallet:
    """A test wallet with keypair."""
    name: str
    keypair: Any  # Keypair from solders
    pubkey: str
    
    @classmethod
    def generate(cls, name: str) -> "TestWallet":
        """Generate a new test wallet."""
        if not SOLDERS_AVAILABLE:
            # Fallback: generate a fake pubkey
            import os
            fake_key = os.urandom(32)
            fake_pubkey = hashlib.sha256(fake_key).hexdigest()[:44]
            return cls(name=name, keypair=None, pubkey=fake_pubkey)
        
        keypair = Keypair()
        return cls(
            name=name,
            keypair=keypair,
            pubkey=str(keypair.pubkey()),
        )


@dataclass 
class WalletManager:
    """Manages test wallets for scenario execution."""
    wallets: Dict[str, TestWallet] = field(default_factory=dict)
    
    def get_or_create(self, name: str) -> TestWallet:
        """Get existing wallet or create new one."""
        if name not in self.wallets:
            self.wallets[name] = TestWallet.generate(name)
        return self.wallets[name]
    
    def get_pubkey(self, name: str) -> str:
        """Get pubkey for a wallet by name."""
        return self.get_or_create(name).pubkey
    
    def get_all_pubkeys(self) -> List[str]:
        """Get all wallet pubkeys for airdrop."""
        return [w.pubkey for w in self.wallets.values()]


@dataclass
class BuiltTransaction:
    """A built transaction ready for submission."""
    instruction_name: str
    program_id: str
    accounts: List[Dict[str, Any]]
    data: bytes
    data_base64: str
    signers: List[str]
    
    # Raw transaction if built with solders
    raw_transaction: Optional[Any] = None
    serialized_base64: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "instruction": self.instruction_name,
            "program_id": self.program_id,
            "accounts": self.accounts,
            "data_base64": self.data_base64,
            "signers": self.signers,
        }


class TransactionBuilder:
    """
    Builds real Solana transactions from scenario steps.
    
    Handles:
    - Instruction data encoding (Anchor discriminator + args)
    - Account resolution (PDAs, ATAs, etc.)
    - Transaction signing
    """
    
    # Known program IDs
    SYSTEM_PROGRAM = "11111111111111111111111111111111"
    TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
    
    def __init__(
        self,
        analysis: ProgramAnalysis,
        program_id: Optional[str] = None,
    ):
        """
        Initialize transaction builder.
        
        Args:
            analysis: Program analysis for instruction specs
            program_id: Override program ID (or use from analysis)
        """
        self.analysis = analysis
        self.program_id = program_id or analysis.program_id or self._generate_program_id()
        self.wallet_manager = WalletManager()
        
        # Pre-generate common wallets
        self.wallet_manager.get_or_create("authority")
        self.wallet_manager.get_or_create("user")
        self.wallet_manager.get_or_create("attacker")
    
    def _generate_program_id(self) -> str:
        """Generate a deterministic program ID from program name."""
        h = hashlib.sha256(self.analysis.name.encode()).digest()
        
        if SOLDERS_AVAILABLE:
            # Create a proper base58 pubkey
            pubkey = Pubkey(h)
            return str(pubkey)
        else:
            # Fallback: create a base58-like string
            alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            result = ""
            for b in h[:32]:
                result += alphabet[b % len(alphabet)]
            return result[:44]

    
    def build_step(self, step: ScenarioStep) -> BuiltTransaction:
        """
        Build a transaction from a scenario step.
        
        Args:
            step: The scenario step to build
            
        Returns:
            BuiltTransaction ready for submission
        """
        # Get instruction spec
        ix_spec = self.analysis.get_instruction(step.instruction)
        if not ix_spec:
            raise ValueError(f"Unknown instruction: {step.instruction}")
        
        # Build instruction data
        data = self._encode_instruction_data(ix_spec, step.arguments)
        
        # Build account list
        accounts = self._build_accounts(ix_spec, step)
        
        # Determine signers
        signers = self._determine_signers(ix_spec, step)
        
        tx = BuiltTransaction(
            instruction_name=step.instruction,
            program_id=self.program_id,
            accounts=accounts,
            data=data,
            data_base64=b64encode(data).decode(),
            signers=signers,
        )
        
        # Build raw transaction if solders available
        if SOLDERS_AVAILABLE:
            tx.raw_transaction, tx.serialized_base64 = self._build_raw_transaction(
                tx, ix_spec, step
            )
        
        return tx
    
    def _encode_instruction_data(
        self,
        ix_spec: InstructionSpec,
        arguments: Dict[str, Any],
    ) -> bytes:
        """Encode instruction data with Anchor discriminator."""
        # Anchor discriminator: first 8 bytes of sha256("global:<instruction_name>")
        discriminator = self._compute_discriminator(ix_spec.name)
        
        # Encode arguments
        args_data = self._encode_arguments(ix_spec, arguments)
        
        return discriminator + args_data
    
    def _compute_discriminator(self, name: str) -> bytes:
        """Compute Anchor instruction discriminator."""
        # Anchor uses: sha256("global:<snake_case_name>")[:8]
        snake_name = self._to_snake_case(name)
        preimage = f"global:{snake_name}"
        return hashlib.sha256(preimage.encode()).digest()[:8]
    
    def _to_snake_case(self, name: str) -> str:
        """Convert camelCase to snake_case."""
        result = []
        for i, c in enumerate(name):
            if c.isupper() and i > 0:
                result.append('_')
            result.append(c.lower())
        return ''.join(result)
    
    def _encode_arguments(
        self,
        ix_spec: InstructionSpec,
        arguments: Dict[str, Any],
    ) -> bytes:
        """Encode instruction arguments."""
        data = b""
        
        for arg in ix_spec.arguments:
            value = arguments.get(arg.name, 0)
            
            # Handle different types
            arg_type = arg.arg_type.lower()
            
            if "u64" in arg_type:
                data += struct.pack("<Q", int(value))
            elif "u32" in arg_type:
                data += struct.pack("<I", int(value))
            elif "u16" in arg_type:
                data += struct.pack("<H", int(value))
            elif "u8" in arg_type:
                data += struct.pack("<B", int(value))
            elif "i64" in arg_type:
                data += struct.pack("<q", int(value))
            elif "i32" in arg_type:
                data += struct.pack("<i", int(value))
            elif "bool" in arg_type:
                data += struct.pack("<B", 1 if value else 0)
            elif "publickey" in arg_type:
                # Assume it's a base58 string
                if isinstance(value, str):
                    data += b64decode(value + "==")[:32]
                else:
                    data += bytes(32)  # Zero pubkey
            else:
                # Unknown type, skip or use as bytes
                if isinstance(value, bytes):
                    data += value
                elif isinstance(value, str):
                    encoded = value.encode()
                    data += struct.pack("<I", len(encoded)) + encoded
        
        return data
    
    def _build_accounts(
        self,
        ix_spec: InstructionSpec,
        step: ScenarioStep,
    ) -> List[Dict[str, Any]]:
        """Build account list for instruction."""
        accounts = []
        
        for acc_spec in ix_spec.accounts:
            # Check if account is explicitly provided in step
            if acc_spec.name in step.accounts:
                pubkey = step.accounts[acc_spec.name]
            else:
                # Generate or derive
                pubkey = self._resolve_account(acc_spec.name, step)
            
            accounts.append({
                "pubkey": pubkey,
                "is_signer": acc_spec.is_signer,
                "is_writable": acc_spec.is_writable,
            })
        
        return accounts
    
    def _resolve_account(self, name: str, step: ScenarioStep) -> str:
        """Resolve an account address by name."""
        name_lower = name.lower()
        
        # System program
        if "system" in name_lower and "program" in name_lower:
            return self.SYSTEM_PROGRAM
        
        # Token program
        if "token" in name_lower and "program" in name_lower:
            return self.TOKEN_PROGRAM
        
        # Associated token program
        if "associated" in name_lower:
            return self.ASSOCIATED_TOKEN_PROGRAM
        
        # Authority/admin/owner - use signer wallet
        if any(kw in name_lower for kw in ["authority", "admin", "owner"]):
            signer = step.signer or "authority"
            return self.wallet_manager.get_pubkey(signer)
        
        # User accounts
        if "user" in name_lower:
            return self.wallet_manager.get_pubkey("user")
        
        # Generate a deterministic pubkey for other accounts
        # Use solders to create a proper base58 pubkey if available
        if SOLDERS_AVAILABLE:
            seed = f"{self.analysis.name}:{name}".encode()
            h = hashlib.sha256(seed).digest()
            # Create a pubkey from the hash bytes
            pubkey = Pubkey(h)
            return str(pubkey)
        else:
            # Fallback: create a fake but valid-looking pubkey
            seed = f"{self.analysis.name}:{name}".encode()
            h = hashlib.sha256(seed).digest()
            # Convert to a base58-like string (alphanumeric, no 0/O/I/l)
            alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            result = ""
            for b in h[:32]:
                result += alphabet[b % len(alphabet)]
            return result[:44]
    
    def _determine_signers(
        self,
        ix_spec: InstructionSpec,
        step: ScenarioStep,
    ) -> List[str]:
        """Determine which wallets need to sign."""
        signers = []
        
        # Add explicit signer from step
        if step.signer:
            signers.append(self.wallet_manager.get_pubkey(step.signer))
        
        # Add required signers from instruction spec
        for acc in ix_spec.accounts:
            if acc.is_signer:
                pubkey = self._resolve_account(acc.name, step)
                if pubkey not in signers:
                    signers.append(pubkey)
        
        return signers

    
    def _build_raw_transaction(
        self,
        tx: BuiltTransaction,
        ix_spec: InstructionSpec,
        step: ScenarioStep,
    ) -> Tuple[Any, str]:
        """Build raw transaction using solders."""
        if not SOLDERS_AVAILABLE:
            return None, ""
        
        try:
            # Build instruction
            program_id = Pubkey.from_string(tx.program_id) if len(tx.program_id) == 44 else Pubkey.default()
            
            account_metas = []
            for acc in tx.accounts:
                try:
                    pubkey = Pubkey.from_string(acc["pubkey"]) if len(acc["pubkey"]) == 44 else Pubkey.default()
                except:
                    pubkey = Pubkey.default()
                
                account_metas.append(AccountMeta(
                    pubkey=pubkey,
                    is_signer=acc["is_signer"],
                    is_writable=acc["is_writable"],
                ))
            
            instruction = Instruction(
                program_id=program_id,
                accounts=account_metas,
                data=tx.data,
            )
            
            # Get payer
            payer_name = step.signer or "authority"
            payer_wallet = self.wallet_manager.get_or_create(payer_name)
            
            if payer_wallet.keypair:
                payer = payer_wallet.keypair.pubkey()
            else:
                payer = Pubkey.default()
            
            # Build message (use a dummy recent blockhash)
            recent_blockhash = Hash.default()
            
            message = Message.new_with_blockhash(
                [instruction],
                payer,
                recent_blockhash,
            )
            
            # Create transaction
            transaction = Transaction.new_unsigned(message)
            
            # Serialize
            serialized = bytes(transaction)
            serialized_b64 = b64encode(serialized).decode()
            
            return transaction, serialized_b64
            
        except Exception as e:
            # If solders fails, return None
            print(f"Warning: Failed to build raw transaction: {e}")
            return None, ""
    
    def build_scenario(self, steps: List[ScenarioStep]) -> List[BuiltTransaction]:
        """Build all transactions for a scenario."""
        return [self.build_step(step) for step in steps]
    
    def get_airdrop_wallets(self) -> List[str]:
        """Get all wallet pubkeys that need SOL."""
        return self.wallet_manager.get_all_pubkeys()
