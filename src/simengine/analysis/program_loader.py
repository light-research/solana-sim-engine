"""
Program Loader: Handles loading and validation of Solana programs.
"""

import os
import hashlib
import struct
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any


@dataclass
class ProgramInfo:
    """Information about a loaded Solana program."""
    path: str
    name: str
    size_bytes: int
    sha256: str
    
    # ELF info (if parseable)
    is_valid_elf: bool = False
    architecture: Optional[str] = None
    entry_point: Optional[int] = None
    
    # Deployment info
    program_id: Optional[str] = None
    deployed: bool = False
    
    # Associated files
    idl_path: Optional[str] = None
    keypair_path: Optional[str] = None


class ProgramLoader:
    """
    Loads and validates Solana BPF programs (.so files).
    
    Handles:
    - File validation (exists, is ELF, correct architecture)
    - Hash computation for integrity
    - Associated file discovery (IDL, keypair)
    - Preparation for Surfpool deployment
    """
    
    # ELF magic number
    ELF_MAGIC = b'\x7fELF'
    
    # BPF architecture markers
    BPF_MACHINE = 0xF7  # EM_BPF
    
    def __init__(self):
        self.loaded_programs: Dict[str, ProgramInfo] = {}
    
    def load(self, path: str) -> ProgramInfo:
        """
        Load a Solana program from a .so file.
        
        Args:
            path: Path to the .so file
            
        Returns:
            ProgramInfo with details about the program
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file is not a valid Solana program
        """
        path = os.path.abspath(path)
        
        if not os.path.exists(path):
            raise FileNotFoundError(f"Program file not found: {path}")
        
        if not path.endswith('.so'):
            raise ValueError(f"Expected .so file, got: {path}")
        
        # Read file
        with open(path, 'rb') as f:
            data = f.read()
        
        # Compute hash
        sha256 = hashlib.sha256(data).hexdigest()
        
        # Validate ELF
        is_valid_elf, arch, entry = self._validate_elf(data)
        
        # Extract name from path
        name = Path(path).stem
        
        # Look for associated files
        idl_path = self._find_idl(path)
        keypair_path = self._find_keypair(path)
        
        info = ProgramInfo(
            path=path,
            name=name,
            size_bytes=len(data),
            sha256=sha256,
            is_valid_elf=is_valid_elf,
            architecture=arch,
            entry_point=entry,
            idl_path=idl_path,
            keypair_path=keypair_path,
        )
        
        self.loaded_programs[path] = info
        return info
    
    def _validate_elf(self, data: bytes) -> Tuple[bool, Optional[str], Optional[int]]:
        """Validate ELF format and extract basic info."""
        if len(data) < 64:
            return False, None, None
        
        # Check magic
        if data[:4] != self.ELF_MAGIC:
            return False, None, None
        
        # Check class (64-bit)
        if data[4] != 2:  # ELFCLASS64
            return False, "32-bit (unexpected)", None
        
        # Check machine type
        # Offset 18-19 in ELF header is e_machine
        machine = struct.unpack('<H', data[18:20])[0]
        
        if machine == self.BPF_MACHINE:
            arch = "BPF"
        elif machine == 0x3E:  # x86_64
            arch = "x86_64"
        else:
            arch = f"Unknown ({machine})"
        
        # Get entry point (offset 24-32 in 64-bit ELF)
        entry = struct.unpack('<Q', data[24:32])[0]
        
        return True, arch, entry
    
    def _find_idl(self, program_path: str) -> Optional[str]:
        """Look for associated IDL file."""
        base = Path(program_path)
        
        # Common IDL locations
        candidates = [
            base.with_suffix('.json'),
            base.parent / 'idl' / f'{base.stem}.json',
            base.parent.parent / 'idl' / f'{base.stem}.json',
            base.parent.parent / 'target' / 'idl' / f'{base.stem}.json',
        ]
        
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        
        return None
    
    def _find_keypair(self, program_path: str) -> Optional[str]:
        """Look for associated keypair file."""
        base = Path(program_path)
        
        # Common keypair locations
        candidates = [
            base.with_name(f'{base.stem}-keypair.json'),
            base.parent / f'{base.stem}-keypair.json',
        ]
        
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        
        return None
    
    def validate_for_deployment(self, info: ProgramInfo) -> Tuple[bool, List[str]]:
        """
        Check if a program is ready for deployment.
        
        Returns:
            Tuple of (is_valid, list of issues)
        """
        issues = []
        
        if not info.is_valid_elf:
            issues.append("Not a valid ELF file")
        
        if info.architecture != "BPF":
            issues.append(f"Wrong architecture: {info.architecture} (expected BPF)")
        
        if info.size_bytes > 10 * 1024 * 1024:  # 10MB limit
            issues.append(f"Program too large: {info.size_bytes} bytes (max 10MB)")
        
        if info.size_bytes < 100:
            issues.append(f"Program suspiciously small: {info.size_bytes} bytes")
        
        return len(issues) == 0, issues
    
    def get_deploy_command(self, info: ProgramInfo, network: str = "localhost") -> str:
        """Generate the solana program deploy command."""
        cmd = f"solana program deploy {info.path}"
        
        if info.keypair_path:
            cmd += f" --program-id {info.keypair_path}"
        
        if network != "localhost":
            if network == "devnet":
                cmd += " --url https://api.devnet.solana.com"
            elif network == "mainnet":
                cmd += " --url https://api.mainnet-beta.solana.com"
        
        return cmd
    
    def summary(self, info: ProgramInfo) -> str:
        """Generate a human-readable summary."""
        lines = [
            f"Program: {info.name}",
            f"  Path: {info.path}",
            f"  Size: {info.size_bytes:,} bytes",
            f"  SHA256: {info.sha256[:16]}...",
            f"  Valid ELF: {'✓' if info.is_valid_elf else '✗'}",
            f"  Architecture: {info.architecture or 'Unknown'}",
        ]
        
        if info.idl_path:
            lines.append(f"  IDL: {info.idl_path}")
        
        if info.keypair_path:
            lines.append(f"  Keypair: {info.keypair_path}")
        
        return "\n".join(lines)
