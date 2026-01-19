"""Base Protocol Adapter interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class AdapterResult:
    """Result from building/executing an adapter action."""
    success: bool
    instructions: List[Any] = None
    accounts: List[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ProtocolAdapter(ABC):
    """Base class for all protocol adapters."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass
    
    @property
    @abstractmethod
    def supported_actions(self) -> List[str]:
        pass
    
    @abstractmethod
    async def build_transaction(self, action: Dict[str, Any], user_wallet: str) -> AdapterResult:
        pass
    
    @abstractmethod
    def get_affected_accounts(self, action: Dict[str, Any], user_wallet: str) -> List[str]:
        pass
    
    @abstractmethod
    def validate_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        pass


_adapters: Dict[str, ProtocolAdapter] = {}


def register_adapter(adapter: ProtocolAdapter):
    _adapters[adapter.name] = adapter


def get_adapter(protocol: str) -> Optional[ProtocolAdapter]:
    return _adapters.get(protocol.lower())
