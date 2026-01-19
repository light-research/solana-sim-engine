"""
State Graph: Models protocol state transitions.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
from enum import Enum

from .models import ProgramAnalysis, InstructionSpec


class StateType(Enum):
    """Type of state node."""
    INITIAL = "initial"
    ACTIVE = "active"
    TERMINAL = "terminal"
    ERROR = "error"


@dataclass
class StateNode:
    """A node in the state graph representing a protocol state."""
    name: str
    state_type: StateType
    description: Optional[str] = None
    
    # State properties
    account_states: Dict[str, str] = field(default_factory=dict)  # account -> state value
    
    # Invariants that must hold in this state
    invariants: List[str] = field(default_factory=list)


@dataclass
class StateTransition:
    """A transition between states triggered by an instruction."""
    from_state: str
    to_state: str
    instruction: str
    
    # Conditions for this transition
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    
    # Side effects
    creates_accounts: List[str] = field(default_factory=list)
    closes_accounts: List[str] = field(default_factory=list)
    modifies_accounts: List[str] = field(default_factory=list)


@dataclass
class StateGraph:
    """
    A graph modeling all possible protocol states and transitions.
    
    Used for:
    - Coverage analysis (have we tested all transitions?)
    - Reachability analysis (can we reach state X from state Y?)
    - Invariant verification (do invariants hold after each transition?)
    """
    nodes: Dict[str, StateNode] = field(default_factory=dict)
    transitions: List[StateTransition] = field(default_factory=list)
    
    # Graph properties
    initial_state: Optional[str] = None
    
    def add_node(self, node: StateNode):
        """Add a state node."""
        self.nodes[node.name] = node
        if node.state_type == StateType.INITIAL:
            self.initial_state = node.name
    
    def add_transition(self, transition: StateTransition):
        """Add a state transition."""
        self.transitions.append(transition)
    
    def get_transitions_from(self, state: str) -> List[StateTransition]:
        """Get all transitions from a given state."""
        return [t for t in self.transitions if t.from_state == state]
    
    def get_transitions_to(self, state: str) -> List[StateTransition]:
        """Get all transitions to a given state."""
        return [t for t in self.transitions if t.to_state == state]
    
    def get_reachable_states(self, from_state: str) -> Set[str]:
        """Get all states reachable from a given state."""
        visited = set()
        queue = [from_state]
        
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            
            for t in self.get_transitions_from(current):
                if t.to_state not in visited:
                    queue.append(t.to_state)
        
        return visited
    
    def find_path(self, from_state: str, to_state: str) -> Optional[List[StateTransition]]:
        """Find a path (sequence of transitions) between two states."""
        if from_state == to_state:
            return []
        
        # BFS
        visited = {from_state}
        queue = [(from_state, [])]
        
        while queue:
            current, path = queue.pop(0)
            
            for t in self.get_transitions_from(current):
                if t.to_state == to_state:
                    return path + [t]
                
                if t.to_state not in visited:
                    visited.add(t.to_state)
                    queue.append((t.to_state, path + [t]))
        
        return None  # No path found
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "nodes": {
                name: {
                    "type": node.state_type.value,
                    "description": node.description,
                    "invariants": node.invariants,
                }
                for name, node in self.nodes.items()
            },
            "transitions": [
                {
                    "from": t.from_state,
                    "to": t.to_state,
                    "instruction": t.instruction,
                    "preconditions": t.preconditions,
                }
                for t in self.transitions
            ],
            "initial_state": self.initial_state,
        }
    
    def to_mermaid(self) -> str:
        """Generate Mermaid diagram syntax."""
        lines = ["stateDiagram-v2"]
        
        # Add initial state indicator
        if self.initial_state:
            lines.append(f"    [*] --> {self.initial_state}")
        
        # Add transitions
        for t in self.transitions:
            lines.append(f"    {t.from_state} --> {t.to_state}: {t.instruction}")
        
        # Add terminal states
        for name, node in self.nodes.items():
            if node.state_type == StateType.TERMINAL:
                lines.append(f"    {name} --> [*]")
        
        return "\n".join(lines)


class StateGraphBuilder:
    """
    Builds a state graph from program analysis.
    
    Uses heuristics to infer states and transitions from
    instruction signatures and naming conventions.
    """
    
    # Keywords that suggest state transitions
    CREATE_KEYWORDS = ["initialize", "create", "open", "new", "init"]
    CLOSE_KEYWORDS = ["close", "delete", "destroy", "remove"]
    ACTIVE_KEYWORDS = ["deposit", "withdraw", "transfer", "swap", "stake", "unstake"]
    
    def build(self, analysis: ProgramAnalysis) -> StateGraph:
        """
        Build a state graph from program analysis.
        
        Args:
            analysis: Parsed program analysis
            
        Returns:
            StateGraph representing the protocol
        """
        graph = StateGraph()
        
        # Identify key states
        states = self._infer_states(analysis)
        for state in states:
            graph.add_node(state)
        
        # Identify transitions
        transitions = self._infer_transitions(analysis, states)
        for transition in transitions:
            graph.add_transition(transition)
        
        return graph
    
    def _infer_states(self, analysis: ProgramAnalysis) -> List[StateNode]:
        """Infer states from instruction patterns."""
        states = []
        
        # Always have an uninitialized state
        states.append(StateNode(
            name="Uninitialized",
            state_type=StateType.INITIAL,
            description="Protocol/account not yet initialized",
        ))
        
        # Check for initialization instruction
        has_init = any(
            any(kw in ix.name.lower() for kw in self.CREATE_KEYWORDS)
            for ix in analysis.instructions
        )
        
        if has_init:
            states.append(StateNode(
                name="Initialized",
                state_type=StateType.ACTIVE,
                description="Protocol/account initialized and active",
            ))
        
        # Check for active operations
        has_active = any(
            any(kw in ix.name.lower() for kw in self.ACTIVE_KEYWORDS)
            for ix in analysis.instructions
        )
        
        if has_active:
            # Add states for different active conditions
            if any("deposit" in ix.name.lower() for ix in analysis.instructions):
                states.append(StateNode(
                    name="HasDeposits",
                    state_type=StateType.ACTIVE,
                    description="Account has active deposits",
                ))
            
            if any("stake" in ix.name.lower() for ix in analysis.instructions):
                states.append(StateNode(
                    name="Staked",
                    state_type=StateType.ACTIVE,
                    description="Tokens are staked",
                ))
        
        # Check for close instruction
        has_close = any(
            any(kw in ix.name.lower() for kw in self.CLOSE_KEYWORDS)
            for ix in analysis.instructions
        )
        
        if has_close:
            states.append(StateNode(
                name="Closed",
                state_type=StateType.TERMINAL,
                description="Protocol/account closed",
            ))
        
        return states
    
    def _infer_transitions(
        self,
        analysis: ProgramAnalysis,
        states: List[StateNode],
    ) -> List[StateTransition]:
        """Infer transitions from instructions."""
        transitions = []
        state_names = {s.name for s in states}
        
        for ix in analysis.instructions:
            name_lower = ix.name.lower()
            
            # Initialization transitions
            if any(kw in name_lower for kw in self.CREATE_KEYWORDS):
                if "Initialized" in state_names:
                    transitions.append(StateTransition(
                        from_state="Uninitialized",
                        to_state="Initialized",
                        instruction=ix.name,
                        creates_accounts=[a.name for a in ix.accounts if "init" in a.name.lower()],
                    ))
            
            # Deposit transitions
            elif "deposit" in name_lower:
                if "HasDeposits" in state_names:
                    transitions.append(StateTransition(
                        from_state="Initialized",
                        to_state="HasDeposits",
                        instruction=ix.name,
                    ))
                    # Can also deposit when already has deposits
                    transitions.append(StateTransition(
                        from_state="HasDeposits",
                        to_state="HasDeposits",
                        instruction=ix.name,
                    ))
            
            # Withdraw transitions
            elif "withdraw" in name_lower:
                if "HasDeposits" in state_names:
                    transitions.append(StateTransition(
                        from_state="HasDeposits",
                        to_state="HasDeposits",
                        instruction=ix.name,
                        preconditions=["balance > 0"],
                    ))
                    # Withdraw all -> back to initialized
                    transitions.append(StateTransition(
                        from_state="HasDeposits",
                        to_state="Initialized",
                        instruction=ix.name,
                        preconditions=["withdrawal_amount == balance"],
                    ))
            
            # Close transitions
            elif any(kw in name_lower for kw in self.CLOSE_KEYWORDS):
                if "Closed" in state_names:
                    # Can close from any active state
                    for state in states:
                        if state.state_type == StateType.ACTIVE:
                            transitions.append(StateTransition(
                                from_state=state.name,
                                to_state="Closed",
                                instruction=ix.name,
                                closes_accounts=[a.name for a in ix.accounts if a.is_writable],
                            ))
            
            # Other active transitions
            elif any(kw in name_lower for kw in self.ACTIVE_KEYWORDS):
                # Generic active state transition
                for state in states:
                    if state.state_type == StateType.ACTIVE:
                        transitions.append(StateTransition(
                            from_state=state.name,
                            to_state=state.name,
                            instruction=ix.name,
                        ))
        
        return transitions
