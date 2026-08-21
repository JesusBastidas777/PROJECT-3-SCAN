"""Thread-safe reserve-before-use global execution budgets."""
from __future__ import annotations
from dataclasses import dataclass,field
from threading import Lock
import time
@dataclass
class ExecutionBudgets:
    max_runtime: float|None=None; max_network_attempts: int|None=None; max_evidence_bytes: int|None=None; max_evidence_records: int|None=None; started: float=field(default_factory=time.monotonic); _used: dict=field(default_factory=dict); _lock: Lock=field(default_factory=Lock)
    def reserve(self,budget_id: str,amount: int=1) -> bool:
        if amount<0: raise ValueError("budget reservation must be non-negative")
        limit=getattr(self,"max_"+budget_id,None)
        with self._lock:
            if self.max_runtime is not None and time.monotonic()-self.started>=self.max_runtime: return False
            used=int(self._used.get(budget_id,0))
            if limit is not None and used+amount>limit: return False
            self._used[budget_id]=used+amount; return True
    def descriptor(self,budget_id: str,unit: str) -> dict:
        limit=getattr(self,"max_"+budget_id,None); used=int(self._used.get(budget_id,0)); return {"limit":limit,"reserved":used,"consumed":used,"remaining":None if limit is None else max(0,limit-used),"unit":unit}
