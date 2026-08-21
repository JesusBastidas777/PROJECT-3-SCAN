"""Lazy bounded deterministic scheduler with cooperative budget stopping."""
from __future__ import annotations
from concurrent.futures import FIRST_COMPLETED,ThreadPoolExecutor,wait
from collections.abc import Callable,Iterable
from typing import Any
from scanner.budgets import ExecutionBudgets
def run_scheduled(function: Callable[[Any],Any],work: Iterable[Any],*,workers: int,max_pending: int,budgets: ExecutionBudgets,budget_id: str="network_attempts") -> tuple[list[tuple[int,Any]],int]:
    if workers<1 or max_pending<workers: raise ValueError("invalid scheduler bounds")
    iterator=enumerate(work); results=[]; pending={}; omitted=0; exhausted=False
    with ThreadPoolExecutor(max_workers=workers) as executor:
        while True:
            while not exhausted and len(pending)<max_pending:
                try: index,item=next(iterator)
                except StopIteration: break
                if not budgets.reserve(budget_id): exhausted=True; omitted+=1; break
                pending[executor.submit(function,item)]=index
            if not pending:
                if exhausted: omitted+=sum(1 for _ in iterator)
                break
            done,_=wait(pending,return_when=FIRST_COMPLETED)
            for future in done:
                index=pending.pop(future)
                try: value=future.result()
                except Exception as exc: value=exc
                results.append((index,value))
    return sorted(results),omitted
