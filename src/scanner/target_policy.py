"""Canonical, non-expanding host selection inside an authorized root target."""
from __future__ import annotations
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

@dataclass(frozen=True)
class SelectionResult:
    selected: tuple[str,...]; excluded: tuple[str,...]; policy: dict

def apply_target_policy(network: object, *, include_hosts: Iterable[str]=(), exclude_hosts: Iterable[str]=(), include_cidrs: Iterable[str]=(), exclude_cidrs: Iterable[str]=()) -> SelectionResult:
    root=ipaddress.ip_network(str(network),strict=False)
    def address(value: str):
        item=ipaddress.ip_address(value)
        if item.version!=root.version or item not in root: raise ValueError(f"selection {value} is outside authorized target {root}")
        return item
    def subnet(value: str):
        item=ipaddress.ip_network(value,strict=False)
        if item.version!=root.version or not item.subnet_of(root): raise ValueError(f"selection {value} is outside authorized target {root}")
        return item
    ih={address(v) for v in include_hosts}; eh={address(v) for v in exclude_hosts}; ic={subnet(v) for v in include_cidrs}; ec={subnet(v) for v in exclude_cidrs}
    include_addresses={item for net in ic for item in net.hosts()}; exclude_addresses={item for net in ec for item in net.hosts()}
    candidates=list(root.hosts()); selected=[]; excluded=[]; constrained=bool(ih or ic)
    for item in candidates:
        included=not constrained or item in ih or item in include_addresses
        denied=item in eh or item in exclude_addresses
        (selected if included and not denied else excluded).append(str(item))
    key=lambda value:int(ipaddress.ip_address(value))
    policy={"include_hosts":sorted(map(str,ih),key=key),"exclude_hosts":sorted(map(str,eh),key=key),"include_cidrs":sorted(map(str,ic)),"exclude_cidrs":sorted(map(str,ec)),"exclusion_precedence":True,"scope_expansion":False}
    return SelectionResult(tuple(selected),tuple(excluded),policy)
