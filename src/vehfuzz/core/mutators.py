from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MutationResult:
    mutated: bytes
    ops: list[dict[str, Any]]


def mutate_bytes(data: bytes, mutators: list[dict[str, Any]], rng: random.Random) -> MutationResult:
    mutated = data
    ops: list[dict[str, Any]] = []
    for m in mutators:
        mtype = str(m.get("type", "")).lower()
        if mtype == "bitflip":
            p = float(m.get("probability", 0.01))
            mutated, detail = _bitflip(mutated, p, rng)
            if detail["flips"] > 0:
                ops.append(detail)
        elif mtype == "havoc":
            max_ops = int(m.get("max_ops", 4))
            mutated, detail = _havoc(mutated, max_ops, rng)
            ops.append(detail)
        elif mtype == "truncate":
            max_remove = int(m.get("max_remove", 8))
            mutated, detail = _truncate(mutated, max_remove, rng)
            ops.append(detail)
        elif mtype == "append":
            max_add = int(m.get("max_add", 16))
            mutated, detail = _append(mutated, max_add, rng)
            ops.append(detail)
        else:
            raise ValueError(f"Unsupported mutator.type: {mtype}")

    return MutationResult(mutated=mutated, ops=ops)


def _bitflip(data: bytes, probability: float, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    if not data:
        return data, {"type": "bitflip", "flips": 0}

    b = bytearray(data)
    flips = 0
    for i in range(len(b)):
        for bit in range(8):
            if rng.random() < probability:
                b[i] ^= 1 << bit
                flips += 1
    return bytes(b), {"type": "bitflip", "probability": probability, "flips": flips}


def _truncate(data: bytes, max_remove: int, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    if not data:
        return data, {"type": "truncate", "removed": 0}
    remove = rng.randint(0, max(0, min(max_remove, len(data))))
    if remove == 0:
        return data, {"type": "truncate", "removed": 0}
    return data[: -remove], {"type": "truncate", "removed": remove}


def _append(data: bytes, max_add: int, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    add = rng.randint(0, max(0, max_add))
    if add == 0:
        return data, {"type": "append", "added": 0}
    extra = bytes(rng.randrange(0, 256) for _ in range(add))
    return data + extra, {"type": "append", "added": add}


def _havoc(data: bytes, max_ops: int, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    b = bytearray(data)
    ops: list[dict[str, Any]] = []
    n = rng.randint(1, max(1, max_ops))
    for _ in range(n):
        choice = rng.choice(["set_byte", "del_byte", "ins_byte"])
        if choice == "set_byte" and b:
            idx = rng.randrange(0, len(b))
            old = b[idx]
            new = rng.randrange(0, 256)
            b[idx] = new
            ops.append({"op": "set_byte", "idx": idx, "old": old, "new": new})
        elif choice == "del_byte" and b:
            idx = rng.randrange(0, len(b))
            old = b[idx]
            del b[idx]
            ops.append({"op": "del_byte", "idx": idx, "old": old})
        elif choice == "ins_byte":
            idx = rng.randrange(0, len(b) + 1)
            new = rng.randrange(0, 256)
            b[idx:idx] = bytes([new])
            ops.append({"op": "ins_byte", "idx": idx, "new": new})
        else:
            ops.append({"op": "noop"})
    return bytes(b), {"type": "havoc", "ops": ops}

