from __future__ import annotations

import math
import re
from collections import Counter


TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)


def tokens(text: str) -> list[str]:
    return TOKEN_RE.findall(text.casefold())


def cosine_similarity(left: str, right: str) -> float:
    a, b = Counter(tokens(left)), Counter(tokens(right))
    if not a or not b:
        return 0.0
    dot = sum(value * b.get(key, 0) for key, value in a.items())
    norm_a = math.sqrt(sum(value * value for value in a.values()))
    norm_b = math.sqrt(sum(value * value for value in b.values()))
    return max(0.0, min(1.0, dot / (norm_a * norm_b)))


def novelty_against(text: str, previous: list[str]) -> float:
    if not previous:
        return 1.0
    return 1.0 - max(cosine_similarity(text, other) for other in previous)

