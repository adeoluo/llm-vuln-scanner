"""Interval estimates for attack success rates.

An attack success rate (ASR) is a binomial proportion ``k / n`` over attempts. Scans use
tens of attempts per probe, where the normal approximation is poor near 0 and 1, so the
reports use the Wilson score interval:

    centre = (p + z^2 / 2n) / (1 + z^2 / n)
    half   = z / (1 + z^2 / n) * sqrt(p (1 - p) / n + z^2 / 4n^2)

which stays inside [0, 1] and has close to nominal coverage for small ``n`` (Brown, Cai
and DasGupta, 2001). Differences between two rates (two models, or a vulnerable and a
hardened application) use Newcombe's hybrid score interval (method 10 of Newcombe,
1998), built from the two Wilson intervals.
"""

from __future__ import annotations

import math

Z95 = 1.959963984540054


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for ``k`` successes in ``n`` trials."""
    if n < 0 or k < 0 or k > n:
        raise ValueError("need 0 <= k <= n")
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = z / denom * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    lo = 0.0 if k == 0 else max(0.0, centre - half)
    hi = 1.0 if k == n else min(1.0, centre + half)
    return (lo, hi)


def newcombe_diff(k1: int, n1: int, k2: int, n2: int, z: float = Z95) -> tuple[float, float, float]:
    """Difference ``p1 - p2`` with Newcombe's hybrid score interval ``(d, lo, hi)``."""
    if n1 == 0 or n2 == 0:
        raise ValueError("both samples must be non-empty")
    p1, p2 = k1 / n1, k2 / n2
    l1, u1 = wilson(k1, n1, z)
    l2, u2 = wilson(k2, n2, z)
    d = p1 - p2
    lo = d - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    hi = d + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)
    return (d, max(-1.0, lo), min(1.0, hi))


def percentile(values: list[float], q: float) -> float:
    """Linear-interpolated percentile (``q`` in [0, 100]) of a non-empty list."""
    if not values:
        raise ValueError("empty list")
    if not 0 <= q <= 100:
        raise ValueError("q must be in [0, 100]")
    s = sorted(values)
    pos = (len(s) - 1) * q / 100
    lo = math.floor(pos)
    hi = math.ceil(pos)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)
