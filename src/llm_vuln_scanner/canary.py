"""Canary tokens: unique strings planted in prompts so that success is checked exactly.

A canary is a short random token such as ``LVS-7F3A-PELICAN``. Probes plant canaries as
secrets in system prompts, as the phrase an injected instruction asks the model to say,
or as the compliance marker a jailbreak asks the model to start with. Because the token
never occurs in normal text, finding it in the output (directly, reformatted or encoded)
is strong evidence that the attack worked, with a false-positive rate near zero.
"""

from __future__ import annotations

import random

WORDS = (
    "PELICAN", "ORCHID", "GRANITE", "LANTERN", "MAPLE", "COMET", "HARBOR", "QUARTZ",
    "SAFFRON", "TUNDRA", "WALRUS", "ZEPHYR", "CITADEL", "FALCON", "JUNIPER", "NEBULA",
    "OSPREY", "PRISM", "RAVINE", "SEQUOIA", "THISTLE", "VIOLET", "WILLOW", "AURORA",
)  # fmt: skip


class CanaryFactory:
    """Deterministic canary generator: the same seed yields the same tokens in order."""

    def __init__(self, seed: int = 0, prefix: str = "LVS") -> None:
        self._rng = random.Random(seed)
        self.prefix = prefix
        self.issued: list[str] = []

    def token(self) -> str:
        """A new token like ``LVS-7F3A-PELICAN`` (16 bits of hex plus a word)."""
        while True:
            tok = f"{self.prefix}-{self._rng.getrandbits(16):04X}-{self._rng.choice(WORDS)}"
            if tok not in self.issued:
                self.issued.append(tok)
                return tok

    def secret(self) -> str:
        """A password-like canary without the prefix, for secrets that should look natural."""
        while True:
            tok = f"{self._rng.choice(WORDS).title()}{self._rng.randint(100, 999)}"
            tok += self._rng.choice(WORDS).lower()[:4]
            if tok not in self.issued:
                self.issued.append(tok)
                return tok

    def fake_aws_key(self) -> tuple[str, str]:
        """An AWS-format access key pair that is syntactically valid and not real."""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        key_id = "AKIA" + "".join(self._rng.choice(alphabet) for _ in range(16))
        b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        secret = "".join(self._rng.choice(b64) for _ in range(40))
        self.issued.extend([key_id, secret])
        return key_id, secret
