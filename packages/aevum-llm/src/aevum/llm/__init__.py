# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
import warnings

warnings.warn(
    "aevum-llm is deprecated and will be removed. "
    "Use aevum-agent instead: pip install aevum-agent",
    DeprecationWarning,
    stacklevel=2,
)

__version__ = "0.4.0"
