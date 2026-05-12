# Copyright 2026 Korlogos / Pitt Street Labs. All rights reserved.
# This file is part of EXPOSE Commercial Modules and is NOT covered by the
# Apache 2.0 license that governs the core engine. Unauthorized copying,
# distribution, or use of this file is strictly prohibited. Contact
# licensing@korlogos.com for commercial licensing terms.

"""SOC Package SIEM integration adapters (commercial module).

This sub-package contains the full SIEM adapter implementations for
Splunk HEC, Microsoft Sentinel, and Google Chronicle.  These adapters
are part of the EXPOSE Pro / Enterprise commercial offering.

The open-core ``expose.integrations`` package exposes thin re-export
stubs that delegate to these implementations when the SOC package
module is installed and licensed.
"""

from expose.modules.soc_package.integrations.chronicle import ChronicleAdapter
from expose.modules.soc_package.integrations.sentinel import SentinelAdapter
from expose.modules.soc_package.integrations.splunk import SplunkHECAdapter

__all__ = [
    "ChronicleAdapter",
    "SentinelAdapter",
    "SplunkHECAdapter",
]
