"""EXPOSE commercial modules (per ADR-009 product-surface licensing).

This package hosts proprietary module implementations that extend EXPOSE
Core's open-source capabilities. Each sub-package corresponds to a product
surface defined in ADR-009:

- ``threat_context`` -- EXPOSE Threat Context (dark web, threat intel feeds)
- ``identity_surface`` -- EXPOSE Identity Surface (future)
- ``research`` -- EXPOSE Research (future)

Modules are loaded conditionally based on license checks; the open-core
engine operates without them. See each sub-package's ``check_license()``
function for the current gate.
"""

__all__: list[str] = []
