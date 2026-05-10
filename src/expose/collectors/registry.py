"""Collector registry — discover enabled collectors by ID (per SPEC §6.1, §10.1).

The dispatcher needs to translate the tenant configuration's
``collectors.enabled`` list (e.g., ``["ct-crtsh", "cloud-aws-ranges", ...]``)
into concrete ``Collector`` *classes* so it can construct instances per work
item with fresh ``CollectorConfig``.

Two registration paths are supported:

1. **Decorator** (``@register_collector``) — used by collectors shipped inside
   the ``expose`` package. Registration happens at import time; the
   bootstrapping code imports ``expose.collectors.builtin`` which transitively
   imports each built-in collector module and triggers its decorator call.

2. **Programmatic** (``CollectorRegistry.register``) — used by tests and
   future out-of-tree collector plugins. Tests in particular need a fresh
   registry per test (otherwise registrations leak between tests); the
   registry exposes a ``snapshot()`` / ``restore()`` pair for that.

The registry is *not* a singleton at runtime in the global-state sense — the
dispatcher constructs its own ``CollectorRegistry`` instance, populates it from
the built-in modules, and passes it through. A module-level
``DEFAULT_REGISTRY`` is provided for convenience but tests should construct
their own to avoid ordering issues.

Collectors are keyed by ``collector_id`` (the stable string identifier on the
class). Re-registering the same ID raises ``CollectorAlreadyRegisteredError`` —
this is a programming error, not a runtime condition.
"""

from collections.abc import Callable, Iterator

from expose.collectors.base import Collector
from expose.collectors.tiers import CollectorTier


class CollectorAlreadyRegisteredError(ValueError):
    """A collector with this ``collector_id`` is already registered.

    Raised by ``CollectorRegistry.register`` and the ``@register_collector``
    decorator. This is a programming error; resolve by either renaming the
    collector or removing the duplicate registration. The framework does not
    allow silent override because that would make collector behavior depend
    on import order.
    """


class CollectorNotRegisteredError(KeyError):
    """No collector is registered for the given ID.

    Raised by ``CollectorRegistry.get``. Operationally this means either a
    typo in the tenant configuration's ``collectors.enabled`` list or a
    collector package that failed to import.
    """


class CollectorRegistry:
    """In-memory registry of collector classes keyed by ``collector_id``.

    Instances of this class are mutable. The dispatcher constructs one per
    process; tests construct ephemeral ones.
    """

    def __init__(self) -> None:
        self._collectors: dict[str, type[Collector]] = {}

    def register(self, collector_cls: type[Collector]) -> type[Collector]:
        """Register ``collector_cls`` under its ``collector_id``.

        Returns the class unchanged so this method can also be used as a
        decorator on the class definition. Raises
        ``CollectorAlreadyRegisteredError`` if the ID is already taken.
        """

        cid = collector_cls.collector_id
        if cid in self._collectors:
            existing = self._collectors[cid]
            msg = (
                f"Collector ID {cid!r} is already registered to "
                f"{existing.__module__}.{existing.__qualname__}; cannot register "
                f"{collector_cls.__module__}.{collector_cls.__qualname__}."
            )
            raise CollectorAlreadyRegisteredError(msg)
        self._collectors[cid] = collector_cls
        return collector_cls

    def get(self, collector_id: str) -> type[Collector]:
        """Return the registered class for ``collector_id`` or raise."""

        try:
            return self._collectors[collector_id]
        except KeyError as exc:
            msg = (
                f"No collector registered for ID {collector_id!r}. Either "
                "the tenant configuration references an unknown collector or "
                "the collector package failed to import."
            )
            raise CollectorNotRegisteredError(msg) from exc

    def is_registered(self, collector_id: str) -> bool:
        """Cheap membership check — useful for tenant-config validation."""

        return collector_id in self._collectors

    def all_ids(self) -> list[str]:
        """Sorted list of registered collector IDs."""

        return sorted(self._collectors)

    def by_tier(self, tier: CollectorTier) -> list[type[Collector]]:
        """All registered collector classes in the given tier.

        Sorted by ``collector_id`` for deterministic iteration order — handy
        for tests, audit logs, and the dispatcher's "what's enabled" report.
        """

        return [
            cls
            for _, cls in sorted(self._collectors.items())
            if cls.tier == tier
        ]

    def __iter__(self) -> Iterator[type[Collector]]:
        """Iterate registered classes in collector-ID order."""

        return iter(cls for _, cls in sorted(self._collectors.items()))

    def __len__(self) -> int:
        return len(self._collectors)

    def __contains__(self, collector_id: object) -> bool:
        return isinstance(collector_id, str) and collector_id in self._collectors

    def snapshot(self) -> dict[str, type[Collector]]:
        """Return a shallow copy of the internal mapping for save/restore.

        Tests use this with ``restore`` to reset the global ``DEFAULT_REGISTRY``
        between cases without relying on a fresh-fixture pattern that may not
        compose well with the production import-time registration model.
        """

        return dict(self._collectors)

    def restore(self, snapshot: dict[str, type[Collector]]) -> None:
        """Replace the internal mapping with ``snapshot``."""

        self._collectors = dict(snapshot)

    def clear(self) -> None:
        """Remove all registrations.

        Tests use this when constructing an ephemeral registry. The
        dispatcher should not call this in production paths.
        """

        self._collectors.clear()


# Module-level default registry. Built-in collector modules call
# ``register_collector(cls)`` at import time which delegates here. Tests that
# need isolation either construct their own ``CollectorRegistry`` or use the
# ``snapshot`` / ``restore`` pair on this instance.
DEFAULT_REGISTRY = CollectorRegistry()


def register_collector(collector_cls: type[Collector]) -> type[Collector]:
    """Class decorator registering ``collector_cls`` in ``DEFAULT_REGISTRY``.

    Usage in a concrete collector module::

        from expose.collectors import Collector, register_collector

        @register_collector
        class CrtShCollector(Collector):
            collector_id = "ct-crtsh"
            collector_version = "0.1.0"
            ...
    """

    return DEFAULT_REGISTRY.register(collector_cls)


def get_collector(collector_id: str) -> type[Collector]:
    """Convenience accessor on ``DEFAULT_REGISTRY``."""

    return DEFAULT_REGISTRY.get(collector_id)


# Type alias for downstream code that wants to inject a registry-like object
# (e.g., tests using a stub) without depending on the concrete class.
RegistryLike = Callable[[str], type[Collector]]


__all__ = [
    "DEFAULT_REGISTRY",
    "CollectorAlreadyRegisteredError",
    "CollectorNotRegisteredError",
    "CollectorRegistry",
    "RegistryLike",
    "get_collector",
    "register_collector",
]
