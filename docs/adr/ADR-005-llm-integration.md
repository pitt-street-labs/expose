# ADR-005: LLM integration

**Status:** Accepted
**Date:** 2026-05-09
**Decision-makers:** Korlogos / Pitt Street Labs

## Context

FatFinger6000 has bounded enrichment work that benefits from LLM judgment: attribution sanity-checking on ambiguous candidates, tech-stack inference where Wappalyzer-style rules are insufficient, noise classification on suspicious observations. The question is which LLM the pipeline uses, where it runs, and how the integration is bounded for safety.

This decision sits inside a deliberate two-environment model:

- **Environment 1** — this codebase. Bounded structured-output enrichment work happens here.
- **Environment 2** — separate, downstream operational environment. Open-ended narrative reasoning and red team lead briefings happen there, possibly using Mythos-class capabilities under appropriate safeguards (Project Glasswing, equivalent programs, or operator-administered controls).

The boundary between environments is a manual JSON handoff with cosign signature verification. Environment 1 must never call Environment 2 capabilities directly.

## Decision

**Multi-provider LLM abstraction with frontier providers as v1 default**, local Ollama as a configurable alternative.

The `LLMProvider` interface supports four implementations in v1:

- `AnthropicDirectProvider` — Anthropic API. Default models: Claude Opus 4.7 (primary), Claude Sonnet 4.6 (cost-optimized bulk).
- `OpenAIProvider` — OpenAI API. Default models: GPT-5.5 (primary), GPT-5.4-mini (bulk).
- `GeminiProvider` — Google Gemini API. Default models: Gemini 2.5 Pro (primary), Gemini 2.5 Flash (bulk).
- `OllamaProvider` — local Ollama at configured endpoint. v1 lab default for standalone runs: Qwen 2.5 7B Instruct Q4_K_M; alternate: Llama 3.1 8B Instruct Q4_K_M.

Operator selects per-tenant which provider is the primary. v1 default for fastest iteration is configurable across the three frontier providers; Ollama is available for cost-bound or air-gap-adjacent runs.

**All LLM calls go through `SafeLLMClient`**, a wrapper enforcing:

- **Sanitization integrity** — verifies external observation content uses `<external_observation>` tags so the model treats it as data.
- **Structured-output validation** — every prompt demands JSON output conforming to a Pydantic schema. Outputs failing validation are rejected and retried up to 2x; persistent failure escalates the case to tie-breaker (if configured) or human review.
- **Per-call audit logging** — provider, model, input tokens, output tokens, latency, cost estimate. Tagged with `tenant_id`.
- **Per-run cost ceiling** — hard stop on breach with fail-safe behavior (mark affected enrichment as `tie_breaker_unavailable`, continue with rule-engine results).
- **Tie-breaker escalation** — configurable triggers (schema validation failure, low self-confidence, rule disagreement) route a single decision to a different provider for second opinion.

**Environment 2 LLM tooling is explicitly out of scope** for this codebase. The artifact's design — full provenance, attribution confidence, deterministic generation — provides Environment 2 with structured input. What Environment 2 does with that input (Mythos, Claude Code, internal tooling, future GA models) is the operator's decision under whatever safeguards their access program requires.

**The LLM never invents observations.** Every claim it makes either references a graph node/edge or is filtered by output schema validation. The LLM has no tool access during enrichment; necessary evidence is pre-baked into the prompt.

## Consequences

**Positive:**

- v1 quality is strong from day one with frontier model defaults.
- Operator can swap providers via config without code changes.
- Local Ollama option supports cost-bound iteration and reduces vendor lock-in concerns.
- Bounded scope (structured-output, no tool access, no narrative generation) preserves safety properties.
- Two-environment separation is principled and matches the safety architecture appropriate for high-capability LLM tooling.
- Tie-breaker escalation gives operators a clean upgrade path when local quality is insufficient.

**Negative:**

- API costs accumulate. Per-run cost ceiling mitigates but operators must monitor.
- Three frontier provider implementations is ~3x the SDK surface to maintain. Mitigated by the abstraction being thin.
- Local Ollama on RTX 2080 Super (8GB VRAM) is throughput-limited to 7B-8B class models at 25-40 tokens/sec. Will not scale to large tenant volumes without GPU upgrade.
- Provider feature parity is uneven (tool use, prompt caching, structured output mechanisms differ). Capability flags and the `SafeLLMClient` wrapper smooth this but some features are best-effort across providers.

## Alternatives considered

**Anthropic API direct as the only provider.** Simplest implementation. Rejected because the multi-provider abstraction is genuinely cheap and the operator value of flexibility is real (existing credits, customer compliance preferences, vendor diversification).

**Through AWS Bedrock or GCP Vertex AI.** Compliance posture for cloud-native customers. Rejected for v1 default but `BedrockProvider` and `VertexProvider` are filed as future-work; they slot into the same abstraction.

**Local LLM only (Ollama with no external option).** Maximum safety, zero vendor relationship. Rejected because the 2080 Super throughput is insufficient for production volumes and quality at 7B-class models is meaningfully lower than frontier models.

**LLM in Environment 1 doing narrative work as well.** Tempting because the pipeline already has access. Rejected because narrative work is open-ended and best done in the safer, audited Environment 2 where downstream LLM workflows have appropriate safeguards. Environment 1 produces structured input; Environment 2 reasons over it.

**No LLM at all in Environment 1.** Pure rule-based attribution. Rejected because the operator confirmed bounded LLM judgment adds value on the long tail of medium-confidence cases that rules cannot decide cleanly.

## When to revisit

Trigger conditions for changes:

- **Local LLM quality degrades or volume grows beyond 2080 Super throughput.** GPU upgrade path documented in deferred issues. Migration to 16GB+ VRAM unlocks 14B-class models; 24GB+ unlocks 32-70B with quantization.
- **External LLM costs exceed tenant cost ceilings repeatedly.** Either tighten enrichment policy (only `medium` and `requires_review`, not `high`) or invest in better local LLM hardware.
- **A new frontier provider emerges or existing providers shift defaults.** New provider is a new `LLMProvider` implementation. Easy to add.
- **Mythos-class GA changes the Environment 2 story.** Coordination happens at the artifact contract boundary; FatFinger6000 itself is unaffected.
- **A regulatory or compliance change requires Environment 1 to operate fully air-gapped.** Local Ollama is the path; quality tradeoff is real.

## References

- Decision recorded in design conversation 2026-05-09 (revised after Mythos product clarification).
- Four deferred-issues in `llm-quality` and `eval-harness` epics. See `docs/issues-backlog.md`.
- Eval harness for tracking provider/model quality: ongoing, with held-out datasets curated per `eval-harness` epic.
