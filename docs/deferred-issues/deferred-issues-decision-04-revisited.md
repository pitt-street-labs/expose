# Deferred issues — Decision 4 (LLM integration, revisited)

These issues capture LLM-quality and scaling concerns deferred from v1 lab
deployment with the 2080 Super GPU and 7B-class models on Ollama. Filed against
the `llm-quality` epic.

---

## Issue: GPU upgrade path and larger-model deployment

**Labels:** `epic:llm-quality`, `area:llm`, `priority:medium`, `type:design`

**Summary**
v1 runs on RTX 2080 Super (8GB VRAM), constraining model selection to 7-8B
quantized models. As candidate volume grows or quality requirements increase,
hardware upgrade becomes necessary. Document the migration path and decision
criteria.

**Triggers for this work**
- Daily run wall-clock exceeding overnight window (currently estimate 1-3
  hours for ~500 candidates, ~overnight for ~5000)
- Quality eval (see eval-harness issue) showing local model accuracy below
  agreed threshold
- Tie-breaker escalation rate to external LLM exceeding ~10% of correlation
  decisions

**Acceptance criteria**
- Document target hardware tiers: 16GB VRAM (RTX 4080/5070 class) → 14B
  models; 24GB+ (RTX 4090/5090, A6000) → 32-70B models with quantization
- Model selection guide for each tier, with structured-output reliability
  notes
- Migration runbook: model swap procedure, eval re-run, rollback path
- Cost/value analysis for each tier vs. external LLM API spend at typical
  candidate volumes
- Multi-GPU support in OllamaProvider for hosts with multiple cards

**Dependencies**
LLM eval harness (separate issue under `eval-harness` epic).

**Estimated effort:** 1 sprint when triggered

---

## Issue: External LLM tie-breaker escalation policy

**Labels:** `epic:llm-quality`, `area:llm`, `priority:high`, `type:design`

**Summary**
The external LLM provider path (Anthropic Direct / Bedrock / Vertex) is
positioned as a tie-breaker for cases where local Ollama quality is
insufficient. Need explicit, deterministic escalation policy so operators know
when external calls happen and analysts can audit.

**Acceptance criteria**
- Configurable escalation triggers, each independently toggleable:
  - `schema_validation_failure_retries` (default: escalate after 2 local
    parse failures)
  - `self_confidence_below_threshold` (default: escalate when model rates
    own answer < 0.5 on a calibrated scale)
  - `rule_disagreement_low_confidence` (default: escalate when LLM
    contradicts rule engine and rule confidence is medium-low)
  - `spot_check_sampling_rate` (default: 0%, opt-in for eval runs)
- All escalations audit-logged with: trigger reason, local model output,
  external model output, final decision adopted, latency, cost
- Manifest records per-run escalation count and provider used
- Cost ceiling configuration: hard cap on external LLM spend per run, with
  fail-safe behavior (continue with local results, mark affected decisions
  as `tie_breaker_unavailable`)
- Documentation: when each trigger is appropriate, expected escalation rates,
  cost projections at typical volumes

**Dependencies**
- LLMProvider abstraction implemented (in v1 scope)
- SafeLLMClient audit logging (in v1 scope)

**Estimated effort:** 1 sprint

**v1 status:** Trigger framework should be in v1 codebase even if all triggers
default off, so configuration is the only gate to enabling — no code change
required to start using tie-breaker.

---

## Issue: LLM correlation eval harness

**Labels:** `epic:eval-harness`, `area:llm`, `priority:high`, `type:infrastructure`

**Summary**
Need an evaluation framework for the local LLM's correlation decisions.
Without one, model swaps, prompt changes, and quality drift are invisible
until they cause production problems.

**Acceptance criteria**
- Held-out eval datasets in repo:
  - `confirmed_yours` — assets with high-confidence ground truth ownership
  - `confirmed_not_yours` — assets known not to belong (competitors,
    typosquats, fan sites, neighbors in cloud space)
  - `ambiguous_with_resolution` — analyst-resolved cases with documented
    reasoning
  - `adversarial_injection` — cert SANs, banners, DNS TXT records with
    planted prompt-injection content (does the LLM make decisions consistent
    with treating this content as data, not instructions?)
- Eval CLI: `<project> eval --provider ollama --model qwen2.5:7b ...`
- Metrics tracked: accuracy on confirmed-yours/not-yours, agreement rate
  with analyst resolutions on ambiguous, immunity rate on adversarial
- Regression gate in CI: significant accuracy drop blocks merge
- Comparison mode: run same eval against multiple providers/models, output
  comparison report
- Quarterly re-evaluation cadence documented

**Dependencies**
LLMProvider abstraction (in v1 scope). Initial eval datasets are a separate
content-curation effort, not blocked by code.

**Estimated effort:** 2 sprints (1 for harness, 1 for initial dataset
curation)

**v1 status:** Harness goes in v1 codebase. Initial datasets can grow
organically — start with a minimal seed (a few dozen of each category) and
expand with each run's analyst-flagged cases.

---

## Issue: Ollama instance pool and parallel correlation execution

**Labels:** `epic:llm-quality`, `area:llm`, `priority:low`, `type:performance`

**Summary**
Single Ollama instance on single GPU is the v1 throughput bottleneck. When
candidate volume grows, parallel execution against multiple Ollama instances
(or multiple GPUs) is the natural scaling lever before hardware upgrade.

**Acceptance criteria**
- `OllamaProvider` accepts a list of endpoints, round-robins requests
- Health-check + circuit-breaker for individual endpoints
- Correlation worker pool sized configurable, defaults to len(endpoints)
- Documentation: scaling pattern (multi-GPU host, multiple hosts, mixed)
- Compatible with Helm chart; multiple Ollama replicas and the worker pool
  scale independently

**Triggers for this work**
Candidate volume sustained above what single-instance can complete within
the daily-batch window.

**Estimated effort:** 1 sprint when triggered

---

## Tracking summary

| Issue | Priority | Effort | Trigger |
|---|---|---|---|
| GPU upgrade path | Medium | 1 sprint | Volume or quality threshold reached |
| External LLM tie-breaker policy | High | 1 sprint | v1 framework + initial config |
| LLM correlation eval harness | High | 2 sprints | v1 code + ongoing dataset curation |
| Ollama instance pool / parallel execution | Low | 1 sprint | When throughput bottleneck appears |

Two of four are flagged for v1 *codebase* presence even though full activation
is deferred — the tie-breaker framework and the eval harness. Both are cheap
to build into the architecture from day one and very expensive to retrofit.

The model-fit recommendation for v1 launch on the 2080 Super:
**Qwen 2.5 7B Instruct at Q4_K_M as default**, Llama 3.1 8B Instruct at Q4_K_M
as configured fallback. Operators can swap models via deployment configuration
without code changes.
