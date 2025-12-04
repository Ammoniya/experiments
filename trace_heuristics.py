"""
Execute heuristic detectors against dynamic trace data extracted from CDP logs.

Each heuristic inspects the execution trace (event tokens, capabilities, raw
event payloads) to spot suspicious behaviours that kept showing up in known
malicious clusters sampled under ``samples/all-15``.  The heuristics deliberately
avoid static AST inspection – they only operate on runtime traces so that we can
spot behaviours such as obfuscated loaders that only unfold at execution time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlparse


# Common host keywords that showed up in malicious Netlify/WordPress loaders.
SUSPICIOUS_HOST_KEYWORDS = (
    "indejs",
    "selectblackrouls",
    "collect-v6.51",
    "collect-v6",
    "51.la",
)

# CDN hosts abused by the loader that chains jsDelivr/Cloudflare assets.
CDN_HOST_KEYWORDS = (
    "cdn.jsdelivr",
    "cdnjs.cloudflare",
    "unpkg.com",
    "ajax.googleapis",
    "static.cloudflare",
    "cloudflare.com",
)

# WordPress droppers built out of the emoji code path tend to create blob workers.
BLOB_WORKER_QUEUE_NAMES = ("wpTestEmojiSupports",)

# Cookie names associated with the 51.la beacon and similar collectors.
SUSPICIOUS_COOKIE_PREFIXES = ("__51", "__vt", "ibx_", "__vtins", "__51v")

# Popular frameworks / build tool markers that indicate benign stacks.
BENIGN_STACK_SIGNATURES = (
    "react-dom",
    "webpack",
    "jquery",
    "vue.runtime",
    "angular",
    "svelte",
    "/node_modules/",
)

# Environment probing targets that often show up in anti-analysis routines.
ANTI_ANALYSIS_PROPERTIES = (
    "navigator.webdriver",
    "navigator.plugins",
    "navigator.mimetypes",
    "navigator.languages",
    "navigator.hardwareconcurrency",
    "window.chrome",
)

# Touch/mobile capability probes.
PLATFORM_DIVERGENCE_PROPERTIES = (
    "ontouchstart",
    "orientation",
    "screen.width",
    "screen.height",
    "maxtouchpoints",
)


@dataclass
class HeuristicMatch:
    """Structured result from a single heuristic detector."""

    name: str
    description: str
    severity: str
    evidence: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
        }


def evaluate_trace(trace: Mapping[str, Any]) -> List[HeuristicMatch]:
    """Run all heuristics against a single trace and return the matches."""
    matches: List[HeuristicMatch] = []
    for detector in TRACE_HEURISTICS:
        try:
            result = detector(trace)
        except Exception as exc:  # pragma: no cover - defensive guardrail
            matches.append(
                HeuristicMatch(
                    name=f"{detector.__name__}_error",
                    description=f"{detector.__name__} failed",
                    severity="warning",
                    evidence=str(exc),
                )
            )
            continue
        if result:
            matches.append(result)
    return matches


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _event_tokens(trace: Mapping[str, Any]) -> List[str]:
    events = trace.get("event_sequence")
    if isinstance(events, list):
        return [str(item) for item in events if isinstance(item, str)]
    return []


def _raw_event_payloads(trace: Mapping[str, Any]) -> Iterator[Tuple[Mapping[str, Any], Mapping[str, Any]]]:
    for record in trace.get("raw_events") or []:
        payloads = record.get("argsValues")
        if not isinstance(payloads, list):
            continue
        for payload in payloads:
            if isinstance(payload, Mapping):
                yield record, payload


def _script_domain(trace: Mapping[str, Any]) -> Optional[str]:
    url = trace.get("script_url") or trace.get("page_url")
    if not url or not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    domain = parsed.netloc.lower()
    if ":" in domain:
        domain = domain.split(":", 1)[0]
    return domain or None


def _extract_host_from_token(token: str) -> Optional[str]:
    for part in token.split("|"):
        if part.startswith("weak_domain="):
            return part.split("=", 1)[1]
        if part.startswith("weak_host="):
            return part.split("=", 1)[1]
        if part.startswith("host="):
            return part.split("=", 1)[1]
    return None


def _extract_hosts_from_events(tokens: Sequence[str]) -> List[str]:
    hosts: List[str] = []
    for token in tokens:
        host = _extract_host_from_token(token)
        if host:
            hosts.append(host.lower())
    return hosts


def _capability_count(trace: Mapping[str, Any], capability: str) -> int:
    counts = trace.get("capability_counts", {})
    if isinstance(counts, Mapping):
        raw_value = counts.get(capability)
        try:
            return int(raw_value or 0)
        except (TypeError, ValueError):
            return 0
    return 0


def _cookie_names(trace: Mapping[str, Any]) -> List[str]:
    names: List[str] = []
    for _, payload in _raw_event_payloads(trace):
        if payload.get("type") not in {"Cookie Read", "Cookie Update"}:
            continue
        keys_value = payload.get("keys") or payload.get("value")
        if not isinstance(keys_value, str):
            continue
        for candidate in keys_value.split(","):
            name = candidate.strip()
            if name:
                names.append(name)
    return names


def _network_hosts(trace: Mapping[str, Any]) -> List[str]:
    """Return hosts captured in networkRequest/XHR/script-set events."""
    return _extract_hosts_from_events(_event_tokens(trace))


def _token_positions(tokens: Sequence[str], substring: str) -> List[int]:
    return [idx for idx, token in enumerate(tokens) if substring in token]


def _has_token(tokens: Sequence[str], needle: str) -> bool:
    return any(needle in token for token in tokens)


def _summarize_hosts(hosts: Iterable[str]) -> str:
    host_list = sorted({host for host in hosts if host})
    return ", ".join(host_list[:5]) if host_list else "unknown host"


def _iter_payloads_by_type(trace: Mapping[str, Any], event_type: str) -> Iterator[Mapping[str, Any]]:
    for _, payload in _raw_event_payloads(trace):
        if payload.get("type") == event_type:
            yield payload


def _stack_from_payload(payload: Mapping[str, Any]) -> str:
    stack = payload.get("registrationStack") or payload.get("stack")
    return str(stack or "")


def _stack_is_benign(stack: str) -> bool:
    if not stack:
        return False
    lowered = stack.lower()
    if any(signature in lowered for signature in BENIGN_STACK_SIGNATURES):
        return True
    frames = [line for line in stack.splitlines() if line.strip()]
    return len(frames) >= 4


def _extract_decoder_outputs(trace: Mapping[str, Any]) -> List[str]:
    outputs: List[str] = []
    for payload in _iter_payloads_by_type(trace, "atob De-obfuscation"):
        preview = payload.get("outputPreview") or payload.get("output") or payload.get("inputPreview")
        if isinstance(preview, str) and preview:
            outputs.append(preview[:256])
    return outputs


def _extract_executor_inputs(trace: Mapping[str, Any]) -> List[str]:
    inputs: List[str] = []
    for payload in _iter_payloads_by_type(trace, "Eval Call"):
        preview = payload.get("codePreview") or payload.get("inputPreview")
        if isinstance(preview, str) and preview:
            inputs.append(preview[:512])
    for payload in _iter_payloads_by_type(trace, "Function Constructor"):
        preview = payload.get("codePreview") or payload.get("outputPreview")
        if isinstance(preview, str) and preview:
            inputs.append(preview[:512])
    return inputs


# ---------------------------------------------------------------------------
# Heuristic detectors
# ---------------------------------------------------------------------------


def detect_obfuscated_eval_chain(trace: Mapping[str, Any]) -> Optional[HeuristicMatch]:
    """Detect chained atob()/Function constructor payloads that immediately eval and beacon."""
    decoder_outputs = _extract_decoder_outputs(trace)
    executor_inputs = _extract_executor_inputs(trace)
    if not decoder_outputs or not executor_inputs:
        return None
    if not any(
        decoded and executed and decoded.strip()[:32] in executed
        for decoded in decoder_outputs
        for executed in executor_inputs
    ):
        return None
    hosts = _network_hosts(trace)
    if not hosts:
        return None
    script_host = _script_domain(trace)
    cross_hosts = [host for host in hosts if script_host is None or host != script_host]
    evidence_host = cross_hosts if cross_hosts else hosts
    return HeuristicMatch(
        name="obfuscated_eval_chain",
        description="Trace decodes payloads via atob/Function constructors and immediately evaluates them before issuing network traffic.",
        severity="high",
        evidence=f"Hosts reached after obfuscation: {_summarize_hosts(evidence_host)}",
    )


def detect_cdn_script_reinjection(trace: Mapping[str, Any]) -> Optional[HeuristicMatch]:
    """Detect scripts that rewrite element.src/textContent before injecting multiple CDN payloads."""
    tokens = _event_tokens(trace)
    script_hosts: List[str] = []
    for token in tokens:
        if not token.startswith("Script Src Set"):
            continue
        host = _extract_host_from_token(token)
        if host and any(keyword in host for keyword in CDN_HOST_KEYWORDS):
            script_hosts.append(host)
    if len(script_hosts) < 2:
        return None
    hook_payloads = list(_iter_payloads_by_type(trace, "Object.defineProperty Called"))
    dom_mutations = [token for token in tokens if "DOM Mutation|Node.appendChild" in token or "DOM Mutation|Node.insertBefore" in token]
    if len(hook_payloads) < 2 or not dom_mutations:
        return None
    if all(_stack_is_benign(_stack_from_payload(payload)) for payload in hook_payloads):
        return None
    return HeuristicMatch(
        name="cdn_script_reinjection",
        description="Script overrides DOM element setters before chaining several CDN script injections.",
        severity="high",
        evidence=f"Injected CDN hosts: {_summarize_hosts(script_hosts)}",
    )


def detect_web3_event_listener(trace: Mapping[str, Any]) -> Optional[HeuristicMatch]:
    """Catch DOMContentLoaded listeners that bootstrap Web3/crypto logic from obfuscated payloads."""
    listener_hits: List[str] = []
    for _, payload in _raw_event_payloads(trace):
        if payload.get("type") != "Event Listener Added":
            continue
        preview = str(payload.get("listenerPreview") or "").lower()
        if any(keyword in preview for keyword in ("web3", "binance", "metamask", "walletconnect", "ethers")):
            listener_hits.append(payload.get("eventType") or "unknown")
    if not listener_hits:
        return None
    tokens = _event_tokens(trace)
    if not any("atob De-obfuscation" in token or "Eval Call" in token for token in tokens):
        return None
    return HeuristicMatch(
        name="web3_listener_bootstrap",
        description="DOMContentLoaded listener contains Web3/crypto bootstrap code extracted from an obfuscated payload.",
        severity="high",
        evidence=f"Listener hooks: {', '.join(listener_hits[:3])}",
    )


def detect_prototype_hardening(trace: Mapping[str, Any]) -> Optional[HeuristicMatch]:
    """Identify traces that aggressively patch global prototypes (common anti-analysis tack used in droppers)."""
    tokens = _event_tokens(trace)
    high_value_targets = ("globalthis", "reflect", "symbol", "promise", "weakmap", "weakset", "map", "set", "aggregateerror", "navigator", "document")
    target_hits: List[str] = []
    suspicious = 0
    for payload in _iter_payloads_by_type(trace, "Object.defineProperty Called"):
        attribute = str(payload.get("property") or payload.get("attribute") or payload.get("object") or "").lower()
        if any(target in attribute for target in high_value_targets):
            target_hits.append(attribute or "unknown")
            if not _stack_is_benign(_stack_from_payload(payload)):
                suspicious += 1
    if len(target_hits) < 5 or suspicious == 0:
        return None
    return HeuristicMatch(
        name="prototype_mass_patching",
        description="Trace rewrites a large number of built-in prototypes (globalThis/Reflect/Promise/etc.), a common anti-analysis technique.",
        severity="medium",
        evidence=f"Patched targets: {', '.join(sorted(set(target_hits))[:5])}",
    )


def detect_cookie_beacon(trace: Mapping[str, Any]) -> Optional[HeuristicMatch]:
    """Detect heavy 51.la style telemetry that churns __51*/__vt* cookies before POSTing to collect endpoints."""
    cookie_names = _cookie_names(trace)
    suspects = [name for name in cookie_names if any(name.startswith(prefix) for prefix in SUSPICIOUS_COOKIE_PREFIXES)]
    if len(suspects) < 2:
        return None
    hosts = _network_hosts(trace)
    if not any("51" in host or "collect-v" in host for host in hosts):
        return None
    if _capability_count(trace, "OBFUSCATION") == 0 and not _has_token(_event_tokens(trace), "Eval Call"):
        return None
    return HeuristicMatch(
        name="cookie_beacon",
        description="Trace churns __51*/__vt* cookies and posts them to 51.la style collection endpoints.",
        severity="medium",
        evidence=f"Cookie keys: {', '.join(sorted(set(suspects))[:5])}",
    )


def detect_blob_worker_dropper(trace: Mapping[str, Any]) -> Optional[HeuristicMatch]:
    """Detect WordPress emoji droppers that spawn blob-based WebWorkers and hook onmessage before reading cookies."""
    tokens = _event_tokens(trace)
    if not _has_token(tokens, "Blob URL Created"):
        return None
    worker_tokens = [token for token in tokens if "Web Worker Created" in token]
    if not any("domain:blob" in token for token in worker_tokens):
        return None
    if not any("onmessage" in token for token in tokens):
        return None
    if not _has_token(tokens, "DOM Property Read|window|sessionStorage"):
        return None
    cookie_hits = [name for name in _cookie_names(trace) if name.startswith("ibx_") or name.startswith("wpfomo")]
    evidence_cookie = cookie_hits[:1] if cookie_hits else ["sessionStorage"]
    worker_names = [token for token in worker_tokens if any(queue in token for queue in BLOB_WORKER_QUEUE_NAMES)]
    return HeuristicMatch(
        name="blob_worker_dropper",
        description="WordPress emoji pipeline spawns blob-based WebWorkers, hooks onmessage, and siphons cookies/session storage.",
        severity="high",
        evidence=f"Worker tokens: {worker_names[0] if worker_names else worker_tokens[0]} | Cookies: {', '.join(evidence_cookie)}",
    )


def detect_suspicious_host_contact(trace: Mapping[str, Any]) -> Optional[HeuristicMatch]:
    """Detect beaconing to known malicious infrastructure (indejs/selectblackrouls/etc.)."""
    hosts = _network_hosts(trace)
    hits = [host for host in hosts if any(keyword in host for keyword in SUSPICIOUS_HOST_KEYWORDS)]
    if not hits:
        return None
    return HeuristicMatch(
        name="c2_host_contact",
        description="Trace beacons to infrastructure previously associated with malicious loaders.",
        severity="high",
        evidence=f"C2 host(s): {_summarize_hosts(hits)}",
    )


def detect_stack_anomaly(trace: Mapping[str, Any]) -> Optional[HeuristicMatch]:
    """Detect DOM/Hooking events that originate from short or anonymous stack traces."""
    suspicious_heads: List[str] = []
    for target_type in ("DOM Mutation", "Object.defineProperty Called"):
        for payload in _iter_payloads_by_type(trace, target_type):
            stack = _stack_from_payload(payload)
            if not _stack_is_benign(stack):
                first_line = stack.strip().splitlines()[0] if stack.strip() else target_type
                suspicious_heads.append(first_line[:80])
    if not suspicious_heads:
        return None
    return HeuristicMatch(
        name="stack_anomaly",
        description="DOM or prototype modification originates from anonymous/shallow stack traces.",
        severity="medium",
        evidence=f"Stack heads: {', '.join(suspicious_heads[:4])}",
    )


def detect_anti_tamper_locking(trace: Mapping[str, Any]) -> Optional[HeuristicMatch]:
    """Flag attempts to lock native prototypes by setting configurable=False."""
    locked = []
    for payload in _iter_payloads_by_type(trace, "Object.defineProperty Called"):
        configurable = payload.get("configurable")
        is_native = payload.get("isNativePrototype") or payload.get("isNative")
        attribute = payload.get("property") or payload.get("attribute") or payload.get("object")
        if configurable is False and is_native:
            locked.append(str(attribute or "unknown"))
    if not locked:
        return None
    return HeuristicMatch(
        name="anti_tamper_locking",
        description="Code locks native prototypes by disabling configurability after hooking.",
        severity="medium",
        evidence=f"Locked properties: {', '.join(sorted(set(locked))[:5])}",
    )


def detect_environment_mimicry(trace: Mapping[str, Any]) -> Optional[HeuristicMatch]:
    """Detect repeated interrogation of webdriver/plugins/mimeTypes to spot analysis."""
    tokens = [token.lower() for token in _event_tokens(trace)]
    hits = [token for token in tokens if any(prop in token for prop in ANTI_ANALYSIS_PROPERTIES)]
    if len(hits) < 2:
        return None
    return HeuristicMatch(
        name="environment_mimicry",
        description="Trace repeatedly inspects webdriver/plugins/mimeTypes, suggesting anti-analysis checks.",
        severity="low",
        evidence=f"Properties accessed: {', '.join(hits[:4])}",
    )


def detect_platform_divergence(trace: Mapping[str, Any]) -> Optional[HeuristicMatch]:
    """Detect scripts that probe touch/screen properties before branching to remote payloads."""
    tokens = _event_tokens(trace)
    lower_tokens = [token.lower() for token in tokens]
    divergence_reads = [token for token in lower_tokens[:40] if any(prop in token for prop in PLATFORM_DIVERGENCE_PROPERTIES)]
    if len(divergence_reads) < 2:
        return None
    first_idx = min(lower_tokens.index(token) for token in divergence_reads)
    window = tokens[first_idx:first_idx + 12]
    if not any("Script Src Set" in token or "networkRequest" in token or "XHR Request" in token for token in window):
        return None
    return HeuristicMatch(
        name="platform_divergence",
        description="Script aggressively probes touch/mobile capabilities before loading remote payloads.",
        severity="medium",
        evidence=f"Probe tokens: {', '.join(divergence_reads[:3])}",
    )


# List of heuristic callables with docstrings explaining their purpose.
TRACE_HEURISTICS = [
    detect_obfuscated_eval_chain,
    detect_cdn_script_reinjection,
    detect_web3_event_listener,
    detect_prototype_hardening,
    detect_cookie_beacon,
    detect_blob_worker_dropper,
    detect_suspicious_host_contact,
    detect_stack_anomaly,
    detect_anti_tamper_locking,
    detect_environment_mimicry,
    detect_platform_divergence,
]
