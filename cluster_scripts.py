#!/usr/bin/env python3
"""
Script clustering using DTW + HDBSCAN (hierarchical density-based clustering)
Focus on nested event types from CDP traces
"""

import os

os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("VECLIB_MAXIMUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

import json
import math
import re
import hashlib
import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict, Counter
from functools import lru_cache
from urllib.parse import urlparse, parse_qs
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import silhouette_samples, pairwise_distances
import hdbscan
from multiprocessing import Pool, cpu_count
import pickle
from tqdm import tqdm

from cluster_neighbors import compute_cluster_neighbors

CAPABILITY_EXACT_MAP = {
    'XHR Request': 'NET_XHR',
    'XHR Response': 'NET_XHR',
    'Fetch Request': 'NET_FETCH',
    'Fetch Response': 'NET_FETCH',
    'Beacon API Call': 'NET_BEACON',
    'Cache API Open': 'CACHE',
    'Cache API Match': 'CACHE',
    'Storage Event': 'STORAGE',
    'WebSocket Connection': 'NET_WS',
    'WebSocket Send': 'NET_WS',
    'WebSocket Receive (onmessage)': 'NET_WS',
    'WebSocket Receive (addEventListener)': 'NET_WS',
    'Redirect via location.href': 'REDIRECT',
    'Redirect via location.replace': 'REDIRECT',
    'Redirect via location.assign': 'REDIRECT',
    'Popup Opened': 'POPUP',
    'Script Src Set': 'DOM_INJECT_SCRIPT',
    'Inline Script Injected': 'DOM_INJECT_SCRIPT',
    'Document.write Call': 'DOM_INJECT_HTML',
    'Document.writeln Call': 'DOM_INJECT_HTML',
    'HTML Property Write (Suspicious)': 'DOM_INJECT_HTML',
    'IFrame Src Set': 'DOM_INJECT_IFRAME',
    'IFrame Created (Potential Context Escape)': 'DOM_INJECT_IFRAME',
    'WARNING: Multiple IFrames Created': 'HOOK_EVASION',
    'Form Submitted': 'CREDENTIALS',
    'Sensitive Field Read': 'CREDENTIALS',
    'Sensitive Field Write': 'CREDENTIALS',
    'Suspicious querySelector': 'CREDENTIALS',
    'Suspicious getElementById': 'CREDENTIALS',
    'Cookie Read': 'COOKIE',
    'Cookie Update': 'COOKIE',
    'Clipboard Read': 'CLIPBOARD',
    'Clipboard Write': 'CLIPBOARD',
    'Hook Detection Attempt': 'HOOK_EVASION',
    'Service Worker Registration': 'SERVICE_WORKER',
    'Web Worker Created': 'WORKER',
    'Blob URL Created': 'BLOB',
    'Download Triggered': 'DOWNLOAD',
    'Object.defineProperty Called': 'HOOKING',
    'Eval Call': 'OBFUSCATION',
    'Function Constructor': 'OBFUSCATION',
    'atob De-obfuscation': 'OBFUSCATION',
    'String.fromCharCode De-obfuscation': 'OBFUSCATION',
    'JSON.parse Suspicious Payload': 'OBFUSCATION',
    'WebGL Context Creation': 'FINGERPRINTING',
    'Canvas toDataURL': 'FINGERPRINTING',
    'PushManager Subscribe': 'PUSH',
    'Notification Request Permission': 'PUSH',
    'Alert Dialog': 'SOCIAL_ENGINEERING',
    'Confirm Dialog': 'SOCIAL_ENGINEERING',
    'Prompt Dialog': 'SOCIAL_ENGINEERING',
    'Fullscreen Requested': 'POPUP',
    'Window Blur (Possible Popup)': 'POPUP',
    'MutationObserver (Native)': 'DOM_MUTATION'
}

SUSPICIOUS_EVENTS = {
    'Cookie Read',
    'Cookie Update',
    'Script Src Set',
    'Inline Script Injected',
    'HTML Property Write (Suspicious)',
    'Document.write Call',
    'Document.writeln Call',
    'Eval Call',
    'Function Constructor',
    'atob De-obfuscation',
    'String.fromCharCode De-obfuscation',
    'JSON.parse Suspicious Payload',
    'Redirect via location.href',
    'Redirect via location.replace',
    'Redirect via location.assign',
    'Sensitive Field Read',
    'Sensitive Field Write',
    'Form Submitted',
    'Clipboard Read',
    'Clipboard Write',
    'Hook Detection Attempt',
    'Service Worker Registration',
    'Web Worker Created',
    'Blob URL Created',
    'IFrame Src Set',
    'IFrame Created (Potential Context Escape)',
    'WARNING: Multiple IFrames Created',
    'MutationObserver (Native)',
    'Sensitive Field Access',
    'Document Fragment Injection'
}

NOISE_EVENT_TYPES = {
    'Monitoring Started',
    'Monitoring Script Fully Loaded'
}

MONITOR_STACK_IDENTIFIERS = (
    'dom_mutation_observer.js',
    'monitoring.js',
    'mutation_observers'
)

AD_DOMAIN_SUFFIXES = {
    'doubleclick.net',
    'googlesyndication.com',
    'googleadservices.com',
    'adservice.google.com',
    'adnxs.com',
    'taboola.com',
    'outbrain.com',
    'criteo.com',
    'scorecardresearch.com'
}

ANALYTICS_DOMAIN_SUFFIXES = {
    'google-analytics.com',
    'googletagmanager.com',
    'googletagservices.com',
    'facebook.net',
    'mixpanel.com',
    'segment.com',
    'snowplowanalytics.com'
}

NETWORK_EVENT_TYPES = {
    'XHR Request',
    'XHR Response',
    'Fetch Request',
    'Fetch Response',
    'Beacon API Call',
    'WebSocket Connection',
    'WebSocket Send',
    'WebSocket Receive (onmessage)',
    'WebSocket Receive (addEventListener)',
    'Network.requestWillBeSent',
    'Network.responseReceived',
    'networkRequest',
    'Script Src Set',
    'IFrame Src Set',
    'Image Src Set',
    'Link Href Set',
    'Form Submitted'
}

COOKIE_VALUE_ATTRIBUTES = {
    'domain',
    'path',
    'expires',
    'max-age',
    'maxage',
    'samesite',
    'priority'
}
COOKIE_FLAG_ATTRIBUTES = {
    'secure',
    'httponly'
}
COOKIE_ATTRIBUTE_KEYS = COOKIE_VALUE_ATTRIBUTES | COOKIE_FLAG_ATTRIBUTES
STACK_URL_PATTERN = re.compile(r'(https?://[^\s)]+)')

WP_VERSION_PARAM_KEYS = (
    'ver', 'version', 'ao_version', 'v', 'wpv', 'tver', 'plugin_ver'
)

WP_PLUGIN_PATTERN = re.compile(r"/wp-content/plugins/([^/]+)/", re.IGNORECASE)
WP_THEME_PATTERN = re.compile(r"/wp-content/themes/([^/]+)/", re.IGNORECASE)

WEAK_ATTRIBUTE_PREFIXES = (
    'weak_host=',
    'weak_path=',
    'weak_domain=',
)


class ScriptClusterer:
    """Cluster JavaScript scripts based on CDP event traces"""

    def __init__(
        self,
        experiment_data_dir,
        max_sequence_length=2000,
        require_ast_preview=False,
        allowed_timestamps=None,
        min_suspicious_events=0,
    ):
        self.experiment_data_dir = Path(experiment_data_dir)
        self.traces = []
        self.sequences = []
        self.capability_sequences = []
        self.encoded_sequences = []
        self.encoder = LabelEncoder()
        self.distance_matrix = None
        self.linkage_matrix = None
        self.clusters = None
        self.cluster_metadata = {}
        self.capability_features = None
        self.capability_vocab = []
        self.capability_clusters = None
        self.hdbscan_model = None
        self.max_sequence_length = max_sequence_length
        self.token_embeddings = {}
        self.embedding_dim = 0
        self.embedding_matrix = None
        self.embedding_metadata = {}
        self.semantic_cost_enabled = False
        self.require_ast_preview = require_ast_preview
        self.min_suspicious_events = max(0, int(min_suspicious_events or 0))
        if allowed_timestamps:
            self.allowed_timestamp_list = list(allowed_timestamps)
            self.allowed_timestamps = set(self.allowed_timestamp_list)
        else:
            self.allowed_timestamp_list = None
            self.allowed_timestamps = None
        self._ast_cache = {}

    def timestamp_matches(self, directory_name):
        """Return True if the given timestamp directory passes the filter."""
        if not self.allowed_timestamp_list:
            return True
        for entry in self.allowed_timestamp_list:
            if directory_name == entry or directory_name.startswith(entry):
                return True
        return False

    @staticmethod
    def get_event_argument(event):
        args_values = event.get('argsValues') or []
        if args_values:
            arg = args_values[0]
            if isinstance(arg, dict):
                return arg
        event_type = event.get('eventType')
        if event_type and event_type != 'consoleAPI':
            fallback = {
                key: value
                for key, value in event.items()
                if key not in {'argsValues', 'timestamp', 'eventType'}
            }
            resource_type = fallback.pop('type', None)
            if resource_type and resource_type != event_type:
                fallback['resourceType'] = resource_type
            fallback['type'] = event_type
            return fallback
        return {}

    @staticmethod
    def should_filter_event(event, arg=None):
        arg = arg if arg is not None else ScriptClusterer.get_event_argument(event)
        event_type = arg.get('type') or event.get('eventType')

        if event_type in NOISE_EVENT_TYPES:
            return True

        stack = arg.get('registrationStack') or ''
        if stack:
            lowered = stack.lower()
            for marker in MONITOR_STACK_IDENTIFIERS:
                if marker in lowered:
                    return True
        return False

    @staticmethod
    def extract_domain(url):
        if not url or not isinstance(url, str):
            return None
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        host = parsed.netloc.lower()
        if ':' in host:
            host = host.split(':', 1)[0]
        return host

    @staticmethod
    def normalize_weak_host(host):
        if not host:
            return None
        host = host.strip().lower().strip('.')
        if not host:
            return None
        labels = [label for label in host.split('.') if label]
        if len(labels) <= 1:
            return host
        normalized = ".".join(labels[:-1]).strip('.')
        return normalized or host

    def categorize_url(self, url, script_domain=None):
        if not url:
            return None

        if url.startswith('data:'):
            return 'domain:data'
        if url.startswith('blob:'):
            return 'domain:blob'

        parsed = urlparse(url)
        if not parsed.netloc:
            return 'domain:relative'

        domain = self.extract_domain(url)
        if not domain:
            return 'domain:unknown'

        if any(domain.endswith(ad) for ad in AD_DOMAIN_SUFFIXES):
            return 'domain:ad'
        if any(domain.endswith(analytics) for analytics in ANALYTICS_DOMAIN_SUFFIXES):
            return 'domain:analytics'
        if script_domain and domain == script_domain:
            return 'domain:script-origin'

        normalized_domain = self.normalize_weak_host(domain)
        if normalized_domain:
            return f"weak_domain={normalized_domain}"
        return 'weak_domain=unknown'

    @staticmethod
    def extract_url_from_arg(arg):
        if not isinstance(arg, dict):
            return None
        for key in ('url', 'requestUrl', 'documentURL', 'src', 'href', 'location', 'action', 'scriptURL'):
            value = arg.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def cookie_segments(cookie_value):
        if not cookie_value or not isinstance(cookie_value, str):
            return []
        return [segment.strip() for segment in cookie_value.split(';') if segment.strip()]

    @staticmethod
    def summarize_cookie_keys(cookie_value, max_keys=3):
        segments = ScriptClusterer.cookie_segments(cookie_value)
        keys = []
        for segment in segments:
            if '=' not in segment:
                continue
            key = segment.split('=', 1)[0].strip()
            if not key or key.lower() in COOKIE_ATTRIBUTE_KEYS:
                continue
            if key not in keys:
                keys.append(key)
            if len(keys) >= max_keys:
                break
        return ",".join(keys) if keys else None

    @staticmethod
    def extract_cookie_attribute(cookie_value, attr_name):
        if not cookie_value or not isinstance(cookie_value, str):
            return None
        target = attr_name.lower()
        segments = ScriptClusterer.cookie_segments(cookie_value)
        for segment in segments:
            if '=' in segment:
                key, val = segment.split('=', 1)
                if key.strip().lower() == target:
                    return val.strip()
            else:
                flag = segment.strip().lower()
                if flag == target:
                    return target
        return None

    @staticmethod
    def extract_cookie_flags(cookie_value):
        segments = ScriptClusterer.cookie_segments(cookie_value)
        flags = []
        for segment in segments:
            if '=' in segment:
                continue
            flag = segment.strip().lower()
            if flag in COOKIE_FLAG_ATTRIBUTES and flag not in flags:
                flags.append(flag)
        return ",".join(flags) if flags else None

    @staticmethod
    def extract_stack_source(stack):
        if not stack or not isinstance(stack, str):
            return None
        match = STACK_URL_PATTERN.search(stack)
        if not match:
            return None
        url = match.group(1)
        cleaned = re.sub(r':\d+(?::\d+)?$', '', url)
        domain = ScriptClusterer.extract_domain(cleaned)
        path = ScriptClusterer.short_path_from_url(cleaned, max_len=80)
        if domain and path:
            return f"{domain}{path}"
        return domain or path

    def map_capability(self, base_type, arg, target_tag=None):
        if base_type in CAPABILITY_EXACT_MAP:
            return CAPABILITY_EXACT_MAP[base_type]

        if base_type and base_type.startswith('Geolocation'):
            return 'GEO'
        if base_type and (base_type.startswith('getUserMedia') or base_type == 'enumerateDevices Call'):
            return 'MEDIA'
        if base_type == 'DOM Mutation':
            if target_tag == 'SCRIPT':
                return 'DOM_INJECT_SCRIPT'
            if target_tag == 'IFRAME':
                return 'DOM_INJECT_IFRAME'
            if target_tag == 'STYLE':
                return 'DOM_INJECT_HTML'
            return 'DOM_MUTATION'
        if base_type == 'setAttribute Called':
            attr = (arg or {}).get('attribute') or ''
            attr_lower = attr.lower()
            if attr_lower in {'src', 'srcdoc'}:
                return 'DOM_INJECT_IFRAME'
            if attr_lower in {'href', 'innerhtml'}:
                return 'DOM_INJECT_HTML'
            if attr_lower.startswith('on'):
                return 'DOM_INJECT_SCRIPT'
            return 'DOM_MUTATION'
        if base_type in {'Timeout (Function) Set', 'Interval (Function) Set'}:
            return 'TIMERS'
        if base_type.startswith('Storage') or 'localStorage' in base_type or 'sessionStorage' in base_type:
            return 'STORAGE'
        if base_type.startswith('Web Worker'):
            return 'WORKER'

        return 'OTHER'

    @staticmethod
    def token_weight(token):
        if not token:
            return 1.0
        base = token.split('|', 1)[0]
        return 2.0 if base in SUSPICIOUS_EVENTS else 1.0

    @staticmethod
    def is_weak_attribute(part):
        return any(part.startswith(prefix) for prefix in WEAK_ATTRIBUTE_PREFIXES)

    @staticmethod
    @lru_cache(maxsize=50000)
    def decompose_token_components(token):
        if not token:
            return "", tuple(), tuple()
        parts = token.split('|')
        base = parts[0]
        strong = []
        weak = []
        for part in parts[1:]:
            if ScriptClusterer.is_weak_attribute(part):
                weak.append(part)
            else:
                strong.append(part)
        return base, tuple(strong), tuple(weak)

    @staticmethod
    def weak_attribute_penalty(weak_a, weak_b):
        if not weak_a and not weak_b:
            return 0.0
        if weak_a == weak_b:
            return 0.0
        if not weak_a or not weak_b:
            return 0.2
        set_a = set(weak_a)
        set_b = set(weak_b)
        overlap = len(set_a & set_b)
        union = len(set_a | set_b)
        similarity = overlap / union if union else 1.0
        base_cost = 0.05
        variable_cost = (1.0 - similarity) * 0.15
        return base_cost + variable_cost

    @staticmethod
    def canonicalize_token(token):
        base, strong, _ = ScriptClusterer.decompose_token_components(token)
        if not base and not strong:
            return token
        if strong:
            return "|".join((base, *strong))
        return base

    @staticmethod
    def has_weak_features(token):
        _, _, weak = ScriptClusterer.decompose_token_components(token)
        return bool(weak)

    @staticmethod
    def blend_embeddings(vec_a, vec_b, alpha=0.5):
        blended = (1.0 - alpha) * vec_a + alpha * vec_b
        norm = np.linalg.norm(blended)
        if norm == 0:
            return vec_a
        return blended / norm

    @staticmethod
    def extract_motifs(sequence, max_n=3):
        motifs = {}
        for n in range(2, max_n + 1):
            key = f"{n}-gram"
            motifs[key] = Counter()
            if len(sequence) < n:
                continue
            for i in range(len(sequence) - n + 1):
                ngram = " > ".join(sequence[i:i + n])
                motifs[key][ngram] += 1
            motifs[key] = dict(motifs[key])
        return motifs

    def build_event_token(self, base_type, arg, trace_context=None):
        """Build a descriptive token for an event."""
        parts = [base_type]
        script_domain = (trace_context or {}).get('script_domain')

        if base_type == "DOM Mutation":
            method = arg.get('method')
            attr = arg.get('attributeName')
            target_desc = self.describe_dom_target(arg.get('target'))
            if method:
                parts.append(str(method))
            if attr:
                parts.append(f"attr={attr}")
            if target_desc:
                parts.append(target_desc)
        elif base_type in {"setAttribute Called", "getAttribute Called"}:
            tag = arg.get('tagName')
            attribute = arg.get('attribute') or arg.get('attributeName')
            if tag:
                parts.append(str(tag).upper())
            if attribute:
                parts.append(str(attribute))
            value = arg.get('value')
            if value and isinstance(value, str) and len(value) < 60:
                parts.append(f"value={value}")
        elif base_type in {"Event Listener Added", "Event Listener Removed"}:
            event_name = arg.get('eventType') or arg.get('listenerType') or arg.get('event')
            if event_name:
                parts.append(f"event={event_name}")
            target_desc = self.describe_listener_target(arg.get('target'))
            if target_desc:
                parts.append(f"target={target_desc}")
            if arg.get('isCapture'):
                parts.append("capture")
            if arg.get('isPassive'):
                parts.append("passive")
        elif base_type.startswith("Web Worker"):
            url = arg.get('scriptURL') or self.extract_url_from_arg(arg)
            bucket = self.categorize_url(url, script_domain)
            if bucket:
                parts.append(bucket)
            host = self.extract_domain(url)
            if host:
                normalized_host = self.normalize_weak_host(host)
                parts.append(f"weak_host={normalized_host or host}")
            path = self.short_path_from_url(url, max_len=60)
            if path:
                parts.append(f"weak_path={path}")
            worker_name = (arg.get('options') or {}).get('name') or arg.get('name')
            if worker_name:
                parts.append(f"name={worker_name}")
        elif base_type in NETWORK_EVENT_TYPES:
            url = self.extract_url_from_arg(arg)
            bucket = self.categorize_url(url, script_domain)
            if bucket:
                parts.append(bucket)
            host = self.extract_domain(url)
            if host:
                normalized_host = self.normalize_weak_host(host)
                parts.append(f"weak_host={normalized_host or host}")
            path = self.short_path_from_url(url)
            if path:
                parts.append(f"weak_path={path}")
            method = (
                arg.get('request', {}).get('method')
                or arg.get('method')
                or ((arg.get('options') or {}).get('method'))
            )
            if not method and isinstance(arg.get('arguments'), list):
                for item in arg['arguments'][1:2]:
                    if isinstance(item, dict) and item.get('method'):
                        method = item['method']
                        break
            if method:
                parts.append(f"method={method}")
            resource_type = arg.get('resourceType')
            if resource_type and resource_type != base_type:
                parts.append(f"resource={resource_type}")
            initiator_type = arg.get('initiatorType')
            if initiator_type:
                parts.append(f"initiator={initiator_type}")
            if base_type == "Form Submitted":
                field_count = arg.get('fieldCount')
                if field_count is not None:
                    parts.append(f"fields={field_count}")
                preview = self.summarize_form_fields(arg.get('fields'))
                if preview:
                    parts.append(f"field_preview={preview}")
        elif base_type in {"Timeout (Function) Set", "Interval (Function) Set"}:
            delay = arg.get('delay')
            if delay is not None:
                parts.append(f"delay={delay}")
            source = self.extract_stack_source(arg.get('registrationStack'))
            if source:
                parts.append(f"source={source}")
        elif base_type in {"Cookie Read", "Cookie Update"}:
            cookie_value = arg.get('value')
            keys = self.summarize_cookie_keys(cookie_value)
            if keys:
                parts.append(f"keys={keys}")
            elif cookie_value == "":
                parts.append("keys=empty")
            domain = self.extract_cookie_attribute(cookie_value, 'domain')
            if domain:
                parts.append(f"domain={domain}")
            path = self.extract_cookie_attribute(cookie_value, 'path')
            if path:
                parts.append(f"path={path}")
            flags = self.extract_cookie_flags(cookie_value)
            if flags:
                parts.append(f"flags={flags}")
        elif base_type in {"Storage Event", "Cache API Open", "Cache API Match"}:
            key = arg.get('key') or arg.get('cacheName')
            if key:
                parts.append(f"key={key}")
            url = arg.get('url') or self.extract_url_from_arg(arg)
            if url:
                bucket = self.categorize_url(url, script_domain)
                if bucket:
                    parts.append(bucket)
            value_summary = self.summarize_storage_value(arg.get('newValue') or arg.get('value'))
            if value_summary:
                parts.append(f"value_preview={value_summary}")
        elif base_type in {"PushManager Subscribe", "Notification Request Permission"}:
            options = arg.get('options') or {}
            keys = sorted(list(options.keys()))
            if keys:
                parts.append(f"options={','.join(keys[:5])}")
        elif base_type in {"WebGL Context Creation", "Canvas toDataURL"}:
            context = arg.get('contextType') or arg.get('tagName')
            if context:
                parts.append(str(context))
        elif base_type in {"Service Worker Registration"}:
            script_url = arg.get('scriptURL') or self.extract_url_from_arg(arg)
            bucket = self.categorize_url(script_url, script_domain)
            if bucket:
                parts.append(bucket)
            host = self.extract_domain(script_url)
            if host:
                parts.append(f"weak_host={self.normalize_weak_host(host) or host}")
            scope = (arg.get('options') or {}).get('scope')
            if scope:
                parts.append(f"scope={scope}")
        elif base_type in {"Clipboard Read", "Clipboard Write"}:
            length = arg.get('textLength')
            if length is not None:
                parts.append(f"len={length}")
            preview = arg.get('textPreview')
            if preview:
                parts.append(f"preview={preview[:40]}")
        elif base_type == "Hook Detection Attempt":
            fname = arg.get('functionName')
            if fname:
                parts.append(f"function={fname}")
        elif base_type in {"Blob URL Created", "Download Triggered"}:
            size = arg.get('blobSize') or len(arg.get('href') or '')
            if size:
                parts.append(f"size={size}")
            target = arg.get('href') or arg.get('blobType')
            if target:
                parts.append(f"target={target[:60]}")
        elif base_type in {"Fullscreen Requested"}:
            element = arg.get('element') or arg.get('elementId')
            if element:
                parts.append(str(element))
        elif base_type in {"Alert Dialog", "Confirm Dialog", "Prompt Dialog"}:
            message = arg.get('message') or ''
            if message:
                parts.append(f"msg={str(message)[:40]}")
        elif base_type in {"Geolocation getCurrentPosition", "Geolocation watchPosition"}:
            options = arg.get('options') or {}
            accuracy = options.get('enableHighAccuracy')
            if accuracy:
                parts.append('high_accuracy')
            timeout = options.get('timeout')
            if timeout:
                parts.append(f"timeout={timeout}")
        elif base_type == "Window Blur (Possible Popup)":
            timestamp = arg.get('timestamp')
            if timestamp:
                parts.append(str(timestamp))
        elif base_type == "WARNING: Multiple IFrames Created":
            count = arg.get('count')
            if count is not None:
                parts.append(f"count={count}")
            message = arg.get('message')
            if message:
                parts.append(message[:40])
        elif base_type == "MutationObserver (Native)":
            mutation_type = arg.get('mutationType')
            if mutation_type:
                parts.append(mutation_type)
            attribute = arg.get('attributeName')
            if attribute:
                parts.append(f"attr={attribute}")
        elif base_type == "IFrame Created (Potential Context Escape)":
            iframe_number = arg.get('iframeNumber')
            if iframe_number is not None:
                parts.append(f"iframe={iframe_number}")
            source = self.extract_stack_source(arg.get('registrationStack'))
            if source:
                parts.append(f"source={source}")
        elif 'object' in arg or 'property' in arg:
            obj = arg.get('object')
            prop = arg.get('property')
            if obj:
                parts.append(str(obj))
            if prop:
                parts.append(str(prop))
                prop_lower = str(prop).lower()
                if prop_lower in {'localstorage', 'sessionstorage'}:
                    summary = self.summarize_storage_value(arg.get('value'))
                    if summary:
                        parts.append(f"keys={summary}")

        return "|".join(parts)

    def parse_event(self, event, trace_context=None, arg=None):
        """Return token, base type, capability and target metadata for an event."""
        arg = arg if arg is not None else self.get_event_argument(event)
        base_type = arg.get('type') or event.get('eventType')
        if not base_type:
            return None

        if base_type == 'consoleAPI':
            return None

        token = self.build_event_token(base_type, arg, trace_context)
        target_tag = None
        if base_type == 'DOM Mutation':
            target = arg.get('target') or {}
            target_tag = target.get('tagName') or target.get('nodeName')
            if target_tag:
                target_tag = str(target_tag).upper()

        capability = self.map_capability(base_type, arg, target_tag)

        return {
            'token': token,
            'base_type': base_type,
            'capability': capability
        }

    @staticmethod
    def compress_sequence(sequence, max_length=None):
        """Collapse consecutive duplicate tokens to reduce noise."""
        if not sequence:
            return []

        compressed = [sequence[0]]
        for token in sequence[1:]:
            if token != compressed[-1]:
                compressed.append(token)
            if max_length and len(compressed) >= max_length:
                break
        return compressed

    @staticmethod
    def describe_dom_target(target):
        """Return a compact descriptor for DOM mutation targets."""
        if not isinstance(target, dict):
            return None

        tag = target.get('tagName') or target.get('nodeName')
        if not tag:
            return None

        tag = str(tag).upper()
        element_id = target.get('id')
        class_name = target.get('className')

        suffix = ""
        if element_id:
            suffix += f"#{element_id}"

        if class_name:
            class_parts = [cls for cls in str(class_name).replace('.', ' ').split() if cls]
            if class_parts:
                suffix += "." + ".".join(class_parts)

        return tag + suffix

    @staticmethod
    def describe_listener_target(target):
        """Return descriptor for event listener targets."""
        if not target:
            return None

        if isinstance(target, str):
            return target

        desc = ScriptClusterer.describe_dom_target(target)
        if desc:
            return desc

        tag = target.get('tagName') or target.get('nodeName') or target.get('type')
        if tag:
            return str(tag)

        selector = target.get('selector') or target.get('name')
        if selector:
            return str(selector)

        return None

    @staticmethod
    def summarize_storage_value(value, max_items=3):
        """Summarize stored keys/values for localStorage/sessionStorage operations."""
        if isinstance(value, dict) and value:
            keys = list(value.keys())[:max_items]
            return ",".join(keys)
        if isinstance(value, list) and value:
            entries = [str(v) for v in value[:max_items]]
            return ",".join(entries)
        if isinstance(value, str) and value:
            return value[:40]
        return None

    @staticmethod
    def summarize_form_fields(fields, max_fields=3):
        if not isinstance(fields, list) or not fields:
            return None
        summaries = []
        for field in fields[:max_fields]:
            name = (field or {}).get('name') or ''
            ftype = (field or {}).get('type') or ''
            length = (field or {}).get('value_length')
            parts = []
            if name:
                parts.append(name)
            if ftype:
                parts.append(ftype)
            if length is not None:
                parts.append(f"len={length}")
            if parts:
                summaries.append(":".join(parts))
        return "|".join(summaries) if summaries else None

    @staticmethod
    def short_path_from_url(url, max_len=40):
        if not url:
            return None
        try:
            parsed = urlparse(url)
        except Exception:
            return None
        path = parsed.path or ''
        if not path:
            return None
        if len(path) > max_len:
            return path[:max_len - 1] + '…'
        return path

    @staticmethod
    def extract_wp_version_from_url(url):
        """Extract version hint from query parameters or filename."""
        try:
            parsed = urlparse(url)
        except Exception:
            return None

        query = parse_qs(parsed.query)
        for key in WP_VERSION_PARAM_KEYS:
            values = query.get(key)
            if values:
                value = values[0]
                if value:
                    return value

        filename = (parsed.path or '').split('/')[-1]
        if filename:
            match = re.search(r'(\d+\.\d+(?:\.\d+)*)', filename)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def extract_wordpress_components(resource_urls):
        """Return lists of detected plugin and theme assets from WP resource URLs."""
        plugins = []
        themes = []

        if not resource_urls:
            return plugins, themes

        for url in resource_urls:
            if not isinstance(url, str):
                continue

            version = ScriptClusterer.extract_wp_version_from_url(url)

            plugin_match = WP_PLUGIN_PATTERN.search(url)
            if plugin_match:
                plugins.append({
                    'name': plugin_match.group(1),
                    'version': version
                })
                continue

            theme_match = WP_THEME_PATTERN.search(url)
            if theme_match:
                themes.append({
                    'name': theme_match.group(1),
                    'version': version
                })

        return plugins, themes

    @staticmethod
    def _token_semantic_cost(token_a, token_b, token_embeddings=None):
        """Return semantic substitution cost between two tokens."""
        if token_a == token_b:
            return 0.0

        base_a, strong_a, weak_a = ScriptClusterer.decompose_token_components(token_a)
        base_b, strong_b, weak_b = ScriptClusterer.decompose_token_components(token_b)

        if base_a == base_b and strong_a == strong_b:
            return ScriptClusterer.weak_attribute_penalty(weak_a, weak_b)

        if token_embeddings:
            vec_a = token_embeddings.get(token_a)
            vec_b = token_embeddings.get(token_b)
            if vec_a is not None and vec_b is not None:
                similarity = float(np.dot(vec_a, vec_b))
                # Numerical guard for rounding errors
                similarity = max(-1.0, min(1.0, similarity))
                return 1.0 - similarity

        weight_a = ScriptClusterer.token_weight(token_a)
        weight_b = ScriptClusterer.token_weight(token_b)
        return max(weight_a, weight_b)

    @staticmethod
    def categorical_dtw_distance(seq_a, seq_b, token_embeddings=None):
        """Compute DTW distance using semantic-aware substitution costs."""
        if not seq_a and not seq_b:
            return 0.0
        if not seq_a:
            return float(len(seq_b))
        if not seq_b:
            return float(len(seq_a))
        if seq_a is seq_b:
            return 0.0
        if len(seq_a) == len(seq_b) and seq_a == seq_b:
            return 0.0

        len_a = len(seq_a)
        len_b = len(seq_b)

        prev = [float('inf')] * (len_b + 1)
        curr = [float('inf')] * (len_b + 1)
        prev[0] = 0.0

        for i in range(1, len_a + 1):
            curr[0] = float('inf')
            token_a = seq_a[i - 1]
            for j in range(1, len_b + 1):
                token_b = seq_b[j - 1]
                cost = ScriptClusterer._token_semantic_cost(token_a, token_b, token_embeddings)
                curr[j] = cost + min(
                    curr[j - 1],    # insertion
                    prev[j],        # deletion
                    prev[j - 1]     # match/substitution
                )
            prev, curr = curr, prev

        return prev[len_b]

    @staticmethod
    def lb_keogh(sequence_a, sequence_b, radius):
        """Compute the LB_Keogh lower bound between two encoded sequences."""
        if radius <= 0:
            radius = 0

        if len(sequence_a) == 0:
            return 0.0
        if len(sequence_b) == 0:
            return float(len(sequence_a))

        seq_a = np.asarray(sequence_a, dtype=float)
        seq_b = np.asarray(sequence_b, dtype=float)
        len_b = len(seq_b)
        total = 0.0

        for idx, value in enumerate(seq_a):
            if len_b == 0:
                total += value * value
                continue

            start = max(0, idx - radius)
            if start >= len_b:
                diff = value - seq_b[-1]
                total += diff * diff
                continue

            end = min(len_b, idx + radius + 1)
            if end <= start:
                segment = seq_b[start:start + 1]
            else:
                segment = seq_b[start:end]

            lower = float(np.min(segment))
            upper = float(np.max(segment))

            if value > upper:
                total += (value - upper) ** 2
            elif value < lower:
                total += (lower - value) ** 2

        return math.sqrt(total)

    @staticmethod
    def lb_improved(sequence_a, sequence_b, radius):
        """Return a symmetric lower bound based on LB_Keogh."""
        if radius <= 0:
            return 0.0
        return max(
            ScriptClusterer.lb_keogh(sequence_a, sequence_b, radius),
            ScriptClusterer.lb_keogh(sequence_b, sequence_a, radius)
        )

    def load_script_metadata(self, url_hash, timestamp):
        """Load script metadata from loaded_js/index.csv"""
        csv_path = self.experiment_data_dir / url_hash / timestamp / 'loaded_js' / 'index.csv'

        if not csv_path.exists():
            return {}

        try:
            df = pd.read_csv(csv_path)
            # Create mapping from script_id to metadata
            metadata = {}
            for _, row in df.iterrows():
                metadata[str(row['script_id'])] = {
                    'url': row['script_url'],
                    'hash': row['hash'],
                    'file_name': row['file_name'],
                    'is_module': row['is_module']
                }
            return metadata
        except Exception as e:
            print(f"Error loading metadata from {csv_path}: {e}")
            return {}

    def load_js_code(self, url_hash, timestamp, file_name):
        """Load JavaScript code from file"""
        js_path = self.experiment_data_dir / url_hash / timestamp / 'loaded_js' / file_name

        if not js_path.exists():
            return None

        try:
            with open(js_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            print(f"Error loading JS from {js_path}: {e}")
            return None

    @staticmethod
    def compute_script_hash(js_path):
        """Compute SHA256 for a JavaScript file."""
        try:
            h = hashlib.sha256()
            with open(js_path, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to hash {js_path}: {exc}")
            return None

    def load_ast_fingerprint(self, url_hash, timestamp, script_metadata):
        """Load cached AST fingerprint data for a script."""
        ast_dir = self.experiment_data_dir / url_hash / timestamp / 'loaded_js_asts'
        if not ast_dir.exists():
            return None

        script_hash = script_metadata.get('hash')
        file_name = script_metadata.get('file_name')
        js_path = None
        if file_name:
            js_path = self.experiment_data_dir / url_hash / timestamp / 'loaded_js' / file_name

        cache_key = None
        if script_hash:
            cache_key = ('hash', script_hash)
        elif file_name:
            cache_key = ('path', url_hash, timestamp, file_name)

        if cache_key and cache_key in self._ast_cache:
            return self._ast_cache[cache_key]

        candidates = []
        if script_hash:
            candidates.append(ast_dir / f"ast_{script_hash}.json")

        if not script_hash and js_path and js_path.exists():
            computed_hash = self.compute_script_hash(js_path)
            if computed_hash:
                script_hash = computed_hash
                candidates.append(ast_dir / f"ast_{computed_hash}.json")
                cache_key = ('hash', computed_hash)

        for candidate in candidates:
            if candidate.exists():
                try:
                    with open(candidate, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        data['__cache_path'] = str(candidate)
                        if cache_key:
                            self._ast_cache[cache_key] = data
                        return data
                except Exception as exc:  # noqa: BLE001
                    print(f"Error reading AST fingerprint at {candidate}: {exc}")
                    if cache_key:
                        self._ast_cache[cache_key] = None
                    return None
        if cache_key:
            self._ast_cache[cache_key] = None
        return None

    @staticmethod
    def build_ast_unit_vector(ast_data):
        """Return a normalized node-type vector for cosine similarity."""
        if not ast_data:
            return None

        unit_vector = ast_data.get('unit_vector')
        if isinstance(unit_vector, dict) and unit_vector:
            return {k: float(v) for k, v in unit_vector.items()}

        raw_counts = ast_data.get('node_type_counts')
        if not isinstance(raw_counts, dict) or not raw_counts:
            return None

        try:
            norm = math.sqrt(sum(float(v) ** 2 for v in raw_counts.values()))
        except Exception:
            return None
        if norm <= 0:
            return None

        return {k: float(v) / norm for k, v in raw_counts.items()}

    def attach_ast_metadata(self, trace, url_hash, timestamp, script_metadata):
        """Attach AST fingerprint metadata (if available) to the trace."""
        ast_data = self.load_ast_fingerprint(url_hash, timestamp, script_metadata)
        if ast_data:
            trace['ast_fingerprint'] = ast_data
            trace['ast_script_hash'] = ast_data.get('script_hash')
            trace['ast_unit_vector'] = self.build_ast_unit_vector(ast_data)
            trace['ast_preview'] = ast_data.get('ast_preview')
        else:
            trace['ast_fingerprint'] = None
            trace['ast_script_hash'] = None
            trace['ast_unit_vector'] = None
            trace['ast_preview'] = None
        trace['ast_similarity'] = None

    def load_fingerprint(self, url_hash, timestamp):
        """Load fingerprint metadata (including WP assets) if available."""
        fp_path = self.experiment_data_dir / url_hash / timestamp / 'fingerprint.json'
        if not fp_path.exists():
            return {}

        try:
            with open(fp_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error reading fingerprint from {fp_path}: {e}")
            return {}

        resource_urls = data.get('resource_urls_with_wp_paths') or []
        plugins, themes = self.extract_wordpress_components(resource_urls)

        return {
            'is_wordpress': data.get('is_wordpress'),
            'wordpress_version': data.get('wordpress_version'),
            'plugins': plugins,
            'themes': themes,
            'url': data.get('url')
        }

    @staticmethod
    def normalize_severity_label(level):
        if not level:
            return None
        label = level.replace('SEVERITY_', '').replace('_', ' ')
        label = label.strip()
        if not label:
            return None
        return label.title()

    @staticmethod
    def compose_virustotal_verdict(malicious_count, suspicious_count, severity_level):
        malicious = int(malicious_count or 0)
        suspicious = int(suspicious_count or 0)

        if malicious > 0:
            return "Malicious"
        if suspicious > 0:
            return "Suspicious"

        normalized = ScriptClusterer.normalize_severity_label(severity_level)
        if normalized:
            return normalized
        return "Clean"

    def load_virustotal_report(self, url_hash, timestamp):
        """Load VirusTotal report summary for the crawled URL if available."""
        vt_path = self.experiment_data_dir / url_hash / timestamp / 'virustotal_report.json'
        if not vt_path.exists():
            return None

        try:
            with open(vt_path, 'r') as f:
                raw_report = json.load(f)
        except Exception as exc:
            print(f"Error reading VirusTotal report from {vt_path}: {exc}")
            return None

        report_blob = raw_report.get('report') or {}
        attributes = report_blob.get('attributes') or {}
        stats = attributes.get('last_analysis_stats') or {}
        malicious = int(stats.get('malicious') or 0)
        suspicious = int(stats.get('suspicious') or 0)
        harmless = int(stats.get('harmless') or 0)
        undetected = int(stats.get('undetected') or 0)
        timeout = int(stats.get('timeout') or 0)
        total_scanners = malicious + suspicious + harmless + undetected + timeout

        severity = attributes.get('threat_severity') or {}
        severity_level = severity.get('threat_severity_level')
        verdict = self.compose_virustotal_verdict(malicious, suspicious, severity_level)

        summary = {
            'url': raw_report.get('url') or attributes.get('url'),
            'report_id': report_blob.get('id'),
            'report_link': (report_blob.get('links') or {}).get('self'),
            'verdict': verdict,
            'verdict_count': malicious + suspicious,
            'malicious_count': malicious,
            'suspicious_count': suspicious,
            'total_scanners': total_scanners if total_scanners > 0 else None,
            'scan_date': attributes.get('last_analysis_date'),
            'threat_severity_level': severity_level,
            'threat_severity_label': self.normalize_severity_label(severity_level),
            'threat_severity_note': severity.get('level_description'),
        }

        # Keep explicit zeros so downstream consumers can distinguish "no detections".
        summary['verdict_count'] = int(summary['verdict_count'])
        summary['malicious_count'] = malicious
        summary['suspicious_count'] = suspicious

        return summary

    def extract_traces(self, max_scripts=None):
        """Extract event traces from all byscripts.json files"""
        print("\n=== Extracting Event Traces ===")

        byscripts_files = list(self.experiment_data_dir.rglob('byscripts.json'))
        print(f"Found {len(byscripts_files)} byscripts.json files")

        if self.allowed_timestamp_list:
            print(f"Timestamp filter enabled: {', '.join(self.allowed_timestamp_list)}")

        filtered_without_ast = 0
        filtered_low_suspicious_events = 0
        skipped_timestamps = 0

        for byscripts_file in tqdm(byscripts_files, desc="Processing files"):
            try:
                # Extract metadata from path
                parts = byscripts_file.parts
                url_hash = parts[-3]
                timestamp = parts[-2]

                if not self.timestamp_matches(timestamp):
                    skipped_timestamps += 1
                    continue

                # Load script metadata
                metadata_map = self.load_script_metadata(url_hash, timestamp)
                fingerprint = self.load_fingerprint(url_hash, timestamp)
                virustotal_summary = self.load_virustotal_report(url_hash, timestamp)

                # Load events
                with open(byscripts_file, 'r') as f:
                    data = json.load(f)

                for script_id, script_data in data.items():
                    events = script_data['events']

                    # Skip scripts with no events
                    if len(events) == 0:
                        continue

                    # Extract nested event types
                    event_sequence = []
                    capability_sequence = []
                    timestamp_sequence = []
                    capability_counts = Counter()
                    suspicious_events = 0

                    script_metadata = metadata_map.get(script_id, {})
                    script_url = script_data.get('url', script_metadata.get('url', 'unknown'))
                    script_domain = self.extract_domain(script_url)
                    trace_context = {'script_domain': script_domain}

                    for event in events:
                        arg = self.get_event_argument(event)
                        if self.should_filter_event(event, arg):
                            continue

                        parsed = self.parse_event(event, trace_context, arg)
                        if not parsed:
                            continue

                        nested_type = parsed['token']
                        capability = parsed['capability']

                        event_sequence.append(nested_type)
                        capability_sequence.append(capability)
                        timestamp_sequence.append(event.get('timestamp', ''))
                        capability_counts[capability] += 1

                        if self.token_weight(nested_type) > 1.0:
                            suspicious_events += 1

                    if len(event_sequence) == 0:
                        continue

                    compressed_sequence = self.compress_sequence(event_sequence, self.max_sequence_length)
                    compressed_cap_sequence = self.compress_sequence(capability_sequence, self.max_sequence_length)
                    motifs = self.extract_motifs(capability_sequence)

                    # Get metadata

                    # Create trace record
                    vt_details = virustotal_summary if virustotal_summary else None

                    trace = {
                        'trace_id': f"{url_hash}_{timestamp}_{script_id}",
                        'url_hash': url_hash,
                        'timestamp': timestamp,
                        'script_id': script_id,
                        'script_url': script_url,
                        'event_sequence': event_sequence,
                        'compressed_event_sequence': compressed_sequence,
                        'capability_sequence': capability_sequence,
                        'compressed_capability_sequence': compressed_cap_sequence,
                        'capability_counts': dict(capability_counts),
                        'capability_motifs': motifs,
                        'suspicious_event_count': suspicious_events,
                        'timestamp_sequence': timestamp_sequence,
                        'num_events': len(event_sequence),
                        'raw_events': events,
                        # Metadata from index.csv
                        'file_name': script_metadata.get('file_name'),
                        'hash': script_metadata.get('hash'),
                        'is_module': script_metadata.get('is_module', False),
                        # WordPress fingerprint metadata
                        'is_wordpress': fingerprint.get('is_wordpress'),
                        'wordpress_version': fingerprint.get('wordpress_version'),
                        'wordpress_plugins': fingerprint.get('plugins', []),
                        'wordpress_themes': fingerprint.get('themes', []),
                        'page_url': fingerprint.get('url'),
                        # VirusTotal metadata
                        'virustotal': vt_details,
                        'virustotal_verdict': (vt_details or {}).get('verdict'),
                        'virustotal_verdict_count': (vt_details or {}).get('verdict_count')
                    }

                    self.attach_ast_metadata(trace, url_hash, timestamp, script_metadata)

                    if self.require_ast_preview and not (trace.get('ast_preview') or '').strip():
                        filtered_without_ast += 1
                        continue

                    if (
                        self.min_suspicious_events > 0
                        and suspicious_events < self.min_suspicious_events
                    ):
                        filtered_low_suspicious_events += 1
                        continue

                    self.traces.append(trace)

                    # Limit for testing
                    if max_scripts and len(self.traces) >= max_scripts:
                        break

                if max_scripts and len(self.traces) >= max_scripts:
                    break

            except Exception as e:
                print(f"Error processing {byscripts_file}: {e}")
                continue

        print(f"\nExtracted {len(self.traces)} script traces")
        if self.require_ast_preview:
            print(f"Filtered out {filtered_without_ast} scripts without AST previews.")
        if self.min_suspicious_events > 0:
            print(
                f"Filtered out {filtered_low_suspicious_events} scripts with "
                f"fewer than {self.min_suspicious_events} suspicious events."
            )
        if self.allowed_timestamps is not None:
            print(f"Skipped {skipped_timestamps} files outside the timestamp filter.")

        # Print event type statistics
        all_events = []
        for trace in self.traces:
            all_events.extend(trace['event_sequence'])

        event_counts = Counter(all_events)
        print(f"\nUnique event types: {len(event_counts)}")
        print("\nTop 15 event types:")
        for event_type, count in event_counts.most_common(15):
            print(f"  {event_type}: {count}")

        return self.traces

    def encode_sequences(self):
        """Prepare compressed event sequences for clustering"""
        print("\n=== Encoding Event Sequences ===")

        # Build compressed sequences for clustering and collect vocabulary
        all_tokens = []
        self.sequences = []
        self.capability_sequences = []
        for trace in self.traces:
            compressed_seq = trace.get('compressed_event_sequence')
            if compressed_seq is None:
                compressed_seq = self.compress_sequence(trace['event_sequence'], self.max_sequence_length)
                trace['compressed_event_sequence'] = compressed_seq
            self.sequences.append(compressed_seq)
            all_tokens.extend(compressed_seq)

            compressed_cap = trace.get('compressed_capability_sequence')
            if compressed_cap is None:
                compressed_cap = self.compress_sequence(trace.get('capability_sequence', []), self.max_sequence_length)
                trace['compressed_capability_sequence'] = compressed_cap
            self.capability_sequences.append(compressed_cap)

        # Fit encoder on compressed tokens for a tighter vocabulary
        if all_tokens:
            self.encoder.fit(all_tokens)
            vocab_size = len(self.encoder.classes_)
            print(f"Vocabulary size: {vocab_size}")

            token_to_index = {token: idx for idx, token in enumerate(self.encoder.classes_)}
            sequence_count = len(self.sequences)
            use_parallel = sequence_count >= 500 and vocab_size >= 5000

            if use_parallel:
                try:
                    worker_count = max(1, cpu_count() - 1)
                except NotImplementedError:
                    worker_count = 1
                worker_count = min(worker_count, sequence_count)
            else:
                worker_count = 1

            if worker_count == 1:
                self.encoded_sequences = [
                    np.array([float(token_to_index[token]) for token in seq], dtype=float)
                    for seq in self.sequences
                ]
            else:
                print(f"Encoding sequences with {worker_count} worker(s)...")
                with Pool(
                    processes=worker_count,
                    initializer=_init_encoder_worker,
                    initargs=(token_to_index,),
                ) as pool:
                    encoded = []
                    for seq in tqdm(
                        pool.imap(_encode_sequence_worker, self.sequences),
                        total=sequence_count,
                        desc="Encoding sequences",
                    ):
                        encoded.append(np.array(seq, dtype=float))
                self.encoded_sequences = encoded
        else:
            print("No events found to encode.")
            self.encoded_sequences = []

        print(f"Prepared {len(self.sequences)} compressed sequences")

        # Print sequence length statistics
        if self.sequences:
            lengths = [len(seq) for seq in self.sequences]
            print(f"Compressed sequence lengths - Min: {min(lengths)}, Max: {max(lengths)}, Mean: {np.mean(lengths):.1f}")

        if self.sequences:
            trained = self.train_token_embeddings()
            if not trained:
                print("Token embeddings unavailable; DTW will use categorical fallback costs.")
        else:
            self.token_embeddings = {}
            self.semantic_cost_enabled = False

    def train_token_embeddings(self, vector_size=64, window=5, min_count=1, epochs=15):
        """Train lightweight Word2Vec embeddings to enable semantic DTW costs."""
        sentences = [seq for seq in self.sequences if seq]
        if not sentences:
            self.token_embeddings = {}
            self.embedding_dim = 0
            self.semantic_cost_enabled = False
            return False

        unique_tokens = set()
        for seq in sentences:
            unique_tokens.update(seq)

        if len(unique_tokens) < 2:
            print("Not enough distinct tokens for embedding training. Skipping semantic DTW.")
            self.token_embeddings = {}
            self.embedding_dim = 0
            self.semantic_cost_enabled = False
            return False

        print("\n=== Training Token Embeddings ===")
        print(f"Token vocabulary size: {len(unique_tokens)} | Sequences: {len(sentences)}")

        try:
            from gensim.models import Word2Vec
        except ImportError:
            print("gensim is not installed; install it to enable semantic DTW.")
            self.token_embeddings = {}
            self.embedding_dim = 0
            self.semantic_cost_enabled = False
            return False

        try:
            worker_count = max(1, cpu_count() - 1)
        except NotImplementedError:
            worker_count = 1

        worker_count = min(worker_count, len(sentences))

        try:
            model = Word2Vec(
                sentences=sentences,
                vector_size=vector_size,
                window=window,
                min_count=min_count,
                sg=1,
                epochs=epochs,
                workers=worker_count,
                negative=10,
                sample=1e-3,
                seed=42
            )
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to train token embeddings: {exc}")
            self.token_embeddings = {}
            self.embedding_dim = 0
            self.semantic_cost_enabled = False
            return False

        normalized_embeddings = {}
        for token in model.wv.index_to_key:
            vec = np.array(model.wv[token], dtype=np.float32)
            norm = np.linalg.norm(vec)
            if norm == 0:
                continue
            normalized_embeddings[token] = vec / norm

        if not normalized_embeddings:
            print("Embedding training produced no usable vectors.")
            self.token_embeddings = {}
            self.embedding_dim = 0
            self.semantic_cost_enabled = False
            return False

        canonical_vectors = defaultdict(list)
        for token, vec in normalized_embeddings.items():
            canonical_key = ScriptClusterer.canonicalize_token(token)
            canonical_vectors[canonical_key].append(vec)

        canonical_means = {}
        for key, vectors in canonical_vectors.items():
            stacked = np.stack(vectors)
            mean_vec = stacked.mean(axis=0)
            norm = np.linalg.norm(mean_vec)
            if norm == 0:
                continue
            canonical_means[key] = mean_vec / norm

        adjusted_embeddings = {}
        for token, vec in normalized_embeddings.items():
            if ScriptClusterer.has_weak_features(token):
                canonical_key = ScriptClusterer.canonicalize_token(token)
                canonical_vec = canonical_means.get(canonical_key)
                if canonical_vec is not None:
                    adjusted_embeddings[token] = ScriptClusterer.blend_embeddings(vec, canonical_vec, alpha=0.5)
                    continue
            adjusted_embeddings[token] = vec

        self.token_embeddings = adjusted_embeddings
        self.embedding_dim = next(iter(adjusted_embeddings.values())).shape[0]
        coverage = len(adjusted_embeddings) / len(unique_tokens) * 100.0
        self.semantic_cost_enabled = True

        print(f"Embedding model trained (dim={self.embedding_dim}, coverage={coverage:.1f}% of tokens).")
        return True

    def compute_sequence_embeddings(
        self,
        vector_size=128,
        window=5,
        min_count=1,
        epochs=40,
        workers=None,
        negative=5,
        seed=42,
    ):
        """Compute Doc2Vec embeddings for every trace sequence."""
        print("\n=== Computing Sequence Embeddings (Doc2Vec) ===")
        documents = []
        for idx, seq in enumerate(self.sequences):
            if not seq:
                continue
            documents.append((idx, seq))

        if not documents:
            print("No sequences with events were found; skipping Doc2Vec training.")
            self.embedding_matrix = None
            self.embedding_metadata = {}
            return None

        try:
            from gensim.models.doc2vec import Doc2Vec, TaggedDocument
        except ImportError:
            print("gensim is not installed; cannot compute Doc2Vec embeddings.")
            self.embedding_matrix = None
            self.embedding_metadata = {}
            return None

        try:
            worker_count = workers or max(1, cpu_count() - 1)
        except NotImplementedError:
            worker_count = workers or 1

        worker_count = max(1, worker_count)

        tagged_docs = [TaggedDocument(words=seq, tags=[f"trace_{idx}"]) for idx, seq in documents]

        print(
            f"Training Doc2Vec on {len(tagged_docs)} documents "
            f"(vector_size={vector_size}, window={window}, min_count={min_count}, epochs={epochs})"
        )

        model = Doc2Vec(
            vector_size=vector_size,
            window=window,
            min_count=min_count,
            workers=worker_count,
            epochs=epochs,
            hs=0,
            negative=negative,
            dm=1,
            dm_mean=1,
            seed=seed,
        )

        model.build_vocab(tagged_docs)
        model.train(tagged_docs, total_examples=len(tagged_docs), epochs=model.epochs)

        embedding_matrix = np.zeros((len(self.traces), vector_size), dtype=np.float32)
        for trace_idx, _ in documents:
            tag = f"trace_{trace_idx}"
            embedding_matrix[trace_idx] = model.dv[tag]

        norms = np.linalg.norm(embedding_matrix, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        embedding_matrix = embedding_matrix / norms

        self.embedding_matrix = embedding_matrix
        self.embedding_metadata = {
            'method': 'doc2vec',
            'vector_size': vector_size,
            'window': window,
            'min_count': min_count,
            'epochs': epochs,
            'negative': negative,
            'seed': seed,
            'workers': worker_count,
        }
        self.cluster_metadata['embedding_method'] = self.embedding_metadata['method']
        print(f"Doc2Vec embeddings computed with shape {embedding_matrix.shape}")
        return self.embedding_matrix

    def compute_embedding_distance_matrix(self, metric='euclidean'):
        """Derive a pairwise distance matrix from the embedding matrix."""
        if self.embedding_matrix is None:
            print("Embedding matrix missing; cannot compute embedding distance matrix.")
            return None

        print(f"\n=== Computing {metric} distance matrix over embeddings ===")
        try:
            distances = pairwise_distances(self.embedding_matrix, metric=metric)
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to compute embedding distance matrix: {exc}")
            return None

        self.distance_matrix = distances.astype(np.float64, copy=False)
        self.cluster_metadata['distance_source'] = f'embedding_{metric}'
        print(f"Embedding distance matrix shape: {self.distance_matrix.shape}")
        return self.distance_matrix

    def compute_capability_features(self):
        """Compute normalized capability count vectors for each trace."""
        capabilities = set()
        for trace in self.traces:
            capabilities.update(trace.get('capability_counts', {}).keys())

        self.capability_vocab = sorted(capabilities)
        if not self.capability_vocab:
            self.capability_features = None
            print("No capability data available.")
            return None

        feature_matrix = np.zeros((len(self.traces), len(self.capability_vocab)), dtype=float)

        for i, trace in enumerate(self.traces):
            counts = trace.get('capability_counts', {})
            total = sum(counts.values()) or 1
            for j, capability in enumerate(self.capability_vocab):
                feature_matrix[i, j] = counts.get(capability, 0) / total

        self.capability_features = feature_matrix
        print(f"Computed capability feature matrix with shape {feature_matrix.shape}")
        return feature_matrix

    def simple_kmeans(self, features, k, random_state=42, max_iter=100):
        """Lightweight k-means implementation to avoid heavy dependencies."""
        n_samples = features.shape[0]
        if k <= 0 or n_samples == 0:
            return np.zeros(n_samples, dtype=int)

        k = min(k, n_samples)
        rng = np.random.default_rng(random_state)
        centroids = features[rng.choice(n_samples, size=k, replace=False)]
        labels = np.zeros(n_samples, dtype=int)

        for _ in range(max_iter):
            distances = np.linalg.norm(features[:, None, :] - centroids[None, :, :], axis=2)
            new_labels = distances.argmin(axis=1)

            if np.array_equal(new_labels, labels):
                break

            labels = new_labels
            new_centroids = []
            for cluster_idx in range(k):
                mask = labels == cluster_idx
                if not np.any(mask):
                    new_centroids.append(features[rng.integers(0, n_samples)])
                else:
                    new_centroids.append(features[mask].mean(axis=0))
            centroids = np.vstack(new_centroids)

        return labels

    def capability_clustering(self, num_clusters=8, random_state=42):
        """Cluster scripts using bag-of-capabilities vectors."""
        print("\n=== Capability Clustering ===")

        if self.capability_features is None:
            features = self.compute_capability_features()
        else:
            features = self.capability_features

        if features is None:
            print("Skipping capability clustering (no features).")
            return None

        effective_clusters = min(num_clusters, len(self.traces))
        if effective_clusters < 1:
            print("Not enough traces for capability clustering.")
            return None

        labels = self.simple_kmeans(features, effective_clusters, random_state=random_state)
        self.capability_clusters = labels

        for trace, label in zip(self.traces, labels):
            trace['capability_cluster'] = int(label) + 1

        counts = Counter(label + 1 for label in labels)
        print("Capability cluster distribution:")
        for cluster_id in sorted(counts):
            print(f"  Capability Cluster {cluster_id}: {counts[cluster_id]} scripts")

        return labels

    def summarize_capability_clusters(self):
        if self.capability_clusters is None:
            print("Capability clusters not available.")
            return

        counts = Counter(label + 1 for label in self.capability_clusters)
        print("\nExisting capability cluster distribution:")
        for cluster_id in sorted(counts):
            print(f"  Capability Cluster {cluster_id}: {counts[cluster_id]} scripts")

    def compute_dtw_distances(self, max_distance=None, num_workers=None, chunk_size=500,
                              lb_window_ratio=0.1):
        """Compute DTW distance matrix between all sequence pairs using multi-processing."""
        print("\n=== Computing DTW Distance Matrix ===")

        n = len(self.sequences)
        if n == 0:
            print("No sequences available for DTW computation.")
            self.distance_matrix = np.zeros((0, 0), dtype=np.float32)
            return

        self.distance_matrix = np.zeros((n, n), dtype=np.float64)
        total_pairs = (n * (n - 1)) // 2
        if total_pairs == 0:
            print("Only one sequence detected; DTW matrix is trivial.")
            return

        if chunk_size is None or chunk_size <= 0:
            chunk_size = 500

        encoded_sequences = self.encoded_sequences if self.encoded_sequences else None
        lb_ratio = max(0.0, lb_window_ratio or 0.0)
        lb_enabled = bool(encoded_sequences) and lb_ratio > 0.0 and max_distance is not None

        if lb_enabled:
            non_empty_lengths = [len(seq) for seq in encoded_sequences if len(seq) > 0]
            max_encoded_len = max(non_empty_lengths) if non_empty_lengths else 1
            expected_radius = max(1, int(max_encoded_len * lb_ratio))
            print(
                f"LB_Keogh pruning enabled (window ratio={lb_ratio:.2f}, approx radius={expected_radius}, "
                f"max_distance={max_distance})."
            )
        else:
            if max_distance is None:
                print("LB_Keogh pruning disabled (no max_distance cap provided).")
            elif not encoded_sequences:
                print("LB_Keogh pruning disabled (encoded sequences unavailable).")
            elif lb_ratio <= 0.0:
                print("LB_Keogh pruning disabled (window ratio <= 0).")

        embedding_lookup = self.token_embeddings if self.token_embeddings else None
        if embedding_lookup:
            print(f"Semantic DTW enabled with {len(embedding_lookup)} learned token vectors.")
        else:
            print("Semantic DTW disabled; using categorical costs.")

        # Auto-select worker count if not provided
        if num_workers is None:
            try:
                num_workers = max(1, cpu_count() - 1)
            except NotImplementedError:
                num_workers = 1

        num_workers = max(1, num_workers)
        print(f"Using {num_workers} worker(s) with chunk size {chunk_size} (total pairs: {total_pairs})")

        def chunk_generator():
            chunk = []
            for i in range(n):
                for j in range(i + 1, n):
                    chunk.append((i, j))
                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []
            if chunk:
                yield chunk

        total_pruned = 0

        if num_workers == 1:
            print("Multi-processing disabled (worker count = 1).")
            with tqdm(total=total_pairs, desc="Computing distances") as pbar:
                for chunk in chunk_generator():
                    for i, j in chunk:
                        if lb_enabled:
                            radius = max(
                                1,
                                int(max(len(encoded_sequences[i]), len(encoded_sequences[j])) * lb_ratio)
                            )
                            lower_bound = ScriptClusterer.lb_improved(
                                encoded_sequences[i], encoded_sequences[j], radius
                            )
                            if lower_bound >= max_distance:
                                total_pruned += 1
                                dist = float(max_distance)
                                self.distance_matrix[i, j] = dist
                                self.distance_matrix[j, i] = dist
                                continue

                        dist = ScriptClusterer.categorical_dtw_distance(
                            self.sequences[i],
                            self.sequences[j],
                            embedding_lookup
                        )
                        if max_distance is not None and dist > max_distance:
                            dist = max_distance
                        self.distance_matrix[i, j] = dist
                        self.distance_matrix[j, i] = dist
                    pbar.update(len(chunk))
        else:
            with Pool(processes=num_workers, initializer=_init_dtw_worker,
                      initargs=(
                          self.sequences,
                          encoded_sequences,
                          max_distance,
                          embedding_lookup,
                          lb_ratio if lb_enabled else 0.0,
                      )) as pool:
                with tqdm(total=total_pairs, desc="Computing distances") as pbar:
                    for chunk_result, pruned in pool.imap_unordered(_dtw_worker, chunk_generator()):
                        total_pruned += pruned
                        for i, j, dist in chunk_result:
                            self.distance_matrix[i, j] = dist
                            self.distance_matrix[j, i] = dist
                        pbar.update(len(chunk_result))

        np.fill_diagonal(self.distance_matrix, 0.0)
        print(f"Distance matrix shape: {self.distance_matrix.shape}")
        print(f"Distance range: [{self.distance_matrix.min():.2f}, {self.distance_matrix.max():.2f}]")
        print(f"Mean distance: {self.distance_matrix.mean():.2f}")
        if total_pruned:
            print(f"LB_Keogh pruning skipped {total_pruned} DTW computations (~{(total_pruned / total_pairs) * 100:.1f}% of pairs).")
        self.cluster_metadata['distance_source'] = 'dtw'

    def hdbscan_clustering(self, min_cluster_size=5, min_samples=None, cluster_selection_epsilon=0.0):
        """Cluster traces using HDBSCAN over sequence embeddings or DTW distances."""
        data_source = None
        metric = None
        if self.embedding_matrix is not None:
            print("Using Sequence Embeddings (Vector Space).")
            data_source = self.embedding_matrix
            metric = 'euclidean'
        elif self.distance_matrix is not None:
            print("Using Precomputed Distance Matrix (Legacy DTW).")
            data_source = self.distance_matrix
            metric = 'precomputed'
        else:
            raise ValueError("No input data found. Compute embeddings or DTW distances first.")

        print("\n=== HDBSCAN Clustering ===")
        print(f"Min cluster size: {min_cluster_size}")
        if min_samples is not None:
            print(f"Min samples: {min_samples}")
        if cluster_selection_epsilon:
            print(f"Cluster selection epsilon: {cluster_selection_epsilon}")

        try:
            jobs = max(1, cpu_count())
        except NotImplementedError:
            jobs = 1

        clusterer = hdbscan.HDBSCAN(
            metric=metric,
            min_cluster_size=min_cluster_size,
            min_samples=min_samples,
            cluster_selection_epsilon=cluster_selection_epsilon,
            core_dist_n_jobs=jobs,
        )

        raw_labels = clusterer.fit_predict(data_source)

        label_mapping = {}
        next_label = 1
        normalized_labels = []
        for label in raw_labels:
            if label == -1:
                normalized_labels.append(-1)
                continue
            if label not in label_mapping:
                label_mapping[label] = next_label
                next_label += 1
            normalized_labels.append(label_mapping[label])

        self.clusters = np.array(normalized_labels, dtype=int)
        self.hdbscan_model = clusterer
        self.cluster_metadata = {
            'method': 'hdbscan_vector' if metric == 'euclidean' else 'hdbscan_dtw',
            'min_cluster_size': min_cluster_size,
            'min_samples': min_samples,
            'cluster_selection_epsilon': cluster_selection_epsilon,
            'raw_labels': raw_labels.tolist(),
            'hdbscan_metric': metric,
        }
        self.linkage_matrix = None  # No dendrogram available for HDBSCAN

        for i, trace in enumerate(self.traces):
            trace['cluster'] = int(self.clusters[i])

        cluster_counts = Counter(self.clusters)
        print(f"\nCluster distribution:")
        for cluster_id in sorted(c_id for c_id in cluster_counts if c_id != -1):
            print(f"  Cluster {cluster_id}: {cluster_counts[cluster_id]} scripts")

        noise = cluster_counts.get(-1, 0)
        if noise:
            print(f"  Noise (-1): {noise} scripts")

        silhouette_scores = self.compute_silhouette_scores()
        if silhouette_scores:
            print("\nCluster silhouette (avg similarity) scores:")
            for cluster_id in sorted(silhouette_scores):
                print(f"  Cluster {cluster_id}: {silhouette_scores[cluster_id]:.3f}")
            overall = self.cluster_metadata.get('silhouette_overall')
            if overall is not None:
                print(f"  Overall silhouette: {overall:.3f}")

        ast_similarity = self.compute_ast_cluster_similarity()
        if ast_similarity:
            print("\nAST similarity (cosine vs. cluster centroid):")
            for cluster_id in sorted(ast_similarity):
                value = ast_similarity[cluster_id]
                label = f"{value:.3f}" if value is not None else "n/a"
                print(f"  Cluster {cluster_id}: {label}")

        neighbor_summary = self.compute_cluster_neighbor_summary(limit=5)
        if neighbor_summary:
            print("\nNearest cluster distances:")
            for cluster_id in sorted(neighbor_summary):
                entries = neighbor_summary[cluster_id]
                preview = ", ".join(
                    f"{item['cluster_id']}={item['distance']:.3f}" for item in entries[:5]
                ) or "n/a"
                print(f"  Cluster {cluster_id}: {preview}")

        vt_stats = self.compute_cluster_virustotal_stats()
        if vt_stats:
            print("\nVirusTotal verdict averages:")
            for cluster_id in sorted(vt_stats):
                entry = vt_stats[cluster_id]
                avg = entry.get('average_verdict_count')
                scanned = entry.get('trace_count_with_verdict', 0)
                total = entry.get('total_traces', scanned)
                if avg is None:
                    print(f"  Cluster {cluster_id}: {scanned}/{total} traces with VirusTotal coverage")
                else:
                    print(
                        f"  Cluster {cluster_id}: {avg:.2f} avg detections "
                        f"({scanned}/{total} traces scanned)"
                    )

        return self.clusters

    def compute_silhouette_scores(self):
        """Compute and store per-cluster silhouette averages."""
        if self.clusters is None:
            print("Silhouette computation skipped (clusters unavailable).")
            return {}

        clustered_mask = self.clusters != -1
        valid_indices = np.where(clustered_mask)[0]
        if len(valid_indices) == 0:
            print("Silhouette computation skipped (no clustered samples).")
            return {}

        unique_clusters = np.unique(self.clusters[clustered_mask])
        if unique_clusters.size < 2:
            print("Silhouette computation skipped (need at least two clusters excluding noise).")
            return {}

        labels = self.clusters[clustered_mask]
        metric = None
        data = None
        if self.embedding_matrix is not None:
            data = self.embedding_matrix[valid_indices]
            metric = 'euclidean'
        elif self.distance_matrix is not None:
            data = self.distance_matrix[np.ix_(valid_indices, valid_indices)]
            metric = 'precomputed'
        else:
            print("Silhouette computation skipped (no embeddings or distance matrix).")
            return {}

        try:
            sample_scores = silhouette_samples(data, labels, metric=metric)
        except Exception as exc:  # noqa: BLE001
            print(f"Silhouette computation failed: {exc}")
            return {}

        per_cluster = {}
        for cluster_id in unique_clusters:
            cluster_mask = labels == cluster_id
            if not np.any(cluster_mask):
                continue
            per_cluster[int(cluster_id)] = float(sample_scores[cluster_mask].mean())

        overall = float(sample_scores.mean()) if len(sample_scores) else None

        for idx_list, trace_idx in enumerate(valid_indices):
            self.traces[trace_idx]['silhouette_score'] = float(sample_scores[idx_list])
        for trace_idx in np.where(~clustered_mask)[0]:
            self.traces[trace_idx]['silhouette_score'] = None

        self.cluster_metadata.setdefault('silhouette_per_cluster', {})
        self.cluster_metadata['silhouette_per_cluster'].update(per_cluster)
        if overall is not None:
            self.cluster_metadata['silhouette_overall'] = overall

        return per_cluster

    def compute_ast_cluster_similarity(self):
        """Compute average cosine similarity of AST vectors within each cluster."""
        if self.clusters is None:
            return {}

        cluster_vectors = defaultdict(list)
        for trace, cluster_id in zip(self.traces, self.clusters):
            if cluster_id == -1:
                continue
            vec = trace.get('ast_unit_vector')
            if not vec:
                continue
            cluster_vectors[int(cluster_id)].append((trace, vec))

        ast_similarity = {}
        ast_counts = {}
        for cluster_id, items in cluster_vectors.items():
            ast_counts[cluster_id] = len(items)
            if len(items) < 2:
                ast_similarity[cluster_id] = None
                continue

            centroid = defaultdict(float)
            for _, vec in items:
                for key, value in vec.items():
                    centroid[key] += value

            centroid_norm = math.sqrt(sum(val * val for val in centroid.values()))
            if centroid_norm <= 0:
                ast_similarity[cluster_id] = None
                continue

            centroid_unit = {k: v / centroid_norm for k, v in centroid.items()}
            cluster_scores = []
            for trace, vec in items:
                score = 0.0
                for key, value in vec.items():
                    score += value * centroid_unit.get(key, 0.0)
                trace['ast_similarity'] = score
                cluster_scores.append(score)

            ast_similarity[cluster_id] = float(sum(cluster_scores) / len(cluster_scores))

        if ast_similarity:
            self.cluster_metadata.setdefault('ast_similarity', {})
            self.cluster_metadata['ast_similarity'].update(ast_similarity)
            self.cluster_metadata['ast_counts'] = ast_counts

        return ast_similarity

    def compute_cluster_neighbor_summary(self, limit=5):
        """Compute and cache nearest cluster IDs for each cluster."""
        if self.distance_matrix is None or self.clusters is None:
            return {}

        neighbors = compute_cluster_neighbors(self.distance_matrix, self.traces, limit=limit)
        if neighbors:
            self.cluster_metadata['cluster_neighbors'] = neighbors
        return neighbors

    def compute_cluster_virustotal_stats(self):
        """Aggregate VirusTotal verdict counts per cluster for reporting."""
        if self.clusters is None:
            return {}

        totals = defaultdict(float)
        coverage = defaultdict(int)
        cluster_sizes = Counter()

        for trace in self.traces:
            cluster_id = trace.get('cluster')
            if cluster_id in (None, -1):
                continue
            cluster_id = int(cluster_id)
            cluster_sizes[cluster_id] += 1

            vt_summary = trace.get('virustotal')
            if not vt_summary:
                continue
            verdict_count = vt_summary.get('verdict_count')
            if verdict_count is None:
                continue
            totals[cluster_id] += float(verdict_count)
            coverage[cluster_id] += 1

        if not coverage:
            return {}

        stats = {}
        for cluster_id, scanned in coverage.items():
            total_traces = cluster_sizes.get(cluster_id, scanned)
            avg = totals[cluster_id] / scanned if scanned else None
            stats[cluster_id] = {
                'average_verdict_count': avg,
                'trace_count_with_verdict': scanned,
                'total_traces': total_traces,
            }

        self.cluster_metadata['virustotal_cluster_stats'] = stats
        return stats

    def analyze_clusters(self):
        """Analyze cluster characteristics"""
        print("\n=== Cluster Analysis ===")

        cluster_analysis = defaultdict(lambda: {
            'scripts': [],
            'event_types': Counter(),
            'capabilities': Counter(),
            'urls': set(),
            'avg_events': 0,
            'suspicious': 0
        })

        for trace in self.traces:
            cluster_id = trace['cluster']
            cluster_analysis[cluster_id]['scripts'].append(trace['trace_id'])
            cluster_analysis[cluster_id]['event_types'].update(trace['event_sequence'])
            cluster_analysis[cluster_id]['capabilities'].update(trace.get('capability_counts', {}))
            cluster_analysis[cluster_id]['urls'].add(trace['script_url'])
            cluster_analysis[cluster_id]['suspicious'] += trace.get('suspicious_event_count', 0)

        # Print analysis
        for cluster_id in sorted(cluster_analysis.keys()):
            cluster = cluster_analysis[cluster_id]
            num_scripts = len(cluster['scripts'])

            # Calculate average events
            cluster_traces = [t for t in self.traces if t['cluster'] == cluster_id]
            avg_events = np.mean([t['num_events'] for t in cluster_traces])

            print(f"\n--- Cluster {cluster_id} ({num_scripts} scripts) ---")
            print(f"Average events per script: {avg_events:.1f}")
            print(f"Unique URLs: {len(cluster['urls'])}")
            print(f"Avg suspicious events: {cluster['suspicious'] / max(num_scripts, 1):.2f}")

            # Top event types in this cluster
            print("Top 5 event types:")
            for event_type, count in cluster['event_types'].most_common(5):
                print(f"  {event_type}: {count}")

            print("Top capabilities:")
            for capability, count in cluster['capabilities'].most_common(5):
                print(f"  {capability}: {count}")

            # Sample URLs
            print("Sample URLs:")
            for url in list(cluster['urls'])[:3]:
                print(f"  {url[:80]}...")

    def save_results(self, output_file='clustering_results.pkl'):
        """Save clustering results"""
        print(f"\n=== Saving Results to {output_file} ===")

        results = {
            'traces': self.traces,
            'sequences': self.sequences,
            'encoded_sequences': self.encoded_sequences,
            'capability_sequences': self.capability_sequences,
            'encoder': self.encoder,
            'distance_matrix': self.distance_matrix,
            'linkage_matrix': self.linkage_matrix,
            'clusters': self.clusters,
            'capability_features': self.capability_features,
            'capability_vocab': self.capability_vocab,
            'capability_clusters': self.capability_clusters,
            'event_types': list(self.encoder.classes_),
            'cluster_metadata': self.cluster_metadata,
            'token_embeddings': self.token_embeddings,
            'embedding_dim': self.embedding_dim,
            'embedding_matrix': self.embedding_matrix,
            'embedding_metadata': self.embedding_metadata,
            'semantic_cost_enabled': self.semantic_cost_enabled,
            'require_ast_preview': self.require_ast_preview,
            'allowed_timestamps': list(self.allowed_timestamp_list) if self.allowed_timestamp_list else None
        }

        with open(output_file, 'wb') as f:
            pickle.dump(results, f)

        print(f"Results saved successfully")

        # Also save traces as JSON for easier inspection
        traces_json = output_file.replace('.pkl', '_traces.json')
        with open(traces_json, 'w') as f:
            json.dump(self.traces, f, indent=2, default=str)
        print(f"Traces saved to {traces_json}")

    @staticmethod
    def load_results(input_file='clustering_results.pkl'):
        """Load saved clustering results"""
        with open(input_file, 'rb') as f:
            results = pickle.load(f)

        clusterer = ScriptClusterer('')
        clusterer.traces = results['traces']
        clusterer.sequences = results['sequences']
        clusterer.encoded_sequences = results.get('encoded_sequences', [])
        clusterer.capability_sequences = results.get('capability_sequences', [])
        clusterer.encoder = results['encoder']
        clusterer.distance_matrix = results['distance_matrix']
        clusterer.linkage_matrix = results.get('linkage_matrix')
        clusterer.clusters = results['clusters']
        clusterer.capability_features = results.get('capability_features')
        clusterer.capability_vocab = results.get('capability_vocab', [])
        clusterer.capability_clusters = results.get('capability_clusters')
        clusterer.cluster_metadata = results.get('cluster_metadata', {})
        clusterer.token_embeddings = results.get('token_embeddings', {})
        clusterer.embedding_dim = results.get('embedding_dim', 0)
        clusterer.embedding_matrix = results.get('embedding_matrix')
        clusterer.embedding_metadata = results.get('embedding_metadata', {})
        clusterer.semantic_cost_enabled = results.get(
            'semantic_cost_enabled',
            bool(clusterer.token_embeddings)
        )
        clusterer.require_ast_preview = results.get('require_ast_preview', False)
        allowed_ts = results.get('allowed_timestamps')
        if allowed_ts:
            clusterer.allowed_timestamp_list = list(allowed_ts)
            clusterer.allowed_timestamps = set(allowed_ts)
        else:
            clusterer.allowed_timestamp_list = None
            clusterer.allowed_timestamps = None

        return clusterer


_DTW_WORKER_CONTEXT = {}


def _init_dtw_worker(sequences, encoded_sequences, max_distance, token_embeddings, lb_window_ratio):
    """Initializer for DTW worker processes."""
    global _DTW_WORKER_CONTEXT
    _DTW_WORKER_CONTEXT = {
        'sequences': sequences,
        'encoded_sequences': encoded_sequences,
        'max_distance': max_distance,
        'token_embeddings': token_embeddings,
        'lb_window_ratio': lb_window_ratio
    }


def _dtw_worker(pairs):
    """Worker function to compute DTW distances for a batch of index pairs."""
    sequences = _DTW_WORKER_CONTEXT['sequences']
    max_distance = _DTW_WORKER_CONTEXT['max_distance']
    token_embeddings = _DTW_WORKER_CONTEXT.get('token_embeddings')
    encoded_sequences = _DTW_WORKER_CONTEXT.get('encoded_sequences')
    lb_ratio = _DTW_WORKER_CONTEXT.get('lb_window_ratio', 0.0)
    lb_enabled = bool(encoded_sequences) and max_distance is not None and lb_ratio > 0.0
    results = []
    pruned = 0
    for i, j in pairs:
        if lb_enabled:
            radius = max(
                1,
                int(max(len(encoded_sequences[i]), len(encoded_sequences[j])) * lb_ratio)
            )
            lower_bound = ScriptClusterer.lb_improved(
                encoded_sequences[i], encoded_sequences[j], radius
            )
            if lower_bound >= max_distance:
                pruned += 1
                results.append((i, j, float(max_distance)))
                continue
        dist = ScriptClusterer.categorical_dtw_distance(sequences[i], sequences[j], token_embeddings)
        if max_distance is not None and dist > max_distance:
            dist = max_distance
        results.append((i, j, dist))
    return results, pruned


_ENCODER_WORKER_CONTEXT = {}


def _init_encoder_worker(token_map):
    """Initializer for sequence encoding workers."""
    global _ENCODER_WORKER_CONTEXT
    _ENCODER_WORKER_CONTEXT = {'token_map': token_map}


def _encode_sequence_worker(sequence):
    """Encode a token sequence using the shared token map."""
    token_map = _ENCODER_WORKER_CONTEXT['token_map']
    return [float(token_map[token]) for token in sequence]


def main():
    """Main execution"""
    import argparse

    parser = argparse.ArgumentParser(description='Cluster JavaScript scripts by CDP event traces')
    parser.add_argument('--data-dir', default='experiment_data',
                        help='Path to experiment data directory')
    parser.add_argument('--max-scripts', type=int, default=None,
                        help='Maximum number of scripts to process (for testing)')
    parser.add_argument('--num-clusters', type=int, default=None,
                        help='[Deprecated] Number of clusters for the legacy hierarchical method')
    parser.add_argument('--min-cluster-size', type=int, default=5,
                        help='Minimum cluster size for HDBSCAN (density-based clustering)')
    parser.add_argument('--min-samples', type=int, default=None,
                        help='Minimum samples for HDBSCAN (defaults to min-cluster-size when omitted)')
    parser.add_argument('--cluster-selection-epsilon', type=float, default=0.0,
                        help='Cluster selection epsilon for HDBSCAN')
    parser.add_argument('--capability-clusters', type=int, default=8,
                        help='Number of capability clusters (bag-of-events view)')
    parser.add_argument('--dtw-workers', type=int, default=None,
                        help='Number of worker processes for DTW computation (default: CPU count - 1)')
    parser.add_argument('--dtw-chunk-size', type=int, default=500,
                        help='Number of pairwise distances per worker batch')
    parser.add_argument('--dtw-max-distance', type=float, default=None,
                        help='Optional cap for DTW distances; enables early abandoning via lower bounds')
    parser.add_argument('--dtw-lb-ratio', type=float, default=0.1,
                        help='Fraction of the sequence length to use as the LB_Keogh window (<=0 disables)')
    parser.add_argument('--sequence-mode', choices=['auto', 'dtw', 'embeddings'], default='auto',
                        help='Select how cluster distances are computed: Doc2Vec embeddings, DTW, or auto fallback.')
    parser.add_argument('--skip-dtw', action='store_true',
                        help='Shortcut for --sequence-mode embeddings (skip DTW entirely).')
    parser.add_argument('--force-dtw', action='store_true',
                        help='Shortcut for --sequence-mode dtw (disable embedding-based clustering).')
    parser.add_argument('--doc2vec-dim', type=int, default=128,
                        help='Dimensionality of Doc2Vec embeddings when sequence-mode uses embeddings.')
    parser.add_argument('--doc2vec-window', type=int, default=5,
                        help='Doc2Vec context window size.')
    parser.add_argument('--doc2vec-min-count', type=int, default=1,
                        help='Minimum token frequency for Doc2Vec vocabulary.')
    parser.add_argument('--doc2vec-epochs', type=int, default=40,
                        help='Training epochs for Doc2Vec.')
    parser.add_argument('--doc2vec-workers', type=int, default=None,
                        help='Worker processes for Doc2Vec (defaults to CPU count - 1).')
    parser.add_argument('--doc2vec-negative', type=int, default=5,
                        help='Negative sampling parameter for Doc2Vec.')
    parser.add_argument('--output', default='clustering_results.pkl',
                        help='Output file for results')
    parser.add_argument('--load', type=str, default=None,
                        help='Load existing results instead of recomputing')
    parser.add_argument('--max-seq-length', type=int, default=2000,
                        help='Maximum length for compressed sequences')
    parser.add_argument('--require-ast-preview', action='store_true',
                        help='Filter traces to those with AST previews available')
    parser.add_argument('--min-suspicious-events', type=int, default=0,
                        help='Drop traces with fewer than this many suspicious events (0 keeps all)')
    parser.add_argument('--timestamp', dest='timestamps', action='append',
                        help='Restrict processing to specific timestamp directories (repeatable)')

    args = parser.parse_args()
    sequence_mode = args.sequence_mode
    if args.skip_dtw:
        sequence_mode = 'embeddings'
    if args.force_dtw:
        sequence_mode = 'dtw'

    if args.load:
        print(f"Loading existing results from {args.load}")
        clusterer = ScriptClusterer.load_results(args.load)
        if clusterer.capability_features is None:
            clusterer.compute_capability_features()
        clusterer.analyze_clusters()
        clusterer.summarize_capability_clusters()
    else:
        # Create clusterer
        clusterer = ScriptClusterer(
            args.data_dir,
            max_sequence_length=args.max_seq_length,
            require_ast_preview=args.require_ast_preview,
            allowed_timestamps=args.timestamps,
            min_suspicious_events=args.min_suspicious_events,
        )

        # Extract traces
        clusterer.extract_traces(max_scripts=args.max_scripts)

        if len(clusterer.traces) == 0:
            print("No traces found. Exiting.")
            return

        # Encode sequences
        clusterer.encode_sequences()

        # Compute capability features
        clusterer.compute_capability_features()
        clusterer.cluster_metadata['sequence_mode_requested'] = sequence_mode

        # Compute embeddings if requested
        embeddings_ready = False
        if sequence_mode in ('auto', 'embeddings'):
            embeddings = clusterer.compute_sequence_embeddings(
                vector_size=args.doc2vec_dim,
                window=args.doc2vec_window,
                min_count=args.doc2vec_min_count,
                epochs=args.doc2vec_epochs,
                workers=args.doc2vec_workers,
                negative=args.doc2vec_negative,
            )
            embeddings_ready = embeddings is not None
            if not embeddings_ready and sequence_mode == 'auto':
                print("Doc2Vec embeddings unavailable; falling back to DTW distances.")

        if sequence_mode == 'embeddings' and not embeddings_ready:
            print("Embeddings-only mode requested but Doc2Vec training failed. Exiting.")
            return

        # Compute DTW distances when needed
        dtw_required = (sequence_mode == 'dtw') or not embeddings_ready
        if dtw_required:
            clusterer.compute_dtw_distances(
                max_distance=args.dtw_max_distance,
                num_workers=args.dtw_workers,
                chunk_size=args.dtw_chunk_size,
                lb_window_ratio=args.dtw_lb_ratio
            )
            clusterer.cluster_metadata['sequence_mode'] = 'dtw'
        else:
            clusterer.cluster_metadata['sequence_mode'] = 'embeddings'
            if clusterer.distance_matrix is None:
                clusterer.compute_embedding_distance_matrix()

        # Perform clustering
        min_cluster_size = args.min_cluster_size
        if args.num_clusters:
            print("WARNING: --num-clusters is deprecated; using it as min_cluster_size for HDBSCAN.")
            min_cluster_size = args.num_clusters

        clusterer.hdbscan_clustering(
            min_cluster_size=min_cluster_size,
            min_samples=args.min_samples,
            cluster_selection_epsilon=args.cluster_selection_epsilon
        )
        clusterer.capability_clustering(num_clusters=args.capability_clusters)

        # Analyze clusters
        clusterer.analyze_clusters()
        clusterer.summarize_capability_clusters()

        # Save results
        clusterer.save_results(args.output)

    print("\n=== Done ===")


if __name__ == '__main__':
    main()
