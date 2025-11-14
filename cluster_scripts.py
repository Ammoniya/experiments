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
import re
import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict, Counter
from urllib.parse import urlparse, parse_qs
from sklearn.preprocessing import LabelEncoder
import hdbscan
from multiprocessing import Pool, cpu_count
import pickle
from tqdm import tqdm

CAPABILITY_EXACT_MAP = {
    'XHR Request': 'NET_XHR',
    'XHR Response': 'NET_XHR',
    'Fetch Request': 'NET_FETCH',
    'Fetch Response': 'NET_FETCH',
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
    'Object.defineProperty Called': 'HOOKING',
    'Eval Call': 'OBFUSCATION',
    'Function Constructor': 'OBFUSCATION',
    'atob De-obfuscation': 'OBFUSCATION',
    'String.fromCharCode De-obfuscation': 'OBFUSCATION',
    'JSON.parse Suspicious Payload': 'OBFUSCATION'
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
    'WebSocket Connection',
    'WebSocket Send',
    'WebSocket Receive (onmessage)',
    'WebSocket Receive (addEventListener)',
    'Network.requestWillBeSent',
    'Network.responseReceived',
    'Script Src Set',
    'IFrame Src Set',
    'Image Src Set',
    'Link Href Set',
    'Form Submitted'
}

WP_VERSION_PARAM_KEYS = (
    'ver', 'version', 'ao_version', 'v', 'wpv', 'tver', 'plugin_ver'
)

WP_PLUGIN_PATTERN = re.compile(r"/wp-content/plugins/([^/]+)/", re.IGNORECASE)
WP_THEME_PATTERN = re.compile(r"/wp-content/themes/([^/]+)/", re.IGNORECASE)


class ScriptClusterer:
    """Cluster JavaScript scripts based on CDP event traces"""

    def __init__(self, experiment_data_dir, max_sequence_length=2000):
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

    @staticmethod
    def get_event_argument(event):
        args_values = event.get('argsValues') or []
        if args_values:
            arg = args_values[0]
            if isinstance(arg, dict):
                return arg
        return {}

    @staticmethod
    def should_filter_event(event):
        arg = ScriptClusterer.get_event_argument(event)
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

        suffix = domain.split('.')[-2:] if '.' in domain else [domain]
        suffix_str = '.'.join(suffix)

        if any(domain.endswith(ad) for ad in AD_DOMAIN_SUFFIXES):
            return 'domain:ad'
        if any(domain.endswith(analytics) for analytics in ANALYTICS_DOMAIN_SUFFIXES):
            return 'domain:analytics'
        if script_domain and domain == script_domain:
            return 'domain:script-origin'

        return f"domain:{suffix_str}"

    @staticmethod
    def extract_url_from_arg(arg):
        if not isinstance(arg, dict):
            return None
        for key in ('url', 'requestUrl', 'documentURL', 'src', 'href', 'location', 'action', 'scriptURL'):
            value = arg.get(key)
            if isinstance(value, str) and value:
                return value
        return None

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
        elif base_type in NETWORK_EVENT_TYPES:
            url = self.extract_url_from_arg(arg)
            bucket = self.categorize_url(url, script_domain)
            if bucket:
                parts.append(bucket)
        elif 'object' in arg or 'property' in arg:
            obj = arg.get('object')
            prop = arg.get('property')
            if obj:
                parts.append(str(obj))
            if prop:
                parts.append(str(prop))

        return "|".join(parts)

    def parse_event(self, event, trace_context=None):
        """Return token, base type, capability and target metadata for an event."""
        arg = self.get_event_argument(event)
        base_type = arg.get('type') or event.get('eventType')
        if not base_type:
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
    def categorical_dtw_distance(seq_a, seq_b):
        """Compute DTW distance with 0/1 cost for categorical tokens."""
        if not seq_a and not seq_b:
            return 0.0
        if not seq_a:
            return float(len(seq_b))
        if not seq_b:
            return float(len(seq_a))

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
                if token_a == token_b:
                    cost = 0.0
                else:
                    weight_a = ScriptClusterer.token_weight(token_a)
                    weight_b = ScriptClusterer.token_weight(token_b)
                    cost = max(weight_a, weight_b)
                curr[j] = cost + min(
                    curr[j - 1],    # insertion
                    prev[j],        # deletion
                    prev[j - 1]     # match/substitution
                )
            prev, curr = curr, prev

        return prev[len_b]

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

    def extract_traces(self, max_scripts=None):
        """Extract event traces from all byscripts.json files"""
        print("\n=== Extracting Event Traces ===")

        byscripts_files = list(self.experiment_data_dir.rglob('byscripts.json'))
        print(f"Found {len(byscripts_files)} byscripts.json files")

        for byscripts_file in tqdm(byscripts_files, desc="Processing files"):
            try:
                # Extract metadata from path
                parts = byscripts_file.parts
                url_hash = parts[-3]
                timestamp = parts[-2]

                # Load script metadata
                metadata_map = self.load_script_metadata(url_hash, timestamp)
                fingerprint = self.load_fingerprint(url_hash, timestamp)

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
                        if self.should_filter_event(event):
                            continue

                        parsed = self.parse_event(event, trace_context)
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
                        'page_url': fingerprint.get('url')
                    }

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
            print(f"Vocabulary size: {len(self.encoder.classes_)}")
            self.encoded_sequences = [
                self.encoder.transform(seq).astype(float) for seq in self.sequences
            ]
        else:
            print("No events found to encode.")
            self.encoded_sequences = []

        print(f"Prepared {len(self.sequences)} compressed sequences")

        # Print sequence length statistics
        if self.sequences:
            lengths = [len(seq) for seq in self.sequences]
            print(f"Compressed sequence lengths - Min: {min(lengths)}, Max: {max(lengths)}, Mean: {np.mean(lengths):.1f}")

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

    def compute_dtw_distances(self, max_distance=None, num_workers=None, chunk_size=500):
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

        if num_workers == 1:
            print("Multi-processing disabled (worker count = 1).")
            with tqdm(total=total_pairs, desc="Computing distances") as pbar:
                for chunk in chunk_generator():
                    for i, j in chunk:
                        dist = self.categorical_dtw_distance(self.sequences[i], self.sequences[j])
                        if max_distance and dist > max_distance:
                            dist = max_distance
                        self.distance_matrix[i, j] = dist
                        self.distance_matrix[j, i] = dist
                    pbar.update(len(chunk))
        else:
            with Pool(processes=num_workers, initializer=_init_dtw_worker,
                      initargs=(self.sequences, max_distance)) as pool:
                with tqdm(total=total_pairs, desc="Computing distances") as pbar:
                    for chunk_result in pool.imap_unordered(_dtw_worker, chunk_generator()):
                        for i, j, dist in chunk_result:
                            self.distance_matrix[i, j] = dist
                            self.distance_matrix[j, i] = dist
                        pbar.update(len(chunk_result))

        np.fill_diagonal(self.distance_matrix, 0.0)
        print(f"Distance matrix shape: {self.distance_matrix.shape}")
        print(f"Distance range: [{self.distance_matrix.min():.2f}, {self.distance_matrix.max():.2f}]")
        print(f"Mean distance: {self.distance_matrix.mean():.2f}")

    def hdbscan_clustering(self, min_cluster_size=5, min_samples=None, cluster_selection_epsilon=0.0):
        """Cluster traces using HDBSCAN over the DTW distance matrix."""
        if self.distance_matrix is None:
            raise ValueError("Distance matrix has not been computed. Run compute_dtw_distances() first.")

        print("\n=== HDBSCAN Clustering ===")
        print(f"Min cluster size: {min_cluster_size}")
        if min_samples is not None:
            print(f"Min samples: {min_samples}")
        if cluster_selection_epsilon:
            print(f"Cluster selection epsilon: {cluster_selection_epsilon}")

        clusterer = hdbscan.HDBSCAN(
            metric='precomputed',
            min_cluster_size=min_cluster_size,
            min_samples=min_samples,
            cluster_selection_epsilon=cluster_selection_epsilon
        )

        raw_labels = clusterer.fit_predict(self.distance_matrix)

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
            'method': 'hdbscan',
            'min_cluster_size': min_cluster_size,
            'min_samples': min_samples,
            'cluster_selection_epsilon': cluster_selection_epsilon,
            'raw_labels': raw_labels.tolist()
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

        return self.clusters

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
            'cluster_metadata': self.cluster_metadata
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

        return clusterer


_DTW_WORKER_CONTEXT = {}


def _init_dtw_worker(sequences, max_distance):
    """Initializer for DTW worker processes."""
    global _DTW_WORKER_CONTEXT
    _DTW_WORKER_CONTEXT = {
        'sequences': sequences,
        'max_distance': max_distance
    }


def _dtw_worker(pairs):
    """Worker function to compute DTW distances for a batch of index pairs."""
    sequences = _DTW_WORKER_CONTEXT['sequences']
    max_distance = _DTW_WORKER_CONTEXT['max_distance']
    results = []
    for i, j in pairs:
        dist = ScriptClusterer.categorical_dtw_distance(sequences[i], sequences[j])
        if max_distance and dist > max_distance:
            dist = max_distance
        results.append((i, j, dist))
    return results


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
    parser.add_argument('--output', default='clustering_results.pkl',
                        help='Output file for results')
    parser.add_argument('--load', type=str, default=None,
                        help='Load existing results instead of recomputing')
    parser.add_argument('--max-seq-length', type=int, default=2000,
                        help='Maximum length for compressed sequences')

    args = parser.parse_args()

    if args.load:
        print(f"Loading existing results from {args.load}")
        clusterer = ScriptClusterer.load_results(args.load)
        if clusterer.capability_features is None:
            clusterer.compute_capability_features()
        clusterer.analyze_clusters()
        clusterer.summarize_capability_clusters()
    else:
        # Create clusterer
        clusterer = ScriptClusterer(args.data_dir, max_sequence_length=args.max_seq_length)

        # Extract traces
        clusterer.extract_traces(max_scripts=args.max_scripts)

        if len(clusterer.traces) == 0:
            print("No traces found. Exiting.")
            return

        # Encode sequences
        clusterer.encode_sequences()

        # Compute capability features
        clusterer.compute_capability_features()

        # Compute DTW distances
        clusterer.compute_dtw_distances(
            num_workers=args.dtw_workers,
            chunk_size=args.dtw_chunk_size
        )

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
