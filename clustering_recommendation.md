# Clustering JavaScript Scripts by CDP Event Traces

## Data Structure Analysis

### Current Structure
```
experiment_data/
├── <hash>/                          # URL hash
│   └── <timestamp>/                 # Execution timestamp
│       └── byscripts.json           # Events grouped by script
```

**byscripts.json format:**
```json
{
  "script_id": {
    "url": "https://example.com/script.js",
    "events": [
      {
        "timestamp": "2025-11-12T11:06:45.616697",
        "eventType": "consoleAPI",
        "consoleType": "log",
        "argsValues": [
          {
            "type": "Object.defineProperty Called",
            "objectType": "function",
            "property": "BROWSER_MAP",
            "hasGetter": true,
            "hasSetter": false,
            ...
          }
        ]
      }
    ]
  }
}
```

### Event Types Observed

**Top-level events:**
- `consoleAPI` - Instrumented API calls (majority)
- `networkRequest` - Network activity
- `Script` - Script loading events
- `XHR` - XMLHttpRequest events

**Nested event types** (in `argsValues[0].type`):
1. `DOM Property Read` (most common)
2. `Object.defineProperty Called`
3. `Event Listener Added`
4. `Timeout (Function) Set`
5. `DOM Mutation`
6. `Cookie Update`
7. `setAttribute Called`
8. `Cookie Read`
9. `Script Src Set`
10. `XHR Request`
11. `Interval (Function) Set`
12. `JSON.parse Suspicious Payload`
13. `Fetch Request`

---

## Recommended Clustering Algorithms for Temporal Behavior

### 1. **Dynamic Time Warping (DTW) + HDBSCAN** ⭐ CURRENT DEFAULT

**Why this works best:**
- **Preserves temporal order**: DTW aligns sequences of different lengths while respecting event order
- **Handles variable script lengths**: Scripts may execute different numbers of events
- **Captures behavioral patterns**: Similar scripts (e.g., analytics, ads) will have similar event sequences even if timing differs
- **Density-based grouping**: HDBSCAN adapts to arbitrary shapes, auto-determines cluster counts, and labels noise/outliers
- **Interpretable hierarchy**: HDBSCAN exposes a condensed tree for drilling into sub-clusters when needed

**Implementation approach:**
```python
from dtaidistance import dtw
import hdbscan
import numpy as np

# 1. Encode event sequences as numeric vectors
# 2. Compute DTW distance matrix between all script pairs
# 3. Feed the dense distance matrix to HDBSCAN (metric='precomputed')
# 4. Inspect HDBSCAN labels (-1 == noise) and condensed tree for hierarchy
```

**Event encoding strategies:**
- **Option A**: One-hot encode event types (13 categories)
- **Option B**: Create composite features combining event type + metadata (hasGetter, hasSetter, etc.)
- **Option C**: Hash categorical properties for dimensionality reduction

---

### 2. **Time-Weighted Sequence Similarity + DBSCAN**

**Why this works:**
- **Density-based**: Finds clusters of arbitrary shape without pre-specifying cluster count
- **Handles outliers**: Malicious/rare scripts won't force bad clusters
- **Time-aware**: Weight events by relative timestamp position in execution

**Implementation approach:**
```python
from sklearn.cluster import DBSCAN
import numpy as np

# 1. Create time-weighted sequence embeddings
# 2. Use custom distance metric (DTW or edit distance)
# 3. Apply DBSCAN with appropriate eps and min_samples
```

**Temporal weighting:**
```
event_weight = base_feature * (1 / (1 + alpha * relative_time))
```
Early events get higher weight (initialization patterns matter more)

---

### 3. **Recurrent Neural Networks (LSTM/GRU) + K-Means on Embeddings**

**Why this works:**
- **Learns temporal dependencies**: RNNs naturally model sequential data
- **Rich embeddings**: Hidden states capture complex behavioral patterns
- **Scalable**: Once trained, generates embeddings quickly

**Implementation approach:**
```python
from tensorflow.keras.layers import LSTM, Dense
from tensorflow.keras.models import Model
from sklearn.cluster import KMeans

# 1. Train seq2seq autoencoder on event sequences
# 2. Extract bottleneck layer embeddings
# 3. Apply K-Means on embeddings
```

**Pros**: Best for large-scale datasets (1000+ scripts)
**Cons**: Requires more data, less interpretable

---

### 4. **N-gram Language Models + TF-IDF + K-Means**

**Why this works:**
- **Treat events as "words"**: Leverage NLP techniques
- **Captures event patterns**: N-grams preserve local temporal structure
- **Simple and fast**: No complex distance calculations

**Implementation approach:**
```python
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

# 1. Convert event sequences to "sentences"
#    e.g., "DOM_Read Object_Define Event_Listener ..."
# 2. Create bigrams/trigrams for temporal context
# 3. Apply TF-IDF vectorization
# 4. Cluster with K-Means or Agglomerative Clustering
```

**Event sequence as text:**
```
"DOM_Read DOM_Read Object_Define Event_Listener Timeout_Set DOM_Read Cookie_Update"
```

---

## Feature Engineering Recommendations

### Core Features to Extract

1. **Event Type Sequence**
   - Primary event type (consoleAPI, networkRequest, etc.)
   - Nested type (DOM Property Read, Object.defineProperty, etc.)
   - Combined type: `f"{eventType}:{argsValues[0].type}"`

2. **Temporal Features**
   - Event timestamps (relative to script start)
   - Inter-event time deltas
   - Event rate (events/second)
   - Burst patterns (sudden event clusters)

3. **Event Metadata** (from argsValues)
   - `hasGetter`, `hasSetter` (property access patterns)
   - `configurable`, `enumerable` (object manipulation)
   - `property` names (e.g., "BROWSER_MAP", "ENGINE_MAP")
   - `object` types (e.g., "document", "window")

4. **Statistical Features**
   - Event type frequency distribution
   - Unique event types count
   - Sequence length
   - Entropy of event distribution

5. **Higher-Order Patterns**
   - N-grams (event pairs, triples)
   - Frequent subsequences (e.g., "DOM Read → Object.defineProperty")
   - Event transitions matrix (Markov chain probabilities)

---

## Data Extraction Pipeline

### Step 1: Parse and Extract
```python
import json
import hashlib
from pathlib import Path
from datetime import datetime

def extract_script_traces(experiment_data_dir):
    traces = []

    for byscripts_file in Path(experiment_data_dir).rglob('byscripts.json'):
        # Extract metadata from path
        parts = byscripts_file.parts
        url_hash = parts[-3]
        timestamp = parts[-2]

        with open(byscripts_file) as f:
            data = json.load(f)

        for script_id, script_data in data.items():
            trace = {
                'url_hash': url_hash,
                'timestamp': timestamp,
                'script_id': script_id,
                'script_url': script_data['url'],
                'events': script_data['events'],
                # Derived identifier
                'trace_id': f"{url_hash}_{timestamp}_{script_id}"
            }
            traces.append(trace)

    return traces
```

### Step 2: Create Event Sequences
```python
def create_event_sequence(events):
    """Convert CDP events to sequence representation"""
    sequence = []

    for event in events:
        # Get top-level event type
        event_type = event.get('eventType', 'unknown')

        # Get nested type if exists
        if 'argsValues' in event and len(event['argsValues']) > 0:
            arg = event['argsValues'][0]
            if isinstance(arg, dict) and 'type' in arg:
                nested_type = arg['type']
                combined_type = f"{event_type}:{nested_type}"
            else:
                combined_type = event_type
        else:
            combined_type = event_type

        # Extract timestamp
        timestamp = event.get('timestamp')

        sequence.append({
            'type': combined_type,
            'timestamp': timestamp,
            'metadata': extract_event_metadata(event)
        })

    return sequence

def extract_event_metadata(event):
    """Extract relevant metadata from event"""
    metadata = {}

    if 'argsValues' in event and len(event['argsValues']) > 0:
        arg = event['argsValues'][0]
        if isinstance(arg, dict):
            # Extract boolean flags
            for key in ['hasGetter', 'hasSetter', 'configurable', 'enumerable']:
                if key in arg:
                    metadata[key] = arg[key]

            # Extract categorical fields
            for key in ['objectType', 'property', 'object']:
                if key in arg:
                    metadata[key] = arg[key]

    return metadata
```

### Step 3: Encode for Clustering
```python
from sklearn.preprocessing import LabelEncoder

def encode_event_sequence(sequence, max_length=500):
    """Convert event sequence to numeric representation"""

    # Create event type vocabulary
    event_types = [event['type'] for event in sequence]

    # Encode as integers
    encoder = LabelEncoder()
    encoded = encoder.fit_transform(event_types)

    # Pad/truncate to fixed length
    if len(encoded) < max_length:
        encoded = np.pad(encoded, (0, max_length - len(encoded)), 'constant', constant_values=-1)
    else:
        encoded = encoded[:max_length]

    return encoded, encoder

# Alternative: Create feature vector
def create_feature_vector(sequence):
    """Create statistical feature vector"""
    from collections import Counter

    event_types = [event['type'] for event in sequence]
    type_counts = Counter(event_types)

    # Statistical features
    features = {
        'sequence_length': len(sequence),
        'unique_events': len(set(event_types)),
        'entropy': calculate_entropy(event_types),
        # Event type frequencies
        **{f"count_{etype}": type_counts.get(etype, 0)
           for etype in ALL_EVENT_TYPES},
        # Temporal features
        'avg_event_rate': calculate_event_rate(sequence),
        'has_network_activity': any('XHR' in e['type'] or 'Fetch' in e['type']
                                     for e in sequence),
        'has_dom_mutation': any('DOM Mutation' in e['type'] for e in sequence),
        'has_cookie_access': any('Cookie' in e['type'] for e in sequence),
    }

    return features
```

---

## Implementation Recommendation

### **Best Approach for Your Use Case:**

**DTW + Hierarchical Clustering** because:

1. ✅ You have temporal event sequences (order matters)
2. ✅ Scripts have variable lengths (DTW handles this)
3. ✅ You want to discover behavioral groups (ads, analytics, tracking, etc.)
4. ✅ Interpretability is important (dendrogram shows relationships)
5. ✅ Dataset size seems moderate (< 10,000 scripts per run)

### Quick Start Code

```python
import numpy as np
from dtaidistance import dtw
from scipy.cluster.hierarchy import linkage, dendrogram, fcluster
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt

# 1. Load and encode sequences
traces = extract_script_traces('experiment_data/')
sequences = []
script_urls = []

encoder = LabelEncoder()
all_events = []
for trace in traces:
    seq = create_event_sequence(trace['events'])
    all_events.extend([e['type'] for e in seq])

encoder.fit(all_events)

for trace in traces:
    seq = create_event_sequence(trace['events'])
    encoded = [encoder.transform([e['type']])[0] for e in seq]
    sequences.append(np.array(encoded, dtype=float))
    script_urls.append(trace['script_url'])

# 2. Compute DTW distance matrix
n = len(sequences)
distance_matrix = np.zeros((n, n))

for i in range(n):
    for j in range(i+1, n):
        dist = dtw.distance(sequences[i], sequences[j])
        distance_matrix[i, j] = dist
        distance_matrix[j, i] = dist

# 3. Hierarchical clustering
condensed_dist = squareform(distance_matrix)
linkage_matrix = linkage(condensed_dist, method='ward')

# 4. Visualize dendrogram
plt.figure(figsize=(15, 8))
dendrogram(linkage_matrix, labels=script_urls, leaf_rotation=90)
plt.tight_layout()
plt.savefig('script_clusters_dendrogram.png', dpi=300)

# 5. Cut into clusters
num_clusters = 10  # Adjust based on dendrogram
clusters = fcluster(linkage_matrix, num_clusters, criterion='maxclust')

# 6. Analyze clusters
for cluster_id in range(1, num_clusters + 1):
    cluster_indices = np.where(clusters == cluster_id)[0]
    print(f"\nCluster {cluster_id} ({len(cluster_indices)} scripts):")
    for idx in cluster_indices[:5]:  # Show first 5
        print(f"  - {script_urls[idx]}")
```

---

## Evaluation Metrics

### Internal Metrics (no ground truth needed)
- **Silhouette Score**: How well-separated clusters are
- **Davies-Bouldin Index**: Ratio of within-cluster to between-cluster distances
- **Calinski-Harabasz Score**: Ratio of between-cluster to within-cluster variance

### Domain-Specific Metrics
- **URL domain clustering**: Scripts from same domain should cluster together
- **Known script categories**: Manually label some scripts (ads, analytics, social) and check cluster purity
- **Behavioral coherence**: Scripts in same cluster should have similar purposes

---

## Advanced Considerations

### 1. **Multi-View Clustering**
Combine multiple representations:
- Event sequence similarity (DTW)
- URL domain similarity (Levenshtein distance)
- Statistical feature similarity (Euclidean distance)

### 2. **Time Series Clustering**
If analyzing script evolution over time:
- Use `timestamp` folder as time axis
- Apply time series clustering (k-Shape, TADPole)

### 3. **Ensemble Clustering**
Run multiple algorithms and combine:
- DTW + Hierarchical
- N-gram + K-Means
- LSTM embeddings + DBSCAN
- Use consensus clustering to merge results

### 4. **Dimensionality Reduction**
Before clustering, reduce feature space:
- **PCA**: Linear dimensionality reduction
- **t-SNE**: Nonlinear, good for visualization
- **UMAP**: Faster than t-SNE, preserves global structure

---

## Expected Cluster Types

Based on the event types observed, you'll likely find clusters for:

1. **Analytics Scripts** (Google Analytics, etc.)
   - High `DOM Property Read`, `Cookie Read/Update`
   - Network requests (XHR, Fetch)

2. **Advertising Scripts**
   - `Object.defineProperty` patterns
   - `Script Src Set` (dynamic script injection)
   - Frequent `DOM Mutation`

3. **Tracking/Fingerprinting**
   - Extensive `DOM Property Read`
   - Browser detection patterns (`BROWSER_MAP`, `ENGINE_MAP`, `OS_MAP`)

4. **UI/Interactive Scripts**
   - Heavy `Event Listener Added`
   - `Timeout/Interval Set`
   - `DOM Mutation`

5. **Utility Libraries** (jQuery, etc.)
   - Massive `DOM Property Read`
   - `Object.defineProperty` for internal setup

6. **Social Media Widgets**
   - Mixed network activity
   - `Cookie` access
   - `iframe` manipulation

---

## Next Steps

1. **Implement extraction pipeline** to process all byscripts.json files
2. **Start with DTW + Hierarchical clustering** on a sample dataset
3. **Visualize and validate** clusters using dendrograms
4. **Iterate on features** - add metadata if event types alone aren't discriminative enough
5. **Scale up** to full dataset once approach is validated
6. **Document cluster characteristics** for interpretability
