#!/usr/bin/env python3
"""
Interactive Dash visualization for script clustering results
Features:
- 3D scatter plot of clusters (t-SNE)
- Click on points to view trace details
- Display JavaScript code snippets
- Show event sequence timeline
"""

import hashlib
import json
import os
import pickle
import sys
import types
from collections import Counter, defaultdict
from pathlib import Path

os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

import numpy as np
import pandas as pd

TSNE_PERPLEXITY = max(2, int(os.environ.get("TSNE_PERPLEXITY", "30")))
TSNE_RANDOM_STATE = int(os.environ.get("TSNE_RANDOM_STATE", "42"))


def _running_inside_ipykernel():
    """Best-effort detection for notebook environments."""
    try:
        from IPython import get_ipython  # type: ignore

        shell = get_ipython()
        if shell is None:
            return False

        return shell.__class__.__name__ == "ZMQInteractiveShell"
    except Exception:
        return False


def _install_comm_stub():
    """Provide a stub comm module so Dash skips Jupyter-only pathways."""

    class _DashDummyComm:
        def send(self, *args, **kwargs):
            pass

        def close(self):
            pass

    comm_stub = types.ModuleType("comm")

    def _create_comm(*args, **kwargs):
        return _DashDummyComm()

    comm_stub.create_comm = _create_comm  # type: ignore[attr-defined]
    sys.modules["comm"] = comm_stub


if os.environ.get("DISABLE_DASH_JUPYTER_COMM", "1") != "0" and not _running_inside_ipykernel():
    _install_comm_stub()


import dash
from dash import Input, Output, State, callback_context, dcc, html
import plotly.express as px
import plotly.graph_objects as go
from sklearn.manifold import TSNE


class ClusterVisualizer:
    """Interactive visualization for clustering results"""

    def __init__(self, results_file, experiment_data_dir):
        self.results_file = results_file
        self.experiment_data_dir = Path(experiment_data_dir)

        # Load results
        print("Loading clustering results...")
        with open(results_file, 'rb') as f:
            results = pickle.load(f)

        self.traces = results['traces']
        self.sequences = results['sequences']
        self.encoder = results['encoder']
        self.distance_matrix = results['distance_matrix']
        self.linkage_matrix = results.get('linkage_matrix')
        self.clusters = results['clusters']
        self.event_types = results.get('event_types', list(self.encoder.classes_))
        self.cluster_metadata = results.get('cluster_metadata', {}) or {}
        self.silhouette_lookup = self.cluster_metadata.get('silhouette_per_cluster', {}) or {}
        self.overall_silhouette = self.cluster_metadata.get('silhouette_overall')
        self.ast_similarity_lookup = self.cluster_metadata.get('ast_similarity', {}) or {}
        self.ast_counts_lookup = self.cluster_metadata.get('ast_counts', {}) or {}

        print(f"Loaded {len(self.traces)} traces with {len(self.event_types)} event types")

        # Compute 3D embeddings for scatter plot
        self.embeddings = None
        self.embedding_method = None
        self.compute_embeddings()

        # Create DataFrame for easier manipulation
        self.df = self.create_dataframe()
        self.cluster_wp_cache = {}

    def compute_embeddings(self):
        """Compute 3D embeddings for visualization (t-SNE only, with fallback)."""
        print("Computing 3D embeddings...")
        n_components = 3
        n_samples = len(self.traces)

        if n_samples < 3:
            print("Not enough samples for t-SNE; using force-directed layout.")
            self.embeddings = self._force_layout(self.distance_matrix, n_components)
            self.embedding_method = "Force Layout"
            print(f"Embeddings (Force Layout) shape: {self.embeddings.shape}")
            return

        perplexity = min(TSNE_PERPLEXITY, n_samples - 1)
        print(f"Using t-SNE (perplexity={perplexity}, random_state={TSNE_RANDOM_STATE})...")
        try:
            tsne = TSNE(
                n_components=n_components,
                metric='precomputed',
                random_state=TSNE_RANDOM_STATE,
                perplexity=perplexity,
                init='random'
            )
            self.embeddings = tsne.fit_transform(self.distance_matrix)
            method = "t-SNE"
        except Exception as exc:  # noqa: BLE001
            print(f"t-SNE failed ({exc}). Falling back to stochastic force-directed layout.")
            self.embeddings = self._force_layout(self.distance_matrix, n_components)
            method = "Force Layout"

        self.embedding_method = method
        print(f"Embeddings ({method}) shape: {self.embeddings.shape}")

    def create_dataframe(self):
        """Create DataFrame with all trace information"""
        data = []

        for i, trace in enumerate(self.traces):
            # Extract domain from URL
            url = trace['script_url']
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
            except:
                domain = 'unknown'

            coords = self.embeddings[i] if self.embeddings is not None else np.zeros(3)

            data.append({
                'trace_id': trace['trace_id'],
                'x': coords[0],
                'y': coords[1],
                'z': coords[2] if len(coords) > 2 else 0.0,
                'cluster': trace['cluster'],
                'cluster_similarity': self.get_cluster_silhouette(trace.get('cluster')),
                'silhouette_score': trace.get('silhouette_score'),
                'ast_similarity': trace.get('ast_similarity'),
                'has_ast': bool(trace.get('ast_unit_vector')),
                'script_url': url,
                'page_url': trace.get('page_url'),
                'domain': domain,
                'num_events': trace['num_events'],
                'url_hash': trace['url_hash'],
                'timestamp': trace['timestamp'],
                'script_id': trace['script_id'],
                'file_name': trace.get('file_name', 'unknown'),
                'index': i  # For easy lookup
            })

        return pd.DataFrame(data)

    @staticmethod
    def _format_wp_label(item):
        if not isinstance(item, dict):
            return None
        name = item.get('name')
        if not name:
            return None
        version = item.get('version')
        if version:
            return f"{name} ({version})"
        return name

    def get_cluster_wp_distribution(self, cluster_id):
        """Return cached plugin/theme counters for a cluster."""
        if cluster_id is None:
            return Counter(), Counter()

        if cluster_id in self.cluster_wp_cache:
            return self.cluster_wp_cache[cluster_id]

        plugin_counter = Counter()
        theme_counter = Counter()

        for trace in self.traces:
            if trace.get('cluster') != cluster_id:
                continue
            for item in trace.get('wordpress_plugins', []):
                label = self._format_wp_label(item)
                if label:
                    plugin_counter[label] += 1
            for item in trace.get('wordpress_themes', []):
                label = self._format_wp_label(item)
                if label:
                    theme_counter[label] += 1

        self.cluster_wp_cache[cluster_id] = (plugin_counter, theme_counter)
        return plugin_counter, theme_counter

    @staticmethod
    def _random_pair(rng, size):
        """Sample two distinct indices."""
        i = int(rng.integers(0, size))
        j = int(rng.integers(0, size - 1))
        if j >= i:
            j += 1
        return i, j

    @staticmethod
    def _force_layout(distance_matrix, n_components=2):
        """Lightweight force-directed layout that avoids heavy linear algebra."""
        n_samples = distance_matrix.shape[0]
        if n_samples == 0:
            return np.zeros((0, n_components))
        if n_samples == 1:
            return np.zeros((1, n_components))

        rng = np.random.default_rng(42)
        coords = rng.normal(scale=0.01, size=(n_samples, n_components))

        if n_samples <= 30:
            pair_indices = [(i, j) for i in range(n_samples)
                            for j in range(i + 1, n_samples)]
            batch_size = len(pair_indices)
        else:
            pair_indices = None
            batch_size = min(2000, max(1, n_samples * (n_samples - 1) // 2))

        iterations = min(600, max(200, 10 * n_samples))
        learning_rate = 0.05

        for _ in range(iterations):
            forces = np.zeros_like(coords)
            if pair_indices is not None:
                iterable = pair_indices
                current_batch = batch_size
            else:
                iterable = (ClusterVisualizer._random_pair(rng, n_samples)
                            for _ in range(batch_size))
                current_batch = batch_size

            count = 0
            for i, j in iterable:
                count += 1
                target = float(distance_matrix[i, j])
                delta = coords[i] - coords[j]
                current = float(np.sqrt((delta ** 2).sum()) + 1e-9)
                if target <= 1e-9 and current <= 1e-9:
                    continue

                weight = 1.0 / (1.0 + target)
                adjustment = (current - target) * weight
                grad = adjustment * (delta / current)

                forces[i] += grad
                forces[j] -= grad

            if count == 0:
                break

            coords -= (learning_rate / current_batch) * forces
            coords -= coords.mean(axis=0, keepdims=True)
            learning_rate *= 0.995

        return coords

    def load_js_code(self, trace):
        """Load JavaScript code plus preview/hash metadata for a trace."""
        url_hash = trace['url_hash']
        timestamp = trace['timestamp']
        file_name = trace.get('file_name')

        artifacts = {
            'code': None,
            'preview': None,
            'hash': None,
            'path': None,
            'error': None
        }

        if not file_name:
            artifacts['error'] = "No file name recorded for this trace."
            return artifacts

        js_path = self.experiment_data_dir / url_hash / timestamp / 'loaded_js' / file_name
        artifacts['path'] = str(js_path)

        if not js_path.exists():
            artifacts['error'] = "JavaScript file not found on disk."
            return artifacts

        try:
            raw_bytes = js_path.read_bytes()
        except Exception as exc:  # noqa: BLE001
            artifacts['error'] = f"Error reading code: {exc}"
            return artifacts

        artifacts['hash'] = hashlib.sha256(raw_bytes).hexdigest()

        code_text = raw_bytes.decode('utf-8', errors='replace')
        if len(code_text) > 50000:
            display_code = code_text[:50000] + "\n\n... (truncated) ..."
        else:
            display_code = code_text

        lines = code_text.splitlines()
        preview_len = min(20, len(lines))
        preview = "\n".join(lines[:preview_len])
        if len(lines) > preview_len:
            preview += "\n... (more lines below) ..."

        artifacts['code'] = display_code or "(file is empty)"
        artifacts['preview'] = preview or "(file is empty)"

        return artifacts

    def get_trace_by_id(self, trace_id):
        """Get trace by trace_id"""
        for trace in self.traces:
            if trace['trace_id'] == trace_id:
                return trace
        return None

    def get_cluster_ast_similarity(self, cluster_id):
        if cluster_id is None:
            return None
        return self.ast_similarity_lookup.get(cluster_id)

    def get_cluster_silhouette(self, cluster_id):
        """Return stored silhouette average for a cluster"""
        if cluster_id is None:
            return None
        return self.silhouette_lookup.get(cluster_id)

    def create_app(self):
        """Create Dash application"""
        app = dash.Dash(__name__)

        # Color palette for clusters
        colors = px.colors.qualitative.Plotly + px.colors.qualitative.Set2 + px.colors.qualitative.Dark24

        app.layout = html.Div([
            html.H1("JavaScript Script Clustering - Interactive Visualization",
                    style={'textAlign': 'center', 'marginBottom': 20}),

            html.Div([
                # Left panel: Scatter plot
                html.Div([
                    html.H3("Cluster Visualization"),
                    html.Div([
                        html.Label("Color by:"),
                        dcc.Dropdown(
                            id='color-by',
                            options=[
                                {'label': 'Cluster', 'value': 'cluster'},
                                {'label': 'Domain', 'value': 'domain'},
                                {'label': 'Number of Events', 'value': 'num_events'}
                            ],
                            value='cluster',
                            style={'width': '200px', 'display': 'inline-block', 'marginLeft': 10}
                        ),
                        html.Label("Point size:", style={'marginLeft': 20}),
                        dcc.Slider(
                            id='point-size',
                            min=3,
                            max=15,
                            step=1,
                            value=8,
                            marks={i: str(i) for i in range(3, 16, 3)},
                            tooltip={"placement": "bottom", "always_visible": False}
                        )
                    ], style={'marginBottom': 10}),

                    dcc.Graph(
                        id='cluster-scatter',
                        style={'height': '600px'},
                        config={'displayModeBar': True}
                    ),

                    html.Div([
                        html.Strong("Instructions: "),
                        html.Span("Click on any point to view trace details, event sequence, and JavaScript code. "),
                        html.Span("Use the legend to toggle or isolate clusters (double-click focuses on one).")
                    ], style={'marginTop': 10, 'padding': 10, 'backgroundColor': '#f0f0f0', 'borderRadius': 5})
                ], style={'width': '48%', 'display': 'inline-block', 'verticalAlign': 'top', 'padding': 10}),

                # Right panel: Details
                html.Div([
                    html.H3("Script Details"),
                    html.Div(id='script-details', style={
                        'padding': 10,
                        'backgroundColor': '#f9f9f9',
                        'borderRadius': 5
                    })
                ], style={'width': '48%', 'display': 'inline-block', 'verticalAlign': 'top', 'padding': 10})
            ]),

            # Store for selected trace
            dcc.Store(id='selected-trace-id')
        ], style={'fontFamily': 'Arial, sans-serif', 'padding': 20})

        @app.callback(
            Output('cluster-scatter', 'figure'),
            [Input('color-by', 'value'),
             Input('point-size', 'value')]
        )
        def update_scatter(color_by, point_size):
            """Update scatter plot"""
            df = self.df.copy()

            # Create hover text
            df['hover_text'] = df.apply(
                lambda row: f"<b>{row['domain']}</b><br>" +
                            f"Cluster: {row['cluster']}<br>" +
                            (f"Avg similarity: {row['cluster_similarity']:.3f}<br>"
                             if pd.notna(row['cluster_similarity']) else "") +
                            (f"AST similarity: {row['ast_similarity']:.3f}<br>"
                             if pd.notna(row['ast_similarity']) else "AST similarity: n/a<br>") +
                            f"Events: {row['num_events']}<br>" +
                            f"Script ID: {row['script_id']}<br>" +
                            f"URL: {row['script_url'][:60]}...",
                axis=1
            )

            axis_base = self.embedding_method or "t-SNE"

            if color_by == 'cluster':
                fig = go.Figure()
                for i, cluster in enumerate(sorted(df['cluster'].unique())):
                    cluster_df = df[df['cluster'] == cluster]
                    fig.add_trace(
                        go.Scatter3d(
                            x=cluster_df['x'],
                            y=cluster_df['y'],
                            z=cluster_df['z'],
                            mode='markers',
                            name=f"Cluster {cluster}",
                            marker=dict(
                                color=colors[i % len(colors)],
                                size=point_size,
                                line=dict(width=0.5, color='white')
                            ),
                            text=cluster_df['hover_text'],
                            hovertemplate="%{text}<extra></extra>",
                            customdata=cluster_df[['trace_id']].to_numpy()
                        )
                    )

                fig.update_layout(
                    title=f'Script Clusters (n={len(df)})',
                    legend=dict(
                        title='Clusters',
                        bgcolor='rgba(255,255,255,0.7)',
                        bordercolor='rgba(0,0,0,0.1)',
                        borderwidth=1,
                        itemsizing='constant'
                    )
                )

            elif color_by == 'domain':
                # Limit number of domains shown
                top_domains = df['domain'].value_counts().head(10).index.tolist()
                df['domain_display'] = df['domain'].apply(
                    lambda x: x if x in top_domains else 'Other'
                )

                fig = px.scatter_3d(
                    df,
                    x='x',
                    y='y',
                    z='z',
                    color='domain_display',
                    hover_data={'x': False, 'y': False, 'z': False, 'domain_display': True, 'trace_id': False},
                    custom_data=['trace_id'],
                    title=f'Scripts by Domain (n={len(df)})',
                    labels={'domain_display': 'Domain'}
                )

            else:  # num_events
                fig = px.scatter_3d(
                    df,
                    x='x',
                    y='y',
                    z='z',
                    color='num_events',
                    hover_data={'x': False, 'y': False, 'z': False, 'num_events': True, 'trace_id': False},
                    custom_data=['trace_id'],
                    color_continuous_scale='Viridis',
                    title=f'Scripts by Number of Events (n={len(df)})',
                    labels={'num_events': '# Events'}
                )

            if color_by != 'cluster':
                fig.update_traces(
                    marker=dict(size=point_size, line=dict(width=0.5, color='white')),
                    hovertemplate='%{customdata[0]}<extra></extra>'
                )

            fig.update_layout(
                scene=dict(
                    xaxis=dict(title=f"{axis_base} 1", gridcolor='lightgray', backgroundcolor='rgba(0,0,0,0)'),
                    yaxis=dict(title=f"{axis_base} 2", gridcolor='lightgray', backgroundcolor='rgba(0,0,0,0)'),
                    zaxis=dict(title=f"{axis_base} 3", gridcolor='lightgray', backgroundcolor='rgba(0,0,0,0)')
                ),
                margin=dict(l=0, r=0, b=0, t=60)
            )

            return fig

        @app.callback(
            Output('script-details', 'children'),
            [Input('cluster-scatter', 'clickData')]
        )
        def display_trace_details(clickData):
            """Display details when point is clicked"""
            if not clickData:
                return html.Div([
                    html.P("Click on a point in the scatter plot to view details", style={'fontStyle': 'italic'})
                ])

            # Get trace_id from clicked point
            trace_id = clickData['points'][0]['customdata'][0]
            trace = self.get_trace_by_id(trace_id)

            if not trace:
                return html.Div([html.P("Trace not found")])

            cluster_similarity = self.get_cluster_silhouette(trace.get('cluster'))
            trace_silhouette = trace.get('silhouette_score')
            cluster_ast_similarity = self.get_cluster_ast_similarity(trace.get('cluster'))
            trace_ast_similarity = trace.get('ast_similarity')
            ast_fingerprint = trace.get('ast_fingerprint') or {}
            ast_preview_text = trace.get('ast_preview')
            ast_parser = ast_fingerprint.get('parser', 'unknown')
            ast_cache_path = ast_fingerprint.get('__cache_path')

            def format_metric(value):
                if value is None:
                    return "n/a"
                try:
                    value = float(value)
                except (TypeError, ValueError):
                    return "n/a"
                if np.isnan(value):
                    return "n/a"
                return f"{value:.3f}"

            # Load JS code artifacts
            js_artifacts = self.load_js_code(trace)
            code_hash = js_artifacts.get('hash')
            code_body = js_artifacts.get('code')
            code_error = js_artifacts.get('error')
            code_location = js_artifacts.get('path')
            raw_events = trace.get('raw_events')

            # Event sequence analysis
            event_counts = Counter(trace['event_sequence'])
            event_sequence_str = ' → '.join(trace['event_sequence'][:20])
            if len(trace['event_sequence']) > 20:
                event_sequence_str += ' → ...'

            wp_plugins = trace.get('wordpress_plugins') or []
            wp_themes = trace.get('wordpress_themes') or []
            cluster_plugin_counts, cluster_theme_counts = self.get_cluster_wp_distribution(trace.get('cluster'))

            def render_wp_items(items, empty_text):
                grouped = defaultdict(Counter)
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    name = item.get('name')
                    if not name:
                        continue
                    version = item.get('version') or 'unspecified'
                    grouped[name][version] += 1

                if not grouped:
                    return html.P(empty_text, style={'fontStyle': 'italic', 'color': '#6b7280'})
                items_ui = []
                for name in sorted(grouped.keys()):
                    version_counter = grouped[name]
                    version_parts = []
                    for version, count in version_counter.most_common():
                        label = version if version and version != 'unspecified' else 'unspecified'
                        if count > 1:
                            version_parts.append(f"{label} ×{count}")
                        else:
                            version_parts.append(label)
                    items_ui.append(
                        html.Li([
                            html.Strong(name),
                            html.Span(f": {', '.join(version_parts)}", style={'fontFamily': 'monospace'})
                        ])
                    )
                return html.Ul(items_ui, style={'marginTop': 8})

            def render_distribution(counter, empty_text):
                if not counter:
                    return html.P(empty_text, style={'fontStyle': 'italic', 'color': '#6b7280'})
                return html.Ul([
                    html.Li(f"{label}: {count} scripts", style={'fontFamily': 'monospace'})
                    for label, count in counter.most_common(8)
                ], style={'marginTop': 8})

            overview_tab = dcc.Tab(
                label="Mission Control",
                value='overview',
                children=[
                    html.Div([
                        html.H4("Metadata", style={'borderBottom': '2px solid #333', 'paddingBottom': 5}),
                        html.Table([
                            html.Tr([html.Td(html.Strong("Trace ID:")), html.Td(trace['trace_id'])]),
                            html.Tr([html.Td(html.Strong("Script ID:")), html.Td(trace['script_id'])]),
                            html.Tr([html.Td(html.Strong("Cluster:")), html.Td(trace['cluster'], style={'color': 'blue', 'fontWeight': 'bold'})]),
                            html.Tr([
                                html.Td(html.Strong("Cluster Avg Similarity:")),
                                html.Td(format_metric(cluster_similarity))
                            ]),
                            html.Tr([
                                html.Td(html.Strong("Trace Silhouette Score:")),
                                html.Td(format_metric(trace_silhouette))
                            ]),
                            html.Tr([
                                html.Td(html.Strong("Cluster AST Similarity:")),
                                html.Td(format_metric(cluster_ast_similarity))
                            ]),
                            html.Tr([
                                html.Td(html.Strong("Trace AST Similarity:")),
                                html.Td(format_metric(trace_ast_similarity))
                            ]),
                            html.Tr([html.Td(html.Strong("Script URL:")), html.Td(trace['script_url'], style={'wordBreak': 'break-all'})]),
                            html.Tr([html.Td(html.Strong("File Name:")), html.Td(trace.get('file_name', 'N/A'))]),
                            html.Tr([html.Td(html.Strong("Number of Events:")), html.Td(trace['num_events'])]),
                            html.Tr([html.Td(html.Strong("URL Hash:")), html.Td(trace['url_hash'])]),
                            html.Tr([html.Td(html.Strong("Page URL:")), html.Td(trace.get('page_url', 'Unavailable'), style={'wordBreak': 'break-all'})]),
                            html.Tr([html.Td(html.Strong("Script SHA256:")), html.Td(code_hash or "Unavailable")]),
                            html.Tr([html.Td(html.Strong("Script Path:")), html.Td(code_location or "Unavailable", style={'wordBreak': 'break-all'})]),
                            html.Tr([html.Td(html.Strong("Timestamp:")), html.Td(trace['timestamp'])]),
                        ], style={'width': '100%', 'marginTop': 10})
                    ], style={'marginBottom': 20}),

                    html.Div([
                        html.H4("Event Sequence (First 20)", style={'borderBottom': '2px solid #333', 'paddingBottom': 5}),
                        html.Div(event_sequence_str, style={
                            'padding': 10,
                            'backgroundColor': '#e8f4f8',
                            'borderRadius': 5,
                            'fontFamily': 'monospace',
                            'fontSize': '12px',
                            'marginTop': 10,
                            'overflowX': 'auto',
                            'whiteSpace': 'nowrap'
                        })
                    ], style={'marginBottom': 20}),

                    html.Div([
                        html.H4("Event Type Distribution", style={'borderBottom': '2px solid #333', 'paddingBottom': 5}),
                        html.Ul([
                            html.Li(f"{event_type}: {count}", style={'fontFamily': 'monospace'})
                            for event_type, count in event_counts.most_common(10)
                        ], style={'marginTop': 10})
                    ], style={'marginBottom': 20}),

                    html.Div([
                        html.H4("WordPress Assets (Trace)", style={'borderBottom': '2px solid #333', 'paddingBottom': 5}),
                        html.Div([
                            html.Div([
                                html.Strong("Plugins"),
                                render_wp_items(wp_plugins, "No plugins detected in WP paths.")
                            ], style={'width': '48%'}),
                            html.Div([
                                html.Strong("Themes"),
                                render_wp_items(wp_themes, "No themes detected in WP paths.")
                            ], style={'width': '48%'})
                        ], style={'display': 'flex', 'gap': '4%', 'marginTop': 10})
                    ], style={'marginBottom': 20}),

                    html.Div([
                        html.H4("Cluster WordPress Distribution", style={'borderBottom': '2px solid #333', 'paddingBottom': 5}),
                        html.Div([
                            html.Div([
                                html.Strong("Plugins"),
                                render_distribution(cluster_plugin_counts, "No plugins observed in this cluster.")
                            ], style={'width': '48%'}),
                            html.Div([
                                html.Strong("Themes"),
                                render_distribution(cluster_theme_counts, "No themes observed in this cluster.")
                            ], style={'width': '48%'})
                        ], style={'display': 'flex', 'gap': '4%', 'marginTop': 10})
                    ], style={'marginBottom': 20}),

                    html.Div([
                        html.H4("AST Fingerprint", style={'borderBottom': '2px solid #333', 'paddingBottom': 5}),
                        html.Div([
                            html.P(f"Nodes: {ast_fingerprint.get('num_nodes', 'n/a')} | "
                                   f"Max depth: {ast_fingerprint.get('max_depth', 'n/a')}",
                                   style={'fontFamily': 'monospace'}),
                            html.P(f"Script hash: {ast_fingerprint.get('script_hash', 'n/a')}",
                                   style={'fontFamily': 'monospace', 'wordBreak': 'break-all'})
                        ], style={'marginTop': 10}),
                        html.Div([
                            html.Strong("Top node types"),
                            html.Ul([
                                html.Li(f"{node}: {count}", style={'fontFamily': 'monospace'})
                                for node, count in sorted(
                                    (ast_fingerprint.get('node_type_counts') or {}).items(),
                                    key=lambda kv: kv[1],
                                    reverse=True
                                )[:8]
                            ]) if ast_fingerprint.get('node_type_counts') else
                            html.P("No AST fingerprint available for this script.",
                                   style={'fontStyle': 'italic', 'color': '#6b7280'})
                        ], style={'marginTop': 10})
                    ], style={'marginBottom': 20}),

                    html.Div([
                        html.H4("Event Timeline", style={'borderBottom': '2px solid #333', 'paddingBottom': 5}),
                        dcc.Graph(
                            figure=self.create_event_timeline(trace),
                            config={'displayModeBar': False},
                            style={'height': '250px'}
                        )
                    ], style={'marginBottom': 20})
                ]
            )

            code_tab = dcc.Tab(
                label="Full Code",
                value='code',
                children=[
                    html.Div([
                        html.H4("JavaScript (text only)", style={'borderBottom': '2px solid #333', 'paddingBottom': 5}),
                        html.Small("Displayed as a raw string to prevent any execution in the browser.", style={'color': '#6b7280'}),
                        html.Pre(
                            code_error or (code_body if code_body else "Code not available"),
                            style={
                                'padding': 12,
                                'backgroundColor': '#1e1e1e',
                                'color': '#d4d4d4',
                                'borderRadius': 6,
                                'fontFamily': 'Consolas, Monaco, monospace',
                                'fontSize': '12px',
                                'marginTop': 10,
                                'maxHeight': '60vh',
                                'overflowY': 'auto',
                                'overflowX': 'auto',
                                'whiteSpace': 'pre'
                            }
                        )
                    ])
                ]
            )

            ast_tab = dcc.Tab(
                label="AST Preview",
                value='ast',
                children=[
                    html.Div([
                        html.H4("Abstract Syntax Tree", style={'borderBottom': '2px solid #333', 'paddingBottom': 5}),
                        html.Small(
                            f"Parser: {ast_parser}" + (f" | Cache: {ast_cache_path}" if ast_cache_path else ""),
                            style={'color': '#6b7280'}
                        ),
                        html.Pre(
                            ast_preview_text or "AST preview not available for this script.",
                            style={
                                'padding': 12,
                                'backgroundColor': '#0b1220',
                                'color': '#e2e8f0',
                                'borderRadius': 6,
                                'fontFamily': 'Consolas, Monaco, monospace',
                                'fontSize': '12px',
                                'marginTop': 10,
                                'maxHeight': '60vh',
                                'overflowY': 'auto',
                                'whiteSpace': 'pre',
                                'lineHeight': '1.4'
                            }
                        )
                    ])
                ]
            )

            events_tab = dcc.Tab(
                label="CDP Events",
                value='cdp',
                children=[
                    html.Div([
                        html.H4("Captured Events", style={'borderBottom': '2px solid #333', 'paddingBottom': 5}),
                        html.Small("Full CDP payload shown as JSON. Rendered as text only.", style={'color': '#6b7280'}),
                        html.Pre(
                            json.dumps(raw_events, indent=2) if raw_events else "Raw CDP events not available for this trace.",
                            style={
                                'padding': 12,
                                'backgroundColor': '#0a0a0a',
                                'color': '#f5f5f5',
                                'borderRadius': 6,
                                'fontFamily': 'Consolas, Monaco, monospace',
                                'fontSize': '12px',
                                'marginTop': 10,
                                'maxHeight': '60vh',
                                'overflowY': 'auto',
                                'whiteSpace': 'pre',
                                'lineHeight': '1.4'
                            }
                        )
                    ])
                ]
            )

            details = html.Div([
                dcc.Tabs(
                    value='overview',
                    children=[overview_tab, code_tab, ast_tab, events_tab],
                    colors={'border': '#d1d5db', 'primary': '#111827', 'background': '#f9fafb'}
                )
            ])

            return details

        return app

    def create_event_timeline(self, trace):
        """Create event timeline visualization"""
        events = trace['event_sequence']
        timestamps = trace.get('timestamp_sequence', [])

        # Create figure
        fig = go.Figure()

        # If we have timestamps, use them
        if timestamps and len(timestamps) == len(events):
            try:
                from datetime import datetime
                # Parse timestamps
                parsed_times = [datetime.fromisoformat(ts) for ts in timestamps]
                # Convert to relative seconds
                start_time = parsed_times[0]
                relative_times = [(t - start_time).total_seconds() for t in parsed_times]

                # Encode event types as numbers
                event_codes = [self.encoder.transform([e])[0] for e in events]

                fig.add_trace(go.Scatter(
                    x=relative_times,
                    y=event_codes,
                    mode='markers',
                    marker=dict(size=6, color=event_codes, colorscale='Viridis'),
                    text=events,
                    hovertemplate='%{text}<br>Time: %{x:.3f}s<extra></extra>'
                ))

                fig.update_layout(
                    xaxis_title="Time (seconds)",
                    yaxis_title="Event Type (encoded)",
                    margin=dict(l=40, r=20, t=20, b=40),
                    plot_bgcolor='white',
                    xaxis=dict(showgrid=True, gridcolor='lightgray'),
                    yaxis=dict(showgrid=True, gridcolor='lightgray')
                )
            except:
                # Fallback to index-based
                event_codes = [self.encoder.transform([e])[0] for e in events]
                fig.add_trace(go.Scatter(
                    x=list(range(len(events))),
                    y=event_codes,
                    mode='markers',
                    marker=dict(size=6, color=event_codes, colorscale='Viridis'),
                    text=events,
                    hovertemplate='%{text}<br>Index: %{x}<extra></extra>'
                ))

                fig.update_layout(
                    xaxis_title="Event Index",
                    yaxis_title="Event Type (encoded)",
                    margin=dict(l=40, r=20, t=20, b=40)
                )
        else:
            # Use event index
            event_codes = [self.encoder.transform([e])[0] for e in events]
            fig.add_trace(go.Scatter(
                x=list(range(len(events))),
                y=event_codes,
                mode='markers',
                marker=dict(size=6, color=event_codes, colorscale='Viridis'),
                text=events,
                hovertemplate='%{text}<br>Index: %{x}<extra></extra>'
            ))

            fig.update_layout(
                xaxis_title="Event Index",
                yaxis_title="Event Type (encoded)",
                margin=dict(l=40, r=20, t=20, b=40),
                plot_bgcolor='white',
                xaxis=dict(showgrid=True, gridcolor='lightgray'),
                yaxis=dict(showgrid=True, gridcolor='lightgray')
            )

        return fig


def main():
    """Main execution"""
    import argparse

    parser = argparse.ArgumentParser(description='Visualize script clustering results')
    parser.add_argument('--results', default='clustering_results.pkl',
                        help='Path to clustering results pickle file')
    parser.add_argument('--data-dir', default='experiment_data',
                        help='Path to experiment data directory')
    parser.add_argument('--port', type=int, default=8050,
                        help='Port for Dash server')
    parser.add_argument('--host', default='127.0.0.1',
                        help='Host for Dash server')
    parser.add_argument('--no-server', action='store_true',
                        help='Build the Dash layout without launching the server')

    args = parser.parse_args()

    # Create visualizer
    visualizer = ClusterVisualizer(args.results, args.data_dir)

    # Create app (even when skipping server so layout can be validated)
    app = visualizer.create_app()

    if args.no_server:
        print("Dash app initialized (--no-server specified). Skipping server launch.")
        return

    print(f"\n{'='*60}")
    print(f"Starting Dash server at http://{args.host}:{args.port}")
    print(f"{'='*60}\n")

    run_kwargs = {'debug': True, 'host': args.host, 'port': args.port}
    try:
        if hasattr(app, 'run'):
            app.run(**run_kwargs)
        else:
            app.run_server(**run_kwargs)
    except PermissionError as exc:
        print(f"Failed to start Dash server (permission error): {exc}")
        print("Your environment may block opening listening sockets. "
              "Run this script on a local machine or pass --no-server.")
        sys.exit(1)
    except OSError as exc:
        print(f"Failed to start Dash server: {exc}")
        print("Run this command manually on a machine that can expose ports:\n"
              f"  python3 visualize_clusters.py --results {args.results} "
              f"--data-dir {args.data_dir}")
        sys.exit(1)


if __name__ == '__main__':
    main()
