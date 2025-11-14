import json
import csv
from pathlib import Path
from collections import defaultdict

def load_script_ids_from_csv(csv_path):
    script_ids = set()
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            script_ids.add(row['script_id'])
    return script_ids

def process_trace_file(trace_path, csv_path):
    with open(trace_path, 'r') as f:
        events = json.load(f)

    csv_script_ids = load_script_ids_from_csv(csv_path)

    script_info = {}
    for event_obj in events:
        if 'event' not in event_obj:
            continue
        event = event_obj['event']
        if 'method' not in event:
            continue

        if event['method'] == 'Debugger.scriptParsed':
            params = event['params']
            script_id = params['scriptId']
            url = params.get('url', '')

            if script_id in csv_script_ids:
                if url.startswith('chrome://') or url.startswith('chrome-error://'):
                    continue

                if script_id not in script_info:
                    script_info[script_id] = {
                        'url': url,
                        'events': []
                    }

    tracked_script_ids = set(script_info.keys())

    for event_obj in events:
        if 'event' not in event_obj:
            continue
        event = event_obj['event']
        if 'method' not in event:
            continue

        if event['method'] == 'Runtime.consoleAPICalled':
            timestamp = event_obj['timestamp']
            params = event['params']

            stack_trace = params.get('stackTrace', {})
            call_frames = stack_trace.get('callFrames', [])

            target_script_id = None
            for frame in call_frames:
                url = frame.get('url', '')
                if url and not url.startswith('chrome://') and not url.startswith('chrome-error://'):
                    target_script_id = frame.get('scriptId')
                    break

            if target_script_id and target_script_id in tracked_script_ids:
                args_values = []
                for arg in params.get('args', []):
                    if 'value' in arg:
                        value = arg['value']
                        if isinstance(value, str):
                            try:
                                parsed_value = json.loads(value)
                                args_values.append(parsed_value)
                            except (json.JSONDecodeError, ValueError):
                                args_values.append(value)
                        else:
                            args_values.append(value)

                event_entry = {
                    'timestamp': timestamp,
                    'eventType': 'consoleAPI',
                    'consoleType': params.get('type'),
                    'argsValues': args_values
                }

                script_info[target_script_id]['events'].append(event_entry)

        elif event['method'] == 'Network.requestWillBeSent':
            timestamp = event_obj['timestamp']
            params = event['params']

            initiator = params.get('initiator', {})
            stack_trace = initiator.get('stack', {})
            call_frames = stack_trace.get('callFrames', [])

            target_script_id = None
            for frame in call_frames:
                url = frame.get('url', '')
                if url and not url.startswith('chrome://') and not url.startswith('chrome-error://'):
                    target_script_id = frame.get('scriptId')
                    break

            if target_script_id and target_script_id in tracked_script_ids:
                request = params.get('request', {})
                event_entry = {
                    'timestamp': timestamp,
                    'eventType': 'networkRequest',
                    'requestId': params.get('requestId'),
                    'url': request.get('url'),
                    'method': request.get('method'),
                    'type': params.get('type'),
                    'initiatorType': initiator.get('type')
                }

                script_info[target_script_id]['events'].append(event_entry)

    return script_info

def find_all_trace_files(base_dir):
    base_path = Path(base_dir)
    trace_files = []
    for trace_file in base_path.rglob('trace_v2.json'):
        trace_dir = trace_file.parent
        csv_file = trace_dir / 'loaded_js' / 'index.csv'
        if csv_file.exists():
            trace_files.append((trace_file, csv_file, trace_dir))
    return trace_files

def main():
    import sys

    base_dir = '/home/ravindu/compweb/notebooks/2025-11-11/experiment_data'
    force_rerun = '--force' in sys.argv

    trace_files = find_all_trace_files(base_dir)

    print(f"Found {len(trace_files)} trace_v2.json files to process")
    if force_rerun:
        print("Force rerun enabled - will reprocess all files")

    skipped = 0
    processed = 0

    for trace_path, csv_path, output_dir in trace_files:
        output_path = output_dir / 'byscripts.json'

        if output_path.exists() and not force_rerun:
            skipped += 1
            continue

        print(f"Processing: {trace_path}")

        try:
            result = process_trace_file(trace_path, csv_path)

            with open(output_path, 'w') as f:
                json.dump(result, f, indent=2)

            print(f"  Written: {output_path}")
            print(f"  Scripts: {len(result)}")
            total_events = sum(len(info['events']) for info in result.values())
            print(f"  Events: {total_events}")
            processed += 1
        except Exception as e:
            print(f"  Error: {e}")

    print(f"Done! Processed: {processed}, Skipped: {skipped}")

if __name__ == '__main__':
    main()
