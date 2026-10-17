"""Bind on-demand task details to the same native task while exports catch up."""
import json

class TaskExportChanging(Exception):
    pass

def stable_json(path):
    before=path.stat();value=json.loads(path.read_bytes());after=path.stat()
    if (before.st_ino,before.st_mtime_ns,before.st_size)!=(after.st_ino,after.st_mtime_ns,after.st_size):
        raise TaskExportChanging('Native export changed during read')
    return value,after.st_mtime_ns

def task_detail(file,payload_file,task_id,expected_revision=None):
    detail,detail_stamp=stable_json(file)
    task=detail.get('task',{})
    if task.get('id')!=task_id:raise ValueError('Task identity mismatch')
    if not expected_revision:return detail
    payload,snapshot_stamp=stable_json(payload_file)
    header=next((t for t in payload.get('tasks',[]) if t.get('id')==task_id),None)
    if not header or header.get('projectionRevision')!=expected_revision:
        raise TaskExportChanging('Task list advanced during request')
    if any(task.get(k)!=header.get(k) for k in ('agent','session','turn')):
        raise ValueError('Native task ownership mismatch')
    if any(any(c.get(k)!=task.get(k) for k in ('agent','session','turn')) for c in detail.get('contexts',[])):
        raise ValueError('Context belongs to a different native task')
    # The native serial exporter writes task details before publishing its list.
    # A later atomic task file can be offered without inventing task attribution.
    # Compare file versions, never task activity timestamps or opaque UUID order.
    if task.get('projectionRevision')!=expected_revision:
        detail['previewTaskExport']={'state':'ahead_of_snapshot' if detail_stamp>snapshot_stamp else 'behind_snapshot',
                                     'snapshotRevision':expected_revision}
    return detail
