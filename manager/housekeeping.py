"""Bound job/log/audit history while preserving active jobs and current drafts."""
import time
from . import store

def prune(days=14):
    cutoff=int(time.time())-days*86400
    with store.connect() as c:
        c.execute("DELETE FROM jobs WHERE status IN ('success','error') AND updated_at<?",(cutoff,))
        c.execute('DELETE FROM telemetry_history WHERE ts<?',(int(time.time())-30*86400,))
        c.execute('DELETE FROM attempts WHERE ts<?',(int(time.time())-900,))
        c.execute('DELETE FROM audit WHERE ts<?',(int(time.time())-90*86400,))
        c.execute('DELETE FROM install_logs WHERE ts<?',(int(time.time())-30*86400,))
        c.execute('DELETE FROM config_versions WHERE id NOT IN (SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY node_id,name ORDER BY id DESC) AS rn FROM config_versions) WHERE rn<=30)')
    return True
