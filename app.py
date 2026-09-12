from pathlib import Path
import hashlib
import os
import threading
import uuid

import streamlit as st

from engine import Job, Settings, SafetyError

ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get('TL_HASH_DATA_DIR', str(ROOT)))
st.set_page_config(page_title='ThreatLocker • Hash Manager', page_icon='🛡️', layout='wide')


@st.cache_resource
def controller():
    # One local operator/job across browser tabs. Refresh cannot start duplicate workers.
    return {'job': None, 'digest': None, 'lock': threading.RLock()}


control = controller()
job = control['job']
busy = bool(job and job.active)
st.title('ThreatLocker Hash Manager')
st.caption('Application-scoped hash deletion · Windows & macOS · Selective and bulk workflows')

with st.sidebar:
    st.header('Connection')
    org = st.text_input('Organization ID', placeholder='Organization UUID', disabled=busy).strip().lower()
    token = st.text_input('Authorization', type='password', help='Paste the exact Authorization header value. Kept in process memory only.', disabled=busy).strip()
    left, right = st.columns(2)
    instance = left.text_input('API instance', value='d', max_chars=1, disabled=busy).strip().lower()
    user_instance = right.text_input('UserInstance', value='D', max_chars=1, disabled=busy).strip()
    st.caption(f'Endpoint: https://portalapi.{instance or "…"}.threatlocker.com/portalApi')
    st.divider()
    st.header('Performance')
    mode = st.selectbox('Lookup strategy', ['Selective', 'Bulk'], disabled=busy,
                        help='Selective searches each requested hash within its application. Bulk scans each application once and matches locally.')
    workers = st.slider('Concurrent requests', 1, 16, 6, disabled=busy)
    page_size = st.selectbox('Bulk page size', [100, 1000, 5000, 10000], index=1, disabled=busy)
    timeout = st.slider('Read timeout (seconds)', 10, 120, 60, disabled=busy)
    st.info('Use Selective for a small subset of a large application. Use Bulk for tens of thousands of hashes. Start with 6 workers.')
    st.caption('Local single-operator app. Do not expose this server publicly. Authorization is never written to run files.')

cfg = Settings(org, token, instance, user_instance, workers, mode, page_size, timeout)
st.subheader('1 · Import your deletion list')
upload = st.file_uploader('CSV file', type=['csv'], disabled=busy,
                          help='Required: ApplicationId, Hash, OsType. Optional: RecordType. Maximum 512 MB.')
st.caption('OsType: 1 = Windows, 2 = macOS. RecordType: HASH or SHA256ONLY. Each application is checked against the organization and OS before any deletion.')
st.download_button('Download CSV template',
                   'ApplicationId,Hash,OsType,RecordType\n00000000-0000-0000-0000-000000000001,' + 'A'*64 + ',2,SHA256ONLY\n',
                   'hash-deletion-template.csv', 'text/csv')
digest = hashlib.sha256(upload.getbuffer()).hexdigest() if upload else None
if upload:
    st.caption(f'{upload.name} · {upload.size / 1024 / 1024:.2f} MB')

if st.button('Validate connection & build dry-run preview', type='primary', disabled=busy or upload is None):
    try:
        cfg.validate()
        with control['lock']:
            if control['job'] and control['job'].active:
                raise SafetyError('Another job is already running.')
            run_dir = DATA_ROOT / 'runs' / uuid.uuid4().hex
            new_job = Job(cfg, run_dir)
            with (run_dir / 'input.csv').open('wb') as f:
                f.write(upload.getbuffer())
            control['job'] = new_job
            control['digest'] = digest
            new_job.start()
        st.rerun()
    except SafetyError as e:
        st.error(str(e))

st.subheader('2 · Review & execute')
st.warning('Live deletion changes application definitions and may affect policy behavior. It is not automatically reversible. This app only deletes exact hash-only records; it never deletes applications or policies.')
if job and not job.active and job.phase == 'Ready':
    apps, rows = job.preview()
    st.dataframe(apps, hide_index=True, width='stretch')
    with st.expander('Exact targets — first 100 records'):
        st.dataframe(rows, hide_index=True, width='stretch')
    snap = job.snapshot()
    st.write(f"{snap.get('planned', 0):,} exact records planned; {snap.get('unmatched', 0):,} requested hashes without a matching hash-only record; {snap.get('duplicates', 0):,} duplicate CSV rows removed.")
    st.caption('If a hash has multiple exact hash-only records within the named application, all matching record IDs are included. Unmatched hashes are skipped. Preview expires after 30 minutes.')
    required = f"DELETE {snap.get('planned', 0)}"
    confirmation = st.text_input(f'Type {required} to authorize these exact records', key=f'confirm_{job.directory.name}')
    same = cfg == job.cfg and digest == control['digest']
    if not same:
        st.info('Connection settings or CSV changed. Build a new dry-run preview before executing.')
    if st.button('Execute verified deletion plan', disabled=confirmation != required or not same or not snap.get('planned'), type='primary'):
        try:
            with control['lock']:
                job.start(execute=True)
            st.rerun()
        except SafetyError as e:
            st.error(str(e))

st.subheader('3 · Run monitor & audit')


@st.fragment(run_every='2s')
def monitor():
    current = control['job']
    if not current:
        st.info('Upload a CSV and build a dry-run preview to begin. No live requests have been sent.')
        return
    snap = current.snapshot()
    st.write(f"**{snap['phase']}** — {snap['message']}")
    cols = st.columns(4)
    cols[0].metric('Planned records', f"{snap.get('planned', 0):,}")
    cols[1].metric('Requests accepted', f"{snap.get('accepted', 0):,}")
    cols[2].metric('Verified absent', f"{snap.get('verified', 0):,}")
    cols[3].metric('Phase elapsed', f"{snap['elapsed']:.0f}s")
    if snap.get('planned') and 'sent' in snap:
        st.progress(min(1.0, snap['sent']/snap['planned']), text=f"{snap['sent']:,} / {snap['planned']:,} requests finished")
    st.caption(f"CSV rows: {snap.get('rows', 0):,} · API rows inspected: {snap.get('scanned', 0):,}")
    if current.active:
        st.caption('Closing the browser does not stop the server job. Use Stop; in-flight requests finish and dispatched deletions are verified.')
        if st.button('Stop submitting new requests', disabled=current.stop.is_set() or snap['phase'] == 'Verifying'):
            current.stop.set()
            st.rerun(scope='fragment')
    else:
        # Redraw confirmation/settings after a background phase completes.
        marker = (current.directory.name, current.phase)
        if st.session_state.get('rendered_phase') != marker:
            st.session_state['rendered_phase'] = marker
            st.rerun()
        for filename, label, mime in [('results.csv', 'Download exact-record results', 'text/csv'),
                                     ('summary.json', 'Download run summary', 'application/json')]:
            path = current.directory / filename
            if path.exists():
                with path.open('rb') as f:
                    st.download_button(label, f, file_name=f'{current.directory.name}-{filename}', mime=mime)
        st.caption(f'Local audit directory: {current.directory}')
        if snap['phase'] in ('Failed', 'Stopped / review required'):
            st.error('Review the audit before retrying. Build a fresh dry run; uncertain POSTs are never automatically replayed.')


monitor()
