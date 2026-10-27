import math
import secrets
import string
import re
import time
import streamlit as st

st.set_page_config(
    page_title="Sentinel Security Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ----------------------------------------------------------------------------
# Styling
# ----------------------------------------------------------------------------
st.markdown(
    """
    <style>
    .stApp {
        background: radial-gradient(circle at 20% 0%, #052e2b 0%, #020617 45%, #041f2e 100%);
    }
    .sentinel-hero {
        padding: 1.5rem 1.75rem;
        border-radius: 1rem;
        background: linear-gradient(135deg, rgba(16,185,129,0.12), rgba(6,182,212,0.06));
        border: 1px solid rgba(16,185,129,0.25);
        margin-bottom: 1.25rem;
    }
    .sentinel-title {
        font-size: 2.4rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: #f8fafc;
        margin: 0;
    }
    .sentinel-sub {
        color: #94a3b8;
        font-size: 0.95rem;
        margin-top: 0.35rem;
    }
    .pill {
        display: inline-block;
        padding: 0.2rem 0.7rem;
        border-radius: 999px;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        background: rgba(16,185,129,0.15);
        color: #6ee7b7;
        border: 1px solid rgba(16,185,129,0.35);
    }
    .metric-card {
        padding: 1rem 1.1rem;
        border-radius: 0.9rem;
        background: rgba(15,23,42,0.75);
        border: 1px solid rgba(51,65,85,0.7);
    }
    .finding {
        padding: 0.7rem 0.9rem;
        border-radius: 0.7rem;
        background: rgba(2,6,23,0.7);
        border: 1px solid rgba(51,65,85,0.7);
        margin-bottom: 0.5rem;
    }
    .sev-critical { color: #fda4af; border-color: rgba(244,63,94,0.5) !important; }
    .sev-high     { color: #fdba74; border-color: rgba(249,115,22,0.5) !important; }
    .sev-medium   { color: #fcd34d; border-color: rgba(245,158,11,0.5) !important; }
    .sev-low      { color: #7dd3fc; border-color: rgba(14,165,233,0.5) !important; }
    code.pw {
        font-size: 1.05rem;
        color: #67e8f9;
        word-break: break-all;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ----------------------------------------------------------------------------
# Session state
# ----------------------------------------------------------------------------
if "posture" not in st.session_state:
    st.session_state.posture = 72
if "nodes" not in st.session_state:
    st.session_state.nodes = [
        {"id": "n1", "name": "edge-gateway", "kind": "edge", "exposure": 18, "patched": True},
        {"id": "n2", "name": "web-frontend", "kind": "web", "exposure": 42, "patched": True},
        {"id": "n3", "name": "auth-api", "kind": "api", "exposure": 67, "patched": False},
        {"id": "n4", "name": "primary-db", "kind": "db", "exposure": 88, "patched": False},
        {"id": "n5", "name": "billing-api", "kind": "api", "exposure": 55, "patched": True},
    ]

# ----------------------------------------------------------------------------
# Signature engine
# ----------------------------------------------------------------------------
SIGNATURES = [
    (re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*\S+", re.I), "Hardcoded credential", "critical",
     "Plaintext secret assignment detected."),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key", "critical",
     "Exposed AWS access key identifier."),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "JWT token", "high",
     "Signed token may leak claims."),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "IP address", "low",
     "Internal or external host reference."),
    (re.compile(r"(?:api[_-]?key|secret|token)\s*[:=]\s*\S+", re.I), "API key / secret", "high",
     "Sensitive key material in payload."),
    (re.compile(r"<script\b[^>]*>", re.I), "Script injection", "high",
     "Possible XSS vector in input."),
    (re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*\b(?:FROM|INTO|WHERE)\b", re.I), "SQL statement", "medium",
     "Raw SQL fragment — check for injection."),
    (re.compile(r"\b(?:eval|exec|system)\s*\(", re.I), "Dangerous call", "high",
     "Code execution primitive detected."),
]

SEV_PENALTY = {"critical": 18, "high": 12, "medium": 6, "low": 2}
SEV_RISK = {"critical": 40, "high": 25, "medium": 12, "low": 5}

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def scan_payload(text: str):
    findings = []
    for pattern, label, severity, detail in SIGNATURES:
        if pattern.search(text):
            findings.append({"label": label, "severity": severity, "detail": detail})
    return findings


def entropy_bits(length: int, pool: int) -> int:
    if pool <= 1:
        return 0
    return round(length * math.log2(pool))


def crack_time(bits: int) -> str:
    guesses_per_sec = 1e11
    seconds = (2 ** bits) / guesses_per_sec
    if seconds < 1:
        return "instant"
    if seconds < 60:
        return f"{round(seconds)} sec"
    if seconds < 3600:
        return f"{round(seconds / 60)} min"
    if seconds < 86400:
        return f"{round(seconds / 3600)} hr"
    if seconds < 3.15e7:
        return f"{round(seconds / 86400)} days"
    if seconds < 3.15e10:
        return f"{round(seconds / 3.15e7)} yrs"
    return "centuries+"


def generate_password(length: int, opts: dict) -> str:
    sets = {
        "lower": string.ascii_lowercase,
        "upper": string.ascii_uppercase,
        "digits": string.digits,
        "symbols": "!@#$%^&*()-_=+[]{};:,.?/",
    }
    pool = "".join(sets[k] for k, on in opts.items() if on)
    if not pool:
        return ""
    return "".join(secrets.choice(pool) for _ in range(length))


KIND_COLORS = {
    "edge": "#38bdf8",
    "web": "#34d399",
    "api": "#fbbf24",
    "db": "#fb7185",
}

# ----------------------------------------------------------------------------
# Header
# ----------------------------------------------------------------------------
st.markdown(
    """
    <div class="sentinel-hero">
        <span class="pill">Sentinel v2.4 · Live</span>
        <h1 class="sentinel-title">🛡️ Sentinel Security Console</h1>
        <p class="sentinel-sub">
            A unified threat-analysis workstation: scan indicators of compromise, forge
            cryptographic credentials, and map your live attack surface.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ----------------------------------------------------------------------------
# Sidebar — posture
# ----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🎯 Posture Score")
    st.metric("Security Posture", f"{st.session_state.posture} / 100")
    st.progress(st.session_state.posture / 100)
    if st.session_state.posture > 80:
        st.success("Hardened")
    elif st.session_state.posture > 60:
        st.warning("Moderate risk")
    else:
        st.error("Critical exposure")
    st.divider()
    st.caption("All analysis runs locally. No telemetry · No network egress.")

# ----------------------------------------------------------------------------
# Tabs
# ----------------------------------------------------------------------------
tab_scan, tab_forge, tab_surface = st.tabs(
    ["🔍 Threat Scanner", "🔐 Password Forge", "🌐 Attack Surface"]
)

# ---------------------------- Threat Scanner --------------------------------
with tab_scan:
    col_in, col_out = st.columns([3, 2], gap="large")

    with col_in:
        st.subheader("Indicator of Compromise Scanner")
        st.caption("Paste logs, config, or payloads. Sentinel matches against 8 heuristic signatures.")
        payload = st.text_area(
            "Payload",
            height=240,
            placeholder="db_password = 'hunter2'\napi_key: sk_live_9f2...\n<script>alert(1)</script>",
            label_visibility="collapsed",
        )
        c1, c2, c3 = st.columns([1, 1, 2])
        run = c1.button("Run Deep Scan", type="primary", use_container_width=True)
        clear = c2.button("Clear", use_container_width=True)
        c3.caption(f"{len(payload)} chars")

        if clear:
            st.session_state.pop("scan_result", None)
            st.rerun()

        if run:
            if not payload.strip():
                st.warning("Provide a payload to scan.")
            else:
                with st.spinner("Scanning payload against signature set…"):
                    time.sleep(0.6)
                    findings = scan_payload(payload)
                st.session_state.scan_result = findings
                penalty = sum(SEV_PENALTY[f["severity"]] for f in findings)
                st.session_state.posture = max(5, 90 - penalty)

    with col_out:
        st.subheader("Analysis Result")
        findings = st.session_state.get("scan_result")

        if findings is None:
            st.info("No scan yet. Submit a payload to begin.")
        elif not findings:
            st.success("Clean — no signatures matched. Payload appears benign.")
        else:
            risk = min(100, sum(SEV_RISK[f["severity"]] for f in findings))
            st.error(f"⚠️ {len(findings)} indicator(s) detected")
            st.progress(risk / 100)
            for f in findings:
                st.markdown(
                    f'<div class="finding sev-{f["severity"]}">'
                    f'<strong>{f["label"]}</strong> '
                    f'<span style="opacity:0.75;font-size:0.8rem;">· {f["severity"]}</span>'
                    f'<div style="color:#94a3b8;font-size:0.8rem;margin-top:0.25rem;">{f["detail"]}</div>'
                    f"</div>",
                    unsafe_allow_html=True,
                )

# ---------------------------- Password Forge --------------------------------
with tab_forge:
    col_cfg, col_an = st.columns([3, 2], gap="large")

    with col_cfg:
        st.subheader("Cryptographic Password Forge")
        st.caption("Uses Python's `secrets` CSPRNG — never `random`.")

        length = st.slider("Length", min_value=8, max_value=64, value=20)

        o1, o2 = st.columns(2)
        with o1:
            lower = st.checkbox("Lowercase a-z", value=True)
            digits = st.checkbox("Digits 0-9", value=True)
        with o2:
            upper = st.checkbox("Uppercase A-Z", value=True)
            symbols = st.checkbox("Symbols !@#", value=True)

        opts = {"lower": lower, "upper": upper, "digits": digits, "symbols": symbols}

        if "pw_seed" not in st.session_state:
            st.session_state.pw_seed = 0

        if st.button("🔄 Regenerate", use_container_width=True):
            st.session_state.pw_seed += 1

        password = generate_password(length, opts)

        if password:
            st.markdown(
                f'<div class="finding" style="border-color:rgba(6,182,212,0.4);">'
                f'<code class="pw">{password}</code></div>',
                unsafe_allow_html=True,
            )
            st.code(password, language=None)
        else:
            st.warning("Enable at least one character set.")

    with col_an:
        st.subheader("Strength Analysis")
        sets = {
            "lower": string.ascii_lowercase,
            "upper": string.ascii_uppercase,
            "digits": string.digits,
            "symbols": "!@#$%^&*()-_=+[]{};:,.?/",
        }
        pool_size = sum(len(sets[k]) for k, on in opts.items() if on)
        bits = entropy_bits(length, pool_size)
        strength = min(100, round((bits / 128) * 100))

        if bits >= 100:
            label, tone = "Fortress", "normal"
        elif bits >= 70:
            label, tone = "Strong", "normal"
        elif bits >= 45:
            label, tone = "Fair", "off"
        else:
            label, tone = "Weak", "inverse"

        st.metric("Entropy", f"{bits} bits")
        st.progress(strength / 100)
        st.write(f"**Verdict:** {label}")
        st.write(f"**Character pool:** `{pool_size}`")
        st.write(f"**Brute-force @ 1e11/s:** `{crack_time(bits)}`")

        if st.button("Commit to Posture Score", type="primary", use_container_width=True):
            st.session_state.posture = min(100, 40 + round(bits / 2))
            st.rerun()

# ---------------------------- Attack Surface --------------------------------
with tab_surface:
    col_map, col_sum = st.columns([3, 2], gap="large")

    with col_map:
        st.subheader("Live Attack Surface")
        st.caption("Each node exposes an attack vector. Patch to reduce exposure.")

        for node in st.session_state.nodes:
            color = KIND_COLORS[node["kind"]]
            status = "🔒 patched" if node["patched"] else "🔓 open"
            c1, c2, c3 = st.columns([4, 2, 1])
            with c1:
                st.markdown(
                    f'<div style="font-family:monospace;color:#e2e8f0;">'
                    f'<span style="color:{color};">●</span> {node["name"]} '
                    f'<span style="color:#64748b;font-size:0.75rem;">[{node["kind"]}]</span> '
                    f'<span style="color:#94a3b8;font-size:0.75rem;">{status}</span></div>',
                    unsafe_allow_html=True,
                )
                st.progress(node["exposure"] / 100)
            with c2:
                st.caption(f"exposure {node['exposure']}%")
            with c3:
                if not node["patched"]:
                    if st.button("Patch", key=f"patch_{node['id']}", use_container_width=True):
                        for n in st.session_state.nodes:
                            if n["id"] == node["id"]:
                                n["patched"] = True
                                n["exposure"] = max(5, n["exposure"] - 30)
                        avg = sum(n["exposure"] for n in st.session_state.nodes) / len(st.session_state.nodes)
                        st.session_state.posture = round(100 - avg)
                        st.rerun()
                else:
                    st.button("Patched", key=f"done_{node['id']}", disabled=True, use_container_width=True)

    with col_sum:
        st.subheader("Surface Summary")
        nodes = st.session_state.nodes
        avg_exposure = round(sum(n["exposure"] for n in nodes) / len(nodes))
        open_count = sum(1 for n in nodes if not n["patched"])

        st.metric("Avg Exposure", f"{avg_exposure}%")
        m1, m2 = st.columns(2)
        m1.metric("Unpatched", open_count)
        m2.metric("Total Nodes", len(nodes))

        lateral = "High" if avg_exposure > 60 else "Medium" if avg_exposure > 30 else "Low"
        st.write(f"**Lateral risk:** {lateral}")
        st.write(f"**Critical paths:** {3 if open_count > 1 else open_count}")

        if st.button("Reset Topology", use_container_width=True):
            st.session_state.nodes = [
                {"id": "n1", "name": "edge-gateway", "kind": "edge", "exposure": 18, "patched": True},
                {"id": "n2", "name": "web-frontend", "kind": "web", "exposure": 42, "patched": True},
                {"id": "n3", "name": "auth-api", "kind": "api", "exposure": 67, "patched": False},
                {"id": "n4", "name": "primary-db", "kind": "db", "exposure": 88, "patched": False},
                {"id": "n5", "name": "billing-api", "kind": "api", "exposure": 55, "patched": True},
            ]
            st.session_state.posture = 72
            st.rerun()

# ----------------------------------------------------------------------------
# Footer
# ----------------------------------------------------------------------------
st.divider()
st.caption("🖥️ Sentinel Security Console — runs entirely in-process. No external calls.")