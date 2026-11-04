"""
Unit and Contract Verification Suite for static/index.html
Run via: pytest tests/test_ui_static_contract.py -v
"""
import json
import os
import re
import subprocess
import time
from pathlib import Path
import pyotp
import pytest
import requests
from bs4 import BeautifulSoup

INDEX_HTML_PATH = Path("/home/tcus/Desktop/An toan thuong mai dien tu/static/index.html")
EVIDENCE_DIR = Path("/home/tcus/Desktop/An toan thuong mai dien tu/evidence")


@pytest.fixture(scope="module")
def html_content():
    assert INDEX_HTML_PATH.exists(), f"File not found: {INDEX_HTML_PATH}"
    with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture(scope="module")
def soup(html_content):
    return BeautifulSoup(html_content, "html.parser")


def test_case_insensitive_slide_absence(html_content):
    """Verify zero occurrences of the word 'slide' / 'Slide' in static/index.html."""
    matches = re.findall(r"slide", html_content, re.IGNORECASE)
    assert len(matches) == 0, f"Found {len(matches)} occurrences of 'slide': {matches[:5]}"


def test_fastapi_endpoints_accessibility():
    """Verify FastAPI static and evidence endpoints return HTTP 200."""
    endpoints = [
        "http://localhost:8000/static/index.html",
        "http://localhost:8000/evidence/SUMMARY.md",
        "http://localhost:8000/evidence/T1_totp_valid.json",
        "http://localhost:8000/evidence/T2_replay_detected.json",
        "http://localhost:8000/evidence/T3_otp_invalid_expired.json",
        "http://localhost:8000/evidence/T4_session_fixation.json",
        "http://localhost:8000/evidence/T5_rbac_bypass_denied.json",
        "http://localhost:8000/evidence/T6_refund_flow_valid.json",
        "http://localhost:8000/evidence/T7_log_masking.json",
        "http://localhost:8000/evidence/T8_session_revocation.json",
    ]
    for url in endpoints:
        resp = requests.get(url, timeout=5)
        assert resp.status_code == 200, f"Endpoint {url} returned {resp.status_code}"


def test_javascript_syntax_via_node(soup):
    """Extract embedded script tags and verify JavaScript syntax using node -c."""
    scripts = soup.find_all("script")
    inline_scripts = [s for s in scripts if not s.get("src") and (s.string or s.text)]
    assert len(inline_scripts) >= 2, f"Expected at least 2 inline scripts, found {len(inline_scripts)}"

    for idx, s in enumerate(inline_scripts):
        code = (s.string or s.text).encode("utf-8")
        proc = subprocess.run(
            ["node", "-c", "-"],
            input=code,
            capture_output=True,
        )
        assert proc.returncode == 0, (
            f"JavaScript syntax error in inline script {idx}:\n"
            f"Stderr: {proc.stderr.decode('utf-8')}"
        )


def test_totp_engine_mathematical_conformity(html_content):
    """
    Stress-test client-side TOTPEngine against pyotp across 66+ edge-case timestamps:
    - Epoch 0, 1
    - Step rollover boundaries: 29, 30, 31, 59, 60, 61, 89, 90, 91
    - Leap seconds: 1483228799, 1483228800, 1483228801
    - Y2K38 boundary: 2147483647, 2147483648
    - Distant future: 2500000000
    - Multi-step drift offsets: [-60, -30, -1, 0, +1, +30, +60]
    Verifies both pure JS SHA-1 fallback and WebCrypto implementations.
    """
    start = html_content.find("const TOTPEngine = {")
    assert start != -1, "TOTPEngine definition not found in HTML"
    end = html_content.find("};", start) + 2
    totp_engine_code = html_content[start:end]

    test_timestamps = [
        0, 1, 15, 29, 30, 31, 59, 60, 61, 89, 90, 91,
        1483228799, 1483228800, 1483228801,
        1600000000, 1700000000, 1730000000, 1762278000,
        2147483647, 2147483648, 2500000000
    ]
    now = int(time.time())
    for drift in [-60, -30, -1, 0, +1, +30, +60]:
        test_timestamps.append(now + drift)

    secrets = [
        "JBSWY3DPEHPK3PXP",
        "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    ]

    expected = []
    for sec in secrets:
        totp = pyotp.TOTP(sec, digits=6, interval=30)
        for ts in test_timestamps:
            expected.append({"secret": sec, "ts": ts, "code": totp.at(ts)})

    tc_json = json.dumps([{"secret": e["secret"], "ts": e["ts"]} for e in expected])
    runner_js = f"""
{totp_engine_code}
const testCases = {tc_json};

async function run() {{
    const {{ webcrypto }} = require('node:crypto');

    // 1. Pure JS fallback
    global.window = {{ crypto: {{}} }};
    const resFallback = [];
    for (const tc of testCases) {{
        resFallback.push(await TOTPEngine.generateCode(tc.secret, tc.ts));
    }}

    // 2. WebCrypto
    global.window = {{ crypto: webcrypto }};
    const resWebCrypto = [];
    for (const tc of testCases) {{
        resWebCrypto.push(await TOTPEngine.generateCode(tc.secret, tc.ts));
    }}

    console.log(JSON.stringify({{ fallback: resFallback, webcrypto: resWebCrypto }}));
}}
run().catch(err => {{ console.error(err); process.exit(1); }});
"""
    proc = subprocess.run(["node", "-e", runner_js], capture_output=True, text=True)
    assert proc.returncode == 0, f"Node script failed: {proc.stderr}"

    data = json.loads(proc.stdout)
    fallback_res = data["fallback"]
    webcrypto_res = data["webcrypto"]

    for idx, e in enumerate(expected):
        assert fallback_res[idx] == e["code"], (
            f"Pure JS mismatch for secret {e['secret']} at ts {e['ts']}: "
            f"got {fallback_res[idx]}, expected {e['code']}"
        )
        assert webcrypto_res[idx] == e["code"], (
            f"WebCrypto mismatch for secret {e['secret']} at ts {e['ts']}: "
            f"got {webcrypto_res[idx]}, expected {e['code']}"
        )


def test_dom_elements_across_modules(soup):
    """Verify presence and attributes of DOM elements across all functional modules."""
    # 1. Auth Modal & 2FA Forms
    assert soup.find(id="btnOpenAuthModal") is not None
    assert soup.find(id="authModal") is not None
    assert soup.find(id="step1Form") is not None
    assert soup.find(id="step2Form") is not None
    assert soup.find(id="loginUsername") is not None
    assert soup.find(id="loginPassword") is not None
    assert soup.find(id="mfaOtpCode") is not None
    assert soup.find(id="btnSubmitStep1") is not None
    assert soup.find(id="btnSubmitStep2") is not None

    # Auto TOTP generation button (has onclick='autoGenerateTotpCode()')
    auto_totp_btn = soup.find(lambda tag: tag.name == "button" and "autoGenerateTotpCode()" in tag.get("onclick", ""))
    assert auto_totp_btn is not None, "Auto TOTP generation button missing from Step 2 view"

    # 2. Storefront
    assert soup.find(id="page-store") is not None
    assert soup.find(id="productsGrid") is not None
    assert soup.find(id="tabBtn-store") is not None

    # 3. CSKH Workspace & Refund Modal
    assert soup.find(id="page-cskh") is not None
    assert soup.find(id="ordersTableBody") is not None
    assert soup.find(id="cskhRefundsTableBody") is not None
    assert soup.find(id="tabBtn-cskh") is not None
    assert soup.find(id="refundModal") is not None
    assert soup.find(id="refundForm") is not None
    assert soup.find(id="modalOrderId") is not None
    assert soup.find(id="modalCustomerName") is not None
    assert soup.find(id="modalAmount") is not None
    assert soup.find(id="modalPan") is not None
    assert soup.find(id="modalCvv") is not None
    assert soup.find(id="modalMaskPreview") is not None
    assert soup.find(id="btnSubmitRefund") is not None

    # SoD Alert Modal
    assert soup.find(id="sodAlertModal") is not None
    assert soup.find(id="sodModalMessage") is not None

    # 4. Kế toán Workspace
    assert soup.find(id="page-ketoan") is not None
    assert soup.find(id="ketoanRefundsTableBody") is not None
    assert soup.find(id="tabBtn-ketoan") is not None

    # 5. Admin Workspace & SIEM & Test Suite & Evidence
    assert soup.find(id="page-admin") is not None
    assert soup.find(id="tabBtn-admin") is not None
    assert soup.find(id="auditLogsTableBody") is not None
    assert soup.find(id="auditFilterAction") is not None
    assert soup.find(id="auditFilterResult") is not None
    assert soup.find(id="testCardsGrid") is not None
    assert soup.find(id="btnRunAllTests") is not None

    # Evidence Modal
    assert soup.find(id="evidenceModal") is not None
    assert soup.find(id="evidenceModalTitle") is not None
    assert soup.find(id="evidenceModalBadge") is not None
    assert soup.find(id="evidenceModalSubTitle") is not None
    assert soup.find(id="evidenceModalMeta") is not None
    assert soup.find(id="evidenceModalJson") is not None


def test_javascript_getelementbyid_references(html_content, soup):
    """Verify that every element ID queried by document.getElementById in JS actually exists in DOM."""
    all_dom_ids = set(el["id"] for el in soup.find_all(id=True))
    queried_ids = set(re.findall(r"document\.getElementById\(['\"](.*?)['\"]\)", html_content))
    missing = queried_ids - all_dom_ids
    assert not missing, f"JavaScript queries element IDs not found in HTML DOM: {missing}"


def test_siem_table_9_mandatory_columns(soup):
    """Verify SIEM Audit Log table renders all 9 mandatory headers."""
    admin_page = soup.find(id="page-admin")
    assert admin_page is not None
    table = admin_page.find("table")
    assert table is not None
    headers = [th.text.strip() for th in table.find_all("th")]
    assert len(headers) == 9, f"Expected 9 headers in SIEM table, found {len(headers)}: {headers}"
    expected_header_fields = [
        "Timestamp",
        "Actor",
        "Role",
        "Action",
        "Object ID",
        "Result",
        "Source IP",
        "Correlation ID",
        "Session ID Hash"
    ]
    for idx, field in enumerate(expected_header_fields):
        assert any(field.lower() in h.lower() for h in headers), (
            f"Mandatory header field '{field}' missing from SIEM table: {headers}"
        )


def test_pci_dss_masking_attributes(soup):
    """Verify PCI-DSS input masking: CVV input must be password type, PAN input must have oninput formatting helper."""
    cvv_input = soup.find(id="modalCvv")
    assert cvv_input is not None
    assert cvv_input.get("type") == "password", "modalCvv field MUST have type='password'"

    pan_input = soup.find(id="modalPan")
    assert pan_input is not None
    assert "onPanInput" in pan_input.get("oninput", ""), "modalPan field must have oninput handler for formatting"
    mask_preview = soup.find(id="modalMaskPreview")
    assert mask_preview is not None, "modalMaskPreview element must exist to display live masked PAN"
