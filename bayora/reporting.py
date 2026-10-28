import html
import json
from pathlib import Path
from .runner import verify_report


def export(report, destination):
    """Export only verified projections; HTML is static and fully escaped."""
    if not verify_report(report):
        raise ValueError('Cannot export a report whose evidence/projection is inconsistent')
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    (dest/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    e = lambda x: html.escape(str(x))
    rows = ''.join('<tr>'+''.join(f'<td>{e(f[k])}</td>' for k in ('category','trial','outcome','confidence','review_status'))+'</tr>' for f in report['findings'])
    checks = ''.join(f'<tr><td>{e(k)}</td><td>{e(v)}</td></tr>' for k,v in report['harness_checks'].items())
    limitations = ''.join(f'<li>{e(x)}</li>' for x in report['limitations'])
    text = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BAYORA evaluation passport</title><style>
body{{font:16px/1.6 system-ui,sans-serif;background:#edf2f7;color:#17263a;margin:0}}main{{max-width:1100px;margin:auto;padding:40px 24px}}h1{{font-size:40px;letter-spacing:-1px;margin:4px 0}}h2{{font-size:23px;margin-top:32px}}.eyebrow{{color:#007c83;font-weight:700;letter-spacing:3px}}.cards{{display:flex;gap:15px;flex-wrap:wrap}}.card{{background:white;border:1px solid #d9e1ea;border-radius:12px;padding:20px;flex:1;min-width:180px}}.card strong{{display:block;font-size:23px}}table{{border-collapse:collapse;width:100%;background:white;font-size:14px}}td,th{{text-align:left;padding:12px;border-bottom:1px solid #dde4ec}}th{{background:#17314c;color:white}}.notice{{border-left:4px solid #d89c22;background:#fff6dc;padding:18px}}code{{overflow-wrap:anywhere}}.scroll{{overflow-x:auto}}footer{{color:#596a7c;margin-top:32px}}</style>
<main><div class="eyebrow">BAYORA / SYNTHETIC DEMO</div><h1>Evaluation passport</h1>
<p>Attack the AI. Validate the Defense. Audit the Test.</p>
<div class="cards"><div class="card">Harness integrity<strong>{e(report['harness_integrity'])}</strong></div><div class="card">Target observability<strong>{e(report['target_observability'])}</strong></div><div class="card">Evidence assurance<strong>Level 0</strong></div></div>
<p class="notice">This run evaluates a bundled simulator. It does not certify a customer system. Local process isolation and network enforcement are unverified.</p>
<p>Run: <code>{e(report['run_id'])}</code><br>Target: <code>{e(report['contract']['target'])}</code><br>State: {e(report['state'])}</p>
<h2>Observed results</h2><p>{e(report['metrics']['attempts'])} attempts · {e(report['outcomes'])} · Model cost: $0 (no provider calls)</p>
<div class="scroll"><table><thead><tr><th>Category</th><th>Trial</th><th>Outcome</th><th>Confidence</th><th>Review</th></tr></thead><tbody>{rows}</tbody></table></div>
<h2>Harness checks</h2><table><thead><tr><th>Gate</th><th>Result</th></tr></thead><tbody>{checks}</tbody></table>
<h2>Canary / session contamination</h2><p>{e(report['canary']['status'])}: {e(report['canary']['interpretation'])}</p>
<h2>What this report cannot prove</h2><ul>{limitations}</ul>
<h2>Evidence record</h2><p>{e(report['assurance_claim'])}<br>{e(report['manifest']['event_count'])} events<br>Root: <code>{e(report['manifest']['root_hash'])}</code><br>Contract: <code>{e(report['contract_hash'])}</code></p>
<footer>BAYORA 0.1.0 · Architecture v2 implementation starter · Candidate findings require review</footer></main></html>'''
    (dest/'report.html').write_text(text,encoding='utf-8')
    return dest/'report.html'
