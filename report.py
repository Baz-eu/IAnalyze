"""
Générateur de rapport HTML de sécurité
Produit un rapport standalone navigable avec toutes les failles et remédiations
"""

import json
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from scanner.analyzer import ChunkResult, Vulnerability


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": ("#7f1d1d", "#fca5a5"),
    "HIGH":     ("#78350f", "#fcd34d"),
    "MEDIUM":   ("#1e3a5f", "#93c5fd"),
    "LOW":      ("#14532d", "#86efac"),
    "INFO":     ("#374151", "#d1d5db"),
}


class ReportGenerator:

    def generate(
        self,
        results: list[ChunkResult],
        cross_analysis: dict,
        global_context: dict,
        repo_url: str,
        output_path: Path,
    ) -> Path:
        """Génère le rapport HTML complet."""
        all_vulns = []
        for r in results:
            for v in r.vulnerabilities:
                all_vulns.append(v)

        all_vulns.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))

        stats = self._compute_stats(results, all_vulns)
        html = self._render_html(results, all_vulns, cross_analysis, global_context, repo_url, stats)

        output_path.write_text(html, encoding="utf-8")
        return output_path

    def _compute_stats(self, results, vulns):
        by_sev = defaultdict(int)
        by_cat = defaultdict(int)
        by_file = defaultdict(int)
        scores = []

        for v in vulns:
            by_sev[v.severity] += 1
            by_cat[v.category] += 1
            by_file[v.file_path] += 1

        for r in results:
            if r.security_score > 0:
                scores.append(r.security_score)

        avg_score = sum(scores) / len(scores) if scores else 0

        return {
            "total": len(vulns),
            "by_severity": dict(by_sev),
            "by_category": dict(by_cat),
            "by_file": dict(sorted(by_file.items(), key=lambda x: x[1], reverse=True)[:10]),
            "avg_score": avg_score,
            "files_analyzed": len(results),
            "chunks_analyzed": len(results),
        }

    def _render_html(self, results, vulns, cross, ctx, repo_url, stats):
        now = datetime.now().strftime("%d/%m/%Y à %H:%M")
        repo_name = ctx.get("repo_name", repo_url.split("/")[-1])
        tech_stack = ", ".join(ctx.get("tech_stack", []))
        global_summary = ctx.get("summary", "")
        cross_vulns = cross.get("cross_vulnerabilities", [])
        cross_summary = cross.get("summary", "")

        score_color = "#14532d" if stats["avg_score"] >= 7 else "#78350f" if stats["avg_score"] >= 4 else "#7f1d1d"

        vuln_cards = ""
        for i, v in enumerate(vulns):
            bg, accent = SEVERITY_COLORS.get(v.severity, ("#374151", "#d1d5db"))
            fixed_code_block = f"""
            <div class="code-section">
              <div class="code-label green-label">✓ Code corrigé</div>
              <pre><code>{self._escape(v.fixed_code)}</code></pre>
            </div>""" if v.fixed_code else ""

            vuln_cards += f"""
        <div class="vuln-card" data-severity="{v.severity}">
          <div class="vuln-header" onclick="toggle(this)">
            <span class="sev-badge" style="background:{accent};color:{bg}">{v.severity}</span>
            <div class="vuln-title-block">
              <span class="vuln-title">{self._escape(v.category.replace('_',' '))} — {self._escape(v.location)}</span>
              <span class="vuln-file">{self._escape(v.file_path)}{f' ~ligne {v.line_hint}' if v.line_hint else ''}</span>
            </div>
            <span class="vuln-cwe">{self._escape(v.cwe)}</span>
            <span class="chevron">▾</span>
          </div>
          <div class="vuln-body">
            <div class="vuln-section">
              <div class="section-label">Description</div>
              <p>{self._escape(v.description)}</p>
            </div>
            <div class="code-section">
              <div class="code-label red-label">✗ Code vulnérable</div>
              <pre><code>{self._escape(v.vulnerable_code)}</code></pre>
            </div>
            <div class="vuln-section">
              <div class="section-label">Scénario d'attaque</div>
              <p>{self._escape(v.attack_scenario)}</p>
            </div>
            <div class="vuln-section">
              <div class="section-label">Remédiation</div>
              <p>{self._escape(v.remediation)}</p>
            </div>
            {fixed_code_block}
          </div>
        </div>"""

        cross_cards = ""
        for cv in cross_vulns:
            bg, accent = SEVERITY_COLORS.get(cv.get("severity", "MEDIUM"), ("#374151", "#d1d5db"))
            cross_cards += f"""
        <div class="cross-card">
          <span class="sev-badge" style="background:{accent};color:{bg}">{cv.get('severity','?')}</span>
          <div style="flex:1">
            <p style="font-weight:600;margin:0 0 6px">{self._escape(cv.get('description',''))}</p>
            <p style="font-size:13px;color:#6b7280;margin:0 0 4px">Features : {', '.join(cv.get('affected_features',[]))}</p>
            <p style="font-size:13px;margin:0 0 4px"><strong>Chaîne d'attaque :</strong> {self._escape(cv.get('attack_chain',''))}</p>
            <p style="font-size:13px;margin:0"><strong>Remédiation :</strong> {self._escape(cv.get('remediation',''))}</p>
          </div>
        </div>"""

        sev_counts = "".join([
            f'<div class="stat-pill" style="background:{SEVERITY_COLORS.get(s,("#374151","#d1d5db"))[1]};color:{SEVERITY_COLORS.get(s,("#374151","#d1d5db"))[0]}">'
            f'{stats["by_severity"].get(s, 0)} {s}</div>'
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        ])

        file_rows = "".join([
            f'<tr><td style="font-family:monospace;font-size:12px">{self._escape(f)}</td>'
            f'<td style="text-align:right;font-weight:600">{c}</td></tr>'
            for f, c in list(stats["by_file"].items())[:8]
        ])

        return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport de sécurité — {self._escape(repo_name)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;color:#111827;line-height:1.6}}
  .header{{background:#111827;color:#f9fafb;padding:2rem 2.5rem}}
  .header h1{{font-size:22px;font-weight:600;margin-bottom:4px}}
  .header .meta{{font-size:13px;color:#9ca3af}}
  .main{{max-width:1100px;margin:0 auto;padding:2rem 1.5rem}}
  .section-title{{font-size:16px;font-weight:600;margin:2rem 0 1rem;padding-bottom:8px;border-bottom:1px solid #e5e7eb}}
  .stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:1.5rem}}
  .stat-card{{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px 16px}}
  .stat-card .label{{font-size:12px;color:#6b7280;margin-bottom:4px}}
  .stat-card .value{{font-size:24px;font-weight:600}}
  .sev-pills{{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:1.5rem}}
  .stat-pill{{font-size:12px;font-weight:600;padding:4px 12px;border-radius:20px}}
  .filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:1rem}}
  .filter-btn{{font-size:12px;padding:5px 14px;border-radius:20px;border:1px solid #d1d5db;background:#fff;cursor:pointer;transition:all .15s}}
  .filter-btn.active,.filter-btn:hover{{background:#111827;color:#fff;border-color:#111827}}
  .vuln-card{{background:#fff;border:1px solid #e5e7eb;border-radius:10px;margin-bottom:10px;overflow:hidden}}
  .vuln-header{{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer}}
  .vuln-header:hover{{background:#f9fafb}}
  .sev-badge{{font-size:11px;font-weight:700;padding:3px 9px;border-radius:20px;flex-shrink:0;letter-spacing:.03em}}
  .vuln-title-block{{flex:1;min-width:0}}
  .vuln-title{{font-size:14px;font-weight:500;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
  .vuln-file{{font-size:12px;color:#6b7280;font-family:monospace}}
  .vuln-cwe{{font-size:11px;color:#9ca3af;flex-shrink:0}}
  .chevron{{color:#9ca3af;flex-shrink:0;transition:transform .2s}}
  .vuln-body{{display:none;padding:0 16px 16px;border-top:1px solid #f3f4f6}}
  .vuln-body.open{{display:block}}
  .chevron.open{{transform:rotate(180deg)}}
  .vuln-section{{margin-top:12px}}
  .section-label{{font-size:11px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}}
  .vuln-section p{{font-size:13px;color:#374151}}
  .code-section{{margin-top:12px}}
  .code-label{{font-size:11px;font-weight:600;margin-bottom:4px;padding:3px 8px;border-radius:4px;display:inline-block}}
  .red-label{{background:#fee2e2;color:#991b1b}}
  .green-label{{background:#dcfce7;color:#166534}}
  pre{{background:#1e293b;color:#e2e8f0;padding:12px;border-radius:8px;font-size:12px;overflow-x:auto;line-height:1.6;white-space:pre-wrap;word-break:break-all}}
  .cross-card{{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px 16px;margin-bottom:10px;display:flex;gap:12px;align-items:flex-start}}
  .summary-box{{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin-bottom:1.5rem;font-size:14px;color:#374151}}
  .file-table{{width:100%;border-collapse:collapse;font-size:13px}}
  .file-table td{{padding:6px 8px;border-bottom:1px solid #f3f4f6}}
  .file-table tr:last-child td{{border-bottom:none}}
  .info-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:1.5rem}}
  @media(max-width:600px){{.info-grid{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="header">
  <h1>🔐 Rapport d'audit de sécurité</h1>
  <div class="meta">{self._escape(repo_url)} · Généré le {now} · Claude Opus</div>
</div>
<div class="main">

  <div class="section-title">Vue d'ensemble</div>
  <div class="stats-grid">
    <div class="stat-card"><div class="label">Failles totales</div><div class="value">{stats['total']}</div></div>
    <div class="stat-card"><div class="label">Fichiers analysés</div><div class="value">{stats['files_analyzed']}</div></div>
    <div class="stat-card"><div class="label">Score moyen sécurité</div><div class="value" style="color:{score_color}">{stats['avg_score']:.1f}/10</div></div>
    <div class="stat-card"><div class="label">Stack technique</div><div class="value" style="font-size:13px;margin-top:4px">{self._escape(tech_stack)}</div></div>
  </div>
  <div class="sev-pills">{sev_counts}</div>

  {'<div class="summary-box">' + self._escape(global_summary) + '</div>' if global_summary else ''}

  <div class="info-grid">
    <div>
      <div class="section-title" style="margin-top:0">Fichiers les plus risqués</div>
      <div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden">
        <table class="file-table"><tbody>{file_rows}</tbody></table>
      </div>
    </div>
    <div>
      <div class="section-title" style="margin-top:0">Préoccupations globales</div>
      <div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:12px 16px">
        {''.join(f'<p style="font-size:13px;margin-bottom:6px">• {self._escape(c)}</p>' for c in ctx.get('risk_map',{}).get('security_concerns',[])[:8]) or '<p style="font-size:13px;color:#6b7280">Aucune préoccupation globale identifiée</p>'}
      </div>
    </div>
  </div>

  {'<div class="section-title">Vulnérabilités transversales</div>' + cross_cards + ('<div class="summary-box">' + self._escape(cross_summary) + '</div>' if cross_summary else '') if cross_cards else ''}

  <div class="section-title">Vulnérabilités détectées ({stats['total']})</div>
  <div class="filters">
    <button class="filter-btn active" onclick="filterSev('ALL',this)">Toutes</button>
    {''.join(f'<button class="filter-btn" onclick="filterSev(\'{s}\',this)">{s} ({stats["by_severity"].get(s,0)})</button>' for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] if stats["by_severity"].get(s,0))}
  </div>
  <div id="vuln-list">
    {vuln_cards if vuln_cards else '<p style="color:#6b7280;font-size:14px">Aucune vulnérabilité détectée.</p>'}
  </div>

</div>
<script>
function toggle(header){{
  const body=header.nextElementSibling;
  const chev=header.querySelector('.chevron');
  body.classList.toggle('open');
  chev.classList.toggle('open');
}}
function filterSev(sev,btn){{
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.vuln-card').forEach(card=>{{
    card.style.display=(sev==='ALL'||card.dataset.severity===sev)?'block':'none';
  }});
}}
</script>
</body>
</html>"""

    def _escape(self, text: str) -> str:
        if not text:
            return ""
        return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
