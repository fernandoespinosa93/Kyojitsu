from __future__ import annotations
import json
from pathlib import Path


def render_report_html(summary: dict) -> str:
    """Self-contained report: never fetch private evidence or external assets."""
    if 'assessment' not in summary:
        from .assessment import build_assessment
        summary = dict(summary, assessment=build_assessment(summary))
    root = Path(__file__).parent / 'web'
    css = (root/'studio.css').read_text(encoding='utf-8') + '\n' + (root/'report.css').read_text(encoding='utf-8')
    js = (root/'report.js').read_text(encoding='utf-8')
    data = json.dumps(summary, ensure_ascii=True).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    # Data is substituted last: user prompts containing template markers remain data.
    return (root/'report.html').read_text(encoding='utf-8').replace('__CSS__',css).replace('__JS__',js).replace('__DATA__',data)
