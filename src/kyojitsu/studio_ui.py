from pathlib import Path

_WEB = Path(__file__).with_name('web')
STUDIO_HTML = (_WEB / 'studio.html').read_text(encoding='utf-8').replace(
    '__CSS__', (_WEB / 'studio.css').read_text(encoding='utf-8')
).replace('__JS__', (_WEB / 'studio.js').read_text(encoding='utf-8'))
