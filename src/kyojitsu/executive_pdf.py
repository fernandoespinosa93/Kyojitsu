"""Vector executive PDF, no network, fonts to download or third-party runtime packages.

Uses the PDF standard Helvetica fonts and WinAnsi (Spanish / Western text).
Only aggregate evidence is included: no raw prompts, credentials or responses.
"""
from __future__ import annotations
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

# Standard Helvetica character advances in 1/1000 text units (ASCII 32..126).
WIDTHS = [278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584]
NAVY = (.12, .08, .14)
BLUE = (.55, .35, .72)
CYAN = (.80, .35, .68)
GREEN = (.29, .64, .46)
AMBER = (.86, .58, .20)
CORAL = (.82, .34, .38)
VIOLET = (.63, .43, .82)
INK = (.18, .15, .20)
MUTED = (.43, .39, .46)
LIGHT = (.965, .955, .97)
BORDER = (.87, .84, .89)
COLORS = {'finding': (.66,.19,.20), 'inconclusive': (.60,.40,.13), 'blocked': (.16,.44,.31),
          'no_finding': (.48,.30,.63), 'out_of_scope': MUTED, 'not_tested': MUTED}


def clean(value) -> str:
    return re.sub(r'[\x00-\x08\x0b-\x1f]', '', str(value)).replace('\u2014','-').replace('\u2192',' / ')


def width(text: str, size=10, bold=False) -> float:
    result = 0
    for c in clean(text):
        base = unicodedata.normalize('NFD', c)[0]
        code = ord(base)
        result += WIDTHS[code-32] if 32 <= code <= 126 else 556
    return result*size/1000 * (1.05 if bold else 1)


def wrap(text: str, available: float, size=10, bold=False) -> list[str]:
    lines = []
    for para in clean(text).split('\n'):
        line = ''
        for word in para.split():
            while width(word,size,bold) > available:
                i = max(1, int(len(word)*available/width(word,size,bold)) - 1)
                if line:
                    lines.append(line); line = ''
                lines.append(word[:i]); word = word[i:]
            proposed = (line+' '+word).strip()
            if width(proposed,size,bold) > available and line:
                lines.append(line); line = word
            else:
                line = proposed
        lines.append(line)
    return lines or ['']


class Document:
    def __init__(self, run_id: str):
        self.pages: list[list[str]] = []
        self.run_id = run_id
        self.y = 0
        self.new_page()

    def cmd(self, s):
        self.pages[-1].append(s)

    def rect(self, x, y, w, h, fill):
        self.cmd(f'{fill[0]:.3f} {fill[1]:.3f} {fill[2]:.3f} rg {x:.2f} {842-y-h:.2f} {w:.2f} {h:.2f} re f')

    def text(self, text, x, y, size=10, bold=False, color=INK):
        encoded = clean(text).encode('cp1252', errors='replace').hex()
        self.cmd(f'BT /F{2 if bold else 1} {size} Tf {color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg 1 0 0 1 {x:.2f} {842-y-size:.2f} Tm <{encoded}> Tj ET')


    def line(self, x1, y1, x2, y2, color=BORDER, stroke=1):
        self.cmd(f'{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} RG {stroke:.2f} w {x1:.2f} {842-y1:.2f} m {x2:.2f} {842-y2:.2f} l S')

    def horizontal_bars(self, title, items, *, note=''):
        """Static executive chart. items = [(label, value, max_value, color, suffix)]."""
        h = 42 + max(1, len(items)) * 34 + (18 if note else 0)
        self.ensure(h + 12)
        self.text(title, 40, self.y, 11.5, True, NAVY)
        self.y += 22
        bar_x, bar_w = 260, 245
        for label, value, maximum, color, suffix in items:
            self.text(label, 40, self.y+2, 8.8, False, INK)
            self.rect(bar_x, self.y, bar_w, 12, (.91,.935,.965))
            ratio = max(0.0, min(1.0, float(value) / float(maximum or 1)))
            if ratio:
                self.rect(bar_x, self.y, max(2, bar_w*ratio), 12, color)
            self.text(f'{value}{suffix}', 514, self.y+1, 8.5, True, color)
            self.y += 32
        if note:
            self.paragraph(note, 8.5, MUTED, gap=4)
        else:
            self.y += 5

    def generation_chart(self, metrics):
        self.ensure(205)
        self.text('Evolución por ronda',40,self.y,11.5,True,NAVY); self.y += 22
        if not metrics:
            self.paragraph('No hay datos por ronda para graficar.',9,MUTED); return
        x0,y0,w,h=70,self.y,455,132
        for q in range(5):
            yy=y0+h*q/4
            self.line(x0,yy,x0+w,yy,BORDER,.6)
            self.text(f'{100-q*25}%',42,yy-3,7.8,False,MUTED)
        den=max(1,len(metrics)-1)
        series=[('guardrail_bypass_rate',BLUE,'Bypass observable',lambda v: None if v is None else float(v)),
                ('confirmed_attack_success_rate',CORAL,'Éxito confirmado',lambda v: float(v or 0)),
                ('avg_fitness',GREEN,'Puntuación promedio',lambda v: max(0,min(100,float(v or 0)*100)))]
        for key,color,label,convert in series:
            pts=[]
            for i,m in enumerate(metrics):
                val=convert(m.get(key))
                if val is None: continue
                x=x0+w*i/den; y=y0+h*(1-val/100); pts.append((x,y))
            for a,b in zip(pts,pts[1:]): self.line(a[0],a[1],b[0],b[1],color,1.5)
            for x,y in pts: self.rect(x-1.8,y-1.8,3.6,3.6,color)
        for i,m in enumerate(metrics):
            x=x0+w*i/den; self.text(f"G{m.get('generation',i)}",x-6,y0+h+8,7.5,False,MUTED)
        self.y=y0+h+27
        lx=80
        for _,color,label,_ in series:
            self.rect(lx,self.y,12,3,color); self.text(label,lx+17,self.y-3,7.7,False,MUTED); lx += 150
        self.y += 24

    def new_page(self):
        self.pages.append([])
        self.rect(0,0,595,6,BLUE)
        self.text('Kyojitsu',40,23,14,True,NAVY)
        self.text('Evaluaci\u00f3n de seguridad de IA',130,27,9,color=MUTED)
        self.rect(40,52,515,1,BORDER)
        self.y = 72

    def ensure(self, amount):
        if self.y + amount > 782:
            self.new_page()

    def paragraph(self, text, size=10.5, color=INK, indent=0, bold=False, gap=9):
        lines = wrap(text, 515-indent, size, bold)
        for line in lines:
            self.ensure(size*1.45)
            self.text(line,40+indent,self.y,size,bold,color)
            self.y += size*1.45
        self.y += gap

    def heading(self, text):
        self.ensure(58)
        self.y += 10
        self.paragraph(text,15,NAVY,bold=True,gap=12)

    def table(self, headers, values, widths):
        def header():
            self.ensure(30)
            self.rect(40,self.y,515,27,NAVY)
            x=40
            for v,w in zip(headers,widths):
                self.text(v,x+8,self.y+7,9,True,(1,1,1)); x+=w
            self.y+=27
        header()
        for n, cells in enumerate(values):
            lines=[wrap(v,w-16,9) for v,w in zip(cells,widths)]
            h=max(len(x) for x in lines)*13+16
            if self.y+h>778:
                self.new_page();header()
            if n%2==0:self.rect(40,self.y,515,h,LIGHT)
            x=40
            for col,w in zip(lines,widths):
                for i,line in enumerate(col):self.text(line,x+8,self.y+8+13*i,9)
                x+=w
            self.y+=h
            self.rect(40,self.y-1,515,.5,BORDER)
        self.y+=13

    def save(self,path):
        total=len(self.pages)
        for i,page in enumerate(self.pages):
            self.pages[i]=page
            saved=self.pages[-1]
            # Add footers directly to the appropriate content stream.
            text=f'{self.run_id}   |   Uso restringido   |   {i+1} / {total}'
            data=clean(text).encode('cp1252',errors='replace').hex()
            page.append(f'BT /F1 8 Tf .38 .43 .50 rg 1 0 0 1 40 24 Tm <{data}> Tj ET')
        objs=[b'',b'',b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>']
        kids=[]
        for page in self.pages:
            stream='\n'.join(page).encode('ascii');cid=len(objs)+1
            objs.append(b'<< /Length '+str(len(stream)).encode()+b' >>\nstream\n'+stream+b'\nendstream')
            pid=len(objs)+1;kids.append(pid)
            objs.append(f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {cid} 0 R >>'.encode())
        objs[0]=b'<< /Type /Catalog /Pages 2 0 R >>'
        objs[1]=f'<< /Type /Pages /Count {len(kids)} /Kids [ {" ".join(str(x)+" 0 R" for x in kids)} ] >>'.encode()
        data=bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n');offsets=[0]
        for i,o in enumerate(objs,1):
            offsets.append(len(data));data.extend(f'{i} 0 obj\n'.encode()+o+b'\nendobj\n')
        off=len(data);data.extend(f'xref\n0 {len(objs)+1}\n0000000000 65535 f \n'.encode())
        for v in offsets[1:]:data.extend(f'{v:010d} 00000 n \n'.encode())
        data.extend(f'trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{off}\n%%EOF\n'.encode())
        Path(path).write_bytes(data)


def export_executive_pdf(summary: dict, path: str | Path) -> None:
    a=summary['assessment'];m=a['metrics'];run=summary['run'];d=Document(run['id'])
    d.paragraph('Evaluaci\u00f3n de guardrails',25,NAVY,bold=True,gap=5)
    d.paragraph(str(summary.get('experiment',{}).get('name') or run['target']),13,BLUE,gap=8)
    try:
        date = datetime.fromisoformat(run['created_at']).astimezone(timezone.utc).strftime('%d/%m/%Y %H:%M UTC')
    except (ValueError, TypeError):
        date = str(run['created_at'])
    status = {'completed':'Completada','budget_exhausted':'Límite de pruebas alcanzado',
              'failed':'Fallo','generator_failed':'Fallo del generador','cancelled':'Cancelada'}.get(run['status'],run['status'])
    d.paragraph(f"Fecha: {date}   |   Estado: {status}",9,MUTED)
    if summary.get('synthetic'):
        d.paragraph('SIMULACI\u00d3N DE LABORATORIO. Este documento NO describe la seguridad de una API real.',11,(.62,.32,.12),bold=True)
    d.paragraph('Resumen ejecutivo',15,NAVY,bold=True)
    if m['confirmed_successes']:
        conclusion=f"Se confirmaron {m['unique_successful_prompts']} prompts exitosos en {m['successful_techniques']} t\u00e9cnicas, sobre {m['valid_adversarial']} evaluaciones adversariales v\u00e1lidas. Priorizar los hallazgos y volver a probar los mismos casos tras aplicar correcciones."
    elif m['unresolved'] or m['errors']:
        conclusion=f"No hay ataques confirmados con la evidencia disponible. Hay {m['unresolved']} pruebas pendientes de resolver y {m['errors']} errores t\u00e9cnicos. El resultado no permite declarar que la defensa haya resistido todo el alcance."
    else:
        conclusion='No se confirmaron violaciones en esta muestra. Los bloqueos observados no garantizan protecci\u00f3n frente a otras formulaciones, modelos o componentes no evaluados.'
    d.paragraph(conclusion)
    cards=[('Prompts exitosos',m['unique_successful_prompts']),('Bloqueos expl\u00edcitos',m['explicit_blocks']),('Sin resolver',m['unresolved'])]
    d.ensure(85)
    for i,(label,value) in enumerate(cards):
        x=40+i*175;d.rect(x,d.y,165,72,LIGHT);d.rect(x,d.y,3,72,BLUE)
        d.text(label,x+12,d.y+9,9,color=MUTED);d.text(str(value),x+12,d.y+28,24,True,NAVY)
    d.y+=88
    total_chart=max(1,m['valid_adversarial'])
    d.horizontal_bars('Distribución ejecutiva de resultados',[
        ('Bloqueos confirmados',m['explicit_blocks'],total_chart,GREEN,''),
        ('Ataques confirmados',m['confirmed_successes'],total_chart,CORAL,''),
        ('Pruebas sin resolver',m['unresolved'],total_chart,AMBER,''),
        ('Errores técnicos',m['errors'],max(1,m['evaluations']),VIOLET,''),
    ],note='Las barras usan como referencia la muestra adversarial válida; los errores técnicos se comparan contra las evaluaciones totales.')
    planned=max(1,m['techniques_planned'])
    d.horizontal_bars('Cobertura del alcance seleccionado',[
        ('Técnicas con evidencia válida',m['selected_techniques_with_valid_tests'],planned,BLUE,''),
        ('Técnicas con hallazgos confirmados',m['successful_techniques'],planned,CORAL,''),
    ],note='Cobertura indica técnicas seleccionadas que recibieron pruebas válidas. No representa un porcentaje de certificación de cumplimiento.')
    d.generation_chart(summary.get('generation_metrics') or [])
    d.table(['Indicador','Resultado'],[
        ('Evaluaciones totales / adversariales v\u00e1lidas',f"{m['evaluations']} / {m['valid_adversarial']}"),
        ('T\u00e9cnicas con pruebas v\u00e1lidas / seleccionadas',f"{m['selected_techniques_with_valid_tests']} / {m['techniques_planned']}"),
        ('Bloqueos indicados solo por texto',str(m['text_blocks'])),
        ('Cruce de entrada (solo con se\u00f1al conocida)',f"{m['bypass_observed']}% sobre {m['bypass_denominator']} pruebas" if m['bypass_observed'] is not None else 'No observable'),
        ('Consultas permitidas denegadas / probadas',(f"{m['benign_denied']} / {m['benign_tests']}" + (' (parcial)' if m['benign_unresolved'] else '')) if m['benign_tests'] else 'No medido: sin controles benignos'),
    ],[355,160])
    d.paragraph(a['notice'],9,MUTED)
    d.heading('Resultados frente al marco seleccionado')
    d.paragraph('Los conteos son evaluaciones, no porcentajes de cumplimiento. Una misma prueba puede aparecer en varios marcos. Las categor\u00edas no ejecutadas no reciben un resultado favorable.',10,MUTED)
    for fw in a['frameworks']:
        selected=[c for c in a['categories'] if c['framework']==fw and c['selected']]
        d.heading('OWASP LLM Top 10 2025' if fw=='owasp_llm_2025' else 'MITRE ATLAS')
        if selected:
            d.table(['Categor\u00eda','Pruebas','\u00c9xitos','Estado'],[(c['id']+' - '+c['name'],str(c['metrics']['valid_adversarial']),str(c['metrics']['confirmed_successes']),c['label']) for c in selected],[222,50,49,194])
        outside=[c['id'] for c in a['categories'] if c['framework']==fw and not c['selected']]
        if outside:d.paragraph('Fuera de alcance: '+', '.join(outside)+'.',9,MUTED)
    d.heading('Resultados por t\u00e9cnica')
    d.table(['T\u00e9cnica','Pruebas','\u00c9xitos','Sin resolver'],[(t['name'],str(t['metrics']['valid_adversarial']),str(t['metrics']['confirmed_successes']),str(t['metrics']['unresolved'])) for t in a['techniques']],[305,70,60,80])
    d.heading('Plan de mejora')
    for rec in a['recommendations']:
        d.ensure(100)
        d.paragraph(f"{rec['id']}  {rec['priority']}  {rec['title']}",12,NAVY,bold=True,gap=5)
        d.paragraph('Evidencia: '+rec['evidence'],9,MUTED,gap=6)
        d.paragraph(rec['action'],10,gap=6)
        d.paragraph('Validar la correcci\u00f3n: '+rec['verification'],10,gap=6)
        d.paragraph('Responsable sugerido: '+rec['owner'],9,MUTED,gap=14)
    d.ensure(270)
    d.heading('M\u00e9todo y l\u00edmites de la evaluaci\u00f3n')
    gen=a['generator'];mode=gen.get('mode','rules')
    d.paragraph('Generaci\u00f3n: '+('reglas locales adaptativas, sin llamadas a un LLM.' if mode=='rules' else f"{mode}; modelo {gen.get('model','')}; {gen.get('calls',0)} llamadas en la campa\u00f1a, incluida su comprobaci\u00f3n inicial."))
    for n,text in enumerate(a['limitations'],1):d.paragraph(f'{n}. {text}',10,gap=9)
    d.paragraph('El HTML y assessment.json contienen la matriz y referencias a los casos. La base SQLite conserva la evidencia detallada y las revisiones. Este PDF omite los prompts y las respuestas por privacidad.',9,MUTED)
    d.save(path)
