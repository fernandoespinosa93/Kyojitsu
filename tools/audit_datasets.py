"""Read-only, aggregate audit of the six project corpora; no prompts in output.
Usage: python tools/audit_datasets.py --directory PATH --output docs/dataset_audit.json
Labels are descriptive metadata, NOT independently verified security outcomes.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3

FILES=['dataset_PALO_ALTO.db','dataset_TREND_AI.db','dataset_PALO_ALTO_SIN_GUARDRAILS.db',
       'successful_prompts_verified.json','successful_prompts_verified.json.maliciousinput',
       'successful_prompts_verified.json.maliciousoutput']
# Manual structural correspondence to the implemented operators. No payload
# matching and no assertion that variants preserve intent or bypass the same defenses.
CORRESPONDENCE={
 'Nested Role Playing':('partial','nested_role','Encapsula un rol; no modela sesiones independientes ni conversacion multi-turn.'),
 'Question Based Evasion':('partial','question_rewrite','Reformula como pregunta; no verifica que mantenga la intención.'),
 'Contextual Misdirection':('partial','contextual_reframe','Cambia el marco; no demuestra desvio contextual equivalente.'),
 'Task Confusion':('partial','contextual_reframe / json_envelope','Estructuras afines; sin un motor especifico de conflicto entre tareas.'),
 'Json Confusion':('partial','json_envelope','Envoltura JSON válida; no reproduce todos los casos de ambigüedad del parser.'),
 'Ambiguous Tool Request':('integration','none','Requiere herramientas instrumentadas, permisos y un registro de acciones.'),
 'Metaphorical Instruction':('gap','none','No hay operador local de metáforas. Un LLM puede producirlas, pero necesita evaluación específica.'),
 'Role Reversal':('partial','nested_role','Plantilla de rol; no equivale a invertir una jerarquia real de mensajes.'),
 'Indirect Generation':('partial','indirect_request','Indirección en texto, sin prueba de equivalencia semántica.'),
 'Semantic Rewriting':('partial','semantic_wrapper / question_rewrite','Cambios programados, no parafrasis libres con un modelo en modo local.'),
 'Semantic Ambiguity':('partial','semantic_wrapper','No garantiza crear ni resolver ambigüedad semántica equivalente.'),
 'Indirect Questioning':('partial','indirect_request','Reformulación indirecta de un solo turno.'),
 'Incremental Disclosure':('integration','segmented','Fragmenta dentro de un prompt; no implementa divulgación progresiva multi-turn.'),
 'Semantic Fragmentation':('partial','segmented','División de palabras y recombinación; sin validación semántica independiente.'),
 'Data Encoding Fragmentation':('partial','encoded_fragment / segmented','Codifica fragmentos; repertorio limitado, no todas las codificaciones.'),
 'Hypothetical Scenario':('partial','hypothetical','Marco hipotetico programado, no equivalencia garantizada con el corpus.'),
 'Fragmented Tool Description':('integration','segmented','El texto fragmentado no prueba como el agente utiliza herramientas reales.'),
 'Obfuscated Command Chain':('integration','encoded_fragment / segmented','No ejecuta cadenas ni valida un intérprete de comandos; requiere un simulador autorizado.'),
 'Contextual Manipulation':('partial','contextual_reframe','Contexto local sin manipular memoria persistente ni RAG real.'),
}


def audit(directory:Path)->dict:
    result={'schema_version':'1.0','comparison':'manual_structural_not_verified_equivalence',
            'limitations':['El nombre successful no demuestra éxito.',
             'blocked=false solo significa que el log no marcó un bloqueo; no prueba un objetivo adversarial logrado.',
             'attack_type mezcla categorías de contenido y técnicas de ataque; no es una taxonomía de evasiones consistente.',
             'Los corpus no se envían a proveedores ni se ejecutan con esta auditoría.'], 'files':[]}
    for name in FILES:
        path=directory/name
        if not path.exists():
            result['files'].append({'name':name,'available':False});continue
        raw=path.read_bytes();item={'name':name,'available':True,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
        if name.endswith('.db'):
            # Immutable mode neither creates WAL/SHM files nor modifies the source.
            conn=sqlite3.connect(path.resolve().as_uri()+'?mode=ro&immutable=1',uri=True)
            conn.execute('PRAGMA query_only=ON')
            records=conn.execute('SELECT query, blocked, attack_type FROM prompts').fetchall();conn.close()
            item.update(records=len(records),unique_normalized_prompts=len({' '.join(str(r[0]).casefold().split()) for r in records}),
                        logged_blocked_values=dict(Counter(str(r[1]) for r in records)),
                        attack_types=dict(Counter(str(r[2]).strip() if r[2] is not None else '(sin etiqueta)' for r in records)),
                        evidence_kind='endpoint_log_not_independent_attack_success')
        else:
            records=json.loads(raw)
            if not isinstance(records,list):raise ValueError(name+' no es una lista JSON')
            techniques=Counter(str(r.get('technique','')).strip() for r in records)
            fields=sorted({k for r in records for k in r})
            item.update(records=len(records),unique_normalized_prompts=len({' '.join(str(r.get('prompt','')).casefold().split()) for r in records}),
                        fields=fields,techniques=dict(techniques),categories=dict(Counter(str(r.get('category','')).strip() for r in records)),
                        has_observed_success_fields=bool(set(fields)&{'success','attack_success','outcome','blocked','verified_success'}))
            item['structural_mapping']=[{'label':label,'records':count,'status':CORRESPONDENCE[label][0],
               'local_operators':CORRESPONDENCE[label][1],'limitation':CORRESPONDENCE[label][2]}
               for label,count in techniques.items() if label in CORRESPONDENCE]
        result['files'].append(item)
    return result

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--directory',required=True,type=Path);ap.add_argument('--output',required=True,type=Path)
    args=ap.parse_args();data=audit(args.directory);args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Auditado:',sum(f.get('records',0) for f in data['files']),'registros. Sin enviar prompts a una API.')
