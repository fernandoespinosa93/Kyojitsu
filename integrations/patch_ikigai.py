r"""Aplica el contrato experimental Kyojitsu v2 a ikigai_gpt.py.

Uso en PowerShell:
    py integrations/patch_ikigai.py C:\ruta\ikigai_gpt.py

El script crea una copia .bak antes de escribir y se detiene si el archivo no
coincide con la versión esperada.
"""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path


MARKER = '"experiment_contract": "kyojitsu-v2"'


REPLACEMENTS = [
    (
        '''        except Exception as e:
            print(f"\\033[33m[WARN] Guardrails v4 error: {e}\\033[0m")
            return {"allowed": True}
''',
        '''        except Exception as e:
            print(f"\\033[31m[ERROR] Guardrails v4 error: {e}\\033[0m")
            return {
                "allowed": False,
                "reason": "Guardrail internal error",
                "attack_type": "guardrail_error",
                "risk_score": 10.0,
                "guardrail_error": True,
                "trace_id": trace_id,
            }
''',
    ),
    (
        '''                "risk_score": guard_result.get("risk_score", 0)
            }
''',
        '''                "risk_score": guard_result.get("risk_score", 0),
                "stage": "guardrail_error" if guard_result.get("guardrail_error") else "input",
                "guardrail_error": bool(guard_result.get("guardrail_error", False)),
                "trace_id": guard_result.get("trace_id")
            }
''',
    ),
    (
        '''                "blocked": True,
                "reason": "Output validation failed"
            }
''',
        '''                "blocked": True,
                "reason": "Output validation failed",
                "stage": "output",
                "guardrail_error": False
            }
''',
    ),
    (
        '''        "blocked": False,
        "reason": None
    }
''',
        '''        "blocked": False,
        "reason": None,
        "stage": "completed",
        "guardrail_error": False
    }
''',
    ),
    (
        '''            "guardrails": "active" if guardrails_enabled else "DISABLED",
            "guardrails_stats": guardrails.get_stats(),
''',
        '''            "guardrails": "active" if guardrails_enabled else "DISABLED",
            "experiment_contract": "kyojitsu-v2",
            "guardrail_fail_mode": "closed",
            "guardrails_stats": guardrails.get_stats(),
''',
    ),
]


def patch_file(path: Path) -> Path:
    text = path.read_text(encoding="utf-8")
    if MARKER in text:
        raise ValueError("El archivo ya contiene el contrato kyojitsu-v2.")
    updated = text
    for old, new in REPLACEMENTS:
        count = updated.count(old)
        if count != 1:
            raise ValueError(
                f"La versión no coincide con el parche esperado: un bloque apareció {count} veces."
            )
        updated = updated.replace(old, new, 1)
    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, backup)
    path.write_text(updated, encoding="utf-8", newline="\n")
    return backup


def main() -> int:
    parser = argparse.ArgumentParser(description="Instrumenta Ikigai para experimentos Kyojitsu v2.")
    parser.add_argument("path", type=Path, help="Ruta a ikigai_gpt.py")
    args = parser.parse_args()
    if not args.path.is_file():
        parser.error(f"No existe el archivo: {args.path}")
    try:
        backup = patch_file(args.path)
    except ValueError as exc:
        parser.error(str(exc))
    print(f"Ikigai instrumentado. Respaldo: {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
