# miu-tools

Herramientas del ecosistema MIU.

## Módulos

- df_calculator_advanced.js: D_f Hill+Zipf+KS
- cohere_search.py: Búsqueda semántica Cohere rerank-v3.5
- tools/audit_record_generator.py: actas deterministas con IDs estables, Markdown, JSON, CHECKPOINT y manifest SHA256; tres rutas antiguas delegan en esta implementación.

## Actas y continuidad

La herramienta de actas usa solo la biblioteca estándar de Python. Sus salidas son locales hasta que un consumidor las guarde y verifique en un sustrato remoto.

```bash
python tools/audit_record_generator.py --input audit-input.json --output-dir audit-output
python -m unittest discover -s tests -v
```

El [contrato de entrada y los límites](docs/AUDIT_RECORDS.md) separan evidencia declarada, ejecución y persistencia. No se añadieron llamadas a modelos, despliegues ni credenciales.

https://doi.org/10.5281/zenodo.20547558
