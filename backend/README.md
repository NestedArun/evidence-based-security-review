# Backend (Checkpoint 1: foundation)

FastAPI + SQLAlchemy/SQLite + Pydantic + Tree-sitter code processing + local Ollama AI review + deterministic source-code evidence verification (Checkpoints 1-3).
Static analysis, correlation, judge and evaluation remain for later checkpoints.

## Run
    cd backend
    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements-dev.txt
    python -m pytest                      # tests
    uvicorn app.main:app --reload         # API on http://127.0.0.1:8000 (docs at /docs)

## API
| Method | Path | Purpose |
| --- | --- | --- |
| GET | /health | liveness |
| POST | /reviews | `{project_name, project_path}` -> Review (PENDING) |
| GET | /reviews, /reviews/{id} | Review (matches `schemas/review.schema.json`) |
| POST | /reviews/{id}/process | run Code Processing; review becomes RUNNING (FAILED on error) |
| GET | /reviews/{id}/files | discovered source files (.py), skip reasons, sha256 |
| GET | /reviews/{id}/code-units[?file=] | extracted code units |
| POST | /reviews/{id}/ai-review | run four local Ollama agents and persist candidate findings |
| GET | /reviews/{id}/findings | candidate findings |

A review stays `RUNNING` after processing because later pipeline stages do not exist yet;
`COMPLETED` is reserved for a finished pipeline. Submitted code is only read, never executed.

## Settings (env vars, all optional)
`EBSR_DATABASE_URL` (default `sqlite:///backend/data/review.db`), `EBSR_PROJECT_CONFIG`,
`EBSR_MAX_FILE_BYTES` (1 000 000), `EBSR_MAX_UNIT_LINES` (200).

## Code-unit layout
`function` / `method` (decorators included), `class` (class-body statements between methods),
`module` (top-level statements between definitions). Units never overlap; long units are split
into line chunks (`chunk_index`). Line numbers are 1-based and match the original file.


## Checkpoint 2
Set `EBSR_OLLAMA_MODEL` to the installed local Ollama model (for example `gemma3:4b`). The AI endpoint requires a processed review in `RUNNING` state. Ollama errors are returned explicitly; no findings are fabricated. Candidate findings are hypotheses only.


## Checkpoint 3

After `/ai-review`, call `POST /reviews/{id}/evidence`. The evidence layer reads the reviewed
source file and applies deterministic Python AST/lexical checks for:

* source evidence
* sink evidence
* data-flow evidence
* security-control evidence

It never executes submitted source code and never treats agreement between LLM agents as
independent evidence. Re-running evidence verification replaces the existing evidence for
the review's findings so the result is reproducible rather than duplicated.

Checkpoint 3 does not create final decisions; `VERIFIED`, `UNCERTAIN`, and `REJECTED` remain
reserved for the later Judge/Decision checkpoint.
