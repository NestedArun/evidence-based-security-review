# Backend (Checkpoint 1: foundation)

FastAPI + SQLAlchemy/SQLite + Pydantic + Tree-sitter code processing. No LLM, evidence,
static-analysis, correlation, judge or evaluation logic yet (Checkpoints 2-6).

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

A review stays `RUNNING` after processing because later pipeline stages do not exist yet;
`COMPLETED` is reserved for a finished pipeline. Submitted code is only read, never executed.

## Settings (env vars, all optional)
`EBSR_DATABASE_URL` (default `sqlite:///backend/data/review.db`), `EBSR_PROJECT_CONFIG`,
`EBSR_MAX_FILE_BYTES` (1 000 000), `EBSR_MAX_UNIT_LINES` (200).

## Code-unit layout
`function` / `method` (decorators included), `class` (class-body statements between methods),
`module` (top-level statements between definitions). Units never overlap; long units are split
into line chunks (`chunk_index`). Line numbers are 1-based and match the original file.
