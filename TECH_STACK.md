# Technology Stack

## 1. Purpose

This document defines the technologies approved for the initial implementation of the evidence-based security code-review system.

The implementation should remain simple, local, reproducible, and suitable for execution on a standard development laptop.

---

## 2. Core Technologies

| Area                     | Technology   |
| ------------------------ | ------------ |
| Primary language         | Python 3.11+ |
| Backend                  | FastAPI      |
| LLM runtime              | Ollama       |
| Code parsing             | Tree-sitter  |
| Static analysis          | Semgrep      |
| Python security analysis | Bandit       |
| Data validation          | Pydantic     |
| Database                 | SQLite       |
| Database abstraction     | SQLAlchemy   |
| Testing                  | pytest       |
| Frontend                 | React        |
| Frontend tooling         | Vite         |
| Version control          | Git          |

---

## 3. LLM

The initial implementation must support a locally hosted LLM through Ollama.

The specific model should remain configurable through project configuration rather than being hard-coded into the application.

The system must not require a paid cloud LLM API for the core workflow.

---

## 4. Backend

FastAPI will provide the application API and connect the frontend with the research engine.

The backend should remain separated from the core analysis components so that the research engine can also be tested independently.

---

## 5. Code Processing

Tree-sitter will be used for source-code parsing and structural code analysis where appropriate.

The processing pipeline must preserve source-code metadata including file paths and line locations.

---

## 6. Static Analysis

The initial implementation will use:

* Semgrep
* Bandit

Static-analysis results must remain distinguishable from LLM-generated findings and reasoning.

They are treated as independent corroborating evidence.

---

## 7. Data Validation

Pydantic will be used for structured data models and validation.

Important objects will eventually include:

* Review
* Code Unit
* Candidate Finding
* Evidence
* Static Analysis Result
* Decision
* Report
* Evaluation Result

The exact schemas will be defined separately.

---

## 8. Database

SQLite will be used for the initial research prototype.

The database should store research-relevant records without introducing unnecessary infrastructure.

A migration to another database should only occur if implementation requirements demonstrate a genuine need.

---

## 9. Testing

pytest will be used for automated testing.

Tests should cover:

* Code processing
* Agent output handling
* Evidence verification
* Static-analysis integration
* Finding correlation
* Judge decisions
* API behavior
* Evaluation calculations

---

## 10. Frontend

The initial frontend will use React with Vite.

The frontend is secondary to the research engine.

The first interface should prioritize functionality:

1. Upload/select code
2. Start review
3. View review status
4. View findings
5. View evidence
6. View decisions
7. View report

Visual design and advanced dashboard features are not priorities for the initial research prototype.

---

## 11. Initial Language Scope

The first implementation will focus on Python.

The architecture should remain extensible so that JavaScript and Java can be added later.

Supporting additional languages is not required for the first working prototype.

---

## 12. Local-First Requirement

The initial system should operate locally.

The core workflow should not require:

* Paid APIs
* Cloud deployment
* Cloud databases
* GPU hardware
* Kubernetes
* Docker
* Redis
* PostgreSQL
* Vector databases

Additional infrastructure may only be introduced if a documented implementation requirement justifies it.

---

## 13. Configuration

Model selection, analysis settings, paths, thresholds, and other changeable implementation settings should be configurable rather than hard-coded.

Secrets and local environment-specific values must not be committed to Git.

---

## 14. Technology Change Rule

The implementation AI must not introduce major technologies that are not defined in this document without first documenting why the technology is required and what existing component it replaces or complements.

Technology should remain subordinate to the research architecture.
