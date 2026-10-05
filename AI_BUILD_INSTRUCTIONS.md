# AI BUILD INSTRUCTIONS

## 1. ROLE

You are the primary coding agent for this project.

Your job is to implement the system described in this repository.

The research architecture and scope have already been decided.

**Implement the existing design. Do not redesign the research.**

---

## 2. READ BEFORE CODING

Read these files first:

* `README.md`
* `PROJECT_RULES.md`
* `ARCHITECTURE.md`
* `TECH_STACK.md`
* `RESEARCH_SCOPE.md`
* `EVALUATION.md`
* `configuration/project_config.json`
* all files under `schemas/`
* `dataset/ground_truth.json`
* sample files under `dataset/`

Treat these files as the specification.

If something is unclear, prefer the simplest implementation consistent with the existing specification.

---

## 3. CORE SYSTEM

The system is an evidence-based AI security code-review framework.

Required pipeline:

```text
Project
  ↓
Code Processing
  ↓
Specialized AI Agents
  ↓
Candidate Findings
  ↓
Evidence Verification
  ↓
Semgrep + Bandit
  ↓
Finding Correlation
  ↓
Judge
  ↓
VERIFIED / UNCERTAIN / REJECTED
  ↓
Report + Evaluation
```

Initial scope:

* Python
* SQL Injection
* Command Injection
* Hardcoded Secrets
* Weak Cryptography
* Authentication/Authorization
* Ollama
* Semgrep
* Bandit
* FastAPI
* SQLite
* React/Vite

Follow `RESEARCH_SCOPE.md` for the authoritative scope.

---

## 4. IMPORTANT RESEARCH RULES

AI findings are hypotheses.

Do not allow an LLM to directly declare a finding verified.

Final decisions must use evidence.

Multiple LLM agents agreeing is **not** independent verification.

Static-analysis results must remain distinguishable from LLM results.

Never fabricate:

* findings
* evidence
* static-analysis results
* confidence
* evaluation metrics

Do not automatically modify:

`dataset/ground_truth.json`

---

## 5. SCHEMAS

The JSON schemas under `schemas/` are the canonical data contracts.

Do not invent alternative undocumented formats.

Important separation:

```text
Finding
    ↓
Evidence
    ↓
Static Result
    ↓
Decision
```

Do not put final confidence/decision into the finding object unless the schema explicitly requires it.

---

## 6. IMPLEMENTATION ORDER

Build in checkpoints.

### Checkpoint 1

Backend foundation:

* project structure
* FastAPI
* SQLite
* SQLAlchemy
* models
* schemas
* project/file processing
* basic API
* tests

### Checkpoint 2

AI:

* Ollama client
* four logical agents
* structured finding generation
* validation/error handling

### Checkpoint 3

Evidence:

* source evidence
* sink evidence
* data-flow evidence
* security-control evidence

### Checkpoint 4

Static analysis:

* Semgrep
* Bandit
* normalized results
* finding correlation

### Checkpoint 5

Decision:

* Judge
* evidence score
* confidence
* VERIFIED / UNCERTAIN / REJECTED
* report

### Checkpoint 6

Evaluation:

* single-LLM baseline
* multi-agent baseline
* proposed system
* precision
* recall
* false-positive rate
* evidence completeness

### Checkpoint 7

Frontend:

* dashboard
* review page
* findings
* evidence
* decisions
* evaluation results

---

## 7. TESTING RULE

After every checkpoint:

1. run tests
2. fix errors
3. rerun tests
4. verify previous functionality
5. continue

Do not wait until the entire project is finished before testing.

---

## 8. PRIORITY

The immediate goal is a working research prototype, not a production product.

Prioritize:

```text
Working end-to-end pipeline
>
Research correctness
>
Evidence traceability
>
Evaluation
>
Testing
>
UI polish
```

Do not spend time on:

* cloud deployment
* CI/CD
* advanced RAG
* vector databases
* fine-tuning
* multiple LLM providers
* IDE integration
* GitHub integration
* Java/JavaScript support
* autonomous code modification

These are future work.

---

## 9. ERROR HANDLING

If Ollama, Semgrep, or Bandit is unavailable:

* report the actual error
* do not fabricate results
* do not silently mark analysis as successful

If an LLM produces invalid structured output:

* retry/recover where reasonable
* validate again
* otherwise report the failure

---

## 10. SECURITY

Never execute submitted Python source code.

The system analyzes source code; it should not run the analyzed application.

Keep execution of external analysis tools controlled.

---

## 11. FINAL ACCEPTANCE TEST

The prototype is successful when this works:

```text
Upload/select project
      ↓
Select analysis configuration
      ↓
Process code
      ↓
Run AI agents
      ↓
Generate findings
      ↓
Verify evidence
      ↓
Run Semgrep/Bandit
      ↓
Correlate
      ↓
Judge
      ↓
Display final decisions
      ↓
Run evaluation
      ↓
Display actual metrics
```

Build the smallest complete implementation that demonstrates the research contribution.

Do not add unnecessary features.

## FINAL RULE

**Read the repository first. Implement the existing design. Work checkpoint-by-checkpoint. Test continuously. Do not redesign the research.**
