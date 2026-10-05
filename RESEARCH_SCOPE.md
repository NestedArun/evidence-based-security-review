# Research Scope

## 1. Initial Implementation Scope

The initial implementation focuses on evidence-based security code review for Python projects.

The system is designed to investigate whether source-code evidence and independent static-analysis corroboration can improve the reliability of AI-generated security findings.

---

## 2. Programming Language

### Initial language

Python.

The architecture should remain extensible to additional languages, but Java and JavaScript are outside the initial implementation scope.

---

## 3. Vulnerability Categories

The initial implementation covers five categories:

| ID  | Category                       | Example CWE                            |
| --- | ------------------------------ | -------------------------------------- |
| V01 | SQL Injection                  | CWE-89                                 |
| V02 | Command Injection              | CWE-78                                 |
| V03 | Hardcoded Secrets              | CWE-798 / related weaknesses           |
| V04 | Weak Cryptography              | CWE-327 / related weaknesses           |
| V05 | Authentication / Authorization | CWE-287 / CWE-862 / related weaknesses |

The specific CWE assigned to an individual finding must correspond to the actual weakness identified.

---

## 4. Security Analysis Agents

The system contains four logical specialized analysis agents:

1. Security Review Agent
2. OWASP/CWE Agent
3. Crypto Agent
4. Authentication/Authorization Agent

These agents use the same local LLM runtime with different specialized responsibilities and prompts.

Multiple agents do not constitute independent verification by themselves.

---

## 5. LLM

The initial system uses one locally hosted LLM through Ollama.

The specific model is configurable.

The system must not require multiple simultaneous LLMs.

---

## 6. Evidence Verification

Candidate findings must be examined using structured evidence.

Initial evidence categories:

1. Source evidence
2. Sink evidence
3. Data-flow evidence
4. Security-control evidence
5. Static-analysis evidence

Evidence should reference concrete source-code locations whenever applicable.

---

## 7. Static Analysis

The initial implementation uses:

* Semgrep
* Bandit

Static-analysis results are treated as independent corroborating evidence and must remain distinguishable from LLM-generated reasoning.

---

## 8. Final Decision States

Every candidate finding reaching the decision stage should receive one of:

* VERIFIED
* UNCERTAIN
* REJECTED

The exact decision and confidence calculation methodology will be defined separately in the evaluation/design specifications.

---

## 9. Severity

The initial severity levels are:

* CRITICAL
* HIGH
* MEDIUM
* LOW

Severity and confidence are separate concepts.

Severity represents the potential impact of the vulnerability.

Confidence represents the strength of the evidence supporting the finding.

---

## 10. Initial Review Workflow

The initial workflow is:

Source Code
→ Code Processing
→ Specialized AI Analysis
→ Candidate Findings
→ Evidence Verification
→ Semgrep/Bandit Corroboration
→ Finding Correlation
→ Judge
→ Final Decision
→ Report

---

## 11. Out of Scope

The initial implementation does not include:

* Java analysis
* JavaScript analysis
* C/C++ analysis
* Binary analysis
* Malware analysis
* Android analysis
* Cloud deployment
* CI/CD integration
* IDE plugins
* GitHub App integration
* Real-time scanning
* Automatic source-code modification
* Model fine-tuning
* Multiple LLM models
* Vector databases
* Advanced RAG systems
* Autonomous remediation

These may be considered future extensions but are not part of the initial research implementation.

---

## 12. Scope Change Rule

Any expansion of programming languages, vulnerability categories, agents, tools, or major system capabilities must be explicitly documented.

The implementation AI must not silently expand the research scope.
