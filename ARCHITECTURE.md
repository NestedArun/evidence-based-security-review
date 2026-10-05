# System Architecture

## 1. Purpose

This document defines the architecture of the evidence-based multi-agent AI security code-review system.

The architecture separates AI-based security analysis from evidence verification, independent static-analysis corroboration, decision making, reporting, and evaluation.

The implementation must preserve these architectural boundaries.

---

## 2. Architectural Principle

AI-generated security findings are hypotheses.

A candidate finding must not automatically become a final security conclusion.

The system must attempt to independently verify findings using source-code evidence and static-analysis results before producing a final decision.

---

## 3. System Layers

The system consists of six major layers:

1. Input Layer
2. Code Processing Layer
3. AI Analysis Layer
4. Evidence Verification Layer
5. Judge / Decision Layer
6. Output Layer

---

## 4. Input Layer

### Responsibility

Accept the source code or project that will be reviewed and create a normalized review request.

### Initial scope

Python source-code projects.

### Responsibilities

* Accept source-code input
* Validate input
* Identify the review target
* Create a review request
* Pass the project to the Code Processing Layer

### Must not

* Perform vulnerability analysis
* Generate security findings
* Make security decisions

---

## 5. Code Processing Layer

### Responsibility

Transform the input project into structured code units that can be analyzed while preserving source-code context.

### Processing

Project
→ File Discovery
→ Language Detection
→ File Filtering
→ Parsing
→ Function/Class Extraction
→ Code Chunking
→ Metadata Attachment

### Code-unit metadata

Each code unit should preserve information such as:

* File path
* Language
* Start line
* End line
* Function name, when available
* Class name, when available
* Source code

### Must not

* Decide whether a vulnerability exists
* Produce final security decisions

---

## 6. AI Analysis Layer

### Specialized Agents

The initial architecture contains:

1. Security Review Agent
2. OWASP/CWE Agent
3. Crypto Agent
4. Authentication/Authorization Agent

### Security Review Agent

Performs broad security-oriented analysis and identifies potential security weaknesses.

### OWASP/CWE Agent

Analyzes security findings with emphasis on OWASP categories and CWE classification.

### Crypto Agent

Analyzes cryptographic usage and potential cryptographic weaknesses.

### Authentication/Authorization Agent

Analyzes authentication and authorization mechanisms and potential access-control weaknesses.

### Output

The AI Analysis Layer produces candidate security findings.

Candidate findings are hypotheses and are not final decisions.

### Must not

* Mark findings as verified solely from model reasoning
* Invent source-code evidence
* Produce final confidence without the defined decision process
* Replace the Evidence Verification Layer

---

## 7. Evidence Verification Layer

### Responsibility

Independently examine the source code and determine whether the evidence required to support a candidate finding can be established.

### Evidence categories

The initial evidence model includes:

1. Source evidence
2. Sink evidence
3. Data-flow evidence
4. Security-control evidence
5. Static-analysis evidence

### Source evidence

Identifies the origin of potentially untrusted or security-sensitive data.

### Sink evidence

Identifies a security-sensitive or potentially dangerous operation.

### Data-flow evidence

Determines whether a relevant relationship exists between the source and sink.

### Security-control evidence

Determines whether an appropriate security control exists or is missing.

### Static-analysis evidence

Uses independent static-analysis tools to provide corroborating evidence.

Initial static-analysis tools:

* Semgrep
* Bandit

### Principle

Static-analysis evidence must remain distinguishable from LLM-generated reasoning.

Agreement between multiple LLM agents alone is not considered independent corroboration.

---

## 8. Finding Correlation Layer

Finding correlation operates between evidence verification and final decision making.

### Responsibility

* Group related findings
* Identify duplicate findings
* Associate findings from different agents with the same source-code location
* Preserve the original agent findings
* Produce unified findings for decision making

Multiple agents identifying the same underlying vulnerability must not automatically be reported as multiple independent vulnerabilities.

---

## 9. Judge / Decision Layer

### Responsibility

Combine candidate findings, evidence, static-analysis results, and relevant analysis information to produce a structured decision.

### Initial decision states

* VERIFIED
* UNCERTAIN
* REJECTED

### Judge inputs

* Unified finding
* Source evidence
* Sink evidence
* Data-flow evidence
* Security-control evidence
* Static-analysis results
* Relevant agent analysis

### Judge outputs

* Finding identifier
* Decision status
* Evidence assessment
* Confidence
* Decision rationale
* Remediation information, when available

### Important constraint

The Judge must not rely solely on an arbitrary LLM-generated confidence value.

The decision process must use explicitly defined evidence and decision criteria.

---

## 10. Output Layer

### Responsibility

Present final security findings in a structured and traceable form.

A final finding should preserve the relationship between:

Finding
→ Source Code Location
→ Evidence
→ Static Analysis
→ Decision
→ Confidence
→ Explanation
→ Remediation

### Output information may include

* Finding ID
* Vulnerability category
* CWE
* Severity
* File
* Line range
* Description
* Evidence
* Static-analysis results
* Decision
* Confidence
* Rationale
* Remediation

---

## 11. End-to-End Data Flow

The primary workflow is:

Input Project
→ Code Processing
→ AI Analysis
→ Candidate Findings
→ Evidence Verification
→ Static-Analysis Corroboration
→ Finding Correlation
→ Judge
→ Final Decision
→ Report

---

## 12. Architectural Separation

The following responsibilities must remain distinct:

| Responsibility                 | Component                   |
| ------------------------------ | --------------------------- |
| Project input                  | Input Layer                 |
| Source processing              | Code Processing Layer       |
| Security hypothesis generation | AI Analysis Layer           |
| Source-code verification       | Evidence Verification Layer |
| Static-analysis corroboration  | Semgrep / Bandit            |
| Finding consolidation          | Finding Correlation         |
| Final decision                 | Judge                       |
| Presentation                   | Output Layer                |
| Experimental measurement       | Evaluation Layer            |

---

## 13. Research Boundary

The architecture must preserve the central research concept:

AI-generated security findings are independently examined using traceable source-code evidence and static-analysis corroboration before final decisions are produced.

The implementation must not reduce the system to a simple LLM-only security reviewer.

---

## 14. Implementation Constraint

The coding implementation may change internal class structures, APIs, algorithms, and technical implementation details when necessary.

However, the following architectural responsibilities must not be removed or silently merged:

* Specialized security analysis
* Evidence verification
* Static-analysis corroboration
* Finding correlation
* Judge / decision making
* Structured final output
* Evaluation
