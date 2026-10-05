# Evaluation Methodology

## 1. Objective

The evaluation measures whether evidence verification and independent static-analysis corroboration improve the reliability of AI-based security code review.

The evaluation compares simpler AI review configurations against the proposed evidence-based architecture.

---

## 2. Evaluation Configurations

### Configuration A — Single LLM Baseline

Workflow:

Code
→ Single LLM
→ Findings

This configuration does not use specialized multi-agent analysis, evidence verification, or Judge-based verification.

---

### Configuration B — Multi-Agent Baseline

Workflow:

Code
→ Specialized Agents
→ Findings

This configuration uses the specialized security analysis agents but does not apply the full evidence-verification and decision pipeline.

---

### Configuration C — Proposed System

Workflow:

Code
→ Specialized Agents
→ Evidence Verification
→ Semgrep/Bandit
→ Finding Correlation
→ Judge
→ Final Findings

This configuration represents the proposed research system.

---

## 3. Implementation Requirement

The three configurations should be implemented as selectable modes of the same application where practical.

Separate applications are not required.

---

## 4. Ground-Truth Dataset

The initial evaluation dataset should contain manually verified Python security examples.

The initial target is approximately:

* 15–25 vulnerable samples
* 15–25 secure samples

The dataset should cover the five initial vulnerability categories:

1. SQL Injection
2. Command Injection
3. Hardcoded Secrets
4. Weak Cryptography
5. Authentication / Authorization

The initial dataset is intentionally small and will be expanded after the core prototype is operational.

---

## 5. Ground-Truth Integrity

Ground-truth labels must be manually verified or explicitly approved by the researcher.

The system must not automatically modify ground-truth labels.

AI may assist with candidate dataset generation, but candidate examples must be reviewed before becoming ground truth.

---

## 6. Primary Metrics

The initial implementation will calculate:

### Precision

Precision measures the proportion of reported vulnerabilities that are correct.

Precision = TP / (TP + FP)

---

### Recall

Recall measures the proportion of actual vulnerabilities that were detected.

Recall = TP / (TP + FN)

---

### False Positive Rate

False Positive Rate measures the proportion of actual negative cases incorrectly reported as vulnerabilities.

FPR = FP / (FP + TN)

---

### Evidence Completeness

Evidence completeness measures how many expected evidence elements were successfully established for a finding.

Initial evidence elements:

* Source
* Sink
* Data flow
* Security control
* Static-analysis corroboration

Evidence completeness should be calculated from the applicable evidence elements for each finding.

---

## 7. Finding Matching

A predicted finding should be matched against ground truth primarily using:

* Vulnerability category
* Source-code file
* Overlapping source-code location

The initial implementation should avoid complex semantic matching.

---

## 8. Confusion Matrix

The evaluation system should record:

* True Positives
* False Positives
* False Negatives
* True Negatives

These values should be retained so that additional metrics can be calculated later.

---

## 9. Secondary Metrics

The following metrics are part of the broader research evaluation but are not mandatory for the first 75% prototype:

* Confidence calibration
* Review time
* Additional statistical analysis

These should be added after the core evaluation pipeline is operational.

---

## 10. Experimental Comparison

The primary comparison is:

Single LLM
vs.
Multi-Agent
vs.
Proposed Evidence-Based System

The objective is to determine whether the proposed verification architecture improves reliability, particularly by reducing false positives while maintaining or improving recall.

---

## 11. No Fabricated Results

The evaluation system must never generate or hard-code experimental performance values.

All reported metrics must be calculated from actual system outputs and ground-truth data.

Placeholder values may be displayed during development but must be clearly identified as placeholders and must never be presented as experimental results.

---

## 12. Initial Two-Day Target

The immediate objective is to implement a functional evaluation pipeline rather than a statistically comprehensive research study.

The first prototype should be capable of:

1. Running the three review configurations.
2. Comparing predictions against ground truth.
3. Calculating precision.
4. Calculating recall.
5. Calculating false-positive rate.
6. Calculating evidence completeness.
7. Producing a comparison table.

Dataset expansion, confidence calibration, review-time analysis, and deeper statistical analysis will be performed during the subsequent research period.
