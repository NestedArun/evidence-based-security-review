# Project Rules

## 1. Research Integrity

This project is a research implementation.

The implementation must follow the research objectives, architecture, scope, data contracts, and evaluation methodology defined in this repository.

The implementation AI must not silently change the research methodology.

If a design change appears necessary, it must be explicitly identified and documented rather than silently introduced.

---

## 2. AI Findings Are Hypotheses

An AI-generated security finding must initially be treated as a hypothesis.

An LLM identifying a possible vulnerability does not by itself constitute sufficient evidence that the vulnerability exists.

The system must distinguish between:

* AI-generated hypothesis
* Supporting evidence
* Independent static-analysis corroboration
* Final security decision

---

## 3. Evidence Must Be Traceable

Security findings should reference concrete evidence from the analyzed source code whenever possible.

Evidence should preserve relevant information such as:

* File
* Line or code location
* Variable or function
* Source of potentially untrusted data
* Security-sensitive operation or sink
* Relevant data-flow relationship
* Security control, when applicable
* Static-analysis result, when applicable

The system must not fabricate source-code evidence.

---

## 4. Static Analysis Is Independent Corroboration

Static-analysis results must be treated as an independent source of corroborating evidence.

Agreement between multiple AI agents alone must not be considered independent proof.

Static-analysis results must remain distinguishable from LLM-generated reasoning.

---

## 5. Final Decisions Must Be Explainable

A final security decision should be supported by structured evidence and a clear explanation.

The system should distinguish between findings that are:

* Verified
* Uncertain
* Rejected

The exact decision mechanism will be defined by the research design and evaluation methodology.

---

## 6. Confidence Must Be Structured

Confidence must not be an arbitrary number generated without justification.

The system should derive confidence from defined evidence and decision criteria.

The methodology for confidence calculation must remain explicit and reproducible.

---

## 7. Ground Truth Must Not Be Automatically Changed

Ground-truth evaluation data must not be modified automatically by the AI system.

Ground-truth labels must be manually verified or explicitly approved by the researcher.

AI-generated candidate examples may be used as assistance during dataset preparation, but they must not automatically become ground truth.

---

## 8. Research Results Must Not Be Fabricated

The implementation must never invent:

* Accuracy
* Precision
* Recall
* F1 score
* False-positive rate
* Evidence completeness
* Confidence calibration
* Review time
* Experimental results

Experimental results must only be produced from actual executed experiments and recorded evaluation data.

---

## 9. Preserve Research Scope

The initial research scope must not silently expand during implementation.

New:

* vulnerability categories
* programming languages
* agents
* datasets
* evaluation metrics
* analysis tools
* system capabilities

must be explicitly documented before becoming part of the research scope.

---

## 10. Reproducibility

The system should be designed so that an experiment can be repeated using the same:

* Source code
* Dataset
* Configuration
* Model configuration
* Analysis tools
* Evaluation procedure

Whenever technically possible, the system should record the configuration used for an experiment.

---

## 11. Local-First Development

The initial system should be designed to operate locally.

Mandatory dependence on paid cloud APIs should be avoided.

External services must not become required for the core research workflow unless explicitly approved and documented.

---

## 12. Separation of Responsibilities

The following responsibilities must remain conceptually separate:

1. Code preprocessing
2. AI security analysis
3. Evidence verification
4. Static analysis
5. Finding correlation
6. Decision making
7. Reporting
8. Evaluation

Components may communicate with each other through defined interfaces, but their research responsibilities must remain distinguishable.

---

## 13. Implementation AI Restrictions

The coding AI may:

* Implement the defined architecture
* Write application code
* Create tests
* Implement APIs
* Implement agents
* Integrate approved analysis tools
* Implement database storage
* Implement the user interface
* Refactor implementation code
* Fix implementation bugs

The coding AI must not:

* Change the research question
* Remove the evidence-verification concept
* Remove independent static-analysis corroboration
* Replace the proposed methodology with a simpler LLM-only reviewer
* Automatically modify ground truth
* Invent experimental results
* Claim that a finding is verified without applying the defined verification process
* Add major research components without documenting the change

---

## 14. Implementation Before Optimization

Correctness, traceability, reproducibility, and research validity take priority over:

* UI polish
* Performance optimization
* Model size
* Feature count
* Deployment complexity

The first implementation should establish a correct research pipeline before optimization.

---

## 15. Documentation Requirement

Important architectural, methodological, and experimental decisions must be documented in the repository.

The repository should remain understandable to another researcher who did not participate in the original implementation.

---

## 16. Change Principle

When implementation constraints conflict with the research design:

1. Identify the conflict.
2. Document the conflict.
3. Propose alternatives.
4. Do not silently change the research methodology.
