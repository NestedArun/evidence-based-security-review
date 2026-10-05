# Evidence-Based Security Code Review

## Project Overview

This project investigates an evidence-based multi-agent AI framework for improving the reliability of automated security code review.

The system treats AI-generated security findings as hypotheses that require independent verification. Specialized security analysis agents identify potential vulnerabilities, while an evidence verification layer examines the source code and supporting evidence. Static analysis tools are used as an independent source of corroboration, and a Judge component combines the available evidence to produce a structured security decision with an associated confidence level.

The research focuses on reducing false positives, identifying missed vulnerabilities, improving explainability, and producing security findings that can be traced back to concrete evidence in the source code.

## Core Research Question

Can evidence verification and independent static-analysis corroboration improve the reliability of multi-agent AI-based security code review?

## Core Research Goal

To design, implement, and evaluate a multi-agent security code-review framework in which AI-generated vulnerability findings are independently verified using source-code evidence and static-analysis results before being presented as final findings.

## Research Focus

The initial implementation focuses on:

* AI-assisted security code review
* Multi-agent security analysis
* Source-code evidence verification
* Static-analysis corroboration
* Structured confidence assessment
* Explainable security findings
* Evaluation of false positives and missed vulnerabilities

## Project Status

Research and system design phase.

Implementation will be developed incrementally according to the architecture, research scope, data contracts, and evaluation methodology defined in this repository.

## Important Principle

AI-generated findings are treated as hypotheses, not as automatically trustworthy security conclusions.

Every final finding should be supported by traceable evidence whenever possible.
