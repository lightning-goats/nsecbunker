# Nsec Bunker Conservative Audit Design

**Date:** 2026-02-27
**Scope:** Local, extension-only audit of `nsecbunker`

## Goal

Audit the full extension for locally verifiable defects, fix only confirmed bugs,
and avoid speculative refactors or cross-LNbits changes.

## Constraints

- Stay inside the `nsecbunker` extension.
- Do not rely on unverified assumptions about the wider LNbits app.
- Preserve existing uncommitted work unless a change is required by a proven bug.
- Prefer minimal fixes over architectural cleanup.

## Approach

The audit proceeds layer by layer:

1. Import and bootstrap paths (`__init__.py`, routers, task registration)
2. Data definitions (`models.py`, `migrations.py`)
3. Core behavior (`helpers.py`, `crud.py`, `services.py`, `discovery.py`)
4. Interfaces (`views.py`, `views_api.py`)
5. Background cleanup (`tasks.py`)
6. Frontend assets (`static/js/index.js`, template)

For each layer:

1. Read the implementation and compare it to the README/specification contract.
2. Reproduce a concrete failure locally, or prove a local contract violation.
3. Add a focused failing test where practical.
4. Apply the smallest fix that addresses the root cause.
5. Re-run the targeted checks before moving on.

## Non-Goals

- No feature expansion.
- No broad refactors for style or preference.
- No fixes based only on hypothetical integration behavior outside this repo.

## Verification

Verification will be incremental:

- Targeted import/compile checks for Python modules
- Targeted pytest coverage for reproduced bugs
- A final regression pass over the tests added during the audit

## Expected Deliverable

A small set of minimal, local bug fixes with matching regression coverage and a
clear record of anything that could not be verified in this environment.
