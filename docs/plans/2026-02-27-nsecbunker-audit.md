# Nsec Bunker Audit Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Audit the `nsecbunker` extension conservatively, fix only locally proven bugs, and add targeted regression coverage for each confirmed defect.

**Architecture:** Work from the outside in: establish that the extension imports cleanly, then inspect each runtime layer (data, services, API, tasks, frontend) for locally reproducible defects. Each fix should follow TDD: create the smallest failing test or failing import check, implement the minimal root-cause fix, and rerun only the relevant checks before moving forward.

**Tech Stack:** Python, FastAPI/LNbits extension patterns, pytest, JavaScript (frontend assets)

---

### Task 1: Baseline Import Audit

**Files:**
- Modify: `__init__.py`
- Modify: `views.py`
- Modify: `views_api.py`
- Modify: `tasks.py`
- Test: `tests/test_imports.py`

**Step 1: Write the failing test**

```python
import importlib


def test_extension_modules_import():
    for module in (
        "nsecbunker.__init__",
        "nsecbunker.views",
        "nsecbunker.views_api",
        "nsecbunker.tasks",
    ):
        importlib.import_module(module)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_imports.py -q`
Expected: FAIL if any module has import-time errors or invalid symbols.

**Step 3: Write minimal implementation**

```python
# Adjust only the import-time bug that the failing test proves,
# such as a bad dependency import, router reference, or task registration path.
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_imports.py -q`
Expected: PASS

**Step 5: Commit**

```bash
git add tests/test_imports.py __init__.py views.py views_api.py tasks.py
git commit -m "fix: resolve nsecbunker import-time failures"
```

### Task 2: Data Model and Migration Audit

**Files:**
- Modify: `models.py`
- Modify: `migrations.py`
- Test: `tests/test_models_and_migrations.py`

**Step 1: Write the failing test**

```python
from nsecbunker import models, migrations


def test_model_exports_and_migration_names():
    assert hasattr(models, "NsecBunkerKey")
    assert hasattr(models, "NsecBunkerPermission")
    assert hasattr(models, "NsecBunkerSigningLog")
    assert hasattr(migrations, "m001_initial")
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_models_and_migrations.py -q`
Expected: FAIL if expected models or migration entrypoints are missing or broken.

**Step 3: Write minimal implementation**

```python
# Fix only the mismatched names, broken field definitions, or migration
# structure exposed by the failing test.
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_models_and_migrations.py -q`
Expected: PASS

**Step 5: Commit**

```bash
git add tests/test_models_and_migrations.py models.py migrations.py
git commit -m "fix: align nsecbunker models and migrations"
```

### Task 3: Helper and Service Contract Audit

**Files:**
- Modify: `helpers.py`
- Modify: `services.py`
- Modify: `crud.py`
- Modify: `discovery.py`
- Test: `tests/test_services.py`

**Step 1: Write the failing test**

```python
import pytest

from nsecbunker import helpers


def test_parse_private_key_rejects_invalid_input():
    with pytest.raises(ValueError):
        helpers.parse_private_key("not-a-key")
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_services.py -q`
Expected: FAIL if helper validation or service contracts are broken.

**Step 3: Write minimal implementation**

```python
# Implement the smallest change needed to make the specific helper/service
# contract pass, then add one test per newly confirmed bug.
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_services.py -q`
Expected: PASS

**Step 5: Commit**

```bash
git add tests/test_services.py helpers.py services.py crud.py discovery.py
git commit -m "fix: correct nsecbunker helper and service bugs"
```

### Task 4: API and View Audit

**Files:**
- Modify: `views_api.py`
- Modify: `views.py`
- Modify: `templates/nsecbunker/index.html`
- Test: `tests/test_views_api.py`

**Step 1: Write the failing test**

```python
from nsecbunker.views_api import api_router


def test_api_router_is_defined():
    assert api_router is not None
    assert api_router.routes
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_views_api.py -q`
Expected: FAIL if API routes are not registered correctly or view imports break.

**Step 3: Write minimal implementation**

```python
# Fix only the concrete route, schema, or view bug demonstrated by the test.
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_views_api.py -q`
Expected: PASS

**Step 5: Commit**

```bash
git add tests/test_views_api.py views_api.py views.py templates/nsecbunker/index.html
git commit -m "fix: repair nsecbunker API and view wiring"
```

### Task 5: Frontend and Task Safety Audit

**Files:**
- Modify: `static/js/index.js`
- Modify: `tasks.py`
- Test: `tests/test_static_contracts.py`

**Step 1: Write the failing test**

```python
from pathlib import Path


def test_frontend_contains_expected_bootstrap_hooks():
    source = Path("static/js/index.js").read_text()
    assert "window.app = Vue.createApp" in source
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_static_contracts.py -q`
Expected: FAIL if the frontend bootstrap or task hooks violate the extension's own template contract.

**Step 3: Write minimal implementation**

```python
# Apply the narrowest JS or task fix needed for the proven mismatch.
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_static_contracts.py -q`
Expected: PASS

**Step 5: Commit**

```bash
git add tests/test_static_contracts.py static/js/index.js tasks.py
git commit -m "fix: restore nsecbunker frontend and task contracts"
```

### Task 6: Final Regression Verification

**Files:**
- Modify: `tests/test_imports.py`
- Modify: `tests/test_models_and_migrations.py`
- Modify: `tests/test_services.py`
- Modify: `tests/test_views_api.py`
- Modify: `tests/test_static_contracts.py`

**Step 1: Run the full targeted test set**

```bash
pytest \
  tests/test_imports.py \
  tests/test_models_and_migrations.py \
  tests/test_services.py \
  tests/test_views_api.py \
  tests/test_static_contracts.py -q
```

**Step 2: Verify all tests pass**

Run: `pytest tests/test_imports.py tests/test_models_and_migrations.py tests/test_services.py tests/test_views_api.py tests/test_static_contracts.py -q`
Expected: PASS

**Step 3: Run a compile check**

```bash
python3 -m compileall .
```

**Step 4: Verify the compile check passes**

Run: `python3 -m compileall .`
Expected: PASS with no syntax errors in the extension files.

**Step 5: Commit**

```bash
git add tests
git commit -m "test: add nsecbunker audit regression coverage"
```
