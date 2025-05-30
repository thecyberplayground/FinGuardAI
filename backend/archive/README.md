# FinGuardAI Archive Directory

This directory contains files that were part of earlier development iterations but have been superseded by newer implementations or are no longer actively used in the core scanning functionality.

## Directory Structure

- **integrated_system/** - Earlier scanner implementations
  - `simple_scanner.py` - Replaced by the more comprehensive `vulnerability_scanner.py`
  - `direct_scanner.py` - Functionality merged into main `scan.py`
  - `run_scan.py` - Superseded by root-level `scan.py`

- **ml/** - Machine learning related code that's no longer in active use
  - `train_model_synthetic.py` - Uses synthetic data which doesn't align with our current approach
  - `train_with_kdd.py` - Older dataset training methods
  - `train_model_with_nslkdd.py` - Redundant with newer training methods
  - `download_*.py` - Dataset downloaders used during initial development
  - **remediation/** - Earlier remediation implementations
    - `financial_recommendations.py` - Financial sector specific recommendations
    - `test_recommendations.py` - Testing file for recommendations

- **test_files/** - Testing scripts that were used during development

- Other files:
  - `analyze_portal_lcu.py` - One-off analysis script
  - `real_predictive_analysis.py` - Prototype analysis tool
  - `run_predictive_analysis.py` - Redundant with integrated scanning functionality

## Purpose

These files are kept for reference but are not part of the active codebase. This helps maintain a cleaner, more focused main codebase while preserving historical implementations.

## Note

If you need to restore any of these files to active use, please make sure to also update any import statements in files that reference them.
