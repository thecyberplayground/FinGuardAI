# FinGuardAI Codebase Cleanup

## Overview

This document describes the cleanup performed on the FinGuardAI codebase to improve maintainability and reduce clutter. The goal was to identify and archive redundant, obsolete, or test-only files while maintaining all core functionality.

## Changes Made

1. **Created Archive Structure**
   - `/backend/archive/` - Main archive directory
   - `/backend/archive/integrated_system/` - Archived scanner implementations
   - `/backend/archive/ml/` - Archived ML components
   - `/backend/archive/test_files/` - Archived test scripts
   - `/backend/archive/ml/remediation/` - Archived remediation components

2. **Archived Files**
   - **Scanner Implementations**:
     - `simple_scanner.py` - Superseded by `vulnerability_scanner.py`
     - `direct_scanner.py` - Functionality merged into main `scan.py` 
     - `run_scan.py` - Redundant with root-level `scan.py`

   - **ML Components**:
     - `train_model_synthetic.py` - Uses synthetic data which conflicts with our approach
     - `train_with_kdd.py` - Older dataset training
     - `train_model_with_nslkdd.py` - Superseded by newer training
     - Various `download_*.py` files - Dataset downloaders not needed in production

   - **Test & Analysis**:
     - All `test_*.py` files - Only needed during development
     - `analyze_portal_lcu.py` - One-off analysis script
     - `real_predictive_analysis.py` - Prototype
     - `run_predictive_analysis.py` - Redundant with integrated scanning

   - **Remediation**:
     - `financial_recommendations.py` - Not integrated with main scan flow
     - `test_recommendations.py` - Testing only

## Core Components Retained

The following components form the core of our scanning functionality:

1. **Root-level Scan Command**
   - `/scan.py` - Main entry point for all scanning operations

2. **Scanner Components**
   - `/backend/integrated_system/vulnerability_scanner.py` - Core scanner
   - `/backend/integrated_system/enhanced_report.py` - Report generation
   - `/backend/integrated_system/vulnerability_predictor.py` - ML prediction

3. **ML Framework**
   - Key ML components for threat detection
   - Essential remediation modules referenced by core functionality

## Future Guidelines

1. **New Development**
   - Add new functionality directly to core components when possible
   - Avoid creating new files for minor features
   - Follow the established patterns in existing code

2. **Testing**
   - Keep test scripts separate from production code
   - Consider adding a proper `/tests` directory with unit tests

3. **Maintenance**
   - Review and archive unused code periodically
   - Update documentation when code organization changes

## Guiding Principles

This cleanup supports our guiding principles:
- Keep the codebase clean and organized
- Avoid duplication of code
- Focus on the areas of code relevant to the task
- Support all environments (dev, test, prod)
