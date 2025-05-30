"""
FinGuardAI - Remediation Module

This module provides security remediation recommendations based on detected threats.
"""

from .recommendations import get_recommendations_for_threat, get_remediation_engine

__all__ = ['get_recommendations_for_threat', 'get_remediation_engine']
