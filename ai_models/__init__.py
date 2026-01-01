"""
AI Models Package
Contains AI-powered security analysis modules using Ollama
"""

from .ollama_client import OllamaClient
from .vuln_analyzer import VulnerabilityAnalyzer
from .exploit_suggester import ExploitSuggester
from .attack_planner import AttackPlanner

__all__ = ["OllamaClient", "VulnerabilityAnalyzer", "ExploitSuggester", "AttackPlanner"]

__version__ = "1.0.0"
