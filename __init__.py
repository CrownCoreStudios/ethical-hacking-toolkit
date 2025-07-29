"""
Ethical Hacking Toolkit

A comprehensive toolkit for ethical hacking, penetration testing, and security analysis.
This package provides a collection of security tools for network analysis,
vulnerability assessment, reverse engineering, and digital forensics.
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"
__license__ = "MIT"

# Import key modules to make them available at the package level
from . import network_analysis
from . import forensic_analysis
from . import reverse_engineering
from . import vulnerability_assessment

__all__ = [
    'network_analysis',
    'forensic_analysis',
    'reverse_engineering',
    'vulnerability_assessment',
]
