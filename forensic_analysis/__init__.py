""
Forensic Analysis Module

This module contains tools for digital forensics, including:
- Memory analysis
- Browser history extraction
- File type identification
- EXIF data viewing
- File hashing
"""

from .memory_analyzer import analyze_memory
from .browser_history import extract_browser_history
from .file_type_identifier import identify_file_type
from .exif_viewer import view_exif_data
from .hash_calculator_gui import calculate_file_hash

__all__ = [
    'analyze_memory',
    'extract_browser_history',
    'identify_file_type',
    'view_exif_data',
    'calculate_file_hash',
]
