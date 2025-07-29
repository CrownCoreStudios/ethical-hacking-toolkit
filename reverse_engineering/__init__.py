""
Reverse Engineering Module

This module contains tools for reverse engineering, including:
- PE (Portable Executable) file analysis
- Code disassembly
- String extraction from binaries
- XOR cipher analysis
"""

from .pe_analyzer import analyze_pe_file
from .disassembler import disassemble_code
from .string_extractor import extract_strings
from .xor_cipher import xor_decrypt, xor_encrypt, brute_force_xor

__all__ = [
    'analyze_pe_file',
    'disassemble_code',
    'extract_strings',
    'xor_decrypt',
    'xor_encrypt',
    'brute_force_xor',
]
