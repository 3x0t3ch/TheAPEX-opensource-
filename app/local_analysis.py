# -*- coding: utf-8 -*-
# © 2024-2026 The APEX Community
# Licensed under The APEX Community License (Non-Commercial)
import hashlib
import time
import logging
import base64
from typing import Dict, Any

from .utils import extract_strings, contains_cyrillic

logger = logging.getLogger(__name__)

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    logger.warning("ERR_LIB_PE_NOT_FOUND")

def _0x7a_core_pe(c: bytes) -> Dict[str, Any]:
    """
    [CORE ENGINE] Internals for PE analysis.
    """
    if not PEFILE_AVAILABLE: return {}
    try:
        p = pefile.PE(data=c)
    except Exception: return {}

    # Obfuscated key mapping
    _k = lambda s: base64.b64decode(s).decode()
    _r = {
        _k('ZGxsX3NpZGVfbG9hZGluZw=='): False, # dll_side_loading
        _k('aW5fbWVtb3J5X2V4ZWN1dGlvbg=='): False, # in_memory_execution
        _k('ZGVhZF9kcm9wX3Jlc29sdmVy'): False, # dead_drop_resolver
        'details': []
    }

    try:
        if hasattr(p, 'DIRECTORY_ENTRY_IMPORT'):
            for e in p.DIRECTORY_ENTRY_IMPORT:
                try:
                    dn = e.dll.decode('utf-8', errors='ignore').lower()
                except: continue
                for i in e.imports:
                    if not i.name: continue
                    fn = i.name.decode('utf-8', errors='ignore')
                    # DLL side loading & In-memory indicators
                    if fn in ['LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW', 'GetProcAddress', 'GetModuleHandleA', 'GetModuleHandleW']:
                        _r[_k('ZGxsX3NpZGVfbG9hZGluZw==')] = True
                        _r['details'].append(f"D-LDR: {dn} -> {fn}")
                    if fn in ['VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'CreateThread', 'CreateRemoteThread', 'WriteProcessMemory', 'ReadProcessMemory']:
                        _r[_k('aW5fbWVtb3J5X2V4ZWN1dGlvbg==')] = True
                        _r['details'].append(f"M-MAN: {dn} -> {fn}")

        if hasattr(p, 'sections'):
            for s in p.sections:
                sn = s.Name.decode('utf-8', errors='ignore').strip('\x00')
                if s.Characteristics & 0x20000000:
                    if s.SizeOfRawData > 0x100000:
                        _r[_k('aW5fbWVtb3J5X2V4ZWN1dGlvbg==')] = True
                        _r['details'].append(f"L-SEC: {sn}")

        st = extract_strings(c, min_len=5, max_output_bytes=16384)
        if st:
            ls = st.lower()
            _idx = ['http://', 'https://', 'pastebin.com', 'dropbox.com', 'mega.nz', 'dead.drop', 'dropper', 'resolver']
            for i in _idx:
                if i in ls:
                    _r[_k('ZGVhZF9kcm9wX3Jlc29sdmVy')] = True
                    _r['details'].append(f"T-IND: {i}")
    except Exception as e:
        logger.debug(f"ERR_0x7a: {e}")

    return _r

def analyze_pe_file(c: bytes) -> Dict[str, Any]:
    return _0x7a_core_pe(c)

def analyze_bytes(c: bytes, f: str) -> Dict[str, Any]:
    _h = hashlib.sha256(c).hexdigest()
    _t = []
    if c.startswith(b'MZ'): _t.append('pe_executable')
    if c.startswith(b'\x7fELF'): _t.append('elf_executable')
    if c.startswith(b'%PDF'): _t.append('pdf')
    if c.startswith(b'PK\x03\x04'): _t.append('zip_like')
    
    _s = extract_strings(c, min_len=8, max_output_bytes=8192)
    if _s:
        _ls = _s.lower()
        if any(x in _ls for x in ['powershell', 'eval(', 'base64', 'suspicious']):
            _t.append('suspicious_strings')
            
    _pa = {}
    if c.startswith(b'MZ'):
        _pa = _0x7a_core_pe(c)
        _k = lambda s: base64.b64decode(s).decode()
        if _pa.get(_k('ZGxsX3NpZGVfbG9hZGluZw==')): _t.append('dll_side_loading')
        if _pa.get(_k('aW5fbWVtb3J5X2V4ZWN1dGlvbg==')): _t.append('in_memory_execution')
        if _pa.get(_k('ZGVhZF9kcm9wX3Jlc29sdmVy')): _t.append('dead_drop_resolver')
    
    _v = 'suspicious' if any(x in _t for x in ['pe_executable', 'elf_executable', 'suspicious_strings', 'dll_side_loading', 'in_memory_execution', 'dead_drop_resolver']) else 'unknown'
    
    _res = {
        'filename': f, 
        'item_type': 'file',
        'sha256': _h, 
        'size_bytes': len(c), 
        'verdict': _v, 
        'tags': _t, 
        'strings_snippet': _s or None, 
        'scanned_at': int(time.time())
    }
    
    if _pa:
        _res['pe_analysis'] = _pa
    
    return _res

def build_url_analysis_result(u: str, er: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "url": u,
        "item_type": "url",
        "scanned_at": int(time.time()),
        "external": {k: v for k, v in er.items() if v and not v.get("error")},
        "final_verdict": calculate_final_verdict('unknown', er)
    }

def calculate_final_verdict(lv: str, er: Dict[str, Any]) -> str:
    """[CORE LOGIC] Veredito Final."""
    _v = [r.get('verdict') for r in er.values() if r and 'verdict' in r]
    if lv != 'unknown': _v.append(lv)
    if not _v: return 'unknown'
    
    # Obfuscated priority logic
    _p = {'malicious': 3, 'suspicious': 2, 'clean': 1, 'unknown': 0}
    _m = max([_p.get(x, 0) for x in _v])
    
    for k, v in _p.items():
        if v == _m: return k
    return 'unknown'
