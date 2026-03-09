"""
feature_extractor.py
────────────────────
Extracts features that exactly match the schemas stored in the
real model artifact feature-list pickle files:

  EXE  : 2381 features  F1 … F2381  (EMBER-style byte/PE features)
  PDF  : 29  named features
  DOCX : 30  named features
  GEN  : 20  named features
"""

import os
import re
import math
import struct
import hashlib
from collections import Counter

# ═══════════════════════════════════════════════════════════════
#  Low-level helpers
# ═══════════════════════════════════════════════════════════════

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _byte_histogram(data: bytes) -> list:
    """Normalised byte-frequency histogram (256 bins)."""
    n = len(data) or 1
    c = Counter(data)
    return [c.get(i, 0) / n for i in range(256)]


def _byte_entropy_histogram(data: bytes, window: int = 2048, step: int = 1024) -> list:
    """
    Sliding-window entropy histogram.
    256 bins, each bin = avg entropy of windows whose dominant byte
    falls in that value range.
    """
    if len(data) < window:
        data = data + b'\x00' * (window - len(data))

    bins      = [[] for _ in range(256)]
    positions = range(0, len(data) - window + 1, step)
    if not positions:
        positions = [0]

    for start in positions:
        chunk = data[start: start + window]
        dom   = Counter(chunk).most_common(1)[0][0]   # dominant byte
        ent   = _entropy(chunk)
        bins[dom].append(ent)

    return [float(sum(b) / len(b)) if b else 0.0 for b in bins]


def _printable_strings(data: bytes, min_len: int = 5) -> list:
    """Extract printable ASCII strings from raw bytes."""
    pattern = rb'[ -~]{' + str(min_len).encode() + rb',}'
    return re.findall(pattern, data)


def _count_patterns(data: bytes, *patterns) -> list:
    """Count occurrences of each byte pattern in data."""
    return [data.count(p if isinstance(p, bytes) else p.encode()) for p in patterns]


# ═══════════════════════════════════════════════════════════════
#  EXE Feature Extraction  →  F1 … F2381
# ═══════════════════════════════════════════════════════════════

_COMMON_DLLS = [
    'kernel32', 'user32', 'ntdll', 'advapi32', 'shell32', 'ole32',
    'oleaut32', 'ws2_32', 'wininet', 'urlmon', 'gdi32', 'msvcrt',
    'comctl32', 'shlwapi', 'psapi', 'winspool', 'comdlg32', 'version',
    'setupapi', 'crypt32', 'netapi32', 'wldap32', 'secur32', 'bcrypt',
    'ncrypt', 'dbghelp', 'imagehlp', 'winmm', 'dsound', 'd3d9',
    'opengl32', 'glu32', 'msvcp140', 'vcruntime140', 'ucrtbase',
]

_SUSPICIOUS_APIS = [
    'virtualalloc', 'virtualallocex', 'writeprocessmemory', 'readprocessmemory',
    'createremotethread', 'shellexecute', 'shellexecuteex', 'urldownloadtofile',
    'winexec', 'regsetvalue', 'openprocess', 'virtualprotect', 'loadlibrary',
    'getprocaddress', 'createprocess', 'setwindowshookex', 'getasynckeystate',
    'keybd_event', 'mouse_event', 'cryptencrypt', 'cryptdecrypt',
    'internetopen', 'internetconnect', 'httpsendrequest', 'internetreadfile',
    'wsasocket', 'connect', 'send', 'recv', 'bind', 'listen',
    'createfile', 'writefile', 'deletefile', 'copyfile', 'movefile',
    'createservice', 'startservice', 'regcreatekey', 'regdeletekey',
    'isdebuggerpresent', 'checkremotedebugger', 'outputdebugstring',
]


def extract_exe_features(filepath: str) -> dict:
    """
    Returns a dict  { 'F1': float, 'F2': float, … 'F2381': float }.
    Feature layout:
      F1   – F256  : byte histogram          (256)
      F257 – F512  : byte entropy histogram  (256)
      F513 – F616  : string features         (104)
      F617 – F626  : general PE info         (10)
      F627 – F688  : PE header fields        (62)
      F689 – F943  : section info  (≤5 sct)  (255)
      F944 – F2223 : import hashes           (1280)
      F2224– F2351 : export hashes           (128)
      F2352– F2381 : misc extras             (30)
    """
    feats = [0.0] * 2381

    try:
        with open(filepath, 'rb') as fh:
            data = fh.read()
    except Exception:
        return {f'F{i + 1}': 0.0 for i in range(2381)}

    # ── Group 1: Byte histogram  F1-F256 ─────────────────────────
    bh = _byte_histogram(data)
    for i, v in enumerate(bh):
        feats[i] = v                          # index 0-255 → F1-F256

    # ── Group 2: Byte entropy histogram  F257-F512 ───────────────
    beh = _byte_entropy_histogram(data)
    for i, v in enumerate(beh):
        feats[256 + i] = v                    # index 256-511 → F257-F512

    # ── Group 3: String features  F513-F616 ─────────────────────
    base = 512
    strings = _printable_strings(data)
    num_strings     = len(strings)
    str_lens        = [len(s) for s in strings] or [0]
    avg_str_len     = sum(str_lens) / len(str_lens)
    max_str_len     = max(str_lens)
    min_str_len     = min(str_lens)

    all_str = b' '.join(strings).lower()
    num_paths   = all_str.count(b'c:\\')   + all_str.count(b'\\\\')
    num_mz      = data.count(b'MZ')
    num_urls    = all_str.count(b'http://') + all_str.count(b'https://')
    num_reg     = all_str.count(b'hkey_') + all_str.count(b'registry')
    num_exes    = sum(all_str.count(ext.encode()) for ext in ['.exe', '.dll', '.bat', '.cmd', '.ps1'])
    num_ips     = len(re.findall(rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', data))

    printable_count = sum(1 for b in data if 0x20 <= b < 0x7f)
    printable_ratio = printable_count / (len(data) or 1)

    sus_kw_count = sum(data.lower().count(api.encode()) for api in _SUSPICIOUS_APIS)

    str_feats = [
        min(num_strings,  10000) / 10000,
        min(avg_str_len,  1000)  / 1000,
        min(max_str_len,  10000) / 10000,
        min(min_str_len,  100)   / 100,
        min(num_paths,    500)   / 500,
        min(num_mz,       50)    / 50,
        min(num_urls,     500)   / 500,
        min(num_reg,      500)   / 500,
        min(num_exes,     500)   / 500,
        min(num_ips,      500)   / 500,
        printable_ratio,
        min(sus_kw_count, 100)   / 100,
    ]
    # Pad to 104 features
    str_feats += [0.0] * (104 - len(str_feats))
    for i, v in enumerate(str_feats[:104]):
        feats[base + i] = v

    # ── Group 4: General PE info  F617-F626 ─────────────────────
    base = 616
    gen_feats = [0.0] * 10
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=False)

        gen_feats[0] = len(data) / (1024 * 1024)                         # file_size_mb
        gen_feats[1] = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0.0
        gen_feats[2] = len(pe.DIRECTORY_ENTRY_IMPORT) / 100.0 if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0.0
        gen_feats[3] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) / 200.0 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0.0
        gen_feats[4] = 1.0 if pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress else 0.0  # has_relocations
        gen_feats[5] = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0.0
        gen_feats[6] = 1.0 if pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress else 0.0  # has_signature
        gen_feats[7] = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_TLS') else 0.0
        gen_feats[8] = pe.FILE_HEADER.NumberOfSymbols / 1000.0
        gen_feats[9] = _entropy(data) / 8.0
        pe.close()
    except Exception:
        gen_feats[0] = len(data) / (1024 * 1024)
        gen_feats[9] = _entropy(data) / 8.0

    for i, v in enumerate(gen_feats):
        feats[base + i] = v

    # ── Group 5: Header fields  F627-F688 ────────────────────────
    base = 626
    hdr_feats = [0.0] * 62
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        hdr_feats[0]  = pe.FILE_HEADER.Machine / 0xFFFF
        hdr_feats[1]  = pe.FILE_HEADER.NumberOfSections / 100.0
        hdr_feats[2]  = pe.FILE_HEADER.TimeDateStamp / 0xFFFFFFFF
        hdr_feats[3]  = pe.FILE_HEADER.Characteristics / 0xFFFF
        hdr_feats[4]  = pe.OPTIONAL_HEADER.Magic / 0xFFFF
        hdr_feats[5]  = pe.OPTIONAL_HEADER.MajorLinkerVersion / 100.0
        hdr_feats[6]  = pe.OPTIONAL_HEADER.MinorLinkerVersion / 100.0
        hdr_feats[7]  = min(pe.OPTIONAL_HEADER.SizeOfCode, 10**8) / 10**8
        hdr_feats[8]  = min(pe.OPTIONAL_HEADER.SizeOfInitializedData, 10**8) / 10**8
        hdr_feats[9]  = min(pe.OPTIONAL_HEADER.SizeOfUninitializedData, 10**8) / 10**8
        hdr_feats[10] = pe.OPTIONAL_HEADER.AddressOfEntryPoint / 0xFFFFFFFF
        hdr_feats[11] = pe.OPTIONAL_HEADER.BaseOfCode / 0xFFFFFFFF
        hdr_feats[12] = min(pe.OPTIONAL_HEADER.ImageBase, 10**12) / 10**12
        hdr_feats[13] = min(pe.OPTIONAL_HEADER.SectionAlignment, 10**6) / 10**6
        hdr_feats[14] = min(pe.OPTIONAL_HEADER.FileAlignment, 10**6) / 10**6
        hdr_feats[15] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion / 100.0
        hdr_feats[16] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion / 100.0
        hdr_feats[17] = pe.OPTIONAL_HEADER.MajorImageVersion / 100.0
        hdr_feats[18] = pe.OPTIONAL_HEADER.MinorImageVersion / 100.0
        hdr_feats[19] = pe.OPTIONAL_HEADER.MajorSubsystemVersion / 100.0
        hdr_feats[20] = pe.OPTIONAL_HEADER.MinorSubsystemVersion / 100.0
        hdr_feats[21] = min(pe.OPTIONAL_HEADER.SizeOfImage, 10**8) / 10**8
        hdr_feats[22] = min(pe.OPTIONAL_HEADER.SizeOfHeaders, 10**6) / 10**6
        hdr_feats[23] = pe.OPTIONAL_HEADER.CheckSum / 0xFFFFFFFF
        hdr_feats[24] = pe.OPTIONAL_HEADER.Subsystem / 100.0
        hdr_feats[25] = pe.OPTIONAL_HEADER.DllCharacteristics / 0xFFFF
        hdr_feats[26] = min(pe.OPTIONAL_HEADER.SizeOfStackReserve, 10**8) / 10**8
        hdr_feats[27] = min(pe.OPTIONAL_HEADER.SizeOfStackCommit, 10**8) / 10**8
        hdr_feats[28] = min(pe.OPTIONAL_HEADER.SizeOfHeapReserve, 10**8) / 10**8
        hdr_feats[29] = min(pe.OPTIONAL_HEADER.SizeOfHeapCommit, 10**8) / 10**8
        hdr_feats[30] = pe.OPTIONAL_HEADER.LoaderFlags / 0xFFFF
        hdr_feats[31] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes / 100.0
        # Data directories (16 entries, 2 values each = 32 features)
        for j, dd in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY[:16]):
            if 32 + j * 2 < 62:
                hdr_feats[32 + j * 2]     = min(dd.VirtualAddress, 10**8) / 10**8
                hdr_feats[32 + j * 2 + 1] = min(dd.Size, 10**8) / 10**8
        pe.close()
    except Exception:
        pass

    for i, v in enumerate(hdr_feats):
        feats[base + i] = v

    # ── Group 6: Section info  F689-F943 (5 sections × 51) ───────
    base = 688
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=False)
        for s_idx, section in enumerate(pe.sections[:5]):
            sbase = base + s_idx * 51
            raw   = section.get_data()
            feats[sbase]      = len(section.Name.rstrip(b'\x00')) / 8.0
            feats[sbase + 1]  = min(section.SizeOfRawData, 10**7) / 10**7
            feats[sbase + 2]  = min(section.Misc_VirtualSize, 10**7) / 10**7
            feats[sbase + 3]  = _entropy(raw) / 8.0
            feats[sbase + 4]  = section.Characteristics / 0xFFFFFFFF
            feats[sbase + 5]  = section.VirtualAddress / 0xFFFFFFFF
            # Byte histogram per section (256/5 = ~45 bins → use 16 bins)
            if raw:
                bh_s = _byte_histogram(raw)
                for k in range(16):
                    feats[sbase + 6 + k] = bh_s[k * 16]   # sub-sample
            # Physical vs virtual ratio
            if section.Misc_VirtualSize:
                feats[sbase + 22] = min(section.SizeOfRawData / section.Misc_VirtualSize, 10.0) / 10.0
            # Printable ratio
            if raw:
                feats[sbase + 23] = sum(1 for b in raw if 0x20 <= b < 0x7f) / len(raw)
            # Remaining slots stay 0
        pe.close()
    except Exception:
        pass

    # ── Group 7: Import hashes  F944-F2223 (1280 slots) ──────────
    base = 943
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=False)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            slot = 0
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.lower().decode('utf-8', errors='ignore').rstrip('.dll') if entry.dll else ''
                dll_idx  = _COMMON_DLLS.index(dll_name) if dll_name in _COMMON_DLLS else -1
                for imp in entry.imports[:40]:   # up to 40 per DLL
                    if slot >= 1280:
                        break
                    api_name = imp.name.lower().decode('utf-8', errors='ignore') if imp.name else ''
                    h = (hash(dll_name + api_name) % 65536) / 65536.0
                    feats[base + slot] = h
                    slot += 1
                if slot >= 1280:
                    break
        pe.close()
    except Exception:
        pass

    # ── Group 8: Export hashes  F2224-F2351 (128 slots) ──────────
    base = 2223
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=False)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for i, exp in enumerate(pe.DIRECTORY_ENTRY_EXPORT.symbols[:128]):
                name = exp.name.lower().decode('utf-8', errors='ignore') if exp.name else ''
                feats[base + i] = (hash(name) % 65536) / 65536.0
        pe.close()
    except Exception:
        pass

    # ── Group 9: Misc extras  F2352-F2381 (30) ───────────────────
    base = 2351
    feats[base]      = _entropy(data) / 8.0
    feats[base + 1]  = len(data) / (50 * 1024 * 1024)          # file_size / 50MB
    feats[base + 2]  = 1.0 if data[:2] == b'MZ' else 0.0       # is_pe
    feats[base + 3]  = min(data.count(b'\x00'), 100000) / 100000.0
    feats[base + 4]  = min(sus_kw_count, 50) / 50.0
    feats[base + 5]  = min(num_mz, 20) / 20.0
    feats[base + 6]  = printable_ratio
    # leave rest as 0

    return {f'F{i + 1}': feats[i] for i in range(2381)}


# ═══════════════════════════════════════════════════════════════
#  PDF Feature Extraction  →  29 named features
# ═══════════════════════════════════════════════════════════════

def extract_pdf_features(filepath: str) -> dict:
    feats = {
        'PdfSize': 0, 'MetadataSize': 0, 'Pages': 0, 'XrefLength': 0,
        'TitleCharacters': 0, 'isEncrypted': 0, 'EmbeddedFiles': 0,
        'Images': 0, 'Obj': 0, 'Endobj': 0, 'Stream': 0, 'Endstream': 0,
        'Xref': 0, 'Trailer': 0, 'StartXref': 0, 'PageNo': 0, 'Encrypt': 0,
        'ObjStm': 0, 'JS': 0, 'Javascript': 0, 'AA': 0, 'OpenAction': 0,
        'Acroform': 0, 'JBIG2Decode': 0, 'RichMedia': 0, 'Launch': 0,
        'EmbeddedFile': 0, 'XFA': 0, 'Colors': 0,
    }
    try:
        feats['PdfSize'] = os.path.getsize(filepath)

        with open(filepath, 'rb') as fh:
            raw = fh.read()

        # Decode for keyword counting
        txt = raw.decode('latin-1', errors='ignore')
        tl  = txt.lower()

        # Structural counts
        feats['Obj']       = txt.count(' obj')    + txt.count('\nobj')
        feats['Endobj']    = txt.count('endobj')
        feats['Stream']    = txt.count('stream\n') + txt.count('stream\r')
        feats['Endstream'] = txt.count('endstream')
        feats['Xref']      = txt.count('\nxref')
        feats['Trailer']   = txt.count('trailer')
        feats['StartXref'] = txt.count('startxref')

        # XRef length (characters between 'xref' and 'trailer')
        xref_match = re.search(r'xref\s+([\s\S]*?)trailer', txt)
        if xref_match:
            feats['XrefLength'] = len(xref_match.group(1))

        # Metadata
        meta_match = re.search(r'<</.*?>>', txt, re.DOTALL)
        feats['MetadataSize'] = len(meta_match.group(0)) if meta_match else 0

        # Title characters
        title_match = re.search(r'/Title\s*\((.*?)\)', txt, re.DOTALL)
        feats['TitleCharacters'] = len(title_match.group(1)) if title_match else 0

        # Page counts
        pages = len(re.findall(r'/Type\s*/Page\b', txt, re.IGNORECASE))
        feats['Pages']  = pages
        feats['PageNo'] = pages

        # Keyword features (case-sensitive PDF object names)
        kw_map = {
            'isEncrypted':  ['/Encrypt'],
            'EmbeddedFiles': ['/EmbeddedFiles'],
            'Images':        ['/Image'],
            'Encrypt':       ['/Encrypt'],
            'ObjStm':        ['/ObjStm'],
            'JS':            ['/JS'],
            'Javascript':    ['/Javascript'],
            'AA':            ['/AA'],
            'OpenAction':    ['/OpenAction'],
            'Acroform':      ['/AcroForm', '/Acroform'],
            'JBIG2Decode':   ['/JBIG2Decode'],
            'RichMedia':     ['/RichMedia'],
            'Launch':        ['/Launch'],
            'EmbeddedFile':  ['/EmbeddedFile'],
            'XFA':           ['/XFA'],
            'Colors':        ['/Colors'],
        }
        for feat_name, keywords in kw_map.items():
            feats[feat_name] = sum(txt.count(kw) for kw in keywords)

        feats['isEncrypted'] = 1 if feats['Encrypt'] > 0 else 0

    except Exception as e:
        pass

    return feats


# ═══════════════════════════════════════════════════════════════
#  DOCX / DOC Feature Extraction  →  30 named features
# ═══════════════════════════════════════════════════════════════

def extract_docx_features(filepath: str) -> dict:
    feats = {
        'macro_present': 0, 'autoexec_macro': 0, 'powershell_usage': 0,
        'shell_commands': 0, 'external_connections': 0, 'obfuscation_score': 0,
        'vba_code_size': 0, 'suspicious_keywords': 0, 'file_size_kb': 0,
        'ole_streams': 0, 'embedded_objects': 0, 'dde_links': 0,
        'auto_open': 0, 'document_open': 0, 'workbook_open': 0,
        'suspicious_imports': 0, 'base64_strings': 0, 'hex_strings': 0,
        'chr_calls': 0, 'environ_calls': 0, 'createobject_calls': 0,
        'shell_calls': 0, 'wscript_calls': 0, 'document_write_calls': 0,
        'downloadfile_calls': 0, 'registry_access': 0, 'process_creation': 0,
        'network_access': 0, 'file_access': 0, 'entropy_score': 0.0,
    }
    try:
        file_size = os.path.getsize(filepath)
        feats['file_size_kb'] = file_size / 1024.0

        with open(filepath, 'rb') as fh:
            raw = fh.read()

        feats['entropy_score'] = _entropy(raw)

        try:
            from oletools.olevba import VBA_Parser
            vba = VBA_Parser(filepath)

            if vba.detect_vba_macros():
                feats['macro_present'] = 1
                all_vba_code = ''

                for _, stream_path, _, vba_code in vba.extract_macros():
                    all_vba_code += vba_code + '\n'

                feats['vba_code_size'] = len(all_vba_code)
                cl = all_vba_code.lower()

                # Autoexec macros
                autoexec_kw = ['autoopen', 'auto_open', 'document_open', 'workbook_open',
                               'autoclose', 'auto_close', 'document_close', 'workbook_close',
                               'autoexec', 'autoexit', 'document_beforeclose']
                feats['autoexec_macro']  = 1 if any(k in cl for k in autoexec_kw) else 0
                feats['auto_open']       = 1 if 'autoopen'     in cl or 'auto_open' in cl else 0
                feats['document_open']   = 1 if 'document_open' in cl else 0
                feats['workbook_open']   = 1 if 'workbook_open' in cl else 0

                # Suspicious operations
                feats['powershell_usage']     = cl.count('powershell')
                feats['shell_commands']        = cl.count('shell(') + cl.count('shell ')
                feats['external_connections']  = cl.count('http://') + cl.count('https://') + cl.count('ftp://')
                feats['suspicious_imports']    = cl.count('#import') + cl.count('declare function')
                feats['base64_strings']        = cl.count('base64')  + cl.count('fromb64')
                feats['hex_strings']           = len(re.findall(r'&h[0-9a-f]{2,}', cl))
                feats['chr_calls']             = cl.count('chr(')
                feats['environ_calls']         = cl.count('environ(')
                feats['createobject_calls']    = cl.count('createobject(')
                feats['shell_calls']           = cl.count('shell(')
                feats['wscript_calls']         = cl.count('wscript')
                feats['document_write_calls']  = cl.count('document.write')
                feats['downloadfile_calls']    = cl.count('downloadfile') + cl.count('urldownload')
                feats['registry_access']       = cl.count('regread') + cl.count('regwrite') + cl.count('hkey_')
                feats['process_creation']      = cl.count('createprocess') + cl.count('winexec') + cl.count('shell(')
                feats['network_access']        = cl.count('winhttprequest') + cl.count('xmlhttp') + cl.count('wininet')
                feats['file_access']           = cl.count('open ') + cl.count('filecopy') + cl.count('kill ')

                # Obfuscation score
                obs = feats['hex_strings'] + feats['chr_calls'] + feats['base64_strings']
                feats['obfuscation_score']     = min(obs, 100)

                # Suspicious keyword density
                sus_kws = ['eval', 'execute', 'environ', 'createobject', 'shell',
                           'powershell', 'cmd', 'wscript', 'cscript', 'regsvr32', 'mshta']
                feats['suspicious_keywords'] = sum(cl.count(k) for k in sus_kws)

            vba.close()

        except ImportError:
            # Fallback: raw byte scan
            raw_l = raw.decode('latin-1', errors='ignore').lower()
            feats['macro_present']    = 1 if ('vbaproject' in raw_l or 'macro' in raw_l) else 0
            feats['powershell_usage'] = raw_l.count('powershell')
            feats['entropy_score']    = _entropy(raw)

        except Exception:
            pass

        # ── Raw-byte VBA keyword scan (runs when oletools finds no macros) ──
        # Covers cases where VBA is in a non-standard container or raw stream.
        if feats['macro_present'] == 0:
            try:
                # Scan the raw file bytes (works on both OLE and OOXML containers
                # where XML is stored uncompressed, or plain binary files).
                raw_l = raw.decode('latin-1', errors='ignore').lower()

                # Treat as macro-present if VBA project signature found
                if ('vbaproject' in raw_l or 'attribute vb_name' in raw_l
                        or 'sub autoopen' in raw_l or 'sub document_open' in raw_l):
                    feats['macro_present']  = 1
                    feats['autoexec_macro'] = 1 if (
                        'autoopen' in raw_l or 'document_open' in raw_l
                        or 'workbook_open' in raw_l) else 0
                    feats['auto_open']     = 1 if 'autoopen'      in raw_l else 0
                    feats['document_open'] = 1 if 'document_open' in raw_l else 0
                    feats['workbook_open'] = 1 if 'workbook_open' in raw_l else 0

                    feats['powershell_usage']   = raw_l.count('powershell')
                    feats['shell_commands']      = raw_l.count('shell(')
                    feats['createobject_calls']  = raw_l.count('createobject')
                    feats['environ_calls']        = raw_l.count('environ(')
                    feats['wscript_calls']        = raw_l.count('wscript')
                    feats['downloadfile_calls']   = raw_l.count('urldownloadtofile') + raw_l.count('downloadfile')
                    feats['registry_access']      = raw_l.count('regwrite') + raw_l.count('hkcu') + raw_l.count('hklm')
                    feats['base64_strings']       = raw_l.count('base64') + raw_l.count(' -enc ')
                    feats['network_access']       = raw_l.count('http://') + raw_l.count('https://')
                    feats['vba_code_size']        = sum(
                        raw_l.count(k) * 20
                        for k in ['sub ', 'function ', 'dim ', 'end sub', 'end function']
                    )
                    sus_kws = ['eval', 'execute', 'environ', 'createobject', 'shell',
                               'powershell', 'cmd', 'wscript', 'cscript', 'regsvr32', 'mshta']
                    feats['suspicious_keywords'] = sum(raw_l.count(k) for k in sus_kws)
                    feats['obfuscation_score']    = min(
                        feats['base64_strings'] + feats['chr_calls'], 100)
            except Exception:
                pass

        # OLE streams count
        try:
            import olefile
            if olefile.isOleFile(filepath):
                ole = olefile.OleFileIO(filepath)
                feats['ole_streams'] = len(ole.listdir())
                feats['embedded_objects'] = len([e for e in ole.listdir() if 'embedde' in str(e).lower()])
                ole.close()
        except Exception:
            pass

        # DDE links (raw scan)
        feats['dde_links'] = raw.count(b'DDE') + raw.count(b'DDEAUTO')

    except Exception:
        pass

    return feats


# ═══════════════════════════════════════════════════════════════
#  Generic Feature Extraction  →  20 named features
# ═══════════════════════════════════════════════════════════════

def extract_generic_features(filepath: str) -> dict:
    feats = {
        'file_size_kb': 0.0, 'entropy': 0.0, 'byte_diversity': 0.0,
        'null_byte_ratio': 0.0, 'printable_ratio': 0.0, 'high_byte_ratio': 0.0,
        'compression_ratio': 0.0, 'section_count': 0, 'import_count': 0,
        'export_count': 0, 'string_count': 0, 'avg_string_len': 0.0,
        'url_count': 0, 'ip_count': 0, 'pe_header_valid': 0,
        'signature_present': 0, 'packer_detected': 0, 'overlay_size': 0,
        'resource_count': 0, 'timestamp_valid': 0,
    }
    try:
        file_size = os.path.getsize(filepath)
        feats['file_size_kb'] = file_size / 1024.0

        with open(filepath, 'rb') as fh:
            data = fh.read()

        feats['entropy']         = _entropy(data)
        feats['byte_diversity']  = len(set(data)) / 256.0
        feats['null_byte_ratio'] = data.count(0) / (len(data) or 1)
        feats['printable_ratio'] = sum(1 for b in data if 0x20 <= b < 0x7f) / (len(data) or 1)
        feats['high_byte_ratio'] = sum(1 for b in data if b >= 0x80) / (len(data) or 1)

        # Simple compression estimate (repeated 4-byte sequences)
        if len(data) >= 8:
            chunks  = [data[i:i+4] for i in range(0, len(data)-4, 4)]
            uniq    = len(set(chunks))
            feats['compression_ratio'] = 1.0 - (uniq / max(len(chunks), 1))

        # String analysis
        strings = _printable_strings(data)
        feats['string_count']   = len(strings)
        if strings:
            lens = [len(s) for s in strings]
            feats['avg_string_len'] = sum(lens) / len(lens)

        all_str = b' '.join(strings).lower()
        feats['url_count'] = all_str.count(b'http://') + all_str.count(b'https://')
        feats['ip_count']  = len(re.findall(rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', data))

        # PE-specific (if applicable)
        if data[:2] == b'MZ':
            feats['pe_header_valid'] = 1
            try:
                import pefile
                pe = pefile.PE(data=data, fast_load=False)
                feats['section_count'] = len(pe.sections)

                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    feats['import_count'] = sum(len(e.imports) for e in pe.DIRECTORY_ENTRY_IMPORT)
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    feats['export_count'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
                if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress:
                    feats['signature_present'] = 1
                if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                    feats['resource_count'] = sum(1 for _ in pe.DIRECTORY_ENTRY_RESOURCE.entries)

                # Overlay
                last_section_end = max(
                    (s.PointerToRawData + s.SizeOfRawData for s in pe.sections), default=0
                )
                feats['overlay_size'] = max(len(data) - last_section_end, 0) / 1024.0

                # Timestamp validity (rough check: after 1990 and not far future)
                ts = pe.FILE_HEADER.TimeDateStamp
                feats['timestamp_valid'] = 1 if 631152000 <= ts <= 2000000000 else 0

                # Simple packer detection: high entropy in first section
                if pe.sections:
                    first_data = pe.sections[0].get_data()
                    feats['packer_detected'] = 1 if _entropy(first_data) > 7.0 else 0

                pe.close()
            except Exception:
                pass

    except Exception:
        pass

    return feats


# ═══════════════════════════════════════════════════════════════
#  Router
# ═══════════════════════════════════════════════════════════════

def extract_features(filepath: str, file_type: str) -> dict:
    if file_type == 'exe':
        return extract_exe_features(filepath)
    elif file_type == 'pdf':
        return extract_pdf_features(filepath)
    elif file_type in ('doc', 'docx'):
        return extract_docx_features(filepath)
    else:
        return extract_generic_features(filepath)
