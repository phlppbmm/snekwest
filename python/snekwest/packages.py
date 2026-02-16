"""
snekwest.packages
~~~~~~~~~~~~~~~~~

Re-exports urllib3, idna, and chardet for compatibility with requests.
Some code (including tests) does ``from requests.packages.urllib3 import ...``.
"""

import urllib3

try:
    import idna
except ImportError:
    idna = None

try:
    import chardet
except ImportError:
    try:
        import charset_normalizer as chardet
    except ImportError:
        chardet = None
