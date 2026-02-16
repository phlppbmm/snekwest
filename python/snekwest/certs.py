"""
snekwest.certs
~~~~~~~~~~~~~~

This module returns the preferred default CA certificate bundle. There is
only one -- the one from the certifi package.
"""

from certifi import where

if __name__ == "__main__":
    print(where())
