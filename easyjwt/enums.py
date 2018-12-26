#!venv/bin/python
# -*- coding: utf-8 -*-

"""
    Enum definitions.
"""

import enum


class Algorithm(enum.Enum):
    """
        The supported algorithms for cryptographically signing the tokens.
    """

    HS256 = 'HS256'
    """
        HMAC using the SHA-256 hash algorithm.
    """

    HS384 = 'HS384'
    """
        HMAC using the SHA-384 hash algorithm.
    """

    HS512 = 'HS512'
    """
        HMAC using the SHA-512 hash algorithm.
    """
