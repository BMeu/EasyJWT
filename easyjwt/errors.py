#!venv/bin/python
# -*- coding: utf-8 -*-

"""
    Error class definitions.
"""


class EasyJWTError(Exception):
    """
        A base class for all errors raised by :class:`EasyJWT`.
    """
    pass


class InvalidPayloadError(EasyJWTError):
    """
        Raised if a token cannot be verified due to an invalid payload.
    """
