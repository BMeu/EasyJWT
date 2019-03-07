#!venv/bin/python
# -*- coding: utf-8 -*-

"""
    EasyJWT
"""
# TODO: Improve package documentation.

from .enums import Algorithm
from .errors import CreationError
from .errors import EasyJWTError
from .errors import ExpiredTokenError
from .errors import ImmatureTokenError
from .errors import InvalidClaimSetError
from .errors import InvalidClassError
from .errors import InvalidKeyError
from .errors import InvalidSignatureError
from .errors import MissingRequiredClaimsError
from .errors import UnspecifiedClassError
from .errors import UnsupportedAlgorithmError
from .errors import VerificationError
from .easyjwt import EasyJWT

__all__ = [
    'Algorithm',
    'CreationError',
    'EasyJWT',
    'EasyJWTError',
    'ExpiredTokenError',
    'ImmatureTokenError',
    'InvalidClaimSetError',
    'InvalidClassError',
    'InvalidKeyError',
    'InvalidSignatureError',
    'MissingRequiredClaimsError',
    'UnspecifiedClassError',
    'UnsupportedAlgorithmError',
    'VerificationError',
]
