#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
    EasyJWT provides a simple interface to creating and verifying
    `JSON Web Tokens (JWTs) <https://tools.ietf.org/html/rfc7519>`_ in Python. It allows you to once define the claims
    of the JWT, and to then create and accept tokens with these claims without having to check if all the required data
    is given or if the token actually is the one you expect.

    See the included README file or the documentation for details on how to use EasyJWT.
"""

from .enums import Algorithm
from .errors import CreationError
from .errors import EasyJWTError
from .errors import ExpiredTokenError
from .errors import ImmatureTokenError
from .errors import IncompatibleKeyError
from .errors import InvalidAudienceError
from .errors import InvalidClaimSetError
from .errors import InvalidClassError
from .errors import InvalidIssuedAtError
from .errors import InvalidIssuerError
from .errors import InvalidSignatureError
from .errors import MissingRequiredClaimsError
from .errors import UnspecifiedClassError
from .errors import UnsupportedAlgorithmError
from .errors import VerificationError
from .easyjwt import EasyJWT
from .easyjwt import EasyJWTClass

__all__ = [
    'Algorithm',
    'CreationError',
    'EasyJWT',
    'EasyJWTClass',
    'EasyJWTError',
    'ExpiredTokenError',
    'ImmatureTokenError',
    'IncompatibleKeyError',
    'InvalidAudienceError',
    'InvalidClaimSetError',
    'InvalidClassError',
    'InvalidIssuedAtError',
    'InvalidIssuerError',
    'InvalidSignatureError',
    'MissingRequiredClaimsError',
    'UnspecifiedClassError',
    'UnsupportedAlgorithmError',
    'VerificationError',
]
