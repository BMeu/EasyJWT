#!venv/bin/python
# -*- coding: utf-8 -*-

"""
    Error class definitions.
"""

from typing import Iterable
from typing import Optional

# region Base Error


class EasyJWTError(Exception):
    """
        A base class for all errors raised by :class:`EasyJWT`.
    """

    def __init__(self, message: str) -> None:
        """
            :param message: A user-readable description of this error.
        """

        self._message = message

    def __str__(self) -> str:
        """
            Get a user-readable description of the error.

            :return: A string describing the error.
        """
        return self._message

# endregion

# region Creation Error


class CreationError(EasyJWTError):
    """
        A base class for all errors raised during the creation of a token.
    """
    pass

# endregion

# region Verification Error


class VerificationError(EasyJWTError):
    """
        A base class for all errors raised during the verification of a token.
    """
    pass

# region Invalid Claims


class InvalidClaimsBaseError(VerificationError):
    """
        A base class for all errors raised if the token contains invalid claims.
    """
    pass


class InvalidClaimSetError(InvalidClaimsBaseError):
    """
        Raised if the verification of a token fails because the claim set is invalid due to missing or unexpected
        claims.
    """

    def __init__(self,
                 missing_claims: Optional[Iterable[str]] = None,
                 unexpected_claims: Optional[Iterable[str]] = None
                 ) -> None:
        """
            :param missing_claims: The names of claims that are expected but missing in the claim set.
            :param unexpected_claims: The names of claims that are given in the claim set but are not specified in the
                                      class.
        """

        if missing_claims is None:
            missing_claims = set()

        if unexpected_claims is None:
            unexpected_claims = set()

        missing = '{' + ', '.join(missing_claims) + '}'
        unexpected = '{' + ', '.join(unexpected_claims) + '}'

        super().__init__(f'Missing claims: {missing}. Unexpected claims: {unexpected}')


class InvalidClassError(InvalidClaimsBaseError):
    """
        Raised if the verification of a token fails because the :class:`EasyJWT` class with which it has been created is
        not the one with which it is being verified.
    """

    def __init__(self, expected_class: str, actual_class: str) -> None:
        """
            :param expected_class: The class with which the token is being verified.
            :param actual_class: The class with which the token has been created.
        """

        super().__init__(f'Expected class {expected_class}. Got class {actual_class}')


class UnspecifiedClassError(InvalidClaimsBaseError):
    """
        Raised if the verification of a token fails because the :class:`EasyJWT` class with which it has been created is
        not specified in the claim set.
    """

    def __init__(self) -> None:
        super().__init__('Missing class specification')


# endregion

# endregion
