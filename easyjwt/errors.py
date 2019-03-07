#!venv/bin/python
# -*- coding: utf-8 -*-

"""
    Error class definitions.
"""

from typing import Iterable
from typing import Optional
from typing import Set

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


class MissingRequiredClaimsError(CreationError):
    """
        Raised if the creation of a token fails because non-optional claims are empty.
    """

    missing_claims: Set[str]
    """
        A set of the names of claims that are expected but missing in the claim set.
    """

    def __init__(self, missing_claims: Iterable[str]) -> None:
        """
            :param missing_claims: The names of claims that are required but empty.
        """

        self.missing_claims = set(missing_claims)

        # Do not use the newly created set here. If e.g. a list has been passed the order should be preserved.
        missing = '{' + ', '.join(missing_claims) + '}'

        super().__init__(f'Required empty claims: {missing}')

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

    missing_claims: Set[str]
    """
        A set of the names of claims that are expected but missing in the claim set.

        If no missing claims are given, this will be an empty set.
    """

    unexpected_claims: Set[str]
    """
        A set of the names of claims that are given in the claim set but are not specified in the class.

        If no unexpected claims are given, this will be an empty set.
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

        # Create a string representation of the given claims. For this, the parameters must not be None.
        # Do not create a set of the claims yet as that could alter the order in which the claims will be printed.
        missing_claims = missing_claims if missing_claims is not None else set()
        unexpected_claims = unexpected_claims if unexpected_claims is not None else set()

        missing = '{' + ', '.join(missing_claims) + '}'
        unexpected = '{' + ', '.join(unexpected_claims) + '}'

        # Save the given claims as sets.
        self.missing_claims = set(missing_claims)
        self.unexpected_claims = set(unexpected_claims)

        # Set the message.
        super().__init__(f'Missing claims: {missing}. Unexpected claims: {unexpected}')


class InvalidClassError(InvalidClaimsBaseError):
    """
        Raised if the verification of a token fails because the :class:`EasyJWT` class with which it has been created is
        not the one with which it is being verified.
    """

    actual_class: str
    """
        The name of the class with which the token has been created.
    """

    expected_class: str
    """
        The name of the class with which the token has been verified.
    """

    def __init__(self, expected_class: str, actual_class: str) -> None:
        """
            :param expected_class: The class with which the token is being verified.
            :param actual_class: The class with which the token has been created.
        """

        self.actual_class = actual_class
        self.expected_class = expected_class

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
