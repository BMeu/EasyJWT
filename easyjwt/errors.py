#!venv/bin/python
# -*- coding: utf-8 -*-

"""
    Error class definitions.
"""

import typing


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


class InvalidPayloadBaseError(EasyJWTError):
    """
        A base class for all errors raised if a token's payload is invalid.
    """

    pass


class MissingClassError(InvalidPayloadBaseError):
    """
        Raised if the verification of a token fails because the :class:`EasyJWT` class with which it has been created is
        not specified in the payload.
    """

    def __init__(self) -> None:
        super().__init__('Missing class specification')


class PayloadFieldError(InvalidPayloadBaseError):
    """
        Raised if the verification of a token fails because it misses some expected fields or it contains some
        unexpected fields.
    """

    def __init__(self, missing_fields: typing.Optional[typing.Iterable[str]] = None,
                 unexpected_fields: typing.Optional[typing.Iterable[str]] = None) -> None:
        """
            :param missing_fields: The names of fields that are expected but are missing in the payload.
            :param unexpected_fields: The names of fields that are given in the payload but are not specified in the
                                      class.
        """

        if missing_fields is None:
            missing_fields = set()

        if unexpected_fields is None:
            unexpected_fields = set()

        missing = '{' + ', '.join(missing_fields) + '}'
        unexpected = '{' + ', '.join(unexpected_fields) + '}'

        super().__init__(f'Missing fields: {missing}. Unexpected fields: {unexpected}')


class WrongClassError(InvalidPayloadBaseError):
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
