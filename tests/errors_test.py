#!venv/bin/python
# -*- coding: utf-8 -*-

from unittest import TestCase

from easyjwt import EasyJWTError
from easyjwt import UnspecifiedClassError
from easyjwt import InvalidClaimSetError
from easyjwt import InvalidClassError


class EasyJWTErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected result: The message is correctly initialized.
        """

        message = 'EasyJWTError message'
        error = EasyJWTError(message)
        self.assertEqual(message, error._message)

    def test_str(self):
        """
            Test casting the error to a string.

            Expected result: The message is returned.
        """

        error = EasyJWTError('EasyJWTError message')
        self.assertEqual(error._message, str(error))


class MissingClassErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected result: The message is correctly initialized.
        """

        error = UnspecifiedClassError()
        self.assertEqual('Missing class specification', error._message)


class PayloadFieldErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected result: The message is correctly initialized with the given claims.
        """

        missing = ['missing_1', 'missing_2']
        unexpected = ['unexpected_1', 'unexpected_2']

        # No missing claims, no unexpected claims.
        error = InvalidClaimSetError()
        message = 'Missing claims: {}. Unexpected claims: {}'
        self.assertEqual(message, error._message)

        # Missing claims, no unexpected claims.
        error = InvalidClaimSetError(missing_claims=missing)
        message = 'Missing claims: {missing_1, missing_2}. Unexpected claims: {}'
        self.assertEqual(message, error._message)

        # No missing claims, unexpected claims.
        error = InvalidClaimSetError(unexpected_claims=unexpected)
        message = 'Missing claims: {}. Unexpected claims: {unexpected_1, unexpected_2}'
        self.assertEqual(message, error._message)

        # Missing claims, unexpected claims.
        error = InvalidClaimSetError(missing_claims=missing, unexpected_claims=unexpected)
        message = 'Missing claims: {missing_1, missing_2}. Unexpected claims: {unexpected_1, unexpected_2}'
        self.assertEqual(message, error._message)


class WrongClassErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected result: The message is correctly initialized.
        """

        expected_class = 'ExpectedEasyJWTClass'
        actual_class = 'ActualEasyJWTClass'
        error = InvalidClassError(expected_class=expected_class, actual_class=actual_class)
        self.assertEqual(f'Expected class {expected_class}. Got class {actual_class}', error._message)
