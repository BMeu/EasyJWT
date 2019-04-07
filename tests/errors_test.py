#!venv/bin/python
# -*- coding: utf-8 -*-

from unittest import TestCase

from easyjwt import EasyJWTError
from easyjwt import ExpiredTokenError
from easyjwt import ImmatureTokenError
from easyjwt import InvalidAudienceError
from easyjwt import InvalidClaimSetError
from easyjwt import InvalidClassError
from easyjwt import InvalidIssuedAtError
from easyjwt import InvalidIssuerError
from easyjwt import InvalidSignatureError
from easyjwt import MissingRequiredClaimsError
from easyjwt import UnspecifiedClassError
from easyjwt import UnsupportedAlgorithmError

# region Base Error


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

# endregion

# region Creation Errors


class MissingRequiredClaimsErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected result: The message is correctly initialized with the given claims.
        """

        missing = ['missing_1', 'missing_2']

        error = MissingRequiredClaimsError(missing)
        message = 'Required empty claims: {missing_1, missing_2}'
        self.assertEqual(message, error._message)
        self.assertSetEqual(set(missing), error.missing_claims)

# endregion

# region Verification Errors


class ExpiredTokenErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected Result: The message is correctly initialized.
        """

        error = ExpiredTokenError()
        self.assertEqual('Token has expired', error._message)


class ImmatureTokenErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected Result: The message is correctly initialized.
        """

        error = ImmatureTokenError()
        self.assertEqual('Token is not yet valid', error._message)


class InvalidAudienceErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected Result: The message is correctly initialized.
        """

        error = InvalidAudienceError()
        self.assertEqual('Invalid audience', error._message)


class InvalidClaimSetErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected Result: The message is correctly initialized with the given claims. The claims are saved in the
                             error object.
        """

        missing = ['missing_1', 'missing_2']
        unexpected = ['unexpected_1', 'unexpected_2']

        # No missing claims, no unexpected claims.
        error = InvalidClaimSetError()
        message = 'Missing claims: {}. Unexpected claims: {}'
        self.assertEqual(message, error._message)
        self.assertSetEqual(set(), error.missing_claims)
        self.assertSetEqual(set(), error.unexpected_claims)

        # Missing claims, no unexpected claims.
        error = InvalidClaimSetError(missing_claims=missing)
        message = 'Missing claims: {missing_1, missing_2}. Unexpected claims: {}'
        self.assertEqual(message, error._message)
        self.assertSetEqual(set(missing), error.missing_claims)
        self.assertSetEqual(set(), error.unexpected_claims)

        # No missing claims, unexpected claims.
        error = InvalidClaimSetError(unexpected_claims=unexpected)
        message = 'Missing claims: {}. Unexpected claims: {unexpected_1, unexpected_2}'
        self.assertEqual(message, error._message)
        self.assertSetEqual(set(), error.missing_claims)
        self.assertSetEqual(set(unexpected), error.unexpected_claims)

        # Missing claims, unexpected claims.
        error = InvalidClaimSetError(missing_claims=missing, unexpected_claims=unexpected)
        message = 'Missing claims: {missing_1, missing_2}. Unexpected claims: {unexpected_1, unexpected_2}'
        self.assertEqual(message, error._message)
        self.assertSetEqual(set(missing), error.missing_claims)
        self.assertSetEqual(set(unexpected), error.unexpected_claims)


class InvalidClassErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected Result: The message is correctly initialized. The classes are saved in the error object.
        """

        expected_class = 'ExpectedEasyJWTClass'
        actual_class = 'ActualEasyJWTClass'

        error = InvalidClassError(expected_class=expected_class, actual_class=actual_class)
        self.assertEqual(f'Expected class {expected_class}. Got class {actual_class}', error._message)
        self.assertEqual(actual_class, error.actual_class)
        self.assertEqual(expected_class, error.expected_class)


class InvalidIssuedAtErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected Result: The message is correctly initialized.
        """

        error = InvalidIssuedAtError()
        self.assertEqual('Invalid issued-at date', error._message)


class InvalidIssuerErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected Result: The message is correctly initialized.
        """

        error = InvalidIssuerError()
        self.assertEqual('Invalid issuer', error._message)


class InvalidSignatureErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected Result: The message is correctly initialized.
        """

        error = InvalidSignatureError()
        self.assertEqual('Invalid signature', error._message)


class UnspecifiedClassErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected Result: The message is correctly initialized.
        """

        error = UnspecifiedClassError()
        self.assertEqual('Missing class specification', error._message)


class UnsupportedAlgorithmErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected Result: The message is correctly initialized.
        """

        error = UnsupportedAlgorithmError()
        self.assertEqual('Algorithm used for encoding the token is not supported', error._message)

# endregion
