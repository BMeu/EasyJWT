#!/usr/bin/python
# -*- coding: utf-8 -*-

from unittest import TestCase

from easyjwt import Algorithm
from easyjwt import EasyJWT
from easyjwt import InvalidClassError
from easyjwt import MissingRequiredClaimsError
from easyjwt import UnsupportedAlgorithmError


class AccountValidationToken(EasyJWT):

    _optional_claims = EasyJWT._optional_claims.union({
        'email',
    })

    def __init__(self, key):
        super().__init__(key)

        self.user_id = None
        self.email = None


class AccountDeletionToken(EasyJWT):

    def __init__(self, key):
        super().__init__(key)

        self.user_id = None


class IntegrationTest(TestCase):

    # region Test Setup

    def setUp(self):
        """
            Prepare the test cases.
        """

        self.email = 'mail@example.com'
        self.key = 'abcdefghijklmnopqrstuvwxyz'
        self.user_id = 42

    def tearDown(self):
        """
            Clean up after each test.
        """

        # Reset class variables.
        AccountValidationToken.algorithm = Algorithm.HS256
        AccountValidationToken.previous_algorithms = set()
        AccountValidationToken.strict_verification = True

        AccountDeletionToken.algorithm = Algorithm.HS256
        AccountDeletionToken.previous_algorithms = set()
        AccountDeletionToken.strict_verification = True

    # endregion

    def test_creation_and_verification(self):
        """
            Test that the creation of tokens succeeds and the created token can be verified, but only with the correct
            class.

            Expected Result: No errors are raised; the created token is returned.
        """

        self.assertTrue(AccountDeletionToken.strict_verification)
        self.assertTrue(AccountValidationToken.strict_verification)

        # Create an instance of the token class.
        validation_token_object = AccountValidationToken(self.key)
        self.assertIsNotNone(validation_token_object)

        # Try to create a token without setting required claims.
        with self.assertRaises(MissingRequiredClaimsError):
            validation_token = validation_token_object.create()
            self.assertIsNone(validation_token)

        # Try to create a token with setting mandatory claims.
        validation_token_object.user_id = self.user_id
        validation_token = validation_token_object.create()
        self.assertIsNotNone(validation_token)

        # Try to verify the created token.
        verified_token_object = AccountValidationToken.verify(validation_token, self.key)
        self.assertIsNotNone(verified_token_object)
        self.assertEqual(self.user_id, verified_token_object.user_id)

        # Try to verify the created token with a different class.
        with self.assertRaises(InvalidClassError):
            verified_token_object = AccountDeletionToken.verify(validation_token, self.key)
            self.assertIsNone(verified_token_object)

    def test_no_strict_verification(self):
        """
            Test that tokens can be verified by other classes if strict verification is disabled.

            Expected Result: The verification succeeds.
        """

        AccountDeletionToken.strict_verification = False
        AccountValidationToken.strict_verification = False

        validation_token_object = AccountValidationToken(self.key)
        validation_token_object.user_id = self.user_id
        validation_token = validation_token_object.create()

        verified_token_object = AccountDeletionToken.verify(validation_token, self.key)
        self.assertIsNotNone(verified_token_object)
        self.assertEqual(self.user_id, verified_token_object.user_id)

    def test_optional_claims(self):
        """
            Test that optional claims work as expected.

            Expected Result: The creation and verification of a token with and without optional claims succeeds.
        """

        # Create a token without setting the optional claims.
        token_object = AccountValidationToken(self.key)
        token_object.user_id = self.user_id
        token = token_object.create()
        self.assertIsNotNone(token)

        verified_token_object = AccountValidationToken.verify(token, self.key)
        self.assertIsNotNone(verified_token_object)
        self.assertEqual(self.user_id, verified_token_object.user_id)
        self.assertIsNone(verified_token_object.email)

        # Create a token with setting the optional claims.
        token_object = AccountValidationToken(self.key)
        token_object.user_id = self.user_id
        token_object.email = self.email
        token = token_object.create()
        self.assertIsNotNone(token)

        verified_token_object = AccountValidationToken.verify(token, self.key)
        self.assertIsNotNone(verified_token_object)
        self.assertEqual(self.user_id, verified_token_object.user_id)
        self.assertEqual(self.email, verified_token_object.email)

    def test_previous_algorithms(self):
        """
            Test that tokens can be verified, even if the encoding algorithm has changed.

            Expected Result: The verification succeeds.
        """

        # Create a token with the "old" algorithm
        AccountValidationToken.algorithm = Algorithm.HS256
        token_object = AccountValidationToken(self.key)
        token_object.user_id = self.user_id
        token = token_object.create()

        # Use a new algorithm for encoding tokens. Try to verify the token without specifying the old algorithm.
        AccountValidationToken.algorithm = Algorithm.HS512
        with self.assertRaises(UnsupportedAlgorithmError):
            verified_token_object = AccountValidationToken.verify(token, self.key)
            self.assertIsNone(verified_token_object)

        # Set the old algorithm. The verification will now succeed.
        AccountValidationToken.previous_algorithms = {Algorithm.HS256}
        verified_token_object = AccountValidationToken.verify(token, self.key)
        self.assertIsNotNone(verified_token_object)
        self.assertEqual(self.user_id, verified_token_object.user_id)
