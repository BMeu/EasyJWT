#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
    This test ensures the compatibility of new versions of `EasyJWT` with old versions: tokens created with old versions
    of `EasyJWT` must be decodable by new versions of `EasyJWT`. Additionally, an externally created token must also
    be decodable.

    For each version X.Y.Z of `EasyJWT`, a file ``compatibility_tokens/X_Y_Z.jwt`` contains the token created by
    :class:`CompatibilityToken` (defined below in this module) in the corresponding version of `EasyJWT`. The file
    ``compatibility_tokens/external.jwt`` contains the externally created token.

    The test case loads all `JWT` files present in ``compatibility_tokens`` and tries to verify them with
    :class:`CompatibilityToken` (the externally created token is verified with :class:`ExternalCompatibilityToken`).

    The values for the token are defined in the constants below. The dates are chosen to not cause verification failures
    for the foreseeable future. These values _must not_ change, as they are used for verifying the claim set of the
    token. The key with which the tokens have been encoded is defined in :attr:`KEY`.

    The algorithm used for encoding the tokens is the default algorithm of `EasyJWT`. Should this default algorithm ever
    change in future versions of `EasyJWT`, the previous default algorithm must be added to the list of previous
    algorithms in :class:`CompatibilityToken`.

    The tokens for the downwards compatibility test can be created using the script `create_compatibility_testcase.py`
    in the project's root directory. The externally created token has been created with https://jwt.io/ on May 4, 2019.

    The claim set of the tokens is
    ```
        {
          "aud": "CompatibilityTest",
          "exp": 16756675200,
          "iat": 1556841600,
          "iss": "CompatibilityTest",
          "jti": "EasyJWT.CompatibilityTest",
          "nbf": 1546300800,
          "sub": "EasyJWT Compatibility Test",
          "dict_claim": {
             "inner_float_claim": 13.37,
             "inner_int_claim": 42,
             "inner_list_claim": [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024],
             "inner_string_claim": "A string claim value"
          },
          "float_claim": 13.37,
          "int_claim": 42,
          "list_claim": [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024],
          "string_claim": "A string claim value"
        }
    ```

    The tokens created with `EasyJWT` additionally contain the claim `"_easyjwt_class": "CompatibilityToken"`.
"""

from unittest import TestCase

from contextlib import contextmanager
from datetime import datetime
from os import listdir
from os.path import dirname
from os.path import isdir
from os.path import join
from os.path import splitext

from easyjwt import EasyJWT
from easyjwt import EasyJWTError

# region Configuration

KEY = ('Gallia est omnis divisa in partes tres, quarum unam incolunt Belgae, aliam Aquitani, tertiam qui ipsorum ' +
       'lingua Celtae, nostra Galli appellantur.')
"""
    The key used for encrypting and decrypting the tokens.

    This key _must never_ change. Otherwise, the verification of old versions will fail.
"""

TOKEN_FOLDER = join(dirname(__file__), 'compatibility_tokens')
"""
    The path to the folder where the tokens for the compatibility test are stored.
"""

# endregion

# region Claim Values

# region Registered Claims

AUDIENCE = 'CompatibilityTest'

EXPIRATION_DATE = datetime(2500, 12, 31)

ISSUED_AT = datetime(2019, 5, 3)

ISSUER = 'CompatibilityTest'

JWT_ID = 'EasyJWT.CompatibilityTest'

NOT_BEFORE_DATE = datetime(2019, 1, 1)

SUBJECT = 'EasyJWT Compatibility Test'

# endregion

# region Private Claims

FLOAT_CLAIM = 13.37

INT_CLAIM = 42

LIST_CLAIM = [2 ** n for n in range(0, 11)]

STRING_CLAIM = 'A string claim value'

DICT_CLAIM = {
    'inner_float_claim': FLOAT_CLAIM,
    'inner_int_claim': INT_CLAIM,
    'inner_list_claim': LIST_CLAIM,
    'inner_string_claim': STRING_CLAIM,
}

# endregion

# endregion

# region Token Definition


class CompatibilityToken(EasyJWT):
    """
        A token that is used to check the downwards compatibility of each new version of `EasyJWT`.

        The definition of this token _must never_ change, except for breaking changes in new versions.
    """

    def __init__(self, key: str) -> None:
        """
            :param key: The private key that is used for encoding and decoding the token.
        """

        super().__init__(key)

        self.dict_claim = None
        self.float_claim = None
        self.int_claim = None
        self.list_claim = None
        self.string_claim = None

    @classmethod
    def create_compatibility_token(cls) -> str:
        """
            Create a token for testing downwards compatibility in the current version of `EasyJWT`.

            Return: The created token.
        """

        easyjwt = cls(KEY)
        easyjwt.set_claim_set()

        return easyjwt.create(ISSUED_AT)

    def set_claim_set(self) -> None:
        """
            Set the claim set values.
        """

        # Set registered claims.
        self.audience = AUDIENCE
        self.expiration_date = EXPIRATION_DATE
        # Set the issued-at date so it will be included when getting the claim set for the external token.
        self.issued_at_date = ISSUED_AT
        self.issuer = ISSUER
        self.JWT_ID = JWT_ID
        self.not_before_date = NOT_BEFORE_DATE
        self.subject = SUBJECT

        # Set private claims.
        self.dict_claim = DICT_CLAIM
        self.float_claim = FLOAT_CLAIM
        self.int_claim = INT_CLAIM
        self.list_claim = LIST_CLAIM
        self.string_claim = STRING_CLAIM


class ExternalCompatibilityToken(CompatibilityToken):
    """
        A token used to check the compatibility of each new version of `EasyJWT` with an externally created token.

        This class is only needed for verifying the external token without strict verification.
    """

    strict_verification = False

# endregion


class CompatibilityTest(TestCase):

    @contextmanager
    def assertNotRaises(self, unexpected_exception, message: str) -> None:
        """
            Test that an exception is not raised. The test passes if `unexpected_exception` is not raised, and fails
            if an exception of the type of `unexpected_exception` is raised..

            :param unexpected_exception: The exception that should not be raised.
            :param message: The message to display in case of an assertion failure.
        """

        try:
            yield None
        except unexpected_exception as actual_exception:
            raise self.failureException(f'{actual_exception.__class__.__name__} raised : {message}')

    @staticmethod
    def get_token_and_version_from_file(file_name: str) -> (str, str):
        """
            Get the token and token version from the given file.

            :param file_name: The relative path to the token file within the :attr:`TOKEN_FOLDER`.
            :return: A tuple of two strings: the first string is the token, the second one its version.
        """

        # Extract the token version from the file name.
        version = splitext(file_name)[0]
        version = version.replace('_', '.')

        with open(join(TOKEN_FOLDER, file_name), 'r') as file:
            # The token is expected in the first line of the file.
            token = file.readline()

        # Allow linebreaks and other whitespaces around the token.
        token = token.strip()
        return token, version

    def verify_claim_set(self, token_object: CompatibilityToken, message: str):
        """
            Verify the claim set of the given token object.

            :param token_object: The token object to verify.
            :param message: A message to display in case of assertion failures.
        """

        # Verify registered claims.
        self.assertEqual(AUDIENCE, token_object.audience, message)
        self.assertEqual(EXPIRATION_DATE, token_object.expiration_date, message)
        self.assertEqual(ISSUED_AT, token_object.issued_at_date, message)
        self.assertEqual(ISSUER, token_object.issuer, message)
        self.assertEqual(JWT_ID, token_object.JWT_ID, message)
        self.assertEqual(NOT_BEFORE_DATE, token_object.not_before_date, message)
        self.assertEqual(SUBJECT, token_object.subject, message)

        # Verify private claims.
        self.assertDictEqual(DICT_CLAIM, token_object.dict_claim, message)
        self.assertEqual(FLOAT_CLAIM, token_object.float_claim, message)
        self.assertEqual(INT_CLAIM, token_object.int_claim, message)
        self.assertListEqual(LIST_CLAIM, token_object.list_claim, message)
        self.assertEqual(STRING_CLAIM, token_object.string_claim, message)

    def test_downwards_compatibility(self):
        """
            Test the compatibility of the current version of `EasyJWT` with older versions of `EasyJWT`.

            Expected Result: The verification succeeds without errors. All data is restored.
        """

        for folder_entry in listdir(TOKEN_FOLDER):
            # Skip all folders.
            if isdir(folder_entry):
                continue

            # Skip all files not ending in 'jwt' and the external token.
            if not folder_entry.endswith('jwt') or folder_entry == 'external.jwt':
                continue

            # Get the token and its version.
            token, version = self.get_token_and_version_from_file(folder_entry)
            message = 'Token v' + version

            # Try to verify the token.
            with self.assertNotRaises(EasyJWTError, message):
                token_object = CompatibilityToken.verify(token, KEY, ISSUER, AUDIENCE)

            # Verify the claim set.
            self.assertIsNotNone(token_object, message)
            self.verify_claim_set(token_object, message)

    def test_external_compatibility(self):
        """
            Test the compatibility of the current version of `EasyJWT` with externally created tokens.

            Expected Result: The verification succeeds without errors. All data is restored.
        """

        # Get the token. The version is not needed.
        token, _ = self.get_token_and_version_from_file('external.jwt')
        message = 'External Token'

        # Try to verify the token.
        with self.assertNotRaises(EasyJWTError, message):
            token_object = ExternalCompatibilityToken.verify(token, KEY, ISSUER, AUDIENCE)

        # Verify the claim set.
        self.assertIsNotNone(token_object, message)
        self.verify_claim_set(token_object, message)
