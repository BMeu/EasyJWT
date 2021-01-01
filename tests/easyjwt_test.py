#!/usr/bin/python3
# -*- coding: utf-8 -*-

from unittest import TestCase

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from jwt import decode

from easyjwt import Algorithm
from easyjwt import EasyJWT
from easyjwt import ExpiredTokenError
from easyjwt import ImmatureTokenError
from easyjwt import IncompatibleKeyError
from easyjwt import InvalidAudienceError
from easyjwt import InvalidClaimSetError
from easyjwt import InvalidClassError
from easyjwt import InvalidIssuedAtError
from easyjwt import InvalidIssuerError
from easyjwt import InvalidSignatureError
from easyjwt import MissingRequiredClaimsError
from easyjwt import UnspecifiedClassError
from easyjwt import UnsupportedAlgorithmError
from easyjwt import VerificationError
from easyjwt.restoration import restore_timestamp_to_datetime


# noinspection DuplicatedCode
class EasyJWTTest(TestCase):

    # region Test Setup

    def setUp(self):
        """
            Prepare the test cases.
        """

        self.key = 'abcdefghijklmnopqrstuvwxyz'

        # Do not use microseconds.
        self.audience = ['EasyJWT']
        self.expiration_date = datetime.utcnow().replace(microsecond=0) + timedelta(minutes=15)
        self.issued_at_date = datetime.utcnow().replace(microsecond=0) + timedelta(minutes=1)
        self.issuer = 'Issued by EasyJWT'
        self.JWT_ID = 'JSON Web Token Unique Identifier'
        self.not_before_date = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=5)
        self.subject = 'EasyJWT UnitTest'

    def tearDown(self):
        """
            Clean up after each test case.
        """

        # Always reset the class variables to their defaults to prevent unexpected behaviour.
        EasyJWT.strict_verification = True

    # endregion

    # region Instantiation

    # __init__()
    # ==========

    def test_init_lenient_verification(self):
        """
            Test initializing a new token object, with strict verification disabled.

            Expected Result: The instance variables are set correctly, the _easywt_class instance variable does not
                             exist.
        """

        EasyJWT.strict_verification = False
        easyjwt = EasyJWT(self.key)

        self.assertNotIn('_easyjwt_class', vars(easyjwt))
        self.assertEqual(self.key, easyjwt._key)

        self.assertIsNone(easyjwt.audience)
        self.assertIsNone(easyjwt.expiration_date)
        self.assertIsNone(easyjwt.issued_at_date)
        self.assertIsNone(easyjwt.issuer)
        self.assertIsNone(easyjwt.JWT_ID)
        self.assertIsNone(easyjwt.not_before_date)
        self.assertIsNone(easyjwt.subject)

    def test_init_strict_verification(self):
        """
            Test initializing a new token object, with strict verification enabled.

            Expected Result: The instance variables are set correctly, the _easyjwt_class instance variable is
                             initialized.
        """

        easyjwt = EasyJWT(self.key)

        self.assertEqual(easyjwt._get_class_name(), easyjwt._easyjwt_class)
        self.assertEqual(self.key, easyjwt._key)

        self.assertIsNone(easyjwt.audience)
        self.assertIsNone(easyjwt.expiration_date)
        self.assertIsNone(easyjwt.issued_at_date)
        self.assertIsNone(easyjwt.issuer)
        self.assertIsNone(easyjwt.JWT_ID)
        self.assertIsNone(easyjwt.not_before_date)
        self.assertIsNone(easyjwt.subject)

    # endregion

    # region Token Creation

    # create()
    # ========

    def test_create_failure_incompatible_key(self):
        """
            Test creating a token using an incompatible key.

            Expected Result: An `IncompatibleKeyError` error is raised.
        """

        # Ensure that the algorithm needs an HMAC key. Provide an asymmetric key instead.
        incompatible_key = '-----BEGIN PUBLIC KEY-----'
        self.assertIn(EasyJWT.algorithm, {Algorithm.HS256, Algorithm.HS384, Algorithm.HS512})

        easyjwt = EasyJWT(incompatible_key)

        with self.assertRaises(IncompatibleKeyError) as exception_cm:
            token = easyjwt.create()
            self.assertIsNone(token)

        message = 'The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.'
        self.assertEqual(message, str(exception_cm.exception))

    def test_create_failure_missing_required_claims(self):
        """
            Test creating a token if required claims are empty.

            Expected Result: An `MissingRequiredClaimsError` error is raised.
        """

        # Unset the claim for the EasyJWT class which is always required.
        easyjwt = EasyJWT(self.key)
        easyjwt._easyjwt_class = None
        self.assertTrue(easyjwt._is_claim('_easyjwt_class'))

        with self.assertRaises(MissingRequiredClaimsError) as exception_cm:
            token = easyjwt.create()
            self.assertIsNone(token)

        self.assertEqual('Required empty claims: {_easyjwt_class}', str(exception_cm.exception))

    def test_create_success_lenient_verification(self):
        """
            Test creating a token with strict verification disabled.

            Expected Result: A token is created successfully. The create token can be decoded.
        """

        EasyJWT.strict_verification = False

        easyjwt = EasyJWT(self.key)
        easyjwt.expiration_date = self.expiration_date
        easyjwt.issuer = self.issuer
        easyjwt.JWT_ID = self.JWT_ID
        easyjwt.not_before_date = self.not_before_date
        easyjwt.subject = self.subject

        token = easyjwt.create()
        self.assertIsNotNone(token)

        self.assertIsNotNone(easyjwt.issued_at_date)

        claim_set = decode(token, self.key, algorithms=easyjwt._get_decode_algorithms())
        self.assertIsNotNone(claim_set)

    def test_create_success_with_issued_at_date(self):
        """
             Test creating a token with specifying an issued-at date.

             Expected Result: A token is created. The created token can be decoded.
        """

        easyjwt = EasyJWT(self.key)
        easyjwt.expiration_date = self.expiration_date
        easyjwt.issuer = self.issuer
        easyjwt.JWT_ID = self.JWT_ID
        easyjwt.not_before_date = self.not_before_date
        easyjwt.subject = self.subject

        token = easyjwt.create(self.issued_at_date)
        self.assertIsNotNone(token)

        self.assertEqual(self.issued_at_date, easyjwt.issued_at_date)

        claim_set = decode(token, self.key, algorithms=easyjwt._get_decode_algorithms())
        self.assertIsNotNone(claim_set)

    def test_create_success_without_issued_at_date(self):
        """
             Test creating a token without specifying an issued-at date.

             Expected Result: A token is created. The created token can be decoded.
        """

        easyjwt = EasyJWT(self.key)
        easyjwt.expiration_date = self.expiration_date
        easyjwt.issuer = self.issuer
        easyjwt.JWT_ID = self.JWT_ID
        easyjwt.not_before_date = self.not_before_date
        easyjwt.subject = self.subject

        token = easyjwt.create()
        self.assertIsNotNone(token)

        self.assertIsNotNone(easyjwt.issued_at_date)

        claim_set = decode(token, self.key, algorithms=easyjwt._get_decode_algorithms())
        self.assertIsNotNone(claim_set)

    # _get_claim_set()
    # ================

    def test_get_claim_set_lenient_verification(self):
        """
            Test getting the claim set with strict verification disabled.

            Expected Result: The `_easyjwt_class` claim is not included.
        """

        EasyJWT.strict_verification = False
        claim_set = dict()

        easyjwt = EasyJWT(self.key)
        self.assertDictEqual(claim_set, easyjwt._get_claim_set())

    def test_get_claim_set_with_optional_claims(self):
        """
            Test getting the claim set if optional claims are set.

            Expected Result: A dictionary with the entries for the class and the optional claims is returned.
        """

        claim_set = dict(
            _easyjwt_class='EasyJWT',
            aud=self.audience,
            exp=self.expiration_date,
            iat=self.issued_at_date,
            iss=self.issuer,
            jti=self.JWT_ID,
            nbf=self.not_before_date,
            sub=self.subject,
        )

        easyjwt = EasyJWT(self.key)
        easyjwt.audience = self.audience
        easyjwt.expiration_date = self.expiration_date
        easyjwt.issued_at_date = self.issued_at_date
        easyjwt.issuer = self.issuer
        easyjwt.JWT_ID = self.JWT_ID
        easyjwt.not_before_date = self.not_before_date
        easyjwt.subject = self.subject

        self.assertDictEqual(claim_set, easyjwt._get_claim_set())

    def test_get_claim_set_without_optional_claims_and_without_empty_claims(self):
        """
            Test getting the claim set without getting empty claims if optional claims are not set.

            Expected Result: A dictionary with the entry for the class is returned. Optional claims are not included.
        """

        claim_set = dict(
            _easyjwt_class='EasyJWT',
        )

        easyjwt = EasyJWT(self.key)
        self.assertDictEqual(claim_set, easyjwt._get_claim_set(with_empty_claims=False))

    def test_get_claim_set_without_optional_claims_but_with_empty_claims(self):
        """
            Test getting the claim set with getting empty claims if optional claims are not set.

            Expected Result: A dictionary with the entry for the class is returned. Optional claims are included and
                             empty.
        """

        claim_set = dict(
            _easyjwt_class='EasyJWT',
            aud=None,
            exp=None,
            iat=None,
            iss=None,
            jti=None,
            nbf=None,
            sub=None,
        )
        easyjwt = EasyJWT(self.key)
        self.assertDictEqual(claim_set, easyjwt._get_claim_set(with_empty_claims=True))

    # _get_required_empty_claims()
    # ============================

    def test_get_required_empty_claims(self):
        """
            Test getting the claims that are required and empty.

            Expected Result: Only the names of claims that are not optional, but have no value are returned.
        """

        easyjwt = EasyJWT(self.key)

        # Assert there is an optional, empty claim. This claim is not included in the output.
        self.assertIsNone(easyjwt.not_before_date)
        self.assertTrue(easyjwt._is_optional_claim('nbf'))

        # Set an optional claim. This claim is not included in the output.
        easyjwt.expiration_date = self.expiration_date
        self.assertTrue(easyjwt._is_optional_claim('exp'))

        # Create a non-optional claim and set a value. This claim is not included in the output.
        easyjwt.required = True
        self.assertTrue(easyjwt._is_claim('required'))

        # Create a non-optional, empty claim. This claim is included in the output.
        required_empty_claim = 'required_empty'
        easyjwt.required_empty = None
        self.assertTrue(easyjwt._is_claim(required_empty_claim))

        self.assertSetEqual({required_empty_claim}, easyjwt._get_required_empty_claims())

    # endregion

    # region Token Restoration

    # verify()
    # ========

    def test_verify_failure_expired_token(self):
        """
            Test verifying an expired token.

            Expected Result: An `ExpiredTokenError` error is raised.
        """

        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.expiration_date = self.expiration_date - timedelta(minutes=30)

        token = easyjwt_creation.create()

        with self.assertRaises(ExpiredTokenError):
            easyjwt_verification = EasyJWT.verify(token, self.key)
            self.assertIsNone(easyjwt_verification)

    def test_verify_failure_incompatible_key(self):
        """
            Test verifying a token using an incompatible key.

            Expected Result: An `IncompatibleKeyError` error is raised.
        """

        # Ensure that the algorithm needs an HMAC key. Provide a asymmetric key instead.
        incompatible_key = '-----BEGIN PUBLIC KEY-----'
        self.assertIn(EasyJWT.algorithm, {Algorithm.HS256, Algorithm.HS384, Algorithm.HS512})

        easyjwt_creation = EasyJWT(self.key)
        token = easyjwt_creation.create()

        with self.assertRaises(IncompatibleKeyError) as exception_cm:
            easyjwt_verification = EasyJWT.verify(token, incompatible_key)
            self.assertIsNone(easyjwt_verification)

        message = 'The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.'
        self.assertEqual(message, str(exception_cm.exception))

    def test_verify_failure_invalid_audience_no_audience_expected(self):
        """
            Test verifying a token with an audience claim, but without expecting one when verifying the token.

            Expected Result: An `InvalidAudienceError` is raised.
        """

        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.audience = self.audience
        token = easyjwt_creation.create()

        with self.assertRaises(InvalidAudienceError):
            easyjwt_verification = EasyJWT.verify(token, self.key)
            self.assertIsNone(easyjwt_verification)

    def test_verify_failure_invalid_audience_no_audience_in_token(self):
        """
            Test verifying a token without an audience claim, but expecting one.

            Expected Result: An `InvalidClaimSetError` is raised.
        """

        easyjwt_creation = EasyJWT(self.key)
        token = easyjwt_creation.create()

        with self.assertRaises(InvalidClaimSetError) as exception_cm:
            easyjwt_verification = EasyJWT.verify(token, self.key, audience=self.audience)
            self.assertIsNone(easyjwt_verification)

        self.assertIn('audience', exception_cm.exception.missing_claims)

    def test_verify_failure_invalid_audience_wrong_audience(self):
        """
            Test verifying a token with an audience claim, but expecting a different audience when verifying the token.

            Expected Result: An `InvalidAudienceError` is raised.
        """

        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.audience = self.audience
        token = easyjwt_creation.create()

        with self.assertRaises(InvalidAudienceError):
            easyjwt_verification = EasyJWT.verify(token, self.key, audience=['PyJWT'])
            self.assertIsNone(easyjwt_verification)

    def test_verify_failure_invalid_audience_wrong_type(self):
        """
            Test verifying a token with an audience claim, but giving an audience of a wrong type.

            Expected Result: An `InvalidAudienceError` is raised.
        """

        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.audience = self.audience
        token = easyjwt_creation.create()

        with self.assertRaises(InvalidAudienceError):
            # noinspection PyTypeChecker
            easyjwt_verification = EasyJWT.verify(token, self.key, audience=42.1337)
            self.assertIsNone(easyjwt_verification)

    def test_verify_failure_invalid_claim_set(self):
        """
            Test verifying a token with unsupported claims.

            Expected Result: An `InvalidClaimSetError` error is raised.
        """

        easyjwt_creation = EasyJWT(self.key)

        # Add some claim to the object that is not part of the class.
        fake_claim = 'part_of_the_claim_set'
        easyjwt_creation.part_of_the_claim_set = True
        self.assertTrue(easyjwt_creation._is_claim(fake_claim))

        token = easyjwt_creation.create()

        with self.assertRaises(InvalidClaimSetError) as exception_cm:
            easyjwt_verification = EasyJWT.verify(token, self.key)
            self.assertIsNone(easyjwt_verification)

        self.assertIn(fake_claim, str(exception_cm.exception))

    def test_verify_failure_invalid_issued_at(self):
        """
            Test verifying a token with an invalid issued-at date.

            Expected Result: An `InvalidIssuedAtError` is raised.
        """

        easyjwt_creation = EasyJWT(self.key)
        # noinspection PyTypeChecker
        token = easyjwt_creation.create(issued_at='NaN')

        with self.assertRaises(InvalidIssuedAtError):
            easyjwt_verification = EasyJWT.verify(token, self.key)
            self.assertIsNone(easyjwt_verification)

    def test_verify_failure_invalid_issuer(self):
        """
            Test verifying a token with an invalid issuer.

            Expected Result: An `InvalidIssuerError` is raised.
        """

        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.issuer = self.issuer
        token = easyjwt_creation.create()

        invalid_issuer = 'Impersonating ' + self.issuer
        with self.assertRaises(InvalidIssuerError):
            easyjwt_verification = EasyJWT.verify(token, self.key, issuer=invalid_issuer)
            self.assertIsNone(easyjwt_verification)

    def test_verify_failure_invalid_signature(self):
        """
            Test verifying a token using an invalid key.

            Expected Result: An `InvalidSignatureError` error is raised.
        """

        easyjwt_creation = EasyJWT(self.key)
        token = easyjwt_creation.create()

        key = 'invalid-' + self.key
        with self.assertRaises(InvalidSignatureError):
            easyjwt_verification = EasyJWT.verify(token, key)
            self.assertIsNone(easyjwt_verification)

    def test_verify_failure_missing_issuer(self):
        """
            Test verifying a token without giving an issuer.

            Expected Result: An `InvalidIssuerError` is raised.
        """

        easyjwt_creation = EasyJWT(self.key)
        token = easyjwt_creation.create()

        with self.assertRaises(InvalidClaimSetError) as exception_cm:
            easyjwt_verification = EasyJWT.verify(token, self.key, issuer=self.issuer)
            self.assertIsNone(easyjwt_verification)

        self.assertSetEqual({'issuer'}, exception_cm.exception.missing_claims)

    def test_verify_failure_not_yet_valid_token(self):
        """
            Test verifying a token that is not yet valid.

            Expected Result: An `ImmatureTokenError` error is raised.
        """

        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.not_before_date = self.not_before_date + timedelta(minutes=15)

        token = easyjwt_creation.create()

        with self.assertRaises(ImmatureTokenError):
            easyjwt_verification = EasyJWT.verify(token, self.key)
            self.assertIsNone(easyjwt_verification)

    def test_verify_failure_unsupported_algorithm(self):
        """
            Test verifying a token with an incompatible algorithm.

            Expected Result: An `UnsupportedAlgorithmError` is raised.
        """

        # Save the default algorithm to restore it later.
        encoding_algorithm = EasyJWT.algorithm

        easyjwt_creation = EasyJWT(self.key)
        token = easyjwt_creation.create()

        # Change the algorithm for now so that the one used for creation is not supported.
        EasyJWT.algorithm = Algorithm.HS512
        self.assertNotEqual(encoding_algorithm, EasyJWT.algorithm)

        # Try to verify the token.
        with self.assertRaises(UnsupportedAlgorithmError):
            easyjwt_verification = EasyJWT.verify(token, self.key)
            self.assertIsNone(easyjwt_verification)

        # Restore the default algorithm on the class to prevent side effect on other parts of the tests.
        EasyJWT.algorithm = encoding_algorithm

    def test_verify_failure_verification_error(self):
        """
            Test verifying a token with an expiration date claim that is not an integer.

            Expected Result: A `VerificationError` is raised.
        """

        # Create the token with a string expiration date.
        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.expiration_date = 'January 1, 2019 12:34.56'
        token = easyjwt_creation.create()

        # Try to verify the token.
        with self.assertRaises(VerificationError) as exception_cm:
            easyjwt_verification = EasyJWT.verify(token, self.key)
            self.assertIsNone(easyjwt_verification)

        self.assertEqual('Expiration Time claim (exp) must be an integer.', str(exception_cm.exception))

    def test_verify_success_lenient_verification(self):
        """
            Test verifying a token without the `_easyjwt_class` claim with strict verification disabled.

            Expected Result: The token is successfully verified and an object representing the token is returned.
        """

        EasyJWT.strict_verification = False

        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.JWT_ID = self.JWT_ID
        easyjwt_creation.subject = self.subject
        token = easyjwt_creation.create()

        easyjwt_verification = EasyJWT.verify(token, self.key)
        self.assertIsNotNone(easyjwt_verification)
        self.assertEqual(easyjwt_creation._key, easyjwt_verification._key)
        self.assertEqual(easyjwt_creation.audience, easyjwt_verification.audience)
        self.assertEqual(easyjwt_creation.expiration_date, easyjwt_verification.expiration_date)
        self.assertEqual(easyjwt_creation.issued_at_date, easyjwt_verification.issued_at_date)
        self.assertEqual(easyjwt_creation.issuer, easyjwt_verification.issuer)
        self.assertEqual(easyjwt_creation.JWT_ID, easyjwt_verification.JWT_ID)
        self.assertEqual(easyjwt_creation.not_before_date, easyjwt_verification.not_before_date)
        self.assertEqual(easyjwt_creation.subject, easyjwt_verification.subject)
        self.assertNotIn('_easyjwt_class', vars(easyjwt_verification))

    def test_verify_success_with_validated_registered_claims(self):
        """
            Test verifying a valid token with valid registered claims that are validated (exp, iss, nbf), using the
            correct key.

            Expected Result: An object representing the token is returned.
        """

        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.audience = self.audience
        easyjwt_creation.expiration_date = self.expiration_date
        easyjwt_creation.issuer = self.issuer
        easyjwt_creation.JWT_ID = self.JWT_ID
        easyjwt_creation.not_before_date = self.not_before_date
        easyjwt_creation.subject = self.subject
        token = easyjwt_creation.create()

        easyjwt_verification = EasyJWT.verify(token, self.key, issuer=self.issuer, audience=self.audience)
        self.assertIsNotNone(easyjwt_verification)
        self.assertEqual(easyjwt_creation._key, easyjwt_verification._key)
        self.assertEqual(easyjwt_creation.audience, easyjwt_verification.audience)
        self.assertEqual(easyjwt_creation.expiration_date, easyjwt_verification.expiration_date)
        self.assertEqual(easyjwt_creation.issued_at_date, easyjwt_verification.issued_at_date)
        self.assertEqual(easyjwt_creation.issuer, easyjwt_verification.issuer)
        self.assertEqual(easyjwt_creation.JWT_ID, easyjwt_verification.JWT_ID)
        self.assertEqual(easyjwt_creation.not_before_date, easyjwt_verification.not_before_date)
        self.assertEqual(easyjwt_creation.subject, easyjwt_verification.subject)
        self.assertEqual(easyjwt_creation._easyjwt_class, easyjwt_verification._easyjwt_class)

    def test_verify_success_without_validated_registered_claims(self):
        """
            Test verifying a valid token without registered claims that are validated (exp, iss, nbf), using the correct
            key.

            Expected Result: An object representing the token is returned.
        """

        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.JWT_ID = self.JWT_ID
        easyjwt_creation.subject = self.subject
        token = easyjwt_creation.create()

        easyjwt_verification = EasyJWT.verify(token, self.key)
        self.assertIsNotNone(easyjwt_verification)
        self.assertEqual(easyjwt_creation._key, easyjwt_verification._key)
        self.assertEqual(easyjwt_creation.audience, easyjwt_verification.audience)
        self.assertEqual(easyjwt_creation.expiration_date, easyjwt_verification.expiration_date)
        self.assertEqual(easyjwt_creation.issued_at_date, easyjwt_verification.issued_at_date)
        self.assertEqual(easyjwt_creation.issuer, easyjwt_verification.issuer)
        self.assertEqual(easyjwt_creation.JWT_ID, easyjwt_verification.JWT_ID)
        self.assertEqual(easyjwt_creation.not_before_date, easyjwt_verification.not_before_date)
        self.assertEqual(easyjwt_creation.subject, easyjwt_verification.subject)
        self.assertEqual(easyjwt_creation._easyjwt_class, easyjwt_verification._easyjwt_class)

    # _get_claim_names()
    # ==================

    def test_get_claim_names_lenient_verification(self):
        """
            Test getting the set of claim names with strict verification disabled.

            Expected Result: A set with the claim names for the `EasyJWT` class and all optional claims returned.
        """

        EasyJWT.strict_verification = False

        claim_names = {'aud', 'exp', 'iat', 'iss', 'jti', 'nbf', 'sub'}
        easyjwt = EasyJWT(self.key)
        self.assertSetEqual(claim_names, easyjwt._get_claim_names())

    def test_get_claim_names_strict_verification(self):
        """
            Test getting the set of claim names with strict verification enabled.

            Expected Result: A set with the claim names for the `EasyJWT` class and all optional claims returned.
        """

        claim_names = {'_easyjwt_class', 'aud', 'exp', 'iat', 'iss', 'jti', 'nbf', 'sub'}
        easyjwt = EasyJWT(self.key)
        self.assertSetEqual(claim_names, easyjwt._get_claim_names())

    def test_claim_names_and_claim_set_keys_equal(self):
        """
            Assert that the set of claim names is exactly the same as the set of claim set keys (if empty claims are
            included).

            Expected Result: The set of claim names equals the set of claim set keys.
        """

        easyjwt = EasyJWT(self.key)
        claim_names = easyjwt._get_claim_names()
        claim_set = easyjwt._get_claim_set(with_empty_claims=True)
        self.assertSetEqual(claim_names, set(claim_set.keys()))

    # _get_decode_algorithms()
    # ========================

    def test_get_decode_algorithms(self):
        """
            Test getting the algorithms for decoding a token.

            Expected Result: A set of all previous encoding algorithms and the current one is returned.
        """

        # Temporarily save the current class variables to restore them later. Otherwise, changes could influence other
        # parts of the tests.
        current_alg_temp = EasyJWT.algorithm
        previous_algs_temp = EasyJWT.previous_algorithms

        # Set some test algorithms.
        EasyJWT.algorithm = Algorithm.HS256
        EasyJWT.previous_algorithms = [Algorithm.HS384, Algorithm.HS512]

        algorithms = [Algorithm.HS384.value, Algorithm.HS512.value, Algorithm.HS256.value]
        self.assertListEqual(algorithms, EasyJWT._get_decode_algorithms())

        # Restore the class variables.
        EasyJWT.algorithm = current_alg_temp
        EasyJWT.previous_algorithms = previous_algs_temp

    # _get_restore_method_for_claim()
    # ===============================

    def test_get_restore_method_for_claim_expiration_date(self):
        """
            Test getting the restore method for the expiration date.

            Expected Result: The method `restoration.restore_timestamp_to_datetime()` is returned.
        """

        restore_method = EasyJWT._get_restore_method_for_claim('expiration_date')
        self.assertEqual(restore_timestamp_to_datetime, restore_method)

    def test_get_restore_method_for_claim_issued_at_date(self):
        """
            Test getting the restore method for the issued-at date.

            Expected Result: The method `restoration.restore_timestamp_to_datetime()` is returned.
        """

        restore_method = EasyJWT._get_restore_method_for_claim('issued_at_date')
        self.assertEqual(restore_timestamp_to_datetime, restore_method)

    def test_get_restore_method_for_claim_none(self):
        """
            Test getting the restore method for a claim that has no such method.

            Expected Result: `None`.
        """

        restore_method = EasyJWT._get_restore_method_for_claim('claim_with_no_restore_method')
        self.assertIsNone(restore_method)

    def test_get_restore_method_for_claim_not_before_date(self):
        """
            Test getting the restore method for the not-before date.

            Expected Result: The method `restoration.restore_timestamp_to_datetime()` is returned.
        """

        restore_method = EasyJWT._get_restore_method_for_claim('not_before_date')
        self.assertEqual(restore_timestamp_to_datetime, restore_method)

    # _restore_claim_set()
    # ====================

    def test_restore_claim_set_with_optional_claims(self):
        """
            Test restoring a claim set if optional claims are given.

            Expected Result: The values in the claim set are correctly mapped to their respective instance variables.
                             The date values are converted to `datetime` objects.
        """

        # Prepare a claim set. The dates must be included as a timestamp (seconds since the epoch).
        exp_timestamp = int(self.expiration_date.replace(tzinfo=timezone.utc).timestamp())
        iat_timestamp = int(self.issued_at_date.replace(tzinfo=timezone.utc).timestamp())
        nbf_timestamp = int(self.not_before_date.replace(tzinfo=timezone.utc).timestamp())
        claim_set = dict(
            _easyjwt_class='EasyJWT',
            aud=self.audience,
            exp=exp_timestamp,
            iat=iat_timestamp,
            iss=self.issuer,
            jti=self.JWT_ID,
            nbf=nbf_timestamp,
            sub=self.subject,
        )

        easyjwt = EasyJWT(self.key)
        easyjwt._restore_claim_set(claim_set)
        self.assertEqual(self.audience, easyjwt.audience)
        self.assertEqual(self.expiration_date, easyjwt.expiration_date)
        self.assertEqual(self.issued_at_date, easyjwt.issued_at_date)
        self.assertEqual(self.issuer, easyjwt.issuer)
        self.assertEqual(self.JWT_ID, easyjwt.JWT_ID)
        self.assertEqual(self.not_before_date, easyjwt.not_before_date)
        self.assertEqual(self.subject, easyjwt.subject)

    def test_restore_claim_set_without_optional_claims(self):
        """
            Test restoring a claim set if optional claims are not given.

            Expected Result: The values in the claim set are mapped to their respective instance variables. Optional
                             claims are empty, without causing an error.
        """

        claim_set = dict(
            _easyjwt_class='EasyJWT',
        )

        easyjwt = EasyJWT(self.key)
        easyjwt._restore_claim_set(claim_set)
        self.assertIsNone(easyjwt.audience)
        self.assertIsNone(easyjwt.expiration_date)
        self.assertIsNone(easyjwt.issued_at_date)
        self.assertIsNone(easyjwt.issuer)
        self.assertIsNone(easyjwt.JWT_ID)
        self.assertIsNone(easyjwt.not_before_date)
        self.assertIsNone(easyjwt.subject)

    # _verify_claim_set()
    # ===================

    def test_verify_claim_set_failure_class_missing(self):
        """
            Test verifying a claim set with a missing class claim.

            Expected result: An `UnspecifiedClassError` error is raised.
        """

        # Remove the class claim from the claim set.
        easyjwt = EasyJWT(self.key)
        claim_set = easyjwt._get_claim_set()
        del claim_set['_easyjwt_class']

        with self.assertRaises(UnspecifiedClassError):
            easyjwt._verify_claim_set(claim_set)

    def test_verify_claim_set_failure_class_wrong(self):
        """
            Test verifying a claim set with a faulty value in the class claim.

            Expected result: An `InvalidClassError` error with an explaining message is raised.
        """

        # Manipulate the class claim in the claim set.
        easyjwt = EasyJWT(self.key)
        claim_set = easyjwt._get_claim_set()
        claim_set['_easyjwt_class'] = 'InheritedEasyJWT'

        with self.assertRaises(InvalidClassError) as exception_cm:
            easyjwt._verify_claim_set(claim_set)

        self.assertEqual('Expected class EasyJWT. Got class InheritedEasyJWT', str(exception_cm.exception))

    def test_verify_claim_set_failure_claims_missing(self):
        """
            Test verifying a claim set with missing claims.

            Expected result: An `InvalidClaimSetError` error with an explaining message is raised.
        """

        # Create a new instance variable in the object by assigning to it. This instance variable will automatically
        # become a claim. When calling the verify method on this object, this should cause the expected failure if the
        # claim is not in the created token.
        easyjwt = EasyJWT(self.key)
        easyjwt.email = 'test@example.com'

        # Now remove the claim from the claim set.
        claim_set = easyjwt._get_claim_set()
        del claim_set['email']

        with self.assertRaises(InvalidClaimSetError) as exception_cm:
            easyjwt._verify_claim_set(claim_set)

        self.assertEqual('Missing claims: {email}. Unexpected claims: {}', str(exception_cm.exception))

    def test_verify_claim_set_failure_claims_unexpected(self):
        """
            Test verifying a claim set with unexpected claims.

            Expected result: An `InvalidClaimSetError` error with an explaining message is raised.
        """

        easyjwt = EasyJWT(self.key)

        # Add a claim to the claim set.
        claim_set = easyjwt._get_claim_set()
        claim_set['user_id'] = 42

        with self.assertRaises(InvalidClaimSetError) as exception_cm:
            easyjwt._verify_claim_set(claim_set)

        self.assertEqual('Missing claims: {}. Unexpected claims: {user_id}', str(exception_cm.exception))

    def test_verify_claim_set_failure_claims_unexpected_and_missing(self):
        """
            Test verifying a claim set with missing and unexpected claims.

            Expected result: An `InvalidClaimSetError` error with an explaining message is raised.
        """

        # Create a new instance variable in the object by assigning to it. This instance variable will automatically
        # become a claim. When calling the verify method on this object, this should cause the expected failure if the
        # claim is not in the created token.
        easyjwt = EasyJWT(self.key)
        easyjwt.email = 'test@example.com'

        # Now remove the (now expected) claim from the claim set. Meanwhile, add an unexpected claim to the claim set.
        claim_set = easyjwt._get_claim_set()
        claim_set['user_id'] = 1
        del claim_set['email']

        with self.assertRaises(InvalidClaimSetError) as exception_cm:
            easyjwt._verify_claim_set(claim_set)

        self.assertEqual('Missing claims: {email}. Unexpected claims: {user_id}', str(exception_cm.exception))

    def test_verify_claim_set_success_lenient_verification(self):
        """
            Test verifying a valid claim set without an `_easyjwt_class` claim with strict verification disabled.

            Expected result: `True`
        """

        EasyJWT.strict_verification = False

        easyjwt = EasyJWT(self.key)
        easyjwt.audience = self.audience
        easyjwt.expiration_date = self.expiration_date
        easyjwt.issued_at_date = self.issued_at_date
        easyjwt.issuer = self.issuer
        easyjwt.JWT_ID = self.JWT_ID
        easyjwt.not_before_date = self.not_before_date
        easyjwt.subject = self.subject

        claim_set = easyjwt._get_claim_set()
        self.assertTrue(easyjwt._verify_claim_set(claim_set))

    def test_verify_claim_set_success_with_optional_claims(self):
        """
            Test verifying a valid claim set containing (valid) optional claims.

            Expected result: `True`
        """

        easyjwt = EasyJWT(self.key)
        easyjwt.audience = self.audience
        easyjwt.expiration_date = self.expiration_date
        easyjwt.issued_at_date = self.issued_at_date
        easyjwt.issuer = self.issuer
        easyjwt.JWT_ID = self.JWT_ID
        easyjwt.not_before_date = self.not_before_date
        easyjwt.subject = self.subject

        claim_set = easyjwt._get_claim_set()
        self.assertTrue(easyjwt._verify_claim_set(claim_set))

    def test_verify_claim_set_success_without_optional_claims(self):
        """
            Test verifying a valid claim set not containing optional claims.

            Expected result: `True`
        """

        easyjwt = EasyJWT(self.key)

        claim_set = easyjwt._get_claim_set()
        self.assertTrue(easyjwt._verify_claim_set(claim_set))

    # endregion

    # region Instance Variable and Claim Helpers

    # _is_claim()
    # ===========

    def test_is_claim_blacklist(self):
        """
            Test if the instance variables in the blacklist are claims.

            Expected Result: `False` for all variables in the blacklist.
        """

        for instance_var in EasyJWT._public_non_claims:
            self.assertFalse(EasyJWT._is_claim(instance_var), f'{instance_var} unexpectedly is a claim')

    def test_is_claim_private_instance_vars(self):
        """
            Test if private instance variables that are not in the whitelist are claims.

            Expected Result: `False`
        """

        instance_var = '_not_part_of_the_claim_set'
        self.assertNotIn(instance_var, EasyJWT._private_claims)
        self.assertFalse(EasyJWT._is_claim(instance_var))

    def test_is_claim_public_instance_vars(self):
        """
            Test if public instance variables that are not in the blacklist are claims.

            Expected Result: `True`
        """

        instance_var = 'part_of_the_claim_set'
        self.assertNotIn(instance_var, EasyJWT._private_claims)
        self.assertTrue(EasyJWT._is_claim(instance_var))

    def test_is_claim_whitelist(self):
        """
            Test if the instance variables in the whitelist are claims.

            Expected Result: `True` for all variables in the whitelist.
        """

        for instance_var in EasyJWT._private_claims:
            self.assertTrue(EasyJWT._is_claim(instance_var), f'{instance_var} unexpectedly is not a claim')

    # _is_optional_claim()
    # ====================

    def test_is_optional_claim_easyjwt_class(self):
        """
            Test if the claim for the `EasyJWT` class is optional.

            Expected Result: `False`
        """

        self.assertFalse(EasyJWT._is_optional_claim('_easyjwt_class'))

    def test_is_optional_claim_non_optional_claim(self):
        """
            Test if a claim that is not in the optional claims set is optional.

            Expected Result: `False`
        """

        claim = 'non_optional_claim'
        self.assertNotIn(claim, EasyJWT._optional_claims)
        self.assertFalse(EasyJWT._is_optional_claim(claim))

    def test_is_optional_claim_optional_set(self):
        """
            Test if the claims in the optional claims set are optional.

            Expected Result: `True` for all claims in the set.
        """

        for claim in EasyJWT._optional_claims:
            self.assertTrue(EasyJWT._is_optional_claim(claim), f'{claim} unexpectedly is not optional')

    # _map_claim_name_to_instance_var()
    # =================================

    def test_map_claim_name_to_instance_var_mapped(self):
        """
            Test that all claim names in the mapping return the corresponding instance variable name.

            Expected Result: The instance variable name for each claim name is returned.
        """

        for instance_var, claim_name in EasyJWT._instance_var_claim_name_mapping.items():
            self.assertEqual(instance_var, EasyJWT._map_claim_name_to_instance_var(instance_var))

    def test_map_claim_name_to_instance_var_unmapped(self):
        """
            Test that a claim name that is not in the map is returned as the instance variable.

            Expected Result: The name of the claim is returned unchanged.
        """

        claim_name = 'part_of_the_claim_set'
        self.assertNotIn(claim_name, EasyJWT._instance_var_claim_name_mapping.inv)
        self.assertEqual(claim_name, EasyJWT._map_claim_name_to_instance_var(claim_name))

    # _map_instance_var_to_claim_name()
    # =================================

    def test_map_instance_var_to_claim_name_mapped(self):
        """
            Test that all instance variable names in the mapping return the corresponding claim name.

            Expected Result: The claim name for each instance variable name is returned.
        """

        for instance_var, claim_name in EasyJWT._instance_var_claim_name_mapping.items():
            self.assertEqual(claim_name, EasyJWT._map_instance_var_to_claim_name(instance_var))

    def test_map_instance_var_to_claim_name_unmapped(self):
        """
            Test that an instance variable that is not in the map is returned as the claim name.

            Expected Result: The name of the instance variable is returned unchanged.
        """

        instance_var = 'part_of_the_claim_set'
        self.assertNotIn(instance_var, EasyJWT._instance_var_claim_name_mapping)
        self.assertEqual(instance_var, EasyJWT._map_instance_var_to_claim_name(instance_var))

    # endregion

    # region Others

    # _get_class_name()
    # =================

    def test_get_class_name(self):
        """
            Test getting the name of the class.

            Expected Result: `EasyJWT`
        """

        easyjwt = EasyJWT(self.key)
        self.assertEqual('EasyJWT', easyjwt._get_class_name())

    # endregion

    # region System Methods

    # __str__()
    # =========

    def test_str(self):
        """
            Test converting the object to a string.

            Expected Result: The token is returned as if `create()` had been called.
        """

        easyjwt = EasyJWT(self.key)

        # Note: If this assertion ever fails it might be because the issued-at date is set within `create()` and the
        # difference between the two calls is too large.
        self.assertEqual(easyjwt.create(), str(easyjwt))

    # endregion

    # region Registered Claims

    # Audience
    # ========

    def test_registered_claim_audience(self):
        """
            Test the registered claim ``aud``.

            Expected Result: The field is an optional claim and correctly mapped to the claim name and vice versa.
        """
        instance_var_name = 'audience'
        claim_name = 'aud'

        self.assertTrue(EasyJWT._is_claim(instance_var_name))
        self.assertTrue(EasyJWT._is_optional_claim(claim_name))
        self.assertEqual(instance_var_name, EasyJWT._map_claim_name_to_instance_var(claim_name))
        self.assertEqual(claim_name, EasyJWT._map_instance_var_to_claim_name(instance_var_name))

    def test_registered_claim_expiration_date(self):
        """
            Test the registered claim ``exp``.

            Expected Result: The field is an optional claim and correctly mapped to the claim name and vice versa.
        """
        instance_var_name = 'expiration_date'
        claim_name = 'exp'

        self.assertTrue(EasyJWT._is_claim(instance_var_name))
        self.assertTrue(EasyJWT._is_optional_claim(claim_name))
        self.assertEqual(instance_var_name, EasyJWT._map_claim_name_to_instance_var(claim_name))
        self.assertEqual(claim_name, EasyJWT._map_instance_var_to_claim_name(instance_var_name))

    def test_registered_claim_issued_at_date(self):
        """
            Test the registered claim ``iat``.

            Expected Result: The field is an optional claim and correctly mapped to the claim name and vice versa.
        """
        instance_var_name = 'issued_at_date'
        claim_name = 'iat'

        self.assertTrue(EasyJWT._is_claim(instance_var_name))
        self.assertTrue(EasyJWT._is_optional_claim(claim_name))
        self.assertEqual(instance_var_name, EasyJWT._map_claim_name_to_instance_var(claim_name))
        self.assertEqual(claim_name, EasyJWT._map_instance_var_to_claim_name(instance_var_name))

    def test_registered_claim_issuer(self):
        """
            Test the registered claim ``iss``.

            Expected Result: The field is an optional claim and correctly mapped to the claim name and vice versa.
        """
        instance_var_name = 'issuer'
        claim_name = 'iss'

        self.assertTrue(EasyJWT._is_claim(instance_var_name))
        self.assertTrue(EasyJWT._is_optional_claim(claim_name))
        self.assertEqual(instance_var_name, EasyJWT._map_claim_name_to_instance_var(claim_name))
        self.assertEqual(claim_name, EasyJWT._map_instance_var_to_claim_name(instance_var_name))

    def test_registered_claim_JWT_ID(self):
        """
            Test the registered claim ``jti``.

            Expected Result: The field is an optional claim and correctly mapped to the claim name and vice versa.
        """
        instance_var_name = 'JWT_ID'
        claim_name = 'jti'

        self.assertTrue(EasyJWT._is_claim(instance_var_name))
        self.assertTrue(EasyJWT._is_optional_claim(claim_name))
        self.assertEqual(instance_var_name, EasyJWT._map_claim_name_to_instance_var(claim_name))
        self.assertEqual(claim_name, EasyJWT._map_instance_var_to_claim_name(instance_var_name))

    def test_registered_claim_not_before_date(self):
        """
            Test the registered claim ``nbf``.

            Expected Result: The field is an optional claim and correctly mapped to the claim name and vice versa.
        """
        instance_var_name = 'not_before_date'
        claim_name = 'nbf'

        self.assertTrue(EasyJWT._is_claim(instance_var_name))
        self.assertTrue(EasyJWT._is_optional_claim(claim_name))
        self.assertEqual(instance_var_name, EasyJWT._map_claim_name_to_instance_var(claim_name))
        self.assertEqual(claim_name, EasyJWT._map_instance_var_to_claim_name(instance_var_name))

    def test_registered_claim_subject(self):
        """
            Test the registered claim ``sub``.

            Expected Result: The field is an optional claim and correctly mapped to the claim name and vice versa.
        """
        instance_var_name = 'subject'
        claim_name = 'sub'

        self.assertTrue(EasyJWT._is_claim(instance_var_name))
        self.assertTrue(EasyJWT._is_optional_claim(claim_name))
        self.assertEqual(instance_var_name, EasyJWT._map_claim_name_to_instance_var(claim_name))
        self.assertEqual(claim_name, EasyJWT._map_instance_var_to_claim_name(instance_var_name))

    # endregion
