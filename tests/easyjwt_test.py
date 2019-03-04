#!venv/bin/python
# -*- coding: utf-8 -*-

from unittest import TestCase

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from jwt import decode
from jwt import ExpiredSignatureError
from jwt import ImmatureSignatureError

from easyjwt import Algorithm
from easyjwt import EasyJWT
from easyjwt import MissingClassError
from easyjwt import PayloadFieldError
from easyjwt import WrongClassError
from easyjwt.restoration import restore_timestamp_to_datetime


class EasyJWTTest(TestCase):

    # region Test Setup

    def setUp(self):
        """
            Prepare the test cases.
        """

        self.key = 'abcdefghijklmnopqrstuvwxyz'

        # Do not use microseconds.
        self.expiration_date = datetime.utcnow().replace(microsecond=0) + timedelta(minutes=15)
        self.issued_at_date = datetime.utcnow().replace(microsecond=0) + timedelta(minutes=1)
        self.not_before_date = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=5)

    # endregion

    # region Instantiation

    # __init__()
    # ==========

    def test_init(self):
        """
            Test initializing a new token object.

            Expected Result: The instance variables are set correctly.
        """

        easyjwt = EasyJWT(self.key)

        self.assertEqual(easyjwt._get_class_name(), easyjwt._easyjwt_class)
        self.assertEqual(self.key, easyjwt._key)

        self.assertIsNone(easyjwt.expiration_date)
        self.assertIsNone(easyjwt.issued_at_date)
        self.assertIsNone(easyjwt.not_before_date)

    # endregion

    # region Token Creation

    # create()
    # ========

    def test_create_with_issued_at_date(self):
        """
             Test creating a token with specifying an issued-at date.

             Expected Result: A token is created. The created token can be decoded.
        """
        easyjwt = EasyJWT(self.key)
        easyjwt.expiration_date = self.expiration_date
        easyjwt.not_before_date = self.not_before_date

        token = easyjwt.create(self.issued_at_date)
        self.assertIsNotNone(token)

        self.assertEqual(self.issued_at_date, easyjwt.issued_at_date)

        payload = decode(token, self.key, algorithms=easyjwt._get_decode_algorithms())
        self.assertIsNotNone(payload)

    def test_create_without_issued_at_date(self):
        """
             Test creating a token without specifying an issued-at date.

             Expected Result: A token is created. The created token can be decoded.
        """
        easyjwt = EasyJWT(self.key)
        easyjwt.expiration_date = self.expiration_date
        easyjwt.not_before_date = self.not_before_date

        token = easyjwt.create()
        self.assertIsNotNone(token)

        self.assertIsNotNone(easyjwt.issued_at_date)

        payload = decode(token, self.key, algorithms=easyjwt._get_decode_algorithms())
        self.assertIsNotNone(payload)

    # _get_payload()
    # ==============

    def test_get_payload_with_optional_fields(self):
        """
            Test getting the payload dictionary with setting optional fields.

            Expected Result: A dictionary with the entries for the class and the optional fields is returned.
        """
        payload = dict(
            _easyjwt_class='EasyJWT',
            exp=self.expiration_date,
            iat=self.issued_at_date,
            nbf=self.not_before_date,
        )
        easyjwt = EasyJWT(self.key)
        easyjwt.expiration_date = self.expiration_date
        easyjwt.issued_at_date = self.issued_at_date
        easyjwt.not_before_date = self.not_before_date

        self.assertDictEqual(payload, easyjwt._get_payload())

    def test_get_payload_without_optional_fields_and_without_empty_fields(self):
        """
            Test getting the payload dictionary without setting optional fields and without getting empty fields.

            Expected Result: A dictionary with the entry for the class is returned.
        """
        payload = dict(
            _easyjwt_class='EasyJWT',
        )
        easyjwt = EasyJWT(self.key)
        self.assertDictEqual(payload, easyjwt._get_payload(with_empty_fields=False))

    def test_get_payload_without_optional_fields_but_with_empty_fields(self):
        """
            Test getting the payload dictionary without setting optional fields but with getting empty fields.

            Expected Result: A dictionary with entries for the class and empty optional fields is returned.
        """
        payload = dict(
            _easyjwt_class='EasyJWT',
            exp=None,
            iat=None,
            nbf=None,
        )
        easyjwt = EasyJWT(self.key)
        self.assertDictEqual(payload, easyjwt._get_payload(with_empty_fields=True))

    # endregion

    # region Token Restoration

    # verify()
    # ========

    def test_verify_failure_expired_token(self):
        """
            Test verifying an expired token.

            Expected Result: No object representing the token is returned, but an error is raised.
        """
        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.expiration_date = self.expiration_date - timedelta(minutes=30)

        token = easyjwt_creation.create()

        with self.assertRaises(ExpiredSignatureError):
            easyjwt_verification = EasyJWT.verify(token, self.key)
            self.assertIsNone(easyjwt_verification)

    def test_verify_failure_invalid_token(self):
        """
            Test verifying an invalid token.

            Expected Result: No object representing the token is returned, but an error is raised.
        """
        easyjwt_creation = EasyJWT(self.key)

        # Add some payload field to the object that is not part of the class.
        fake_field = 'part_of_the_payload'
        easyjwt_creation.part_of_the_payload = True
        self.assertTrue(easyjwt_creation._is_payload_field(fake_field))

        token = easyjwt_creation.create()

        with self.assertRaises(PayloadFieldError) as exception_cm:
            easyjwt_verification = EasyJWT.verify(token, self.key)
            self.assertIsNone(easyjwt_verification)
            self.assertIn(fake_field, str(exception_cm.exception))

    def test_verify_failure_not_yet_valid_token(self):
        """
            Test verifying a token that is not yet valid.

            Expected Result: No object representing the token is returned, but an error is raised.
        """
        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.not_before_date = self.not_before_date + timedelta(minutes=15)

        token = easyjwt_creation.create()

        with self.assertRaises(ImmatureSignatureError):
            easyjwt_verification = EasyJWT.verify(token, self.key)
            self.assertIsNone(easyjwt_verification)

    def test_verify_success_with_expiration_date_and_not_before_date(self):
        """
            Test verifying a valid token with an expiration date and a not-before date with the correct key.

            Expected Result: An object representing the token is returned.
        """

        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.expiration_date = self.expiration_date
        easyjwt_creation.not_before_date = self.not_before_date
        token = easyjwt_creation.create()

        easyjwt_verification = EasyJWT.verify(token, self.key)
        self.assertIsNotNone(easyjwt_verification)
        self.assertEqual(easyjwt_creation._key, easyjwt_verification._key)
        self.assertEqual(easyjwt_creation.expiration_date, easyjwt_verification.expiration_date)
        self.assertEqual(easyjwt_creation.not_before_date, easyjwt_verification.not_before_date)
        self.assertEqual(easyjwt_creation._easyjwt_class, easyjwt_verification._easyjwt_class)

    def test_verify_success_without_expiration_date_and_not_before_date(self):
        """
            Test verifying a valid token without an expiration date and a not-before date with the correct key.

            Expected Result: An object representing the token is returned.
        """

        easyjwt_creation = EasyJWT(self.key)
        token = easyjwt_creation.create()

        easyjwt_verification = EasyJWT.verify(token, self.key)
        self.assertIsNotNone(easyjwt_verification)
        self.assertEqual(easyjwt_creation._key, easyjwt_verification._key)
        self.assertEqual(easyjwt_creation.expiration_date, easyjwt_verification.expiration_date)
        self.assertEqual(easyjwt_creation.not_before_date, easyjwt_verification.not_before_date)
        self.assertEqual(easyjwt_creation._easyjwt_class, easyjwt_verification._easyjwt_class)

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

        algorithms = {Algorithm.HS256.value, Algorithm.HS384.value, Algorithm.HS512.value}
        self.assertSetEqual(algorithms, EasyJWT._get_decode_algorithms())

        # Restore the class variables.
        EasyJWT.algorithm = current_alg_temp
        EasyJWT.previous_algorithms = previous_algs_temp

    # _get_payload_fields()
    # =====================

    def test_get_payload_fields(self):
        """
            Test getting the list of payload fields.

            Expected Result: A set with the field for the EasyJWT class and all claims is returned.
        """
        payload_fields = {'_easyjwt_class', 'exp', 'iat', 'nbf'}
        easyjwt = EasyJWT(self.key)
        self.assertSetEqual(payload_fields, easyjwt._get_payload_fields())

    def test_payload_fields_and_payload_keys_equal(self):
        """
            Assert that the list of payload fields is exactly the same as the list of payload keys (if empty fields are
            included).

            Expected Result: The list of payload fields equals the list of payload keys.
        """
        easyjwt = EasyJWT(self.key)
        payload_fields = easyjwt._get_payload_fields()
        payload = easyjwt._get_payload(with_empty_fields=True)
        self.assertSetEqual(payload_fields, set(payload.keys()))

    # _get_restore_method_for_payload_field()
    # =======================================

    def test_get_restore_method_for_payload_field_expiration_date(self):
        """
            Test getting the restore method for the expiration date.

            Expected Result: The method `restoration.restore_timestamp_to_datetime()` is returned.
        """
        restore_method = EasyJWT._get_restore_method_for_payload_field('expiration_date')
        self.assertEqual(restore_timestamp_to_datetime, restore_method)

    def test_get_restore_method_for_payload_field_issued_at_date(self):
        """
            Test getting the restore method for the issued-at date.

            Expected Result: The method `restoration.restore_timestamp_to_datetime()` is returned.
        """
        restore_method = EasyJWT._get_restore_method_for_payload_field('issued_at_date')
        self.assertEqual(restore_timestamp_to_datetime, restore_method)

    def test_get_restore_method_for_payload_field_none(self):
        """
            Test getting the restore method for a payload that has no such method.

            Expected Result: `None`.
        """
        restore_method = EasyJWT._get_restore_method_for_payload_field('payload_field_with_no_restore_method')
        self.assertIsNone(restore_method)

    def test_get_restore_method_for_payload_field_not_before_date(self):
        """
            Test getting the restore method for the not-before date.

            Expected Result: The method `restoration.restore_timestamp_to_datetime()` is returned.
        """
        restore_method = EasyJWT._get_restore_method_for_payload_field('not_before_date')
        self.assertEqual(restore_timestamp_to_datetime, restore_method)

    # _restore_payload()
    # ==================

    def test_restore_payload_with_optional_fields(self):
        """
            Test restoring a payload dictionary if optional fields are given.

            Expected Result: The values in the payload are mapped to their respective instance variables.
        """
        exp_timestamp = int(self.expiration_date.replace(tzinfo=timezone.utc).timestamp())
        iat_timestamp = int(self.issued_at_date.replace(tzinfo=timezone.utc).timestamp())
        nbf_timestamp = int(self.not_before_date.replace(tzinfo=timezone.utc).timestamp())
        payload = dict(
            _easyjwt_class='EasyJWT',
            exp=exp_timestamp,
            iat=iat_timestamp,
            nbf=nbf_timestamp,
        )

        easyjwt = EasyJWT(self.key)
        easyjwt._restore_payload(payload)
        self.assertEqual(self.expiration_date, easyjwt.expiration_date)
        self.assertEqual(self.issued_at_date, easyjwt.issued_at_date)
        self.assertEqual(self.not_before_date, easyjwt.not_before_date)

    def test_restore_payload_without_optional_fields(self):
        """
            Test restoring a payload dictionary if optional fields are not given.

            Expected Result: The values in the payload are mapped to their respective instance variables.
        """
        payload = dict(
            _easyjwt_class='EasyJWT',
        )

        easyjwt = EasyJWT(self.key)
        easyjwt._restore_payload(payload)
        self.assertIsNone(easyjwt.expiration_date)
        self.assertIsNone(easyjwt.issued_at_date)
        self.assertIsNone(easyjwt.not_before_date)

    # _verify_payload()
    # =================

    def test_verify_payload_failure_class_missing(self):
        """
            Test verifying a payload with a missing class field.

            Expected result: The exception for a missing class is raised.
        """
        easyjwt = EasyJWT(self.key)
        payload = easyjwt._get_payload()
        del payload['_easyjwt_class']

        with self.assertRaises(MissingClassError):
            easyjwt._verify_payload(payload)

    def test_verify_payload_failure_class_wrong(self):
        """
            Test verifying a payload with a faulty value in the class field.

            Expected result: An exception with an explaining message is raised.
        """
        easyjwt = EasyJWT(self.key)
        payload = easyjwt._get_payload()
        payload['_easyjwt_class'] = 'InheritedEasyJWT'

        with self.assertRaises(WrongClassError) as exception_cm:
            easyjwt._verify_payload(payload)

        self.assertEqual('Expected class EasyJWT. Got class InheritedEasyJWT', str(exception_cm.exception))

    def test_verify_payload_failure_field_missing(self):
        """
            Test verifying a payload with missing fields.

            Expected result: An exception with an explaining message is raised.
        """

        # Just add a non-optional field dynamically.
        easyjwt = EasyJWT(self.key)
        easyjwt.email = 'test@example.com'

        # And then delete it from the payload.
        payload = easyjwt._get_payload()
        del payload['email']

        with self.assertRaises(PayloadFieldError) as exception_cm:
            easyjwt._verify_payload(payload)

        self.assertEqual('Missing fields: {email}. Unexpected fields: {}', str(exception_cm.exception))

    def test_verify_payload_failure_fields_unexpected(self):
        """
            Test verifying a payload with unexpected fields.

            Expected result: An exception with an explaining message is raised.
        """
        easyjwt = EasyJWT(self.key)
        payload = easyjwt._get_payload()
        payload['user_id'] = 1

        with self.assertRaises(PayloadFieldError) as exception_cm:
            easyjwt._verify_payload(payload)

        self.assertEqual('Missing fields: {}. Unexpected fields: {user_id}', str(exception_cm.exception))

    def test_verify_payload_failure_fields_unexpected_and_missing(self):
        """
            Test verifying a payload with missing and unexpected fields.

            Expected result: An exception with an explaining message is raised.
        """

        # Just add a non-optional field dynamically.
        easyjwt = EasyJWT(self.key)
        easyjwt.email = 'test@example.com'

        # And then delete it from the payload while adding an unexpected one.
        payload = easyjwt._get_payload()
        del payload['email']
        payload['user_id'] = 1

        with self.assertRaises(PayloadFieldError) as exception_cm:
            easyjwt._verify_payload(payload)

        self.assertEqual('Missing fields: {email}. Unexpected fields: {user_id}', str(exception_cm.exception))

    def test_verify_payload_success_with_optional_fields(self):
        """
            Test verifying a valid payload with (valid) optional fields.

            Expected result: `True`
        """
        easyjwt = EasyJWT(self.key)
        easyjwt.expiration_date = self.expiration_date
        easyjwt.issued_at_date = self.issued_at_date
        easyjwt.not_before_date = self.not_before_date
        payload = easyjwt._get_payload()
        self.assertTrue(easyjwt._verify_payload(payload))

    def test_verify_payload_success_without_optional_fields(self):
        """
            Test verifying a valid payload without an expiration date.

            Expected result: `True`
        """
        easyjwt = EasyJWT(self.key)
        payload = easyjwt._get_payload()
        self.assertTrue(easyjwt._verify_payload(payload))

    # endregion

    # region Instance Variable and Payload Field Helpers

    # _is_optional_payload_field()
    # ============================

    def test_is_optional_payload_field_easyjwt_class(self):
        """
            Test if the payload field for the EasyJWT class is optional.

            Expected Result: `False`
        """
        self.assertFalse(EasyJWT._is_optional_payload_field('_easyjwt_class'))

    def test_is_optional_payload_field_expiration_date(self):
        """
            Test if the payload field for the expiration date is optional.

            Expected Result: `True`
        """
        self.assertTrue(EasyJWT._is_optional_payload_field('exp'))

    def test_is_optional_payload_field_issued_at_date(self):
        """
            Test if the payload field for the issued-at date is optional.

            Expected Result: `True`
        """
        self.assertTrue(EasyJWT._is_optional_payload_field('iat'))

    def test_is_optional_payload_field_non_optional_field(self):
        """
            Test if a payload field that is not in the optional fields list is optional.

            Expected Result: `False`
        """
        field = 'non_optional_payload_field'
        self.assertNotIn(field, EasyJWT._optional_payload_fields)
        self.assertFalse(EasyJWT._is_optional_payload_field(field))

    def test_is_optional_payload_field_not_before_date(self):
        """
            Test if the payload field for the not-before date is optional.

            Expected Result: `True`
        """
        self.assertTrue(EasyJWT._is_optional_payload_field('nbf'))

    def test_is_optional_payload_field_optional_list(self):
        """
            Test if the payload fields in the optional fields list are optional.

            Expected Result: `True`
        """
        for field in EasyJWT._optional_payload_fields:
            self.assertTrue(EasyJWT._is_optional_payload_field(field))

    # _is_payload_field()
    # ===================

    def test_is_payload_field_blacklist(self):
        """
            Test if the instance variables in the blacklist are payload fields.

            Expected Result: `False`
        """
        for instance_var in EasyJWT._public_non_payload_fields:
            self.assertFalse(EasyJWT._is_payload_field(instance_var), f'{instance_var} is a payload field')

    def test_is_payload_field_expiration_date(self):
        """
            Test if the instance variable for the expiration date is a payload field.

            Expected Result: `True`.
        """
        self.assertTrue(EasyJWT._is_payload_field('expiration_date'))

    def test_is_payload_field_issued_at_date(self):
        """
            Test if the instance variable for the issued-at date is a payload field.

            Expected Result: `True`.
        """
        self.assertTrue(EasyJWT._is_payload_field('issued_at_date'))

    def test_is_payload_field_not_before_date(self):
        """
            Test if the instance variable for the not-before date is a payload field.

            Expected Result: `True`.
        """
        self.assertTrue(EasyJWT._is_payload_field('not_before_date'))

    def test_is_payload_field_private_instance_vars(self):
        """
            Test if private instance variables that are not in the whitelist are payload fields.

            Expected Result: `False`
        """
        instance_var = '_not_part_of_the_payload'
        self.assertNotIn(instance_var, EasyJWT._private_payload_fields)
        self.assertFalse(EasyJWT._is_payload_field(instance_var))

    def test_is_payload_field_public_instance_vars(self):
        """
            Test if public instance variables that are not in the blacklist are payload fields.

            Expected Result: `True`
        """
        instance_var = 'part_of_the_payload'
        self.assertNotIn(instance_var, EasyJWT._private_payload_fields)
        self.assertTrue(EasyJWT._is_payload_field(instance_var))

    def test_is_payload_field_whitelist(self):
        """
            Test if the instance variables in the whitelist are payload fields.

            Expected Result: `True`
        """
        for instance_var in EasyJWT._private_payload_fields:
            self.assertTrue(EasyJWT._is_payload_field(instance_var), f'{instance_var} is not a payload field')

    # _map_instance_var_to_payload_field()
    # ====================================

    def test_map_instance_var_to_payload_field_expiration_date(self):
        """
            Test that the expiration date is mapped correctly from instance var to payload field.

            Expected Result: The payload field for the expiration date is returned.
        """
        self.assertEqual('exp', EasyJWT._map_instance_var_to_payload_field('expiration_date'))

    def test_map_instance_var_to_payload_field_issued_at_date(self):
        """
            Test that the issued-at date is mapped correctly from instance var to payload field.

            Expected Result: The payload field for the issued-at date is returned.
        """
        self.assertEqual('iat', EasyJWT._map_instance_var_to_payload_field('issued_at_date'))

    def test_map_instance_var_to_payload_field_not_before_date(self):
        """
            Test that the not-before date is mapped correctly from instance var to payload field.

            Expected Result: The payload field for the not-before date is returned.
        """
        self.assertEqual('nbf', EasyJWT._map_instance_var_to_payload_field('not_before_date'))

    def test_map_instance_var_to_payload_field_unmapped(self):
        """
            Test that an instance variable that is not in the map is returned as the payload field.

            Expected Result: The name of the instance variable is returned unchanged.
        """
        instance_var = 'part_of_the_payload'
        self.assertNotIn(instance_var, EasyJWT._instance_var_payload_field_mapping)
        self.assertEqual(instance_var, EasyJWT._map_instance_var_to_payload_field(instance_var))

    # _map_payload_field_to_instance_var()
    # ====================================

    def test_map_payload_field_to_instance_var_expiration_date(self):
        """
            Test that the expiration date is mapped correctly from payload field to instance variable.

            Expected Result: The instance variable for the expiration date is returned.
        """
        self.assertEqual('expiration_date', EasyJWT._map_payload_field_to_instance_var('exp'))

    def test_map_payload_field_to_instance_var_issued_at_date(self):
        """
            Test that the issued-at date is mapped correctly from payload field to instance variable.

            Expected Result: The instance variable for the issued-at date is returned.
        """
        self.assertEqual('issued_at_date', EasyJWT._map_payload_field_to_instance_var('iat'))

    def test_map_payload_field_to_instance_var_not_before_date(self):
        """
            Test that the not-before date is mapped correctly from payload field to instance variable.

            Expected Result: The instance variable for the not-before date is returned.
        """
        self.assertEqual('not_before_date', EasyJWT._map_payload_field_to_instance_var('nbf'))

    def test_map_payload_field_to_instance_var_unmapped(self):
        """
            Test that a payload field that is not in the map is returned as the instance variable.

            Expected Result: The name of the payload field is returned unchanged.
        """
        payload_field = 'part_of_the_payload'
        self.assertNotIn(payload_field, EasyJWT._instance_var_payload_field_mapping.inv)
        self.assertEqual(payload_field, EasyJWT._map_payload_field_to_instance_var(payload_field))

    # endregion

    # region Others

    # _get_class_name()
    # =================

    def test_get_class_name(self):
        """
            Test getting the name of the class.

            Expected Result: 'EasyJWT' is returned.
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
        self.assertEqual(easyjwt.create(), str(easyjwt))

    # endregion
