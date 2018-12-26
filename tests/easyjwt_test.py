#!venv/bin/python
# -*- coding: utf-8 -*-

from unittest import TestCase

from time import time

from easyjwt import Algorithm
from easyjwt import EasyJWT
from easyjwt import MissingClassError
from easyjwt import PayloadFieldError
from easyjwt import WrongClassError


class EasyJWTTest(TestCase):

    def setUp(self):
        """
            Prepare the test cases.
        """

        self.key = 'abcdefghijklmnopqrstuvwxyz'
        self.expiration_date = time() + (15 * 60)

    def test_init(self):
        """
            Test initializing a new token object.

            Expected Result: The instance variables are set correctly.
        """

        easyjwt = EasyJWT(self.key)
        self.assertEqual(easyjwt._get_class_name(), easyjwt._easyjwt_class)
        self.assertIsNone(easyjwt.expiration_date)
        self.assertEqual(self.key, easyjwt._key)

    def test_verify_success(self):
        """
            Test verifying a valid token with the correct key.

            Expected Result: An object representing the token is returned.
        """

        easyjwt_creation = EasyJWT(self.key)
        easyjwt_creation.expiration_date = self.expiration_date
        token = easyjwt_creation.create()

        easyjwt_verification = EasyJWT.verify(token, self.key)
        self.assertIsNotNone(easyjwt_verification)
        self.assertEqual(easyjwt_creation._key, easyjwt_verification._key)
        self.assertEqual(easyjwt_creation.expiration_date, easyjwt_verification.expiration_date)
        self.assertEqual(easyjwt_creation._easyjwt_class, easyjwt_verification._easyjwt_class)

    def test_verify_failure(self):
        """
            Test verifying an invalid token.

            Expected Result: No object representing the token is returned, but an error is raised.
        """
        jwtoken_creation = EasyJWT(self.key)
        jwtoken_creation.expiration_date = self.expiration_date

        # Add some payload field to the object that is not part of the class.
        fake_field = 'part_of_the_payload'
        jwtoken_creation.part_of_the_payload = True
        self.assertTrue(jwtoken_creation._is_payload_field(fake_field))

        token = jwtoken_creation.create()

        with self.assertRaises(PayloadFieldError) as exception_cm:
            jwtoken_verification = EasyJWT.verify(token, self.key)
            self.assertIsNone(jwtoken_verification)
            self.assertIn(fake_field, str(exception_cm.exception))

    def test_create(self):
        """
             Test creating a token if it has not been created before.

             Expected Result: A token is created.
        """
        jwtoken = EasyJWT(self.key)
        jwtoken.expiration_date = self.expiration_date

        token = jwtoken.create()
        self.assertIsNotNone(token)
        self.assertEqual(self.expiration_date, jwtoken.expiration_date)

    def test_get_payload_fields(self):
        """
            Test getting the list of payload fields.

            Expected Result: A list with the fields for the validity and expiration date is returned.
        """
        payload_fields = {'_easyjwt_class', 'exp'}
        jwtoken = EasyJWT(self.key)
        self.assertSetEqual(payload_fields, jwtoken._get_payload_fields())

    def test_get_payload(self):
        """
            Test getting the payload dictionary.

            Expected Result: A dictionary with the entries for the validity and expiration date is returned.
        """
        payload = dict(
            _easyjwt_class='EasyJWT',
            exp=None,
        )
        jwtoken = EasyJWT(self.key)
        self.assertDictEqual(payload, jwtoken._get_payload())

    def test_payload_fields_and_payload_keys_equal(self):
        """
            Assert that the list of payload fields is exactly the same as the list of payload keys.

            Expected Result: The list of payload fields equals the list of payload keys.
        """
        jwtoken = EasyJWT(self.key)
        payload_fields = jwtoken._get_payload_fields()
        payload = jwtoken._get_payload()
        self.assertSetEqual(payload_fields, set(payload.keys()))

    def test_restore_payload(self):
        """
            Test restoring a payload dictionary.

            Expected Result: The values in the payload are mapped to their respective instance variables.
        """
        payload = dict(
            _jwtoken_class='EasyJWT',
            exp=946684800.0,
        )

        jwtoken = EasyJWT(self.key)
        jwtoken._restore_payload(payload)
        self.assertEqual(payload['exp'], jwtoken.expiration_date)

    def test_verify_payload_success(self):
        """
            Test verifying a valid payload.

            Expected result: `True`
        """
        jwtoken = EasyJWT(self.key)
        payload = jwtoken._get_payload()
        self.assertTrue(jwtoken._verify_payload(payload))

    def test_verify_payload_failure_missing_class(self):
        """
            Test verifying a payload with a missing class field.

            Expected result: The exception for a missing class is raised.
        """
        jwtoken = EasyJWT(self.key)
        payload = jwtoken._get_payload()
        del payload['_easyjwt_class']

        with self.assertRaises(MissingClassError):
            jwtoken._verify_payload(payload)

    def test_verify_payload_failure_wrong_class(self):
        """
            Test verifying a payload with a faulty value in the class field.

            Expected result: An exception with an explaining _message is raised.
        """
        jwtoken = EasyJWT(self.key)
        payload = jwtoken._get_payload()
        payload['_easyjwt_class'] = 'InheritedEasyJWT'

        with self.assertRaises(WrongClassError) as exception_cm:
            jwtoken._verify_payload(payload)

        self.assertEqual('Expected class EasyJWT. Got class InheritedEasyJWT', str(exception_cm.exception))

    def test_verify_payload_failure_missing_fields(self):
        """
            Test verifying a payload with missing fields.

            Expected result: An exception with an explaining _message is raised.
        """
        jwtoken = EasyJWT(self.key)
        payload = jwtoken._get_payload()
        del payload['exp']

        with self.assertRaises(PayloadFieldError) as exception_cm:
            jwtoken._verify_payload(payload)

        self.assertEqual('Missing fields: {expiration_date}. Unexpected fields: {}', str(exception_cm.exception))

    def test_verify_payload_failure_unexpected_fields(self):
        """
            Test verifying a payload with unexpected fields.

            Expected result: An exception with an explaining _message is raised.
        """
        jwtoken = EasyJWT(self.key)
        payload = jwtoken._get_payload()
        payload['user_id'] = 1

        with self.assertRaises(PayloadFieldError) as exception_cm:
            jwtoken._verify_payload(payload)

        self.assertEqual('Missing fields: {}. Unexpected fields: {user_id}', str(exception_cm.exception))

    def test_verify_payload_failure_missing_and_unexpected_fields(self):
        """
            Test verifying a payload with missing and unexpected fields.

            Expected result: An exception with an explaining _message is raised.
        """
        easyjwt = EasyJWT(self.key)
        easyjwt.expiration_date = self.expiration_date
        payload = easyjwt._get_payload()
        del payload['exp']
        payload['user_id'] = 1

        with self.assertRaises(PayloadFieldError) as exception_cm:
            easyjwt._verify_payload(payload)

        self.assertEqual('Missing fields: {expiration_date}. Unexpected fields: {user_id}', str(exception_cm.exception))

    def test_get_class_name(self):
        """
            Test getting the name of the class.

            Expected Result: 'EasyJWT' is returned.
        """
        jwtoken = EasyJWT(self.key)
        self.assertEqual('EasyJWT', jwtoken._get_class_name())

    def test_get_decode_algorithms(self):
        """
            Test getting the algorithms for decoding a token.

            Expected Result: A set of all previous encoding algorithms and the current one is returned.
        """
        # Temporarily save the current class variables to restore them later. Otherwise, changes could influence other
        # parts of the tests.
        current_alg_temp = EasyJWT._algorithm
        previous_algs_temp = EasyJWT._previous_algorithms

        EasyJWT._algorithm = Algorithm.HS256
        EasyJWT._previous_algorithms = [Algorithm.HS384, Algorithm.HS512]

        algorithms = {Algorithm.HS256.value, Algorithm.HS384.value, Algorithm.HS512.value}
        self.assertSetEqual(algorithms, EasyJWT._get_decode_algorithms())

        # Restore the class variables.
        EasyJWT._algorithm = current_alg_temp
        EasyJWT._previous_algorithms = previous_algs_temp

    def test_is_payload_field_expiration_date(self):
        """
            Test if the instance variable for the expiration date is a payload field.

            Expected Result: `True`.
        """
        self.assertTrue(EasyJWT._is_payload_field('expiration_date'))

    def test_is_payload_field_whitelist(self):
        """
            Test if the instance variables in the whitelist are payload fields.

            Expected Result: `True` for each entry in the whitelist.
        """
        for instance_var in EasyJWT._private_payload_fields:
            self.assertTrue(EasyJWT._is_payload_field(instance_var), f'{instance_var} is not a payload field')

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
            Test if public instance variables (that are not in the whitelist) are payload fields.

            Expected Result: `True`
        """
        instance_var = 'part_of_the_payload'
        self.assertNotIn(instance_var, EasyJWT._private_payload_fields)
        self.assertTrue(EasyJWT._is_payload_field(instance_var))

    def test_map_instance_var_to_payload_field_expiration_date(self):
        """
            Test that the expiration date is mapped correctly from instance var to payload field.

            Expected Result: The payload field for the expiration date is returned.
        """
        self.assertEqual('exp', EasyJWT._map_instance_var_to_payload_field('expiration_date'))

    def test_map_instance_var_to_payload_field_unmapped(self):
        """
            Test that an instance variable that is not in the map is returned as the payload field.

            Expected Result: The name of the instance variable is returned unchanged.
        """
        instance_var = 'part_of_the_payload'
        self.assertNotIn(instance_var, EasyJWT._instance_var_payload_field_mapping)
        self.assertEqual(instance_var, EasyJWT._map_instance_var_to_payload_field(instance_var))

    def test_map_payload_field_to_instance_var_expiration_date(self):
        """
            Test that the expiration date is mapped correctly from payload field to instance variable.

            Expected Result: The instance variable for the expiration date is returned.
        """
        self.assertEqual('expiration_date', EasyJWT._map_payload_field_to_instance_var('exp'))

    def test_map_payload_field_to_instance_var_unmapped(self):
        """
            Test that payload field that is not in the map is returned as the instance variable.

            Expected Result: The name of the payload field is returned unchanged.
        """
        payload_field = 'part_of_the_payload'
        self.assertNotIn(payload_field, EasyJWT._instance_var_payload_field_mapping.inv)
        self.assertEqual(payload_field, EasyJWT._map_payload_field_to_instance_var(payload_field))

    def test_str(self):
        """
            Test converting the object to a string.

            Expected Result: The token is returned as if `create()` had been called.
        """
        jwtoken = EasyJWT(self.key)
        self.assertEqual(jwtoken.create(), str(jwtoken))
