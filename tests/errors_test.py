#!venv/bin/python
# -*- coding: utf-8 -*-

from unittest import TestCase

from easyjwt import EasyJWTError
from easyjwt import MissingClassError
from easyjwt import PayloadFieldError
from easyjwt import WrongClassError


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

        error = MissingClassError()
        self.assertEqual('Missing class specification', error._message)


class PayloadFieldErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected result: The message is correctly initialized with the given fields.
        """

        missing = ['missing_1', 'missing_2']
        unexpected = ['unexpected_1', 'unexpected_2']

        # No missing fields, no unexpected fields.
        error = PayloadFieldError()
        message = 'Missing fields: {}. Unexpected fields: {}'
        self.assertEqual(message, error._message)

        # Missing fields, no unexpected fields.
        error = PayloadFieldError(missing_fields=missing)
        message = 'Missing fields: {missing_1, missing_2}. Unexpected fields: {}'
        self.assertEqual(message, error._message)

        # No missing fields, unexpected fields.
        error = PayloadFieldError(unexpected_fields=unexpected)
        message = 'Missing fields: {}. Unexpected fields: {unexpected_1, unexpected_2}'
        self.assertEqual(message, error._message)

        # Missing fields, unexpected fields.
        error = PayloadFieldError(missing_fields=missing, unexpected_fields=unexpected)
        message = 'Missing fields: {missing_1, missing_2}. Unexpected fields: {unexpected_1, unexpected_2}'
        self.assertEqual(message, error._message)


class WrongClassErrorTest(TestCase):

    def test_init(self):
        """
            Test the initialization of the error.

            Expected result: The message is correctly initialized.
        """

        expected_class = 'ExpectedEasyJWTClass'
        actual_class = 'ActualEasyJWTClass'
        error = WrongClassError(expected_class=expected_class, actual_class=actual_class)
        self.assertEqual(f'Expected class {expected_class}. Got class {actual_class}', error._message)
