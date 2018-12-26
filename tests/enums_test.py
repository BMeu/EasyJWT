#!venv/bin/python
# -*- coding: utf-8 -*-

from unittest import TestCase

from time import time

from easyjwt import Algorithm
from easyjwt import EasyJWT


class AlgorithmTest(TestCase):

    def test_algorithms_supported(self):
        """
            Test that the algorithms in the enum are actually supported.

            Expected result: All algorithms specified in the enum can encode and decode the token.
        """

        key = 'abcdefghijklmnopqrstuvwxyz'
        expiration_date = time() + (15 * 60)

        for algorithm in list(Algorithm):

            # Set the algorithm on the class so it is used for decoding.
            EasyJWT._algorithm = algorithm

            easyjwt_creation = EasyJWT(key)
            easyjwt_creation.expiration_date = expiration_date

            # Encode the token with the current algorithm.
            token = easyjwt_creation.create()
            self.assertEqual(algorithm, easyjwt_creation._algorithm, msg=f'Algorithm {algorithm} not set on token')
            self.assertIsNotNone(token, msg=f'Failed to encode token with algorithm {algorithm}')

            # Decode the token with the current algorithm.
            easyjwt_verification = EasyJWT.verify(token, key)
            self.assertEqual(algorithm, easyjwt_verification._algorithm, msg=f'Algorithm {algorithm} not set on token')
            self.assertIsNotNone(easyjwt_verification, msg=f'Failed to decode token with algorithm {algorithm}')
