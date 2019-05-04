#!/usr/bin/python3
# -*- coding: utf-8 -*-

from unittest import TestCase

from easyjwt import Algorithm
from easyjwt import EasyJWT


class AlgorithmTest(TestCase):

    def test_algorithms_supported(self):
        """
            Test that the algorithms in the enum are actually supported.

            Expected result: All algorithms specified in the enum can encode and decode the token.
        """

        key = 'abcdefghijklmnopqrstuvwxyz'

        # noinspection PyTypeChecker
        for algorithm in list(Algorithm):

            # Set the algorithm on the class so it is used for decoding.
            EasyJWT.algorithm = algorithm

            easyjwt_creation = EasyJWT(key)

            # Encode the token with the current algorithm.
            token = easyjwt_creation.create()
            self.assertEqual(algorithm, easyjwt_creation.algorithm, msg=f'Algorithm {algorithm} not set on token')
            self.assertIsNotNone(token, msg=f'Failed to encode token with algorithm {algorithm}')

            # Decode the token with the current algorithm.
            easyjwt_verification = EasyJWT.verify(token, key)
            self.assertEqual(algorithm, easyjwt_verification.algorithm, msg=f'Algorithm {algorithm} not set on token')
            self.assertIsNotNone(easyjwt_verification, msg=f'Failed to decode token with algorithm {algorithm}')
