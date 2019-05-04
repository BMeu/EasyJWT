#!/usr/bin/python3
# -*- coding: utf-8 -*-

from unittest import TestCase

from datetime import datetime
from datetime import timezone

from easyjwt.restoration import restore_timestamp_to_datetime


class RestorationTest(TestCase):

    # restore_timestamp_to_datetime()
    # ===============================

    def test_restore_timestamp_to_datetime_none(self):
        """
            Test restoring a timestamp if the timestamp is `None`.

            Expected Result: `None`
        """

        self.assertIsNone(restore_timestamp_to_datetime(None))

    def test_restore_timestamp_to_datetime_value(self):
        """
            Test restoring a timestamp if the timestamp is given.

            Expected Result: The corresponding `datetime` object.
        """

        date = datetime.utcnow().replace(microsecond=0)
        timestamp = int(date.replace(tzinfo=timezone.utc).timestamp())
        self.assertEqual(date, restore_timestamp_to_datetime(timestamp))
