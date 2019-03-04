#!venv/bin/python
# -*- coding: utf-8 -*-

"""
    Collection of functions converting a value from the payload to the expected format for the token object.

    All functions must have the signature `(Optional[Any]) -> Optional[Any]` as an empty value may be given in the
    payload. The functions must handle these cases gracefully.

    The association between payload fields and their restoration function is defined in the dictionary
    :attr:`.EasyJWT._payload_field_restore_methods`.
"""

from typing import Optional

from datetime import datetime


def restore_timestamp_to_datetime(timestamp: Optional[int]) -> Optional[datetime]:
    """
        Convert a timestamp into a `datetime` object.

        :param timestamp: The timestamp to convert (in UTC).
        :return: The corresponding `datetime` object (in UTC). `None` if `timestamp` is `None`.
    """
    if timestamp is None:
        return None

    return datetime.utcfromtimestamp(timestamp)
