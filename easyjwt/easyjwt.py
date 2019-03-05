#!venv/bin/python
# -*- coding: utf-8 -*-

"""
    Definitions for handling JSON Web Tokens (JWT).
"""

from typing import Any
from typing import Callable
from typing import ClassVar
from typing import Dict
from typing import Optional
from typing import Set

from datetime import datetime

from bidict import bidict
from jwt import decode as jwt_decode
from jwt import encode as jwt_encode

from . import Algorithm
from . import UnspecifiedClassError
from . import InvalidClaimSetError
from . import InvalidClassError
from .restoration import restore_timestamp_to_datetime


class EasyJWT(object):
    """
        A base class for representing JSON Web Tokens (JWT).

        To use a JWT, you have to create a subclass inheriting from :class:`EasyJWT`. All public instance variables of
        this class (that is, all instance variables not starting with an underscore) will make up the payload of your
        token (there will be a few meta payload fields in the token as well that :class:`EasyJWT` needs to verify the
        token).
    """

    # region Class Variables

    algorithm: ClassVar[Algorithm] = Algorithm.HS256
    """
        The algorithm used for encoding the token.

        When changing the algorithm, its old value must be added to :attr:`previous_algorithms` so that old tokens may
        still be decoded properly.
    """

    previous_algorithms: ClassVar[Set[Algorithm]] = {}
    """
        All algorithms that have previously been used for encoding the token, needed for decoding the token.

        When changing the :attr:`algorithm`, its old value must be added to this set. The algorithm specified in
        :attr:`algorithm` does not have to be part of this set.
    """

    _instance_var_payload_field_mapping: ClassVar[bidict] = bidict(
        expiration_date='exp',
        issued_at_date='iat',
        not_before_date='nbf',
    )
    """
        A bidirectional mapping from the name of an instance variable to its name in the payload (and vice versa).

        Before creating the payload for a token, all instance variables collected for the payload will be renamed
        according to this mapping. If an instance variable is not found in this mapping, its name will directly be used
        in the payload.

        When restoring the payload from a token, all payload fields will be written to the instance variable given by
        the inverse mapping. If a payload field is not found in this inverse mapping, its name will be used as the
        instance variable.
    """

    _optional_payload_fields: ClassVar[Set[str]] = {
        'exp',
        'iat',
        'nbf',
    }
    """
        Set of payload fields that are optional, i.e. that can be empty in the token's payload without causing an error.

        Note that the name of the _payload field_ must be given, not the name of the _instance variable_ (see
        :attr:`_instance_var_payload_field_mapping`).
    """

    _payload_field_restore_methods: ClassVar[Dict[str, Callable[[Optional[Any]], Optional[Any]]]] = dict(
        expiration_date=restore_timestamp_to_datetime,
        issued_at_date=restore_timestamp_to_datetime,
        not_before_date=restore_timestamp_to_datetime,
    )
    """
        A dictionary mapping a payload field to a method that will restore its value from the payload into the expected
        format of the object.

        Note that the name of the _instance variable_ must be given as the key, not the name of the _payload field_ (see
        :attr:`_instance_var_payload_field_mapping`).
    """

    _private_payload_fields: ClassVar[Set[str]] = {
        '_easyjwt_class',
    }
    """
        Set of instance variable names that are part of the payload although their names begin with an underscore.
    """

    _public_non_payload_fields: ClassVar[Set[str]] = {
        'algorithm',
        'previous_algorithms',
    }
    """
        Set of instance variable names that are not part of the payload although their names do not begin with an
        underscore.
    """

    # endregion

    # region Instance Variables

    # TODO: Mention the exception that will be raised if the verification fails.
    expiration_date: Optional[datetime]
    """
        The date and time at which this token will expire.

        If this field is included in a token and this token is verified after the date has passed, the verification
        will fail.

        Must be given in UTC.
    """

    issued_at_date: Optional[datetime]
    """
        The date and time at which the token has been created.

        This field will automatically be set in :meth:`.create`. See that method on how to overwrite the value.

        When initializing a new object, this field will be `None`. With each creation, it will be updated accordingly.
        When verifying a token and restoring the object, this field will be set to the value given in the token (if it
        is included).

        Will be given in UTC.
    """

    # TODO: Mention the exception that will be raised if the verification fails.
    not_before_date: Optional[datetime]
    """
        The date and time before which this token will not be valid.

        If this field is included in a token and this token is verified before the date has been reached, the
        verification will fail.

        Must be given in UTC.
    """

    _easyjwt_class: str
    """
        The name of the class creating the token.

        Used for validating a token.
    """

    _key: str
    """
        The private key for encoding and decoding the token.
    """

    # endregion

    # region Instantiation

    def __init__(self, key: str) -> None:
        """
            :param key: The private key that is used for encoding and decoding the token.
        """

        self._easyjwt_class = self._get_class_name()
        self._key = key

        self.expiration_date = None
        self.issued_at_date = None
        self.not_before_date = None

    # endregion

    # region Token Creation

    def create(self, issued_at: Optional[datetime] = None) -> str:
        """
            Create the actual token from the :class:`EasyJWT` object.

            :param issued_at: The date and time at which this token was issued. If not given, the current date and time
                              will be used. Must be given in UTC. Defaults to `None`.
            :return: The token represented by the current state of the object.
        """

        # Set the issued-at date.
        self.issued_at_date = issued_at
        if self.issued_at_date is None:
            self.issued_at_date = datetime.utcnow()

        # Encode the object.
        payload = self._get_payload()
        token_bytes = jwt_encode(payload, self._key, algorithm=self.algorithm.value)

        # The encoded payload is a bytestream. Create a UTF-8 string.
        token = token_bytes.decode('utf-8')
        return token

    def _get_payload(self, with_empty_fields: bool = False) -> Dict[str, Any]:
        """
            Get the payload of this token.

            :param with_empty_fields: If set to `True`, fields that have no value will be included.
            :return: A dictionary of instance variables with their current values that make up the token's payload.
                     Instance variable names are mapped to their respective payload field names. Fields that have no
                     value are excluded.
        """

        # TODO: Fail if a non-optional field is empty.

        return {EasyJWT._map_instance_var_to_payload_field(field): value
                for (field, value) in vars(self).items()
                if self._is_payload_field(field) and (with_empty_fields or value is not None)
                }

    # endregion

    # region Token Restoration

    @classmethod
    def verify(cls, token: str, key: str) -> 'EasyJWT':
        """
            Verify the given JSON Web Token.

            :param token: The JWT to verify.
            :param key: The key used for decoding the token. This key must be the same with which the token has been
                        created.
            :return: The object representing the token. The payload values are set on the corresponding instance
                     variables.
            :raise InvalidClaimsBaseError: If the given token's payload is invalid.
        """
        # TODO: List all errors in the docstring.

        # Create an object for the token.
        easyjwt = cls(key)

        # Decode the given token.
        algorithms = easyjwt._get_decode_algorithms()
        payload = jwt_decode(token, easyjwt._key, algorithms=algorithms)

        # Verify and restore the token.
        easyjwt._verify_payload(payload)
        easyjwt._restore_payload(payload)

        return easyjwt

    @classmethod
    def _get_decode_algorithms(cls) -> Set[str]:
        """
            Get all algorithms for decoding.

            :return: A set of all algorithms ever used for encoding the tokens.
        """

        algorithms = {algorithm.value for algorithm in cls.previous_algorithms}
        algorithms.add(cls.algorithm.value)
        return algorithms

    def _get_payload_fields(self) -> Set[str]:
        """
            Get all fields that are part of the payload.

            :return: A set of names of the instance variables that make up the payload fields.
        """

        return set(self._get_payload(with_empty_fields=True).keys())

    @classmethod
    def _get_restore_method_for_payload_field(cls, field: str) -> Optional[Callable[[Optional[Any]], Optional[Any]]]:
        """
            Get the method for the given payload field that restores the field's value to the expected format.

            :param field: The payload field for which the restore method will be returned.
            :return: The method for the given field if it exists. `None` if there is no such method.
        """
        return cls._payload_field_restore_methods.get(field, None)

    def _restore_payload(self, payload: Dict[str, Any]) -> None:
        """
            Restore the token data from the given payload.

            The payload's values will be written to the field's corresponding instance variable.

            :param payload: The payload from which the state will be restored.
        """

        for field, value in payload.items():
            # Find the corresponding instance variable.
            field = self._map_payload_field_to_instance_var(field)

            # Restore the value (if necessary).
            restore_method = self._get_restore_method_for_payload_field(field)
            if restore_method is not None and value is not None:
                value = restore_method(value)

            # Actually set the value.
            setattr(self, field, value)

    def _verify_payload(self, payload: Dict[str, Any]) -> bool:
        """
            Verify that the payload contains exactly the expected fields, that is, expected fields must not be missing
            from the payload and the payload must not contain any additional fields. Furthermore, verify that this
            object is of the right class for the token.

            Expected fields are all those that would be used in a token created by this object.

            :param payload: The payload to verify.
            :return: ``True`` if the payload contains all expected fields and is of this class, ``False`` otherwise.
            :raise UnspecifiedClassError: If the payload does not contain the class with which the token has been created.
            :raise InvalidClaimSetError: If the payload does not contain exactly the expected fields.
            :raise InvalidClassError: If the payload is not verified with the class with which the token has been created.
        """

        # Check the token's class: it must be specified and be this class.
        class_name = self._get_class_name()
        payload_class_name = payload.get('_easyjwt_class', None)
        if payload_class_name is None:
            raise UnspecifiedClassError()

        if payload_class_name != class_name:
            raise InvalidClassError(expected_class=class_name, actual_class=payload_class_name)

        # Determine missing and unexpected fields. Missing fields are those specified in this class but not given in the
        # payload. Unexpected fields are those given in the payload but not specified in this class.
        expected_fields = self._get_payload_fields()
        actual_fields = set(payload.keys())

        # Use the name of the instance variable for missing payload fields to avoid confusion.
        # For unexpected fields, use the name of the payload field.
        missing_fields = {self._map_payload_field_to_instance_var(field) for field
                          in expected_fields.difference(actual_fields) if not self._is_optional_payload_field(field)}
        unexpected_fields = actual_fields.difference(expected_fields)

        # If there are no missing fields or unexpected fields, everything is fine.
        if len(missing_fields) == 0 and len(unexpected_fields) == 0:
            return True

        # Otherwise, raise an exception.
        raise InvalidClaimSetError(missing_fields, unexpected_fields)

    # endregion

    # region Instance Variable and Payload Field Helpers

    @classmethod
    def _is_optional_payload_field(cls, field: str) -> bool:
        """
            Determine if the given payload is optional and may thus be empty in the payload.

            A payload field is optional if it is listed in :attr:`_optional_payload_fields`.

            :param field: The name of the payload field to check.
            :return: `True` if the given payload field is optional, `False` otherwise.
        """
        return field in cls._optional_payload_fields

    @classmethod
    def _is_payload_field(cls, instance_var: str) -> bool:
        """
            Determine if a given instance variable is part of the token's payload.

            An instance variable will be considered to be a part of the payload if:

            * it is listed in :attr:`_private_payload_fields`, or
            * it does not start with an underscore, but
                * is not listed in :attr:`_public_non_payload_fields'.

            :param instance_var: The name of the instance variable to check.
            :return: `True` if the instance variable is part of the payload, `False` otherwise.
        """

        # Some instance variables are always included in the payload.
        if instance_var in cls._private_payload_fields:
            return True

        # Private instance variables are never included (unless explicitly allowed above).
        if instance_var.startswith('_'):
            return False

        # Public instance variables might not be a payload field.
        if instance_var in cls._public_non_payload_fields:
            return False

        return True

    @classmethod
    def _map_instance_var_to_payload_field(cls, instance_var: str) -> str:
        """
            Map an instance variable that will be part of the payload to its name in the payload.

            :param instance_var: The name of the instance variable to map.
            :return: The name of the corresponding payload field.
        """

        # If the instance variable is not defined in the mapping, return the variable's name.
        return cls._instance_var_payload_field_mapping.get(instance_var, instance_var)

    @classmethod
    def _map_payload_field_to_instance_var(cls, payload_field: str) -> str:
        """
            Map a field in the payload to the name of its instance variable.

            :param payload_field: The name of the payload field to map.
            :return: The name of the corresponding instance variable.
        """

        # If the payload field is not defined in the mapping, return its field name.
        return cls._instance_var_payload_field_mapping.inv.get(payload_field, payload_field)

    # endregion

    # region Other

    def _get_class_name(self) -> str:
        """
            Get the class of the own object.

            :return: The name of the class of which `self` is.
        """

        return type(self).__name__

    # endregion

    # region System Methods

    def __str__(self):
        """
            Create the token.

            Alias of :meth:`create`.

            :return: The token represented by the current state of the object.
        """

        return self.create()

    # endregion
