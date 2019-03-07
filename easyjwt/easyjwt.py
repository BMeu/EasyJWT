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
from . import MissingRequiredClaimsError
from .restoration import restore_timestamp_to_datetime


class EasyJWT(object):
    """
        A base class for representing JSON Web Tokens (JWT).

        To use a JWT, you have to create a subclass inheriting from :class:`EasyJWT`. All public instance variables of
        this class (that is, all instance variables not starting with an underscore) will make up the claim set of your
        token (there will be a few meta claims in the token as well that :class:`EasyJWT` needs to verify the token).
    """

    # region Class Variables

    algorithm: ClassVar[Algorithm] = Algorithm.HS256
    """
        The algorithm used for encoding the token.

        When changing the algorithm, its old value must be added to :attr:`previous_algorithms` so that old tokens may
        still be decoded properly.

        This variable is not part of the claim set.
    """

    previous_algorithms: ClassVar[Set[Algorithm]] = {}
    """
        All algorithms that have previously been used for encoding the token, needed for decoding the token.

        When changing the :attr:`algorithm`, its old value must be added to this set. The algorithm specified in
        :attr:`algorithm` does not have to be part of this set.

        This variable is not part of the claim set.
    """

    _claim_restore_methods: ClassVar[Dict[str, Callable[[Optional[Any]], Optional[Any]]]] = dict(
        expiration_date=restore_timestamp_to_datetime,
        issued_at_date=restore_timestamp_to_datetime,
        not_before_date=restore_timestamp_to_datetime,
    )
    """
        A dictionary mapping a claim name to a method that will restore the claim's value from the claim set into the
        expected format of the object.

        Note that the name of the _instance variable_ must be given as the key, not the name of the _claim_ (see
        :attr:`_instance_var_claim_name_mapping`).
    """

    _instance_var_claim_name_mapping: ClassVar[bidict] = bidict(
        expiration_date='exp',
        issued_at_date='iat',
        not_before_date='nbf',
    )
    """
        A bidirectional mapping from the name of an instance variable to its name in the claim set (and vice versa).

        Before creating the claim set for a token, all instance variables collected for the claim set will be renamed
        according to this mapping. If an instance variable is not found in this mapping, its name will directly be used
        as the claim name.

        When restoring the claim set from a token, all claims will be written to the instance variable given by
        the inverse mapping. If a claim name is not found in this inverse mapping, its name will be used as the
        instance variable.
    """

    _optional_claims: ClassVar[Set[str]] = {
        'exp',
        'iat',
        'nbf',
    }
    """
        Set of claims that are optional, i.e. that can be empty in the token's claim set without causing an error.

        Note that the name of the _claim_ must be given, not the name of the _instance variable_ (see
        :attr:`_instance_var_claim_name_mapping`).
    """

    _private_claims: ClassVar[Set[str]] = {
        '_easyjwt_class',
    }
    """
        Set of instance variable names that are part of the claim set although their names begin with an underscore.
    """

    _public_non_claims: ClassVar[Set[str]] = {
        'algorithm',
        'previous_algorithms',
    }
    """
        Set of instance variable names that are not part of the claim set although their names do not begin with an
        underscore.
    """

    # endregion

    # region Instance Variables

    # TODO: Mention the exception that will be raised if the verification fails.
    expiration_date: Optional[datetime]
    """
        The date and time at which this token will expire. This instance variable is mapped to the registered claim
        ``exp``.

        If this claim is included in a token and this token is verified after the date has passed, the verification
        will fail.

        Must be given in UTC.
    """

    issued_at_date: Optional[datetime]
    """
        The date and time at which the token has been created. This instance variable is mapped to the registered claim
        ``iat``.

        This claim will automatically be set in :meth:`.create`. See that method on how to overwrite the value.

        When initializing a new object, this claim will be `None`. With each creation, it will be updated accordingly.
        When verifying a token and restoring the object, this claim will be set to the value given in the token (if it
        is included).

        Will be given in UTC.
    """

    # TODO: Mention the exception that will be raised if the verification fails.
    not_before_date: Optional[datetime]
    """
        The date and time before which this token will not be valid. This instance variable is mapped to the registered
        claim ``nbf``.

        If this claim is included in a token and this token is verified before the date has been reached, the
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
            Create the actual token from the :class:`EasyJWT` object. Empty optional claims will not be included in the
            token. Empty non-optional claims will cause a :class:`MissingRequiredClaimsError`.

            :param issued_at: The date and time at which this token was issued. If not given, the current date and time
                              will be used. Must be given in UTC. Defaults to `None`.
            :return: The token represented by the current state of the object.
            :raise MissingRequiredClaimsError: If instance variables that map to non-optional claims in the claim set
                                               are empty.
        """

        # Set the issued-at date.
        self.issued_at_date = issued_at
        if self.issued_at_date is None:
            self.issued_at_date = datetime.utcnow()

        # Fail if there are empty required claims.
        missing_claims = self._get_required_empty_claims()
        if len(missing_claims) > 0:
            raise MissingRequiredClaimsError(missing_claims)

        # Encode the object.
        claim_set = self._get_claim_set()
        token_bytes = jwt_encode(claim_set, self._key, algorithm=self.algorithm.value)

        # The encoded claim set is a bytestream. Create a UTF-8 string.
        token = token_bytes.decode('utf-8')
        return token

    def _get_claim_set(self, with_empty_claims: bool = False) -> Dict[str, Any]:
        """
            Get the claim set of this token.

            :param with_empty_claims: If set to `True`, claims that have no value will be included.
            :return: A dictionary of instance variables with their current values that make up the token's claim set.
                     Instance variable names are mapped to their respective claim names. Claims that have no value are
                     excluded.
        """

        return {EasyJWT._map_instance_var_to_claim_name(name): value
                for (name, value) in vars(self).items()
                if self._is_claim(name) and (with_empty_claims or value is not None)
                }

    def _get_required_empty_claims(self) -> Set[str]:
        """
            Get all claims that are required but empty.

            :return: A set of names of the claims that are not optional but have an empty value.
        """
        return {name for (name, value) in self._get_claim_set(with_empty_claims=True).items()
                if not self._is_optional_claim(name) and value is None
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
            :return: The object representing the token. The claim values are set on the corresponding instance
                     variables.
            :raise InvalidClaimsBaseError: If the given token's claim set is invalid.
        """
        # TODO: List all errors in the docstring.

        # Create an object for the token.
        easyjwt = cls(key)

        # Decode the given token.
        algorithms = easyjwt._get_decode_algorithms()
        claim_set = jwt_decode(token, easyjwt._key, algorithms=algorithms)

        # Verify and restore the token.
        easyjwt._verify_claim_set(claim_set)
        easyjwt._restore_claim_set(claim_set)

        return easyjwt

    def _get_claim_names(self) -> Set[str]:
        """
            Get the names of all claims in the claim set, mapped to the respective instance variable's name.

            :return: A set of names of the instance variables that make up the claim set.
        """

        return set(self._get_claim_set(with_empty_claims=True).keys())

    @classmethod
    def _get_decode_algorithms(cls) -> Set[str]:
        """
            Get all algorithms for decoding.

            :return: A set of all algorithms ever used for encoding the tokens.
        """

        algorithms = {algorithm.value for algorithm in cls.previous_algorithms}
        algorithms.add(cls.algorithm.value)
        return algorithms

    @classmethod
    def _get_restore_method_for_claim(cls, claim: str) -> Optional[Callable[[Optional[Any]], Optional[Any]]]:
        """
            Get the method for the given claim that restores the claim value to the expected format.

            :param claim: The claim for which the restore method will be returned.
            :return: The method for the given claim if it exists. `None` if there is no such method.
        """

        return cls._claim_restore_methods.get(claim, None)

    def _restore_claim_set(self, claim_set: Dict[str, Any]) -> None:
        """
            Restore the token data from the given claim set.

            The claims' values will be written to the claims' corresponding instance variable.

            :param claim_set: The claim set from which the state will be restored.
        """

        for name, value in claim_set.items():
            # Find the corresponding instance variable.
            name = self._map_claim_name_to_instance_var(name)

            # Restore the value (if necessary).
            restore_method = self._get_restore_method_for_claim(name)
            if restore_method is not None and value is not None:
                value = restore_method(value)

            # Actually set the value.
            setattr(self, name, value)

    def _verify_claim_set(self, claim_set: Dict[str, Any]) -> bool:
        """
            Verify that the claim set contains exactly the expected claims, that is, non-optional claims must not be
            missing from the claim set and the claim set must not contain any additional claims. Furthermore, verify
            that this object is of the right class for the token.

            Expected claims are all the (non-optional) claims that would be used in a token created by this object.

            :param claim_set: The claim set to verify.
            :return: `True` if the claim set contains all expected claims and is of this class, `False` otherwise.
            :raise UnspecifiedClassError: If the claim set does not contain the class with which the token has been
                                          created.
            :raise InvalidClaimSetError: If the claim set does not contain exactly the expected (non-optional) claims.
            :raise InvalidClassError: If the claim set is not verified with the class with which the token has been
                                      created.
        """

        # Check the token's class: it must be specified and be this class.
        class_name = self._get_class_name()
        claim_class_name = claim_set.get('_easyjwt_class', None)
        if claim_class_name is None:
            raise UnspecifiedClassError()

        if claim_class_name != class_name:
            raise InvalidClassError(expected_class=class_name, actual_class=claim_class_name)

        # Determine missing and unexpected claims. Missing claims are those specified in this class but not given in the
        # claim set. Unexpected claims are those given in the claim set but not specified in this class.
        expected_claims = self._get_claim_names()
        actual_claims = set(claim_set.keys())

        # Use the name of the instance variable for missing claims to avoid confusion.
        # For unexpected claims, use the name of the claim.
        missing_claims = {self._map_claim_name_to_instance_var(name) for name
                          in expected_claims.difference(actual_claims) if not self._is_optional_claim(name)}
        unexpected_claims = actual_claims.difference(expected_claims)

        # If there are no missing or unexpected claims, everything is fine.
        if len(missing_claims) == 0 and len(unexpected_claims) == 0:
            return True

        # Otherwise, raise an exception.
        raise InvalidClaimSetError(missing_claims, unexpected_claims)

    # endregion

    # region Instance Variable and Claim Helpers

    @classmethod
    def _is_claim(cls, instance_var: str) -> bool:
        """
            Determine if a given instance variable is part of the token's claim set.

            An instance variable will be considered to be a claim if:

            * it is listed in :attr:`_private_claims`, or
            * it does not start with an underscore, but
                * is not listed in :attr:`_public_non_claims'.

            :param instance_var: The name of the instance variable to check.
            :return: `True` if the instance variable is part of the claim set, `False` otherwise.
        """

        # Some instance variables are always included in the claim set.
        if instance_var in cls._private_claims:
            return True

        # Private instance variables are never included (unless explicitly allowed above).
        if instance_var.startswith('_'):
            return False

        # Public instance variables might not be a claim.
        if instance_var in cls._public_non_claims:
            return False

        return True

    @classmethod
    def _is_optional_claim(cls, claim_name: str) -> bool:
        """
            Determine if the given claim is optional and may thus be empty or missing in the claim set.

            A claim is optional if it is listed in :attr:`_optional_claims`.

            :param claim_name: The name of the claim to check.
            :return: `True` if the given claim is optional, `False` otherwise.
        """

        return claim_name in cls._optional_claims

    @classmethod
    def _map_claim_name_to_instance_var(cls, claim_name: str) -> str:
        """
            Map a claim to the name of its instance variable.

            :param claim_name: The name of the claim to map.
            :return: The name of the corresponding instance variable.
        """

        # If the claim_name name is not defined in the mapping, return its own name.
        return cls._instance_var_claim_name_mapping.inv.get(claim_name, claim_name)

    @classmethod
    def _map_instance_var_to_claim_name(cls, instance_var: str) -> str:
        """
            Map an instance variable that will be part of the claim set to its claim name.

            :param instance_var: The name of the instance variable to map.
            :return: The name of the corresponding claim.
        """

        # If the instance variable is not defined in the mapping, return the variable's name.
        return cls._instance_var_claim_name_mapping.get(instance_var, instance_var)

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
