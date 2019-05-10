API
===

.. automodule:: easyjwt

.. contents:: Contents
    :backlinks: none
    :local:

Classes
-------

This section lists all classes defined by |project|.

.. autoclass:: easyjwt.EasyJWT
    :members:
    :show-inheritance:

Enumerations
------------

This section lists all enumerations defined by |project|.

.. autoclass:: easyjwt.Algorithm
    :members:
    :show-inheritance:

Errors
------

This section lists all error classes defined by |project|.

.. autoclass:: easyjwt.EasyJWTError
    :members:
    :show-inheritance:

Creation Errors
~~~~~~~~~~~~~~~

This section lists all error classed defined by |project| that may be raised during the creation of a token. Note that
some error classes may also listed below `Verification Errors`_.

.. autoclass:: easyjwt.CreationError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.IncompatibleKeyError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.MissingRequiredClaimsError
    :members:
    :show-inheritance:

Verification Errors
~~~~~~~~~~~~~~~~~~~

This section lists all error classed defined by |project| that may be raised during the verification of a token. Note
that some error classes may also listed below `Creation Errors`_.

.. autoclass:: easyjwt.VerificationError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.ExpiredTokenError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.ImmatureTokenError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.IncompatibleKeyError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.InvalidAudienceError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.InvalidClaimSetError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.InvalidClassError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.InvalidIssuedAtError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.InvalidIssuerError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.InvalidSignatureError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.UnspecifiedClassError
    :members:
    :show-inheritance:

.. autoclass:: easyjwt.UnsupportedAlgorithmError
    :members:
    :show-inheritance:

Modules
-------

This section lists all modules defined by |project|.

restoration
~~~~~~~~~~~

.. automodule:: easyjwt.restoration
    :members:

Types
-----

This section lists the types defined by |project|.

.. autodata:: easyjwt.easyjwt.EasyJWTClass
