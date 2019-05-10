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

.. autoexception:: easyjwt.EasyJWTError
    :members:
    :show-inheritance:

Creation Errors
~~~~~~~~~~~~~~~

This section lists all error classed defined by |project| that may be raised during the creation of a token. Note that
some error classes may also listed below `Verification Errors`_.

.. autoexception:: easyjwt.CreationError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.IncompatibleKeyError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.MissingRequiredClaimsError
    :members:
    :show-inheritance:

Verification Errors
~~~~~~~~~~~~~~~~~~~

This section lists all error classed defined by |project| that may be raised during the verification of a token. Note
that some error classes may also listed below `Creation Errors`_.

.. autoexception:: easyjwt.VerificationError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.ExpiredTokenError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.ImmatureTokenError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.IncompatibleKeyError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.InvalidAudienceError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.InvalidClaimSetError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.InvalidClassError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.InvalidIssuedAtError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.InvalidIssuerError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.InvalidSignatureError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.UnspecifiedClassError
    :members:
    :show-inheritance:

.. autoexception:: easyjwt.UnsupportedAlgorithmError
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
