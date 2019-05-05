# EasyJWT

[![PyPI](https://img.shields.io/pypi/v/easyjwt.svg)](https://pypi.org/project/easyjwt/)
[![PyPI - License](https://img.shields.io/pypi/l/easyjwt.svg)](https://github.com/BMeu/EasyJWT/blob/master/LICENSE)
[![Build Status](https://travis-ci.org/BMeu/EasyJWT.svg?branch=master)](https://travis-ci.org/BMeu/EasyJWT)
[![codecov](https://codecov.io/gh/BMeu/EasyJWT/branch/master/graph/badge.svg)](https://codecov.io/gh/BMeu/EasyJWT)
[![Documentation Status](https://readthedocs.org/projects/easyjwt/badge/?version=latest)](https://easyjwt.readthedocs.io/en/latest/?badge=latest)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/easyjwt.svg)

EasyJWT provides a simple interface to creating and verifying
[JSON Web Tokens (JWTs)](https://tools.ietf.org/html/rfc7519) in Python. It allows you to once define the claims of the
JWT, and to then create and accept tokens with these claims without having to check if all the required data is given
or if the token actually is the one you expect.

```python
from easyjwt import EasyJWT

# Define the claims of your token.
class MySuperSimpleJWT(EasyJWT):

    def __init__(self, key):
        super().__init__(key)
        
        # Define a claim `name`.
        self.name = None

# Create a token with some values.
token_object = MySuperSimpleJWT('Super secret key')
token_object.name = 'Zaphod Beeblebrox'
token = token_object.create()

# Verify the created token.
verified_token_object = MySuperSimpleJWT.verify(token, 'Super secret key')
assert verified_token_object.name == 'Zaphod Beeblebrox'
```

## Features

 * Define the claims of your token once as a class, then use this class to easily create and verify multiple tokens.
 * No worries about typos in dictionary keys: the definition of your claim set as a class enables IDEs to find those
   typos for you.
 * Multiple tokens may have the same claims, but different intentions. EasyJWT will take care of this for you: you can
   define a token for account validation and one for account deletion, both with the account ID as a claim, and you
   don't need to worry about accidentally deleting a newly created account instead of validating it, just because
   someone mixed up the tokens.
 * Tokens will be rejected if mandatory claims are missing or unexpected claims are included.
 * You can define optional claims for your tokens.
 * All registered JWT claims are supported: `aud`, `exp`, `iat`, `iss`, `jti`, `nbf`, and `sub`.

## System Requirements & Installation

EasyJWT requires Python 3.6 or newer.

EasyJWT is available [on PyPI](https://pypi.org/project/easyjwt/). You can install it using your favorite package
manager.

 * PIP:

    ```bash
    python -m pip install easyjwt
    ```

 * Pipenv:

    ```bash
    pipenv install easyjwt
    ```

## Usage

Before you can create tokens, you need to define the claims that your token will have. You do this by creating a token
class that inherits from `EasyJWT`. In its `__init__` method, you specify the claims of your token, simply by defining
attributes with the name of your claims. EasyJWT will consider all attributes to be claims, unless they start with an
underscore `_`. Remember to call the `__init__` method on the parent class to correctly initialize the objects of your
class.

```python
from easyjwt import EasyJWT

class MySuperSimpleJWT(EasyJWT):

    def __init__(self, key):
        super().__init__(key)
        
        # These are the claims of your token: `name` and `email`.
        self.name = None
        self.email = None

        # This attribute will not become a claim since it starts with an underscore.
        self._not_an_attribute = True
```

You can now create the actual token by instantiating your class with the key with which the token will be encoded,
setting your values on this token object, and then calling EasyJWT's `create` method.

```python
token_object = MySuperSimpleJWT('Super secret key')
token_object.name = 'Zaphod Beeblebrox'
token_object.email = 'elprez@universe.gov'

token = token_object.create()
```

If you forget to set the value of one your claims, the creation will fail with an `MissingRequiredClaimsError`
exception (see below for information on how to define [optional claims](#optional-claims)).

Once you receive a token to verify, you simply pass it and the key with which it has been encoded to EasyJWT's `verify`
method. If the token is valid, the returned object will contain the values of the token.

```python
verified_token_object = MySuperSimpleJWT.verify(token, 'Super secret key')

assert verified_token_object.name == 'Zaphod Beeblebrox'
assert verified_token_object.email == 'elprez@universe.gov'
```

If you try to verify a token that is missing one or more of the claims specified in your token class, or it includes one
or more claims that you did not specify in your token class, the verification will fail by raising an
`InvalidClaimSetError` exception. Thus, you always know that the data you expect in the token will in fact be present.

The neat thing about EasyJWT is: it knows with which class a token has been created, and will only accept tokens if they
have been created with the class with which you are trying to verify it ([see below](#accepting-third-party-tokens)
for more information and how to disable this behavior). Thus, you can have multiple token classes with the same claims,
but different contexts, and you don't have to worry about mixing up their tokens!

```python
from easyjwt import EasyJWT

class AccountValidationToken(EasyJWT):
    """ Validate the newly created user account with the specified ID. """

    def __init__(self, key):
        super().__init__(key)
        
        self.user_id = None

class AccountDeletionToken(EasyJWT):
    """ Delete the user account with the specified ID. """

    def __init__(self, key):
        super().__init__(key)
        
        self.user_id = None

validation_token_object = AccountValidationToken('Super secret key')
validation_token_object.user_id = 42
validation_token = validation_token_object.create()

# Verifying the validation token with the deletion token class will fail!
# AccountDeletionToken.verify(validation_token, 'Super secret key')
```

If you try to verify a token with a wrong class, EasyJWT will automatically reject your token by raising an
`InvalidClassError` exception.

### Accepting Third-Party Tokens

By default, EasyJWT will only accept tokens that have been created by the class with which you verify
it.<sup><a name="fn1-def" href="#fn1">[1]</a></sup> This is
done by including a special claim in the token upon creation. This claim is required when verifying a token. Tokens
without this claim or with a wrong value for this claim will fail verification. Usually, tokens from other sources will
not include this claim, and thus the validation of such a token will fail.

You can disable the verification of this special claim by setting a special flag in your token class. This flag will
also prevent the special claim from being included in the created tokens.

```python
from easyjwt import EasyJWT

class ThirdPartyJWT(EasyJWT):

    # Disable the validation of the special claim.
    strict_verification = False

    # The usual definition of the token's claim set ...
```

If you try to verify a token without this special claim and without disabling the strict verification mode, EasyJWT
will raise an `UnspecifiedClassError` exception.

---

> <a name="fn1" href="#fn1-def">[1]</a>: To be precise, the name of the class with which the token has been created must
> be the same as the name of the class with which it is being verified. This class name is included in each token
> created by EasyJWT in the special claim `_easyjwt_class`.

### Encoding Algorithms

Tokens created by EasyJWT are encoded using the HS256 algorithm by default. If you want to use a different algorithm,
you can specify this algorithm in the definition of your token class.

```python
from easyjwt import Algorithm
from easyjwt import EasyJWT

class MySuperSimpleJWT(EasyJWT):

    # Use the HS512 algorithm.
    algorithm = Algorithm.HS512

    # The usual definition of the token's claim set ...
```

If you have previously created tokens with your token class, and later want to change the algorithm for new tokens,
you should tell EasyJWT to still use the previous algorithms for decoding tokens. Otherwise, tokens created with the old
version of your code cannot be verified!

```python
from easyjwt import Algorithm
from easyjwt import EasyJWT

class MySuperSimpleJWT(EasyJWT):

    # Use the HS512 algorithm.
    algorithm = Algorithm.HS512

    # Previously, tokens have been encoded with HS256, EasyJWT's default algorithm.
    # Thus, list it here.
    previous_algorithms = {Algorithm.HS256}

    # The usual definition of the token's claim set ...
```

You can find a list of all available algorithms in the
[API documentation](https://easyjwt.readthedocs.io/en/latest/api.html#easyjwt.Algorithm).

### Optional Claims

All the claims you specify in the `__init__` method of your token class are mandatory, both for creating a token of this
class and for verifying a token. If you want some of these claims to be optional (both for creating and verifying a
token), you can override EasyJWT's `_optional_claims` class variable. You can override this class variable in your token
class to include the names of your optional claims. Note that you must include the value of `EasyJWT._optional_claims`
in your class. Otherwise, the registered claims will become mandatory.

```python
from easyjwt import EasyJWT

class MySuperSimpleJWT(EasyJWT):

    # The claim `my_optional_claim` is optional. All other claims are still mandatory.
    _optional_claims = EasyJWT._optional_claims.union({'my_optional_claim'})

    def __init__(self, key):
        super().__init__(key)
        
        self.my_optional_claim = None
        self.my_mandatory_claim = None

token_object = MySuperSimpleJWT('Super secret key')
token_object.my_mandatory_claim = 'Some value'

token = token_object.create()
```

### Registered Claims

EasyJWT supports all registered claims of the JWT specification: `aud`, `exp`, `iat`, `iss`, `jti`, `nbf`, and `sub`.
All of these claims are optional.

#### Audience: `aud`

The audience identifies the recipients of the token, and can either be a string or a list of strings.

You can set an audience for your token using the attribute `audience` of your token object. This attribute will
automatically be mapped to the `aud` claim when creating the token.

```python
from easyjwt import EasyJWT

class MySuperSimpleJWT(EasyJWT):

    def __init__(self, key):
        super().__init__(key)
        
        self.name = None

token_object = MySuperSimpleJWT('Super secret key')
token_object.name = 'Zaphod Beeblebrox'

# This token is intended for everyone, and especially for Zaphod Beeblebrox.
token_object.audience = ['Zaphod Beeblebrox', 'Everyone']

token = token_object.create()
```

To verify a token with an audience, you must pass at least one of the audience values to EasyJWT's `verify` method.
Otherwise, the verification will fail with an `InvalidAudienceError` exception. After the verification, the token's
audience will be set on the `audience` attribute.

```python
# We are everyone, so this token is intended for us.
verified_token_object = MySuperSimpleJWT.verify(token, 'Super secret key', audience='Everyone')

assert verified_token_object.audience == ['Zaphod Beeblebrox', 'Everyone']
```

#### Expiration Date: `exp`

The expiration date specifies how long the token will be valid. If a token with an expiration date is verified after its
expiration date has passed, the token will be invalid.

You can set an expiration date for your token using the attribute `expiration_date` to a `datetime` object. This
attribute will automatically be mapped to the `exp` claim when creating the token. Note that you must specify the
expiration date in UTC.

```python
import datetime
from easyjwt import EasyJWT

class MySuperSimpleJWT(EasyJWT):

    def __init__(self, key):
        super().__init__(key)
        
        self.name = None

token_object = MySuperSimpleJWT('Super secret key')
token_object.name = 'Zaphod Beeblebrox'

# This token will expire in 15 minutes.
token_object.expiration_date = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)

token = token_object.create()
```

When verifying a token with an expiration date, EasyJWT automatically checks if the expiration date has passed. If this
is the case, the verification will fail with an `ExpiredTokenError` exception. After the verification, the token's
expiration date will be set on the `expiration_date` attribute as a `datetime` object in UTC.

#### Issued At: `iat`

The issued at-date specifies the token's time of creation.

When creating a token, this claim will automatically be set to the current time. If you want to set a different
issued at-date, you can pass a `datetime` object (in UTC) to the optional `issued_at` parameter of EasyJWT's `create`
method.

```python
import datetime
from easyjwt import EasyJWT

class MySuperSimpleJWT(EasyJWT):

    def __init__(self, key):
        super().__init__(key)
        
        self.name = None

token_object = MySuperSimpleJWT('Super secret key')
token_object.name = 'Zaphod Beeblebrox'

# This token was issued five minutes ago.
token = token_object.create(issued_at=datetime.datetime.utcnow() - datetime.timedelta(minutes=5))
```

After verifying a token with an issued at-date, its issued at-date will be set on the `issued_at_date` attribute.

#### Issuer: `iss`

The issuer identifies the creator of the token.

You can set the issuer of your token using the `issuer` attribute of your token object. This attribute will
automatically be mapped to the `iss` claim when creating the token.

```python
from easyjwt import EasyJWT

class MySuperSimpleJWT(EasyJWT):

    def __init__(self, key):
        super().__init__(key)
        
        self.name = None

token_object = MySuperSimpleJWT('Super secret key')
token_object.name = 'Zaphod Beeblebrox'

# This token is intended for everyone, and especially for Zaphod Beeblebrox.
token_object.issuer = 'Arthur Dent'

token = token_object.create()
```

To verify a token with an issuer, you must pass the issuer specified in the token to EasyJWT's `verify` method.
Otherwise, the verification will fail with an `InvalidIssuerError` exception. After the verification, the token's issuer
will be set on the `issuer` attribute.

```python
# We are everyone, so this token is intended for us.
verified_token_object = MySuperSimpleJWT.verify(token, 'Super secret key', issuer='Arthur Dent')

assert verified_token_object.issuer == 'Arthur Dent'
```

#### JWT ID: `jti`

The JWT ID is an identifier for your token. It must be unique for each token.

You can set the JWT ID of your token using the `JWT_ID` attribute of your token object. This attribute will
automatically be mapped to the `jti` claim when creating the token

```python
from easyjwt import EasyJWT

class MySuperSimpleJWT(EasyJWT):

    def __init__(self, key):
        super().__init__(key)
        
        self.name = None

token_object = MySuperSimpleJWT('Super secret key')
token_object.name = 'Zaphod Beeblebrox'

# This ID must be unique for each token.
token_object.JWT_ID = 'My super simple JWT 1'

token = token_object.create()
```

After verifying a token with a JWT ID, this ID will be set on the `JWT_ID` attribute.

Note that this claim is not verified by EasyJWT. It is your responsibility to validate it after verifying the token if
you need this validation.

#### Not Before: `nbf`

The not before-date specifies the time before which the token will not be valid. If a token with a not before-date is
verified before its not before-date has been reached, the token will be invalid.

You can set a not before-date for your token using the attribute `not_before_date` to a datetime object. This attribute
will automatically be mapped to the `nbf` claim when creating the token. Note that you must specify the not before-date
in UTC.

```python
import datetime
from easyjwt import EasyJWT

class MySuperSimpleJWT(EasyJWT):

    def __init__(self, key):
        super().__init__(key)
        
        self.name = None

token_object = MySuperSimpleJWT('Super secret key')
token_object.name = 'Zaphod Beeblebrox'

# This token will be valid in 5 minutes.
token_object.not_before_date = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)

token = token_object.create()
```

When verifying a token with a not before-date, EasyJWT automatically checks if the not before-date has been reached. If
this is not the case, the verification will fail with an `ImmatureTokenError` exception. After the verification, the
token's not before-date will be set on the `not_before_date` attribute as a `datetime` object in UTC.

#### Subject: `sub`

The subject specifies the topic of your token.

You can set the subject of your token using the `subject` attribute of your token object. This attribute will
automatically be mapped to the `sub` claim when creating the token.

```python
from easyjwt import EasyJWT

class MySuperSimpleJWT(EasyJWT):

    def __init__(self, key):
        super().__init__(key)
        
        self.name = None

token_object = MySuperSimpleJWT('Super secret key')
token_object.name = 'Zaphod Beeblebrox'

# This token is all about Douglas Adams' master work.
token_object.subject = 'The Hitchhiker\'s Guide to the Galaxy'

token = token_object.create()
```

After verifying a token with a subject, this subject will be set on the `subject` attribute.

Note that this claim is not verified by EasyJWT. It is your responsibility to validate it after verifying the token if
you need this validation.

## Future Ideas

 * Allow creating tokens without an issued at-date.
 * Add a mode to accept arbitrary claims and create corresponding attributes as needed.
 * Allow specifying functions to pack and unpack claim values before creating a token and after verifying a token,
   respectively.

## Acknowledgements

EasyJWT is just an easy-to-use abstraction layer around José Padilla's [PyJWT library](https://pypi.org/project/PyJWT/)
that does the actual work of creating and verifying the tokens according to the JWT specification. Without his work,
EasyJWT would not be possible.

## License

EasyJWT is developed by [Bastian Meyer](https://www.bastianmeyer.eu)
<[bastian@bastianmeyer.eu](mailto:bastian@bastianmeyer.eu)> and is licensed under the
[MIT License]((http://www.opensource.org/licenses/MIT)). For details, see the attached [LICENSE](LICENSE) file. 
