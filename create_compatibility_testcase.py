#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
    Create a token with the current version of EasyJWT and save it to the specified file.

    For full usage information, run
    ```
        pipenv shell
        python create_compatibility_testcase.py -h
    ```
"""

from datetime import datetime
from datetime import timezone
from json import dumps
from os.path import join
from sys import argv

from tests.compatibility_test import CompatibilityToken
from tests.compatibility_test import ExternalCompatibilityToken
from tests.compatibility_test import TOKEN_FOLDER

if __name__ == '__main__':

    # Print a usage message.
    help_options = {'-h', '--help'}
    if len(argv) != 2 or argv[1] in help_options:
        print(f'Create a token with the current version of EasyJWT and save it to')
        print(f'{TOKEN_FOLDER}/[VERSION].jwt.')
        print()
        print(f'USAGE:')
        print(f'    {argv[0]} [OPTIONS] [VERSION]')
        print()
        print(f'REQUIRED ARGUMENTS:')
        print(f'    VERSION         The current version of EasyJWT.')
        print(f'                    Will be used as the file name for the created token.')
        print()
        print(f'OPTIONS:')
        print(f'    -e, --external  Get the claim set of the external token, instead of creating a token file.')
        print(f'    -h, --help      Print this usage message and exit.')

        exit(0 if len(argv) == 2 and argv[1] in help_options else 1)

    # If requested, create the external token claim set.
    if argv[1] in {'-e', '--external'}:
        # Set the values on the claim set.
        external_token = ExternalCompatibilityToken('')
        external_token.set_claim_set()

        # Get the claim set and convert the values of the date claims to integer timestamps.
        # noinspection PyProtectedMember
        claim_set = external_token._get_claim_set()
        for date_claim in {'exp', 'iat', 'nbf'}:
            date = claim_set.get(date_claim, None)
            if date is None or not isinstance(date, datetime):
                continue

            timestamp = int(date.replace(tzinfo=timezone.utc).timestamp())
            claim_set[date_claim] = timestamp

        print(dumps(claim_set, indent=4, sort_keys=True))
        exit(0)

    # Create the token.
    token = CompatibilityToken.create_compatibility_token()

    # Save the token to a file.
    version = argv[1]
    file_name = version.replace('.', '_') + '.jwt'
    file_path = join(TOKEN_FOLDER, file_name)
    with open(file_path, 'w') as file:
        file.write(token)

    print(f'Saved token to file {file_path}.')
    exit(0)
