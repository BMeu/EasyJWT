from setuptools import find_packages
from setuptools import setup

with open('README.md', 'r') as readme:
    long_description = readme.read()

setup(
    name='easyjwt',
    version='0.1.1',
    packages=find_packages(exclude=['docs', 'tests*']),

    python_requires='>=3.6',
    install_requires=[
        'bidict',
        'PyJWT',
    ],

    author='Bastian Meyer',
    author_email='bastian@bastianmeyer.eu',
    url='https://github.com/BMeu/EasyJWT',
    project_urls={
        'Documentation': 'https://easyjwt.readthedocs.io/en/latest/?badge=latest',
        'Source': 'https://github.com/BMeu/EasyJWT',
        'Tracker': 'https://github.com/BMeu/EasyJWT/issues',
    },

    description='Super simple JSON Web Tokens with Python',
    long_description=long_description,
    long_description_content_type='text/markdown',

    keywords='jwt token tokens JSON',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
