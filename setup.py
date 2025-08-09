#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import os
import re


# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read requirements from requirements.txt
with open('requirements.txt') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]


# Read version from __init__.py
def get_version():
    version_file = os.path.join(this_directory, 'lancalc', '__init__.py')
    with open(version_file, 'r') as f:
        version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", f.read(), re.M)
        if version_match:
            return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


setup(
    name='lancalc',
    version=get_version(),
    author='wachawo',
    description='A desktop application for calculating network configurations',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/lancalc/lancalc',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: System :: Networking',
        'Topic :: Utilities',
    ],
    python_requires='>=3.7',
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'lancalc=lancalc.main:main',
        ],
    },
    include_package_data=True,
    package_data={
        'lancalc': ['*.py'],
    },
    keywords='network calculator subnet ip address',
    project_urls={
        'Bug Reports': 'https://github.com/lancalc/lancalc/issues',
        'Source': 'https://github.com/lancalc/lancalc',
        'Documentation': 'https://github.com/lancalc/lancalc#readme',
    },
)
