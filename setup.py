#
# Copyright (C) 2021 GrammaTech, Inc.
#
# This code is licensed under the MIT license. See the LICENSE file in
# the project root for license terms.
#
# This project is sponsored by the Office of Naval Research, One Liberty
# Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
# N68335-17-C-0700.  The content of the information does not necessarily
# reflect the position or policy of the Government and no official
# endorsement should be inferred.
#

import imp

import setuptools

version = imp.load_source(
    "pkginfo.version", "gtirb_test_helpers/version.py"
).__version__

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="gtirb-test-helpers",
    version=version,
    author="GrammaTech",
    author_email="gtirb@grammatech.com",
    description="Utilities for creating GTIRB IR in tests",
    packages=setuptools.find_packages(),
    package_data={"gtirb_test_helpers": ["py.typed"]},
    install_requires=["gtirb >= 1.10.3"],
    classifiers=["Programming Language :: Python :: 3"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/grammatech/gtirb-test-helpers",
    license="MIT",
)
