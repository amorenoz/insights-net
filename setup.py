#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""The setup script."""

from setuptools import setup, find_packages

with open("README.md") as readme_file:
    readme = readme_file.read()

requirements = [
    "ipython",
    "coverage",
    "ipykernel",
    "click",
    "colorama",
    "rich",
    "ovsdbapp",
    "insights-core",
    "tabulate",
]

setup_requirements = [
    "pytest-runner",
]

test_requirements = [
    "pytest",
    "pylint",
]

setup(
    author="Adrián Moreno",
    author_email="amorenoz@redhat.com",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
    ],
    description="Network analysis tools based on insights-core",
    install_requires=requirements,
    license="Apache Software License 2.0",
    long_description=readme,
    include_package_data=True,
    name="insights-net",
    packages=find_packages(include=["insights_net*"]),
    setup_requires=setup_requirements,
    scripts=["bin/insights-net"],
    test_suite="tests",
    tests_require=test_requirements,
    version="0.0.1",
    zip_safe=False,
)
