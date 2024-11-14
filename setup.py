import os
from setuptools import setup, find_packages

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md")) as infile:
    long_description = infile.read()

setup(
    name="graval",
    version="0.0.4",
    description="GraVal - graphics (card) validation framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rayonlabs/graval",
    author="jondurbin & cxmplex",
    license_expression="MIT",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    package_data={
        "graval": ["lib/*.so"],
    },
    install_requires=[
        "setuptools>=0.75",
    ],
    extras_require={
        "dev": [
            "black",
            "flake8",
            "wheel",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3 :: Only"
    ],
)
