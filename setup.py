from setuptools import setup, find_packages

setup(
    name="codeql-pii-detection-poc",
    version="0.1.0",
    packages=find_packages(),
    package_data={
        '': ['*.py', '*.js'],
    },
    include_package_data=True,
    python_requires=">=3.7",
    install_requires=[
        "structlog>=23.1.0",
    ],
)