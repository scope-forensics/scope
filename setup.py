from setuptools import setup, find_packages

setup(
    name="scope",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.24.0",
        "botocore>=1.27.0",
    ],
    entry_points={
        'console_scripts': [
            'scope=scope.cli:main',
        ],
    },
    author="Scope",
    author_email="scopeforensics@protonmail.com",
    description="A tool for cloud forensics investigations",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/scope-forensics/scope",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache 2.0 License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)

if __name__ == "__main__":
    setup() 