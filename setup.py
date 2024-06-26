import setuptools
from setuptools.command.install import install

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

exec(open('src/securespacy/version.py').read())

class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        import os
        install.run(self)
        pickle_fn = os.path.expanduser('~/.tokenized_matcher.pickle')
        if os.path.exists(pickle_fn):
            print(f'Deleting cache file {pickle_fn}. It will be regenerated.')
            os.unlink(pickle_fn)

setuptools.setup(
    name="securespacy",
    version=__version__,
    author="Joey Costoya",
    author_email="joey_costoya@trendmicro.com",
    description="Custom Spacy tokenizer and NER extractor for IoCs",
    license="Apache Software License 2.0",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.trendmicro.com/CoreTech-FTR/securespacy",
    project_urls={
        "Bug Tracker": "https://github.trendmicro.com/CoreTech-FTR/securespacy/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    test_suite='nose.collector',
    tests_require=['nose', 'publicsuffix2'],
    python_requires=">=3.6",
    install_requires=["spacy>=3.0.5", "publicsuffix2>=2.20191221"],
    include_package_data=True,
    cmdclass={
        'install': PostInstallCommand,
    },
)
