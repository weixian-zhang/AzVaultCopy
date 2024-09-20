from setuptools import setup, find_packages
import os

# eg 1 - install local
# https://www.turing.com/kb/how-to-create-pypi-packages#step-4:-write-the-package-code
# eg 2 - click app to pypi
# https://blog.thesourcepedia.org/build-cli-app-in-python-with-click-and-publish-to-pypi
# twine upload test pypi
# https://packaging.python.org/en/latest/guides/using-testpypi/

cwd = os.path.dirname(os.path.realpath(__file__))

# Utility function to read the requirements from the requirements.txt file
def _modules():
    requirement_fp = os.path.join(cwd, 'requirements.txt')
    with open(requirement_fp) as f:
        modules = f.read().splitlines()
        return modules
    
def _readme():
    readme_fp = os.path.join(cwd, 'README.md')
    with open(readme_fp) as f:
        readme = f.read()
        return readme

setup(
    name="azvaultcopy",  # Replace with your package name
    version="0.1.5",  # Version of the package
    author="Weixian Zhang",
    author_email="wxztechpass@outlook.com",
    description="cmdline tool to copy Azure Key Vault certs and secrets from one vault to another in same or a different tenant",
    long_description=_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/weixian-zhang/AzVaultCopy",  # URL to the repository or project page
    packages=find_packages(exclude=['tests']),  # Automatically find packages in the directory
    install_requires=_modules(),
    license= "MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",  # Replace with your license
        'Operating System :: Microsoft :: Windows',
    ],
    python_requires=">=3.11",  # Specify the minimum Python version,
    py_modules=['azvaultcopy', 'src'],
    entry_points={
        'console_scripts': [
            'azvaultcopy = src.azvaultcopy:cli'
        ]
    }
)
