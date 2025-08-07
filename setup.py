from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='sbom_ind',
    version='1.0.0',
    description='CAST Highlight SBOM Generator',
    author='Your Name',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=requirements,
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'sbom-ind=src.main:main',
        ],
    },
    python_requires='>=3.8',
) 