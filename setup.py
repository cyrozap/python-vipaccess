from setuptools import setup
from codecs import open

with open('README.rst') as f:
    readme = f.read()

setup(
    name='python-vipaccess',
    version='0.1.2',
    description="A free software implementation of Symantec's VIP Access application and protocol",
    long_description=readme,
    url='https://github.com/cyrozap/python-vipaccess',
    author='Forest Crossman',
    author_email='cyrozap@gmail.com',
    license='Apache 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='development',
    packages=['vipaccess'],
    install_requires=[
        'image',
        'lxml',
        'oath',
        'PyCrypto',
        'qrcode',
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'vipaccess=vipaccess.utils:main',
        ],
    },
    test_suite='nose.collector',
)
