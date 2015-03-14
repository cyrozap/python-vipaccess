# python-vipaccess

[![Build Status](https://travis-ci.org/cyrozap/python-vipaccess.svg?branch=master)](https://travis-ci.org/cyrozap/python-vipaccess)
[![Coverage Status](https://coveralls.io/repos/cyrozap/python-vipaccess/badge.svg?branch=master)](https://coveralls.io/r/cyrozap/python-vipaccess?branch=master)

python-vipaccess is a free and open source software (FOSS) implementation of
Symantec's VIP Access client. It is able to generate OATH URIs and their
corresponding QR codes so any TOTP-generating application can be used as a VIP
OTP token.

Right now, it only supports the bare minimum number of features of the VIP
Access provisioning protocol to work, but I might add support for the other
features at some point in the future.

You can see my original blog post [here][1], in which I describe how I
reverse-engineered the VIP Access application.

## Dependencies

- Python 2.7
- [image](https://pypi.python.org/pypi/image/1.3.3)
- [lxml](https://pypi.python.org/pypi/lxml/3.4.0)
- [oath](https://pypi.python.org/pypi/oath/1.2)
- [PyCrypto](https://pypi.python.org/pypi/pycrypto/2.6.1)
- [qrcode](https://pypi.python.org/pypi/qrcode/5.0.1)
- [requests](https://pypi.python.org/pypi/requests/)

If you have `pip` installed on your system, you can install them with
`pip install image lxml oath PyCrypto qrcode requests`.

## Installation

1. Check out this repository by running
   `git clone https://github.com/cyrozap/python-vipaccess.git`
2. Switch to the `python-vipaccess` directory by running `cd python-vipaccess`
3. Install the `vipaccess` module
   - With pip: `pip install .`
   - Without pip: `python setup.py install`

## Usage

Execute `vipaccess` (it should be in your `PATH`).


[1]: http://www.cyrozap.com/2014/09/29/reversing-the-symantec-vip-access-provisioning-protocol/
