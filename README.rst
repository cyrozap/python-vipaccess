python-vipaccess
================

|Build Status| |Coverage Status| |Apache 2.0 License|

python-vipaccess is a free and open source software (FOSS)
implementation of Symantec's VIP Access client. It is able to generate
OATH URIs and their corresponding QR codes so any TOTP-generating
application can be used as a VIP OTP token.

Right now, it only supports the bare minimum number of features of the
VIP Access provisioning protocol to work, but I might add support for
the other features at some point in the future.

You can see my original blog post
`here <http://www.cyrozap.com/2014/09/29/reversing-the-symantec-vip-access-provisioning-protocol/>`__,
in which I describe how I reverse-engineered the VIP Access application.

Dependencies
------------

-  Python 2.7
-  `image <https://pypi.python.org/pypi/image/1.3.3>`__
-  `lxml <https://pypi.python.org/pypi/lxml/3.4.0>`__
-  `oath <https://pypi.python.org/pypi/oath/1.2>`__
-  `PyCrypto <https://pypi.python.org/pypi/pycrypto/2.6.1>`__
-  `qrcode <https://pypi.python.org/pypi/qrcode/5.0.1>`__
-  `requests <https://pypi.python.org/pypi/requests/>`__

If you have ``pip`` installed on your system, you can install them with
``pip install image lxml oath PyCrypto qrcode requests``.

Installation
------------

Via pip (recommended)
~~~~~~~~~~~~~~~~~~~~~

``pip install python-vipaccess``

Manual
~~~~~~

1. Check out this repository by running
   ``git clone https://github.com/cyrozap/python-vipaccess.git``
2. Switch to the ``python-vipaccess`` directory by running
   ``cd python-vipaccess``
3. Install the ``vipaccess`` module

   -  With pip: ``pip install .``
   -  Without pip: ``python setup.py install``

Usage
-----

Execute ``vipaccess`` (it should be in your ``PATH``).

.. |Build Status| image:: https://travis-ci.org/cyrozap/python-vipaccess.svg?branch=master
   :target: https://travis-ci.org/cyrozap/python-vipaccess
.. |Coverage Status| image:: https://coveralls.io/repos/cyrozap/python-vipaccess/badge.svg?branch=master
   :target: https://coveralls.io/r/cyrozap/python-vipaccess?branch=master
.. |Apache 2.0 License| image:: http://img.shields.io/badge/license-Apache--2.0-blue.svg
   :target: https://www.apache.org/licenses/LICENSE-2.0.html
