# -*- coding: utf-8 -*-
#
#   Copyright 2014 Forest Crossman
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


from __future__ import print_function

import base64
import binascii
import hashlib
import hmac
import string
import sys
import time
# Python 2/3 compatibility
try:
    import urllib.parse as urllib
except ImportError:
    import urllib

import qrcode
import requests
from Crypto.Cipher import AES
from Crypto.Random import random
from lxml import etree
from oath import totp


PROVISIONING_URL = 'https://services.vip.symantec.com/prov'

HMAC_KEY = b'\xdd\x0b\xa6\x92\xc3\x8a\xa3\xa9\x93\xa3\xaa\x26\x96\x8c\xd9\xc2\xaa\x2a\xa2\xcb\x23\xb7\xc2\xd2\xaa\xaf\x8f\x8f\xc9\xa0\xa9\xa1'

TOKEN_ENCRYPTION_KEY = b'\x01\xad\x9b\xc6\x82\xa3\xaa\x93\xa9\xa3\x23\x9a\x86\xd6\xcc\xd9'

REQUEST_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8" ?>
<GetSharedSecret Id="%(timestamp)d" Version="2.0"
    xmlns="http://www.verisign.com/2006/08/vipservice"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <TokenModel>%(token_model)s</TokenModel>
    <ActivationCode></ActivationCode>
    <OtpAlgorithm type="%(otp_algorithm)s"/>
    <SharedSecretDeliveryMethod>%(shared_secret_delivery_method)s</SharedSecretDeliveryMethod>
    <DeviceId>
        <Manufacturer>%(manufacturer)s</Manufacturer>
        <SerialNo>%(serial)s</SerialNo>
        <Model>%(model)s</Model>
    </DeviceId>
    <Extension extVersion="auth" xsi:type="vip:ProvisionInfoType"
        xmlns:vip="http://www.verisign.com/2006/08/vipservice">
        <AppHandle>%(app_handle)s</AppHandle>
        <ClientIDType>%(client_id_type)s</ClientIDType>
        <ClientID>%(client_id)s</ClientID>
        <DistChannel>%(dist_channel)s</DistChannel>
        <ClientInfo>
            <os>%(os)s</os>
            <platform>%(platform)s</platform>
        </ClientInfo>
        <ClientTimestamp>%(timestamp)d</ClientTimestamp>
        <Data>%(data)s</Data>
    </Extension>
</GetSharedSecret>'''


def generate_request(**request_parameters):
    '''Generate a token provisioning request.'''
    request_parameters['timestamp'] = request_parameters.get(
        'timestamp',
        int(time.time())
        )
    request_parameters['token_model'] = request_parameters.get(
        'token_model',
        'VSST'
        )
    request_parameters['otp_algorithm'] = request_parameters.get(
        'otp_algorithm',
        'HMAC-SHA1-TRUNC-6DIGITS'
        )
    request_parameters['shared_secret_delivery_method'] = request_parameters.get(
        'shared_secret_delivery_method',
        'HTTPS'
        )
    request_parameters['manufacturer'] = request_parameters.get(
        'manufacturer',
        'Apple Inc.'
        )
    request_parameters['serial'] = request_parameters.get(
        'serial',
        ''.join([random.choice(string.digits + string.ascii_uppercase)
            for x in range(0, 12)]
            )
        )
    request_parameters['model'] = request_parameters.get(
        'model',
        'MacBookPro%d,%d' % (random.randint(1, 12), random.randint(1, 4))
        )
    request_parameters['app_handle'] = request_parameters.get(
        'app_handle',
        'iMac010200'
        )
    request_parameters['client_id_type'] = request_parameters.get(
        'client_id_type',
        'BOARDID'
        )
    request_parameters['client_id'] = request_parameters.get(
        'client_id',
        'Mac-' + ''.join([random.choice('0123456789ABCDEF')
            for x in range(0, 16)]
            )
        )
    request_parameters['dist_channel'] = request_parameters.get(
        'dist_channel',
        'Symantec'
        )
    request_parameters['platform'] = request_parameters.get(
        'platform',
        'iMac'
        )
    request_parameters['os'] = request_parameters.get(
        'os',
        request_parameters['model']
        )

    data_before_hmac = u'%(timestamp)d%(timestamp)d%(client_id_type)s%(client_id)s%(dist_channel)s' % request_parameters
    request_parameters['data'] = base64.b64encode(
        hmac.new(
            HMAC_KEY,
            data_before_hmac.encode('utf-8'),
            hashlib.sha256
            ).digest()
        ).decode('utf-8')

    return REQUEST_TEMPLATE % request_parameters

def get_token_from_response(response_xml):
    '''Retrieve relevant token details from Symantec's provisioning
    response.'''
    # Define an arbitrary namespace "vipservice" because xpath doesn't like it
    # when it's "None"
    namespace = {'vipservice':'http://www.verisign.com/2006/08/vipservice'}

    tree = etree.fromstring(response_xml)
    result = tree.xpath(
        '//vipservice:Status/vipservice:StatusMessage',
        namespaces=namespace
        )[0].text

    if result == 'Success':
        token = {}
        container = tree.xpath(
            '//vipservice:SecretContainer',
            namespaces=namespace
            )[0]
        encryption_method = container.xpath(
            '//vipservice:EncryptionMethod',
            namespaces=namespace
            )[0]
        token['salt'] = base64.b64decode(
            encryption_method.xpath('//vipservice:PBESalt',
                namespaces=namespace
                )[0].text
            )
        token['iteration_count'] = int(
            encryption_method.xpath(
                '//vipservice:PBEIterationCount',
                namespaces=namespace
                )[0].text
            )
        token['iv'] = base64.b64decode(
            encryption_method.xpath(
                '//vipservice:IV',
                namespaces=namespace
                )[0].text
            )

        device = container.xpath('//vipservice:Device', namespaces=namespace)[0]
        secret = device.xpath('//vipservice:Secret', namespaces=namespace)[0]
        data = secret.xpath('//vipservice:Data', namespaces=namespace)[0]
        token['id'] = secret.attrib['Id']
        token['cipher'] = base64.b64decode(
            data.xpath(
                '//vipservice:Cipher',
                namespaces=namespace
                )[0].text
            )
        token['digest'] = base64.b64decode(
            data.xpath(
                '//vipservice:Digest',
                namespaces=namespace
                )[0].text
            )

        return token

def decrypt_key(token_iv, token_cipher):
    '''Decrypt the OTP key using the hardcoded AES key.'''
    decryptor = AES.new(TOKEN_ENCRYPTION_KEY, AES.MODE_CBC, token_iv)
    decrypted = decryptor.decrypt(token_cipher)

    # "decrypted" has PKCS#7 padding on it, so we need to remove that
    if type(decrypted[-1]) != int:
        num_bytes = ord(decrypted[-1])
    else:
        num_bytes = decrypted[-1]
    otp_key = decrypted[:-num_bytes]

    return otp_key

def generate_otp_uri(token_id, secret):
    '''Generate the OTP URI.'''
    token_parameters = {}
    token_parameters['otp_type'] = urllib.quote('totp')
    token_parameters['app_name'] = urllib.quote('VIP Access')
    token_parameters['account_name'] = urllib.quote(token_id)
    token_parameters['parameters'] = urllib.urlencode(
        dict(
            secret=base64.b32encode(secret).upper(),
            issuer='Symantec'
            )
        )

    return 'otpauth://%(otp_type)s/%(app_name)s:%(account_name)s?%(parameters)s' % token_parameters

def generate_qr_code(uri):
    '''Generate a QR code from the OTP URI.'''
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4
        )
    qr.add_data(uri)
    qr.make(fit=True)
    im = qr.make_image()
    return im

def check_token(token_id, secret):
    '''Check the validity of the generated token.'''
    otp = totp(binascii.b2a_hex(secret).decode('utf-8'))
    test_url = 'https://idprotect.vip.symantec.com/testtoken.v'
    token_check = requests.post(
        test_url,
        data=dict(
            tokenID=token_id,
            firstOTP=otp
            )
        )
    if "Your credential is functioning properly and is ready for use" in token_check.text:
        return True
    else:
        return False

def main():
    request = generate_request()

    response = requests.post(PROVISIONING_URL, data=request)

    otp_token = get_token_from_response(response.content)

    otp_secret = decrypt_key(otp_token['iv'], otp_token['cipher'])

    if not check_token(otp_token['id'], otp_secret):
        sys.stderr.write("Something went wrong--the token is invalid.\n")
        sys.exit(1)

    otp_uri = generate_otp_uri(otp_token['id'], otp_secret)
    print(otp_uri)

    image = generate_qr_code(otp_uri)
    image.show()

    return True
