#!/usr/bin/env python3
#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

import argparse
import sys
from os import path
from cbor2 import loads
import base64
import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM

msg_type_dict = {
    1: 'Device identity message v1',
    2: 'Public key message v1',
    3: 'CSR message v1',
    5: 'Provisioning response v1'
}
device_type_dict = {
    1: 'nRF9160 SIAA',
    2: 'nRF9160 SIBA',
    3: 'NRF9160 SIAA'
}

def parse_args():
    parser = argparse.ArgumentParser(description="CSR parser")
    parser.add_argument("-d", "--data", type=str, help="base64 string: CSR or attestation token", default="")
    args = parser.parse_args()
    return args

def base64_decode(string):
    """
    add padding before decoding.
    """
    padding = 4 - (len(string) % 4)
    string = string + ("=" * padding)
    return base64.urlsafe_b64decode(string)

def main():

    if not len(sys.argv) > 1:
        raise RuntimeError('No input provided')

    args = parse_args()
    if len(args.data) <= 0:
        raise RuntimeError("No CBOR data provided")

    body_cose = args.data.split('.')
    body = body_cose[0]

    cose = ""
    if len(body_cose) > 1:
        cose = body_cose[1]

    body_bytes = base64_decode(body)
    body_obj = loads(body_bytes)

    if len(cose):
        cose_bytes = base64_decode(cose)
        cose_obj = loads(cose_bytes)
        print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
        print("COSE:")
        print("      " + cose_obj.value[0].hex())
        print("      " + str(cose_obj.value[1]))
        print("      " + str(cose_obj.value[2]))
        print("      " + cose_obj.value[3].hex())

    print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
    print("Msg Type:    " + msg_type_dict[body_obj[0]])

    if body_obj[0] == 3:
        print("Device UUID: " + body_obj[1].hex())
        print("Key ID: " + body_obj[2].hex())

        csr_asn1 = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, body_obj[3])
        csr_pem_str = OpenSSL.crypto.dump_certificate_request(FILETYPE_PEM,csr_asn1)

        print("Full CSR:")
        csr_pem_list = str(csr_pem_str.decode()).split('\n')
        for line in csr_pem_list:
            print(line)

        print("Device public key:")
        pub_key_str = OpenSSL.crypto.dump_publickey(FILETYPE_PEM, csr_asn1.get_pubkey())
        print(pub_key_str.decode())

    elif body_obj[0] == 1:
        print("Device UUID: " + body_obj[1].hex())
        print("Device Type: " + device_type_dict[body_obj[2]])
        print("FW UUID:     " + body_obj[3].hex())

    print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")

if __name__ == '__main__':
    main()
