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

def parse_args():
    parser = argparse.ArgumentParser(description="CSR parser")
    parser.add_argument("-c",	"--csr", type=str, help="base64 CSR string", default="")
    parser.add_argument("-s",	"--scsr", type=str, help="base64 CSR string with COSE signature", default="")
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

    csr = ""
    cose = ""

    if args.scsr:
        csr_cose = args.scsr.split('.')
        csr = csr_cose[0]
        cose = csr_cose[1]
    elif args.csr:
        csr = args.csr
    else:
        raise RuntimeError("No CBOR data provided")

    csr_bytes = base64_decode(csr)
    csr_obj = loads(csr_bytes)

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
    print("Msg Type:    " + msg_type_dict[csr_obj[0]])

    if csr_obj[0] == 3:
        print("Device UUID: " + csr_obj[1].hex())
        print("Modem Slot:  " + str(csr_obj[2]))

        csr_asn1 = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, csr_obj[3])
        csr_pem_str = OpenSSL.crypto.dump_certificate_request(FILETYPE_PEM,csr_asn1)

        print("Full CSR:")
        csr_pem_list = str(csr_pem_str.decode()).split('\n')
        for line in csr_pem_list:
            print(line)

        print("Device public key:")
        pub_key_str = OpenSSL.crypto.dump_publickey(FILETYPE_PEM, csr_asn1.get_pubkey())
        print(pub_key_str.decode())

    print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")

if __name__ == '__main__':
    main()
