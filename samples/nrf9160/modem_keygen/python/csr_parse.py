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
    parser.add_argument("-k", "--keygen", type=str, help="base64url string: KEYGEN output", default="")
    parser.add_argument("-a", "--attest", type=str, help="base64url string: ATTESTTOKEN output", default="")
    args = parser.parse_args()
    return args

def base64_decode(string):
    """
    add padding before decoding.
    """
    padding = 4 - (len(string) % 4)
    string = string + ("=" * padding)
    return base64.urlsafe_b64decode(string)

def parse_cose(cose_str):
    """
    parse COSE payload.
    """
    if len(cose_str) == 0:
        return

    # Decode to binary and parse cbor
    cose_bytes = base64_decode(cose_str)
    cose_obj = loads(cose_bytes)

    print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
    print("COSE:")
    # TODO: not sure what this first value is
    print("  Value: " + cose_obj.value[0].hex())

    # the unprotected header contains a map, where 4 indicates the key id
    key_id = False
    for key in cose_obj.value[1].keys():
        if key == 4:
            key_id = True
            break

    # Print key id value if found, otherwise just print the map
    if key_id:
        print("  Key ID: " + "0x" + cose_obj.value[1][4].hex())
    else:
        print("  " + str(cose_obj.value[1]))

    # The COSE payload may contain a cbor attestation payload
    # If present, decode the cbor and print
    print("  ---------------")
    print("  Attestation:")
    if str(cose_obj.value[2]) != "None":
        attest_obj = loads(cose_obj.value[2])
        # TODO: not sure what the first value is
        print("    ???:        " + str(attest_obj[0]))
        print("    Dev. UUID:  " + attest_obj[1].hex())
        print("    sec_tag:    " + "0x" + attest_obj[2].hex())
        # TODO: Not sure what the 32 and 16 byte payloads are...
        #       Hash/signatures of something
        print("    32 bytes:   " + attest_obj[3].hex())
        print("    16 bytes:   " + attest_obj[4].hex())
    else:
        print("    Not present")
    print("  ---------------")

    # Print the 64-bit signature
    print("  Sig:")
    print("      " + cose_obj.value[3].hex())
    print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")

    return

def parse_keygen_output(keygen_str):
    """
    parse keygen output.
    """
    print("\nParsing AT%KEYGEN output:\n")

    # Input format: <base64url_body>.<base64url_cose>
    #               cose portion is optional
    body_cose = keygen_str.split('.')
    body = body_cose[0]

    # Decode base64url to binary
    body_bytes = base64_decode(body)

    # This can be either a CSR or device public key
    try:
        # Try to load CSR, if it fails, assume public key
        csr_asn1 = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, body_bytes)

    except OpenSSL.crypto.Error:
        # Handle public key only
        pub_key = OpenSSL.crypto.load_publickey(OpenSSL.crypto.FILETYPE_ASN1,body_bytes)
        pub_key_str = OpenSSL.crypto.dump_publickey(FILETYPE_PEM, pub_key)

    else:
        # CSR loaded, print it
        csr_pem_str = OpenSSL.crypto.dump_certificate_request(FILETYPE_PEM,csr_asn1)
        csr_pem_list = str(csr_pem_str.decode()).split('\n')
        for line in csr_pem_list:
            print(line)

        # Extract public key
        pub_key_str = OpenSSL.crypto.dump_publickey(FILETYPE_PEM, csr_asn1.get_pubkey())

    print("Device public key:")
    print(pub_key_str.decode())

    # Get optional cose
    cose = ""
    if len(body_cose) > 1:
        cose = body_cose[1]

    parse_cose(cose)

    return

def parse_attesttoken_output(atokout_str):
    print("\nParsing AT%ATTESTTOKEN output:\n")

    # Input format: <base64url_body>.<base64url_cose>
    #               cose portion is optional
    body_cose = atokout_str.split('.')
    body = body_cose[0]

    # Decode base64url to binary
    body_bytes = base64_decode(body)
    # Load into CBOR parser
    body_obj = loads(body_bytes)

    # Print parsed CBOR
    print("---------------")
    print("Msg Type:    " + msg_type_dict[body_obj[0]])
    print("Dev UUID:    " + body_obj[1].hex())
    print("Dev Type:    " + device_type_dict[body_obj[2]])
    print("FW UUID:     " + body_obj[3].hex())
    print("---------------")

    # Get optional cose
    cose = ""
    if len(body_cose) > 1:
        cose = body_cose[1]

    parse_cose(cose)

    return

def main():

    if not len(sys.argv) > 1:
        raise RuntimeError('No input provided')

    args = parse_args()
    if len(args.keygen) > 0:
        parse_keygen_output(args.keygen)
    elif len(args.attest) > 0:
        parse_attesttoken_output(args.attest)
    else:
        raise RuntimeError("No input data provided")

    return

if __name__ == '__main__':
    main()
