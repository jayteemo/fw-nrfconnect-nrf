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
import hashlib

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
payload_id_dict = {
    8: 'pubkey_msg_v2',
    9: 'CSR_msg_v1'
}
header_key_type_dict = {
    -7: 'ECDSA w/ SHA-256',
    -2: 'identity_key',
    -4: 'nordic_base_production_key',
    -5: 'nordic_base_rd_key'
}

payload_digest = ""

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

    # print protected header info
    phdr_obj = loads(cose_obj.value[0])
    for key in phdr_obj.keys():
        print("  Prot Hdr:   " + str(key) + " : " +
              str(phdr_obj[key]) + " (" +
              header_key_type_dict.get(phdr_obj[key]) + ")")

    # the unprotected header contains a map (and another cose object)
    for key in cose_obj.value[1].keys():
        unphdr_obj = loads(cose_obj.value[1].get(key))
        print("  Unprot Hdr: " + str(key)  + " : " +
              str(unphdr_obj) + " (" +
              header_key_type_dict.get(unphdr_obj) + ")")

    # The COSE payload may contain a cbor attestation payload
    # If present, decode the cbor and print
    print("  ---------------")
    print("  Attestation:")
    if str(cose_obj.value[2]) != "None":
        attest_obj = loads(cose_obj.value[2])
        print("    Payload ID: " + payload_id_dict.get(attest_obj[0]))
        print("    Dev. UUID:  " + attest_obj[1].hex())
        # Print the sec_tag byte as an integer
        print("    sec_tag:    " + str(attest_obj[2][0]))
        # SHA256 digest of cert/key in the payload
        print("    SHA256:     " + attest_obj[3].hex())
        print("    Nonce:      " + attest_obj[4].hex())
    else:
        print("    Not present")
    print("  ---------------")

    # Print the 64-bit signature
    print("  Sig:")
    print("      " + cose_obj.value[3].hex())

    if len(payload_digest) > 0:
        if attest_obj[3].hex() == payload_digest:
            print("\nCOSE digest matches payload")
        else:
            print("\nCOSE digest does NOT match payload")
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

    global payload_digest
    payload_digest = hashlib.sha256(body_bytes).hexdigest()
    print("SHA256 Digest:")
    print(payload_digest + "\n")

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
    print("Dev Type:    " + device_type_dict.get(body_obj[2]))
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
