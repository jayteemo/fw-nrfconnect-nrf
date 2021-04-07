CSR Parse Example

```
usage: csr_parse.py [-h] [-k KEYGEN] [-a ATTEST]

CSR parser

optional arguments:
  -h, --help            show this help message and exit
  -k KEYGEN, --keygen KEYGEN
                        base64url string: KEYGEN output
  -a ATTEST, --attest ATTEST
                        base64url string: ATTESTTOKEN output
```

Parse modem keygen output; with or without COSE portion.
`python3 csr_parse.py -k <base64url AT%KEYGEN output>`

Parse modem attestation token output; with or without COSE portion.
`python3 csr_parse.py -a <base64url AT%ATTESTTOKEN output>`

