#!/usr/bin/env pyhton

import sys
import hmac
import time
import base64
import urllib
import hashlib

SECRET_KEY = "YOUR_SECRET_KEY"


def main(file_path):
    # expires in 15m
    expires = int(time.time()) + 60*15
    
    string_to_sign = 'GET\n{}\n{}'.format(expires, file_path)
    h = hmac.new(SECRET_KEY, string_to_sign, hashlib.sha256)
    sig = urllib.quote(base64.b64encode(h.digest()).strip())
    
    print "{file_path}?expires={expires}&signature={sig}".format(
        file_path=file_path, expires=expires, sig=sig
    )
    
if __name__ == "__main__":
    main(sys.argv[1])
