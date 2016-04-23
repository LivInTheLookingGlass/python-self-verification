# coding=utf-8
from __future__ import division, absolute_import, print_function
from base64 import b64encode
from fractions import gcd
from random import randrange
from collections import namedtuple
from math import log
from binascii import hexlify, unhexlify
import sys


PY3 = sys.version_info[0] == 3
if PY3:
    binary_type = bytes
    range_func = range
else:
    binary_type = str
    range_func = xrange


def is_prime(n, k=30):
    # http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    if n <= 3:
        return n == 2 or n == 3
    neg_one = n - 1

    # write n-1 as 2^s*d where d is odd
    s, d = 0, neg_one
    while not d & 1:
        s, d = s + 1, d >> 1
    assert 2 ** s * d == neg_one and d & 1

    for _ in range_func(k):
        a = randrange(2, neg_one)
        x = pow(a, d, n)
        if x in (1, neg_one):
            continue
        for _ in range_func(s - 1):
            x = x ** 2 % n
            if x == 1:
                return False
            if x == neg_one:
                break
        else:
            return False
    return True


def randprime(n=10 ** 8):
    p = 1
    while not is_prime(p):
        p = randrange(n)
    return p


def multinv(modulus, value):
    """
        Multiplicative inverse in a given modulus

        >>> multinv(191, 138)
        18
        >>> multinv(191, 38)
        186
        >>> multinv(120, 23)
        47
    """
    # http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    x, lastx = 0, 1
    a, b = modulus, value
    while b:
        a, q, b = b, a // b, a % b
        x, lastx = lastx - q * x, x
    result = (1 - lastx * modulus) // value
    if result < 0:
        result += modulus
    assert 0 <= result < modulus and value * result % modulus == 1
    return result


KeyPair = namedtuple('KeyPair', 'public private')
Key = namedtuple('Key', 'exponent modulus')


def keygen(n, public=None):
    """ Generate public and private keys from primes up to N.

    Optionally, specify the public key exponent (65537 is popular choice).

        >>> pubkey, privkey = keygen(2**64)
        >>> msg = 123456789012345
        >>> coded = pow(msg, *pubkey)
        >>> plain = pow(coded, *privkey)
        >>> assert msg == plain

    """
    # http://en.wikipedia.org/wiki/RSA
    prime1 = randprime(n)
    prime2 = randprime(n)
    composite = prime1 * prime2
    totient = (prime1 - 1) * (prime2 - 1)
    if public is None:
        private = None
        while True:
            private = randrange(totient)
            if gcd(private, totient) == 1:
                break
        public = multinv(totient, private)
    else:
        private = multinv(totient, public)
    assert public * private % totient == gcd(public, totient) == gcd(private, totient) == 1
    assert pow(pow(1234567, public, composite), private, composite) == 1234567
    return KeyPair(Key(public, composite), Key(private, composite))


def encode(msg, pubkey, verbose=False):
    chunksize = int(log(pubkey.modulus, 256))
    outchunk = chunksize + 1
    outfmt = '%%0%dx' % (outchunk * 2,)
    bmsg = msg if isinstance(msg, binary_type) else msg.encode('utf-8')
    result = []
    for start in range_func(0, len(bmsg), chunksize):
        chunk = bmsg[start:start + chunksize]
        chunk += b'\x00' * (chunksize - len(chunk))
        plain = int(hexlify(chunk), 16)
        coded = pow(plain, *pubkey)
        bcoded = unhexlify((outfmt % coded).encode())
        if verbose:
            print('Encode:', chunksize, chunk, plain, coded, bcoded)
        result.append(bcoded)
    return b''.join(result)


def decode(bcipher, privkey, verbose=False):
    chunksize = int(log(privkey.modulus, 256))
    outchunk = chunksize + 1
    outfmt = '%%0%dx' % (chunksize * 2,)
    result = []
    for start in range_func(0, len(bcipher), outchunk):
        bcoded = bcipher[start: start + outchunk]
        coded = int(hexlify(bcoded), 16)
        plain = pow(coded, *privkey)
        chunk = unhexlify((outfmt % plain).encode())
        if verbose:
            print('Decode:', chunksize, chunk, plain, coded, bcoded)
        result.append(chunk)
    return b''.join(result).rstrip(b'\x00').decode('utf-8')


def key_to_str(key):
    """
    Convert `Key` to string representation
    >>> key_to_str(Key(50476910741469568741791652650587163073, 95419691922573224706255222482923256353))
    '25f97fd801214cdc163796f8a43289c1:47c92a08bc374e96c7af66eb141d7a21'
    """
    return ':'.join((('%%0%dx' % ((int(log(number, 256)) + 1) * 2)) % number) for number in key)


def str_to_key(key_str):
    """
    Convert string representation to `Key` (assuming valid input)
    >>> (str_to_key('25f97fd801214cdc163796f8a43289c1:47c92a08bc374e96c7af66eb141d7a21') ==
    ...  Key(exponent=50476910741469568741791652650587163073, modulus=95419691922573224706255222482923256353))
    True
    """
    return Key(*(int(number, 16) for number in key_str.split(':')))


def sign(msg, privkey):
	import hashlib
	h = hashlib.new('sha512')
	h.update(msg)
	checksum = h.hexdigest()
	return encode(checksum, privkey)


def verify(msg, sig, pubkey):
	import hashlib
	h = hashlib.new('sha512')
	h.update(msg)
	checksum = h.hexdigest()
	return decode(sig, pubkey) == checksum
	return False


def verify_integrity():
	f = open(__file__, "rb")
	text = f.read()
	f.close()
	text = 'signature = '.join(text.split('signature = ')[0:3])
	return verify(text, signature, str_to_key(pubkey))


hashes = {	"MD5": 'e762b5b0dd4379e664691d7317654e32',
		  	"SHA1": '5b5c14b69a7f2440091e6cdcd2c4214717f3b388',
		  	"SHA224": '3ac610612a0a6f2341066125c72f1c113386ce990ad8835d5b722263',
		  	"SHA256": 'f7c22306649c354ceec972febdf5cf85a4d6012432c3af2f5887db049ac3de79',
		  	"SHA384": '24534cb5e9cf3660349f9d56a17c08b07ecf65a99220a6401c79120bb3307169959781adb5424813f43bab4394e1d165',
		  	"SHA512": '3538d6b73aaf50669406d578e9163aafc2ca468bcfece62bcbb9a1cd8744ff7ad9ef8408b59dc2664bf8d8052a95ee705d286f80ef15162ff59933845d2616db'}

pubkey = '633a7d5db9a6af9893043ac9371f8c8007ec523480724ecdfe5810a144d81d884fe41a911068744e71e00de710a402ed7a6e9284e42e94c34e82747a0cb6f3a9:64d7229d26a83da2470e83450ecb2ba52ba0a2370c459332feac135a3bc8fba513cda66cbd8b0d10e39d1f50792222341d5b591b9b6ef5ca966bedde6d02a267'
signature = 'F\xef{\xab\x06\xd4\x94\xa9\x98\xbe\x08J\xc82!\x90J\x08\xe92\xa8h\xe9XC\xdf\x9b\xb6#\xdd\x9a*;\xfa\xc5\x8eXj\x94\x19\xfbFa+\x82\xc0\xa0hxx\x82U\xce\xea\xbd\xa0:5\xe0\xee\x8a\xe54\xcb\x13m\x13\n\xebT[\x9c\xa1\xf9\xbd\xc4\xe29\x1eix\x02\x13\x88\x97\x95\xafB(<\x8a\x07\xca\xb1\xff\'\xeb\xect\x1d\xa6/\xe3\xaa\x116\xc4\xb3\xf4\xdaU\x87Z\x0c\xab\\\x08\x9c\xbegD$>\xc60o.\xdaV\xa3\x8e"2\xf8\n\xde\x1e;\x01$\xd0\x8b\xf2\xe7\xa1\xd7*\xfee\xb6\xd1FI\x98f\xc7\xab\x00\xf5\xf7\xfa\x1b\xb2\xcf;@\x1a]\x86\xd3\xa5\x07\x89\xe96\x13\x0cek$\x95w\x9b\xb41\xc8]\xaa\xaf\r\x01\x88'
privkey = '4b2e0a0367c699c3c767f8089e7db2fee6b320cfcde7a130f5500c3eba47a9afe4f9a588c764c4ad96aabae9191c7136f06d9b1748a16714b39ec7c9eeec0559:64d7229d26a83da2470e83450ecb2ba52ba0a2370c459332feac135a3bc8fba513cda66cbd8b0d10e39d1f50792222341d5b591b9b6ef5ca966bedde6d02a267'
