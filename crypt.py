import asn1tools
from eleptic import *
import string
from pygost.gost3410 import CURVE_PARAMS #p, q, a, b, x, y
from pygost.gost3412 import *
from pygost.utils import *
from random import randrange
from pygost.utils import *
import random
from pygost.gost34112012 import GOST34112012 as GostHash

cmd_scheme = asn1tools.compile_files('schemes/cmd_scheme.asn')
challenge_scheme = asn1tools.compile_files('schemes/challenge_scheme.asn')
gost_sign_file = asn1tools.compile_files('schemes/gost_sign.asn')
pub_key_scheme = asn1tools.compile_files('schemes/public_key_scheme.asn')
session_key_scheme = asn1tools.compile_files('schemes/session_scheme.asn')
cert_scheme = asn1tools.compile_files('schemes/cert_scheme.asn')
priv_key_scheme = asn1tools.compile_files('schemes/private_key_scheme.asn')


def RandomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def decode_string(res, length):
    vect = []
    for i in range(0, length):
        vect.append(chr(res % 256))
        res = res // 256
    return "".join(reversed(vect))

def EncryptGostOpen(chunk, curv, O):
	num = 0
	for i in chunk:
		num *= 256
		num += ord(i)
	k = randrange(1, curv.p-1)
	pk = curv.mult(k, curv.P)
	qk = curv.mult(k, O)
	l = (num*qk[0])%curv.p
	return pk,l

def DecryptGostOpen(curve, O, l, d):
    D = curve.mult(d, O)
    t = l*(invert(D[0],curve.p))%curve.p
    return t

def GenSign(curve, message, d, Q):
    hash_message = GostHash(message).digest()
    e = int.from_bytes(hash_message, "big", signed=False) % curve.q

    r = 0
    s = 0
    while r == 0 or s == 0:
        k = random.randrange(1, curve.q)
        C = curve.mult(k, curve.P)
        r = C[0] % curve.q
        s = (r*d + k*e) % curve.q


    sign = gost_sign_file.encode('GostSignFile', dict(keyset=
    {
        'key': dict
            (
            algid=b'\x80\x06\x07\x00',
            test='gostSignKey',
            keydata=dict
            (
                qx = Q[0],
                qy = Q[1]
            ),
            param=dict
                (
                fieldparam=dict
                (
                    prime=curve.p
                ),
                curveparam=dict
                    (
                    a=curve.a,
                    b=curve.b
                ),
                genparam=dict
                    (
                    px=curve.P[0],
                    py=curve.P[1]
                ),
                q=curve.q
            ),
            ciphertext=dict
            (
                r=r,
                s=s
            )
        )
    }, last={}))
    print("sign generated")
    return sign

def AuthSign(curve, message, sign_data, Q):
    sign_str = gost_sign_file.decode('GostSignFile', sign_data)
    r = sign_str['keyset']['key']['ciphertext']['r']
    s = sign_str['keyset']['key']['ciphertext']['s']

    if r > curve.q or s > curve.q:
        return False
    hash = GostHash(message).digest()
    e = int.from_bytes(hash, "big", signed=False) % curve.q
    if e == 0:
        e = 1


    v = invert(e, curve.q)
    z1 = (s*v) % curve.q
    z2 = (-r*v) % curve.q

    C = curve.add(curve.mult(z1, curve.P), curve.mult(z2, Q))

    if  C[0] % curve.q == r:
        print("sign true")
        return True
    else:
        print("sign false")
        return False



def EncryptGostSym(text, gost):
    if isinstance(text, str):
        text = text.encode()
    ans = b''
    for i in range(0, len(text), 16):
        st = text[i:i + 16]
        if len(st) < 16:
            st = st + b' ' * (16 - len(st))
        ans += gost.encrypt(st)
    return ans

def DecryptGostSym(encText, gost):
    ans = b''
    for i in range(0, len(encText), 16):
        st = encText[i:i + 16]
        ans += gost.decrypt(st)
    return ans.rstrip()