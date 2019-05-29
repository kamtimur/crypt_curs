import asn1tools
import random
from pygost.gost34112012 import GOST34112012 as GostHash
from pygost.gost3410 import CURVE_PARAMS #p, q, a, b, x, y
from eleptic import *
#сгненрировать ключи УЦ
#сгненрировать сертификат УЦ самоподписанный
#сгненрировать ключи клиента
#сгненрировать сертификат клиента, подписанный УЦ

priv_key_scheme = asn1tools.compile_files('schemes/private_key_scheme.asn')
pub_key_scheme = asn1tools.compile_files('schemes/public_key_scheme.asn')
cert_scheme = asn1tools.compile_files('schemes/cert_scheme.asn')
gost_sign_file = asn1tools.compile_files('schemes/gost_sign.asn')

def GenSign(message,d,Q):
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

def GenCACert():
    d = random.randrange(1, curve.q)
    Q = curve.mult(d, curve.P)

    pub_key_data = pub_key_scheme.encode('PubKey', dict(keyset=
    {
        'key': dict
            (
            algid=b'\x80\x06\x07\x00',
            test='PubKey',
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
        )
    }, last={}))

    priv_key_data = priv_key_scheme.encode('PrivKey', dict(keyset=
    {
        'key': dict
            (
            algid=b'\x80\x06\x07\x00',
            test='PrivKey',
            keydata=dict
            (
                d = d,
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
        )
    }, last={}))

    sign = GenSign(pub_key_data,d,Q)
    cert_data = cert_scheme.encode('Cert',
                                {
                                    'pub': pub_key_data,
                                    'capub': pub_key_data,
                                    'sign': sign
                                })
    cert_file = open('CA.crt', "wb")
    cert_file.write(cert_data)
    cert_file.close()

    priv_file = open('CA.priv', "wb")
    priv_file.write(priv_key_data)
    priv_file.close()

    pub_file = open('CA.pub', "wb")
    pub_file.write(pub_key_data)
    pub_file.close()

def GenCert(pub,CApub,sign):
    cert_data = cert_scheme.encode('Cert',
                                {
                                    'pub': pub,
                                    'capub': CApub,
                                    'sign': sign
                                })
    return cert_data


def GenCertAndKeysClient(client_name):
    d = random.randrange(1, curve.q)
    Q = curve.mult(d, curve.P)

    pub_key_data = pub_key_scheme.encode('PubKey', dict(keyset=
    {
        'key': dict
            (
            algid=b'\x80\x06\x07\x00',
            test='PubKey',
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
        )
    }, last={}))

    priv_key_data = priv_key_scheme.encode('PrivKey', dict(keyset=
    {
        'key': dict
            (
            algid=b'\x80\x06\x07\x00',
            test='PrivKey',
            keydata=dict
            (
                d = d,
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
        )
    }, last={}))

    #создать подпись сертификата с помощью закрытого ключа УЦ
    #получение закрытого ключа УЦ
    priv_key_CA_file = open('CA.priv', "rb")
    priv_key_CA_data = priv_key_CA_file.read()
    priv_key_CA_array= priv_key_scheme.decode('PrivKey', priv_key_CA_data)
    priv_key_CA = priv_key_CA_array['keyset']['key']['keydata']['d']
    # получение открытого ключа УЦ
    pub_key_CA_file = open('CA.pub', "rb")
    pub_key_CA_data = pub_key_CA_file.read()
    pub_key_CA_array= pub_key_scheme.decode('PubKey', pub_key_CA_data)
    pub_key_CA = (pub_key_CA_array['keyset']['key']['keydata']['qx'],pub_key_CA_array['keyset']['key']['keydata']['qy'])
    # pub_key_CA[0] = pub_key_CA_array['keyset']['key']['keydata']['qx']
    # pub_key_CA[1] = pub_key_CA_array['keyset']['key']['keydata']['qy']

    sign = GenSign(pub_key_data,priv_key_CA,pub_key_CA)

    cert_data = GenCert(pub_key_data,pub_key_CA_data,sign)

    cert_file = open(client_name+'.crt', "wb")
    cert_file.write(cert_data)
    cert_file.close()

    priv_file = open(client_name+'.priv', "wb")
    priv_file.write(priv_key_data)
    priv_file.close()

    pub_file = open(client_name+'.pub', "wb")
    pub_file.write(pub_key_data)
    pub_file.close()


curve_param = CURVE_PARAMS["GostR3410_2012_TC26_ParamSetA"]

curve = EllipticCurve(
    int.from_bytes(curve_param[0], "big"),
    int.from_bytes(curve_param[2], "big"),
    int.from_bytes(curve_param[3], "big"),
    (
        int.from_bytes(curve_param[4], "big"),
        int.from_bytes(curve_param[5], "big")
    ),
    int.from_bytes(curve_param[1], "big")
)


# GenCACert()
GenCertAndKeysClient('client2')