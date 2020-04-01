#!/usr/bin python3
import requests
from Crypto.Util.number import bytes_to_long, getPrime
import Crypto.Random.random as random
from hashlib import sha256
from gmpy2 import gcd, invert
from json import loads
import uuid

def main():
    session = requests.Session()

    response = session.get('http://192.168.16.128:8000/public_key')
    pubkey = loads(response.text)
    N = int(pubkey["n"])
    e = int(pubkey["e"])
    response = session.post('http://192.168.16.128:8000/api/auth/register', json={"username": str(uuid.uuid1()), "password": "1testt"})

    a = b"2020-11-28"
    m = b"test message"
    r = N
    while gcd(r, N) != 1 :
        r = random.randint(1, N)
    r_p = N
    while gcd(r_p, N) != 1 :
        r_p = random.randint(1, N)
    u = N
    while gcd(u, N) != 1 :
        u = random.randint(1, N)
    alpha = (pow(((r**3)*r_p),e, N) # (r^3r')^e
            * bytes_to_long(sha256(m).digest()) #h(m) 
            * (u**2 + 1)) % N
    response = session.post('http://192.168.16.128:8000/api/auth/pre_sign', json={"a": "2020-11-28", "alpha": str(alpha)})
    x = int(loads(response.text)["x"])
    beta = (pow(r, e, N) * (u - x)) % N
    response = session.post('http://192.168.16.128:8000/api/auth/sign', json={"a": "2020-11-28", "alpha": str(alpha), "beta": str(beta)})
    sig = loads(response.text)
    beta_ = int(sig["beta_invert"])
    T = int(sig["t"])
    c = ((u * x + 1) * invert(u-x, N)) % N
    s = (T 
        * bytes_to_long(sha256(a).digest()) 
        * bytes_to_long(sha256(m).digest())
        * bytes_to_long(sha256(m).digest()) 
        * pow(r*r_p, 2 * e - 2, N) 
        * ((c*c + 1) ** 2)) % N
    response = session.post('http://192.168.16.128:8000/verify', json={"a": "2020-11-28","c": str(c), "s": str(s), "m": "test message"})
    print(response)
    print(response.text)
    print("s^e={}".format(pow(s, e, N)))
    print("h(a)h(m)^2(c^2+1)^2={}".format(
        bytes_to_long(sha256(a).digest())
        * (bytes_to_long(sha256(m).digest()) ** 2)
        * ((c ** 2 + 1) ** 2)
        % N))

if __name__ == "__main__":
    main()