#!/usr/bin python3
import requests
from Crypto.Util.number import bytes_to_long, getPrime
import Crypto.Random.random as random
from hashlib import sha256
from gmpy2 import gcd, invert
from json import loads, dumps
import uuid
from PyInquirer import prompt, print_json

def main():
    session = requests.Session()
    questions = [
        {
            'type': 'input',
            'name': 'address',
            'message': 'Where is server?',
        }
    ]
    address = prompt(questions)["address"]

    response = session.get('{}/ballot'.format(address))
    ballot = loads(response.text)
    print(ballot)
    m = b"test message"
    if ballot["multiple"]:
        questions = [
            {
                'type': 'checkbox',
                'name': 'candidates',
                'message': 'vote candidates',
                'choices': [
                    (lambda x: {'name': x})(x) for x in ballot['candidates']['candidates']
                ],
            }
        ]
    else:
        questions = [
            {
                'type': 'list',
                'name': 'candidates',
                'message': 'choose who you want to vote',
                'choices': [
                    x for x in ballot['candidates']['candidates']
                ],
            },
        ]
    candidates = prompt(questions)
    m = dumps(candidates).encode()

    response = session.get('{}/public_key'.format(address))
    pubkey = loads(response.text)
    N = int(pubkey["n"])
    e = int(pubkey["e"])
    response = session.post('{}/api/auth/register'.format(address), json={"username": str(uuid.uuid1()), "password": "1testt"})

    a = b"2020-11-28"
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
    response = session.post('{}/api/auth/pre_sign'.format(address), json={"a": "2020-11-28", "alpha": str(alpha)})
    x = int(loads(response.text)["x"])
    beta = (pow(r, e, N) * (u - x)) % N
    response = session.post('{}/api/auth/sign'.format(address), json={"a": "2020-11-28", "alpha": str(alpha), "beta": str(beta)})
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
    response = session.post('{}/verify'.format(address), json={"a": "2020-11-28","c": str(c), "s": str(s), "m": m})
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