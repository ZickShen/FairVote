#!/usr/bin python3
import requests
from Crypto.Util.number import bytes_to_long, getPrime
import Crypto.Random.random as random
from hashlib import sha256
from gmpy2 import gcd, invert
from json import loads, dumps
import uuid
from PyInquirer import prompt, print_json
from ctypes import cdll
from ctypes import c_char_p
from ctypes import *

class go_string(Structure):
    _fields_ = [
        ("p", c_char_p),
        ("n", c_int)]

def main():
    libencrypt = cdll.LoadLibrary("../target/release/libencrypt.so")
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
    voted = False
    while not voted:
        candidates = prompt(questions)
        confirm = [
            {
                'type': 'list',
                'name': 'confirm',
                'message': 'There are condidate(s) you\'ve choosen: {}.\nDid you choose right?'.format(" ".join(candidates["candidates"])),
                'choices': [
                    "yes",
                    "no",
                ],
            }
        ]
        confirm = prompt(confirm)
        voted = confirm["confirm"] == "yes"
    m = dumps(candidates)
    m_bytes = m.encode()

    response = session.get('{}/sign_public_key'.format(address))
    pubkey = loads(response.text)
    N = int(pubkey["n"])
    e = int(pubkey["e"])
    response = session.post('{}/api/auth/register'.format(address), json={"username": str(uuid.uuid1()), "password": "1testt"})

    response = session.get('{}/encrypt_public_key'.format(address))
    encpubkey = response.text.encode()
    result = libencrypt.encrypt(c_char_p(encpubkey), c_char_p(m_bytes))
    m_bytes = cast(result, c_char_p).value
    m = m_bytes.decode('utf-8')

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
            * bytes_to_long(sha256(m_bytes).digest()) #h(m) 
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
        * bytes_to_long(sha256(m_bytes).digest())
        * bytes_to_long(sha256(m_bytes).digest()) 
        * pow(r*r_p, 2 * e - 2, N) 
        * ((c*c + 1) ** 2)) % N
    response = session.post('{}/verify'.format(address), json={"a": "2020-11-28","c": str(c), "s": str(s), "m": m})
    with open("tmp", "w") as f:
        f.write(dumps({"a": "2020-11-28","c": str(c), "s": str(s), "m": m}))
    print(response)
    print(response.text)
    # print("s^e={}".format(pow(s, e, N)))
    # print("h(a)h(m)^2(c^2+1)^2={}".format(
    #     bytes_to_long(sha256(a).digest())
    #     * (bytes_to_long(sha256(m_bytes).digest()) ** 2)
    #     * ((c ** 2 + 1) ** 2)
    #     % N))
    vote_agent = cdll.LoadLibrary("./vote-agent.so")
    vote_agent.Vote.argtyps = [go_string, go_string, go_string]
    vote_agent.Vote.restype = None
    config = go_string(c_char_p(b'./config.toml'), len('./config.toml'))
    service = go_string(c_char_p(b'echo'), 4)
    signature = go_string(c_char_p(b'tmp'), 3)
    vote_agent.Vote(config, service, signature)

if __name__ == "__main__":
    main()