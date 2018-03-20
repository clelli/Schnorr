#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Dec 14 17:53:27 2017

@author: chiara
"""

# %% import

from hashlib import sha256
from base58 import b58decode_check, __chars as b58digits
from secp256k1 import pointAdd, pointMultiply, \
                      order as ec_order, prime as ec_prime, G as ec_G, \
                      a as ec_a, b as ec_b
from FiniteFields import modInv, modular_sqrt
from string import hexdigits
from ec_signature import decode_prv,int_to_bytes, hash_to_int, decode_msg, \
                         ec_x_to_y, ecssa_verify, ecssa_verify_raw, \
                         ec_point_to_bytes, ecssa_recover
# %% combined public key
prv1 = decode_prv('0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d92ad1d')
prv2 = decode_prv('0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d')

# Inputs
Q1 = pointMultiply(prv1, ec_G)
Q2 = pointMultiply(prv2, ec_G)

# Steps
HQ1 = hash_to_int(sha256(ec_point_to_bytes(Q1, False)))
HQ2 = hash_to_int(sha256(ec_point_to_bytes(Q2, False)))
Q_All = pointAdd(pointMultiply(HQ1, Q1), pointMultiply(HQ2, Q2))

# stage 1
msg = '9788fd27b3aafd1bd1591a1158ce2d8bdc37ab4040dddb64e64d17616e69ce2b'
msg = decode_msg(msg)
m = sha256(msg).digest()

eph_prv1 = 0x012a2a833eac4e67e06611aba01345b85cdd4f5ad44f72e369ef0dd640424dbb
eph_prv2 = 0x01a2a0d3eac4e67e06611aba01345b85cdd4f5ad44f72e369ef0dd640424dbdb

## Steps
R1 = pointMultiply(eph_prv1, ec_G)
if R1[1] % 2 == 1: #must be even
    eph_prv1 = ec_order - eph_prv1 
    R1 = pointMultiply(eph_prv1, ec_G)
R1_x = R1[0]

R2 = pointMultiply(eph_prv2, ec_G)
if R2[1] % 2 == 1: #must be even
    eph_prv2 = ec_order - eph_prv2
    R2 = pointMultiply(eph_prv2, ec_G)
R2_x = R2[0]


## stage 2

## steps
prv1 = HQ1* prv1
prv2 = HQ2* prv2


R2_y_recovered = ec_x_to_y(R2_x, 0)   
R2_recovered = (R2_x, R2_y_recovered)
R1_All = pointAdd(R1, R2_recovered)

if R1_All[1] % 2 == 1:      # must be even
    eph_prv1 = ec_order - eph_prv1
R1_All_x = int_to_bytes(R1_All[0], 32)

e1 = hash_to_int(sha256(R1_All_x + m))
assert e1 != 0 and e1 < ec_order, "sign fail"
s1 = (eph_prv1 - e1 * prv1) % ec_order


R1_y_recovered = ec_x_to_y(R1_x, 0)
R1_recovered = (R1_x, R1_y_recovered)
R2_All = pointAdd(R2, R1_recovered)

if R2_All[1] % 2 == 1:
    eph_prv2 = ec_order - eph_prv2
R2_All_x = int_to_bytes(R2_All[0], 32)

e2 = hash_to_int(sha256(R2_All_x + m))
assert e2 != 0 and e2 < ec_order, "sign fail"
s2 = (eph_prv2 - e2 * prv2) % ec_order

## combine stage 2 signatures into a full signature

assert R1_All_x == R2_All_x, "sign fail"
R_All_x = R1_All[0]
s_All = (s1 + s2) % ec_order
ssasig = (R_All_x, s_All)


#verification
v = ecssa_verify(msg, ssasig, Q_All, hasher = sha256)
print(v)
