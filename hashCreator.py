#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# hashCreator - Creates Hashes for the Login Process on Dahua devices over the DVRIP or Dahua Private Protocol 
# Copyright (C) 2020  Thomas Vogt
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# ***************
# Important Note:
# This code is mainly based and copyied from Bashis code on https://github.com/mcw0/Tools
# ***************

import binascii
import time
import bitarray
from bitarray.util import *


import sys
import json
import ndjson	# pip3 install ndjson
import argparse
import copy
import _thread	
import hashlib
import inspect

from OpenSSL import crypto # pip3 install pyopenssl
from pwn import *	# https://github.com/Gallopsled/pwntools



################# code import from mscw
# From: https://github.com/haicen/DahuaHashCreator/blob/master/DahuaHash.py
def compressor(in_var, out):
    i=0
    j=0
	
    while i<len(in_var):
        # python 2.x (thanks to @davidak501)
        # out[j] = (ord(in_var[i]) + ord(in_var[i+1])) % 62;
        # python 3.x
        out[j] = (in_var[i] + in_var[i+1]) % 62
        if (out[j] < 10):
            out[j] += 48
        elif (out[j] < 36):
            out[j] += 55
        else:
            out[j] += 61        
        i=i+2
        j=j+1



def Dahua_Gen1_hash(passw):
#	if len(passw)>6:
#		debug("Warning: password is more than 6 characters. Hash may be incorrect")
	m = hashlib.md5()
	m.update(passw.encode("latin-1"))
	
	s=m.digest()
	crypt=[]
	for b in s:
		crypt.append(b)
	out2=['']*8
	compressor(crypt,out2)
	data=''.join([chr(a) for a in out2])
	return data

# Dahua DVRIP random MD5 password hash
#
def Dahua_DVRIP_md5_hash(Dahua_random, username, password):
	RANDOM_HASH = hashlib.md5((username + ':' + Dahua_random + ':' + Dahua_Gen1_hash(password)).encode('latin-1')).hexdigest().upper()
	return RANDOM_HASH

#
# Dahua random MD5 password hash
#
def Dahua_Gen2_md5_hash(Dahua_random, Dahua_realm, username, password):
	PWDDB_HASH = hashlib.md5((username + ':' + Dahua_realm + ':' + password).encode('latin-1')).hexdigest().upper()
	PASS = (username + ':' + Dahua_random + ':' + PWDDB_HASH).encode('latin-1')
	RANDOM_HASH = hashlib.md5(PASS).hexdigest().upper()
	return RANDOM_HASH

################# end of code import from mscw

import codecs

def calculate_hash_callback(mytmpPayload, username, password):
    print("in-calculcate-hash")
    print("mytmpPayload: ")
    print(mytmpPayload)

    mytmpPayload = mytmpPayload.decode("utf-8")
    #b = bytearray()
    #b.extend(map(ord,mytmpPayload))
    #tmpdata = bitarray.bitarray(mytmpPayload).to01()
    #print(mytmpPayload)
    #mytmpPayload = bitarray.bitarray(tmpdata).tobytes().decode('utf-8)')
    #mytmpPayload = b
    #Payload = binascii.a2b_hex(mytmpPayload(:))
    #mytmpPayload = Payload
    REALM = mytmpPayload.split('\r\n')[0].split(':')[1] if mytmpPayload.split('\r\n')[0].split(':')[0] == 'Realm' else False
    RANDOM = mytmpPayload.split('\r\n')[1].split(':')[1] if mytmpPayload.split('\r\n')[1].split(':')[0] == 'Random' else False
    HASH = username + '&&' + Dahua_Gen2_md5_hash(RANDOM, REALM, username, password) + Dahua_DVRIP_md5_hash(RANDOM, username, password)
    myHash = HASH
    ba = bitarray.bitarray()
    ba.frombytes(myHash.encode('utf-8'))
    print("end-of-hash-calculation\n\n")
    return myHash
