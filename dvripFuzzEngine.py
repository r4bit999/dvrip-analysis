#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# DVRIP Protocol Client and Fuzzing Eninge
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

import binascii
import bitarray
import json
import logging
import ndjson
import os
import socket
import struct # for hex conversion
import sys # for print without ln
import time

from hashCreator import calculate_hash_callback
from bitarray.util import *


# global tcp socket
s = socket
fuzzLength = 10
runmodul = ""

deskey = ""

# Class job: unit template of a DVRIP network packet
class DVRIP_PDU(object):
    b1_msg_type         = binascii.a2b_hex("a0050060")
    b2_pyaload_length   = bytes()
    b3_ID_msg_num       = bitarray.bitarray()
    b4_unknown_1        = bitarray.bitarray()
    b5_SessionID_RCV    = bitarray.bitarray()
    b6_unknown_2        = bitarray.bitarray()
    b7_SessionID_SEND   = bytes()
    b8_unknown_login4way_ID = bitarray.bitarray()
    b9_payload          = "dummy"

    # Initialization of new class instances
    def __init__(self, b1_msg_type, b2_pyaload_length, b3_ID_msg_num, b4_unknown_1, b5_SessionID_RCV, b6_unknown_2, b7_SessionID_SEND, b8_unknown_login4way_ID, b9_payload ):
        self.b1_msg_type = b1_msg_type
        self.b2_pyaload_length = b2_pyaload_length
        self.b3_ID_msg_num = b3_ID_msg_num
        self.b4_unknown_1 = b4_unknown_1
        self.b5_SessionID_RCV = b5_SessionID_RCV
        self.b6_unknown_2 = b6_unknown_2
        self.b7_SessionID_SEND = b7_SessionID_SEND
        self.b8_unknown_login4way_ID = b8_unknown_login4way_ID
        self.b9_payload = b9_payload

    # Function job: convert bytecode hex to binarystream
    def stream(self):     
        # Conditions: should handle empty payload field (block9)
     
        tmpPayload = "test"
        tmpPayload = self.b9_payload
        logging.debug(tmpPayload)
        logging.debug(self.b9_payload)
        logging.debug(type(self.b9_payload))

        if (self.b9_payload != b''):
            self.b9_payload = binascii.hexlify(tmpPayload.encode("utf8"))
            logging.debug("in-if")
        
        logging.debug("init-done")

        # here is the final join of the parameters before sending to the target
        tmpBinary = b'01010101010101010101010101010101'
        tmpBinary = b''.join([self.b1_msg_type, self.b2_pyaload_length, self.b3_ID_msg_num, self.b4_unknown_1,
        self.b5_SessionID_RCV, self.b6_unknown_2, self.b7_SessionID_SEND, self.b8_unknown_login4way_ID,
        self.b9_payload      ])

        logging.debug("\nstreamdata:")
        logging.debug(tmpBinary)

        my_bytes = binascii.a2b_hex(tmpBinary)

        logging.debug("end-of-stream()\n\n")
        return my_bytes

    # Function job: Converting ByteStream to P2P Object
    def toSymbol(self, my_bytes):
        self.b1_msg_type            = my_bytes[:4]
        self.b2_pyaload_length      = my_bytes[4:8]
        self.b3_ID_msg_num          = my_bytes[8:12]
        self.b4_unknown_1           = my_bytes[12:16]
        self.b5_SessionID_RCV       = my_bytes[16:20]
        self.b6_unknown_2           = my_bytes[20:24]
        self.b7_SessionID_SEND      = my_bytes[24:28]
        self.b8_unknown_login4way_ID    = my_bytes[28:32]
        self.b9_payload             = my_bytes[32:]

    # Function Job: Print current PDU block content
    def state(self):
        print("\nPrint current instance state:")
        print(self.b1_msg_type)
        print(self.b2_pyaload_length)
        print(self.b3_ID_msg_num)
        print(self.b4_unknown_1)
        print(self.b5_SessionID_RCV)
        print(self.b6_unknown_2)
        print(self.b7_SessionID_SEND)
        print(self.b8_unknown_login4way_ID)
        print(self.b9_payload)
        print("End of State()\n")

# Class which handels all fuzzing methods
class fuzzingEngine(object):
    # Manipulate DVRIP Packet for messageType fuzzing
    def setFuzzFieldsMsg1_fuzzing_msgType(self, currentPDU):
        #    b'c4a3af48', b'9956b6b4', # username
        #    b'6e6302f2', b'b792f12c', # password

        # login is is working from time to time

        '''
        19:14:59|[Manager] info tid:3244 si.loginType=0, si.clientAddress=192.168.178.60, si.clientType=Local si.authorityInfo= si.authorityType= si.passwordType=Plain                                               
        19:14:59|[Manager] info tid:3269 si.loginType=0, si.clientAddress=192.168.178.60, si.clientType=DVRIP si.authorityInfo= si.authorityType= si.passwordType=Plain                                               
        19:15:02|[Manager] info tid:3241 si.loginType=0, si.clientAddress=192.168.178.60, si.clientType=Local si.authorityInfo= si.authorityType= si.passwordType=Plain                                               
        19:15:02|[Manager] info tid:3239 si.loginType=0, si.clientAddress=192.168.178.60, si.clientType=Local si.authorityInfo= si.authorityType= si.passwordType=Plain 
        '''

        # Complete randomized 4 bytes
        b1_preFuzz                  = b'a0'
        fuzzy1                      = binascii.hexlify(os.urandom(3))
        currentPDU.b1_msg_type            = b''.join([b1_preFuzz, fuzzy1])        
        
        #currentPDU.b1_msg_type            = binascii.hexlify(os.urandom(4))
        #currentPDU.b2_pyaload_length      = payloadLength #b'04000000'
        currentPDU.b2_pyaload_length      = b'00000000'

        currentPDU.b3_ID_msg_num          = b'c4a3af48' #user
        currentPDU.b4_unknown_1           = b'9956b6b4' #user
        currentPDU.b5_SessionID_RCV       = b'6e6302f2' #pass
        currentPDU.b6_unknown_2           = b'b792f12c' #pass
        currentPDU.b7_SessionID_SEND      = binascii.hexlify(os.urandom(4))
        currentPDU.b8_unknown_login4way_ID    = binascii.hexlify(os.urandom(4))

        # payload length must be written in b2
        #currentPDU.b9_payload             = payload

        logging.debug(currentPDU.state())
        print("setFuzzFieldsMsg1_fuzzing_msgType")

    # Manipulate DVRIP Packet for Buffer Overflow detection
    def setFuzzFieldsMsg1_search_buffer_overflow(self, currentPDU):
            
        global fuzzLength
        payload = "A"*fuzzLength
        #print(payload)
        payloadLength = len(payload) #84 (int) => 54 in hex; hex(84):54 
        payloadLength = struct.pack("<I", payloadLength)
        payloadLength = binascii.hexlify(payloadLength)

        # 0e6909badf8d9e4a aabbccdd
        
        # Complete randomized 4 bytes
        b1_preFuzz                  = b'a0'
        fuzzy1                      = binascii.hexlify(os.urandom(3))
        currentPDU.b1_msg_type            = b''.join([b1_preFuzz, fuzzy1])        
        
        #self.b1_msg_type            = binascii.hexlify(os.urandom(4))
        currentPDU.b2_pyaload_length      = payloadLength #b'04000000'
        #self.b2_pyaload_length      = b'00000000'

        currentPDU.b3_ID_msg_num          = binascii.hexlify(os.urandom(4)) #user
        currentPDU.b4_unknown_1           = binascii.hexlify(os.urandom(4)) #user
        currentPDU.b5_SessionID_RCV       = binascii.hexlify(os.urandom(4)) #pass
        currentPDU.b6_unknown_2           = binascii.hexlify(os.urandom(4)) #pass
        currentPDU.b7_SessionID_SEND      = binascii.hexlify(os.urandom(4))
        currentPDU.b8_unknown_login4way_ID    = binascii.hexlify(os.urandom(4))

        # payload length must be written in b2
        currentPDU.b9_payload             = payload

        logging.debug(currentPDU.state())

        fuzzLength = fuzzLength * 2
        print(fuzzLength)

    # Msg1 all fields manipulation
    def setFuzzFieldsMsg1_fuzz_all_fields(self, currentPDU):
            


        # 0e6909badf8d9e4a aabbccdd
        
        # Complete randomized 4 bytes
    
        
        currentPDU.b1_msg_type            = binascii.hexlify(os.urandom(4))
        currentPDU.b2_pyaload_length      = b'00000000'

        currentPDU.b3_ID_msg_num          = binascii.hexlify(os.urandom(4)) #user
        currentPDU.b4_unknown_1           = binascii.hexlify(os.urandom(4)) #user
        currentPDU.b5_SessionID_RCV       = binascii.hexlify(os.urandom(4)) #pass
        currentPDU.b6_unknown_2           = binascii.hexlify(os.urandom(4)) #pass
        currentPDU.b7_SessionID_SEND      = binascii.hexlify(os.urandom(4))
        currentPDU.b8_unknown_login4way_ID    = binascii.hexlify(os.urandom(4))


        logging.debug(currentPDU.state())



    def setFuzzFieldsMsg1_DES_search(self, currentPDU):

        global deskey

        ### si.passwordType=Plain is not working but most of the time!!

        # Complete randomized 4 bytes
        b1_preFuzz                  = b'a0'
        fuzzy1                      = binascii.hexlify(os.urandom(3))
        currentPDU.b1_msg_type            = b''.join([b1_preFuzz, fuzzy1])        
        
        currentPDU.b2_pyaload_length      = b'00000000'

        currentPDU.b3_ID_msg_num          = deskey.encode()[:8] #user
        currentPDU.b4_unknown_1           = deskey.encode()[8:16] #user
        currentPDU.b5_SessionID_RCV       = binascii.hexlify(os.urandom(4)) #pass
        currentPDU.b6_unknown_2           = binascii.hexlify(os.urandom(4)) #pass
        currentPDU.b7_SessionID_SEND      = binascii.hexlify(os.urandom(4))
        currentPDU.b8_unknown_login4way_ID    = binascii.hexlify(os.urandom(4))

    # Function job: Set fuzz values for msg1 login4way process
    def setFuzzFieldsMsg1(self, currentPDU):
        global msg1FuzzState
        
        #fuzzModeMsg1 = "fuzz des decryption"
        runmodul = msg1FuzzState

        if runmodul == "fuzz login4way msg1 msgType":
            self.setFuzzFieldsMsg1_fuzzing_msgType(currentPDU)

        if runmodul == "fuzz login4way msg1 bof":
            self.setFuzzFieldsMsg1_search_buffer_overflow(currentPDU)

        if runmodul == "fuzz login4way msg1 allFields":
            self.setFuzzFieldsMsg1_fuzz_all_fields(currentPDU)

        if runmodul == "fuzz des decryption":
            self.setFuzzFieldsMsg1_DES_search(currentPDU)


    def setFuzzFieldsMsg2(self, currentPDU):
        ''' # we only want payload manipulation
        currentPDU.b1_msg_type                  = binascii.hexlify(os.urandom(4))
        currentPDU.b2_pyaload_length            = b'00000000'
        currentPDU.b3_ID_msg_num                = binascii.hexlify(os.urandom(4)) #user
        currentPDU.b4_unknown_1                 = binascii.hexlify(os.urandom(4)) #user
        currentPDU.b5_SessionID_RCV             = binascii.hexlify(os.urandom(4)) #pass
        currentPDU.b6_unknown_2                 = binascii.hexlify(os.urandom(4)) #pass
        currentPDU.b7_SessionID_SEND            = binascii.hexlify(os.urandom(4))
        currentPDU.b8_unknown_login4way_ID      = binascii.hexlify(os.urandom(4))
        '''
        print("manipulate payload done")

        global fuzzLength
        payload = "A"*fuzzLength
        payloadLength = len(payload) #84 (int) => 54 in hex; hex(84):54 
        payloadLength = struct.pack("<I", payloadLength)
        payloadLength = binascii.hexlify(payloadLength)

        currentPDU.b2_pyaload_length = payloadLength
        currentPDU.b9_payload = payload + currentPDU.b9_payload
        fuzzLength = fuzzLength *2
        logging.debug(currentPDU.state())



    # Function job: sending Commands over TCP-stream based authentication
    def setFuzzBinaryCommands(self, currentPDU, code):
        global s
        '''
        'a4000000'   | '00000000'     | '08000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | ''                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
        'b4000078'   | '11000000'     | '08000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | '2.800.0000004.0.R'   

        'a4000000'   | '00000000'     | '07000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | ''                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
        'b4000078'   | '0f000000'     | '07000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | '5C0726FPAGEC7C2'      

        'a4000000'   | '00000000'     | '0b000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | ''                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
        'b4000078'   | '0c000000'     | '0b000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | 'IPC-HFW1431S'   
        '''

        #payload = "A"*fuzzLength
        #print(payload)
        #code = len(payload) #84 (int) => 54 in hex; hex(84):54 
        code = struct.pack("<I", code)
        code = binascii.hexlify(code)

        currentPDU.b3_ID_msg_num          = code
        print("code is ", code)
        print("code2 is ", currentPDU.b3_ID_msg_num)

    ### <summary> console.runCmd memory address fuzzing
    ### <returns> loop fuzz request/response
    def doLoopFuzzRunCmd_search_memory(self, dvripSession, filelist):
        filepath = filelist
  
        counter1 = 1

        while True:

            time.sleep(0.1)

            api_argsFuzz = {
            "id":       dvripSession.sequenceID,
            "magic":    "0x1234",
            "method":   "console.runCmd",
            "params": {
                #"command": line.rstrip('\n')
                #"command": "memory -a '0x17" + binascii.hexlify(os.urandom(3)).decode() + "'"
                "command": "memory -a '0x" + binascii.hexlify(os.urandom(4)).decode() + "'"
            },
            "object":   dvripSession.objectID,
            "SID":      dvripSession.serviceID,
            "session":  dvripSession.sessionID,
            }

            data = json.dumps(api_argsFuzz)

            dvripSession.callJsanAPIFUZZ(data)

            logging.debug("next command fuzz payload")

    ### <summary> console.runCmd OS Injection and BoF detection
    ### <returns> loop fuzz request/response
    def doLoopFuzzRunCmd_OSInjection(self, dvripSession, filelist, injectionType):
        filepath = filelist

        ########### rund CMD c2ommand
        # telnet vulnhost2.local | tee -a test004
        # {"SID": 1, "id": 6, "magic": "0x1234", "method": "console.runCmd", 
        # "params": {"command": "user -u"}, "object": 19551576, "session": 397305870}' 
  
        counter1 = 1
        #filepath = '/opt/r4bit/dahua/Tools/services.dump.list'
        #filepath = '/root/Master/fuzzing/lists/services.dump.list'

        # Bof Detection
        #filepath = '/root/Master/fuzzing/lists/FuzzingStrings-SkullSecurity.org.txt'

        #filepath = '/usr/share/seclists/Fuzzing/command-injection-commix.txt'

        with open(filepath) as fp:
            for cnt, line in enumerate(fp):
                time.sleep(2)
                logging.info("Line {}: {}".format(cnt, line))
                buf = line
                buf2 = buf
                if injectionType == "bof":
                    buf2 = eval(buf)
                #print(buf2)
                
                api_argsFuzz = {
                "id":       dvripSession.sequenceID,
                "magic":    "0x1234",
                "method":   "console.runCmd",
                "params": {
                    #"command": line.rstrip('\n')
                    "command": buf2
                },
                "object":   dvripSession.objectID,
                "SID":      dvripSession.serviceID,
                "session":  dvripSession.sessionID,
                }

                data = json.dumps(api_argsFuzz)

                dvripSession.callJsanAPIFUZZ(data)

                logging.debug("next command OS-Injection fuzz payload")




  

# Class job: lass to handle DVRIP session, do login4way function and stores sessionID for later usage
class DVRIP_SESSION(object):
    rhost       = "192.168.1.108"
    rport       = 37777
    username    = "admin"
    password    = "admin"
    requestID   = ""
    sessionID   = b'efffff7f'
    sessionIDraw   = b'efffff7f'
    objectID    = ""                    # Object ID will be returned after called <service>.factory.instance
    serviceID   = ""                    # SID will be returned after we called <service>.attach with 'Object ID'
    callbackID  = ""                    # 'callback' ID will be returned after we called <service>.attach with 'proc: <Number>' (callback will have same number)
    payload     = "hello"   #json dump summary
    sequenceID  = 2 # starting with 2
    DVRIP_PDU_response = DVRIP_PDU(b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'' )

    # Initialize Class Instance with username and password
    def __init__(self, rhost, rport, username, password):
        
        self.username = username
        self.password = password
        self.rhost = rhost
        self.rport = rport
  
    # Function job: print DVRIP_SESSION instance variables
    def state(self):
        print("\nDVRIP_SESSION State variables:")
        print("RemoteHost: ", self.rhost)
        print("RemotePort: ", self.rport)
        print("Username: " , self.username)
        print("Password: " , self.password)
        print("SessionID: " , self.sessionID)
        print("SessionIDraw: " , binascii.b2a_hex(self.sessionIDraw))

    # Function job: DES encryption login4way, 2 way login4way
    def pseudologin4way(self):
        DVRIP_PDU_msg1 = DVRIP_PDU(
            b'a0745f26', b'00000000', 
            b'c4a3af48', b'9956b6b4', # username
            b'6e6302f2', b'b792f12c', # password  ### => 1234567b
            #b'fa269dec', b'29d84afb', # password  ### => 1234567a
            b'05020001', b'00000000', 
            b'' )

        global s
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.rhost, self.rport))

        s.send(DVRIP_PDU_msg1.stream())

        data_recv = s.recv(1024)

        DVRIP_PDU_msg4 = DVRIP_PDU(b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'' )
        DVRIP_PDU_msg4.toSymbol(data_recv)      # contains field from server
        DVRIP_PDU_msg4.state()
        self.sessionIDraw = binascii.hexlify(DVRIP_PDU_msg4.b5_SessionID_RCV) # GOOOOODm remove \x from hex
        self.sessionID = int.from_bytes(DVRIP_PDU_msg4.b5_SessionID_RCV, byteorder='little')

        print("Successful login4way with ", self.sessionIDraw, " as ", self.sessionID)
        print("maybe false positive, lets test the session now")

    # Funktion job: Test of fuzzed DES encryption which triggers event on device
    # random username password
    # a04faff9 00000000 7af1960d 9f0cd64e 486edeb8 2f2611b5 fa30aa66 4b1e3ffa ;; gives a server response with session?
    def pseudologin4way2(self):
        DVRIP_PDU_msg1 = DVRIP_PDU(
            b'a04faff9', b'00000000', 
            b'7af1960d', b'9f0cd64e', # username
            b'486edeb8', b'2f2611b5', # password
            b'fa30aa66', b'4b1e3ffa', 
            b'' )

        global s
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.rhost, self.rport))

        s.send(DVRIP_PDU_msg1.stream())

        data_recv = s.recv(1024)

        DVRIP_PDU_msg4 = DVRIP_PDU(b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'' )
        DVRIP_PDU_msg4.toSymbol(data_recv)      # contains field from server
        DVRIP_PDU_msg4.state()
        self.sessionIDraw = binascii.hexlify(DVRIP_PDU_msg4.b5_SessionID_RCV) # GOOOOODm remove \x from hex
        self.sessionID = int.from_bytes(DVRIP_PDU_msg4.b5_SessionID_RCV, byteorder='little')

        print("Successful login4way with ", self.sessionIDraw, " as ", self.sessionID)
        print("maybe false positive, lets test the session now")


    # Function job: Try login4way to the target device with username password
    # Returns / stores SessionID from message4
    # TODO: create new function, boolean application flow
    def login4way(self, doFuzzingState):

        DVRIP_PDU_msg1 = DVRIP_PDU(
            b'a0050060', 
            b'00000000',
            b'c4a3af48', 
            b'9956b6b4', 
            b'fa269dec', 
            b'29d84afb', 
            b'05020001', 
            b'0000a1aa', 
            b'' )
        logging.debug(DVRIP_PDU_msg1.stream())
        global s
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.rhost, self.rport))

        global runmodul

        ###### Fuzzing Check########################################
        ############################################################
        if doFuzzingState == True:
            if runmodul != 'fuzz login4way msg2 allFields':
                fuzzEngine = fuzzingEngine()
                fuzzEngine.setFuzzFieldsMsg1(DVRIP_PDU_msg1)
                #DVRIP_PDU_msg1.setFuzzFieldsMsg1()

        s.send(DVRIP_PDU_msg1.stream())

        if doFuzzingState == True:
            if runmodul != 'fuzz login4way msg2 allFields':
                return 0    # go back to calling function
        ###### End of Fuzzing ######################################
        ############################################################

        print("Fuzzing state should be True, your should not see that!")
        
        data_recv = s.recv(1024)

        DVRIP_PDU_msg2 = DVRIP_PDU(b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'' )
        DVRIP_PDU_msg2.toSymbol(data_recv)      # contains field from server
        DVRIP_PDU_msg2.state()
        logging.debug(data_recv)
        logging.debug("\nCalculating Hash")
        myHash = calculate_hash_callback(DVRIP_PDU_msg2.b9_payload, self.username, self.password)
        logging.debug(myHash)
        DVRIP_PDU_msg3 = DVRIP_PDU(b'a0050060', b'47000000', b'00000000', b'00000000', b'00000000', b'00000000', b'05020008', b'0000a1aa', b'' )
        #DVRIP_PDU_msg3.b9_payload = myHash.hex()



        DVRIP_PDU_msg3.b9_payload = myHash

        if doFuzzingState == True:
            if runmodul == 'fuzz login4way msg2 allFields':
                fuzzEngine = fuzzingEngine()
                fuzzEngine.setFuzzFieldsMsg2(DVRIP_PDU_msg3)
                s.settimeout(1)

        DVRIP_PDU_msg3.state()
        # send msg3
        tmpsend = DVRIP_PDU_msg3.stream()
        logging.debug(tmpsend)
        s.send(tmpsend)

        try:

            # convert msg4 to PDU unit
            data_recv = s.recv(1024)

        except socket.timeout as e:
            logging.debug(e)
            sys.stdout.write("*")
            #counter1 +=1
            logging.debug("next")

        DVRIP_PDU_msg4 = DVRIP_PDU(b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'' )
        DVRIP_PDU_msg4.toSymbol(data_recv)      # contains field from server
        DVRIP_PDU_msg4.state()
        self.sessionIDraw = binascii.hexlify(DVRIP_PDU_msg4.b5_SessionID_RCV) # GOOOOODm remove \x from hex
        self.sessionID = int.from_bytes(DVRIP_PDU_msg4.b5_SessionID_RCV, byteorder='little')

        print("Successful login4way with ", self.sessionIDraw, " as ", self.sessionID)

    # Function job: Sending KeepAlive so that the session stays active 
    def keepAlive(self):
        service_args = {
            "method":"global.keepAlive",
            "magic" : "0x1234",
            "params":{
				"timeout": 30,
				"active":True
				},
            "id":12, #self.sequenceID,
            "session":self.sessionID}

        #data = json.dumps(query_args)
        payload = json.dumps(service_args)
        logging.debug(payload)

        payloadLength = len(payload) #84 (int) => 54 in hex; hex(84):54 
        payloadLength = struct.pack("<I", payloadLength)
        payloadLength = binascii.hexlify(payloadLength)

        logging.debug(payload)
        logging.debug(type(payload))
        self.payload = payload
        logging.debug(self.payload)


        #tmppayload = '{"method": "global.keepAlive", "magic": "0x1234", "params": {"timeout": 30, "active": true}, "id": 2, "session": ', self.sessionID, "}"
        #logging.debug("%s", str(tmppayload))
        #self.payload = tmppayload
        DVRIP_PDU_msg1 = DVRIP_PDU(b'f6000000', payloadLength, b'02000000', b'00000000', payloadLength, b'00000000', self.sessionIDraw, b'00000000', self.payload )
        logging.debug(DVRIP_PDU_msg1.state())
        stream = DVRIP_PDU_msg1.stream()
        global s
        s.send(stream)      

        data_recv = s.recv(1024)

        DVRIP_PDU_msg2 = DVRIP_PDU(b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'' )
        DVRIP_PDU_msg2.toSymbol(data_recv)      # contains field from server
        DVRIP_PDU_msg2.state()

    # Function job: sending logout PDU to disable session
    def logout(self):
        '''
        [[[ client logout request + server resposne ]]]
        '0a000000'   | '00000000'     | 'f9ffff7f' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | ''                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
        '0b010078'   | '00000000'     | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | ''    
        '''
        DVRIP_PDU_msg1 = DVRIP_PDU(b'0a000000', b'00000000', self.sessionIDraw, b'00000000', 
        b'00000000', b'00000000', b'00000000', b'00000000', b'' )
        logging.debug(DVRIP_PDU_msg1.state())
        stream = DVRIP_PDU_msg1.stream()
        global s
        s.send(stream)      

        data_recv = s.recv(1024)

        DVRIP_PDU_msg2 = DVRIP_PDU(b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'' )
        DVRIP_PDU_msg2.toSymbol(data_recv)      # contains field from server
        DVRIP_PDU_msg2.state()
        logging.debug("end-of-logout")
    
    # Function job: temp: keepalive: Run command in console service 
    def consoleCommannd(self):
        query_args = {
            "method":"global.keepAlive",
            "magic" : "0x1234",
            "params":{
				"timeout": 30,
				"active":True
				},
            "id":self.sequenceID,
            "session":self.sessionID}

        data = json.dumps(query_args)
        
        logging.debug(data)
        logging.debug(type(data))
        self.payload = data
        logging.debug(self.payload)


        #tmppayload = '{"method": "global.keepAlive", "magic": "0x1234", "params": {"timeout": 30, "active": true}, "id": 2, "session": ', self.sessionID, "}"
        #logging.debug(str(tmppayload))
        #self.payload = tmppayload
        DVRIP_PDU_msg1 = DVRIP_PDU(b'f6000000', b'7c000000', b'06000000', b'00000000', b'7c000000', b'00000000', self.sessionIDraw, b'00000000', self.payload )
        logging.debug(DVRIP_PDU_msg1.state())
        stream = DVRIP_PDU_msg1.stream()
        global s
        s.send(stream)      

        data_recv = s.recv(1024)

        DVRIP_PDU_msg2 = DVRIP_PDU(b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'' )
        DVRIP_PDU_msg2.toSymbol(data_recv)      # contains field from server
        DVRIP_PDU_msg2.state()

    # Fuzz Function job: call json api with arguments, print output
    def callJsanAPIFUZZ(self, api_args):
        # will increase P2P sequcne ID in PDU +1
        data = api_args
        payloadLength = len(data) #84 (int) => 54 in hex; hex(84):54 
        payloadLength = struct.pack("<I", payloadLength)
        payloadLength = binascii.hexlify(payloadLength)
        
        seqNrRAW = struct.pack("<I", self.sequenceID)
        seqNrRAW = binascii.hexlify(seqNrRAW)
        logging.debug(seqNrRAW)

        self.payload = data # json api args
        # payload length 54 must be length of payload, or no response from server
        DVRIP_PDU_msg1 = DVRIP_PDU(
            b'f6000000', payloadLength, 
            seqNrRAW, b'00000000', 

            payloadLength, b'00000000', 
            self.sessionIDraw, b'00000000', 
            
            self.payload )
        stream = DVRIP_PDU_msg1.stream()
        global s
        s.send(stream)      

        #data_recv = s.recv(2048)
        


        try:
            s.settimeout(0.9)
            data_recv = s.recv(8192)
            logging.debug(data)
            logging.debug("console args")
            #print("Line {}: {}".format(cnt, line))

            self.DVRIP_PDU_response  = DVRIP_PDU(b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'' )
            self.DVRIP_PDU_response.toSymbol(data_recv)      # contains field from server
            #self.DVRIP_PDU_response.state()
            #####print(self.DVRIP_PDU_response.b9_payload)
            self.sequenceID += 1
            logging.debug("sequenceID: %s", self.sequenceID)

        except socket.timeout as e:
            logging.debug(e)
            sys.stdout.write("*")
            #counter1 +=1
            logging.debug("next")


    # Function job: call json api with arguments, print output
    def callJsanAPI(self, api_args):
        # will increase P2P sequcne ID in PDU +1
        data = api_args
        payloadLength = len(data) #84 (int) => 54 in hex; hex(84):54 
        payloadLength = struct.pack("<I", payloadLength)
        payloadLength = binascii.hexlify(payloadLength)
        
        seqNrRAW = struct.pack("<I", self.sequenceID)
        seqNrRAW = binascii.hexlify(seqNrRAW)
        logging.debug(seqNrRAW)

        self.payload = data # json api args
        # payload length 54 must be length of payload, or no response from server
        DVRIP_PDU_msg1 = DVRIP_PDU(
            b'f6000000', payloadLength, 
            seqNrRAW, b'00000000', 

            payloadLength, b'00000000', 
            self.sessionIDraw, b'00000000', 
            
            self.payload )
        stream = DVRIP_PDU_msg1.stream()
        global s
        s.send(stream)      

        #data_recv = s.recv(2048)
        data_recv = s.recv(8192*2)

        self.DVRIP_PDU_response  = DVRIP_PDU(b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'' )
        self.DVRIP_PDU_response.toSymbol(data_recv)      # contains field from server
        self.DVRIP_PDU_response.state()
        self.sequenceID += 1
        logging.debug("sequenceID: %s", self.sequenceID)

    # Function job: sending Commands over TCP-stream based authentication
    def executeBasicBinaryCommands(self):
        global s
        '''
        'a4000000'   | '00000000'     | '08000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | ''                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
        'b4000078'   | '11000000'     | '08000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | '2.800.0000004.0.R'   

        'a4000000'   | '00000000'     | '07000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | ''                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
        'b4000078'   | '0f000000'     | '07000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | '5C0726FPAGEC7C2'      

        'a4000000'   | '00000000'     | '0b000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | ''                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
        'b4000078'   | '0c000000'     | '0b000000' | '00000000' | '00000000' | '00000000' | '00000000' | '00000000' | 'IPC-HFW1431S'   
        '''

        time.sleep(3)
        # 1 2.800.0.R version in payload 
        logging.debug("\n**********\nTest of Unknown packet")## working!!! session based authentication?!!! 
        DVRIP_PDU_msg1 = DVRIP_PDU( b'a4000000', b'00000000', b'08000000', b'00000000',
                                b'00000000', b'00000000', b'00000000', b'00000000',b'',)
        
        stream = DVRIP_PDU_msg1.stream()
        s.send(stream)      
        data_recv = s.recv(1024)


        # 2 SN in payload
        logging.debug("\n**********\nTest of Unknown packet")
        DVRIP_PDU_msg1 = DVRIP_PDU( b'a4000000', b'00000000', b'07000000', b'00000000',
                                b'00000000', b'00000000', b'00000000', b'00000000',b'',)
        
        stream = DVRIP_PDU_msg1.stream()
        s.send(stream)      
        data_recv = s.recv(1024)



        # 2 SN in payload
        logging.debug("\n**********\nTest of Unknown packet")
        DVRIP_PDU_msg1 = DVRIP_PDU( b'a4000000', b'00000000', b'07000000', b'00000000',
                                b'00000000', b'00000000', b'00000000', b'00000000',b'',)
        
        stream = DVRIP_PDU_msg1.stream()
        s.send(stream)      
        data_recv = s.recv(1024)


        # 3 \x00 stream x 100
        logging.debug("\n**********\nTest of Unknown packet")
        DVRIP_PDU_msg1 = DVRIP_PDU( b'a4000000', b'00000000', b'06000000', b'00000000',
                                b'00000000', b'00000000', b'00000000', b'00000000',b'',)
        
        stream = DVRIP_PDU_msg1.stream()
        s.send(stream)      
        data_recv = s.recv(1024)


        # 4
        logging.debug("\n**********\nTest of Unknown packet")
        DVRIP_PDU_msg1 = DVRIP_PDU( b'a4000000', b'00000000', b'05000000', b'00000000',
                                b'00000000', b'00000000', b'00000000', b'00000000',b'',)
        
        stream = DVRIP_PDU_msg1.stream()
        s.send(stream)      
        data_recv = s.recv(1024)

        time.sleep(10)
        timer = 25
        loop = False
        if loop == True:
                
            # still working after 49 seconds,workings only with active TCP Session
            while True:
            # 5

                logging.debug("\n**********\nTest of Unknown packet")
                DVRIP_PDU_msg1 = DVRIP_PDU( b'a4000000', b'00000000', b'08000000', b'00000000',
                                        b'00000000', b'00000000', b'00000000', b'00000000',b'',)
                
                stream = DVRIP_PDU_msg1.stream()
                s.send(stream)      
                data_recv = s.recv(1024)
                

                DVRIP_PDU_msg2 = DVRIP_PDU(b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'' )
                DVRIP_PDU_msg2.toSymbol(data_recv)      # contains field from server
                DVRIP_PDU_msg2.state()       
                #timer += 1
                logging.debug("\n****timer: %s", timer)
                time.sleep(timer) 

    # Function job: Testing JSON commands, 
    # Function calls: callJsonAPI
    def executeBasicRPCCommands(self):
        ####################### start 1
        api_args = {
            "method":"magicBox.getDeviceType",
            "params": None,
            "session": self.sessionID,
            "id": self.sequenceID,
            }

        data = json.dumps(api_args)
        #self.sequenceID +=1
        self.callJsanAPI(data)
        ## end call
        ####################### start 1
        api_args = {
            "method":"magicBox.getDeviceType",
            "params": None,
            "session": self.sessionID,
            "id": self.sequenceID,
            }

        data = json.dumps(api_args)
        #self.sequenceID +=1
        self.callJsanAPI(data)
        ## end call


        ####################### start 2
        api_args = {
            "method":"magicBox.getSerialNo",
            "params": None,
            "session": self.sessionID,
            "id": self.sequenceID,
            }

        data = json.dumps(api_args)
        self.callJsanAPI(data)
        ## end call


        ####################### start 3
        api_args = {
            "method":"magicBox.getVendor",
            "params": None,
            "session": self.sessionID,
            "id": self.sequenceID,
            }

        data = json.dumps(api_args)
 
        self.callJsanAPI(data)
        ## end call

        logging.debug("end-of-calljsonapi")
        #time.sleep(3)


    ##############################

    # Function job: run console command
    def executeBasicConsoleCommand(self, doFuzzingState):
        ####################### start 1
        # {"id": 4, "magic": "0x1234", "method": "console.factory.instance", "params": null, "session": 397305870}
        # #1 Initialize RPC Server
        api_args = {
            "id": self.sequenceID,
            "magic": "0x1234",
            "method":"console.factory.instance",
            "params": None,
            "session": self.sessionID,
            }

        data = json.dumps(api_args)
        self.callJsanAPI(data)

        ## end call
        payloadDICT = json.loads(self.DVRIP_PDU_response.b9_payload)
        #print(payloadDICT)
        #print(payloadDICT['result'])
        self.objectID = payloadDICT['result']
        #time.sleep(1)

        # 2: Initialize RPC Server
        # {"id": 5, "magic": "0x1234", "method": "console.attach", "params": {"proc": 5}, "object": 19551576, "session": 397305870}
        api_args = {
            "id":       self.sequenceID,
            "magic":    "0x1234",
            "method":   "console.attach",
            "params": {
                "proc": self.sequenceID
            },
            "object":   self.objectID,
            "session":  self.sessionID,
            }

        data = json.dumps(api_args)
        self.callJsanAPI(data)

        payloadDICT = json.loads(self.DVRIP_PDU_response.b9_payload)
        #print(payloadDICT)
        #print(payloadDICT['params']['SID'])
        self.serviceID = payloadDICT['params']['SID']
        ## end call

        ########### rund CMD command
        # telnet vulnhost2.local | tee -a test004
        # {"SID": 1, "id": 6, "magic": "0x1234", "method": "console.runCmd", 
        # "params": {"command": "user -u"}, "object": 19551576, "session": 397305870}' 
        api_args = {
            "id":       self.sequenceID,
            "magic":    "0x1234",
            "method":   "console.runCmd",
            "params": {
                "command": "user"
            },
            "object":   self.objectID,
            "SID":      self.serviceID,
            "session":  self.sessionID,
            }

        data = json.dumps(api_args)
        self.callJsanAPI(data)

        logging.debug("donexxxxxxxx")
        payloadDICT = json.loads(self.DVRIP_PDU_response.b9_payload)
        logging.debug(payloadDICT)
        tmpx = print(payloadDICT['params']['info']['Data'])
        logging.debug("\n\ntry json decoder")
        teststring = "this is a test\nand others"
        logging.debug(str(tmpx).strip('\n'))
        
        
        if doFuzzingState == True:
            global runmodul
            myFuzzingEngine = fuzzingEngine()
            logging.debug("console fuzzing inline")
            if runmodul == "fuzz console memory":
                logging.debug("start fuzz console memory")
                fuzzList = "not used in this mode"
                myFuzzingEngine.doLoopFuzzRunCmd_search_memory(self, fuzzList)
            if runmodul == "fuzz console os-injection":
                logging.debug("start fuzz console memory")
                fuzzList = "/root/Master/fuzzing/lists/FuzzingStrings-SkullSecurity.org.txt"
                myFuzzingEngine.doLoopFuzzRunCmd_OSInjection(self, fuzzList, "bof")  

                print("bof detection done, wait 3 seconds")
                time.sleep(3)

                logging.debug("normal os inject")
                fuzzList = "/root/Master/fuzzing/lists/command-injection-commix.txt"
                myFuzzingEngine.doLoopFuzzRunCmd_OSInjection(self, fuzzList, "command")  


            #self.fuzzRunCmd(              "/root/Master/fuzzing/lists/FuzzingStrings-SkullSecurity.org.txt") 
            #self.fuzzRunCmd_search_memory("/root/Master/fuzzing/lists/FuzzingStrings-SkullSecurity.org.txt") 
            #fuzzRunCmd_search_memory
            # for once active session, handle session timeout /crash
                    #filepath = '/root/Master/fuzzing/lists/FuzzingStrings-SkullSecurity.org.txt'


        #self.serviceID = payloadDICT['params']['SID']
        ## end call


        logging.debug("end-of-executeBasicConsoleCommand")
        #time.sleep(3)



# Function job: initiate fuzzing of message1 from login4way
def fuzzingDES(speed):
    myDVRIP_SESSION = DVRIP_SESSION('192.168.178.107', 37777, 'admin', '1234567b')
    
    doFuzzingState = True

    # Test working login4way to the target device

    with open('/opt/r4bit/des_kpt/CT_8x_a.data', 'r') as content_file:
        content = content_file.read()

        global deskey


        fuzzCounter = 1

        for x in content.split():
            deskey = x
            print(deskey)
            myDVRIP_SESSION.login4way(doFuzzingState)
            print("Fuzzcounter: ", fuzzCounter)
            fuzzCounter += 1
            time.sleep(speed) #1.2

# Function job: Fuzzing of UDP service methods
def udpFuzzService():

    # system.listService
    print("udpFuzzService")

    buf = "A"

    # original: { 
    # "method" : "DHDiscover.search", 
    # "params" : 
    # { "mac" : "", 
    # "uni" : 1 } 
    # }

    api_args2 = {
        "method":"DHDiscover.search",
        "params": {
            "mac": "",
            "uni": 1
            }
        }

    data = json.dumps(api_args2)

    payloadLength = len(data) #84 (int) => 54 in hex; hex(84):54 
    payloadLength = struct.pack("<I", payloadLength)
    payloadLength = binascii.hexlify(payloadLength)
   
    udpPack1 = DVRIP_PDU(
        b'20000000', b'44484950', 
        b'00000000', b'00000000', 

        payloadLength, b'00000000', 
        payloadLength, b'00000000', 
        
        data )

    stream = udpPack1.stream()

    UDP_IP = "192.168.178.107"
    UDP_PORT = 37810
    MESSAGE = stream
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
    data = sock.recv(2048)
    print(data)
    # end of first UDP test

    counter1 = 1
    #filepath = '/opt/r4bit/dahua/Tools/services.dump.list'
    filepath = '/root/Master/fuzzing/lists/services.dump.list'
    with open(filepath) as fp:
        for cnt, line in enumerate(fp):
            logging.debug("Line {}: {}".format(cnt, line))
            
            api_argsFuzz = {
            #"method": line.rstrip('\n'),
            "method": line.rstrip('\n'),
            "params": {
                "mac": "",
                "uni": 1
                }
            }

            data = json.dumps(api_argsFuzz)

            payloadLength = len(data) #84 (int) => 54 in hex; hex(84):54 
            payloadLength = struct.pack("<I", payloadLength)
            payloadLength = binascii.hexlify(payloadLength)

            
            udpPack1 = DVRIP_PDU(
                b'20000000', b'44484950', 
                b'00000000', b'00000000', 

                payloadLength, b'00000000', 
                payloadLength, b'00000000', 
                
                data )

            stream = udpPack1.stream()


            UDP_IP = "192.168.178.108"

            UDP_PORT = 37810
            #MESSAGE = searchDeviceStream
            MESSAGE = stream

            logging.debug("UDP target IP: %s", UDP_IP)
            logging.debug("UDP target port: %s", UDP_PORT)
            #logging.debug "message:", MESSAGE

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            #my_bytes = binascii.a2b_hex(MESSAGE)
            sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
            try:
                sock.settimeout(0.9)
                data = sock.recv(1024)
                print(data)
                print("Line {}: {}".format(cnt, line))

            except socket.timeout as e:
                logging.debug(e)
                sys.stdout.write("*")
                counter1 +=1
                logging.debug("next")

# Function job: initiate fuzzing of message1 from login4way
def msg1fuzzing(speed):
    myDVRIP_SESSION = DVRIP_SESSION('192.168.178.107', 37777, 'admin', '1234567b')
    
    doFuzzingState = True

    fuzzCounter = 1

    if doFuzzingState == True:
        while True:
            myDVRIP_SESSION.login4way(doFuzzingState)
            print("Fuzzcounter: ", fuzzCounter)
            fuzzCounter += 1
            time.sleep(speed) #1.2




# <summary> simulate 4-way login, binary commands, RPC commands
def simulateAllClientFunctions():
    doFuzzingState = False

    # create session object
    myDVRIP_SESSION = DVRIP_SESSION('192.168.178.107', 37777, 'admin', '1234567b')

    # do 4-way login4way Handshake
    myDVRIP_SESSION.login4way(doFuzzingState)
    time.sleep(2)

    # execute basic binary commands
    myDVRIP_SESSION.executeBasicBinaryCommands()
    time.sleep(2)

    # execute basic RPC commands with JSON
    myDVRIP_SESSION.executeBasicRPCCommands()
    time.sleep(2)

    # execute basic RPC command in console
    myDVRIP_SESSION.executeBasicConsoleCommand(doFuzzingState)
    time.sleep(2)

    print("\nClient Simulation is finished now!")

# Function job: call login4way test
def simulateDESLogin():
    doFuzzingState = False

    # create session object
    myDVRIP_SESSION = DVRIP_SESSION('192.168.178.107', 37777, 'admin', '1234567b')

    # do 4-way login4way Handshake
    myDVRIP_SESSION.pseudologin4way()
    time.sleep(2)

    # execute basic binary commands
    print("do binary commands")
    myDVRIP_SESSION.executeBasicBinaryCommands()
    print("done binary commands")
    time.sleep(2)

    # execute basic RPC commands with JSON
    myDVRIP_SESSION.executeBasicRPCCommands()
    print("done RPC Commands")
    time.sleep(2)


    # execute basic RPC command in console
    myDVRIP_SESSION.executeBasicConsoleCommand(doFuzzingState)
    time.sleep(2)

    print("\nClient Simulation is finished now!")


# Function job: initiate fuzzing of message1 from login4way
def fuzzBinaryCommands(speed):
    myDVRIP_SESSION = DVRIP_SESSION('192.168.178.107', 37777, 'admin', '1234567b')
    
    doFuzzingState = False

    fuzzCounter = 0
    code = 0
    myDVRIP_SESSION.login4way(doFuzzingState)
    myFuzzEngine = fuzzingEngine()

    doFuzzingState = True

    if doFuzzingState == True:
        while True:
            
            print("Fuzzcounter: ", fuzzCounter)
            time.sleep(speed) #1.2

            logging.debug("\n**********\nFuzz next Binary Command")

            DVRIP_binaryPDU = DVRIP_PDU( 
                b'a4000000', b'00000000', 
                b'08000000',                 # <= this field we will fuzz now
                b'00000000', b'00000000', 
                b'00000000', b'00000000', 
                b'00000000', b'',)
            
            myFuzzEngine.setFuzzBinaryCommands(DVRIP_binaryPDU, code)
            stream = DVRIP_binaryPDU.stream()
            s.send(stream)      
            data_recv = s.recv(1024)

            DVRIP_PDU_msg2 = DVRIP_PDU(b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'00', b'' )
            DVRIP_PDU_msg2.toSymbol(data_recv)      # contains field from server
            DVRIP_PDU_msg2.state()     
            logging.debug("\nbinaryout is: %s", DVRIP_PDU_msg2.b9_payload)
 
            fuzzCounter += 1
            code += 3
 


############################################
############################################
############################################
### Start of main Script

def main():
    
    logLevel = logging.INFO
    global msg1FuzzState
    global runmodul

    # Logging configuration
    logging.basicConfig(
        level=logLevel,
        format="%(asctime)s [%(levelname)s] line %(lineno)d, %(funcName)s(): %(message)s",
        handlers=[
            logging.FileHandler("debug.log"),
            logging.StreamHandler()
        ]
    )

  
    #### end of clone

    # calculation of runtime of program
    start_time = time.time()

    # interactive

    runmodul = "client simulate all"

    # errorDetection() # thread for error detection on target device
    # fuzz template for each szenario, run all fuzz injections

    if runmodul == "client simulate all":       ## verified
        logging.info(runmodul)
        simulateAllClientFunctions() # login4way and run all knwon example commands
    if runmodul == "client simulate des login": ### verified
        logging.info(runmodul)
        simulateDESLogin() # 

    if runmodul == "fuzz login4way msg1 msgType": ### verified!
        logging.info(runmodul)
        msg1FuzzState = runmodul
        speed = 0.1
        msg1fuzzing(speed) # start fuzzing of message 1 from login4way
    if runmodul == "fuzz login4way msg1 bof": ### verfied!
        logging.info(runmodul)
        msg1FuzzState = runmodul
        speed = 0.6 
        msg1fuzzing(speed) # start fuzzing of message 1 from login4way
    if runmodul == "fuzz login4way msg1 allFields": ### verified
        logging.info(runmodul)
        msg1FuzzState = runmodul
        speed = 0.1
        msg1fuzzing(speed) # start fuzzing of message 1 from login4way
    if runmodul == "fuzz login4way msg2 allFields": ### verified
        logging.info(runmodul)
        msg1FuzzState = runmodul
        speed = 0.1
        msg1fuzzing(speed) # start fuzzing of message 1 from login4way
    
    if runmodul == "fuzz des decryption": ### verified
        logging.info(runmodul)
        msg1FuzzState = runmodul
        speed = 0.5
        fuzzingDES(speed) # search DESKEY with crask.sh CT fields
    if runmodul == "fuzz binary command": ### verified
        logging.info(runmodul)
        #msg1FuzzState = runmodul
        speed = 0.1
        fuzzBinaryCommands(speed) # search DESKEY with crask.sh CT fields

    if runmodul == "fuzz console memory" or runmodul == "fuzz console os-injection": # buffer overlow
        doFuzzingState = False
        logging.info(runmodul)
        myDVRIP_SESSION = DVRIP_SESSION('192.168.178.107', 37777, 'admin', '1234567b')
        myDVRIP_SESSION.login4way(doFuzzingState)
        doFuzzingState = True
        myDVRIP_SESSION.executeBasicConsoleCommand(doFuzzingState)

    if runmodul == "fuzz udp service":
        logging.info(runmodul)
        udpFuzzService()


    ################## END OF SCRIPT ##################
    print("\n--- %s seconds ---\n" % (time.time() - start_time))
    ################## END OF SCRIPT ##################

    logging.info('end of main')


if __name__ == "__main__":
    main()


