#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Dahua Logging Eninge - written for (patched) telnet login
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


import time
import os
import telnetlib
import subprocess
from subprocess import Popen, PIPE
from threading import Thread
import re


logFileName = time.strftime("%Y-%m-%d--%H-%M-%S.log")
print("Starting logging Engine..")
print("Create log File ", logFileName, "\n")
a = 0
isNew = False
# used for line of file 


# def escape_ansi: Code Import from
# https://www.tutorialspoint.com/How-can-I-remove-the-ANSI-escape-sequences-from-a-string-in-python

def escape_ansi(line):
    ansi_escape =re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    return ansi_escape.sub('', line)
# end of import

# search for new message
def isNewMessage(myline):
    global isNew
    global a
    # line = line lof log message
    r = re.search("(m_lastRegStatus|Has Been Deleted|Connect RPCServer Successfully|Extracting UDN|Extracting device type|<P2PDevice.cpp:478>send heartbeat|<P2PDevice.cpp:150>recv 200 OK|key dhp2pP2P1|\[AmbaVideo\] black Recalc)",myline)
    if r != None:
        #print("found a entry, so its old message")
        ###print(line)
        isNew =  False
        ####print("old message")
    else:
        if myline != '':
            if escape_ansi(myline) != '':
                #print("'' detected")

                isNew = True
                #print(myline.isprintable())
                #print("new Message %s", a)
                print(myline)
                #r = re.search("IsUserValid\(\) user", myline)
                #r = re.search("extra data", myline)
                
                ###if r != None:
                ###    print(myline)
        a += 1

def processLogData(data):
    lineList = data.split("\n")
    for lines in lineList:
        isNewMessage(lines)

def parseLogData():
    last_position = 0
    while True: #loop forever
        with open('/root/Master/fuzzing/logging/' + logFileName) as f:
            f.seek(last_position)
            new_data = f.read()
            last_position = f.tell()
        processLogData(new_data)
        time.sleep(0.1) #sleep some amount of time

def runTelnetLib():
    host_ip = "192.168.178.107"

    tn = telnetlib.Telnet(host_ip)

    command = "logView -r all 1"
    tn.write(command.encode('ascii') + b"\n")

    file = open("/root/Master/fuzzing/logging/" + logFileName, "a",errors='replace')

    while True:
        data = tn.read_until(b'None', 0.2)
        file.write(data.decode("utf-8","replace"))
        file.flush()

###########################

runTelnetThread = Thread(target=runTelnetLib)
runTelnetThread.start()
print("Saving Device-Log to local file")

time.sleep(1)

parseLogDataThread = Thread(target=parseLogData)
parseLogDataThread.start()
print("Parsing Log-Data startet")
