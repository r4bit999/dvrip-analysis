# DVRIP Protocol Client and Fuzzing Engine
This repository is only for informational and educational purpose.  
Feel free to reach me out tvogt@stud.hs-offenburg.de

**dvripFuzzEngine.py** : main application - client simulation and fuzzing of the DVRIP protocol (implementation)  
change runmodul = "client simulate all" in the main() function to the corresponding module you want to run. IP, username, password is also currently hardcoded.

**dvripLoggingEninge.py** : logging Engine - written for (patched) telnet access  
**dvripNetzobInferring.py** : protocol analysis and inferring with Netzob  
**dvripWireshark.lua** : Wireshark Dissector for DVRIP  
**hashCreator.py** : hash function interface for DVRIP login process, based on https://github.com/mcw0/Tools  
**dvripNetzobInferring-output-example.txt** : example output file from Netzob inference
