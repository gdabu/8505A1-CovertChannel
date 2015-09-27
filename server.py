import sys
from scapy.all import *

secret_messageByteArray = [""];
secret_message = "";
character_index = 0;
BYTE_SIZE = 8;
bit_index = 0;





def globalReset():
    global secret_messageByteArray;
    global character_index;
    global bit_index;
    global secret_message;

    secret_messageByteArray = [""]
    character_index = 0;
    bit_index = 0;
    secret_message = "";


#Look for the specific IP addresses for the covert traffic
def parse(pkt):
    global secret_messageByteArray;
    global character_index;
    global BYTE_SIZE;
    global bit_index;
    global secret_message;
    

    # print(pkt["TCP"].sport)
    if ( pkt["TCP"].sport < 25088 ):
        bit = 0;
    elif (pkt["TCP"].sport > 25088 ):
        bit = 1;
    elif (pkt["TCP"].sport == 25088):
        print("Message Received:")
        print str(secret_messageByteArray)
        print(secret_message)
        globalReset()
        return

    secret_messageByteArray[character_index] += `bit`;

    bit_index+=1;
    if(bit_index == BYTE_SIZE):

        secret_message += str(chr(int(secret_messageByteArray[character_index], 2)))
        secret_messageByteArray.append("");
        character_index+=1;
        bit_index = 0;

    # print secret_messageByteArray

#Main
sniff(filter="dst port 80 and dst 192.168.0.9", prn=parse)
