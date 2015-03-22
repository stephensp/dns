#!/usr/bin/python -u 
import sys
import struct
import string
import binascii

class header_obj(object):
    def __init__(self, h_id, byte_2, byte_3, qdcount, ancount, nscount, arcount):
        self.h_id = h_id 
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount
        self.decode_byte2(byte_2)
        
    def decode_byte2(self, byte_2):
        self.qr = byte_2 & 1
        self.opcode = (byte_2 & 30 ) >> 1
        self.aa = (byte_2 & 32) >> 5
        self.tc = (byte_2 & 64) >> 6
        selef.rd = (byte_2 & 128) >> 7


def create_header():
    # This functions creates the header of a packet to send
    # since we will only be creating headers for packets
    # we are sending most of the parameters are hardcoded in

    # ID = 1337 
    # QR = 0b0 ; Opcode = 0b0000; AA = 0bX; TC = 0bX; RD=0b1 = 128 (byte_2)
    # RA = 0bX ; Z = 0b000; RCODE = 0bXXXX = 0 (byte_3)
    # QDCOUNT = 0b0000_0000_0000_0001 ; indicates question
    # ANCOUNT = 0b0000_0000_0000_0000; indicates we are not providing answer
    # NSCOUNT = 0b0000_0000_0000_0000; ignore any responses in this entry
    # ARCOUNT = 0b0000_0000_0000_0000; ignore any reponses in this entry

    
#    header = struct.pack('!hhhhhh', 1337, 128, 1, 0, 0, 0)
    header = struct.pack('!hhhhhh', 1337, 256, 1, 0, 0, 0)

    return header

def unpack_header(header):
    h_id, byte_2, byte_3, qdcount, ancount, nscount, arcount  = struct.unpack('!HBBHHHH', header)
    
    decoded_header = header_obj(h_id, byte_2, byte_3, qdcount, ancount, nscount, arcount)
    
    return decoded_header
    
def create_question(address):
    adr_split = address.split('.')
    
    # Add QNAME
    question = ''
    for i in range(0, len(adr_split)):
        question = question + struct.pack('!B', len(adr_split[i])) + adr_split[i]
    
    # Specify end of the name, 0x00
    # Add QTYPE , 0x0001, specifiies A type
    # Add QCLASS, 0x0001, specifies internet address
    question = question + struct.pack('!BHH',0, 1, 1)

    return question


def create_request(address):
    request = create_header() + create_question(address)
    return request

    
#address = "www.northeastern.edu"
#request = create_request(address)
#print binascii.hexlify(bytearray(request))

