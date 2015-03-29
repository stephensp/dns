#!/usr/bin/python -u 
import sys
import struct
import string
import binascii

class header_obj(object):
    def __init__(self, h_id, byte_2, qdcount, ancount, nscount, arcount):
        self.h_id = h_id 
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount
        self.decode_byte2(byte_2)
        
    def decode_byte2(self, byte_2):
        self.qr = (byte_2 >> 15) & 1
        self.op = (byte_2 >> 11) & 0xf
        self.aa = (byte_2 >> 10) & 1
        self.tc = (byte_2 >> 9) & 1
        self.rd = (byte_2 >> 8) & 1
        self.ra = (byte_2 >> 7) & 1
        self.z = (byte_2 >> 4) & 0x7 
        self.rcode = byte_2 & 0xf


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
    h_id, byte_2, qdcount, ancount, nscount, arcount  = struct.unpack('!HHHHHH', header)
    
    decoded_header = header_obj(h_id, byte_2, qdcount, ancount, nscount, arcount)
    
    
#    print binascii.hexlify(bytearray(header))
#    print "id " + str(decoded_header.h_id)
#    print "qd " + str(decoded_header.qdcount)
#    print "an " + str(decoded_header.ancount)
#    print "ns " + str(decoded_header.nscount)
#    print "ar " + str(decoded_header.arcount)
#    print "byte_2 " + str(byte_2)
#
#    print "qr " + str(decoded_header.qr)
#    print "op " + str(decoded_header.op)
#    print "aa " + str(decoded_header.aa)
#    print "tc " + str(decoded_header.tc)
#    print "rd " + str(decoded_header.rd)
#    print "ra " + str(decoded_header.ra)
#    print "z " + str(decoded_header.z)
#    print "rcode " + str(decoded_header.rcode)
    
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

def decode_answer(packet):
   # print binascii.hexlify(bytearray(packet))
    header = unpack_header(packet[:12])
    print binascii.hexlify(bytearray(packet[12:]))



    
#address = "www.northeastern.edu"
#request = create_request(address)
#print binascii.hexlify(bytearray(request))

