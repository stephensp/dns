#!/usr/bin/python -u 
import sys
import struct
import string
import binascii

# Objec that contains all the elements of the header
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

# Contains all parameters of an answer
class ans_obj(object):
    def __init__(self, name, type_q, class_q, ttl, rdlength, ip_adr, pref):
        self.name = name
        self.type_q= type_q 
        self.class_q= class_q 
        self.ttl = ttl 
        self.rdlength = rdlength 
        self.ip_adr = ip_adr
        self.pref = pref


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
    
def create_question(address, req_type):
    adr_split = address.split('.') # Break up the address on .
    
    # Add QNAME
    question = ''
    for i in range(0, len(adr_split)):
        question = question + struct.pack('!B', len(adr_split[i])) + adr_split[i]
    
    # Specify end of the name, 0x00
    # Add QTYPE , 0x0001, specifiies A type
    # Add QCLASS, 0x0001, specifies internet address
    if(req_type == 0):
        question = question + struct.pack('!BHH',0, 1, 1)
    if(req_type == 1):
        question = question + struct.pack('!BHH',0, 0xf, 1)
    if(req_type == 2):
        question = question + struct.pack('!BHH',0, 0x2, 1)

    return question


def create_request(address, req_type):
    # Request is just a header and a question!
    request = create_header() + create_question(address, req_type)
    return request

def unpack_question(question, size):
    question = question[:(size - 12)]
    return question
    
# This function takes an offset and a packet and decodes the name stored there
# It will read until it finds a 0x00. It deals with points and returns an 
# offset of where it stopped reading. 
def read_word(packet, offset):
    
    (length,)  = struct.unpack("!B", packet[offset])
    name = []

    while(length != 0x00):
        if(length & 0xc0) == 0xc0:
            (ptr_offset,) = struct.unpack("!B", packet[offset+1]) # get the seond half
            ptr_offset = ((length & 0x3f) << 8) | ptr_offset # clear the pointer signal 
            tmp_name, tmp  = read_word(packet, ptr_offset)
            name = name + tmp_name 

            # The offset should not include the expanded name
            return name, (offset + 2) 

        # If it is not a pointer just parse 
        name.append(packet[offset+1:offset+length+1])
        offset = offset + length + 1 
        (length,)  = struct.unpack("!B", packet[offset])

    return name, offset+1
    
    
def unpack_answer(packet, offset):
#    print binascii.hexlify(bytearray(packet))
    (length,)  = struct.unpack("!B", packet[offset:offset+1])

    # get name
    name = []
    name, offset = read_word(packet, offset)


    name = '.'.join(name)
#    print "Printing name: "
#    print name

#    print binascii.hexlify(bytearray(packet[offset:]))
    type_q, class_q, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset+10])
    offset = offset + 10 
    
#    print "name = " + str(name)
#    print "type = " + str(type_q) 
#    print "class= " + str(class_q) 
#    print "ttl = " + str(ttl) 
#    print "rdlength = " + str(rdlength) 

    
    
    # Mail server, need to take into account preferences
    if (type_q == 0x000f):
        (pref,) = struct.unpack("!H", packet[offset:offset+2])
        offset = offset + 2
        alias, offset = read_word(packet, offset)
        alias = '.'.join(alias)
        decoded_answer = ans_obj(name, type_q, class_q, ttl, rdlength, alias, pref)
        return decoded_answer, offset

    # CNAME
    if (type_q == 0x0005) or (type_q == 0x0002):
        alias, offset = read_word(packet, offset)
        alias = '.'.join(alias)
#        print alias
        decoded_answer = ans_obj(name, type_q, class_q, ttl, rdlength, alias, -1)
        return decoded_answer, offset

    ip = []

    # A type
    if type_q  == 0x0001: 
        # This is a standard A class
        my_ip = packet[offset:offset+rdlength]
        
        for j in range(0, rdlength):
            (value,) = struct.unpack("!B", packet[offset+j])
            ip.append(value)

        ip = '.'.join(str(x) for x in ip)
        decoded_answer = ans_obj(name, type_q, class_q, ttl, rdlength, ip, -1)
        return decoded_answer, offset

    # All other types are unsupported
    return -1, -1




   



    
#address = "www.northeastern.edu"
#request = create_request(address)
#print binascii.hexlify(bytearray(request))

