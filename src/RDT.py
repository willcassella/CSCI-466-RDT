import Network
import argparse
from time import sleep
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)

    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S

    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]

        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S


def dispatch_packet(network, packet):
    network.udt_send(packet.get_byte_S())


def construct_packet(network, buffer):
    # Keep waiting for data
    buffer += network.udt_receive()

    # check if we have received enough bytes
    if (len(buffer) < Packet.length_S_length):
        return (buffer, None, None)  # not enough bytes to read packet length

    # extract length of packet
    length = int(buffer[:Packet.length_S_length])
    if len(buffer) < length:
        return (buffer, None, None)  # not enough bytes to read the whole packet

    # create packet from buffer content and add to return string
    packet_data = buffer[0:length]
    buffer = buffer[length:]

    # Make sure the packet isn't corrupt
    if Packet.corrupt(packet_data):
        return (buffer, False, None)

    return (buffer, True, Packet.from_byte_S(packet_data))


class RDT_1_0:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)

    def disconnect(self):
        self.network.disconnect()

    def send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        dispatch_packet(self.network, p)

    def receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration


class RDT_2_1:
    PACKET_TYPE_LENGTH = 1
    PACKET_MESSAGE = 0
    PACKET_ACK = 1
    PACKET_NACK = 2

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
        self.seq_number = 0
        self.byte_buffer = ''

    def disconnect(self):
        self.network.disconnect()

    def send(self, msg_S):
        # Send the packet
        p = RDT_2_1._create_message_packet(self.seq_number, msg_S)
        dispatch_packet(self.network, p)

        # Await response from server
        while True:
            # Try to get a response from the server (may be corrupt)
            (self.byte_buffer, good, response) = construct_packet(self.network, self.byte_buffer)

            # If we haven't gotten a response
            if good is None:
                continue

            # If the response is corrupt
            if not good:
                # Try again
                dispatch_packet(self.network, p)
                continue

            # We have a good packet, so extract information
            (seq, type, msg) = RDT_2_1._get_packet_info(response)

            # If the response is an ACK for the current sequence
            if seq == self.seq_number and type == RDT_2_1.PACKET_ACK:
                # All is good
                self.seq_number += 1
                return

            # If the response is a NACK for the current sequence
            if seq == self.seq_number and type == RDT_2_1.PACKET_NACK:
                # Receiver still in 'receive' state, resend packet
                dispatch_packet(self.network, p)
                continue

            # If the response is a MESSAGE for a future sequence
            if seq > self.seq_number and type == RDT_2_1.PACKET_MESSAGE:
                # Receiver got the message (we must have previously gotten a corrupted ACK), ask to resend and let calling function get ready
                dispatch_packet(self.network, RDT_2_1._create_nack_packet(seq))
                self.seq_number += 1
                return

            # If the response is a MESSAGE for an old sequence
            if seq < self.seq_number and type == RDT_2_1.PACKET_MESSAGE:
                # We used to be a receiver, sender must have never gotten our ACK. Send message again
                dispatch_packet(self.network, p)
                continue

            print("UNEXPECTED STATE")
            exit(-1)

    def receive(self):
        # Try to get a response from the server
        (self.byte_buffer, good, packet) = construct_packet(self.network, self.byte_buffer)

        # If we haven't gotten a packet
        if good is None:
            return None

        # If the packet is corrupt
        if good == False:
            # Send NACK
            dispatch_packet(self.network, RDT_2_1._create_nack_packet(self.seq_number))
            return None

        # Packet is good, so extract info
        (seq, type, msg) = RDT_2_1._get_packet_info(packet)

        # If the packet is a message for the current sequence
        if seq == self.seq_number and type == RDT_2_1.PACKET_MESSAGE:
            # Send ack, return message to calling function
            dispatch_packet(self.network, RDT_2_1._create_ack_packet(self.seq_number))
            self.seq_number += 1
            return msg

        # If the response is a MESSAGE for a future sequence
        if seq > self.seq_number and type == RDT_2_1.PACKET_MESSAGE:
            # Receiver got the message (we must missed a previous ACK), ask to resend and let calling function get ready
            dispatch_packet(self.network, RDT_2_1._create_nack_packet(seq))
            self.seq_number += 1
            return

        # If the packet is a message for an old sequence
        if seq < self.seq_number and type == RDT_2_1.PACKET_MESSAGE:
            # Sender never got our ack, send it again to put them out of send state
            dispatch_packet(self.network, RDT_2_1._create_ack_packet(seq))
            return None

        print("UNEXPECTED STATE")
        exit(-1)

    @staticmethod
    def _get_packet_info(p):
        return (p.seq_num, int(p.msg_S[0:RDT_2_1.PACKET_TYPE_LENGTH]), p.msg_S[RDT_2_1.PACKET_TYPE_LENGTH:])

    @staticmethod
    def _create_message_packet(seq_num, msg_S):
        return Packet(seq_num, str(RDT_2_1.PACKET_MESSAGE).zfill(RDT_2_1.PACKET_TYPE_LENGTH) + msg_S)

    @staticmethod
    def _create_ack_packet(seq_num):
        return Packet(seq_num, str(RDT_2_1.PACKET_ACK).zfill(RDT_2_1.PACKET_TYPE_LENGTH))

    @staticmethod
    def _create_nack_packet(seq_num):
        return Packet(seq_num, str(RDT_2_1.PACKET_NACK).zfill(RDT_2_1.PACKET_TYPE_LENGTH))


class RDT_3_0:
    PACKET_TYPE_LENGTH = 1
    PACKET_MESSAGE = 0
    PACKET_ACK = 1

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
        self.seq_number = 0
        self.byte_buffer = ''

    def disconnect(self):
        self.network.disconnect()

    def send(self, msg_S):
        # Create packet to send
        p = RDT_3_0._create_message_packet(self.seq_number, msg_S)

        # Wait for an ACK
        timeout = 0
        while True:
            # Decrement timeout counter
            timeout -= 1
            if timeout < 0:
                # Resend the message
                dispatch_packet(self.network, p)
                timeout = 100

            (self.byte_buffer, good, response) = construct_packet(self.network, self.byte_buffer)

            # If we haven't received a packet
            if good is None:
                continue

            # If the packet is corrupt
            if not good:
                # Resend message
                dispatch_packet(self.network, p)
                continue

            # Packet is good, so get the info
            (seq, type, msg) = RDT_3_0._get_packet_info(response)

            # If the packet is an ACK for this sequence
            if seq == self.seq_number and type == RDT_3_0.PACKET_ACK:
                # T'sall good
                return

            # If the response is a MESSAGE for a future sequence
            if seq > self.seq_number and type == RDT_3_0.PACKET_MESSAGE:
                # Receiver got the message (we must have not gotten a previous ACK), ignore and let calling function get ready
                self.seq_number += 1
                return

            # If the response is a MESSAGE for an old sequence
            if seq < self.seq_number and type == RDT_3_0.PACKET_MESSAGE:
                # We used to be a receiver, sender must have never gotten our ACK. Send message again
                dispatch_packet(self.network, p)
                continue

            print("UNEXPECTED STATE")
            exit(-1)

    def receive(self):
        # Try to get a response from the server
        (self.byte_buffer, good, packet) = construct_packet(self.network, self.byte_buffer)

        # If we haven't gotten a packet
        if good is None:
            return None

        # If the packet is corrupt
        if not good:
            # Let them send it again
            return None

        # Packet is good, so extract info
        (seq, type, msg) = RDT_3_0._get_packet_info(packet)

        # If the packet is a message for the current sequence
        if seq == self.seq_number and type == RDT_3_0.PACKET_MESSAGE:
            # Send ack, return message to calling function
            dispatch_packet(self.network, RDT_3_0._create_ack_packet(self.seq_number))
            self.seq_number += 1
            return msg

        # If the response is a MESSAGE for a future sequence
        if seq > self.seq_number and type == RDT_3_0.PACKET_MESSAGE:
            # Receiver got the message (we must missed a previous ACK), ignore and let calling function get ready
            self.seq_number += 1
            return

        # If the packet is a message for an old sequence
        if seq < self.seq_number and type == RDT_3_0.PACKET_MESSAGE:
            # Sender never got our ack, send it again to put them out of send state
            dispatch_packet(self.network, RDT_3_0._create_ack_packet(seq))
            return None

        print("UNEXPECTED STATE")
        exit(-1)


    @staticmethod
    def _get_packet_info(packet):
        return (packet.seq_num, int(packet.msg_S[0:RDT_3_0.PACKET_TYPE_LENGTH]), packet.msg_S[RDT_3_0.PACKET_TYPE_LENGTH:])


    @staticmethod
    def _create_message_packet(seq_num, msg_S):
        return Packet(seq_num, str(RDT_3_0.PACKET_MESSAGE).zfill(RDT_3_0.PACKET_TYPE_LENGTH) + msg_S)


    @staticmethod
    def _create_ack_packet(seq_num):
        return Packet(seq_num, str(RDT_3_0.PACKET_ACK).zfill(RDT_3_0.PACKET_TYPE_LENGTH))


if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT_1_0(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.receive())
        rdt.disconnect()

    else:
        sleep(1)
        print(rdt.receive())
        rdt.send('MSG_FROM_SERVER')
        rdt.disconnect()
