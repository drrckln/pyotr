import bencode
import requests
import sha
import struct
import socket
import Queue
import threading
import time
import os
from dns.inet import inet_ntop

''' Networking '''


def recvall(socket, expected):
    ''' Allows you to receive an expected amount off a socket '''
    data = ''
    while True:
        newdata = socket.recv(expected)
        data += newdata
        expected -= len(newdata)
        if not expected:
            break
    return data


''' Metainfo '''

class Torrent():
    ''' Holds torrent metainfo; can announce to tracker; stores peer list '''
    def decode(self, file_load):
        ''' Decodes the bencoded file, returns decoded dictionary '''
        torrent = bencode.bdecode(open(file_load, 'rb').read())
        return torrent

    def splice_shas(self, torrent):
        ''' Splices the SHA1 keys into a list '''
        pieces = torrent['info']['pieces']
        sha_list = []

        for i in range(len(pieces)/20):
           sha_list.append(pieces[20*i:20*(i+1)])
        return sha_list

    def getdicthash(self, file_load):
        ''' Returns the SHA1 hash of the 'info' key in the metainfo file '''
        contents = open(file_load, 'rb').read()
        start = contents.index('4:info') + 6
        end = -1
        dictliteral = contents[start:end]
        dictsha = sha.new(dictliteral)
        return dictsha.digest()

    def piece_list(self):
        piece_list = zip([x for x in range(len(self.sha_list))], self.sha_list)
        return piece_list

    def preallocate(self):
        self.write_target.write(bytearray(self.file_size))

    def __init__(self, file_load):
        self.torrent = self.decode(file_load)
        self.sha_list = self.splice_shas(self.torrent)
        self.info_hash = self.getdicthash(file_load)
        self.file_size = self.torrent['info']['length']
        self.pieces = self.torrent['info']['pieces']
        self.piece_length = self.torrent['info']['piece length']
        self.file_name = self.torrent['info']['name']
        self.piece_list = self.piece_list()
        self.write_target = open(os.getcwd() + '/' + self.file_name, 'wb+')
        self.piece_queue = Queue.Queue()
        self.write_queue = Queue.Queue()
        self.preallocate()
        self.peer_list = []


    def announce(self):
        ''' Announces to a tracker

        Currently returns 1 peer's IP and port, hardcoded '''
        payload = {'info_hash': self.info_hash,
                   'peer_id':'-PYOTR0-dfhmjb0skee6',
                   'port':'6881',
                   'uploaded':'0',
                   'downloaded':'0',
                   'key':'2c4dec5f',
                   'left': len(self.sha_list),
                   'no_peer_id':'0',
                   'event':'started',
                   'compact':'1',
                   'numwant':'30'}

        response = requests.get(self.torrent['announce'], params = payload)
        reply = bencode.bdecode(response.content)
        print("""
    Response received, decoded..
    peers: {0}
    complete: {1}
    interval: {2}
    incomplete: {3}
    """.format(repr(reply['peers']), reply['complete'], reply['interval'], reply['incomplete']))

        data = reply['peers']
        multiple = len(data)/6
        #print struct.unpack("!" + "LH"*multiple, data)
        print "Converting 'peers' to more readable form:"
        for i in range(0, multiple):
            self.peer_list.append((inet_ntop(2, data[6*i:6*i+4]), struct.unpack("!H", data[6*i+4:6*i+6])[0]))
        print self.peer_list



''' Peer '''

class Peer():
    ''' Describes the essential info/state of the peer-bound-to-single-torrent '''
    def __init__(self, info_hash, ip, port, piece_queue, write_queue):
        self.info_hash = info_hash
        self.ip = ip
        self.port = port
        self.piece_queue = piece_queue
        self.write_queue = write_queue
        self.bitfield = None


''' Writing Thread '''

class Writer (threading.Thread):
    ''' Thread that writes data to disk from finished pieces queue (aka write_queue) '''
    # currently for one file, how do I decouple?
    def __init__(self, write_target, write_queue, piece_length, piece_queue):
        threading.Thread.__init__(self)
        self.write_target = write_target
        self.write_queue = write_queue
        self.piece_length = piece_length
        self.piece_queue = piece_queue

    def run(self):
        while True:
            if not self.write_queue.empty():
                index, current_piece = self.write_queue.get()
                self.write_target.seek(index*piece_length, 0)
                self.write_target.write(current_piece)
                print "wrote a piece", index
                self.write_queue.task_done()
            if self.piece_queue.empty():
                return

''' Sending Thread '''

class Sender(threading.Thread):
    ''' Sends all messages '''
    def __init__(self, socket):
        threading.Thread.__init__(self)
        self.socket = socket
        self.cmd_q = Queue.Queue()

    def send(self, msg):
        self.socket.sendall(msg)

    def handshake(self):
        ''' Initiates handshake with peer '''
        msg = chr(19) + 'BitTorrent protocol' + '\x00'*8 + torrent.info_hash + '-PYOTR0-dfhmjb0skee6'
        return msg
        # print "Handshake rcvd: %s" % repr(socket.recv(68))

    def have(self, piece):
        ''' Constructs msg for sending a 'have piece' msg to a peer '''
        msg = struct.pack('!L', 5) + chr(4) + struct.pack('!L', piece)

    # the length is incorrect. why?
    def bitfield(self):
        ''' Sends bitfield '''
        length = len(pieces)/20
        msg = struct.pack('!L', length+1) + chr(5) + '\x00'*(length-1)
        return msg

    def request(self, piece, offset, length):
        ''' Constructs msg for requesting a block from a peer '''
        msg = struct.pack('!L', 13) + chr(6) + struct.pack('!LLL', piece, offset, length)
        return msg

    def run(self):
        while True:
            if not self.orders.empty():
                flag, data = self.orders.get()




''' Receiving Thread '''

class Receiver(threading.Thread):
    ''' Flags and deals with received messages '''
    def __init__(self, socket):
        threading.Thread.__init__(self)
        self.socket = socket
        self.cmd_q = Queue.Queue()

    def flagmsg(self, socket):
        ''' Takes a bit off socket buffer; returns a tuple of the action and the data from a socket

        BLOCKS'''
        first  = socket.recv(4)
        length = struct.unpack('!L', first)[0]
        id_data = recvall(socket, length)
        if id_data == '':
            return
        id = id_data[0]
        data = id_data[1:]
        id_dict1 = {'\x01': 'unchoke', '\x00': 'choke', '\x03': 'not interested', '\x02': 'interested'}
        id_dict2 = {'\x05': 'bitfield', '\x04': 'have', '\x07': 'piece', '\x06': 'request', '\x08': 'cancel'}
        if id in id_dict1:
            return (id_dict1[id], None)
        else:
            return (id_dict2[id], data)


    def receive_loop(self, index):
        ''' Gets multiple blocks now '''
        if piece_queue.empty():
            piece_data = [None]*(file_size%piecelength)
        else: piece_data = [None]*piece_length
        while True:
            flag, data = self.flagmsg(self.s)
            print "Message type:", flag
            if flag == 'choke':
                print 'Peer choked us! :('
            elif flag == 'unchoke':
                ''' If unchoked, send a request! '''
                print 'Peer unchoked us!'
                time.sleep(1)
                print 'Requesting block'
                self.s.sendall(request(index, 0, 16384))
                # we don't actually need this, can get from length of data. attribute it?
            elif flag == 'interested':
                print "Peer wants stuff we have."
            elif flag == 'not interested':
                print "Peer is not interested in what we have so far."
            elif flag == 'have':
                print "Peer now has this piece"
            elif flag == 'bitfield':
                num = int(data.encode('hex'), 16)
                bitfield = bin(num)[2:len(sha_list)+2]
                bfield = [ (True if x == '1' else False) for x in bitfield ]
                print bitfield
                time.sleep(1)
            elif flag == 'request':
                break
            elif flag == 'piece':
                piece, offset = struct.unpack('!LL', data[:8])
                print repr(data[:20])
                print "Piece Index: ", piece
                print "Offset:", offset
                #print "Length sent:",len(data[8:])
                piece_data[offset:offset+16384] = data[8:]
                if None not in piece_data:
                    print "yay! finished a piece!"
                    break
                self.s.sendall(request(index, offset+16384, 16384))
            elif flag == 'cancel':
                print "Peer cancelled request for this piece"
        return piece_data

    def run(self):
        return



''' Connection Thread '''

class Connection(threading.Thread):
    ''' Controls the connection to a single peer
    also instantiates Send and Receive objects'''
    def __init__(self, peer):
        ''' Starts a socket, Sender thread, and Receiver thread '''
        threading.Thread.__init__(self)
        self.p = peer
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sendr = Sender(self.s)
        self.recvr = Receiver(self.s)
        self.sendr.start()
        self.recvr.start()

    def run(self):
        try:
            self.s.connect((self.p.ip, self.p.port))
            self.recvr.handshake(self.s)
            #bitfield(self.s)  # don't need it, can't get it right, gets us kicked
        except socket.error as e:
            print e.__class__
            print "Couldn't connect"
            self.s.close()
            return
        while not self.piece_queue.empty():
            index, now_sha = self.piece_queue.get()
            self.s.sendall(make_request(index, 0, 16384))
            print index
            try:
                current_piece = self.receive_loop(index)
            except:
                print "Failed connection"
                failed = index, now_sha
                self.piece_queue.task_done()
                self.piece_queue.put(failed)
                return
                #thread.exit() also works?
            current_piece = "".join(current_piece)
            piece_sha = sha.new(current_piece).digest()
            if now_sha == piece_sha:
                print "SHA1 matches for piece", index
                self.write_queue.put((index, current_piece))
                self.s.sendall(make_have(index))
                self.piece_queue.task_done()
            else:
                print "Failed SHA1 check :("
                failed = index, now_sha
                self.piece_queue.task_done()
                self.piece_queue.put(failed)






''' MAIN '''

def handshake():
    ''' Initiates handshake with peer '''
    msg = chr(19) + 'BitTorrent protocol' + '\x00'*8 + torrent.info_hash + '-PYOTR0-dfhmjb0skee6'
    return msg

def request(piece, offset, length):
    ''' Constructs msg for requesting a block from a peer '''
    msg = struct.pack('!L', 13) + chr(6) + struct.pack('!LLL', piece, offset, length)
    return msg

if __name__ == "__main__":
    file_load = 'Sapolsky.mp4.torrent'
    print "Preparing to download", file_load
    torrent = Torrent(file_load)
    torrent.announce()

    for piece in torrent.piece_list:
        torrent.piece_queue.put(piece)

    peers = []

    for (ip, port) in torrent.peer_list:
        peers.append(Peer(torrent.info_hash, ip, port, torrent.piece_queue, torrent.write_queue))

    print peers
    print ""

    # Starts the Writer thread for this file
    print "Starting Writer thread.."
    write_thread = Writer(torrent.write_target, torrent.write_queue, torrent.piece_length, torrent.piece_queue)
    write_thread.setDaemon(True)
    write_thread.start()

    # testing
    ip, port = torrent.peer_list[1]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.sendall(handshake())
    print "Handshake rcvd: %s" % repr(s.recv(68))
    time.sleep(2)

    while not torrent.piece_queue.empty():
        index, now_sha = torrent.piece_queue.get()
        s.sendall(request(index, 0, 16384))
        time.sleep(0.5)
        torrent.piece_queue.task_done()

    #print "Starting Peer threads.."
    #for peer in peers:
    #    thread = Connection(peer)
    #    thread.setDaemon(True)
    #    thread.start()

    #print "Spinning up threads. Some will fail, since peer won't take two connections."
    #print ""
    #for (ip, port) in torrent.peer_list:
    #    t = Connection(piece_queue, ip, port)
    #    t.setDaemon(True)
    #    t.start()

    torrent.piece_queue.join()
    write_thread.join()


    print "File downloaded and verified!"


'''

  # testing
    ip, port = torrent.peer_list[1]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.sendall(handshake())
    print "Handshake rcvd: %s" % repr(s.recv(68))
    time.sleep(2)

    while not torrent.piece_queue.empty():
        index, now_sha = torrent.piece_queue.get()
        s.sendall(request(index, 0, 16384))
        time.sleep(0.5)
        torrent.piece_queue.task_done()
'''
