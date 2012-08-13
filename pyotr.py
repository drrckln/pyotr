import bencode
import requests
import sha
import struct
import socket
import Queue
import threading
import time
import random
import os

''' Metainfo '''

def decode(file_load):
    ''' Decodes the bencoded file, returns decoded dictionary '''
    torrent = bencode.bdecode(open(file_load, 'rb').read())
    return torrent


def splice_shas(torrent):
    ''' Splices the SHA1 keys into a list '''
    pieces = metainfo['info']['pieces']
    sha_list = []

    for i in range(len(pieces)/20):
       sha_list.append(pieces[20*i:20*(i+1)])
    return sha_list


def getdicthash(file_load):
    ''' Returns the SHA1 hash of the 'info' key in the metainfo file '''
    contents = open(file_load, 'rb').read()
    start = contents.index('4:info') + 6
    end = -1
    dictliteral = contents[start:end]
    dictsha = sha.new(dictliteral)
    return dictsha.digest()



''' Networking? '''


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


''' Tracker '''


def announce(file_load):
    ''' Announces to a tracker 
    
    Currently returns 1 peer's IP and port, hardcoded '''
    torrent = decode(file_load)
    left = len(sha_list)
    payload = {'info_hash': info_hash,
               'peer_id':'-PYOTR0-dfhmjb0skee6',
               'port':'6881',
               'uploaded':'0',
               'downloaded':'0',
               'key':'2c4dec5f',
               'left': left,
               'no_peer_id':'0',
               'event':'started',
               'compact':'1',
               'numwant':'30'}
    
    print "Announcing to tracker in:"
    for count_down in range(3, 0, -1):
        time.sleep(1)
        print count_down
    
    response = requests.get(torrent['announce'], params = payload)
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
        print socket.inet_ntop(socket.AF_INET, data[6*i:6*i+4]) + ":" + repr(struct.unpack("!H", data[6*i+4:6*i+6])[0])
    print
    ip =  socket.inet_ntop(socket.AF_INET, data[0:4])
    port = int(repr(struct.unpack("!H", data[4:6])[0]))
    return (ip, port)











''' Peer '''

def handshake(socket):
    ''' Initiates handshake with peer '''
    info_hash = getdicthash('Sapolsky.mp4.torrent')    
    msg = chr(19) + 'BitTorrent protocol' + '\x00'*8 + info_hash + '-PYOTR0-dfhmjb0skee6'
    print "Beginning handshake with peer"
    socket.send(msg)
    print "Handshake sent: ", repr(msg)
    print "Handshake rcvd: %s" % repr(socket.recv(4096))

def make_have(piece):
    ''' Constructs msg for sending a 'have piece' msg to a peer '''
    return struct.pack('!L', 5) + chr(4) + struct.pack('!L', piece)


def make_request(piece, offset, length):
    ''' Constructs msg for requesting a block from a peer '''
    return struct.pack('!L', 13) + chr(6) + struct.pack('!LLL', piece, offset, length)

def flagmsg(socket):
    ''' Takes a bit off socket buffer; returns a tuple of the action and the data from a socket

    BLOCKS'''
    first  = socket.recv(4)
    length = struct.unpack('!L', first)[0]
    id_data = recvall(socket, length)
    if id_data == '':
        return
    id = id_data[0]
    data = id_data[1:]
    if id == '\x00':
        return ('choke', None)
    elif id == '\x01':
        return ('unchoke', None)
    elif id == '\x02':
        return ('interested', None)
    elif id == '\x03':
        return ('not interested', None)
    elif id == '\x04':
        return ('have', data)
    elif id == '\x05':
        return ('bitfield', data)
    elif id == '\x06':
        return ('request', data)
    elif id == '\x07':
        return ('piece', data)
    elif id == '\x08':
        return ('cancel', data)


def receive_loop(index, socket):
    ''' Currently hardcodes for first data block '''
    if piece_queue.empty():
        piece_data = [None]*(file_size%piecelength)
    else: piece_data = [None]*piece_length
    last_req_length = 16384
    while True:
        flag, data = flagmsg(socket)
        print "Message type:", flag
        if flag == 'choke':
            print 'Peer choked us! :('
        elif flag == 'unchoke':
            ''' If unchoked, send a request! '''
            print 'Peer unchoked us!'
            time.sleep(1)
            print 'Requesting block'
            socket.sendall(make_request(index, 0, 16384))
            last_req_length = 16384
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
            time.sleep(2)
            print "\nThis peer is a seeder"
            time.sleep(2)
        elif flag == 'request':
            break
        elif flag == 'piece':
            piece, offset = struct.unpack('!LL', data[:8])
            print repr(data[:20])
            print "Piece Index: ", piece 
            print "Offset:", offset
            print ""  
            #print "Length sent:",len(data[8:])
            piece_data[offset:offset+last_req_length] = data[8:]
            if None not in piece_data:
                print "yay! finished a piece!"
                break
            first_blank = piece_data.index(None)
            size_left = piece_data.count(None)
            socket.sendall(make_request(index, first_blank, min(16384, size_left)))
            last_req_length = min(16384, size_left)
        elif flag == 'cancel':
            print "Peer cancelled request for this piece"
    return piece_data



''' CLASS STUFF '''

class PeerConnection(threading.Thread):
    ''' Grab blocks from peers, pulling indices off queue '''
    def __init__(self, piece_queue, ip, port):
        threading.Thread.__init__(self)
        self.write_target = write_target
        self.piece_queue = piece_queue
        self.port = port
        self.ip = ip
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.ip, self.port))
        handshake(self.s)
    
    def run(self):
        while not piece_queue.empty():
            index, now_sha = self.piece_queue.get()
            self.s.sendall(make_request(index, 0, 16384))
            current_piece = receive_loop(index, self.s)
            current_piece = "".join(current_piece)
            piece_sha = sha.new(current_piece).digest()
            if now_sha == piece_sha:
                print "SHA1 matches for piece", index
                print ""
                self.write_target.seek(index*piece_length, 0)
                self.write_target.write(current_piece)
                self.s.sendall(make_have(index))
                self.piece_queue.task_done()
            else:
                print "Failed SHA1 check :("
                print ""
                failed = index, now_sha
                self.piece_queue.task_done()
                self.piece_queue.put(failed)


''' MAIN '''
file_load = 'Sapolsky.mp4.torrent'
print "Loaded", file_load
print

piece_queue = Queue.Queue()
metainfo = decode(file_load)
file_size = metainfo['info']['length']
info_hash = getdicthash(file_load)
piece_length = metainfo['info']['piece length']
name = metainfo['info']['name']
# preallocates a file size... just one file though
write_target = open(os.getcwd() + '/' + name, 'wb+')
allocation = bytearray(file_size)
write_target.write(allocation)


sha_list = splice_shas(file_load)
piece_list = zip([x for x in range(len(sha_list))], sha_list)
random.shuffle(piece_list)
print "Pieces currently download in random order. Shuffling into queue.."
time.sleep(1)
for piece in piece_list:
    piece_queue.put(piece)


ip, port = announce(file_load)


print "Spinning up two threads. One will fail, since peer won't take two connections."
print ""
for i in range(2):
    t = PeerConnection(piece_queue, ip, 51413)
    t.setDaemon(True)
    t.start()


piece_queue.join()


print "FILE FULLY DOWNLOADED (though not yet written)"





'''
class Peer(Protocol):
    def __init__(self, address):
        self.write(handshake?)
    def dataReceived(self, data):
        self.data += data
        # bunch of if statements

class PeerFactory():
    def buildProtocol(address):
        Peer(address)

if __name__ == '__main__':
    fac = PeerFactory()
    for peer in peerList
        fac.buildProtocol(peer)

'''

