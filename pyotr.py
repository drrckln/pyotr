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
    peer_list = []
    for i in range(0, multiple):
        peer_list.append((socket.inet_ntop(socket.AF_INET, data[6*i:6*i+4]), struct.unpack("!H", data[6*i+4:6*i+6])[0]))
    print peer_list
    #ip =  socket.inet_ntop(socket.AF_INET, data[0:4])
    #port = int(repr(struct.unpack("!H", data[4:6])[0]))
    return peer_list


''' Peer '''

def handshake(socket):
    ''' Initiates handshake with peer '''
    info_hash = getdicthash(file_load)    
    msg = chr(19) + 'BitTorrent protocol' + '\x00'*8 + info_hash + '-PYOTR0-dfhmjb0skee6'
    print "Beginning handshake with peer"
    socket.send(msg)
    print "Handshake sent: ", repr(msg)
    print "Handshake rcvd: %s" % repr(socket.recv(68))

def make_have(piece):
    ''' Constructs msg for sending a 'have piece' msg to a peer '''
    return struct.pack('!L', 5) + chr(4) + struct.pack('!L', piece)

# the length is incorrect. why?
def bitfield(socket):
    ''' Sends bitfield '''
    length = len(pieces)/20
    print length
    msg = struct.pack('!L', length+1) + chr(5) + '\x00'*(length-1)
    socket.send(msg)
    
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
    id_dict1 = {'\x01': 'unchoke', '\x00': 'choke', '\x03': 'not interested', '\x02': 'interested'}
    id_dict2 = {'\x05': 'bitfield', '\x04': 'have', '\x07': 'piece', '\x06': 'request', '\x08': 'cancel'}
    if id in id_dict1:
    	return (id_dict1[id], None)
    else:
		return (id_dict2[id], data)


def receive_loop(index, socket):
    ''' Gets multiple blocks now '''
    if piece_queue.empty():
        piece_data = [None]*(file_size%piecelength)
    else: piece_data = [None]*piece_length
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
            socket.sendall(make_request(index, offset+16384, 16384))
        elif flag == 'cancel':
            print "Peer cancelled request for this piece"
    return piece_data



''' CLASS STUFF '''

class PeerConnection(threading.Thread):
    ''' Grab blocks from peers, pulling indices off queue '''
    def __init__(self, piece_queue, ip, port):
        threading.Thread.__init__(self)
        self.piece_queue = piece_queue
        self.write_queue = write_queue
        self.port = port
        self.ip = ip

    def run(self):
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect((self.ip, self.port))
            handshake(self.s)
            #bitfield(self.s)
            # don't need it, can't get it right, gets us kicked
        except:
            print "Couldn't connect"
            return
        while not piece_queue.empty():
            index, now_sha = self.piece_queue.get()
            print index
            try:
                current_piece = receive_loop(index, self.s)
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
                
class Writer (threading.Thread):
    def __init__(self, write_target, write_queue, piece_length):
        threading.Thread.__init__(self)
        self.write_target = write_target
        self.write_queue = write_queue
        self.piece_length = piece_length
  
    def run(self):
        while True:
            if not self.write_queue.empty():
                index, current_piece = self.write_queue.get()
                self.write_target.seek(index*piece_length, 0)
                self.write_target.write(current_piece)
                print "wrote a piece!"
            if piece_queue.empty():
                return


''' MAIN '''
file_load = 'Sapolsky.mp4.torrent'
print "Loaded", file_load
piece_queue = Queue.Queue()
metainfo = decode(file_load)
file_size = metainfo['info']['length']
info_hash = getdicthash(file_load)
pieces = metainfo['info']['pieces']
piece_length = metainfo['info']['piece length']
name = metainfo['info']['name']
# preallocates a file size... just one file though
write_target = open(os.getcwd() + '/' + name, 'wb+')
write_target.write(bytearray(file_size))
write_queue = Queue.Queue()

sha_list = splice_shas(file_load)
piece_list = zip([x for x in range(len(sha_list))], sha_list)
random.shuffle(piece_list)
print "Pieces currently download in random order. Shuffling into queue.."
time.sleep(1)
for piece in piece_list:
    piece_queue.put(piece)


peer_list = announce(file_load)


write_thread = Writer(write_target, write_queue, piece_length)
write_thread.setDaemon(True)
write_thread.start()

print "Spinning up threads. Some will fail, since peer won't take two connections."
print ""
for (ip, port) in peer_list:
    t = PeerConnection(piece_queue, ip, port)
    t.setDaemon(True)
    t.start()

piece_queue.join()
write_thread.join()

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

