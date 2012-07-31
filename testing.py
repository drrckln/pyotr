import bencode
import requests
import sha
import struct
import socket
import twisted

def decode(file):
    torrent = bencode.bdecode(open(file, 'rb').read())
    return torrent

def handshake(file):
    info_hash = getdicthash(file)
    # open a socket, send this:
    return chr(19) + 'BitTorrent Protocol' + '\0'*8 + info_hash + '-TR2610-dfhmjb0skee6'

def announce(file):
    info_hash = getdicthash(file)
    torrent = decode(file)
    payload = {'info_hash': info_hash,
               'peer_id':'-TR2610-dfhmjb0skee6',
               'port':'6881',
               'uploaded':'0',
               'downloaded':'0',
               'key':'2c4dec5f',
               'left':'50000',
               'no_peer_id':'0',
               'event':'started',
               'compact':'1',
               'numwant':'30'}

    response = requests.get(torrent['announce'], params = payload)
    print response.content
    reply = bencode.bdecode(response.content)
    print reply.keys()
    print 'peers: ' + repr(reply['peers'])
    # print 'min interval: ' + str(reply['min interval'])
    print 'complete: ' + str(reply['complete'])
    print 'interval: ' + str(reply['interval'])
    # print 'downloaded: ' + str(reply['downloaded'])
    print 'incomplete: ' + str(reply['incomplete'])
    data = reply['peers']
    multiple = len(data)/6
    print struct.unpack("!" + "LH"*multiple, data)
    for i in range(0, multiple):
        print socket.inet_ntop(socket.AF_INET, data[6*i:6*i+4]) + ":" + repr(struct.unpack("!H", data[6*i+4:6*i+6])[0])
    ip =  socket.inet_ntop(socket.AF_INET, data[0:4])
    port = int(repr(struct.unpack("!H", data[4:6])[0]))

    msg = handshake('Sapolsky.mp4.torrent')

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    s.connect((ip, 51413))
    s.send(msg)
    print repr(msg)
    print "Received: %s" % s.recv(1024)
    

def getdicthash(file):
    contents = open(file, 'rb').read()
    start = contents.index('4:info') + 6
    end = -1
    dictliteral = contents[start:end]
    dictsha = sha.new(dictliteral)
    return dictsha.digest()




announce('Sapolsky.mp4.torrent')


def spliceshas(torrent):
    tor = bencode.bdecode(open(torrent, 'rb').read()) 
    print tor['info'].keys()
    pieces = tor['info']['pieces']
    pieceshas = []

    for i in range(len(pieces)/20):
       pieceshas.append(pieces[20*i:20*(i+1)])

    print pieceshas[0:3]




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
def handshake(file):
    info_hash = getdicthash(file)
    # open a socket, send this:
    return chr(19) + 'BitTorrent Protocol' + '\x00'*8 + info_hash + '-TR2610-dfhmjb0skee6'

'''


def message(peer, length, id, payload):
    # open socket, send
    # lengthprefix messageID payload
    # length 4 byte big endian
    # messageID 1 decimal byte

def keepalive(peer):
    message(peer, 0, 0, 0)

def choke(peer):
    message(peer, 1, 0, 0)

def unchoke(peer):
    message(peer, 1, 1, 0)

def interested(peer):
    message(peer, 1, 2, 0)

def notinterested(peer):
    message(peer, 1, 3, 0)

def have(peer):
    message(peer, 5, 4, pieceindex)

def bitfield(peer):
    message(peer, 0001+X, 5, bitfield)

def request(peer):
    message(peer, 0013, 6, index/begin/length)
    # index = integer specifying zero-based piece index
    # begin = integer specifying the zero-based byte offset within the piece
    # length = integer specifying the requested length

def piece(peer):
    message(peer, 0009+X, 7, index/begin/block)
    # block = block of data, which is a subset of the piece specified by index

def cancel(peer):
    message(peer, 0013, 8, index/begin/length)
    # used to cancel block requests. payload identical to 'request' message
'''
