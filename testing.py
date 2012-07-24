import bencode
import requests
import sha

def decode(file):
    torrent = bencode.bdecode(open(file, 'rb').read())
    return torrent

def announce(file):
    info_hash = getdicthash(file)
    torrent = decode(file)
    payload = {'info_hash': info_hash,
               'peer_id':'-TR2610-dfhmjb0skee6',
               'port':'6881',
               'uploaded':'0',
               'downloaded':'0',
               'key':'2c4dec5f',
               'left':'0',
               'no_peer_id':'0',
               'event':'started',
               'numwant':'80'}

    response = requests.get(torrent['announce'], params = payload)
    print response.content
    reply = bencode.bdecode(response.content)
    print reply.keys()
    print 'peers: ' + str(reply['peers'])
    print 'min interval: ' + str(reply['min interval'])
    print 'complete: ' + str(reply['complete'])
    print 'interval: ' + str(reply['interval'])
    print 'downloaded: ' + str(reply['downloaded'])
    print 'incomplete: ' + str(reply['incomplete'])


def getdicthash(file):
    contents = open(file, 'rb').read()
    start = contents.index('4:info') + 6
    end = -1
    dictliteral = contents[start:end]
    dictsha = sha.new(dictliteral)
    return dictsha.digest()




announce('Sapolsky.mp4.torrent')


def spliceshas(torrent):
    pieceshas = []

    for i in range(len(pieces)/20):
       pieceshas.append(pieces[20*i:20*(i+1)])

    print pieceshas[0:3]
