import bencode

torrent = bencode.bdecode(open('/Users/derrickl/Desktop/Sapolsky.mp4.torrent', 'rb').read())

print torrent.keys()

print torrent['info'].keys()

pieces = torrent['info']['pieces']

print len(pieces)

pieceshas = []

for i in range(len(pieces)/20):
    
