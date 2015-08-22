require_relative 'main'

def serialize_header(inp)
	o = encode(inp['version'], 256, 4).reverse +
		inp['prevhash'].decode('hex').reverse +
		inp['merkle_root'].decode('hex').reverse +
		encode(inp['timestamp'], 256, 4).reverse +
		encode(inp['bits'], 256, 4).reverse +
		encode(inp['nonce'], 256, 4).reverse

	h = bin_dbl_sha256(o).reverse.encode('hex')

	return o.encode('hex')
end

def deserialize_header(inp)
	inp = inp.decode('hex')

	return {
		version: decode(inp[0..3].reverse, 256),
		prevhash: inp[4..36].reverse.encode('hex'),
		merkle_root: inp[37..68].reverse.encode('hex'),
		timestamp: decode(inp[69..72].reverse, 256),
		bits: decode(inp[73..76].reverse, 256),
		nonce: decode(inp[77..80].reverse, 256),
		hash: bin_dbl_sha256(inp).reverse.encode('hex')
	}
end

def mk_merkle_proof(header, hashes, index)
	nodes = hashes.map{|h| h.decode('hex')}

	if (nodes.length % 2) && (nodes.length > 2)
		nodes << nodes[-1]
	end

	layers = [nodes]

	while  nodes.length > 1
		newnodes = []
		(0..(nodes.length-1)).step(2) do |i|
			newnodes << bin_dbl_sha256(nodes[i] + nodes[i+1])
		end

		if (newnodes.length % 2) && (newnodes.length > 2)
			newnodes << newnodes[-1]
		end

		layers << [nodes]
	end

	raise "Invalid root" unless nodes[0].reverse.encode('hex') == header['merkle_root']

	merkle_siblings = (0..layers.length - 1).each{|i| [layers[i][(index >> i) ^ 1]]}

	return {
		hash: hashes[index],
		siblings: merkle_siblings.each{|s| s.reverse.encode('hex')},
		header: header
	}
end