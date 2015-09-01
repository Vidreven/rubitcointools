require_relative 'specials'

class Blocks

	def initialize
		@sp = Specials.new
		@h = Hashes.new
	end

	def serialize_header(inp)

		o = @sp.change_endianness(inp[:version]) +
			@sp.change_endianness(inp[:prevhash]) +
			@sp.change_endianness(inp[:merkle_root]) +
			@sp.change_endianness(inp[:timestamp]) +
			@sp.change_endianness(inp[:bits]) +
			@sp.change_endianness(inp[:nonce])

		o = @sp.changebase(o, 16, 256).map{|c| c.chr}.join
		h = @sp.changebase(@h.bin_dbl_sha256(o), 256, 16)

		raise "Incorrect hash " + h unless @sp.change_endianness(h) == inp[:hash]

		return o
	end

	def deserialize_header(inp)
		h = @sp.changebase(@h.bin_dbl_sha256(inp), 256, 16)
		inp = @sp.changebase(inp, 256, 16)

		return {
			version: @sp.change_endianness('0' + inp[0..6]), # a hack to make the length 4 bytes
			prevhash: @sp.change_endianness(inp[7..70]),
			merkle_root: @sp.change_endianness(inp[71..134]),
			timestamp: @sp.change_endianness(inp[135..142]),
			bits: @sp.change_endianness(inp[143..150]),
			nonce: @sp.change_endianness(inp[151..-1]),
			hash: @sp.change_endianness(h)
		}
	end

	# Returns a Merkle path of the transaction to the root?
	def mk_merkle_proof(header, hashes, index)
		nodes = hashes.map{|h| @sp.change_endianness(h)}
		nodes = nodes.map{|h| @sp.changebase(h, 16, 256).map{|c| c.chr}.join}

		if (nodes.length % 2 == 1) && (nodes.length > 2)
			nodes << nodes[-1]
		end

		layers = nodes

		while  nodes.length > 1
			newnodes = []
			(0..nodes.length-1).step(2) do |i|
				newnodes << @h.bin_dbl_sha256(nodes[i] + nodes[i+1])
			end

			if (newnodes.length % 2 == 1) && (newnodes.length > 2)
				newnodes << newnodes[-1]
			end

			nodes = newnodes
			layers << [nodes]
		end

		raise "Invalid root" unless @sp.changebase(nodes[0].reverse, 256, 16) == header[:merkle_root]

		merkle_siblings = 2 #(0..layers.length - 1).each{|i| [layers[i][(index >> i) ^ 1]]}

		return {
			hash: @sp.changebase(nodes[0].reverse, 256, 16), #hashes[index],
			siblings: merkle_siblings, #.each{|s| s.reverse.encode('hex')},
			header: header
		}
	end
end