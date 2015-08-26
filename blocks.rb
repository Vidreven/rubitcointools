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
		inp = @sp.changebase(inp, 256, 16) #inp.decode('hex')

		return {
			version: @sp.change_endianness(inp[0..7]),
			prevhash: @sp.change_endianness(inp[8..71]),
			merkle_root: @sp.change_endianness(inp[72..136]),
			timestamp: @sp.change_endianness(inp[137..145]),
			bits: @sp.change_endianness(inp[146..154]),
			nonce: @sp.change_endianness(inp[155..-1]),
			#hash: bin_dbl_sha256(inp).reverse.encode('hex')
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
end

# p Blocks.new.serialize_header({version: 3, prevhash: Specials.new.decode('81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000'.reverse, 16),
# 	merkle_root: Specials.new.decode('e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b'.reverse, 16),
# 	timestamp: Specials.new.decode('c7f5d74d', 16), bits: Specials.new.decode('f2b9441a', 16), nonce: Specials.new.decode('42a14695', 16),
# 	hash: Specials.new.decode('00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d', 16)})

#p Specials.new.decode('4dd7f5c7', 16)
#p ['c7f5d74d'].pack('H*').unpack('N*').pack('V*').unpack('H*')