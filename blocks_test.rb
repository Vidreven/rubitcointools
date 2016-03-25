require_relative 'blocks'
require 'test/unit'

class TestBlocks < Test::Unit::TestCase

	def test_serialize_header
		b = Blocks.new
		version = '00000001'
		prevhash = '00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81'
		merkle_root = '2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3'
		timestamp = '4dd7f5c7'
		bits = '1a44b9f2'
		nonce = '9546a142'
		hash = '00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d'
		assert_equal(80, b.serialize_header({version: version, prevhash: prevhash, merkle_root: merkle_root, timestamp: timestamp, bits: bits, nonce: nonce, hash: hash}).length)
	end

	def test_deserialize_header
		b = Blocks.new
		version = '00000001'
		prevhash = '00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81'
		merkle_root = '2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3'
		timestamp = '4dd7f5c7'
		bits = '1a44b9f2'
		nonce = '9546a142'
		hash = '00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d'
		o = b.serialize_header({version: version, prevhash: prevhash, merkle_root: merkle_root, timestamp: timestamp, bits: bits, nonce: nonce, hash: hash})
		h = b.deserialize_header(o)
		assert_equal('00000001', h[:version])
		assert_equal(prevhash, h[:prevhash])
		assert_equal(merkle_root, h[:merkle_root])
		assert_equal(timestamp, h[:timestamp])
		assert_equal(bits, h[:bits])
		assert_equal(nonce, h[:nonce])
		assert_equal(hash, h[:hash])
	end

	def test_mk_merkle_proof
		b = Blocks.new
		version = '00000001'
		prevhash = '00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81'
		merkle_root = '2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3'
		timestamp = '4dd7f5c7'
		bits = '1a44b9f2'
		nonce = '9546a142'
		hash = '00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d'
		header = {version: version, prevhash: prevhash, merkle_root: merkle_root, timestamp: timestamp, bits: bits, nonce: nonce, hash: hash}
		hashes = ['51d37bdd871c9e1f4d5541be67a6ab625e32028744d7d4609d0c37747b40cd2d', '60c25dda8d41f8d3d7d5c6249e2ea1b05a25bf7ae2ad6d904b512b31f997e1a1',
				'01f314cdd8566d3e5dbdd97de2d9fbfbfd6873e916a00d48758282cbb81a45b9', 'b519286a1040da6ad83c783eb2872659eaf57b1bec088e614776ffe7dc8f6d01']
		index = 2
		merkle_proof = b.mk_merkle_proof(header, hashes, index)
		#assert_equal(header[:merkle_root], merkle_proof[:hash])
		assert_equal(hashes[index], merkle_proof[:hash])
		assert_equal(2, merkle_proof[:siblings].length)
	end
end