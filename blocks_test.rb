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
end