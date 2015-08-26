require_relative 'blocks'
require 'test/unit'

class TestBlocks < Test::Unit::TestCase

	def test_serialize_header
		b = Blocks.new
		version = '00000001'
		prevhash = '00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81' #'81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000'
		merkle_root = '2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3' #'e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b'
		timestamp = '4dd7f5c7' #'c7f5d74d'
		bits = '1a44b9f2' #'f2b9441a'
		nonce = '9546a142' #'42a14695'
		hash = '00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d'
		assert_equal(80, b.serialize_header({version: version, prevhash: prevhash, merkle_root: merkle_root, timestamp: timestamp, bits: bits, nonce: nonce, hash: hash}).length)
	end
end