require_relative 'ecdsa'
require_relative 'ecc'
require_relative 'specials'
require_relative 'keys'
require 'test/unit'

class TestECDSA < Test::Unit::TestCase

	def test_encode_sig
		e = ECDSA.new
		r = '008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c7033'
		s = '3b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31'
		sig = e.encode_sig('30', r, s)

		# Minimum and maximum size constraints.
		assert_equal(false, sig.length > 142)
		assert_equal(false, sig.length < 18)
		# A signature is of type 0x30 (compound).
		assert_equal('30', sig[0..1])
		# Make sure the length covers the entire signature.
		assert_equal(sig[2..3].to_i(16) * 2, sig.length - 4)
		# Make sure the length of the S element is still inside the signature.
		assert_equal(true, 8 + sig[6..7].to_i(16) * 2 < sig.length - 2)
		# Verify that the length of the signature matches the sum of the length
		# of the elements.
		assert_equal(true, 8 + sig[6..7].to_i(16) * 2 + sig[76..77].to_i(16) * 2 == sig.length - 4)
		# Zero-length integers are not allowed for R.
		assert_not_equal(0, sig[6..7].to_i(16))
		# Negative numbers are not allowed for R.
		assert_not_equal(0x80, sig[8..9].to_i(16) & 0x80)
		# Zero-length integers are not allowed for S.
		assert_not_equal(0, sig[74..75].to_i(16))
		# Negative numbers are not allowed for S.
		assert_not_equal(0x80, sig[78..79].to_i(16) & 0x80)
	end

	def test_decode_sig
		e = ECDSA.new
		r = '008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c7033'
		s = '3b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31'
		assert_equal(['30', r, s], e.decode_sig(e.encode_sig('30', r, s)))
	end

	def test_deterministic_generate_k
		e = ECDSA.new
		priv = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262'
		msg1 = "76a914b8109afa1fa52d3a5fc9376a99d946ab0628eb0c88ac"
		msg2 = "76a9147bdade678c0d440012a266f8367cb42ad6d62daa88ac"
		msg3 = "76a914e31239e6c27baee56af5c112f123bac9d0df84f688ac"
		#assert_equal(32, e.deterministic_generate_k(Specials.new.random_string(16), priv).size)
		assert_equal(32, e.deterministic_generate_k(msg1, priv).size)
		k1 = e.deterministic_generate_k(msg1, priv)
		k2 = e.deterministic_generate_k(msg2, priv)
		k3 = e.deterministic_generate_k(msg3, priv)
		assert_not_equal(k1, k2)
		assert_not_equal(k2, k3)
		assert_not_equal(k1, k3)
	end

	def test_ecdsa_raw_sign
		e = ECDSA.new
		priv = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262'
		msg = "9302bda273a887cb40c13e02a50b4071a31fd3aae3ae04021b0b843dd61ad18e"
		#assert_equal(3, e.ecdsa_raw_sign(Specials.new.random_string(16), priv).length)
		signature = e.ecdsa_raw_sign(msg, priv)
		assert_equal(3, signature.length)
		assert_equal(31, signature[0])
		assert_equal(64, signature[1].length)
		assert_equal(64, signature[2].length)
	end

	def test_ecdsa_raw_verify
		e = ECDSA.new
		priv = '1111111111111111111111111111111111111111111111111111111111111111'
		x = '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a'
		y = 'a385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'
		sig = '304402202cb265bf10707bf49346c3515dd3d16fc454618c58ec0a0ff448a67654ff7130220' +
				'6c6624d762a1fcef4618284ead8f08678ac05b13c84235f1654e6ad168233e82'

		assert_equal(true, e.ecdsa_raw_verify(sig, e.ecdsa_raw_sign(sig, priv), x+y))
	end

	def test_ecdsa_raw_recover
		e = ECDSA.new

		sig = '304402202cb265bf10707bf49346c3515dd3d16fc454618c58ec0a0ff448a67654ff7130220' +
				'6c6624d762a1fcef4618284ead8f08678ac05b13c84235f1654e6ad168233e82'
		priv = '1111111111111111111111111111111111111111111111111111111111111111'
		x = '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a'
		y = 'a385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'
		a, b =  e.ecdsa_raw_recover(sig, e.ecdsa_raw_sign(sig, priv))
		#assert_equal(x+y, Keys.new.encode_pubkey([a, b], 'hex'))
	end
end