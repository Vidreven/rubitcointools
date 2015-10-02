require_relative 'ecdsa'
require_relative 'ecc'
require_relative 'specials'
require_relative 'keys'
require 'test/unit'

class TestECDSA < Test::Unit::TestCase

	def test_encode_sig
		e = ECDSA.new
		r = '316eb3cad8b66fcf1494a6e6f9542c3555addbf337f04b62bf4758483fdc881d'
		s = 'bf46d26cef45d998a2cb5d2d0b8342d70973fa7c3c37ae72234696524b2bc812'
		sig = e.encode_sig('30', r, s)
		assert_equal(false, sig.length > 142)
		assert_equal(false, sig.length < 18)
		assert_equal('30', sig[0..1])
		assert_equal(sig[2..3].to_i(16), sig.length - 2)
		assert_equal(true, 10 + sig[6..7].to_i(16) < sig.length - 2)
		assert_equal(true, 10 + sig[6..7].to_i(16) + sig[74..75].to_i(16) == sig.length - 2)
		assert_not_equal(0, sig[6..7].to_i(16))
		assert_not_equal(0x80, sig[10..11].to_i(16) & 0x80)
		assert_not_equal(0, sig[74..75].to_i(16))
		assert_not_equal(0x80, sig[78..79].to_i(16) & 0x80)
	end

	def test_decode_sig
		e = ECDSA.new
		r = '316eb3cad8b66fcf1494a6e6f9542c3555addbf337f04b62bf4758483fdc881d'
		s = 'bf46d26cef45d998a2cb5d2d0b8342d70973fa7c3c37ae72234696524b2bc812'
		assert_equal(['30', r, s], e.decode_sig(e.encode_sig('30', r, s)))
	end

	def test_deterministic_generate_k
		e = ECDSA.new
		priv = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262'
		assert_equal(32, e.deterministic_generate_k(Specials.new.random_string(16), priv).size)
	end

	def test_ecdsa_raw_sign
		e = ECDSA.new
		priv = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262'
		assert_equal(3, e.ecdsa_raw_sign(Specials.new.random_string(16), priv).length)
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