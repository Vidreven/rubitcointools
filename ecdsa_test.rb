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
		priv = Specials.new.decode('E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262', 16)
		assert_equal(32, e.deterministic_generate_k(Specials.new.random_string(16), priv).size)
	end

	def test_ecdsa_raw_sign
		e = ECDSA.new
		priv = Specials.new.decode('E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262', 16)
		assert_equal(3, e.ecdsa_raw_sign(Specials.new.random_string(16), priv).length)
	end

	def test_ecdsa_raw_verify
		e = ECDSA.new
		r = Specials.new.decode('316eb3cad8b66fcf1494a6e6f9542c3555addbf337f04b62bf4758483fdc881d', 16)
		s = Specials.new.decode('bf46d26cef45d998a2cb5d2d0b8342d70973fa7c3c37ae72234696524b2bc812', 16)
		x = Specials.new.decode('0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179', 16)
		y = Specials.new.decode('8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16)
		msghash = Specials.new.random_string(16)
		assert_equal(false, e.ecdsa_raw_verify(msghash, [30, r, s], [x, y]))
	end

	def test_ecdsa_raw_recover
		e = ECDSA.new
		r = Specials.new.decode('316eb3cad8b66fcf1494a6e6f9542c3555addbf337f04b62bf4758483fdc881d', 16)
		s = Specials.new.decode('bf46d26cef45d998a2cb5d2d0b8342d70973fa7c3c37ae72234696524b2bc812', 16)
		msghash = Specials.new.random_string(16)
		assert_equal(false, e.ecdsa_raw_recover(msghash, [30, r, s]))
	end
end