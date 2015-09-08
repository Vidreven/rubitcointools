require_relative 'deterministic'
require 'test/unit'

class TestDeterministic < Test::Unit::TestCase

	def test_electrum_stretch
		d = Deterministic.new
		assert_equal(64, d.electrum_stretch('123456789').length)
	end

	def test_electrum_mpk
		d = Deterministic.new
		seed = '1111111111111111111111111111111111111111111111111111111111111111'
		assert_equal(128, d.electrum_mpk(seed).length)
	end

	def test_electrum_privkey
		d = Deterministic.new
		seed = '1111111111111111111111111111111111111111111111111111111111111111'
		assert_equal(64, d.electrum_privkey(seed, 1).length)
	end

	def test_electrum_pubkey
		d = Deterministic.new
		x = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179'
		y = '8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
		assert_equal(130, d.electrum_pubkey(x+y, 1).length)
	end

	def test_electrum_address
		d = Deterministic.new
		x = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179'
		y = '8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
		assert_equal("1", d.electrum_address(x+y, 1)[0])
	end

	def test_raw_bip32_ckd
		d = Deterministic.new
		vbytes = ["\x04\x88\xAD\xE4", "\x04\x88\xB2\x1E"]
		depth = 1
		fingerprint = "ABCDEFBA"
		i = 0
		chaincode = '1' * 64
		x = '0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179'
		y = '8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
		pubkey = x + y
		privkey = '1111111111111111111111111111111111111111111111111111111111111111'
		pubckd = d.raw_bip32_ckd([vbytes[1], depth, fingerprint, i, chaincode, pubkey], i)
		privckd = d.raw_bip32_ckd([vbytes[0], depth, fingerprint, i, chaincode, privkey], i)
		assert_equal(6, pubckd.length)
		assert_equal(6, privckd.length)
		assert_equal(vbytes[1], pubckd[0])
		assert_equal(2, pubckd[1])
		assert_equal(4, pubckd[2].length)
		assert_equal(32, pubckd[4].length)
		assert_equal(65, pubckd[5].length)
		assert_equal(32, privckd[4].length)
	end
end