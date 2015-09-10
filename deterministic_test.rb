require_relative 'deterministic'
require_relative 'specials'
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
		vbytes = ["0488ade4", "0488b21e"]
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

	def test_bip32_serialize
		d = Deterministic.new
		sp = Specials.new
		vbytes = ["0488ade4", "0488b21e"]
		depth = 1
		fingerprint = 1.chr + 0.chr + 4.chr + 9.chr
		i = (1.chr).rjust(4, 0.chr)
		chaincode = 1.chr * 32
		privkey = sp.changebase('1111111111111111111111111111111111111111111111111111111111111111', 16, 256).map{|c| c.chr}.join
		x = sp.changebase('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16, 256).map{|c| c.chr}.join.rjust(33, 0.chr)
		privckd = d.bip32_serialize([vbytes[0], depth, fingerprint, i, chaincode, privkey])
		pubckd = d.bip32_serialize([vbytes[1], depth, fingerprint, i, chaincode, x])
		assert_match("xpub", pubckd)
	end

	def test_bip32_deserialize
		d = Deterministic.new
		sp = Specials.new
		vbytes = ["0488ade4", "0488b21e"]
		depth = 1
		fingerprint = 1.chr + 0.chr + 4.chr + 9.chr
		i = (1.chr).rjust(4, 0.chr)
		chaincode = 1.chr * 32
		privkey = sp.changebase('1111111111111111111111111111111111111111111111111111111111111111', 16, 256).map{|c| c.chr}.join
		x = sp.changebase('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16, 256).map{|c| c.chr}.join.rjust(33, 0.chr)
		privckd = d.bip32_serialize([vbytes[0], depth, fingerprint, i, chaincode, privkey])
		pubckd = d.bip32_serialize([vbytes[1], depth, fingerprint, i, chaincode, x])
		dpriv = d.bip32_deserialize(privckd)
		dpub = d.bip32_deserialize(pubckd)
		assert_equal(6, dpriv.length)
		assert_equal("4".hex.chr + "88".hex.chr + "ad".hex.chr + "e4".hex.chr, dpriv[0])
		assert_equal(depth.chr, dpriv[1])
		assert_equal(fingerprint, dpriv[2])
		assert_equal(i, dpriv[3])
		assert_equal(chaincode, dpriv[4])
		assert_equal(privkey, dpriv[5])
		assert_equal(x, dpub[5])
	end

	def test_raw_bip32_privtopub
		d = Deterministic.new
		vbytes = "0488ade4"
		depth = 1
		fingerprint = "11004499"
		i = 1
		chaincode = '1' * 64
		privkey = '1111111111111111111111111111111111111111111111111111111111111111'
		assert_equal(6, d.raw_bip32_privtopub([vbytes, depth, fingerprint, i, chaincode, privkey]).length)
		assert_equal(130, d.raw_bip32_privtopub([vbytes, depth, fingerprint, i, chaincode, privkey])[5].length)
	end

	def test_bip32_master_key
		d = Deterministic.new
		seed = "ab" * 64
		master = d.bip32_master_key(seed)
		assert_match('xprv', master)
	end
end