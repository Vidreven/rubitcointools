require_relative 'hashes'
require 'test/unit'

class TestHashes < Test::Unit::TestCase

	def test_bin_hash160
		h = Hashes.new
		assert_equal(20, h.bin_hash160('123456789').length)
	end

	def test_ripemd160
		h = Hashes.new
		assert_equal(40, h.ripemd160('12345679').length)
	end

	def test_bin_sha256
		h = Hashes.new
		assert_equal(32, h.bin_sha256('12345679').length)
	end

	def test_bin_dbl_sha256
		h = Hashes.new
		assert_equal(h.bin_sha256(h.bin_sha256('123456789')), h.bin_dbl_sha256('123456789'))
	end

	def test_sha256
		h = Hashes.new
		assert_equal(64, h.sha256('123456789').length)
	end

	def test_bin_slowsha
		h = Hashes.new
		assert_not_equal('123456789', h.bin_slowsha('123456789'))
		assert_not_equal(h.bin_sha256('123456789'), h.bin_slowsha('123456789'))
		assert_not_equal(h.bin_dbl_sha256('123456789'), h.bin_slowsha('123456789'))
		assert_equal(32, h.bin_slowsha('123456789').length)
	end

	def test_slowsha
		h = Hashes.new
		assert_equal(64, h.slowsha('123456789').length)
	end
end