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
end