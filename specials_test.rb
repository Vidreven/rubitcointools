require_relative 'specials'
require 'test/unit'

class TestSpecials < Test::Unit::TestCase

	def test_get_code_string
		@sp = Specials.new
		assert_match('0123456789', @sp.get_code_string(10))
		assert_equal(2, @sp.get_code_string(2).length)
		assert_equal(10, @sp.get_code_string(10).length)
		assert_equal(16, @sp.get_code_string(16).length)
		assert_equal(32, @sp.get_code_string(32).length)
		assert_equal(58, @sp.get_code_string(58).length)
		assert_equal(256, @sp.get_code_string(256).length)
	end

	def test_decode
		@sp = Specials.new
		assert_equal(10, @sp.decode('1010', 2))
		assert_equal(60, @sp.decode('3C', 16))
		assert_equal(55, @sp.decode('55', 10))
		assert_equal(32, @sp.decode('ba', 32))
		assert_equal(256, @sp.decode(1.chr + 0.chr, 256))
	end

	def test_encode
		@sp = Specials.new
		assert_equal('34', @sp.encode(34, 10))
		assert_equal('1010', @sp.encode(10, 2))
		assert_equal('1010', @sp.encode(@sp.decode('1010', 2), 2))
		assert_equal('3c', @sp.encode(@sp.decode('3C', 16), 16))
		assert_equal('ba', @sp.encode(@sp.decode('ba', 32), 32))
		assert_equal(1.chr + 0.chr, @sp.encode(256, 256))
		assert_equal(0.chr + 1.chr + 0.chr, @sp.encode(256, 256, 3))
	end

	def test_changebase
		@sp = Specials.new
		assert_match('10000', @sp.changebase("10", 16, 2))
		assert_match('10', @sp.changebase("10000", 2, 16))
		assert_match('16', @sp.changebase("10", 16, 10))
		assert_match('10', @sp.changebase("16", 10, 16))
		assert_match('222', @sp.changebase("222", 32, 32))
		assert_match('bi', @sp.changebase("40", 10, 32))
		assert_match("1", @sp.changebase(1.chr, 256, 10))
		assert_match("49", @sp.changebase("1", 256, 10))
		assert_match(1.chr, @sp.changebase("1", 10, 256))
		assert_equal('14k7', @sp.changebase("10", 256, 58, 4))
	end

	def test_bin_to_b58check
		sp = Specials.new
		assert_equal(50, sp.bin_to_b58check(sp.get_code_string(32)).length)
	end

	def test_b58check_to_bin
		sp = Specials.new
		assert_equal(32, sp.b58check_to_bin('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ').length)
	end

	def test_random_string
		assert_equal(10, Specials.new.random_string(10).bytesize)
	end

	def test_hash_to_int
		sp = Specials.new
		assert_equal(0, sp.hash_to_int('0' * 40))
		assert_equal(1, sp.hash_to_int('0' * 63 + '1'))
		assert_equal(0, sp.hash_to_int(0.chr * 32))
	end

	def test_change_endianness
		sp = Specials.new
		assert_equal('c7f5d74d', sp.change_endianness('4dd7f5c7'))
		assert_equal('4dd7f5c7', sp.change_endianness(sp.change_endianness('4dd7f5c7')))
		assert_equal('81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000', sp.change_endianness('00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81'))
	end
end