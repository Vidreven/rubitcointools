require_relative 'main'
require 'test/unit'

class TestMain < Test::Unit::TestCase

	def test_change_curve
		assert_equal([13, 17], Main.new.change_curve(3, 7, 0, 11, 13, 17))
	end

	def test_inv
		assert_equal(6, Main.new.inv(5, 29))
	end

	def test_isinf
		assert_equal(true, Main.new.isinf([0, 0]))
		assert_not_equal(true, Main.new.isinf([0, 1]))
	end

	def test_to_jacobian
		assert_equal([5, 29, 1], Main.new.to_jacobian([5, 29]))
		assert_equal(Main::G << 1, Main.new.to_jacobian(Main::G))
		#assert_equal(Main::G << 1, Main.new.to_jacobian(Main::G << 1))
	end

	def test_jacobian_double
		assert_equal([0, 0, 0], Main.new.jacobian_double([3]))
		assert_equal([56576513649176532955305617254616790498672209379484940581393603843805619269570, 39155707150128334349216371677407456506802956851096117747929288260567018884059, 65341020041517633956166170261014086368942546761318486551877808671514674964848], Main.new.jacobian_double(Main.new.to_jacobian(Main::G)))
	end

	def test_jacobian_add
		assert_equal(Main::G, Main.new.jacobian_add([0], Main::G))
		assert_equal(Main::G, Main.new.jacobian_add(Main::G, [0]))
		assert_equal(Main.new.jacobian_double(Main.new.to_jacobian(Main::G)), Main.new.jacobian_add(Main.new.to_jacobian(Main::G), Main.new.to_jacobian(Main::G)))
	end

	def test_from_jacobian
		assert_equal(Main::G, Main.new.from_jacobian(Main.new.to_jacobian(Main::G)))
	end

	def test_jacobian_multiply
		assert_equal([0, 0, 1], Main.new.jacobian_multiply([100, 0], [3]))
		assert_equal([100, 50], Main.new.jacobian_multiply([100, 50], 1))
	end

	def test_fast_add
		assert_equal(Main.new.from_jacobian(Main.new.jacobian_double(Main.new.to_jacobian(Main::G))), Main.new.fast_add(Main::G, Main::G))
	end

	def test_fast_multiply
		assert_equal(Main.new.fast_multiply(Main.new.fast_multiply(Main::G, 20), 30), Main.new.fast_multiply(Main.new.fast_multiply(Main::G, 30), 20))
	end

	def test_get_pubkey_format
		m = Main.new
		assert_equal('decimal', m.get_pubkey_format(['abcdefgh']))
		assert_equal('bin', m.get_pubkey_format('4' + 'a' * 64))
		assert_equal('hex', m.get_pubkey_format('04' + 'b' * 128))
		assert_equal('bin_compressed', m.get_pubkey_format('2' + '1' * 32))
		assert_equal('hex_compressed', m.get_pubkey_format('03' + 'c' * 64))
		assert_equal('bin_electrum', m.get_pubkey_format('0' * 64))
		assert_equal('hex_electrum', m.get_pubkey_format('d' * 128))
	end

	def test_decode_pubkey
		m = Main.new
		assert_equal([1, 2], m.decode_pubkey([1, 2], 'decimal'))
		assert_equal([1, 2], m.decode_pubkey([1, 2]))
		assert_equal([0, 0], m.decode_pubkey('4' + (0.chr) * 64))
		assert_equal([0, Main::P], m.decode_pubkey('2' + (0.chr) * 32))
		assert_equal([0, 0], m.decode_pubkey('04' + '0' * 128))
		assert_equal([1, Main::P], m.decode_pubkey('03' + '0' * 63 + '1'))
	end

	def test_encode_pubkey
		m = Main.new
		assert_equal([5, 10], m.encode_pubkey([5, 10], 'decimal'))
		assert_equal(4.chr, m.encode_pubkey([5, 10], 'bin')[0])
		assert_equal(2.chr, m.encode_pubkey([5, 10], 'bin_compressed')[0])
		assert_equal('hex', m.get_pubkey_format(m.encode_pubkey([5, 10], 'hex')))
		assert_equal('hex_compressed', m.get_pubkey_format(m.encode_pubkey([5, 10], 'hex_compressed')))
	end

	def test_get_privkey_format
		m = Main.new
		assert_equal('decimal', m.get_privkey_format(123456789))
		assert_equal('bin', m.get_privkey_format('1' * 32))
		assert_equal('bin_compressed', m.get_privkey_format('1' * 33))
		assert_equal('hex', m.get_privkey_format('d' * 64))
		assert_equal('hex_compressed', m.get_privkey_format('e' * 66))
		assert_equal('wif', m.get_privkey_format('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'))
		assert_equal('wif_compressed', m.get_privkey_format('KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp'))
	end

	def test_decode_privkey
		m = Main.new
		assert_equal(1234, m.decode_privkey(1234))
		assert_equal(0, m.decode_privkey((0.chr) * 32))
		assert_equal(0, m.decode_privkey((0.chr) * 32 + 1.chr))
		assert_equal(0, m.decode_privkey('0' * 64))
		assert_equal(0, m.decode_privkey('0' * 64 + '01'))
		assert_equal(32, m.decode_privkey('5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh').size)
		assert_equal(36, m.decode_privkey('KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp').size)
	end

	def test_encode_privkey
		m = Main.new
		assert_equal(1234, m.encode_privkey(1234, 'decimal'))
		assert_equal([0.chr * 32], m.encode_privkey(0.chr * 32, 'bin'))
		assert_equal([0.chr * 32], m.encode_privkey(0, 'bin'))
		assert_equal(0.chr * 32 + 1.chr, m.encode_privkey(0, 'bin_compressed'))
		assert_equal('0' * 64, m.encode_privkey(0, 'hex'))
		assert_equal('0' * 64 + '01', m.encode_privkey(0, 'hex_compressed'))
		assert_equal('5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh', m.encode_privkey('1111111111111111111111111111111111111111111111111111111111111111', 'wif'))
		assert_equal('KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp', m.encode_privkey('1111111111111111111111111111111111111111111111111111111111111111', 'wif_compressed'))
	end

	def test_add_pubkeys
		m = Main.new
		sp = Specials.new
		x = sp.decode('0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179', 16)
		y = sp.decode('8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16)
		#assert_equal([Main::P - 3, 2], m.add_pubkeys([1, 2], [3, 4]))
		assert_equal(m.from_jacobian(m.jacobian_double(m.to_jacobian([x, y]))), m.add_pubkeys([x, y], [x, y]))
	end

	def test_add_privkeys
		m = Main.new
		sp = Specials.new
		p = sp.decode('E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262', 16)
		assert_equal((2*p) % Main::N, m.add_privkeys(p, p))
	end

	def test_multiply
		m = Main.new
		x = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262'
		y = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA3326f'
		assert_equal(m.multiply(m.multiply(Main::G, y), x), m.multiply(m.multiply(Main::G, x), y))
	end

	def test_divide
		m = Main.new
		x = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262'
		assert_equal(Main::G, m.multiply(m.divide(Main::G, x), x))
	end

	def test_compress
		m = Main.new
		x = '0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179'
		y = '8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
		assert_equal(66, m.compress(x+y).length)
	end

	def test_decompress
		m = Main.new
		x = '0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179'
		y = '8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
		assert_equal(130, m.decompress(m.compress(x+y)).length)
	end

	def test_privkey_to_pubkey
		m = Main.new
		priv = '1111111111111111111111111111111111111111111111111111111111111111'
		assert_equal(130, m.privkey_to_pubkey(priv).length)
		assert_equal(130, m.privtopub(priv).length)
	end

	def test_pubtoaddr
		m = Main.new
		x = '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a'
		y = 'a385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'
		assert_equal('1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a', m.pubtoaddr(x+y))
	end

	def test_privtoaddr
		m = Main.new
		priv = '1111111111111111111111111111111111111111111111111111111111111111'
		assert_equal('1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a', m.privtoaddr(priv))
	end

	def test_neg_pubkey
		m = Main.new
		x = '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a'
		y = 'a385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'
		assert_equal(130, m.neg_pubkey(x+y).length)
	end

	def test_neg_privkey
		m = Main.new
		priv = '1111111111111111111111111111111111111111111111111111111111111111'
		assert_equal(0, m.neg_privkey(0))
		assert_equal(64, m.neg_privkey(priv).length)
	end

	def test_subtract_pubkeys
		m = Main.new
		x = '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a'
		y = 'a385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'
		assert_equal('04' + '0' * 128, m.subtract_pubkeys(x+y, x+y))
		#assert_equal('04' + '0' * 128, m.subtract_pubkeys(x+y, x+z))
	end

	def test_subtract_privkeys
		m = Main.new
		p1 = '1111111111111111111111111111111111111111111111111111111111111111'
		p2 = '1111111111111111111111111111111111111111111111111111111111111110'
		assert_equal('0' * 63 + '1', m.subtract_privkeys(p1, p2))
	end

	def test_random_key
		m  = Main.new
		assert_equal(64, m.random_key.length)
	end

	def test_random_electrum_seed
		m = Main.new
		assert_equal(32, m.random_electrum_seed.length)
	end
end