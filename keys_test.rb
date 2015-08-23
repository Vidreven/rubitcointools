require_relative 'keys'
require_relative 'ecc'
require 'test/unit'

class TestKeys < Test::Unit::TestCase

	def test_get_pubkey_format
		k = Keys.new
		assert_equal('decimal', k.get_pubkey_format(['abcdefgh']))
		assert_equal('bin', k.get_pubkey_format('4' + 'a' * 64))
		assert_equal('hex', k.get_pubkey_format('04' + 'b' * 128))
		assert_equal('bin_compressed', k.get_pubkey_format('2' + '1' * 32))
		assert_equal('hex_compressed', k.get_pubkey_format('03' + 'c' * 64))
		assert_equal('bin_electrum', k.get_pubkey_format('0' * 64))
		assert_equal('hex_electrum', k.get_pubkey_format('d' * 128))
	end

	def test_decode_pubkey
		k = Keys.new
		assert_equal([1, 2], k.decode_pubkey([1, 2], 'decimal'))
		assert_equal([1, 2], k.decode_pubkey([1, 2]))
		assert_equal([0, 0], k.decode_pubkey('4' + (0.chr) * 64))
		assert_equal([0, ECC::P], k.decode_pubkey('2' + (0.chr) * 32))
		assert_equal([0, 0], k.decode_pubkey('04' + '0' * 128))
		assert_equal([1, ECC::P], k.decode_pubkey('03' + '0' * 63 + '1'))
	end

	def test_encode_pubkey
		k = Keys.new
		assert_equal([5, 10], k.encode_pubkey([5, 10], 'decimal'))
		assert_equal(4.chr, k.encode_pubkey([5, 10], 'bin')[0])
		assert_equal(2.chr, k.encode_pubkey([5, 10], 'bin_compressed')[0])
		assert_equal('hex', k.get_pubkey_format(k.encode_pubkey([5, 10], 'hex')))
		assert_equal('hex_compressed', k.get_pubkey_format(k.encode_pubkey([5, 10], 'hex_compressed')))
	end

	def test_get_privkey_format
		k = Keys.new
		assert_equal('decimal', k.get_privkey_format(123456789))
		assert_equal('bin', k.get_privkey_format('1' * 32))
		assert_equal('bin_compressed', k.get_privkey_format('1' * 33))
		assert_equal('hex', k.get_privkey_format('d' * 64))
		assert_equal('hex_compressed', k.get_privkey_format('e' * 66))
		assert_equal('wif', k.get_privkey_format('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'))
		assert_equal('wif_compressed', k.get_privkey_format('KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp'))
	end

	def test_decode_privkey
		k = Keys.new
		assert_equal(1234, k.decode_privkey(1234))
		assert_equal(0, k.decode_privkey((0.chr) * 32))
		assert_equal(0, k.decode_privkey((0.chr) * 32 + 1.chr))
		assert_equal(0, k.decode_privkey('0' * 64))
		assert_equal(0, k.decode_privkey('0' * 64 + '01'))
		assert_equal(32, k.decode_privkey('5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh').size)
		assert_equal(36, k.decode_privkey('KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp').size)
	end

	def test_encode_privkey
		k = Keys.new
		assert_equal(1234, k.encode_privkey(1234, 'decimal'))
		assert_equal([0.chr * 32], k.encode_privkey(0.chr * 32, 'bin'))
		assert_equal([0.chr * 32], k.encode_privkey(0, 'bin'))
		assert_equal(0.chr * 32 + 1.chr, k.encode_privkey(0, 'bin_compressed'))
		assert_equal('0' * 64, k.encode_privkey(0, 'hex'))
		assert_equal('0' * 64 + '01', k.encode_privkey(0, 'hex_compressed'))
		assert_equal('5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh', k.encode_privkey('1111111111111111111111111111111111111111111111111111111111111111', 'wif'))
		assert_equal('KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp', k.encode_privkey('1111111111111111111111111111111111111111111111111111111111111111', 'wif_compressed'))
	end

	def test_add_pubkeys
		k = Keys.new
		e = ECC.new
		sp = Specials.new
		x = sp.decode('0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179', 16)
		y = sp.decode('8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16)
		assert_equal(e.from_jacobian(e.jacobian_double(e.to_jacobian([x, y]))), k.add_pubkeys([x, y], [x, y]))
	end

	def test_add_privkeys
		k = Keys.new
		e = ECC.new
		sp = Specials.new
		p = sp.decode('E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262', 16)
		assert_equal((2*p) % ECC::N, k.add_privkeys(p, p))
	end

	def test_multiply
		k = Keys.new
		e = ECC.new
		x = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262'
		y = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA3326f'
		assert_equal(k.multiply(k.multiply(ECC::G, y), x), k.multiply(k.multiply(ECC::G, x), y))
	end

	def test_divide
		k = Keys.new
		e = ECC.new
		x = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262'
		assert_equal(ECC::G, k.multiply(k.divide(ECC::G, x), x))
	end

	def test_compress
		k = Keys.new
		x = '0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179'
		y = '8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
		assert_equal(66, k.compress(x+y).length)
	end

	def test_decompress
		k = Keys.new
		x = '0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179'
		y = '8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
		assert_equal(130, k.decompress(k.compress(x+y)).length)
	end

	def test_privkey_to_pubkey
		k = Keys.new
		priv = '1111111111111111111111111111111111111111111111111111111111111111'
		assert_equal(130, k.privkey_to_pubkey(priv).length)
		assert_equal(130, k.privtopub(priv).length)
	end

	def test_pubtoaddr
		k = Keys.new
		x = '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a'
		y = 'a385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'
		assert_equal('1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a', k.pubtoaddr(x+y))
	end

	def test_privtoaddr
		k = Keys.new
		priv = '1111111111111111111111111111111111111111111111111111111111111111'
		assert_equal('1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a', k.privtoaddr(priv))
	end

	def test_neg_pubkey
		k = Keys.new
		x = '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a'
		y = 'a385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'
		assert_equal(130, k.neg_pubkey(x+y).length)
	end

	def test_neg_privkey
		k = Keys.new
		priv = '1111111111111111111111111111111111111111111111111111111111111111'
		assert_equal(0, k.neg_privkey(0))
		assert_equal(64, k.neg_privkey(priv).length)
	end

	def test_subtract_pubkeys
		k = Keys.new
		x = '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a'
		y = 'a385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'
		assert_equal('04' + '0' * 128, k.subtract_pubkeys(x+y, x+y))
	end

	def test_subtract_privkeys
		k = Keys.new
		p1 = '1111111111111111111111111111111111111111111111111111111111111111'
		p2 = '1111111111111111111111111111111111111111111111111111111111111110'
		assert_equal('0' * 63 + '1', k.subtract_privkeys(p1, p2))
	end

	def test_random_key
		k = Keys.new
		assert_equal(64, k.random_key.length)
	end

	def test_random_electrum_seed
		k = Keys.new
		assert_equal(32, k.random_electrum_seed.length)
	end
end