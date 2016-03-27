require_relative 'scripts'
require 'test/unit'

class TestScripts < Test::Unit::TestCase

	def test_mk_pubkey_script
		s = Scripts.new
		addr = '1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa'
		assert_match('76a914', s.mk_pubkey_script(addr))
		assert_equal(50, s.mk_pubkey_script(addr).length)
	end

	def test_mk_scripthash_script
		s = Scripts.new
		addr = '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'
		assert_match('a914', s.mk_scripthash_script(addr))
		#assert_equal(46, s.mk_scripthash_script(addr).length)
	end

	def test_address_to_script
		s = Scripts.new
		addr = '1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a'
		multi = '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'
		assert_match('76a914', s.address_to_script(addr))
		assert_match('a914', s.address_to_script(multi))
	end

	def test_script_to_address
		s = Scripts.new
		addr = '1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa'
		multi = '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'
		scr = s.address_to_script(addr)
		x = s.script_to_address(scr)
		assert_equal(addr, x)
		scr = s.address_to_script(multi)
		x = s.script_to_address(scr)
		assert_equal(multi, x)
	end

	def test_mk_psh_redeem_script
		s = Scripts.new
		pk1 = "04a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd"
		res = s.mk_psh_redeem_script(1, [pk1])
		assert_equal("51", res[0..1])
		assert_equal("41", res[2..3])
		assert_equal(pk1, res[4..133])
		assert_equal("51", res[134..135])
		assert_equal("ae", res[136..137])
		pk2 = "046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187"
		pk3 = "0411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e83"

		res = s.mk_psh_redeem_script(2, [pk1, pk2, pk3])
		assert_equal("52", res[0..1])
		assert_equal("41", res[2..3])
		assert_equal(pk3, res[4..133])
		assert_equal("41", res[134..135])
		assert_equal(pk2, res[136..265])
		assert_equal("41", res[266..267])
		assert_equal(pk1, res[268..397])
		assert_equal("53", res[398..399])
		assert_equal("ae", res[-2..-1])
	end

	def test_encode_op_n
		s = Scripts.new
		assert_equal("0", s.encode_op_n(0))
		1.upto(16){|n| assert_equal((80 + n).to_s(16), s.encode_op_n(n))}
	end
end