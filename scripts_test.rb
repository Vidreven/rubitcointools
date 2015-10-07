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
end