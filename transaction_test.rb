require_relative 'transaction'
require 'test/unit'

class TestTransaction < Test::Unit::TestCase
	
	def test_json_is_base
		t = Transaction.new
		assert_equal(true, t.json_is_base('1a', 16))
		assert_equal(true, t.json_is_base(5682, 10))
		assert_equal(true, t.json_is_base(5682, 16))
		assert_equal(true, t.json_is_base(nil, 16))
		assert_equal(true, t.json_is_base('1MBngSqZbMydscpzSoehjP8kznMaHAzh9y', 58))
		assert_equal(true, t.json_is_base(['1a', '2b', '3c'], 16))
		assert_equal(true, t.json_is_base({name: '1a', surname: '2b', nickname: '3c'}, 16))
	end

	# def test_json_changebase
	# 	t = Transaction.new
	# 	assert_equal(10, t.json_changebase('a'){|n| n.to_i(16)})
	# 	assert_equal([10, 11], t.json_changebase(['a', 'b']){|n| n.to_i(16)})
	# 	assert_equal([10, 11], t.json_changebase([name: 'a', surname: 'b']){|k, v| v.to_i(16)})
	# end
end