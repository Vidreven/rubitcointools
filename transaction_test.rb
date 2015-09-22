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

	def test_deserialize
		t = Transaction.new
		version = '01000000'
		ins = '01'
		hash = '75db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b079'
		index = '00000000'
		script= '8b4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c703302203'+
				'b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca69c59dc7a6d'+
				'8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e6a9ccda988b323d'+
				'12a367dd758261dd27a63f18f56ce77'
		sequence = 'ffffffff'
		outs = '01'
		value = '33f5010000000000'
		scr = '1976a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac'
		locktime = '00000000'
		tx = version+ins+hash+index+script+sequence+outs+value+scr+locktime
		obj = t.deserialize(tx)
		assert_equal(version, [obj[:version]].pack('H*').reverse.unpack('H*')[0])
		assert_equal(hash, [obj[:ins][0][:outpoint][:hash]].pack('H*').reverse.unpack('H*')[0])
		assert_equal(index, [obj[:ins][0][:outpoint][:index]].pack('H*').reverse.unpack('H*')[0])
		assert_equal(script, '8b' + obj[:ins][0][:script])
		assert_equal(sequence, [obj[:ins][0][:sequence]].pack('H*').reverse.unpack('H*')[0])
		assert_equal(value, [obj[:outs][0][:value]].pack('H*').reverse.unpack('H*')[0])
		assert_equal(scr, '19' + obj[:outs][0][:script])
		assert_equal(locktime, obj[:locktime])
	end

	def test_serialize
		t = Transaction.new
		version = '01000000'
		ins = '01'
		hash = '75db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b079'
		index = '00000000'
		script= '8b4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c703302203'+
				'b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca69c59dc7a6d'+
				'8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e6a9ccda988b323d'+
				'12a367dd758261dd27a63f18f56ce77'
		sequence = 'ffffffff'
		outs = '01'
		value = '33f5010000000000'
		scr = '1976a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac'
		locktime = '00000000'
		tx = version+ins+hash+index+script+sequence+outs+value+scr+locktime
		obj = t.deserialize(tx)
		tx = t.serialize(obj)
		assert_equal(version+ins+hash+index+script+sequence+outs+value+scr+locktime, tx)
	end
end