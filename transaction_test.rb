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

	def test_signature_form
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
		newtx = t.signature_form(tx, 0, script[2..-1])
		tx = version+ins+hash+index+script+sequence+outs+value+scr+locktime
		assert_equal(tx, newtx)
		newtx = t.signature_form(t.deserialize(tx), 0, script[2..-1], 2)
		assert_equal([], newtx[:outs])
		tx = version+ins+hash+index+script+sequence+outs+value+scr+locktime
		newtx = t.signature_form(tx, 0, script[2..-1], 3)
		tx = version+ins+hash+index+script+sequence+outs+value+scr+locktime
		assert_equal(tx, newtx)

		tx23 = '0100000002e00bd5584971a43a0245216613fd7c42277d0cedc503c11c43ba025f4477f728010000' +
			'006b483045022100be35d2177a1507245528ae2a77cdb7b620ac98beeae6089cd301c2195b234e10' +
			'02200112b06c221696d04fb4c04eddbd4833664af5cb80ef6208ec5383a607db1a190121025114bd' +
			'74d6773bf24ce6d504de69821b051ab9eb9d7cd91a921a9413d09011bcffffffff1aa0269b3cb098' +
			'3ebaf875ed62ef51d47310cd85caf9404e33479c9c53652500020000006a473044022001e35c8b64' +
			'0c98362117518c663fcd0f699afb31e69cd23473a8c18ca5037e6e02202eb2dee324a7e8ae5fa7fe' +
			'305fd763da0fad9c2eb29f04e627c4c7a9a15d55b8012103e04a7198a5530179c98d44a23acfe8db' +
			'7654dd2a1038305a60250481dce3020cffffffff03ac18e601000000001976a914630a8fc125aaa4' +
			'512af375e0427a940ce724e48b88ac144f1800000000001976a914a5c9fd413f64f41716b3b5a7c3' +
			'5478550f4815c388ac08350300000000001976a9146a8faf4191cd9228b591f9526bf8678ebf10f0' +
			'a388ac00000000'
		ctx23 = '0100000002e00bd5584971a43a0245216613fd7c42277d0cedc503c11c43ba025f4477f728010000' +
			'006b483045022100be35d2177a1507245528ae2a77cdb7b620ac98beeae6089cd301c2195b234e10' +
			'02200112b06c221696d04fb4c04eddbd4833664af5cb80ef6208ec5383a607db1a190121025114bd' +
			'74d6773bf24ce6d504de69821b051ab9eb9d7cd91a921a9413d09011bcffffffff1aa0269b3cb098' +
			'3ebaf875ed62ef51d47310cd85caf9404e33479c9c53652500020000006a473044022001e35c8b64' +
			'0c98362117518c663fcd0f699afb31e69cd23473a8c18ca5037e6e02202eb2dee324a7e8ae5fa7fe' +
			'305fd763da0fad9c2eb29f04e627c4c7a9a15d55b8012103e04a7198a5530179c98d44a23acfe8db' +
			'7654dd2a1038305a60250481dce3020cffffffff03ac18e601000000001976a914630a8fc125aaa4' +
			'512af375e0427a940ce724e48b88ac144f1800000000001976a914a5c9fd413f64f41716b3b5a7c3' +
			'5478550f4815c388ac08350300000000001976a9146a8faf4191cd9228b591f9526bf8678ebf10f0' +
			'a388ac00000000'

		scr23 = '483045022100be35d2177a1507245528ae2a77cdb7b620ac98beeae6089cd301c2195b234e10'+
			'02200112b06c221696d04fb4c04eddbd4833664af5cb80ef6208ec5383a607db1a190121025114bd' +
			'74d6773bf24ce6d504de69821b051ab9eb9d7cd91a921a9413d09011bc'
		#newtx = t.signature_form(t.deserialize(tx23), 0, scr23)
		#assert_equal("", newtx[:ins][1][:script])
		#newtx = t.signature_form(t.deserialize(tx23), 0, scr23, 2)
		#assert_equal([], newtx[:outs])
		# newtx = t.signature_form(t.deserialize(tx23), 1, scr23, 3)
		# assert_equal("", newtx[:outs][0][:script])
		newtx = t.signature_form(t.deserialize(tx23), 1, scr23, 0x81)
		assert_equal(1, newtx[:ins].length)
	end

	def test_txhash
		t = Transaction.new
		tx23 = '0100000002e00bd5584971a43a0245216613fd7c42277d0cedc503c11c43ba025f4477f728010000' +
			'006b483045022100be35d2177a1507245528ae2a77cdb7b620ac98beeae6089cd301c2195b234e10' +
			'02200112b06c221696d04fb4c04eddbd4833664af5cb80ef6208ec5383a607db1a190121025114bd' +
			'74d6773bf24ce6d504de69821b051ab9eb9d7cd91a921a9413d09011bcffffffff1aa0269b3cb098' +
			'3ebaf875ed62ef51d47310cd85caf9404e33479c9c53652500020000006a473044022001e35c8b64' +
			'0c98362117518c663fcd0f699afb31e69cd23473a8c18ca5037e6e02202eb2dee324a7e8ae5fa7fe' +
			'305fd763da0fad9c2eb29f04e627c4c7a9a15d55b8012103e04a7198a5530179c98d44a23acfe8db' +
			'7654dd2a1038305a60250481dce3020cffffffff03ac18e601000000001976a914630a8fc125aaa4' +
			'512af375e0427a940ce724e48b88ac144f1800000000001976a914a5c9fd413f64f41716b3b5a7c3' +
			'5478550f4815c388ac08350300000000001976a9146a8faf4191cd9228b591f9526bf8678ebf10f0' +
			'a388ac00000000'

		txhash = t.txhash(tx23)
		assert_equal(64, txhash.length)
		txhash = t.txhash(tx23, 2)
		assert_equal(64, txhash.length)
	end

	def test_bin_txhash
		t = Transaction.new
		tx = '010000000175db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b07900000' +
			'0008b4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c70' +
			'3302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca' +
			'69c59dc7a6d8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e' +
			'6a9ccda988b323d12a367dd758261dd27a63f18f56ce77ffffffff0133f50100000000001976a91' +
			'4dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac00000000'
		assert_equal(32, t.bin_txhash(tx).length)
	end

	def test_ecdsa_tx_sign
		t = Transaction.new
		tx = '010000000175db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b07900000' +
			'0008b4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c70' +
			'3302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca' +
			'69c59dc7a6d8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e' +
			'6a9ccda988b323d12a367dd758261dd27a63f18f56ce77ffffffff0133f50100000000001976a91' +
			'4dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac00000000'
		priv = Specials.new.decode('E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262', 16)
		signature = t.ecdsa_tx_sign(tx, priv)
		assert_equal('30', signature[0..1])
	end
end