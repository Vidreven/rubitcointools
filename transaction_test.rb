require_relative 'transaction'
require 'test/unit'

class TestTransaction < Test::Unit::TestCase

	def test_deserialize
		t = Transaction.new
		sp = Specials.new
		ed = ECDSA.new

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

		assert_equal(version, sp.change_endianness(obj[:version]))
		assert_equal(hash, sp.change_endianness(obj[:ins][0][:outpoint][:hash]))
		assert_equal(index, sp.change_endianness(obj[:ins][0][:outpoint][:index]))
		assert_equal(script, '8b' + obj[:ins][0][:scriptSig])
		assert_equal(sequence, sp.change_endianness(obj[:ins][0][:sequence]))
		assert_equal(value, sp.change_endianness(obj[:outs][0][:value]))
		assert_equal(scr, '19' + obj[:outs][0][:scriptPubKey])
		assert_equal(locktime, obj[:locktime])

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
		obj = t.deserialize(tx23)

		assert_equal(version, sp.change_endianness(obj[:version]))
		assert_equal(sequence, sp.change_endianness(obj[:ins][0][:sequence]))
		assert_equal(sequence, sp.change_endianness(obj[:ins][1][:sequence]))
		assert_equal(locktime, obj[:locktime])
		assert_equal(2, obj[:ins].length)
		assert_equal(3, obj[:outs].length)
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

		newtx = t.signature_form(tx, 0, scr[2..-1])
		assert_equal(t.deserialize(tx)[:outs][0][:scriptPubKey], t.deserialize(newtx)[:ins][0][:scriptSig])

		newtx = t.signature_form(t.deserialize(tx), 0, scr[2..-1], 2)
		assert_equal([], newtx[:outs])

		newtx = t.signature_form(tx, 0, scr[2..-1], 3)
		assert_equal(t.deserialize(tx)[:outs][0][:scriptPubKey], t.deserialize(newtx)[:ins][0][:scriptSig])

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

		scr23 = '483045022100be35d2177a1507245528ae2a77cdb7b620ac98beeae6089cd301c2195b234e10'+
			'02200112b06c221696d04fb4c04eddbd4833664af5cb80ef6208ec5383a607db1a190121025114bd' +
			'74d6773bf24ce6d504de69821b051ab9eb9d7cd91a921a9413d09011bc'

		#newtx = t.signature_form(t.deserialize(tx23), 0, scr[2..-1])
		# newtx = t.signature_form(tx23, 0, scr[2..-1])
		# assert_equal("", t.deserialize(newtx)[:ins][1][:scriptSig])
		# newtx = t.signature_form(t.deserialize(tx23), 0, scr23, 2)
		# assert_equal([], newtx[:outs])
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
		hashcode = 3
		tx = '010000000175db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b07900000' +
			'0001976a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88acffffffff0133f50100000000001976a91' +
			'4dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac00000000'
		priv = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262'
		signature = t.ecdsa_tx_sign(tx, priv, hashcode)
		assert_equal('30', signature[0..1])
		sig_len = signature[2..3].to_i(16) * 2
		assert_equal(signature[4..-3].length, sig_len)
		assert_equal(hashcode.to_s.rjust(2, '0'), signature[-2..-1])
		assert_equal(true, ECDSA.new.bip66?(signature[0..-3]))
	end

	def test_ecdsa_tx_verify
		t = Transaction.new
		tx = '010000000175db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b07900000' +
			'0008b4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c70' +
			'3302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca' +
			'69c59dc7a6d8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e' +
			'6a9ccda988b323d12a367dd758261dd27a63f18f56ce77ffffffff0133f50100000000001976a91' +
			'4dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac00000000'
		priv = '1111111111111111111111111111111111111111111111111111111111111111'
		x = '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a'
		y = 'a385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'
		signature = t.ecdsa_tx_sign(tx, priv)
		assert_equal(true, t.ecdsa_tx_verify(tx, signature, x+y))
	end

	# def test_ecdsa_tx_recover
	# 	t = Transaction.new
	# 	tx = '0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f201000000' +
	# 		'1976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff01605af40500000000' +
	# 		'1976a914097072524438d003d23a2f23edb65aae1bb3e46988ac00000000'
	# 	priv = '1111111111111111111111111111111111111111111111111111111111111111'
	# 	signature = t.ecdsa_tx_sign(tx, priv)
	# 	x = '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a'
	# 	y = 'a385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'

	# 	#assert_not_equal(false, t.ecdsa_tx_recover(tx, signature))
	# 	#assert_equal(130, t.ecdsa_tx_recover(tx, signature).length)
	# 	assert_equal(x+y, t.ecdsa_tx_recover(tx, signature))
	# end

	def test_sign
		t = Transaction.new
		tx = '010000000175db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b07900000' +
			'0008b4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c70' +
			'3302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca' +
			'69c59dc7a6d8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e' +
			'6a9ccda988b323d12a367dd758261dd27a63f18f56ce77ffffffff0133f50100000000001976a91' +
			'4dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac00000000'
		priv = '1111111111111111111111111111111111111111111111111111111111111111'
		i = 0
		tx = t.deserialize(tx)
		assert_equal(t.sign(tx, i, priv), t.sign(tx, i, priv))
		tr = t.sign(tx, i, priv)
		sig = tr[:ins][0][:scriptSig][2..141]
		assert_equal(true, ECDSA.new.bip66?(sig))
	end

	def test_sign_all
		t = Transaction.new
		ed = ECDSA.new
		tx = '01000000062e730fecd38a76a3dd93c342595cddbc54b064c453a5d7986789dcfb178a4c37170000006a47304402206490ed13d441a6745a3d519245e6b49fcffa35260f12a71fc99b5ad50f20026302205cfc4b218c070e80a93179b9681590beb6def2cec4418ca7e630'+
		'1f7f229c7708012102755ce609041e8e7681332a3df3d9e35431dbe3e45a77b2ddb9d08313421db33efeffffffafbfd849ddf5d7aafd47bc09d7d684dfd8955ea250faf35b5f86a8cf84dababa1d0000006b483045022100a858f692662a7b0c85131e5551d35eed0ba85d'+
		'ea5024a0e6bc3508dac5bcb7f30220738b15dfa2e200c6ae8922d29dd2bbac7142f9e19fa5986a08f5f8166599a29c012102755ce609041e8e7681332a3df3d9e35431dbe3e45a77b2ddb9d08313421db33efefffffff092941c3c26ae4425d3fc0e59352554a8f74aad98'+
		'c53ceb6fd13edece3baf5c000000006a4730440220469ed8338caadab18a3fb390d9ea68241516e155239d0b446f8864a48a6f67ac022053d1b3319eb5ba3b92c70fd147ab0bcfd74a333112b09fd7dd526262dbeadd9f012102e35c1c227d69f5fc961417ee47fec90670'+
		'a84f06630a937c0357601e45f449bbfeffffff91cca085fe781d0de923043e37f8cbf29a8d5f866c38b7f7604766e949e5c656050000006b483045022100a75083d38d7f9961ce53bdb071c7e704f31b21928d8f5b32ee80855c860485d80220498ba0a9233e723fd5bafa'+
		'4c28833540e6b366ae9583ed773c4bc5b75405a02a0121034816381b34887df06ff4092ca5cf2499c3e2c3a2f9730d29eb185e951241c28efeffffffb0ca2e5bccfac83cbaa0f6046cb1635b2cbe352b24c27f3821cea3db5bbb4fcf010000006a47304402206aba97783d'+
		'1cbfc835daffec0fb56be9bbe1b83e14e5e485d414d39d66e6734502201f911afcea1e504a9f644736233caefb512edefa3c772ed3f7bf66d3b32840b4012103cf92b6960b30611119ad1b914d9e042a92b5cbbd859dbbfefb27ecf9268699e5feffffff5c991bfc0e156c'+
		'0ad9bb98839c392bb183b1cb086a04728c83d45baa967d0752010000006a47304402206c85e5dd2d0f6db89b82b6802a7782830f527fab8d63b86d104a69d0dcef64640220158195f5fdb61e14054f43bb958d28a19fcd01dc64a4b435e5e71b017a465064012103efc478'+
		'ed39e3aa5e78fe18ad979cf43c72d47865353fe12f3334fa902b54b8aefeffffff026cbf1000000000001976a914a9d72f0fcc8e9e36ddea69d48fcd48a884395b3488ac005ed0b2000000001976a914811c7c703ec3025b29a87be0c60c8192b9a37c9d88ac8ed30500'
		priv = '1111111111111111111111111111111111111111111111111111111111111111'

		tx3 = '010000000175db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b07900000' +
			'0008b4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c70' +
			'3302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca' +
			'69c59dc7a6d8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e' +
			'6a9ccda988b323d12a367dd758261dd27a63f18f56ce77ffffffff0133f50100000000001976a91' +
			'4dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac00000000'
		tx2 = '010000000175db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b07900000' +
			'0008b4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c70' +
			'3302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca' +
			'69c59dc7a6d8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e' +
			'6a9ccda988b323d12a367dd758261dd27a63f18f56ce77ffffffff0133f50100000000001976a91' +
			'4dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac00000000'
		tx2 = t.deserialize(tx2)
		assert_equal(t.sign_all(tx3, priv), t.sign(tx2, 0, priv))
		tx = t.sign_all(tx, priv)

		sig0 = tx[:ins][0][:scriptSig][2..143]
		assert_equal(true, ed.bip66?(sig0))
		sig1 = tx[:ins][1][:scriptSig][2..141]
		assert_equal(true, ed.bip66?(sig1))
		sig2 = tx[:ins][2][:scriptSig][2..141]
		assert_equal(true, ed.bip66?(sig2))
		sig3 = tx[:ins][3][:scriptSig][2..143]
		assert_equal(true, ed.bip66?(sig3))
		sig4 = tx[:ins][4][:scriptSig][2..141]
		assert_equal(true, ed.bip66?(sig4))
		sig5 = tx[:ins][5][:scriptSig][2..143]
		assert_equal(true, ed.bip66?(sig5))
	end

	def test_multisign
		t = Transaction.new
		tx = '010000000175db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b07900000' +
			'0008b4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c70' +
			'3302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca' +
			'69c59dc7a6d8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e' +
			'6a9ccda988b323d12a367dd758261dd27a63f18f56ce77ffffffff0133f50100000000001976a91' +
			'4dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac00000000'
		i = 0
		priv = '1' * 64
		script = "76a914569076ba39fc4ff6a2291d9ea9196d8c08f9c7ab88ac"
		sig = t.multisign(tx, i, script, priv)
		assert_equal(true, ECDSA.new.bip66?(sig[0..-3]))
	end

	def test_apply_multisignatures
		t = Transaction.new
		ed = ECDSA.new

		tx = '010000000175db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b07900000' +
			'0008b4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c70' +
			'3302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca' +
			'69c59dc7a6d8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e' +
			'6a9ccda988b323d12a367dd758261dd27a63f18f56ce77ffffffff0133f50100000000001976a91' +
			'4dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac00000000'
		i = 0
		script = "524104a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f" +
			"09e63975a1700c9f4d4df849323dac06cf3bd6458cd41046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669f" +
			"f90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187410411ffd36c7" +
			"0776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea60" +
			"0bd217870a8b4f1f09f3a8e8353ae"
		priv1 = "1" * 64
		priv2 = "2" * 64
		priv3 = "3" * 64
		scriptPK = "76a914569076ba39fc4ff6a2291d9ea9196d8c08f9c7ab88ac"

		sig1 = t.multisign(tx, i, scriptPK, priv1)
		sig2 = t.multisign(tx, i, scriptPK, priv2)
		sig3 = t.multisign(tx, i, scriptPK, priv3)

		res = t.apply_multisignatures(tx, i, script, [sig1])
		sig = res[:ins][0][:scriptSig][3..144]
		assert_equal(true, ed.bip66?(sig))

		res = t.apply_multisignatures(tx, i, script, [sig1, sig2, sig3])
		sig = res[:ins][0][:scriptSig][3..144]
		assert_equal(true, ed.bip66?(sig))

		sig = res[:ins][0][:scriptSig][149..290]
		assert_equal(true, ed.bip66?(sig))

		sig = res[:ins][0][:scriptSig][295..434]
		assert_equal(true, ed.bip66?(sig))
	end

	def test_read_var_int
		t = Transaction.new

		varint = '01'
		int = t.read_var_int!(varint)
		assert_equal(1, int)

		varint = 'fc'
		int = t.read_var_int!(varint)
		assert_equal(252, int)

		varint = 'fdfd00'
		int = t.read_var_int!(varint)
		assert_equal(253, int)

		varint = 'fdff01'
		int = t.read_var_int!(varint)
		assert_equal(511, int)

		varint = 'fdfeff'
		int = t.read_var_int!(varint)
		assert_equal(65534, int)

		varint = 'FEFFFF0000'.downcase
		int = t.read_var_int!(varint)
		assert_equal(65535, int)

		varint = 'FEFFFF0100'.downcase
		int = t.read_var_int!(varint)
		assert_equal(131071, int)

		varint = 'FEFEFFFFFF'.downcase
		int = t.read_var_int!(varint)
		assert_equal(2**32 - 2, int)

		varint = 'FFFFFFFFFF00000000'.downcase
		int = t.read_var_int!(varint)
		assert_equal(2**32 -1, int)
	end

	def test_read_var_string
		t = Transaction.new

		varstr = '01h'
		str = t.read_var_string!(varstr)
		assert_equal('h', str)

		varstr = 'fc' + 'h'*252
		str = t.read_var_string!(varstr)
		assert_equal('h'*252, str)

		varstr = 'fdfd00' + 'h'*253
		str = t.read_var_string!(varstr)
		assert_equal('h'*253, str)

		varstr = '00'
		str = t.read_var_string!(varstr)
		assert_equal('', str)
	end

	def test_to_var_int
		t = Transaction.new

		int = 0
		varint = t.to_var_int(int)
		assert_equal('00', varint)

		int = 252
		varint = t.to_var_int(int)
		assert_equal('fc', varint)

		int = 253
		varint = t.to_var_int(int)
		assert_equal('fdfd00', varint)

		int = 511
		varint = t.to_var_int(int)
		assert_equal('fdff01', varint)

		int = 65534
		varint = t.to_var_int(int)
		assert_equal('fdfeff', varint)

		int = 65535
		varint = t.to_var_int(int)
		assert_equal('feffff0000', varint)

		int = 131071
		varint = t.to_var_int(int)
		assert_equal('feffff0100', varint)

		int = 2**32 - 2
		varint = t.to_var_int(int)
		assert_equal('fefeffffff', varint)

		int = 2**32 - 1
		varint = t.to_var_int(int)
		assert_equal('ffffffffff00000000', varint)
	end

	def test_to_var_str
		t = Transaction.new

		str = '01'
		varstr = t.to_var_str(str)
		assert_equal('0101', varstr)

		str = '01' * 252
		varstr = t.to_var_str(str)
		assert_equal('fc' + '01'*252, varstr)

		str = '01' * 253
		varstr = t.to_var_str(str)
		assert_equal('fdfd00' + '01'*253, varstr)

		str = ''
		varstr = t.to_var_str(str)
		assert_equal('00', varstr)
	end
end