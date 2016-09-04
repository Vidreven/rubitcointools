require 'transaction'

describe Transaction do

	t = Transaction.new
	sp = Specials.new

	priv = '1' * 64
	x = '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a'
	y = 'a385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'

	version = '01000000'
	hash11 = '75db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b079'
	hash231 = 'e00bd5584971a43a0245216613fd7c42277d0cedc503c11c43ba025f4477f728'
	hash232 = '1aa0269b3cb0983ebaf875ed62ef51d47310cd85caf9404e33479c9c53652500'
	index11 = '00000000'
	index231 = '01000000'
	index232 = '02000000'
	scriptSig11 = '8b4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c703302203'+
				'b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca69c59dc7a6d'+
				'8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e6a9ccda988b323d'+
				'12a367dd758261dd27a63f18f56ce77'
	scriptSig231 = '6b483045022100be35d2177a1507245528ae2a77cdb7b620ac98beeae6089cd301c2195b234e10' +
			'02200112b06c221696d04fb4c04eddbd4833664af5cb80ef6208ec5383a607db1a190121025114bd' +
			'74d6773bf24ce6d504de69821b051ab9eb9d7cd91a921a9413d09011bc'
	scriptSig232 = '6a473044022001e35c8b64' +
			'0c98362117518c663fcd0f699afb31e69cd23473a8c18ca5037e6e02202eb2dee324a7e8ae5fa7fe' +
			'305fd763da0fad9c2eb29f04e627c4c7a9a15d55b8012103e04a7198a5530179c98d44a23acfe8db' +
			'7654dd2a1038305a60250481dce3020c'
	sequence = 'ffffffff'
	value11 = '33f5010000000000'
	value231 = 'ac18e60100000000'
	value232 = '144f180000000000'
	value233 = '0835030000000000'
	scriptPubKey11 = '1976a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac'
	scriptPubKey231 = '1976a914630a8fc125aaa4512af375e0427a940ce724e48b88ac'
	scriptPubKey232 = '1976a914a5c9fd413f64f41716b3b5a7c35478550f4815c388ac'
	scriptPubKey233 = '1976a9146a8faf4191cd9228b591f9526bf8678ebf10f0a388ac'
	locktime = '00000000'

	tx11 = version+'01'+hash11+index11+scriptSig11+sequence+'01'+value11+scriptPubKey11+locktime
	tx23 = version + '02' + hash231 + index231 + scriptSig231 + sequence + hash232 + index232 + scriptSig232 + sequence +
			'03' + value231 + scriptPubKey231 + value232 + scriptPubKey232 + value233 + scriptPubKey233 + locktime

	context ".deserialize" do

		context "given 1-1 hex transaction" do

			it "returns json transaction" do
				obj = t.deserialize tx11

				expect(obj[:ins].size).to eql 1
				expect(obj[:outs].size).to eql 1
				expect(sp.change_endianness obj[:version]).to eql version
				expect(sp.change_endianness obj[:ins][0][:outpoint][:hash]).to eql hash11
				expect(sp.change_endianness obj[:ins][0][:outpoint][:index]).to eql index11
				expect('8b' + obj[:ins][0][:scriptSig]).to eql scriptSig11
				expect(sp.change_endianness obj[:ins][0][:sequence]).to eql sequence
				expect(sp.change_endianness obj[:outs][0][:value]).to eql value11
				expect('19' + obj[:outs][0][:scriptPubKey]).to eql scriptPubKey11
				expect(obj[:locktime]).to eql locktime
			end
		end

		context "given 2-3 hex transaction" do

			it "returns json transaction" do
				obj = t.deserialize tx23

				expect(obj[:ins].size).to eql 2
				expect(obj[:outs].size).to eql 3
				expect(sp.change_endianness obj[:version]).to eql version
				expect(sp.change_endianness obj[:ins][0][:outpoint][:hash]).to eql hash231
				expect(sp.change_endianness obj[:ins][0][:outpoint][:index]).to eql index231
				expect('6b' + obj[:ins][0][:scriptSig]).to eql scriptSig231
				expect(sp.change_endianness obj[:ins][0][:sequence]).to eql sequence
				expect(sp.change_endianness obj[:ins][1][:outpoint][:hash]).to eql hash232
				expect(sp.change_endianness obj[:ins][1][:outpoint][:index]).to eql index232
				expect('6a' + obj[:ins][1][:scriptSig]).to eql scriptSig232
				expect(sp.change_endianness obj[:ins][1][:sequence]).to eql sequence
				expect(sp.change_endianness obj[:outs][0][:value]).to eql value231
				expect('19' + obj[:outs][0][:scriptPubKey]).to eql scriptPubKey231
				expect(sp.change_endianness obj[:outs][1][:value]).to eql value232
				expect('19' + obj[:outs][1][:scriptPubKey]).to eql scriptPubKey232
				expect(sp.change_endianness obj[:outs][2][:value]).to eql value233
				expect('19' + obj[:outs][2][:scriptPubKey]).to eql scriptPubKey233
				expect(obj[:locktime]).to eql locktime
			end
		end
	end

	context ".serialize" do

		context "given 1-1 json transaction" do

			it "returns hex format" do
				obj = t.deserialize tx11
				obj = t.serialize obj
				expect(obj).to eql tx11
			end
		end

		context "given 2-3 json transaction" do

			it "returns hex format" do
				obj = t.deserialize tx23
				obj = t.serialize obj
				expect(obj).to eql tx23
			end
		end
	end

	context ".signature_form" do

		context "given incorrect input number" do

			it "raises error" do
				obj = t.deserialize tx11
				expect{t.signature_form(obj, 15, scriptPubKey233)}.to raise_error ArgumentError
			end
		end

		context "given deserialized 1-1 transaction" do

			obj = t.deserialize tx11
			i = 0

			context "For SIGHASH_ALL" do

				it "prepares transaction for signing" do
					result = t.signature_form(obj, i, scriptPubKey231)
					expect(result[:ins][i][:scriptSig]).to eql scriptPubKey231
				end
			end

			context "For SIGHASH_NONE" do

				it "prepares transaction for signing" do
					result = t.signature_form(obj, i, scriptPubKey231, 2)
					expect(result[:ins][i][:scriptSig]).to eql scriptPubKey231
					expect(result[:outs].size).to eql 0
				end
			end

			context "For SIGHASH_SINGLE" do
				
				it "prepares transaction for signing" do
					result = t.signature_form(obj, i, scriptPubKey231, 3)
					expect(result[:ins][i][:scriptSig]).to eql scriptPubKey231
				end
			end

			context "For SIGHASH_ANYONECANPAY" do
				
				it "prepares transaction for signing" do
					result = t.signature_form(obj, i, scriptPubKey231, 0x81)
					expect(result[:ins][i][:scriptSig]).to eql scriptPubKey231
				end
			end
		end

		context "given deserialized 2-3 transaction" do

			obj = t.deserialize tx23
			i = 1

			context "For SIGHASH_ALL" do

				it "prepares transaction for signing" do
					result = t.signature_form(obj, i, scriptPubKey11)

					expect(result[:ins][i][:scriptSig]).to eql scriptPubKey11
					expect(result[:ins].size).to eql 2
					expect(result[:outs].size).to eql 3
				end
			end

			context "For SIGHASH_NONE" do

				it "prepares transaction for signing" do
					result = t.signature_form(obj, i, scriptPubKey11, 2)

					expect(result[:outs].size).to eql 0
					expect(result[:ins].size).to eql 2
					expect(result[:ins][i][:scriptSig]).to eql scriptPubKey11
				end
			end

			context "For SIGHASH_SINGLE" do

				it "prepares transaction for signing" do
					result = t.signature_form(obj, i, scriptPubKey11, 3)

					expect(result[:ins][i][:scriptSig]).to eql scriptPubKey11
					expect(result[:outs].size).to eql 3
					expect(result[:ins].size).to eql 2
					expect(result[:outs][0][:value]).to eql 2**64 - 1
					expect(result[:outs][0][:scriptPubKey]).to eql ''
					expect(result[:outs][2][:value]).to eql 2**64 - 1
					expect(result[:outs][2][:scriptPubKey]).to eql ''
					expect(result[:outs][1][:value]).to eql sp.change_endianness value232
					expect(result[:outs][1][:scriptPubKey]).to eql scriptPubKey232[2..-1]
				end
			end

			context "For SIGHASH_ALL + SIGHASH_ANYONECANPAY" do

				it "prepares transaction for signing" do
					result = t.signature_form(obj, i, scriptPubKey11, 0x81)
					expect(result[:ins].size).to eql 1
					expect(result[:ins][0][:scriptSig]).to eql scriptPubKey11
					expect(result[:outs].size).to eql 3
				end
			end

			context "For SIGHASH_NONE + SIGHASH_ANYONECANPAY" do

				it "prepares transaction for signing" do
					result = t.signature_form(obj, i, scriptPubKey11, 0x82)
					expect(result[:ins].size).to eql 1
					expect(result[:ins][0][:scriptSig]).to eql scriptPubKey11
					expect(result[:outs].size).to eql 0
				end
			end

			context "For SIGHASH_SINGLE + SIGHASH_ANYONECANPAY" do

				it "prepares transaction for signing" do
					result = t.signature_form(obj, i, scriptPubKey11, 0x83)
					expect(result[:ins].size).to eql 1
					expect(result[:ins][0][:scriptSig]).to eql scriptPubKey11
					expect(result[:outs].size).to eql 3
					expect(result[:outs][0][:value]).to eql 2**64 - 1
					expect(result[:outs][0][:scriptPubKey]).to eql ''
					expect(result[:outs][2][:value]).to eql 2**64 - 1
					expect(result[:outs][2][:scriptPubKey]).to eql ''
					expect(result[:outs][1][:value]).to eql sp.change_endianness value232
					expect(result[:outs][1][:scriptPubKey]).to eql scriptPubKey232[2..-1]
				end
			end
		end
	end

	context ".bin_txhash" do

		context "given 1-1 transaction" do

			context "For SIGHASH_ALL" do
				
				it "raw hashes transaction" do
					result = t.bin_txhash tx11
					expect(result.size).to eql 32
				end
			end

			context "For SIGHASH_NONE" do
				
				it "raw hashes transaction" do
					result = t.bin_txhash(tx11, 2)
					expect(result.size).to eql 32
				end
			end

			context "For SIGHASH_SINGLE" do
				
				it "raw hashes transaction" do
					result = t.bin_txhash(tx11, 3)
					expect(result.size).to eql 32
				end
			end

			context "For SIGHASH_ALL + SIGHASH_ANYONECANPAY" do
				
				it "raw hashes transaction" do
					result = t.bin_txhash(tx11, 81)
					expect(result.size).to eql 32
				end
			end

			context "For SIGHASH_NONE + SIGHASH_ANYONECANPAY" do
				
				it "raw hashes transaction" do
					result = t.bin_txhash(tx11, 82)
					expect(result.size).to eql 32
				end
			end

			context "For SIGHASH_SINGLE + SIGHASH_ANYONECANPAY" do
				
				it "raw hashes transaction" do
					result = t.bin_txhash(tx11, 83)
					expect(result.size).to eql 32
				end
			end
		end
	end

	context ".txhash" do

		context "given 2-3 transaction" do

			context "For SIGHASH_ALL" do

				it "hashes transaction" do
					result = t.txhash tx23
					expect(result.size).to eql 64
				end
			end

			context "For SIGHASH_NONE" do

				it "hashes transaction" do
					result = t.txhash(tx23, 2)
					expect(result.size).to eql 64
				end
			end

			context "For SIGHASH_SINGLE" do

				it "hashes transaction" do
					result = t.txhash(tx23, 3)
					expect(result.size).to eql 64
				end
			end

			context "For SIGHASH_ALL + SIGHASH_ANYONECANPAY" do

				it "hashes transaction" do
					result = t.txhash(tx23, 81)
					expect(result.size).to eql 64
				end
			end

			context "For SIGHASH_NONE + SIGHASH_ANYONECANPAY" do

				it "hashes transaction" do
					result = t.txhash(tx23, 82)
					expect(result.size).to eql 64
				end
			end

			context "For SIGHASH_SINGLE + SIGHASH_ANYONECANPAY" do

				it "hashes transaction" do
					result = t.txhash(tx23, 83)
					expect(result.size).to eql 64
				end
			end
		end
	end

	context ".ecdsa_tx_sign" do

		context "For SIGHASH_ALL" do

			it "signs transaction" do
				result = t.ecdsa_tx_sign(tx11, priv)
				expect(ECDSA.new.bip66? result[0..-3]).to be true
				expect(result[-2..-1]).to eql '01'
			end
		end

		context "For SIGHASH_NONE" do

			it "signs transaction" do
				result = t.ecdsa_tx_sign(tx11, priv, 2)
				expect(ECDSA.new.bip66? result[0..-3]).to be true
				expect(result[-2..-1]).to eql '02'
			end
		end

		context "For SIGHASH_SINGLE" do

			it "signs transaction" do
				result = t.ecdsa_tx_sign(tx11, priv, 3)
				expect(ECDSA.new.bip66? result[0..-3]).to be true
				expect(result[-2..-1]).to eql '03'
			end
		end

		context "For SIGHASH_ALL + SIGHASH_ANYONECANPAY" do
			
			it "signs transaction" do
				result = t.ecdsa_tx_sign(tx23, priv, 81)
				expect(ECDSA.new.bip66? result[0..-3]).to be true
				expect(result[-2..-1]).to eql '81'
			end
		end

		context "For SIGHASH_NONE + SIGHASH_ANYONECANPAY" do
			
			it "signs transaction" do
				result = t.ecdsa_tx_sign(tx23, priv, 82)
				expect(ECDSA.new.bip66? result[0..-3]).to be true
				expect(result[-2..-1]).to eql '82'
			end
		end

		context "For SIGHASH_SINGLE + SIGHASH_ANYONECANPAY" do
			
			it "signs transaction" do
				result = t.ecdsa_tx_sign(tx23, priv, 83)
				expect(ECDSA.new.bip66? result[0..-3]).to be true
				expect(result[-2..-1]).to eql '83'
			end
		end
	end

	context ".ecdsa_tx_verify" do

		context "given 1-1 transaction" do

			context "For SIGHASH_ALL" do

				it "verifies transaction" do
					signature = t.ecdsa_tx_sign(tx11, priv)
					result = t.ecdsa_tx_verify(tx11, signature, x+y)
					expect(result).to be true
				end
			end

			context "For SIGHASH_NONE" do

				it "verifies transaction" do
					signature = t.ecdsa_tx_sign(tx11, priv, 2)
					result = t.ecdsa_tx_verify(tx11, signature, x+y, 2)
					expect(result).to be true
				end
			end

			context "For SIGHASH_SINGLE" do

				it "verifies transaction" do
					signature = t.ecdsa_tx_sign(tx11, priv, 3)
					result = t.ecdsa_tx_verify(tx11, signature, x+y, 3)
					expect(result).to be true
				end
			end
		end

		context "given 2-3 transaction" do

			context "For SIGHASH_ALL" do

				it "verifies transaction" do
					signature = t.ecdsa_tx_sign(tx23, priv)
					result = t.ecdsa_tx_verify(tx23, signature, x+y)
					expect(result).to be true
				end
			end

			context "For SIGHASH_NONE" do

				it "verifies transaction" do
					signature = t.ecdsa_tx_sign(tx23, priv, 2)
					result = t.ecdsa_tx_verify(tx23, signature, x+y, 2)
					expect(result).to be true
				end
			end

			context "For SIGHASH_SINGLE" do

				it "verifies transaction" do
					signature = t.ecdsa_tx_sign(tx23, priv, 3)
					result = t.ecdsa_tx_verify(tx23, signature, x+y, 3)
					expect(result).to be true
				end
			end

			context "For SIGHASH_ALL + SIGHASH_ANYONECANPAY" do

				it "verifies transaction" do
					signature = t.ecdsa_tx_sign(tx23, priv, 81)
					result = t.ecdsa_tx_verify(tx23, signature, x+y, 81)
					expect(result).to be true
				end
			end

			context "For SIGHASH_NONE + SIGHASH_ANYONECANPAY" do

				it "verifies transaction" do
					signature = t.ecdsa_tx_sign(tx23, priv, 82)
					result = t.ecdsa_tx_verify(tx23, signature, x+y, 82)
					expect(result).to be true
				end
			end

			context "For SIGHASH_SINGLE + SIGHASH_ANYONECANPAY" do

				it "verifies transaction" do
					signature = t.ecdsa_tx_sign(tx23, priv, 83)
					result = t.ecdsa_tx_verify(tx23, signature, x+y, 83)
					expect(result).to be true
				end
			end
		end
	end

	# context ".ecdsa_tx_recover" do

	# 	context "given transaction and signature" do

	# 		context "For SIGHASH_ALL" do

	# 			it "finds pubkey" do
	# 				signature = t.ecdsa_tx_sign(tx23, priv)
	# 				pubkey = t.ecdsa_tx_recover(tx23, signature)
	# 				expect(pubkey).to eql x+y
	# 			end
	# 		end

	# 		context "For SIGHASH_NONE" do

	# 			it "finds pubkey" do
	# 				signature = t.ecdsa_tx_sign(tx23, priv, 2)
	# 				pubkey = t.ecdsa_tx_recover(tx23, signature, 2)
	# 				expect(pubkey).to eql x+y
	# 			end
	# 		end

	# 		context "For SIGHASH_SINGLE" do

	# 			it "finds pubkey" do
	# 				signature = t.ecdsa_tx_sign(tx23, priv, 3)
	# 				pubkey = t.ecdsa_tx_recover(tx23, signature, 3)
	# 				expect(pubkey).to eql x+y
	# 			end
	# 		end
	# 	end
	# end

	context ".sign" do

		context "given deserialized transaction input" do

			i = 0;
			tx = t.deserialize tx11

			it "signs it" do
				tr = t.sign(tx, i, priv)
				sig = tr[:ins][0][:scriptSig][2..141]
				expect(ECDSA.new.bip66?(sig)).to be true
			end

			it "signs the same every time" do
				expect(t.sign(tx, i, priv)).to eql t.sign(tx, i, priv)
			end
		end
	end

	context "sign_all" do

		context "given a deserialized MIMO transaction" do

			it "signs each input" do

				tx = t.sign_all(t.deserialize(tx23), priv)

				sig0 = tx[:ins][0][:scriptSig][2..141]
				expect(ECDSA.new.bip66?(sig0)).to be true

				sig1 = tx[:ins][1][:scriptSig][2..143]
				expect(ECDSA.new.bip66?(sig1)).to be true
			end
		end
	end

	context ".multisign" do

		context "given a transaction" do

			it "signs it" do
				i = 0
				tx = t.deserialize tx11
				script = scriptPubKey11[2..-1]
				sig = t.multisign(tx, i, script, priv)
				expect(ECDSA.new.bip66?(sig[0..-3])).to be true
			end
		end
	end

	context ".apply_multisignatures" do

		context "given a deserialized multisig tx" do

			it "appends signatures and scripts" do
				script = "524104a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f" +
					"09e63975a1700c9f4d4df849323dac06cf3bd6458cd41046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669f" +
					"f90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187410411ffd36c7" +
					"0776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea60" +
					"0bd217870a8b4f1f09f3a8e8353ae"
				i = 0
				priv1 = priv
				priv2 = "2" * 64
				priv3 = "3" * 64
				scriptPK = scriptPubKey11[2..-1]

				tx = t.deserialize tx11

				sig1 = t.multisign(tx, i, scriptPK, priv1)
				sig2 = t.multisign(tx, i, scriptPK, priv2)
				sig3 = t.multisign(tx, i, scriptPK, priv3)

				res = t.apply_multisignatures(tx11, i, script, [sig1])
				sig = res[:ins][0][:scriptSig][3..142]
				expect(ECDSA.new.bip66? sig).to be true

				res = t.apply_multisignatures(tx11, i, script, [sig1, sig2, sig3])
				sig = res[:ins][0][:scriptSig][3..142]
				expect(ECDSA.new.bip66? sig).to be true

				res = t.apply_multisignatures(tx11, i, script, sig1, sig2, sig3)
				sig = res[:ins][0][:scriptSig][3..142]
				expect(ECDSA.new.bip66? sig).to be true

				sig = res[:ins][0][:scriptSig][147..286]
				expect(ECDSA.new.bip66? sig).to be true

				sig = res[:ins][0][:scriptSig][291..430]
				expect(ECDSA.new.bip66? sig).to be true
			end
		end
	end

	context ".read_var_int" do

		context "given a series of varints" do

			it "reads them as ints" do

				varint = %w(01 fc fdfd00 fdff01 fdfeff feffff0000 feffff0100 fefeffffff ffffffffff00000000)
				int = [1, 252, 253, 511, 65534, 65535, 131071, 2**32 - 2, 2**32 - 1]

				0.upto varint.size - 1 do |i|
					expect(t.read_var_int! varint[i]).to eql int[i]
				end
			end
		end
	end

	context ".read_var_string" do

		context ".given a series of varstrings" do

			it "reads them as strings" do

				varstr = ['01h', 'fc' + 'h'*252, 'fdfd00' + 'h'*253, '00']
				str = ['h', 'h'*252, 'h'*253, '']

				0.upto varstr.size - 1 do |i|
					expect(t.read_var_string! varstr[i]).to eql str[i]
				end
			end
		end
	end

	context	".to_var_int" do

		context "given a series of ints" do

			it "converts them to varints" do

				int = [0, 252, 253, 511, 65534, 65535, 131071, 2**32 - 2, 2**32 - 1]
				varint = %w(00 fc fdfd00 fdff01 fdfeff feffff0000 feffff0100 fefeffffff ffffffffff00000000)

				0.upto int.size - 1 do |i|
					expect(t.to_var_int int[i]).to eql varint[i]
				end
			end
		end
	end

	context ".to_var_str" do

		context ".given a series of strings" do

			it "convert them to varstrings" do

				varstr = ['0101', 'fc' + '01'*252, 'fdfd00' + '01'*253, '00']
				str = ['01', '01'*252, '01'*253, '']

				0.upto str.size - 1 do |i|
					expect(t.to_var_str str[i]).to eql varstr[i]
				end
			end
		end
	end

	context ".mkout" do

		context "given nil input" do

			it "raises error" do
				expect{t.mkout(nil, nil)}.to raise_error ArgumentError
			end
		end

		# context "given nil amount" do
		# 	it "raises error" do
		# 		expect{t.mkout('', nil)}.to raise_error ArgumentError
		# 	end
		# end

		context "given too small amount" do
			it "raises error" do
				expect{t.mkout(500, nil)}.to raise_error ArgumentError
			end
		end

		context "given nil script" do
			it "raises error" do
				expect{t.mkout(546, nil)}.to raise_error ArgumentError
			end
		end

		context "given empty script" do
			it "raises error" do
				expect{t.mkout(546, '')}.to raise_error ArgumentError
			end
		end

		# context "given invalid script" do
		# 	it "raises error" do
		# 		expect{t.mkout(546, '19761488ac')}.to raise_error ArgumentError
		# 	end
		# end

		context "given a valid script" do

			it "creates a valid output" do
				output = t.mkout(scriptPubKey11)

				expect(output[:value]).to eql 546.to_s(16).rjust(16, '0')
				expect(output[:scriptPubKey]).to eql scriptPubKey11
			end
		end

		context "given a valid input" do

			it "creates a valid outpoint" do
				output = t.mkout(5000, scriptPubKey11)

				expect(output[:value]).to eql 5000.to_s(16).rjust(16, '0')
				expect(output[:scriptPubKey]).to eql scriptPubKey11
			end
		end
	end

	context ".mkin" do

		context "given empty input" do

			it "raises error" do
				expect{t.mkin('all', 'some', '')}.to raise_error ArgumentError
			end
		end

		# context "given invalid signature" do

		# 	it "raises error" do
		# 		expect{t.mkin('hash', 'index', '3045')}.to raise_error ArgumentError
		# 	end
		# end

		context "given valid input" do

			it "creates input point" do

				input = t.mkin(hash11, index11, scriptSig11)
				
				expect(input[:outpoint][:hash]).to eql hash11

				expect(input[:outpoint][:index]).to eql index11

				expect(input[:scriptSig]).to eql scriptSig11

				expect(input[:sequence]).to eql sequence
			end
		end
	end

	context "mktx" do

		context "given nil input" do

			it "raises error" do
				expect{t.mktx(nil)}.to raise_error ArgumentError
			end
		end

		context "given empty input" do

			it "raises error" do
				expect{t.mktx('')}.to raise_error ArgumentError
			end
		end

		context "given too few arguments" do

			it "raises error" do
				expect{t.mktx('a')}.to raise_error ArgumentError
				expect{t.mktx(['a'])}.to raise_error ArgumentError
			end
		end

		context "given proper inputs and outputs" do

			it "creates a valid transaction" do

				output = t.mkout(5000, scriptPubKey11[2..-1])
				input = t.mkin(hash11, index11, scriptSig11[2..-1])
				tx = t.mktx(output, input)

				expect(tx[:version]).to eql sp.change_endianness version

				expect(tx[:ins][0][:outpoint][:hash]).to eql hash11

				expect(tx[:ins][0][:outpoint][:index]).to eql index11

				expect(tx[:ins][0][:scriptSig]).to eql scriptSig11[2..-1]

				expect(tx[:ins][0][:sequence]).to eql sequence

				#expect(tx[:outs][0][:value]).to eql 546

				expect(tx[:outs][0][:scriptPubKey]).to eql scriptPubKey11[2..-1]

				expect(tx[:locktime]).to eql locktime

				# ver = t.read_and_modify!(4, tx)
				# expect(ver).to eql version

				# sz = t.read_and_modify!(1, tx)
				# hash = t.read_and_modify!(32, tx)
				# expect(hash).to eql sp.change_endianness hash11

				# index = t.read_and_modify!(4, tx)
				# expect(index).to eql index11

				# sig = t.read_and_modify!(140, tx)
				# expect(sig).to eql scriptSig11

				# seq = t.read_and_modify!(4, tx)
				# expect(seq). to eql sequence

				# sz = t.read_and_modify!(1, tx)

				# val = t.read_and_modify!(8, tx)
				# expect(val).to eql sp.change_endianness 5000.to_s(16).rjust(16, '0')
				
				# sz = t.read_and_modify!(1, tx)

				# scr = t.read_and_modify!(25, tx)
				# expect(scr).to eql scriptPubKey11[2..-1]
				
				# lock = t.read_and_modify!(4, tx)
				# expect(lock).to eql locktime
			end
		end
	end
end