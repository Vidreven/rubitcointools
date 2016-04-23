require 'ecdsa'

describe ECDSA do
	
	e = ECDSA.new

	r = '008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c7033'
	s = '3b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31'
	sig = e.encode_sig('30', r, s)

	priv = '1' * 64
	msg1 = "76a914b8109afa1fa52d3a5fc9376a99d946ab0628eb0c88ac"
	msg2 = "76a9147bdade678c0d440012a266f8367cb42ad6d62daa88ac"
	msg3 = "76a914e31239e6c27baee56af5c112f123bac9d0df84f688ac"

	x = '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a'
	y = 'a385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'

	context "#encode_sig" do

		context "given signature" do

			it "encodes to DER" do
				expect(sig).not_to eql ''
			end

			# Minimum and maximum size constraints.
			it "is of proper length" do
				expect(sig.length).not_to be > 144
				expect(sig.length).not_to be < 18
			end

			# A signature is of type 0x30 (compound).
			it "has proper type" do
				expect(sig[0..1]).to eql '30'
			end

			# Make sure the length covers the entire signature.
			it "has proper length field" do
				expect(sig[2..3].to_i(16) * 2).to eql sig.length - 4
			end

			# Make sure the length of the S element is still inside the signature.
			it "has proper S element" do
				expect(8 + sig[6..7].to_i(16) * 2 < sig.length - 2).to be true
			end

			# Verify that the length of the signature matches the sum of the length
			# of the elements.
			it "has length = to sum of elements" do
				expect(8 + sig[6..7].to_i(16) * 2 + sig[76..77].to_i(16) * 2).to eql sig.length - 4
			end

			# Zero-length integers are not allowed for R.
			it "has proper R" do
				expect(sig[6..7].to_i(16)).not_to eql 0
			end

			# Negative numbers are not allowed for R.
			it "has positive R" do
				expect(sig[8..9].to_i(16) & 0x80).not_to eql 0x80
			end

			# Zero-length integers are not allowed for S.
			it "has proper S" do
				expect(sig[76..77].to_i(16)).not_to eql 0
			end

			# Negative numbers are not allowed for S.
			it "has positive S" do
				expect(sig[78..79].to_i(16) & 0x80).not_to eql 0x80
			end
		end
	end

	context "#decode_sig" do

		context	"given DER encoded signature" do

			it "returns decoded signature" do
				decoded = e.decode_sig sig
				expect(decoded).to eql ['30', r, s]
			end
		end
	end

	context "#bip66?" do

		context "given ECDSA signature" do

			it "checks if it's strict DER encoded" do
				sigs = ['1' * 8, '2' * 143, '20' + '1' * 140, '3016' + '2' * 138,
					'30450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c7033',
					'30450200' + '2' * 134, '3045022281' + '2' * 132,
					'30450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c703302003b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31',
					'30450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c70330220811c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31',
					'30450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c703302103b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31',
					'30450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c703302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31',
					'304503' + '1' * 136,
					'30450221007f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c703302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31',
					'30450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c703304203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31',
					'30450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c70330221300b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31',
					'30450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c703302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31',
					'30460221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c70330221008b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31']
				
				sigs.each_index do |i|
					if [10, 15, 16].include? i
						expect(e.bip66? sigs[i]).to be true
					else
						expect(e.bip66? sigs[i]).to be false
					end
				end
			end
		end
	end

	context "#deterministic_generate_k" do

		context "given message and private key" do

			it "derives k for ECDSA" do
				k = e.deterministic_generate_k(msg1, priv)
				expect(k.to_s(16).size).to eql 64
			end

			it "derives unique k's" do
				k1 = e.deterministic_generate_k(msg1, priv)
				k2 = e.deterministic_generate_k(msg2, priv)
				k3 = e.deterministic_generate_k(msg3, priv)

				expect(k1).not_to eql k2
				expect(k1).not_to eql k3
				expect(k2).not_to eql k3
			end
		end
	end

	context "#ecdsa_raw_sign" do

		context "given a message" do

			signature = e.ecdsa_raw_sign(msg1, priv)

			it "performs ECDSA" do
				expect(signature.size).to eql 3
			end

			it "returns correct type" do
				expect(signature[0]).to eql 31
			end

			it "returns proper length R" do
				expect(signature[1].length).to eql 64
			end

			it "returns proper length S" do
				expect(signature[2].length).to eql 64
			end
		end
	end

	context "#ecdsa_raw_verify" do

		context "given message and signature" do

			it "verifies signature" do
				signature = e.ecdsa_raw_sign(msg1, priv)
				result = e.ecdsa_raw_verify(msg1, signature, x+y)
				expect(result). to be true
			end
		end
	end

	context "#ecdsa_raw_recover" do

		context "given message and signature" do

			it "recoveres pubkey" do
				signature = e.ecdsa_raw_sign(msg1, priv)
				pubkey = e.ecdsa_raw_recover(msg1, signature)
				expect(x+y).to eql Keys.new.encode_pubkey(pubkey, :hex)
			end
		end
	end
end