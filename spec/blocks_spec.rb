require 'blocks'

describe Blocks do

	b = Blocks.new

	version = '00000001'
	prevhash = '00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81'
	merkle_root = '2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3'
	timestamp = '4dd7f5c7'
	bits = '1a44b9f2'
	nonce = '9546a142'
	hash = '00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d'

	header = {version: version, prevhash: prevhash, merkle_root: merkle_root, timestamp: timestamp, bits: bits, nonce: nonce, hash: hash}

	context ".serialize_header" do

		context "given deserialized block header" do

			result = b.serialize_header header

			it "serializes it" do
				expect(result.respond_to? :each_char).to be true
			end

			it "serializes correctly" do
				expect(result.length).to eql 80
			end
		end

		context "given incorrect hash" do

			it "raises error" do
				header[:hash] = '15'
				expect{b.serialize_header header}.to raise_error RuntimeError
			end
		end
	end

	context ".deserialize_header" do

		context "given serialized header" do

			it "deserializes it" do
				header[:hash] = hash
				result = b.serialize_header header
				result = b.deserialize_header result
				expect(result[:version]).to eql version
				expect(result[:prevhash]).to eql prevhash
				expect(result[:merkle_root]).to eql merkle_root
				expect(result[:timestamp]).to eql timestamp
				expect(result[:bits]).to eql bits
				expect(result[:nonce]).to eql nonce
				expect(result[:hash]).to eql hash
			end
		end
	end

	context ".mk_merkle_proof" do

		context "given transaction hashes" do

			it "returns path to a hash" do
				hashes = ['51d37bdd871c9e1f4d5541be67a6ab625e32028744d7d4609d0c37747b40cd2d', 
						'60c25dda8d41f8d3d7d5c6249e2ea1b05a25bf7ae2ad6d904b512b31f997e1a1',
						'01f314cdd8566d3e5dbdd97de2d9fbfbfd6873e916a00d48758282cbb81a45b9', 
						'b519286a1040da6ad83c783eb2872659eaf57b1bec088e614776ffe7dc8f6d01']
				index = 2

				merkle_proof = b.mk_merkle_proof(header, hashes, index)
				expect(hashes[index]).to eql merkle_proof[:hash]
				expect(merkle_proof[:siblings].length).to eql 2
			end
		end
	end
end