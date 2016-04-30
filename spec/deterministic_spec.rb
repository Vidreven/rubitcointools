require 'deterministic'

describe Deterministic do

	d = Deterministic.new

	vbytes = [Deterministic::MAINNET_PRIVATE, Deterministic::MAINNET_PUBLIC, Deterministic::TESTNET_PRIVATE, Deterministic::TESTNET_PUBLIC]
	depth = 1
	fingerprint = "ABCDEFBA"
	i = 0
	chaincode = '1' * 64

	x = '0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179'
	y = '8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'

	context "raw_bip32_ckd" do

		context "given parent private key" do

			key = chaincode

			it "returns rawtuple child private key" do

				privckd = d.raw_bip32_ckd([vbytes[0], depth, fingerprint, i, chaincode, key], i)
				expect(privckd.size).to eql 6
				expect(privckd[0]).to eql vbytes[0]
				expect(privckd[1]).to eql depth + 1
				expect(privckd[2].size).to eql 4
				expect(privckd[3]).to eql 0.chr * 4
				expect(privckd[4].size).to eql 32
				expect(privckd[5].size).to eql 32
			end

			it "returns hardened child key" do
				i = 2**31
				privckd = d.raw_bip32_ckd([vbytes[0], depth, fingerprint, i, chaincode, key], i)
				expect(privckd.size).to eql 6
				expect(privckd[0]).to eql vbytes[0]
				expect(privckd[1]).to eql depth + 1
				expect(privckd[2].size).to eql 4
				expect(privckd[3].unpack('H*')[0]).to eql i.to_s 16
				expect(privckd[4].size).to eql 32
				expect(privckd[5].size).to eql 32
			end
		end

		context "given parent public key" do

			it "returns rawtuple child public key" do
				i = 0
				pubckd = d.raw_bip32_ckd([vbytes[1], depth, fingerprint, i, chaincode, x+y], i)
				expect(pubckd.size).to eql 6
				expect(pubckd[0]).to eql vbytes[1]
				expect(pubckd[1]).to eql depth + 1
				expect(pubckd[2].size).to eql 4
				expect(pubckd[3]).to eql 0.chr * 4
				expect(pubckd[4].size).to eql 32
				expect(pubckd[5].size).to eql 65
				expect(pubckd[5][0]).to eql 4.chr
			end

			it "doesnt allow ckd from hardened key" do
				i = 2**31
				expect{d.raw_bip32_ckd([vbytes[1], depth, fingerprint, i, chaincode, x+y], i)}.to raise_error ArgumentError
			end
		end
	end

	context ".bip32_serialize" do

		context "given private rawtuple" do

			it "serializes it" do
				i = 0
				privckd = d.raw_bip32_ckd([vbytes[0], depth, fingerprint, i, chaincode, chaincode], i)
				result = d.bip32_serialize privckd
				expect(result[0..3]).to eql "xprv"
				expect(result.size).to eql 111
			end
		end

		context "given public rawtuple" do

			it "serializes it" do
				i = 0
				pubckd = d.raw_bip32_ckd([vbytes[1], depth, fingerprint, i, chaincode, x+y], i)
				result = d.bip32_serialize pubckd
				expect(result[0..3]).to eql 'xpub'
				expect(result.size).to eql 111
			end
		end

		context "given testnet private rawtuple" do

			it "serializes it" do
				i = 0
				privckd = d.raw_bip32_ckd([vbytes[2], depth, fingerprint, i, chaincode, chaincode], i)
				result = d.bip32_serialize privckd
				expect(result[0..3]).to eql 'tprv'
				expect(result.size).to eql 111
			end
		end

		context "given testnet public rawtuple" do

			it "serializes it" do
				i = 0
				pubckd = d.raw_bip32_ckd([vbytes[3], depth, fingerprint, i, chaincode, x+y], i)
				result = d.bip32_serialize pubckd
				expect(result[0..3]).to eql 'tpub'
				expect(result.size).to eql 111
			end
		end
	end

	context ".bip32_deserialize" do

		i = 0

		context "given private key" do

			it "deserializes it" do
				privckd = d.raw_bip32_ckd([vbytes[0], depth, fingerprint, i, chaincode, chaincode], i)
				result = d.bip32_serialize privckd
				result = d.bip32_deserialize result
				expect(result).to eql privckd
			end
		end

		context "given public key" do

			it "deserializes it" do
				pubckd = d.raw_bip32_ckd([vbytes[1], depth, fingerprint, i, chaincode, x+y], i)
				result = d.bip32_serialize pubckd
				result = d.bip32_deserialize result
				expect(result).to eql pubckd
			end
		end
	end

	context ".raw_bip32_privtopub" do

		context "given private rawtuple" do

			it "returns public rawtuple" do
				privckd = d.raw_bip32_ckd([vbytes[0], depth, fingerprint, i, chaincode, chaincode], i)
				pubckd = d.raw_bip32_privtopub privckd
				expect(pubckd[0]).to eql vbytes[1]
			end
		end

		context "given private testnet rawtuple" do

			it "returns public testnet rawtuple" do
				privckd = d.raw_bip32_ckd([vbytes[2], depth, fingerprint, i, chaincode, chaincode], i)
				pubckd = d.raw_bip32_privtopub privckd
				expect(pubckd[0]).to eql vbytes[3]
			end
		end 
	end

	context ".bip32_ckd" do

		context "given parent private key" do

			it "derives child private key" do
				i = 0
				privckd = d.raw_bip32_ckd([vbytes[0], depth, fingerprint, i, chaincode, chaincode], i)
				result = d.bip32_serialize privckd
				key = d.bip32_ckd(result, i)
				expect(result[0..3]).to eql "xprv"
				expect(result.size).to eql 111
			end

			it "returns hardened child key" do
				i = 2**31
				privckd = d.raw_bip32_ckd([vbytes[0], depth, fingerprint, i, chaincode, chaincode], i)
				result = d.bip32_serialize privckd
				key = d.bip32_ckd(result, i)
				expect(result[0..3]).to eql "xprv"
				expect(result.size).to eql 111
			end
		end

		context "given parent public key" do

			it "returns child public key" do
				i = 0
				pubckd = d.raw_bip32_ckd([vbytes[1], depth, fingerprint, i, chaincode, x+y], i)
				result = d.bip32_serialize pubckd
				key = d.bip32_ckd(result, i)
				expect(result[0..3]).to eql "xpub"
				expect(result.size).to eql 111
			end
		end
	end

	context ".bip32_master_key" do

		context "wanting key seed" do

			it "generates key seed" do
				seed = '132654798'
				result = d.bip32_master_key seed
				expect(result[0..3]).to eql "xprv"
				expect(result.size).to eql 111
			end
		end
	end

	context ".bip32_bin_extract_key" do

		context "given private rawtuple" do

			it "returns bin private key" do
				privckd = d.raw_bip32_ckd([vbytes[0], depth, fingerprint, i, chaincode, chaincode], i)
				result = d.bip32_serialize privckd
				key = d.bip32_bin_extract_key result
				expect(key.size).to eql 32
			end
		end

		context "given public rawtuple" do
		
			it "returns bin public key" do
				pubckd = d.raw_bip32_ckd([vbytes[1], depth, fingerprint, i, chaincode, x+y], i)
				result = d.bip32_serialize pubckd
				key = d.bip32_bin_extract_key result
				expect(key.size).to eql 65
			end
		end
	end

	context ".bip32_extract_key" do

		context "given private rawtuple" do

			it "returns hex private key" do
				privckd = d.raw_bip32_ckd([vbytes[0], depth, fingerprint, i, chaincode, chaincode], i)
				result = d.bip32_serialize privckd
				key = d.bip32_extract_key result
				expect(key.size).to eql 64
			end
		end

		context "given public rawtuple" do
		
			it "returns hex public key" do
				pubckd = d.raw_bip32_ckd([vbytes[1], depth, fingerprint, i, chaincode, x+y], i)
				result = d.bip32_serialize pubckd
				key = d.bip32_extract_key result
				expect(key.size).to eql 130
			end
		end
	end
end