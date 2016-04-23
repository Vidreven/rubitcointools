require 'keys'
require 'ecc'

describe Keys do

	k = Keys.new

	x = '0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179'
	y = '8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
	pubformats = [:decimal, :bin, :hex, :bin_compressed, :hex_compressed, :bin_electrum, :hex_electrum]
	pubkeys = [k.decode_pubkey(x+y), 4.chr + 1.chr * 64, x+y, 2.chr + 0.chr * 31 + 1.chr,
			'03' + '0' * 62 + '01', 1.chr * 64, 'd' * 128]

	decimal = k.decode_privkey '1' * 64
	privformats = [:decimal, :bin, :bin_compressed, :hex_compressed, :wif, :wif_compressed]
	privkeys = [decimal, 1.chr * 32, 1.chr * 33, '1' * 64, '1' * 64 + '01', '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ',
			'KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp']

	context "#get_pubkey_format" do

		context "given invalid key format" do

			it "raises error" do
				expect{k.get_pubkey_format ''}.to raise_error ArgumentError
			end
		end

		context "given an array" do

			it "gets identified as decimal" do
				format = k.get_pubkey_format [1234567, 987654]
				expect(format).to eql :decimal
			end
		end

		context "given 65 byte key" do

			it "gets identified as bin" do
				format = k.get_pubkey_format(4.chr + 1.chr * 64)
				expect(format).to eql :bin
			end
		end

		context "given 130 char key" do
			
			it "gets identified as hex" do
				format = k.get_pubkey_format('04' + 'b' * 128)
				expect(format).to eql :hex
			end
		end

		context "given a 33 byte key" do

			it "gets identified as bin_compressed" do
				format = k.get_pubkey_format(2.chr + 1.chr * 32)
				expect(format).to eql :bin_compressed
			end
		end

		context "given a 66 char key" do

			it "gets identified as hex_compressed" do
				format = k.get_pubkey_format('03' + 'c' * 64)
				expect(format).to eql :hex_compressed
			end
		end

		context "given a 64 byte key" do

			it "gets identified as bin_electrum" do
				format = k.get_pubkey_format(5.chr * 64)
				expect(format).to eql :bin_electrum
			end
		end

		context "given a 128 char key" do

			it "gets identified as hex_electrum" do
				format = k.get_pubkey_format('d' * 128)
				expect(format).to eql :hex_electrum
			end
		end
	end

	context "#decode_pubkey" do

		pubkeys.each do |key|

			context "given key in #{k.get_pubkey_format key}" do

				it "returns decimal pubkey" do
					key = k.decode_pubkey key
					expect(k.get_pubkey_format key).to eql :decimal
				end
			end
		end
	end

	context "#encode_pubkey" do

		pubkeys.each do |key|
			context "given key in #{k.get_pubkey_format key} format" do
				
				pubformats.each do |format|

					it "returns key in #{format}" do
						result = k.encode_pubkey(key, format)
						expect(k.get_pubkey_format result).to eql format
					end
				end
			end
		end
	end

	context "#get_privkey_format" do

		context "given integer key" do

			it "gets identified as decimal" do
				format = k.get_privkey_format 123456789
				expect(format).to eql :decimal
			end
		end

		context "given 32 byte key" do
			it "gets identified as bin" do
				format = k.get_privkey_format 1.chr * 32
				expect(format).to eql :bin
			end
		end

		context "given 33 byte key" do
			it "gets identified as bin_compressed" do
				format = k.get_privkey_format 1.chr * 33
				expect(format).to eql :bin_compressed
			end
		end

		context "given 64 char key" do
			it "gets identified as hex" do
				format = k.get_privkey_format '1' * 64
				expect(format).to eql :hex
			end
		end

		context "given 66 char key" do
			it "gets identified as hex_compressed" do
				format = k.get_privkey_format '1' * 66
				expect(format).to eql :hex_compressed
			end
		end

		context "given wif key" do
			it "gets identified as wif" do
				format = k.get_privkey_format '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
				expect(format).to eql :wif
			end
		end

		context "given wif_compressed key" do
			it "gets identified as wif_compressed" do
				format = k.get_privkey_format 'KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp'
				expect(format).to eql :wif_compressed
			end
		end
	end

	context "#decode_privkey" do

		privkeys.each do |key|

			context "given key in #{k.get_privkey_format key}" do
				
				it "returns decimal privkey" do
					key = k.decode_privkey key
					expect(k.get_privkey_format key).to eql :decimal
				end
			end
		end
	end

	context "#encode_privkey" do

		privkeys.each do |key|
			context "given key in #{k.get_privkey_format key} format" do
				
				privformats.each do |format|

					it "returns key in #{format}" do
						result = k.encode_privkey(key, format)
						expect(k.get_privkey_format result).to eql format
					end
				end
			end
		end
	end

	context "#add_pubkeys" do

		pubkeys.each do |key1|

			context "given key in #{k.get_pubkey_format key1} format" do

				pubkeys.each do |key2|

					it "adds to it key in #{k.get_pubkey_format key2} format" do
						result = k.add_pubkeys(key1, key2)
						expect(k.get_pubkey_format result).to eql k.get_pubkey_format key1
					end
				end
			end
		end
	end

	context "#add_privkeys" do

		privkeys.each do |key1|

			context "given key in #{k.get_privkey_format key1} format" do

				privkeys.each do |key2|

					it "adds to it key in #{k.get_privkey_format key2} format" do
						result = k.add_privkeys(key1, key2)
						expect(k.get_privkey_format result).to eql k.get_privkey_format key1
					end
				end
			end
		end
	end

	context "#compress" do

		formats = {
			decimal: :hex_compressed,
			bin: :bin_compressed,
			bin_compressed: :bin_compressed,
			hex: :hex_compressed,
			hex_compressed: :hex_compressed
		}

		keys = pubkeys[0..-3]

		keys.each do |key|

			format = k.get_pubkey_format key

			context "given key in #{format} format" do
				
				it "gets compressed to #{formats[format]}" do
					compressed = k.compress key
					expect(k.get_pubkey_format compressed).to eql formats[format]
				end
			end
		end

		context "given key in bin_electrum format" do

			it "raises error" do
				key = 1.chr * 64
				expect{k.compress key}.to raise_error ArgumentError
			end
		end

		context "given key in hex_electrum format" do

			it "raises error" do
				key = '1' * 128
				expect{k.compress key}.to raise_error ArgumentError
			end
		end
	end

	context "#decompress" do

		keys = pubkeys[0..-3]

		keys.each do |key|
			format = k.get_pubkey_format key

			if format.to_s.match 'compressed'
				context "given key in compressed format" do

					it "decompress key" do
						result = k.decompress key
						expect(k.get_pubkey_format result).not_to match /compressed/
					end
				end
			else
				context "given key in decompressed format" do

					it "returns key" do
						result = k.decompress key
						expect(k.get_pubkey_format result).to eql format
					end
				end
			end
		end
	end

	context "#privkey_to_pubkey" do

		context "given an invalid key" do

			it "raises error" do
				expect{k.privkey_to_pubkey (ECC::N + 1000)}.to raise_error ArgumentError
			end
		end

		privkeys.each do |key|

			format = k.get_privkey_format key

			context "given key in #{format} format" do

				it "converts it to pubkey" do
					result = k.privkey_to_pubkey key
					fmt = k.get_pubkey_format result
					expect(pubformats.include? fmt).to be true
				end
			end
		end
	end

	context "#pubkey_to_address" do

		pubkeys.each do |key|

			format = k.get_pubkey_format key

			context "given key in #{format} format" do

				it "converts it to address" do
					address = k.pubkey_to_address key
					expect(address[0]).to eql '1'
				end
			end
		end
	end

	context '#privkey_to_address' do

		privkeys.each do |key|

			format = k.get_privkey_format key

			context "given key in #{format} format" do

				it "converts it to address" do
					result = k.privkey_to_address key
					expect(result[0]).to eql '1'
				end
			end
		end
	end

	context "#random_key" do

		it "returns 64 char string" do
			string = k.random_key
			expect(string.length).to eql 64
		end

		it "returns unique strings" do
			string1 = k.random_key
			string2 = k.random_key
			expect(string2).not_to eql string1
		end
	end
end