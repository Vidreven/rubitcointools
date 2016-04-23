require 'specials'

describe Specials do

	s = Specials.new

	describe "#code_strings" do

		context "given a valid input" do

			s.code_strings.each do |key, value|
				
				it "returns proper base #{key}" do
					base = s.code_strings[key]
					expect(base.size).to eql key
				end
			end
		end
	end

	describe "#decode" do

		context "given a base 10 string" do

			it "returns base 10 string" do
				string = s.decode('123456', 10)
				expect(string).to eql 123456
			end
		end

		context "given a base 2 string" do

			it "converts it to base 10" do
				string = s.decode('1010', 2)
				expect(string).to eql 10
			end
		end

		context "given a base 16 string" do

			it "converts it to base 10" do
				string = s.decode('3C', 16)
				expect(string).to eql 60
			end
		end

		context "given a base 32 string" do

			it "converts it to base 10" do
				string = s.decode('ba', 32)
				expect(string).to eql 32
			end
		end

		context "given a base 58 string" do

			it "converts it to base 10" do
				string = s.decode('11', 58)
				expect(string).to eql 0
			end
		end

		context "given a base 256 string" do

			it "converts it to base 256" do
				string = s.decode(1.chr + 0.chr, 256)
				expect(string).to eql 256
			end
		end
	end

	describe "#encode" do
	
		context "given a base 10 string" do
		
			it "returns a base 10 string" do
				string = s.encode(34, 10)
				expect(string).to eql '34'
			end

			it "returns a base 2 string" do
				string = s.encode(10, 2)
				expect(string).to eql '1010'
			end

			it "returns a base 16 string" do
				string = s.encode(16, 16)
				expect(string).to eql '10'
			end

			it "returns a base 32 string" do
				string = s.encode(32, 32)
				expect(string).to eql 'ba'
			end

			it "returns a base 58 string" do
				string = s.encode(59, 58)
				expect(string).to eql '22'
			end

			it "returns a base 256 string" do
				string = s.encode(256, 256)
				expect(string).to eql 1.chr + 0.chr
			end
		end
	end

	describe "#changebase" do

		context "given an empty string" do

			it "returns an empty string" do
				string = s.changebase('', 16, 256)
				expect(string).to eql ''
			end
		end

		context "given a base 10 string" do

			it "returns a base 10 string" do
				string = s.changebase('34', 10, 10)
				expect(string).to eql '34'
			end
		end

		context "given a base 2 string" do

			it "converts it to base 16 string" do
				string = s.changebase("10000", 2, 16)
				expect(string).to eql '10'
			end
		end

		context "given a base 10 string" do

			it "converts it to base 16 string" do
				string = s.changebase("10", 16, 10)
				expect(string).to eql '16'
			end

			it "converts it to base 256 string" do
				string = s.changebase("1", 10, 256)
				expect(string).to eql 1.chr
			end
		end

		context "given a base 16 string" do

			it "converts it to base 2 string" do
				string = s.changebase("10", 16, 2)
				expect(string).to eql '10000'
			end

			it "converts it to base 10 string" do
				string = s.changebase("10", 16, 10)
				expect(string).to eql '16'
			end
		end

		context "given a base 32 string" do

			it "returns base 32 string" do
				string = s.changebase('222', 32, 32)
				expect(string).to eql '222'
			end

			it "converts it to base 10 string" do
				string = s.changebase('bi', 32, 10)
				expect(string).to eql '40'
			end
		end

		context "given a base 256 string" do
			it "converts it to base 10 string" do
				string = s.changebase(1.chr, 256, 10)
				expect(string).to eql '1'
			end

			it "converts it to base 16 string" do
				string = s.changebase("1", 256, 16)
				expect(string).to eql '31'
			end

			it "converts it to base 58 string" do
				string = s.changebase("10", 256, 58, 4)
				expect(string).to eql '14k7'
			end
		end
	end

	context "#bin_to_b58check" do

		context "given a string" do

			hexhash = '8193d2588a0d7a71eb19977083f7727870b6b048'
			binhash = s.changebase(hexhash, 16, 256)
			result = s.bin_to_b58check binhash

			it "returns non-empty string" do
				expect(result).not_to eql ''
			end

			it "start with 1" do
				expect(result[0]).to eql '1'
			end

			it "should have proper checksum" do
				checksum = Hashes.new.bin_dbl_sha256(0.chr+binhash)[0..3]
				expect(s.changebase(result[1..-1], 58, 256)[-4..-1]).to eql checksum
			end
		end
	end

	context "#b58check_to_bin" do

		context "given a b58check string" do

			it "converts it to binary string" do
				binstr = s.b58check_to_bin('1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa')
				cs = s.code_strings[256]
				expect(binstr.bytes.all?{|c| cs.include? c.chr}).to be true
			end
		end
	end

	context "#b58check_to_hex" do

		context "given a b58check string" do

			test_string = '1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa'

			it "converts it to hexa string" do
				hexstr = s.b58check_to_hex test_string
				cs = s.code_strings[16]
				expect(hexstr.chars.all?{|c| cs.include? c}).to be true
			end

			it "returns correct result" do
				hexstr = s.b58check_to_hex test_string
				expect(hexstr).to eql 'c8e90996c7c6080ee06284600c684ed904d14c5c'
			end

			it "returns correct multisig result" do
				hexstr = s.b58check_to_hex '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'
				expect(hexstr).to eql 'b472a266d0bd89c13706a4132ccfb16f7c3b9fcb'
			end
		end
	end

	context "#hash_to_int" do

		context "given a charlen 40 string" do

			it "gets decoded as hexa string" do
				string = s.hash_to_int '0001' * 10
				expect(string.integer?).to be true
			end

			it "gets properly decoded" do
				string = s.hash_to_int('0' * 38 + '1A')
				expect(string).to eql 26
			end
		end

		context "given a charlen 64 string" do

			it "gets decoded as hexa string" do
				string = s.hash_to_int '00000001' * 8
				expect(string.integer?).to be true
			end

			it "gets properly decoded" do
				string = s.hash_to_int('0' * 62 + '1A')
				expect(string).to eql 26
			end
		end

		context "given a 32-byte string" do

			it "gets converted as binary string" do
				string = s.hash_to_int(0.chr * 32)
				expect(string).to eql 0
			end
		end
	end

	context "#change_endianness" do

		context "given a string" do

			it "returns same length string" do
				string = s.change_endianness '4dd7f5c7'
				expect(string.length).to eql '4dd7f5c7'.length
			end

			it "changes it endianness" do
				string = s.change_endianness '004dd7f5c7'
				expect(string).to eql 'c7f5d74d00'
			end
		end
	end
end