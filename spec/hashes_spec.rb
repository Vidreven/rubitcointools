require 'hashes'
require 'digest'

describe Hashes do
	
	h = Hashes.new

	describe ".bin_hash160" do

		context "given a string input" do

			result = h.bin_hash160 '1'

			it "returns non-empty result" do
				expect(result).not_to eql ''
			end

			it "returns 20 byte result" do
				expect(result.size).to eql 20
			end
		end
	end

	describe ".hash160" do

		context "given a string input" do

			result = h.hash160 '1'

			it "returns non-empty result" do
				expect(result).not_to eql ''
			end

			it "returns 40 character result" do
				expect(result.size).to eql 40
			end
		end
	end

	describe ".bin_sha256" do

		context "given a string input" do

			result = h.bin_sha256 '1'

			it "returns non-empty result" do
				expect(result).not_to eql ''
			end

			it "returns 32 byte result" do
				expect(result.size).to eql 32
			end
		end
	end

	describe ".bin_dbl_sha256" do

		context "given a string input" do

			result = h.bin_dbl_sha256 '1'

			it "returns non-empty result" do
				expect(result).not_to eql ''
			end

			it "returns 32 byte result" do
				expect(result.size).to eql 32
			end

			it "should equal double bin_sha256" do
				expect(result).to eql h.bin_sha256(h.bin_sha256('1'))
			end
		end
	end

	describe ".sha256" do
		context "given a string input" do

			result = h.sha256 '1'

			it "returns non-empty result" do
				expect(result).not_to eql ''
			end

			it "returns 64 character result" do
				expect(result.size).to eql 64
			end
		end
	end

	describe ".bin_slowsha" do

		context "given a string input" do

			result = h.bin_slowsha '1'

			it "returns non-empty result" do
				expect(result).not_to eql ''
			end

			it "returns 32 byte result" do
				expect(result.size).to eql 32
			end

			it "does not equal bin_sha256" do
				expect(result).not_to eql h.bin_sha256 '1'
			end

			it "does not equal bin_dbl_sha256" do
				expect(result).not_to eql h.bin_dbl_sha256 '1'
			end
		end
	end

	describe ".slowsha" do

		context "given a string input" do

			result = h.slowsha '1'

			it "returns 64 character result" do
				expect(result.size).to eql 64
			end
		end
	end
end