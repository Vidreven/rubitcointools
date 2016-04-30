require 'arbitrary'

describe Arbitrary do

	a = Arbitrary.new
	
	context ".random_string" do

		context "given zero length" do

			it "returns empty string" do
				string = a.random_string 0
				expect(string).to eql ''
			end
		end

		context "given non-zero length string" do

			it "returns a byte-string of given length" do
				string = a.random_string 10
				expect(string.bytesize).to eql 10
			end

			it "returns unique strings" do
				string1 = a.random_string 10
				string2 = a.random_string 10
				expect(string1).not_to eql string2
			end
		end
	end

	context ".seed" do

		it "returns random seed" do
			s1 = a.seed
			s2 = a.seed
			expect(s1).not_to eql s2
		end
	end

	context ".xorshift" do

		it "returns random number" do
			s1 = a.xorshift
			s2 = a.xorshift
			expect(s1).not_to eql s2
		end
	end

	context ".get_entropy" do

		it "returns bytes of entropy" do
			e1 = a.get_entropy
			e2 = a.get_entropy
			expect(e1).not_to eql e2
		end
	end
end