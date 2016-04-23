require 'scripts'

describe Scripts do

	s = Scripts.new

	context "#mk_pubkey_script" do

		context "given public key" do

			addr = '1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa'
			script = s.mk_pubkey_script addr

			it "converts it to scriptPubKey" do
				expect(script.length).to eql 50
			end

			it "converts to proper format" do
				expect(script[0..5]).to eql '76a914'
				expect(script[-4..-1]).to eql '88ac'
			end
		end
	end

	context "#mk_scripthash_script" do

		context "given script hash" do

			it "converts it to scriptPubKey" do
				addr = '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'
				script = s.mk_scripthash_script addr
				expect(script[0..3]).to eql 'a914'
				expect(script[-2..-1]).to eql '87'
			end
		end
	end

	context "#encode_op_n" do

		context "given input out of range" do

			it "raises error" do
				expect{s.encode_op_n -1}.to raise_error ArgumentError
				expect{s.encode_op_n 17}.to raise_error ArgumentError
			end
		end

		context "given zero" do

			it "returns '0'" do
				n = s.encode_op_n 0
				expect(n).to eql '0'
			end
		end

		context "given input between 1 and 16" do

			it "converts it to op_n" do
				1.upto 16 do |i|
					expect((s.encode_op_n i).to_i 16).to eql 80 + i
				end
			end
		end
	end

	context "#mk_psh_redeem_script" do

		pk1 = "04a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd"
		pk2 = "046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187"
		pk3 = "0411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e83"

		context "given zero keys" do

			it "raises error" do
				expect{s.mk_psh_redeem_script(0, [])}. to raise_error ArgumentError
			end
		end

		context "given incorrect number of keys" do

			it "raises error" do
				expect{s.mk_psh_redeem_script(3, [])}. to raise_error ArgumentError
			end
		end

		context "given too many keys" do

			it "raises error" do
				expect{s.mk_psh_redeem_script(3, Array.new(17) { |i| i })}. to raise_error ArgumentError
			end
		end

		context "given a pubkey" do
			
			it "encodes to redeem script" do
				res = s.mk_psh_redeem_script(1, [pk1])
				expect(res[0..1]).to eql '51'
				expect(res[2..3]).to eql '41'
				expect(res[4..133]).to eql pk1
				expect(res[134..135]).to eql '51'
				expect(res[136..137]).to eql 'ae'
			end
		end

		context "given m-of-n pubkeys" do
			
			it "encodes to redeem script" do
				res = s.mk_psh_redeem_script(2, [pk1, pk2, pk3])
				expect(res[0..1]).to eql '52'
				expect(res[2..3]).to eql '41'
				expect(res[4..133]).to eql pk3
				expect(res[134..135]).to eql '41'
				expect(res[136..265]).to eql pk2
				expect(res[266..267]).to eql '41'
				expect(res[268..397]).to eql pk1
				expect(res[398..399]).to eql '53'
				expect(res[-2..-1]).to eql 'ae'
			end
		end
	end
end