require 'networking'

describe Networking do
	
	n = Networking.new

	context ".make_request" do

		context "given a URL" do

			it "fetches the web page" do
				body = n.make_request 'https://blockchain.info/q/getdifficulty'
				expect(body).not_to eql ''
			end
		end
	end

	context ".parse_addr_args" do

		context "given a list of bitcion addresess" do

			it "parses network and addresses" do

				net, addrs = n.parse_addr_args("1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe")
				expect(net).to eql 'btc'
				expect(addrs).to eql ["1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe"]

				net, addrs = n.parse_addr_args("1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe", "1GnDF6xkoFVvsTsR4yVBKx7HGgcfXcgSop", "1FzXPK6bS9ZB1RuLKzvH26ii7EencA772R")
				expect(net).to eql 'btc'
				expect(addrs.size).to eql 3

				net, addrs = n.parse_addr_args(["1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe", "1GnDF6xkoFVvsTsR4yVBKx7HGgcfXcgSop", "1FzXPK6bS9ZB1RuLKzvH26ii7EencA772R"])
				expect(net).to eql 'btc'
				expect(addrs.size).to eql 1

				net, addrs = n.parse_addr_args("1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe", "1GnDF6xkoFVvsTsR4yVBKx7HGgcfXcgSop", "1FzXPK6bS9ZB1RuLKzvH26ii7EencA772R", 'testnet')
				expect(net).to eql 'testnet'
				expect(addrs.size).to eql 3

				net, addrs = n.parse_addr_args(["1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe", "1GnDF6xkoFVvsTsR4yVBKx7HGgcfXcgSop", "1FzXPK6bS9ZB1RuLKzvH26ii7EencA772R"], 'testnet')
				expect(net).to eql 'testnet'
				expect(addrs.size).to eql 1
			end
		end
	end

	context ".unspent" do
		
		context "given an address" do

			it "fetches unspent outputs from BCI" do
				unspent = n.unspent('15xVzSD4Y6EvqrkDuHr8zTz2LKH9jHLxPL', 'bci')
				expect(unspent).not_to eql []

				unspent = n.unspent('1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe', 'bci')
				expect(unspent).to eql []
			end

			it "fetches unspent outputs from blockr" do
				unspent = n.unspent(["1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe", "1G9n2BmWB7X4iS4BcBUciAik9PJu742UiV", "1K6HgVehxsgvLaffzn4hHsXM5nmYLRfd6M"], "testnet", "blockr")
				expect(unspent).to eql []

				unspent = n.blockr_unspent(['15xVzSD4Y6EvqrkDuHr8zTz2LKH9jHLxPL', '1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe'], "btc", "blockr")
				expect(unspent).not_to eql []
			end
		end
	end

	context ".history" do

		context "given an address" do

			it "fetches transaction history" do
				data = n.history('15xVzSD4Y6EvqrkDuHr8zTz2LKH9jHLxPL')
				expect(data).not_to eql ''
			end
		end
	end

	context ".pushtx" do
	end

	context ".last_block" do

		it "returns the last block" do
			height = n.last_block
			expect(height > 406509).to be true

			height = n.last_block('testnet')
			expect(height > 764061).to be true
		end
	end

	context ".fetchtx" do

		context "given transaction hash" do

			it "fetches the transaction" do

				txhash = '45ab980280b0da391f46eae7648bb534525b91854879e78326d0da7ee768bbab'
				tx1 = n.fetchtx(txhash, 'bci')
				expect(tx1.size > 218).to be true

				tx2 = n.fetchtx(txhash, 'blockr')
				expect(tx2).to eql tx1
			end
		end
	end

	context ".get_block_at_height" do

		context "given block height" do

			it "returns block" do
				block = n.get_block_at_height 408006
				expect(block).not_to eql ''
			end
		end
	end

	context ".get_block_header_data" do

		context "given block height" do

			it "returns block header" do
				header = n.get_block_header_data 406670
				expect(header[:hash]).to eql '0000000000000000012fe97b388d92e60185e8d360155c69228e0608762b593f'
				expect(header[:version]).to eql 4
				expect(header[:timestamp]).to eql 1460310838
				expect(header[:bits]).to eql 403085044
				expect(header[:nonce]).to eql 2469084554
			end
		end
	end

	context ".get_txs_in_block" do

		context "given block height" do

			it "returns transactions in the block" do
				txs = n.get_txs_in_block 408006
				expect(txs.size).not_to eql 0
			end
		end
	end
end