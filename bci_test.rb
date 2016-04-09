require_relative 'bci'
require 'test/unit'

class TestBCI < Test::Unit::TestCase

	def setup
		@bci = BCI.new
	end

	def test_make_request
		body = @bci.make_request('https://blockchain.info/q/getdifficulty')
		assert_not_equal(body, '')
	end

	def test_parse_addr_args
		net, addrs = @bci.parse_addr_args("1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe")
		assert_equal('btc', net)
		assert_equal(["1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe"], addrs)

		net, addrs = @bci.parse_addr_args("1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe", "1GnDF6xkoFVvsTsR4yVBKx7HGgcfXcgSop", "1FzXPK6bS9ZB1RuLKzvH26ii7EencA772R")
		assert_equal('btc', net)
		assert_equal(3, addrs.size)

		net, addrs = @bci.parse_addr_args(["1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe", "1GnDF6xkoFVvsTsR4yVBKx7HGgcfXcgSop", "1FzXPK6bS9ZB1RuLKzvH26ii7EencA772R"])
		assert_equal('btc', net)
		assert_equal(1, addrs.size)

		net, addrs = @bci.parse_addr_args("1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe", "1GnDF6xkoFVvsTsR4yVBKx7HGgcfXcgSop", "1FzXPK6bS9ZB1RuLKzvH26ii7EencA772R", 'testnet')
		assert_equal('testnet', net)
		assert_equal(3, addrs.size)

		net, addrs = @bci.parse_addr_args(["1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe", "1GnDF6xkoFVvsTsR4yVBKx7HGgcfXcgSop", "1FzXPK6bS9ZB1RuLKzvH26ii7EencA772R"], 'testnet')
		assert_equal('testnet', net)
		assert_equal(1, addrs.size)
	end

	def test_unspent
		unspent = @bci.unspent('15xVzSD4Y6EvqrkDuHr8zTz2LKH9jHLxPL', 'bci')
		assert_not_equal([], unspent)

		unspent = @bci.unspent('1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe', 'bci')
		assert_equal([], unspent)

		unspent = @bci.unspent(["1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe", "1G9n2BmWB7X4iS4BcBUciAik9PJu742UiV", "1K6HgVehxsgvLaffzn4hHsXM5nmYLRfd6M"], "testnet", "blockr")
		assert_equal([], unspent)

		unspent = @bci.blockr_unspent(['15xVzSD4Y6EvqrkDuHr8zTz2LKH9jHLxPL', '1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe'], "btc", "blockr")
		assert_not_equal([], unspent)
	end

	def test_history
		data = @bci.history('15xVzSD4Y6EvqrkDuHr8zTz2LKH9jHLxPL')
		assert_not_equal('', data)
	end

	def test_last_block_height
		height = @bci.last_block_height
		assert_equal(true, height > 406509)

		height = @bci.last_block_height('testnet')
		assert_equal(true, height > 764061)
	end

	def test_fetchtx
		txhash = '45ab980280b0da391f46eae7648bb534525b91854879e78326d0da7ee768bbab'
		tx1 = @bci.fetchtx(txhash, 'bci')
		assert_equal(true, tx1.length > 218)

		tx2 = @bci.fetchtx(txhash, 'blockr')
		assert_equal(tx2, tx1)
	end

	def test_get_block_at_height
		block = @bci.get_block_at_height 406513
		assert_not_equal('', block)
	end

	def test_get_block_header_data
		header = @bci.get_block_header_data 406513
		assert_equal("0000000000000000028a5ff4b60341022cc061c44b25c8c729030c36c2b2a434", header[:hash])
		assert_equal(4, header[:version])
		assert_equal(1460231260, header[:timestamp])
		assert_equal(403085044, header[:bits])
		assert_equal(473159200, header[:nonce])
	end

	def test_get_txs_in_block
		txs = @bci.get_txs_in_block 406513
		assert_not_equal(0, txs.size)
	end
end