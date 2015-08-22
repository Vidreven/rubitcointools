require 'net/http'
require 'json'
 

#uri=URI('https://blockchain.info/unspent?address=16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM')
#uri = URI('https://blockchain.info/q/getdifficulty')
#"https://blockchain.info/unspent?address=1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe"

def make_request(*args)

	uri = URI(*args)

	res = Net::HTTP.get_response(uri)

	return res.body

end

def parse_addr_args(*args)
	# Valid input formats: blockr_unspent([addr1, addr2, addr3])
	# 			blockr_unspent(addr1, addr2, addr3)
	#                      blockr_unspent([addr1, addr2, addr3], network)
	#                      blockr_unspent(addr1, addr2, addr3, network)
	# Where network is 'btc' or 'testnet'

	network = 'btc'
	addr_args = args

	if (args.size > 1) && (['btc', 'testnet'].include? args[-1])
		network = args[-1]
		addr_args = args[0..-2]
	end

	return network, addr_args
end

# Gets the unspent outputs of one or more addresses
def bci_unspent(*args)

	network, addrs = parse_addr_args(*args)
	unspent = []

	addrs.each do |a|
		data = make_request('https://blockchain.info/unspent?address='+a)
		continue if data == 'No free outputs to spend'
		hash = JSON.parse data
		hash["unspent_outputs"].each do |output|
			h = output['tx_hash'].reverse #pack('H*').reverse.unpack('H*')
			unspent << {output: h.to_s + ":" + output["tx_output_n"].to_s, value: output["value"]}
		end
	end

	return unspent
end

def blockr_unspent(*args)
	# Valid input formats: blockr_unspent([addr1, addr2, addr3])
	# 					   blockr_unspent(addr1, addr2, addr3)
	#                      blockr_unspent([addr1, addr2, addr3], network)
	#                      blockr_unspent(addr1, addr2, addr3, network)
	# Where network is 'btc' or 'testnet'

	network, addr_args = parse_addr_args(*args)

	switch = network == "testnet" ? "t" : ""
	blockr_url = "https://#{switch}btc.blockr.io/api/v1/address/unspent/"

	result = make_request(blockr_url + addr_args.join(','))
	data = (JSON.parse result)['data']
	unspent = []

	if data.include? "unspent"
		data = [data]
	end

	data.each do |dat|
		dat['unspent'].each do |u|
			unspent << {output: u['tx'].to_s + ":" + u['n'].to_s, value: u['amount'].sub!(".", "").to_i}
		end
	end

	return unspent
end

def unspent(*args, site)
	if (site == "bci")
		return bci_unspent(*args)
	elsif (site == "blockr")
		return blockr_unspent(*args)
	end	
end

# Gets the transaction output history of a given set of addresses,
# including whether or not they have been spent
# Valid input formats: history([addr1, addr2,addr3])
# 					   history(addr1, addr2, addr3)
def history(*args)

	transactions = []
	addrs = *args
	addrs.each do |addr|
		offset = 0

		while 1
			result = make_request("https://blockchain.info/address/#{addr}?format=json&offset=#{offset}")
			data = JSON.parse result

			transactions.concat(data["txs"])
			if data["txs"].size < 50
				break
			end

			offset += 50
			puts "Fetching more transactions ... #{offset} \n"
		end
	end

	outs = {}
	transactions.each do |tx|
		tx["out"].each do |out|
			if addrs.include?(out["addr"])
				key = tx["tx_index"].to_s + ":" + out["n"].to_s
				outs[key] = {
					address: out["addr"],
					value: out["value"],
					output: tx["hash"].to_s + ":" + out["n"].to_s,
					block_height: tx["block_height"] || "None"
				}
			end
		end
	end

	i = 0
	transactions.each do |tx|
		tx["inputs"].each do |inp|
			if addrs.include?(inp["prev_out"]["addr"])
				key = inp["prev_out"]["tx_index"].to_s + ":" + inp["prev_out"]["n"].to_s
				if outs[key]
					outs[key]["spend"] = tx["hash"] + ":" + i.to_s
				end
			end
			i += 1
		end
	end

	return outs
end

# Pushes a transaction to the network using https://blockchain.info/pushtx
def bci_pushtx(tx)
	if not tx =~ '^[0-9a-fA-F]*$'
		tx = tx.pack("H*")
	end
	return make_request('https://blockchain.info/pushtx', 'tx='+tx)
end

def blockr_pushtx(tx, network="btc")
	switch = network == "testnet" ? "t" : ""
	blockr_url = "https://#{switch}btc.blockr.io/api/v1/address/unspent/"

	if not tx =~ '^[0-9a-fA-F]*$'
		tx = tx.pack("H*")
	end

	return make_request(blockr_url, '{"hex:#{tx}"}')
end

def pushtx(*args, site)
	if (site == "bci")
		return bci_pushtx(*args)
	elsif (site == "blockr")
		return blockr_pushtx(*args)
	end	
end

def last_block_height(network="btc")
	if network == "testnet"
		data = make_request('https://tbtc.blockr.io/api/v1/block/info/last')
		jsonobj = JSON.parse data
		return jsonobj["data"]["nb"]
	end

	data = make_request('https://blockchain.info/latestblock')
	jsonobj = JSON.parse data
	return jsonobj["height"]
end


# Gets a specific transaction
def bci_fetchtx(txhash)
	if not tx =~ '^[0-9a-fA-F]*$'
		tx = tx.pack("H*")
	end

	data = make_request('https://blockchain.info/rawtx/'+txhash+'?format=hex')

	return data
end

def blockr_fetchtx(txhash, network='btc')
	switch = network == "testnet" ? "t" : ""
	blockr_url = "https://#{switch}btc.blockr.io/api/v1/address/unspent/"

	tx = tx.pack("H*") unless tx =~ '^[0-9a-fA-F]*$'

	jsondata = JSON.parse(make_request(blockr_url+txhash))
	return jsondata['data']['tx']['hex']
end

def fetchtx(*args, site)
	if (site == "bci")
		return bci_fetchtx(*args)
	elsif (site == "blockr")
		return blockr_fetchtx(*args)
	end	
end

def firstbits(address)
	if address.length > 25
		return make_request('https://blockchain.info/q/getfirstbits/'+address)
	else
		return make_request('https://blockchain.info/q/resolvefirstbits/'+address)
	end
end

def get_block_at_height(height)
	result = JSON.parse make_request("https://blockchain.info/block-height/#{height}?format=json")
	result["blocks"].each do |block|
		if block["main_chain"] == true
			return block
		end
	end

	raise "Block at this height not found"
end

def get_block_header_data(height)
	block = get_block_at_height(height)

	return {
		version: block['ver'],
		hash: block['hash'],
		prevblock: block['prev_block'],
		timestamp: block['time'],
		merkle_root: block['mrkl_root'],
		bits: block['bits'],
		nonce: block['nonce']
	}
end

def blockr_get_block_header_data(height, network='btc')
	switch = network == "testnet" ? "t" : ""
	blockr_url = "https://#{switch}btc.blockr.io/api/v1/address/unspent/"

	result = JSON.parse make_request(blockr_url)
	block = result['data']

	return {
		version: block['ver'],
		hash: block['hash'],
		prevblock: block['prev_block'],
		timestamp: block['time'],
		merkle_root: block['mrkl_root'],
		bits: block['bits'].to_i(16),
		nonce: block['nonce']
	}
end

def get_txs_in_block(height)
	block = get_block_at_height(height)

	hash = []

	block['tx'].each {|t| hash << t['hash']}

	return hash
end

#puts res.body if res.is_a?(Net::HTTPSuccess)

#puts make_request('https://blockchain.info/q/getdifficulty')

#net, adr = parse_addr_args("1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe")

#podaci = bci_unspent("1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe")

#podaci = blockr_unspent(["1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe", "1G9n2BmWB7X4iS4BcBUciAik9PJu742UiV", "1K6HgVehxsgvLaffzn4hHsXM5nmYLRfd6M"], "testnet")

#podaci = blockr_unspent("1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe")

#podaci = unspent("1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe", "blockr")

#podaci = history("1NnCCeLDdGPjxuqnYS2uWm5SLCVv6zyuRe")

#podaci = get_block_header_data(358999)

#podaci = get_txs_in_block(358999)