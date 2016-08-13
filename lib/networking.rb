require 'net/http'
require 'json'
require_relative 'specials'
require_relative 'transaction'
include Enumerable
 
class Networking
	
	def initilize
		@t = Transaction.new
	end

	def make_request(*args)

		uri = URI(*args)

		res = Net::HTTP.get_response(uri)

		return res.body

	end

	def parse_addr_args(*args)
		# Valid input formats: blockr_unspent([addr1, addr2, addr3])
		# 			blockr_unspent(addr1, addr2, addr3)
		#           blockr_unspent([addr1, addr2, addr3], network)
		#           blockr_unspent(addr1, addr2, addr3, network)
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
			data = make_request('https://blockchain.info/unspent?active='+a)
			next if data == 'No free outputs to spend'
			hash = JSON.parse data
			hash["unspent_outputs"].each do |output|
				h = Specials.new.change_endianness(output['tx_hash'])
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
		return bci_unspent(*args) if site == "bci"
		return blockr_unspent(*args)
	end

	# Gets the transaction output history of a given set of addresses,
	# including whether or not they have been spent
	# Valid input formats: history([addr1, addr2,addr3])
	# 					   history(addr1, addr2, addr3)
	def history(*addrs)

		transactions = []
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

		transactions.each_with_index do |tx, index|
			tx["inputs"].each do |inp|
				if addrs.include?(inp["prev_out"]["addr"])
					key = inp["prev_out"]["tx_index"].to_s + ":" + inp["prev_out"]["n"].to_s
					if outs[key]
						outs[key]["spend"] = tx["hash"] + ":" + index.to_s
					end
				end
			end
		end

		return outs
	end

	# Pushes a transaction to the network using https://blockchain.info/pushtx
	def bci_pushtx(tx)
		tx = @t.serialize tx unless tx.respond_to? :each_char
		return make_request('https://blockchain.info/pushtx', 'tx=#{tx}')
	end

	def blockr_pushtx(tx, network="btc")
		switch = network == "testnet" ? "t" : ""
		blockr_url = "https://#{switch}btc.blockr.io/api/v1/address/unspent/"

		tx = @t.serialize tx unless tx.respond_to? :each_char

		return make_request(blockr_url, '{"hex:#{tx}"}')
	end

	def pushtx(*args, site)
		return bci_pushtx(*args) if site == "bci"
		return blockr_pushtx(*args)
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

		return make_request('https://blockchain.info/rawtx/'+txhash+'?format=hex')
	end

	def blockr_fetchtx(txhash, network='btc')
		switch = network == "testnet" ? "t" : ""
		blockr_url = "https://#{switch}btc.blockr.io/api/v1/tx/raw/"

		jsondata = JSON.parse(make_request(blockr_url+txhash))
		return jsondata['data']['tx']['hex']
	end

	def fetchtx(*args, site)
		return bci_fetchtx(*args) if site == "bci"
		return blockr_fetchtx(*args)
	end

	def get_block_at_height(height)
		result = make_request("https://blockchain.info/block-height/#{height}?format=json")

		raise "Block at this height not found" if result =~ /Unknown Error/

		result = JSON.parse result

		result["blocks"].each{|block| block if block["main_chain"] == true}
	end

	def get_block_header_data(height)
		block = get_block_at_height(height.to_s)
		return {
			version: block[0]['ver'],
			hash: block[0]['hash'],
			prevblock: block[0]['prev_block'],
			timestamp: block[0]['time'],
			merkle_root: block[0]['mrkl_root'],
			bits: block[0]['bits'],
			nonce: block[0]['nonce']
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

		block[0]['tx'].each {|t| hash << t['hash']}

		return hash
	end
end