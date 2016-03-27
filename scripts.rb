require_relative 'specials'

class Scripts

	def initialize
		@sp = Specials.new
	end

	# OP_DUP OP_HASH160 hex_len_PKH PKH OP_EQUALVERIFY OP_CHECKSIG
	def mk_pubkey_script(pkh)
		return '76a914' + @sp.b58check_to_hex(pkh) + '88ac' #addr part needs to be 40 char in length
	end

	def mk_scripthash_script(hash)
		return 'a914' + @sp.b58check_to_hex(hash) + '87'
	end

	# OP_M <PUBKEY1>...<PUBKEYN> OP_N OP_CHECKMULTISIG
	# m - required number of keys
	# keys - string array of pubkeys
	def mk_psh_redeem_script(m, keys)
		raise "Need at least one key to redeem!" if m < 1
		raise "Not enough keys supplied" if keys.length < m
		raise "Too many keys! Maximum is 16." if keys.length > 16

		keys.map!{|key| key.to_s}
		keys.sort!

		script = encode_op_n(m)
		keys.each do |key|
			script += (key.length / 2).to_s(16)
			script += key
		end

		script += encode_op_n(keys.length)
		script += "ae"

		return script
	end

	# Encode small integers to hex OP_N
	def encode_op_n(n)
		raise "Number out of range!" if n < 0 || n > 16
		return "0" if n == 0
		
		op_n = 80 + n
		return op_n.to_s(16)
	end

	def address_to_script(addr)
		if addr[0] == '3' || addr[0] == '2'
			return mk_scripthash_script(addr)
		else
			return mk_pubkey_script(addr)
		end
	end

	def script_to_address(script, vbyte=0)
		if (script[0..5] == '76a914' && script[-4..-1] == '88ac' && script.length == 50)
			hextobin = @sp.changebase(script[6..-5], 16, 256)
			return @sp.bin_to_b58check(hextobin, vbyte)
		else
			if [111, 196].include? vbyte
				#Testnet
				scripthash_byte = 196
			else
				scripthash_byte = 5
			end

			hextobin = @sp.changebase(script[4..-3], 16, 256)
			# BIP0016 scripthash addresses
			return @sp.bin_to_b58check(hextobin, scripthash_byte)
		end
	end
end