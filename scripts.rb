require_relative 'specials'

class Scripts

	def initialize
		@sp = Specials.new
	end

	# OP_DUP OP_HASH160 hex_len_PKH PKH OP_EQUALVERIFY OP_CHECKSIG
	def mk_pubkey_script(addr)
		return '76a914' + @sp.b58check_to_hex(addr) + '88ac' #addr part needs to be 40 char in length
	end

	def mk_scripthash_script(addr)
		return 'a914' + @sp.b58check_to_hex(addr) + '87'
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