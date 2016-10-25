require_relative 'specials'
require_relative 'ecc'
require_relative 'hashes'

class Keys

	def initialize
		@sp = Specials.new
		@e = ECC.new
		@h = Hashes.new
	end

	# Functions for handling pubkey and privkey formats
	# Privkey = 256 bit = 32 byte
	# Pubkey = 512 bit = 64 byte
	# Key prefix = 0x04 (2 bytes)

	def get_pubkey_format(pub)
		if pub.is_a? Array
			return :decimal
		elsif pub.length == 65 && pub[0] == 4.chr
			return :bin
		elsif pub.length == 130 && pub[0..1] == '04'
			return :hex
		elsif pub.length == 33 && [2.chr, 3.chr].include?(pub[0])
			return :bin_compressed
		elsif pub.length == 66 && (['02', '03'].include?pub[0..1])
			return :hex_compressed
		elsif pub.length == 64
			return :bin_electrum
		elsif pub.length == 128
			return :hex_electrum
		else
			raise ArgumentError, "Pubkey not in recognized format"
		end	
	end

	# Encode pubkey from decimal to format
	# 0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179
	# 8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
	def encode_pubkey(pub, format)
		pub = decode_pubkey(pub) unless pub.is_a? Array

		return pub if format ==:decimal

		# 0x04 + 32 bytes + 32 bytes = 65 bytes
		return 4.chr + @sp.encode(pub[0], 256, 32) + @sp.encode(pub[1], 256, 32) if format == :bin

		# 0x02/0x03 + 32 bytes = 33 bytes
		return (2 + pub[1] % 2).chr + @sp.encode(pub[0], 256, 32) if format == :bin_compressed

		# 0x04 + 128 hex chars
		return '04' + @sp.encode(pub[0], 16, 64) + @sp.encode(pub[1], 16, 64) if format == :hex

		# 0x02/0x03 + 64 hex chars
		return '0' + (2 + (pub[1] % 2)).to_s + @sp.encode(pub[0], 16, 64) if format == :hex_compressed

		# 32 bytes + 32 bytes = 64 bytes
		return encode_pubkey(pub, :bin)[1..-1] if format == :bin_electrum

		#128 hex chars
		return encode_pubkey(pub, :hex)[2..-1] if format == :hex_electrum

		# raise ArgumentError, "Invalid format!"
	end

	# Decode pubkey from format to decimal
	def decode_pubkey(pub, format = nil)
		format = get_pubkey_format(pub) if format.nil?

		if format == :decimal
			return pub
		elsif format == :bin
			return [@sp.decode(pub[1..32], 256), @sp.decode(pub[33..65], 256)]
		elsif format == :bin_compressed
			x = @sp.decode(pub[1..32], 256)
			y = @e.get_y x
			raise ArgumentError, "Invalid key" if y == -1
			y = pub[0] == 3.chr ? y : ECC::P - y
			return [x, y]
		elsif format == :hex
			return [@sp.decode(pub[2..65], 16), @sp.decode(pub[66..130], 16)]
		elsif format == :hex_compressed
			return decode_pubkey(@sp.changebase(pub, 16, 256), :bin_compressed)
		elsif format == :bin_electrum
			return [@sp.decode(pub[0..31], 256), @sp.decode(pub[32..64], 256)]
		elsif format == :hex_electrum
			return [@sp.decode(pub[0..63], 16), @sp.decode(pub[64..128], 16)]
		# else
		# 	raise ArgumentError, "Invalid format!"
		end	
	end

	def get_privkey_format(priv)
		if priv.is_a? Integer
			return :decimal
		elsif priv.length == 32
			return :bin
		elsif priv.length == 33
			return :bin_compressed
		elsif priv.length == 64
			return :hex
		elsif priv.length == 66
			return :hex_compressed
		else
			bin_p = @sp.b58check_to_bin(priv)
			if bin_p.length == 32
				return :wif
			elsif bin_p.length == 33
				return :wif_compressed
			else
				raise ArgumentError, "WIF does not represent private key"
			end
		end
	end

	# Decode privkey from format to decimal
	def decode_privkey(priv, format=nil)
		format = get_privkey_format priv if format.nil?

		return priv if format == :decimal
		return @sp.decode(priv, 256) if format == :bin
		return @sp.decode(priv[0..31], 256) if format == :bin_compressed
		return @sp.decode(priv, 16) if format == :hex
		return @sp.decode(priv[0..63], 16) if format == :hex_compressed
		return @sp.decode(@sp.b58check_to_bin(priv), 256) if format == :wif
		return @sp.decode(@sp.b58check_to_bin(priv)[0..31], 256) if format == :wif_compressed

		#raise "WIF does not represent privkey"
	end

	# Encode privkey from decimal to format
	# http://sourceforge.net/p/bitcoin/mailman/bitcoin-development/thread/CAPg+sBhDFCjAn1tRRQhaudtqwsh4vcVbxzm+AA2OuFxN71fwUA@mail.gmail.com/
	def encode_privkey(priv, format, vbyte = 0)
		return encode_privkey(decode_privkey(priv), format, vbyte) unless priv.is_a? Integer

		if format == :decimal
			return priv
		elsif format == :bin
			return @sp.encode(priv, 256, 32)
		elsif format == :bin_compressed
			return @sp.encode(priv, 256, 32) + 1.chr
		elsif format == :hex
			return @sp.encode(priv, 16, 64)
		elsif format == :hex_compressed
			return @sp.encode(priv, 16, 64) + '01'
		elsif format == :wif
			return @sp.bin_to_b58check(@sp.encode(priv, 256, 32), 128 + vbyte.to_i)
		elsif format == :wif_compressed
			return @sp.bin_to_b58check((@sp.encode(priv, 256, 32) + 1.chr), 128 + vbyte.to_i)
		else
			raise "Invalid format"
		end
	end

	def add_pubkeys(p1, p2)
		f1, f2 = get_pubkey_format(p1), get_pubkey_format(p2)

		return encode_pubkey(@e.fast_add(decode_pubkey(p1, f1), decode_pubkey(p2, f2)), f1)
	end

	def add_privkeys(p1, p2)
		f1, f2 = get_privkey_format(p1), get_privkey_format(p2)

		return encode_privkey((decode_privkey(p1, f1) + decode_privkey(p2, f2)) % ECC::N, f1)
	end

	# def multiply(pubkey, privkey)
	# 	f1, f2 = get_pubkey_format(pubkey), get_privkey_format(privkey)
	# 	pubkey, privkey = decode_pubkey(pubkey, f1), decode_privkey(privkey, f2)

	# 	# http://safecurves.cr.yp.to/twist.html
	# 	raise "Point not on curve" if @e.reject?(pubkey) || ((pubkey[0]**3+ECC::B-pubkey[1]*pubkey[1]) % ECC::P != 0)
		
	# 	return encode_pubkey(@e.fast_multiply(pubkey, privkey), f1)
	# end

	# def divide(pubkey, privkey)
	# 	factor = @e.inv(decode_privkey(privkey), ECC::N)
	# 	return multiply(pubkey, factor)
	# end

	def compress(pubkey)
		f = get_pubkey_format pubkey

		if f.to_s.match 'compressed'
			return pubkey
		elsif f == :bin
			encode_pubkey(decode_pubkey(pubkey, f), :bin_compressed)
		elsif f == :hex || f == :decimal
			return encode_pubkey(decode_pubkey(pubkey, f), :hex_compressed)
		else
			raise ArgumentError, "Uncompressable format"
		end
	end

	def decompress(pubkey)
		f = get_pubkey_format pubkey 

		return pubkey unless f.to_s.match 'compressed'

		if f == :bin_compressed
			return encode_pubkey(decode_pubkey(pubkey, f), :bin)
		elsif (f == :hex_compressed)# or (f == :decimal)
			return encode_pubkey(decode_pubkey(pubkey, f), :hex)
		end
	end

	def privkey_to_pubkey(privkey)
		f = get_privkey_format privkey

		privkey = decode_privkey(privkey, f)

		raise ArgumentError, "Invalid privkey" if privkey > ECC::N

		if [:bin, :bin_compressed, :hex, :hex_compressed, :decimal].include? f
			return encode_pubkey(@e.fast_multiply(ECC::G, privkey), f)
		else
		 	return encode_pubkey(@e.fast_multiply(ECC::G, privkey), f.to_s.gsub('wif', 'hex').to_sym)
		end
	end

	alias :privtopub :privkey_to_pubkey

	def pubkey_to_address(pubkey, magicbyte=0)
		pubkey = encode_pubkey(pubkey, :bin)

		@sp.bin_to_b58check(@h.bin_hash160(pubkey), magicbyte)
	end

	alias :pubtoaddr :pubkey_to_address

	def privkey_to_address(priv, magicbyte=0)
		pubkey_to_address(privkey_to_pubkey(priv), magicbyte)
	end

	alias :privtoaddr :privkey_to_address

	# Converts a script to P2SH
	def script_to_address(script, magicbyte=5)
		script = @sp.changebase(script, 16, 256)
		@sp.bin_to_b58check(@h.bin_hash160(script), magicbyte)
	end

	# def neg_pubkey(pubkey)
	# 	f = get_pubkey_format(pubkey)
	# 	pubkey = decode_pubkey(pubkey, f)
	# 	return encode_pubkey([pubkey[0], (ECC::P - pubkey[1]) % ECC::P], f)
	# end

	# def neg_privkey(privkey)
	# 	f = get_privkey_format(privkey)
	# 	privkey = decode_privkey(privkey, f)
	# 	return encode_privkey((ECC::N - privkey) % ECC::N, f)
	# end

	# def subtract_pubkeys(p1, p2)
	# 	p2 = neg_pubkey(p2)
	# 	return add_pubkeys(p1, p2)
	# end

	# def subtract_privkeys(p1, p2)
	# 	p2 = neg_privkey(p2)
	# 	return add_privkeys(p1, p2)
	# end

	def random_key
		begin
			entropy = @sp.random_string 32
			privkey = @h.bin_slowsha(entropy)
		end while !valid? privkey
		privkey
	end

	def valid?(privkey)
		privkey = decode_privkey privkey
		privkey > 0 && privkey < ECC::N
	end

	# def random_electrum_seed
	# 	return random_key[0..31]
	# end
end