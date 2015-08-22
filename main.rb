require_relative 'specials'
require_relative 'hashes'
require 'openssl'
require 'securerandom'
require 'base64'

class Main
	
	# Elliptic curve parameters (secp256k1)
	P = 2**256 - 2**32 - 977 #- 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
	N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
	A = 0
	B = 7
	Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
	Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
	G = [Gx, Gy]

	def initialize
		@sp = Specials.new
		@h = Hashes.new
	end
	
	def change_curve(p, n, a, b, gx, gy)
		$P, $N, $A, $B, $Gx, $Gy = p, n, a, b, gx, gy
		$G = [gx, gy]
	end

	# Modular inverse
	# Extended Euclidean Algorithm
	def inv(a, n)
		return 0 if a == 0

		lm, hm = 1, 0
		low, high = a % n, n

		while low > 1
			r = high/low
			nm, nw = hm - lm * r, high - low * r
			lm, low, hm, high = nm, nw, lm, low
		end

		return lm % n
	end

	# private
	# Protection against small-subgroup attacks. Cofactor of secp256k1 is 1 so point x 1 = 0 => point = [0, 0]
	def isinf(p)
		return p[0] == 0 && p[1] == 0
	end

	# private
	def to_jacobian(p)
		return [p[0], p[1], 1]
	end

	# private
	def jacobian_double(p)
		return [0, 0, 0] unless p[1]
		ysq = (p[1]**2) % P
		s = (4 * p[0] * ysq) % P
		m = (3 * p[0]**2 + A * p[2]**4) % P
		nx = (m**2 - 2 * s) % P
		ny = (m * (s - nx) - 8 * ysq**2) % P
		nz = (2 * p[1] * p[2]) % P

		return [nx, ny, nz]
	end

	#private
	def jacobian_add(p, q)
		return q unless p[1]
		return p unless q[1]

		u1 = (p[0] * q[2]**2) % P
		u2 = (q[0] * p[2]**2) % P
		s1 = (p[1] * q[2]**3) % P
		s2 = (q[1] * p[2]**3) % P

		if u1 == u2
			return [0, 0, 1] unless s1 == s2
			return jacobian_double(p)
		end

		h = u2 - u1
		r = s2 - s1
		h2 = (h * h) % P
		h3 = (h * h2) % P
		u1h2 = (u1 * h2) % P

		nx = (r ** 2 - h3 - 2 * u1h2) % P
		ny = (r * (u1h2 - nx) - s1 * h3) % P
		nz = h * p[2] * q[2]

		return [nx, ny, nz]
	end

	# private
	def from_jacobian(p)
		z = inv(p[2], P)
		return [(p[0] * z**2) % P, (p[1] * z**3) % P]
	end

	# private
	def jacobian_multiply(a, n)
		return [0, 0, 1] if (a[1] == 0) || (n == 0)

		return a if n == 1

		return jacobian_multiply(a, n % N) if (n < 0) || (n >= N)

		return jacobian_double(jacobian_multiply(a, n/2)) if n % 2 == 0

		return jacobian_add(jacobian_double(jacobian_multiply(a, n/2)), a) if n % 2 == 1
	end

	def fast_multiply(a, n)
		 return from_jacobian(jacobian_multiply(to_jacobian(a), n))
	end

	def fast_add(a, b)
		return from_jacobian(jacobian_add(to_jacobian(a), to_jacobian(b)))
	end

	# Functions for handling pubkey and privkey formats
	# Privkey = 256 bit = 32 byte
	# Pubkey = 512 bit = 64 byte
	# Key prefix = 0x04 (2 bytes)

	def get_pubkey_format(pub)
		if (pub.is_a? Array)
			return 'decimal'
		elsif (pub.length == 65) && (pub[0] == '4')
			return 'bin'
		elsif (pub.length == 130) && (pub[0..1] == '04')
			return 'hex'
		elsif (pub.length == 33) && (['2', '3'].include?(pub[0]))
			return 'bin_compressed'
		elsif (pub.length == 66) && (['02', '03'].include?pub[0..1])
			return 'hex_compressed'
		elsif (pub.length == 64)
			return 'bin_electrum'
		elsif (pub.length == 128)
			return 'hex_electrum'
		else
			raise "Pubkey not in recognized format"
		end	
	end

	# Encode pubkey from decimal to format
	# 0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179
	# 8483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
	def encode_pubkey(pub, format)
		pub = decode_pubkey(pub) unless pub.is_a? Array

		return pub if format =='decimal'

		# 0x04 + 32 bytes + 32 bytes = 65 bytes
		return [4.chr] + @sp.encode(pub[0], 256, 32).map{|c| c.chr} + @sp.encode(pub[1], 256, 32).map{|c| c.chr} if format == 'bin'

		# 0x02/0x03 + 32 bytes = 33 bytes
		return [(2 + pub[1] % 2).chr] + @sp.encode(pub[0], 256, 32) if format == 'bin_compressed'

		# 0x04 + 128 hex chars
		return '04' + @sp.encode(pub[0], 16, 64) + @sp.encode(pub[1], 16, 64) if format == 'hex'

		# 0x02/0x03 + 64 hex chars
		return '0' + (2 + (pub[1] % 2)).to_s + @sp.encode(pub[0], 16, 64) if format == 'hex_compressed'

		return @sp.encode(pub[0], 256, 32) + @sp.encode(pub[1], 256, 32) if format == 'bin_electrum'

		return @sp.encode(pub[0], 16, 64) + @sp.encode(pub[1], 16, 64) if format == 'hex_electrum'

		raise "Invalid format!"
	end

	# Decode pubkey from format to decimal
	def decode_pubkey(pub, format = 'None')
		format = get_pubkey_format(pub) if format == 'None'
		
		if format == 'decimal'
			return pub
		elsif format == 'bin'
			return [@sp.decode(pub[1..32], 256), @sp.decode(pub[33..65], 256)]
		elsif format == 'bin_compressed'
			x = @sp.decode(pub[1..32], 256)
			beta = (x*x*x + A*x + B)#.to_i
			beta = square_and_multiply(beta, P)
			y = ((beta + pub[0].to_i) % 2) ? (P - beta) : beta
			return [x, y]
		elsif format == 'hex'
			return [@sp.decode(pub[2..65], 16), @sp.decode(pub[66..130], 16)]
		elsif format == 'hex_compressed'
			return decode_pubkey(@sp.changebase(pub, 16, 256).map{|c| c.chr}, 'bin_compressed')
		elsif format == 'bin_electrum'
			return [@sp.decode(pub[0..31], 256), @sp.decode(pub[32..64], 256)]
		elsif format == 'hex_electrum'
			return [@sp.decode(pub[0..63], 16), @sp.decode(pub[64..128], 16)]
		else
			raise "Invalid format!"
		end	
	end

	def get_privkey_format(priv)
		if priv.is_a? Integer
			return 'decimal'
		elsif priv.length == 32
			return 'bin'
		elsif priv.length == 33
			return 'bin_compressed'
		elsif priv.length == 64
			return 'hex'
		elsif priv.length == 66
			return 'hex_compressed'
		else
			bin_p = @sp.b58check_to_bin(priv)
			if bin_p.length == 32
				return 'wif'
			elsif bin_p.length == 33
				return 'wif_compressed'
			else
				raise "WIF does not represent private key"
			end
		end
	end

	# Encode privkey from decimal to format
	# E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262
	# http://sourceforge.net/p/bitcoin/mailman/bitcoin-development/thread/CAPg+sBhDFCjAn1tRRQhaudtqwsh4vcVbxzm+AA2OuFxN71fwUA@mail.gmail.com/
	def encode_privkey(priv, format, vbyte = 0)
		return encode_privkey(decode_privkey(priv), format, vbyte) unless priv.is_a? Integer

		if format == 'decimal'
			return priv
		elsif format == 'bin'
			return @sp.encode(priv, 256, 32)
		elsif format == 'bin_compressed'
			return @sp.encode(priv, 256, 32)[0] + 1.chr
		elsif format == 'hex'
			return @sp.encode(priv, 16, 64)
		elsif format == 'hex_compressed'
			return @sp.encode(priv, 16, 64) + '01'
		elsif format == 'wif'
			return @sp.bin_to_b58check(@sp.encode(priv, 256, 32).map{|c| c.chr}.join, 128 + vbyte.to_i)
		elsif format == 'wif_compressed'
			return @sp.bin_to_b58check((@sp.encode(priv, 256, 32) + [1]).map{|c| c.chr}.join, 128 + vbyte.to_i)
		else
			raise "Invalid format"
		end
	end

	# Decode pubkey from format to decimal
	def decode_privkey(priv, format='None')
		format = get_privkey_format(priv) if format == 'None'

		return priv if format == 'decimal'
		return @sp.decode(priv, 256) if format == 'bin'
		return @sp.decode(priv[0..31], 256) if format == 'bin_compressed'
		return @sp.decode(priv, 16) if format == 'hex'
		return @sp.decode(priv[0..64], 16) if format == 'hex_compressed'
		return @sp.decode(@sp.b58check_to_bin(priv).map{|c| c.chr}.join, 256) if format == 'wif'
		return @sp.decode(@sp.b58check_to_bin(priv)[0..32].map{|c| c.chr}.join, 256) if format == 'wif_compressed'

		raise "WIF does not represent privkey"
	end

	def add_pubkeys(p1, p2)
		f1, f2 = get_pubkey_format(p1), get_pubkey_format(p2)

		return encode_pubkey(fast_add(decode_pubkey(p1, f1), decode_pubkey(p2, f2)), f1)
	end

	def add_privkeys(p1, p2)
		f1, f2 = get_privkey_format(p1), get_privkey_format(p2)

		return encode_privkey((decode_privkey(p1, f1) + decode_privkey(p2, f2)) % N, f1)
	end

	def multiply(pubkey, privkey)
		f1, f2 = get_pubkey_format(pubkey), get_privkey_format(privkey)
		pubkey, privkey = decode_pubkey(pubkey, f1), decode_privkey(privkey, f2)

		# http://safecurves.cr.yp.to/twist.html
		raise "Point not on curve" if isinf(pubkey) || ((pubkey[0]**3+B-pubkey[1]*pubkey[1]) % P != 0)
		
		return encode_pubkey(fast_multiply(pubkey, privkey), f1)
	end

	def divide(pubkey, privkey)
		factor = inv(decode_privkey(privkey), N)
		return multiply(pubkey, factor)
	end

	def compress(pubkey)
		f = get_pubkey_format(pubkey)

		if f == 'compressed'
			return pubkey
		elsif f == 'bin'
			encode_pubkey(decode_pubkey(pubkey, f), 'bin_compressed')
		elsif (f == 'hex') || (f == 'decimal')
			return encode_pubkey(decode_pubkey(pubkey, f), 'hex_compressed')
		end
	end

	def decompress(pubkey)
		f = get_pubkey_format(pubkey)

		return pubkey unless f.match('compressed')

		if f == 'bin_compressed'
			return encode_pubkey(decode_pubkey(pubkey, f), 'bin')
		elsif (f == 'hex_compressed') or (f == 'decimal')
			return encode_pubkey(decode_pubkey(pubkey, f), 'hex')
		end
	end

	def privkey_to_pubkey(privkey)
		f = get_privkey_format(privkey)

		privkey = decode_privkey(privkey, f)

		raise "Invalid privkey" if privkey > N

		if ['bin', 'bin_compressed', 'hex', 'hex_compressed', 'decimal'].include? f
			return encode_pubkey(fast_multiply(G, privkey), f)
		else
		 	return encode_pubkey(fast_multiply(G, privkey), f.gsub('wif', 'hex'))
		end
	end	

	alias :privtopub :privkey_to_pubkey

	def privkey_to_address(priv, magicbyte = 0)
		return pubkey_to_address(privkey_to_pubkey(priv), magicbyte)
	end

	alias :privtoaddr :privkey_to_address

	def pubkey_to_address(pubkey, magicbyte=0)
		pubkey = encode_pubkey(pubkey, 'bin')

		return @sp.bin_to_b58check(@h.bin_hash160(pubkey.join), magicbyte)
	end

	alias :pubtoaddr :pubkey_to_address

	def neg_pubkey(pubkey)
		f = get_pubkey_format(pubkey)
		pubkey = decode_pubkey(pubkey, f)
		return encode_pubkey([pubkey[0], (P - pubkey[1]) % P], f)
	end

	def neg_privkey(privkey)
		f = get_privkey_format(privkey)
		privkey = decode_privkey(privkey, f)
		return encode_privkey((N - privkey) % N, f)
	end

	def subtract_pubkeys(p1, p2)
		p2 = neg_pubkey(p2)
		return add_pubkeys(p1, p2)
	end

	def subtract_privkeys(p1, p2)
		p2 = neg_privkey(p2)
		return add_privkeys(p1, p2)
	end

	def random_key
		entropy = @sp.random_string(32) + SecureRandom.random_bytes(2**20).to_s + Time.now.to_i.to_s

		return @h.sha256(entropy)
	end

	def random_electrum_seed
		return random_key[0..31]
	end

	# ECDSA

	def encode_sig(v, r, s)
		vb, rb, sb = v.to_s(2), @sp.encode(r, 256), @sp.encode(s, 256)
		result = Base64.encode64(vb + '0' * (32 - rb.length) + rb[0].chr + '0' * (32 - sb.length) + sb[0].chr)

		return result.to_s
	end

	def decode_sig(sig)
		bytez = Base64.decode64(sig)
		return bytez[0], @sp.decode(bytez[1..32], 256), @sp.decode(bytez[33..-1], 256)
	end

	def deterministic_generate_k(msghash, priv)
		v = 0.chr * 32
		k = 0.chr * 32

		priv = encode_privkey(priv, 'bin')
		msghash = @sp.encode(@sp.hash_to_int(msghash), 256, 32)

		k = HMAC.digest("SHA256", k, v + 0.chr + priv + msghash)
		v = HMAC.digest("SHA256", k, v)

		k = HMAC.digest("SHA256", v + 1.chr + priv + msghash)
		v = HMAC.digest("SHA256", k, v)

		return @sp.decode(HMAC.digest("SHA256", k, v), 256)
	end

	def ecdsa_raw_sign(msghash, priv)
		z = @sp.hash_to_int(msghash)
		k = deterministic_generate_k(msghash, priv)
		r, y = fast_multiply(G, k)
		s = inv(k, N) * (z + r * decode_privkey(priv)) % N

		return 27 + (y % 2), r, s
	end

	def ecdsa_raw_verify(msghash, vrs, pub)
		v, r, s = vrs

		w = inv(s, N)
		z = @sp.hash_to_int(msghash)

		u1, u2 = z * w % N, r * w % N
		x, y = fast_add(fast_multiply(G, u1), fast_multiply(decode_pubkey(pub), u2))

		return r == x
	end

	def ecdsa_raw_recover(msghash, vrs)
		v, r, s = vrs

		x = r
		#beta = ((x*x*x + A*x + B) ** (P+1)/4) % P
		beta = (x*x*x + A*x + B)#.to_i
		beta = square_and_multiply(beta, P)
		y = v % 2 ^ beta % 2 ? beta : (P - beta)
		z = @sp.hash_to_int(msghash)
		gz = jacobian_multiply([Gx, Gy, 1], (N - z) % N)
		xy = jacobian_multiply([x, y, 1], s)
		qr = jacobian_add(gz, xy)
		q = jacobian_multiply(qr, inv(r, N))
		q = from_jacobian(q)

		return q if ecdsa_raw_verify(msghash, vrs, q)
		return false
	end

	private

	def square_and_multiply(base, exponent)
		exp = [254, 30, 7, 6, 5, 4, 2]
		temp_res = []

		exp.each do |e|
			t = e.times{base = (base * base) % exponent}
			temp_res << t
		end

		return temp_res.reduce(:/)
	end
end