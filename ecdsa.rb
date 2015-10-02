require_relative 'ecc'
require_relative 'specials'
require_relative 'keys'
require 'openssl'

class ECDSA

	def initialize
		@e = ECC.new
		@sp = Specials.new
		@k = Keys.new
	end

	# DER encoding BIP 66 ?
	# 0x30 + 1 byte length descriptor + 0x02 + 1 byte R length descriptor + R + 0x02 + 1 byte S length descriptor + S
	def encode_sig(v = '30', r, s)
		v, r, s = v.to_s, r.to_s, s.to_s
		raise "r cannot  be negative" if (r[0..1] == '00') && (r[2..3] < '80')
		raise "s cannot  be negative" if (s[0..1] == '00') && (s[2..3] < '80')
		total_length = (10 + r.length + s.length).to_s(16)
		r_length = (r.length).to_s(16)
		s_length = (s.length).to_s(16)
		result = '30' + total_length + "02" + r_length + r + "02" + s_length + s
		return result
	end

	def decode_sig(sig)
		#return sig[0..1], sig[8..71], sig[76..-1]
		v = sig[0..1]
		len = sig[2..3].to_i(16)
		r_len = sig[6..7].to_i(16)
		r = sig[8..(7+r_len)] # sig[8..84]
		s_len = sig[(10+r_len)..(11+r_len)].to_i (16)
		s = sig[(12+r_len)..len+1] # sig[89..-1]
		return v, r, s
	end

	# https://tools.ietf.org/html/rfc6979#section-3.2
	def deterministic_generate_k(msghash, priv)
		v = 1.chr * 32 #'1' * 64
		k = 0.chr * 32 #'0' * 64

		priv = @k.encode_privkey(priv, 'bin')
		#msghash = @sp.encode(@sp.hash_to_int(msghash), 256, 32)

		k = OpenSSL::HMAC.digest("SHA256", k, v + 0.chr + priv + msghash)
		v = OpenSSL::HMAC.digest("SHA256", k, v)

		k = OpenSSL::HMAC.digest("SHA256", k, v + 1.chr + priv + msghash)
		v = OpenSSL::HMAC.digest("SHA256", k, v)

		return @sp.decode(OpenSSL::HMAC.digest("SHA256", k, v), 256)
	end

	# https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
	def ecdsa_raw_sign(msghash, priv)
		z = @sp.hash_to_int(msghash)
		k = deterministic_generate_k(msghash, priv)
		r, y = @e.fast_multiply(ECC::G, k)
		s = @e.inv(k, ECC::N) * (z + r * @k.decode_privkey(priv)) % ECC::N

		return 30 + (y % 2), r, s
	end

	def ecdsa_raw_verify(msghash, vrs, pub)
		v, r, s = vrs
		w = @e.inv(s.to_i, ECC::N)
		z = @sp.hash_to_int(msghash)

		u1, u2 = z * w % ECC::N, r.to_i * w % ECC::N

		x, y = @e.fast_add(@e.fast_multiply(ECC::G, u1), @e.fast_multiply(@k.decode_pubkey(pub), u2))

		return r.to_i == x
	end

	def ecdsa_raw_recover(msghash, vrs)
		v, r, s = vrs

		x = r.to_i
		xcubedaxb = (x*x*x + ECC::A*x + ECC::B)
		beta = @e.pow(xcubedaxb, (ECC::P+1)/4, ECC::P)
		y = beta % 2 == 1 ? beta : (ECC::P - beta)

		# If xcubedaxb is not a quadratic residue, then r cannot be the x coord
    	# for a point on the curve, and so the sig is invalid
		return false if (xcubedaxb - y*y) % ECC::P != 0

		z = @sp.hash_to_int(msghash)
		gz = @e.fast_multiply(ECC::G, (ECC::N - z) % ECC::N)
		xy = @e.fast_multiply([x, y], s.to_i)
		qr = @e.fast_add(gz, xy)
		p, q = @e.fast_multiply(qr, @e.inv(r.to_i, ECC::N))

		return [p, q]
	end
end