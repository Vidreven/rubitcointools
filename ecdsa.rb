require_relative 'ecc'
require_relative 'specials'
require_relative 'keys'
require 'base64'
require 'openssl'

class ECDSA

	def initialize
		@e = ECC.new
		@sp = Specials.new
		@k = Keys.new
	end

	# https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

	# DER encoding BIP 66 ?
	# 0x30 + 1 byte length descriptor + 0x02 + 1 byte R length descriptor + R + 0x02 + 1 byte S length descriptor + S
	def encode_sig(v, r, s)
		vb, rb, sb = v.chr, @sp.encode(r, 256).map{|c| c.chr}.join, @sp.encode(s, 256).map{|c| c.chr}.join
		result = Base64.encode64(vb + 0.chr * (32 - rb.length) + rb + 0.chr * (32 - sb.length) + sb)

		return result.to_s
	end

	def decode_sig(sig)
		bytez = Base64.decode64(sig)
		return bytez[0], @sp.decode(bytez[1..32], 256), @sp.decode(bytez[33..-1], 256)
	end

	# https://tools.ietf.org/html/rfc6979#section-3.2
	def deterministic_generate_k(msghash, priv)
		v = '1' * 32
		k = '0' * 32

		priv = @k.encode_privkey(priv, 'bin').map{|c| c.chr}.join
		msghash = @sp.encode(@sp.hash_to_int(msghash), 256, 32).map{|c| c.chr}.join

		k = OpenSSL::HMAC.digest("SHA256", k, v + '0' + priv + msghash)
		v = OpenSSL::HMAC.digest("SHA256", k, v)

		k = OpenSSL::HMAC.digest("SHA256", k, v + '1' + priv + msghash)
		v = OpenSSL::HMAC.digest("SHA256", k, v)

		return @sp.decode(OpenSSL::HMAC.digest("SHA256", k, v), 256)
	end

	def ecdsa_raw_sign(msghash, priv)
		z = @sp.hash_to_int(msghash)
		k = deterministic_generate_k(msghash, priv)
		r, y = @e.fast_multiply(ECC::G, k)
		s = @e.inv(k, ECC::N) * (z + r * @k.decode_privkey(priv)) % ECC::N

		return 30 + (y % 2), r, s
	end

	def ecdsa_raw_verify(msghash, vrs, pub)
		v, r, s = vrs

		w = @e.inv(s, ECC::N)
		z = @sp.hash_to_int(msghash)

		u1, u2 = z * w % ECC::N, r * w % ECC::N
		x, y = @e.fast_add(@e.fast_multiply(ECC::G, u1), @e.fast_multiply(@k.decode_pubkey(pub), u2))

		return r == x
	end

	def ecdsa_raw_recover(msghash, vrs)
		v, r, s = vrs

		x = r
		#beta = ((x*x*x + A*x + B) ** (P+1)/4) % P
		beta = (x*x*x + ECC::A*x + ECC::B)
		beta = @e.square_and_multiply(beta, ECC::P)
		y = v % 2 ^ beta % 2 ? beta : (ECC::P - beta)
		z = @sp.hash_to_int(msghash)
		gz = @e.fast_multiply(ECC::G, (ECC::N - z) % ECC::N) #jacobian_multiply([Gx, Gy, 1], (N - z) % N)
		xy = @e.fast_multiply([x, y], s) #jacobian_multiply([x, y, 1], s)
		qr = @e.fast_add(gz, xy) #jacobian_add(gz, xy)
		q = @e.fast_multiply(qr, @e.inv(r, ECC::N)) #jacobian_multiply(qr, inv(r, N))
		#q = from_jacobian(q)

		return q if ecdsa_raw_verify(msghash, vrs, q)
		return false
	end
end