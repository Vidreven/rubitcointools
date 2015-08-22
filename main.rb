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

	#private

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