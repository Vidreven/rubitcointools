require 'openssl'

class Arbitrary

	def random_string(length)
		return SecureRandom.random_bytes length
	end

	# Used for seeding xorshift
	# http://xorshift.di.unimi.it/splitmix64.c
	# def seed
	# 	x = Random.new_seed
	# 	z = x + 0x9E3779B97F4A7C15
	# 	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	# 	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	# 	z ^ (z >> 31)
	# end

	# http://xorshift.di.unimi.it/xorshift128plus.c
	# def xorshift
	# 	s = [seed, seed]
	# 	s1 = s[0]
	# 	s0 = s[1]
	# 	s[0] = s0

	# 	s1 ^= s1 << 23
	# 	s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5)
	# 	s[1] + s0
	# end

	def get_entropy
		random_string(64) + OpenSSL::Random.random_bytes(64)  # + xorshift.to_s(16)
	end
end