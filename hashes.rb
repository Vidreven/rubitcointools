require 'digest'

class Hashes

	def bin_hash160(string)
		hash160 = Digest::RMD160.new
		sha256 = Digest::SHA256.new
		return hash160.digest(sha256.digest(string))
	end

	alias :bin_ripemd160 :bin_hash160

	def hash160(string)
		hash160 = Digest::RMD160.new
		return hash160.hexdigest(string)
	end

	alias :ripemd160 :hash160

	def bin_sha256(string)
		sha256 = Digest::SHA256.new
		return sha256.digest(string)
	end

	def bin_dbl_sha256(string)
		return bin_sha256(bin_sha256(string))
	end

	def sha256(string)
		sha256 = Digest::SHA256.new
		return sha256.hexdigest(string)
	end

	def bin_slowsha(string)
		orig_input = string

		100000.times{string = bin_sha256(string + orig_input)}
		return string
	end

	def slowsha(string)
		return bin_slowsha(string).unpack('H*')[0]
	end
end