require 'digest'
require 'securerandom'
require_relative 'hashes'

class Specials

	def initialize
		# Base switching
		@code_strings = {
			2 => '01',
			10 => '0123456789',
			16 => '0123456789abcdef',
			32 => 'abcdefghijklmnopqrstuvwxyz234567',
			58 => '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
			256 => (0..255).map{|c| c.chr}.join('') # represents bytes
		}

		@h = Hashes.new
	end

	def lpad(msg, symbol, length)
		return msg if msg.length > length
		return symbol * (length - msg.length) + msg
	end

	def get_code_string(base)
		return @code_strings[base] if @code_strings.has_key?(base)
		raise "Invalid base!"
	end

	def changebase(string, from, to, minlen = 0)
		return encode(decode(string, from), to, minlen) unless to == from
		return lpad(string, get_code_string(from)[0], minlen)
	end

	def bin_to_b58check(input, magicbyte = 0)
		input_formated = magicbyte.chr + input

		leadingzbytes = 0
		input_formated.each_char do |c|
			break unless c == 0.chr
			leadingzbytes += 1
		end

		checksum = @h.bin_dbl_sha256(input_formated)[0..3]

		return "1" * leadingzbytes + changebase(input_formated + checksum, 256, 58)
	end

	def b58check_to_bin(inp)
		leadingzbyte = inp.match('^1*')[0].to_i
		data = (0.chr) * leadingzbyte + changebase(inp, 58, 16)

		return changebase(data[2..-9], 16, 256)
	end

	# Returned string is twice as long
	def random_string(length)
		return SecureRandom.random_bytes(length)
	end

	# Decode from base 'base' to base 10
	def decode(string, base)
		return string.to_i if base == 10

		code_string = get_code_string(base)
		result = 0

		if base == 256
			def extract(c, cs)
				return cs.index(c)
			end
		else
			def extract(c, cs)
				return cs.index(c.is_a?(String) ? c : c.chr)
			end
		end

		string.downcase! if base == 16

		while string.length > 0
			result *= base
			result += extract(string[0], code_string)
			string = string[1..-1]
		end

		return result
	end

	# Encode from base 10 to base 'base'
	def encode(value, base, minlen = 0)

		return value.to_s if base == 10

		code_string = get_code_string(base)
		result_bytes = []
		padding = ""

		while value > 0
			curcode = code_string[value % base]
			result_bytes = result_bytes.unshift(curcode.ord)
			value /= base
		end

		pad_size = minlen - result_bytes.length

		padding_element =
		if base == 256
			0.chr
		elsif base == 58
			"1"
		else
			"0"
		end

		if pad_size > 0
			padding = padding_element * pad_size
			result = base == 256 ? result_bytes.unshift(padding) : padding + result_bytes.pack("C*")
		else
			result = base == 256 ? result_bytes : result_bytes.pack("C*")
		end

		return result		
	end

	def hash_to_int(x)
		return decode(x, 16) if [40, 64].include? x.length
		return decode(x, 256)
	end

	def change_endianness(hex_string)
		return [hex_string].pack('H*').unpack('N*').pack('V*').unpack('H*')[0]
	end
end