require 'digest'
require 'sysrandom'
require_relative 'hashes'

class Specials

	attr_reader :code_strings

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

	# def get_code_string(base)
	# 	return @code_strings[base] if @code_strings.has_key?(base)
	# 	raise "Invalid base!"
	# end

	def changebase(string, from, to, minlen = 0)
		return encode(decode(string, from), to, minlen) unless to == from
		return string#.rjust(minlen, get_code_string(from)[0])
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
		data = '00' * leadingzbyte + changebase(inp, 58, 16)
		return changebase(data[1..-9], 16, 256)
	end

	def b58check_to_hex(inp)
		return changebase(b58check_to_bin(inp), 256, 16)
	end

	# Decode from base 'base' to base 10
	def decode(string, base)
		return string.to_i if base == 10

		code_string = @code_strings[base] #get_code_string(base)
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

		code_string = @code_strings[base] #get_code_string(base)
		result_bytes = []

		while value > 0
			curcode = code_string[value % base]
			result_bytes = result_bytes.unshift(curcode.ord)
			value /= base
		end

		padding_element =
		if base == 256
			0.chr
		elsif base == 58
			"1"
		else
			"0"
		end

		result = base == 256 ? result_bytes.map{|b| b.chr}.join.rjust(minlen, padding_element) : result_bytes.pack("C*").rjust(minlen, padding_element)

		return result		
	end

	def hash_to_int(x)
		return decode(x, 16) if [40, 64].include? x.length
		return decode(x, 256)
	end

	def change_endianness(hex_string)
		return [hex_string].pack('H*').reverse.unpack('H*')[0]
	end

	def random_string(length)
		return Sysrandom.random_bytes length
	end
end