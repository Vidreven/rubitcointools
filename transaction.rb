require_relative 'specials'

class Transaction

	def initialize
		@sp = Specials.new
	end

	# Decides if object is a base string
	def json_is_base(obj, base)
		code_string = @sp.get_code_string(base)

		if obj.respond_to? :each_char
			obj.each_char do |c|
				return false unless code_string.include? c
			end
		elsif obj.respond_to? :each
			obj.each do |o|
				return false unless json_is_base(o, base)
			end
		elsif obj.respond_to? :each_key
			obj.each_key do |o|
				return false unless json_is_base(obj[o], base)
			end
		end

		return true
	end

	# def json_changebase(obj, &block)

	# 	if obj.is_a? String
	# 		yield obj
	# 	elsif obj.respond_to? :each
	# 		obj.map do |o|
	# 			yield o
	# 		end
	# 	elsif obj.respond_to? :each_pair
	# 		obj.each_pair do |k, v|
	# 			k[v] = yield v
	# 		end
	# 	else
	# 		return obj
	# 	end
	# end

	def deserialize(tx)
		pos = 0
		obj = {ins: [], outs: []}
		obj[:version] = read_as_int(pos, 4, tx)
		pos += 8
		ins = read_var_int(pos, tx)
		pos += ins.length + 2
		ins = @sp.change_endianness(ins).to_i(16)

		ins.times do |in|
			obj[:ins] << {
				outpoint: {
					hash: read_as_int(pos, 32, tx),
					index: read_as_int(pos+64, 4, tx)
				},
				script: read_var_string(pos+72, tx)
			}
		end
	end

	private

	# accepts length in bytes
	def read_as_int(pos, bytes, tx)
		chars = bytes * 2 #reads hexa chars
		return tx[pos.. pos+chars-1]
	end

	# returns variable part of varint
	def read_var_int(pos, tx)
		val = tx[pos..pos+1].to_i(16)
		return val if val < 253
		return read_as_int(pos+2, 2**(val-252), tx)
	end

	# varint + char[]
	# returns the starting position of var_string and string itself
	def read_var_string(pos, tx)
		varpart = read_var_int(pos, tx)
		str_pos = pos + 2 + varpart.length
		size = @sp.change_endianness(varpart).to_i(16) # convert var_int to int
		return [str_pos, read_as_int(str_pos, size/2, tx)]
	end
end

#Transaction.new.deserialize('01000000FD0001' + 'a'*256)