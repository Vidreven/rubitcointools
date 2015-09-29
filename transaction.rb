require_relative 'specials'
require_relative 'hashes'
require_relative 'ecdsa'

class Transaction

	def initialize
		@sp = Specials.new
		@h = Hashes.new
		@dsa = ECDSA.new
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

	def deserialize(tx)
		obj = {ins: [], outs: []}
		obj[:version] = @sp.change_endianness(read_and_modify(4, tx))
		ins = read_var_int(tx)

		ins.times{
			obj[:ins] << {
				outpoint: {
					hash: @sp.change_endianness(read_and_modify(32, tx)),
					index: @sp.change_endianness(read_and_modify(4, tx))
				},
				script: read_var_string(tx),
				sequence: @sp.change_endianness(read_and_modify(4, tx))
			}
		}

		outs = read_var_int(tx)
		outs.times{
			obj[:outs] << {
				value: @sp.change_endianness(read_and_modify(8, tx)),
				script: read_var_string(tx)
			}
		}
		obj[:locktime] = @sp.change_endianness(read_and_modify(4, tx))

		return obj
	end

	def serialize(txobj)
		raw = ''
		raw += @sp.change_endianness(txobj[:version])
		raw += txobj[:ins].length.to_s(16).rjust(2, '0')

		txobj[:ins].each do |input|
			raw += @sp.change_endianness(input[:outpoint][:hash])
			raw += @sp.change_endianness(input[:outpoint][:index])
			scriptlen = input[:script].length / 2 # convert charlen to bytelen
			scriptlen = scriptlen.to_s(16)
			raw += scriptlen + input[:script]
			raw += @sp.change_endianness(input[:sequence])
		end

		raw += txobj[:outs].length.to_s(16).rjust(2, '0')

		txobj[:outs].each do |output|
			raw += @sp.change_endianness(output[:value])
			scriptlen = output[:script].length / 2
			scriptlen = scriptlen.to_s(16)
			raw += scriptlen + output[:script]
		end

		raw += @sp.change_endianness(txobj[:locktime])

		return raw
	end

	# Hashing transactions for signing

	SIGHASH_ALL = 1
	SIGHASH_NONE = 2
	SIGHASH_SINGLE = 3
	SIGHASH_ANYONECANPAY = 0x81

	def signature_form(tx, i, script, hashcode=SIGHASH_ALL)
		i, hashcode = i.to_i, hashcode.to_i

		if tx.respond_to? :each_char
			return serialize(signature_form(deserialize(tx), i, script, hashcode))
		end

		newtx = deepcopy(tx)

		newtx[:ins].each do |input|
			input[:script] = ""
		end

		newtx[:ins][i][:script] = script

		if hashcode == SIGHASH_NONE
			newtx[:outs] = []
		elsif hashcode == SIGHASH_SINGLE
			newtx[:outs].each_index do |index|
				next if index == i
				newtx[:outs][index][:value] = 2**64 - 1
				newtx[:outs][index][:script] = ""
				#newtx[:ins][index][:sequence] = '00000000'
			end
		elsif hashcode == SIGHASH_ANYONECANPAY
			newtx[:ins] = [newtx[:ins][i]]
		end

		return newtx
	end

	def txhash(tx, hashcode='None')
		if hashcode == 'None'
			result = @h.bin_dbl_sha256(tx)
		else
			result = @h.bin_dbl_sha256(tx + hashcode.to_s.rjust(8, '0'))
		end

		return @sp.change_endianness(@sp.changebase(result, 256, 16))
	end

	def bin_txhash(tx, hashcode='None')
		return @sp.changebase(txhash(tx, hashcode), 16, 256)
	end

	def ecdsa_tx_sign(tx, priv, hashcode=SIGHASH_ALL)
		rawsig = @dsa.ecdsa_raw_sign(bin_txhash(tx, hashcode), priv)
		return @dsa.encode_sig(*rawsig) + @sp.encode(hashcode, 16, 2)
	end

	private

	# accepts length in bytes
	# modifies the string by slicing off bytes
	def read_and_modify(bytes, tx)
		chars = bytes * 2 #reads hexa chars
		return tx.slice!(0..chars-1)
	end

	# returns variable part of varint and modyfies tx
	def read_var_int(tx)
		val = tx.slice!(0..1).to_i(16)
		return val if val < 253
		var = read_and_modify(2**(val-252), tx)
		return  @sp.change_endianness(var).to_i(16)
	end

	# varint + char[]
	# returns the string and modyfies tx
	def read_var_string(tx)
		size = read_var_int(tx)
		return read_and_modify(size, tx)
	end

	def deepcopy(obj)
		return Marshal.load(Marshal.dump(obj))
	end
end