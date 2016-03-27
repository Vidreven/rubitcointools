require_relative 'specials'
require_relative 'hashes'
require_relative 'ecdsa'
require_relative 'scripts'

class Transaction

	def initialize
		@sp = Specials.new
		@h = Hashes.new
		@dsa = ECDSA.new
		@k = Keys.new
		@sc = Scripts.new
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
				scriptSig: read_var_string(tx),
				sequence: @sp.change_endianness(read_and_modify(4, tx))
			}
		}

		outs = read_var_int(tx)
		outs.times{
			obj[:outs] << {
				value: @sp.change_endianness(read_and_modify(8, tx)),
				scriptPubKey: read_var_string(tx)
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
			scriptlen = input[:scriptSig].length / 2 # convert charlen to bytelen
			scriptlen = scriptlen.to_s(16)
			raw += scriptlen + input[:scriptSig]
			raw += @sp.change_endianness(input[:sequence])
		end

		raw += txobj[:outs].length.to_s(16).rjust(2, '0')

		txobj[:outs].each do |output|
			raw += @sp.change_endianness(output[:value])
			scriptlen = output[:scriptPubKey].length / 2
			scriptlen = scriptlen.to_s(16)
			raw += scriptlen + output[:scriptPubKey]
		end

		raw += @sp.change_endianness(txobj[:locktime])

		return raw
	end

	# Hashing transactions for signing

	SIGHASH_ALL = 1
	SIGHASH_NONE = 2
	SIGHASH_SINGLE = 3
	SIGHASH_ANYONECANPAY = 0x81

	
	# Prepares the transaction for hashing. Each input has to be handled separately.
	# For hasing each scriptSig in has to be first filled with scriptPubKey.
	def signature_form(tx, i, scriptPubKey, hashcode=SIGHASH_ALL)
		i, hashcode = i.to_i, hashcode.to_i

		if tx.respond_to? :each_char
			return serialize(signature_form(deserialize(tx), i, scriptPubKey, hashcode))
		end

		newtx = deepcopy(tx)

		newtx[:ins].each do |input|
			input[:scriptSig] = ""
		end

		newtx[:ins][i][:scriptSig] = scriptPubKey

		if hashcode == SIGHASH_NONE
			newtx[:outs] = []
		elsif hashcode == SIGHASH_SINGLE
			newtx[:outs].each_index do |index|
				next if index == i
				newtx[:outs][index][:value] = 2**64 - 1
				newtx[:outs][index][:scriptPubKey] = ""
				#newtx[:ins][index][:sequence] = '00000000'
			end
		elsif hashcode == SIGHASH_ANYONECANPAY
			newtx[:ins] = [newtx[:ins][i]]
		end

		return newtx
	end

	# def bin_txhash(tx, hashcode='None')
	# 	if hashcode == 'None'
	# 		result = @h.bin_dbl_sha256(tx)
	# 	else
	# 		result = @h.bin_dbl_sha256(tx + hashcode.to_s.rjust(8, '0'))
	# 	end

	# 	return @sp.change_endianness(result)
	# end

	# Accepts transaction in serialized format and appends hashcode before hashing.
	def bin_txhash(tx, hashcode=SIGHASH_ALL)
		hashcode = hashcode.to_s.rjust(8, '0')
		hashcode = @sp.change_endianness(hashcode)
		result = @h.bin_dbl_sha256(tx + hashcode)

		return @sp.change_endianness(result)
	end

	def txhash(tx, hashcode=nil)
		return @sp.changebase(bin_txhash(tx, hashcode), 256, 16)
	end

	# Signs the transaction, appends the hashcode and encodes it into DER format.
	def ecdsa_tx_sign(tx, priv, hashcode=SIGHASH_ALL)
		rawsig = @dsa.ecdsa_raw_sign(bin_txhash(tx, hashcode), priv)
		return @dsa.encode_sig(*rawsig) + @sp.encode(hashcode, 16, 2)
	end

	def ecdsa_tx_verify(tx, sig, pub, hashcode=SIGHASH_ALL)
		return @dsa.ecdsa_raw_verify(bin_txhash(tx, hashcode), @dsa.decode_sig(sig), pub)
	end

	# recovers pubkey
	# def ecdsa_tx_recover(tx, sig, hashcode=SIGHASH_ALL)
	# 	z = bin_txhash(tx, hashcode)
	# 	v, r, s = @dsa.decode_sig(sig)

	# 	left, right = @dsa.ecdsa_raw_recover(z, [v, r, s])

	# 	return @k.encode_pubkey([left, right], 'hex')
	# end

	# Signing and verifying

	# Takes a deserialized transaction as input, generates the public key and address,
	# signs the input and creates and inserts the proper scriptSig.
	def sign(tx, i, priv, hashcode=SIGHASH_ALL)
		i = i.to_i

		pub = @k.privtopub(priv)
		address = @k.pubtoaddr(pub)
		txobj = deepcopy(tx)

		# u scriptSig ide scriptPubKey transakcije koju želimo potrošiti (ali nije nužno)
		signing_tx = signature_form(tx, i, @sc.mk_pubkey_script(address), hashcode)
		signing_tx = serialize(signing_tx) # Samo ako prethodno nije serijalizirana
		sig = ecdsa_tx_sign(signing_tx, priv, hashcode)

		txobj[:ins][i][:scriptSig] = (sig.length / 2).to_s(16) + sig + (pub.length / 2).to_s(16) + pub

		#return serialize(txobj)
		return txobj
	end

	# Takes a serialized transaction as input
	# and signs every transaction input.
	def sign_all(tx, priv)

		tx = deserialize(tx)

		tx[:ins].each_index do |i|
			#tx = deserialize(sign(tx, i, priv))
			tx = sign(tx, i, priv)
		end

		return tx
	end

	# Takes a deserialized transaction as input and signs the input
	# script =? pubKeyhash
	def multisign(tx, i, script, priv, hashcode=SIGHASH_ALL)
		modtx = signature_form(tx, i, script, hashcode)
		return ecdsa_tx_sign(modtx, priv, hashcode)
	end

	# Takes a serialized multisig transaction as input
	# and appends signatures and script to the input field.
	# Separate persons can controll different pubkeys/signatures.
	# Params:
	# +tx+:: serialized multisig transaction
	# +i+:: - input index
	# +script+:: - PSH reddem script (OP_M pubkeys OP_N OP_CHECKMULTISIG)
	# +sigs+:: - string array of signatures
	def apply_multisignatures(tx, i, script, sigs)
		txobj = deserialize(tx)
		scriptSig = "0" # Push byte 0x0 due to bug in multisig

		sigs.each do |sig|
			scriptSig += (sig.length / 2).to_s(16) + sig
		end

		scriptSig += (script.length / 2).to_s(16) + script

		txobj[:ins][i][:scriptSig] = scriptSig

		return txobj
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