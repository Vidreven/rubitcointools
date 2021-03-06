require_relative 'hashes'
require_relative 'keys'
require_relative 'specials'
require 'openssl'

class Deterministic
	# Electrum wallets

	def initialize
		@h = Hashes.new
		@k = Keys.new
		@sp = Specials.new
	end

	# def electrum_stretch(seed)
	# 	@h.slowsha seed
	# end

	# Accepts seed or stretched seed, returns master public key (public key without '04')
	# def electrum_mpk(seed)
	# 	seed = electrum_stretch(seed)# if seed.length == 32
	# 	@k.privkey_to_pubkey(seed)[2..-1]
	# end

	# Accepts (seed or stretched seed), index and secondary index
	# (conventionally 0 for ordinary addresses, 1 for change) , returns privkey
	# def electrum_privkey(seed, n, for_change=0)
	# 	seed = electrum_stretch(seed)# if seed.length == 32
	# 	mpk = electrum_mpk(seed)
	# 	offset = @h.bin_dbl_sha256(n.to_s + ":" + for_change.to_s + ":" + mpk)
	# 	offset = @sp.changebase(offset, 256, 16)
		
	# 	@k.add_privkeys(seed, offset)
	# end

	# Accepts (seed or stretched seed or master pubkey), index and secondary index
	# (conventionally 0 for ordinary addresses, 1 for change) , returns pubkey
	# def electrum_pubkey(masterkey, n, for_change=0)
	# 	if masterkey.length == 32
	# 		mpk = electrum_mpk(electrum_stretch(masterkey))
	# 	elsif masterkey.length == 64
	# 		mpk = electrum_mpk(masterkey)
	# 	else
	# 		mpk = masterkey
	# 	end

	# 	bin_mpk = @k.encode_pubkey(mpk, 'bin_electrum')
	# 	offset = @h.bin_dbl_sha256(n.to_s + ":" + for_change.to_s + ":" + bin_mpk)
	# 	offset = @k.privtopub(offset)
	# 	offset = '0' + @sp.changebase(offset, 256, 16)

	# 	return @k.add_pubkeys('04'+ mpk, offset)
	# end

	# seed/stretched seed/pubkey -> address (convenience method)
	# def electrum_address(masterkey, n, for_change=0, version=0)
	# 	return @k.pubkey_to_address(electrum_pubkey(masterkey, n, for_change), version)
	# end

	# Given a master public key, a private key from that wallet and its index,
	# cracks the secret exponent which can be used to generate all other private
	# keys in the wallet
	# def crack_electrum_wallet(mpk, pk, n, for_change=0)
	# 	bin_mpk = @k.encode_pubkey(mpk, 'bin_electrum')
	# 	offset = @h.bin_dbl_sha256(n.to_s + ":" + for_change.to_s + ":" + bin_mpk)
	# 	return @k.subtract_privkeys(pk, offset)
	# end

	MAINNET_PRIVATE = "0488ade4" #"\x04\x88\xAD\xE4"
	MAINNET_PUBLIC = "0488b21e" #"\x04\x88\xB2\x1E"
	TESTNET_PRIVATE = "04358394" #"\x045\x83\x94"
	TESTNET_PUBLIC = "043587cf" #"\x045\x87\xCF"
	PRIVATE = [MAINNET_PRIVATE, TESTNET_PRIVATE]
	PUBLIC = [MAINNET_PUBLIC, TESTNET_PUBLIC]

	# BIP32 child key derivation
	# Both public and private
	def raw_bip32_ckd(rawtuple, i)
		vbytes, depth, fingerprint, oldi, chaincode, key = rawtuple
		i = @sp.encode(i.to_i, 256, 4)

		if PRIVATE.include? vbytes
			priv = @k.encode_privkey(key, :bin)
			pub = @k.privtopub key
		else
			pub = key
		end

		if @sp.decode(i, 256) >= 2**31
			if PUBLIC.include? vbytes
				raise ArgumentError, "Can't do private derivation on public key!"
			end

			#h = OpenSSL::HMAC.digest("SHA512", chaincode, "0" + priv + @sp.encode(i, 16, 8))
			h = OpenSSL::HMAC.digest("SHA512", chaincode, 0.chr + priv + i)
		else
			#h = OpenSSL::HMAC.digest("SHA512", chaincode, @k.compress(pub) + @sp.encode(i, 16, 8))
			h = OpenSSL::HMAC.digest("SHA512", chaincode, @k.compress(pub) + i)
		end

		newkey = @k.add_privkeys(h[0..31], priv) if PRIVATE.include? vbytes

		newkey = @k.add_pubkeys(@k.privtopub(h[0..31]), pub) if PUBLIC.include? vbytes

		fingerprint = @h.bin_hash160(pub)[0..3]

		[vbytes, depth + 1, fingerprint, i, h[32..-1], newkey]
	end

	# Assumes byte input and compressed pubkey
	def bip32_serialize(rawtuple)
		vbytes, depth, fingerprint, i, chaincode, key = rawtuple

		#chaincode = chaincode.rjust(32, 0.chr)

		if PRIVATE.include? vbytes
			keydata = 0.chr + key
		else
			keydata = @k.compress key
		end

		vbytes = @sp.changebase(vbytes, 16, 256)

		bindata = vbytes + depth.chr + fingerprint + i + chaincode + keydata

		checksum = @h.bin_dbl_sha256(bindata)[0..3]

		@sp.changebase(bindata + checksum, 256, 58)
	end

	def bip32_deserialize(data)
		dbin = @sp.changebase(data, 58, 256)

		raise ArgumentError, "Invalid checksum" unless @h.bin_dbl_sha256(dbin[0..-5])[0..3] == dbin[-4..-1]

		vbytes = @sp.changebase(dbin[0..3], 256, 16, 8)
		depth = dbin[4].ord
		fingerprint =dbin[5..8]
		i = dbin[9..12]
		chaincode = dbin[13..44]

		if PRIVATE.include? vbytes
			key = dbin[46..77]
		else
			key = @k.decompress dbin[45..77]
		end

		[vbytes, depth, fingerprint, i, chaincode, key]
	end

	def raw_bip32_privtopub(rawtuple)
		vbytes, depth, fingerprint, i, chaincode, key = rawtuple
		if vbytes == MAINNET_PRIVATE
			newvbytes = MAINNET_PUBLIC
		else
			newvbytes = TESTNET_PUBLIC
		end

		[newvbytes, depth, fingerprint, i, chaincode, @k.privtopub(key)]
	end

	def bip32_privtopub(data)
		bip32_serialize(raw_bip32_privtopub(bip32_deserialize(data)))
	end

	def bip32_ckd(data, i)
		bip32_serialize(raw_bip32_ckd(bip32_deserialize(data), i))
	end

	def bip32_master_key(seed)
		h = OpenSSL::HMAC.digest("SHA512", "Bitcoin seed", seed)

		bip32_serialize([MAINNET_PRIVATE, 0, 0.chr * 4, 0.chr * 4, h[32..-1], h[0..31]])
	end

	def bip32_bin_extract_key(data)
		bip32_deserialize(data)[-1]
	end

	def bip32_extract_key(data)
		key = bip32_bin_extract_key data
		return @k.encode_privkey(key, :hex) if key.size == 32
		return @k.encode_pubkey(key, :hex) if key.size == 65
	end

	# Exploits the same vulnerability as above in Electrum wallets
	# Takes a BIP32 pubkey and one of the child privkeys of its corresponding
	# privkey and returns the BIP32 privkey associated with that pubkey

	def raw_crack_bip32_privkey(parent_pub, priv)
		vbytes, depth, fingerprint, i, chaincode, key = priv
		pvbytes, pdepth, pfingerprint, pi, pchaincode, pkey = parent_pub
		i = i.to_i

		raise "Can't crack private derivation!" if i >= 2**31

		h = OpenSSL::HMAC.digest("SHA512", pchaincode, pkey + encode(i, 256, 4))

		pprivkey = @k.subtract_privkeys(key, h[0..32] + "1")

		if vbytes == MAINNET_PUBLIC
			newvbytes = MAINNET_PRIVATE
		else
			newvbytes = TESTNET_PRIVATE
		end

		return [newvbytes, pdepth, pfingerprint, pi, pchaincode, pprivkey]
	end

	def crack_bip32_privkey(parent_pub, priv)
		dsppub = bip32_deserialize(parent_pub)
		dspriv = bip32_deserialize(priv)
		
		return bip32_serialize(raw_crack_bip32_privkey(dsppub, dspriv))
	end
end