Ruby implementation of [pybitcointools](https://github.com/vbuterin/pybitcointools). For learning purposes only.

# Creating a transaction:

1. privkey = @k.random_key

2. privkey = @k.encode_privkey(privkey, :wif)

3. pubkey = @k.privtopub privkey

4. recaddress = @k.pubtoaddr pubkey

5. sendAddr = '1wuE96CexNEEUVC11Fek9WEEPb7a4ZmLh'

6. scriptPubKey = @s.mk_pubkey_script sendAddr

7. amount = 20_000

8. out0 = @t.mkout(amount, scriptPubKey)

9. hash = 'bc3b06095e51116522f49a94757d063b49a8c5fb69db0cf9611813efadca81e6'

10. index = 1

11. in0 = @t.mkin(hash, index, scriptPubKey)

12. tx = @t.mktx(in0, out0)

13. tx = @t.sign_all(tx, privkey)

14. p @t.serialize tx

# Creating a multisig transaction:

1. priv1 = @k.random_key
   priv2 = @k.random_key
   priv3 = @k.random_key

2. priv1 = @k.encode_privkey(priv1, :wif)
   priv2 = @k.encode_privkey(priv2, :wif)
   priv3 = @k.encode_privkey(priv3, :wif)

3. pub1 = @k.privtopub priv1
   pub2 = @k.privtopub priv2
   pub3 = @k.privtopub priv3

4. adr1 = @k.pubtoaddr pub1
   adr2 = @k.pubtoaddr pub2
   adr3 = @k.pubtoaddr pub3

   keys = [pub1, pub2, pub3]
   privs = [priv1, priv2, priv3]

5. redeem_script = @s.mk_psh_redeem_script(2, keys)

6. multi_address = @k.script_to_address redeem_script

7. sendAddr = '19SmXAQRNamQWsMe8DBTNS8DTWQmu9b3ZK'

8. scriptPubKey = @s.mk_pubkey_script sendAddr

9. amount = 10_000

10. out = @t.mkout(amount, scriptPubKey)

11. hash = '40dfcb21ba28d49d828e9185997437260cc7cbb15705de1060ab61d52fa5653a'

12. index = 0

13. inp = @t.mkin(hash, index, scriptPubKey)

14. tx = @t.mktx(inp, out)

15. sig1 = @t.multisign(tx, 0, redeem_script, privs[0])

16. sig2 = @t.multisign(tx, 0, redeem_script, privs[2])

17. tx = @t.apply_multisignatures(tx, 0, redeem_script, sig1, sig2)

18. p @t.serialize tx