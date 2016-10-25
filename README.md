Ruby implementation of [pybitcointools](https://github.com/vbuterin/pybitcointools). For learning purposes only.

Creating a transaction:

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