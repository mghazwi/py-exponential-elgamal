from elgamal import ElgamalCrypto
from crtypes import CipherValue, KeyPair
from timer import time_measure

import babyjubjub
from secrets import randbelow

class TestElgamal():
    
    # Evaluation of each step in the HE process
    eg = ElgamalCrypto()
    # shared key pairs.
    kp = eg._generate_key_pair()
    pk = kp[0] # public key
    sk = kp[1] # private key
    # second set of key pairs
    kp2 = eg._generate_key_pair()
    pk2 = kp2[0] # public key 2
    sk2 = kp2[1] # private key 2
    # third set of key pairs
    kp3 = eg._generate_key_pair()
    pk3 = kp2[0] # public key 3
    sk3 = kp2[1] # private key 3
    # combine pks in tuple
    pks = (pk,pk2)
    # plaintexts (can be modified to any plaintext up to 32bit length) 
    plain1 = 42
    plain2 = 53
    # shared random value
    random = randbelow(babyjubjub.CURVE_ORDER)
    random2 = randbelow(babyjubjub.CURVE_ORDER)
    random3 = randbelow(babyjubjub.CURVE_ORDER)
    # shared ciphertexts
    cipher1 = CipherValue(eg._enc_with_rand(plain1, random, pk))
    cipher2 = CipherValue(eg._enc_with_rand(plain2, random, pk))
    #shared HE added result
    res = eg.do_op('+', None, cipher1, cipher2)
    # encrypt with shared pk
    pk_all = eg._combine_pks(pks)
    c_all = eg._enc_with_rand(plain1,random,pk_all)
    # partial decrypt
    w1 = CipherValue(eg._reenc_multi(c_all,random2,pk3, sk))
    w2 = CipherValue(eg._reenc_multi(c_all,random3,pk3, sk2))

    # evaluate key generation
    def eval_key_gen(self,n):
        kp = []
        with time_measure("key generation"):
            for i in range(n):
                kp.append(self.eg._generate_key_pair())

    # evaluate encryption
    def eval_enc(self,n):
        with time_measure("elgamal-encrypt-plaintext"):
            for i in range(n):
                cipher = CipherValue(self.eg._enc_with_rand(self.plain1,self.random,self.pk))

    # evaluate homomorphic addition
    def eval_hom_add(self,n):
        with time_measure("elgamal-HE-addition"):
            for i in range(n):
                res = self.eg.do_op('+', None, self.cipher1, self.cipher2)

    # evaluate homomorphic substraction
    def eval_hom_sub(self,n):
        with time_measure("elgamal-HE-substraction"):
            for i in range(n):
                res = self.eg.do_op('-', None, self.cipher1, self.cipher2)

    # evaluation homomorphic multiplication
    def eval_hom_mul(self,n):
        with time_measure("elgamal-HE-multiplication"):
            for i in range(n):
                res = self.eg.do_op('*', None, self.cipher1, 2)

    # evaluate decryption (without finding the discrete log)
    def eval_dec(self,n):
        with time_measure("elgamal-dencrypt-result"):
            for i in range(n):
                plainback = self.eg._dec_embedded(self.res, self.sk)

    # evaluate combining pks
    def eval_combine_pks(self,n):
        with time_measure("elgamal-combine-pks"):
            for i in range(n):
                pk_all = self.eg._combine_pks(self.pks)

    # evaluate re-enc multi (partial re-encrypt)
    def eval_reenc_multi(self,n):
        with time_measure("elgamal-reenc-multi"):
            for i in range(n):
                w = CipherValue(self.eg._reenc_multi(self.c_all,self.random2,self.pk3, self.sk))

    # evaluate final re-encrypt
    def eval_reenc_final(self,n):
        wi = (self.w1,self.w2)
        with time_measure("elgamal-reenc-multi"):
            for i in range(n):
                fi = self.eg._reenc_final( self.c_all,wi)

    # evaluate the whole process
    def eval_all(self):
            with time_measure("generate_key_pair"):
                kp = self.eg._generate_key_pair()
            pk = kp[0]
            print(f'pk = {pk}')
            sk = kp[1]
            print(f'sk = {sk}')
            with time_measure("elgamal-encrypt-cipher1"):
                print(f'encryption plaintext1 = {self.plain1}')
                cipher = CipherValue(self.eg._enc_with_rand(self.plain1, self.random, pk))
            with time_measure("elgamal-encrypt-cipher2"):
                print(f'encryption plaintext2 = {self.plain2}')
                cipher2 = CipherValue(self.eg._enc_with_rand(self.plain2, self.random, pk))
            with time_measure("elgamal-HE-addition"):
                res = self.eg.do_op('+', None, cipher, cipher2)
            with time_measure("elgamal-dencrypt-result"):
                plainback, _ = self.eg._dec(res, sk)
            print(f'Result after decryption {plainback}')


# Start the evaluation process:
elgamal = TestElgamal()
# n = number of times to run the functions
n = 1

# Evaluate key gen n times
#elgamal.eval_key_gen(n)

# Evaluate Encryption n times
#elgamal.eval_enc(n)

# Evaluate HE add n times
#elgamal.eval_hom_add(n)

# Evaluate HE sub n times
#elgamal.eval_hom_sub(n)

# Evaluate HE mul n times
#elgamal.eval_hom_mul(n)

# Evaluate decryption n times
#elgamal.eval_dec(n)

# Evaluate the whole process
#elgamal.eval_all()

# point addition
#plain = 3
#plain2 = 2
#xc1 = babyjubjub.Point.GENERATOR * babyjubjub.Fr(plain)
#xc2 = babyjubjub.Point.GENERATOR * babyjubjub.Fr(plain2)
#xy1 = xc1 + xc2
#print(xc1)
#print(xc2)
#print(xy1)

# get params
# print(f'pk = {elgamal.pk}')
# print(f'sk = {elgamal.sk}')
# print(f'rand = {elgamal.random}')
# pfr = babyjubjub.Fr(elgamal.random)
# print(f'randFr = {pfr}')
# gen = babyjubjub.Point.GENERATOR
# print(f'generator = {gen}')
# plain = 42
# print(f'plain = {plain}')
# plainfr = babyjubjub.Fr(plain)
# print(f'plainFr = {plainfr}')
# c = elgamal.eg._enc_with_rand(plain,elgamal.random,elgamal.pk)
# c2 = elgamal.eg._enc_with_rand(plain,elgamal.random,elgamal.pk2)
# print(f'cipher = {c}')

# plainback_embc = elgamal.eg._dec_embedded(c, elgamal.sk)
# print(f'plainback_embc = {plainback_embc}')
# plainback_embd = elgamal.eg._dec_embedded(c2, elgamal.sk2)
# print(f'plainback_embd = {plainback_embd}')

# emb = babyjubjub.Point.GENERATOR * babyjubjub.Fr(plain)
# print(f'plain embedded = {emb}')

# ci = CipherValue(elgamal.eg._enc_with_rand(plain,elgamal.random,elgamal.pk))
# ci2 = CipherValue(elgamal.eg._reenc_with_rand(ci,elgamal.random2,elgamal.pk2, elgamal.sk))

# plainback_emb = elgamal.eg._dec_embedded(ci2, elgamal.sk2)

# print(f'plainback_emb = {plainback_emb}')

# # combine pk
# pk_p = babyjubjub.Point(babyjubjub.Fq(elgamal.pk[0]), babyjubjub.Fq(elgamal.pk[1]))
# pk_p2 = babyjubjub.Point(babyjubjub.Fq(elgamal.pk2[0]), babyjubjub.Fq(elgamal.pk2[1]))
# pk_add = pk_p + pk_p2
# pk_all = [pk_add.u.s, pk_add.v.s]
# print(f'pk_all working = {pk_all}')
# pall = (elgamal.pk,elgamal.pk2)
# pk_all_n = elgamal.eg._combine_pks(pall)
# print(f'pk_all fn = {pk_all_n}')
# c_all = elgamal.eg._enc_with_rand(plain,elgamal.random,pk_all)
# # sk_all = elgamal.sk + elgamal.sk2
# w1 = CipherValue(elgamal.eg._reenc_multi(c_all,elgamal.random2,elgamal.pk3, elgamal.sk))
# w2 = CipherValue(elgamal.eg._reenc_multi(c_all,elgamal.random3,elgamal.pk3, elgamal.sk2))
# fi = elgamal.eg._reenc_final( c_all,w1,w2)
# print(f'fi org = {fi}')
# wi = (w1,w2)
# fi2 = elgamal.eg._reenc_final2( c_all,wi)
# print(f'fi new = {fi2}')
# plainback_all = elgamal.eg._dec_embedded(fi, elgamal.sk3)
# print(f'plainback_all = {plainback_all}')


