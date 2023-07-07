import os
from typing import Tuple, List, Any, Union

from secrets import randbelow

import babyjubjub
from params import CryptoParams
from crtypes import KeyPair, CipherValue, PrivateKeyValue, PublicKeyValue

from timer import time_measure


class ElgamalCrypto():
    params = CryptoParams('elgamal')
    # generate sk and pk
    def _generate_key_pair(self) -> Tuple[List[int], int]:
        sk = randbelow(babyjubjub.CURVE_ORDER)
        pk = babyjubjub.Point.GENERATOR * babyjubjub.Fr(sk)
        return [pk.u.s, pk.v.s], sk
    # encrypt
    def _enc(self, plain: int, _: int, target_pk: int) -> Tuple[List[int], List[int]]:
        pk = self.serialize_pk(target_pk, self.params.key_bytes)
        r = randbelow(babyjubjub.CURVE_ORDER)
        cipher_chunks = self._enc_with_rand(plain, r, pk)
        return cipher_chunks, [r]
    # decrypt without discrete log
    def _dec_embedded(self, cipher: Tuple[int, ...], sk: Any) -> List[int]:
        c1 = babyjubjub.Point(babyjubjub.Fq(cipher[0]), babyjubjub.Fq(cipher[1]))
        c2 = babyjubjub.Point(babyjubjub.Fq(cipher[2]), babyjubjub.Fq(cipher[3]))
        shared_secret = c1 * babyjubjub.Fr(sk)
        plain_embedded = c2 + shared_secret.negate()
        return plain_embedded
    # perform HE operation
    def do_op(self, op: str, public_key: List[int], *args: Union[CipherValue, int]) -> List[int]:
        def deserialize(operand: Union[CipherValue, int]) -> Union[Tuple[babyjubjub.Point, babyjubjub.Point], int]:
            if isinstance(operand, CipherValue):
                # if ciphertext is 0, return (Point.ZERO, Point.ZERO) == Enc(0, 0)
                if operand == CipherValue([0]*4, params=operand.params):
                    return babyjubjub.Point.ZERO, babyjubjub.Point.ZERO
                else:
                    c1 = babyjubjub.Point(babyjubjub.Fq(operand[0]), babyjubjub.Fq(operand[1]))
                    c2 = babyjubjub.Point(babyjubjub.Fq(operand[2]), babyjubjub.Fq(operand[3]))
                    return c1, c2
            else:
                return operand
        args = [deserialize(arg) for arg in args]

        if op == '+':
            e1 = args[0][0] + args[1][0]
            e2 = args[0][1] + args[1][1]
        elif op == '-':
            e1 = args[0][0] + args[1][0].negate()
            e2 = args[0][1] + args[1][1].negate()
        elif op == '*' and isinstance(args[1], int):
            e1 = args[0][0] * babyjubjub.Fr(args[1])
            e2 = args[0][1] * babyjubjub.Fr(args[1])
        elif op == '*' and isinstance(args[0], int):
            e1 = args[1][0] * babyjubjub.Fr(args[0])
            e2 = args[1][1] * babyjubjub.Fr(args[0])
        else:
            raise ValueError(f'Unsupported operation {op}')

        return [e1.u.s, e1.v.s, e2.u.s, e2.v.s]
    # re-randomization
    def do_rerand(self, arg: CipherValue, public_key: List[int]) -> Tuple[List[int], List[int]]:
        # homomorphically add encryption of zero to re-randomize
        r = randbelow(babyjubjub.CURVE_ORDER)
        enc_zero = CipherValue(self._enc_with_rand(0, r, public_key), params=arg.params)
        return self.do_op('+', public_key, arg, enc_zero), [r]
    # encrypt with given random value
    def _enc_with_rand(self, plain: int, random: int, pk: List[int]) -> List[int]:
        plain_embedded = babyjubjub.Point.GENERATOR * babyjubjub.Fr(plain)
        shared_secret = babyjubjub.Point(babyjubjub.Fq(pk[0]), babyjubjub.Fq(pk[1])) * babyjubjub.Fr(random)
        c1 = babyjubjub.Point.GENERATOR * babyjubjub.Fr(random)
        c2 = plain_embedded + shared_secret
        return [c1.u.s, c1.v.s, c2.u.s, c2.v.s]
    # re-encrypt with given random value. this only re-encrypt with one sk, so full re-encryption
    def _reenc_with_rand(self, cipher: Tuple[int, ...] ,random: int, pk: List[int],sk: Any) -> List[int]:
        c1 = babyjubjub.Point(babyjubjub.Fq(cipher[0]), babyjubjub.Fq(cipher[1]))
        c2 = babyjubjub.Point(babyjubjub.Fq(cipher[2]), babyjubjub.Fq(cipher[3]))
        shared_secret = c1 * babyjubjub.Fr(sk)
        plain_embedded = c2 + shared_secret.negate()
        new_shared_secret = babyjubjub.Point(babyjubjub.Fq(pk[0]), babyjubjub.Fq(pk[1])) * babyjubjub.Fr(random)
        d1 = babyjubjub.Point.GENERATOR * babyjubjub.Fr(random)
        d2 = plain_embedded + new_shared_secret
        return [d1.u.s, d1.v.s, d2.u.s, d2.v.s]
    # re-encrypt with given random value. this does partial re-encryption and returns w1 and w2 which is then used for final re-encryption
    def _reenc_multi(self, cipher: Tuple[int, ...] ,random: int, pk: List[int],sk: Any) -> List[int]:
        c1 = babyjubjub.Point(babyjubjub.Fq(cipher[0]), babyjubjub.Fq(cipher[1]))
        c2 = babyjubjub.Point(babyjubjub.Fq(cipher[2]), babyjubjub.Fq(cipher[3]))
        shared_secret = c1 * babyjubjub.Fr(sk)
        shared_secret_neg = shared_secret.negate()
        new_shared_secret = babyjubjub.Point(babyjubjub.Fq(pk[0]), babyjubjub.Fq(pk[1])) * babyjubjub.Fr(random)
        d1 = babyjubjub.Point.GENERATOR * babyjubjub.Fr(random)
        d2 = shared_secret_neg + new_shared_secret
        return [d1.u.s, d1.v.s, d2.u.s, d2.v.s]
    # final step in re-encryption given the cipher that was encrypted with combined pk, and all w1 and w2 from all parties. 
    def _reenc_final(self, cipher: Tuple[int, ...], w: Tuple[List[int], ...]) -> List[int]:
        if len(w) < 1:
            return [0,0,0,0]
        c1 = babyjubjub.Point(babyjubjub.Fq(cipher[0]), babyjubjub.Fq(cipher[1]))
        c2 = babyjubjub.Point(babyjubjub.Fq(cipher[2]), babyjubjub.Fq(cipher[3]))
        w1 = babyjubjub.Point(babyjubjub.Fq(w[0][0]), babyjubjub.Fq(w[0][1]))
        w2 = babyjubjub.Point(babyjubjub.Fq(w[0][2]), babyjubjub.Fq(w[0][3]))
        d1 = w1
        d2 = c2 + w2
        for wi in w[1:]:
            w3 = babyjubjub.Point(babyjubjub.Fq(wi[0]), babyjubjub.Fq(wi[1]))
            w4 = babyjubjub.Point(babyjubjub.Fq(wi[2]), babyjubjub.Fq(wi[3]))
            d1 = d1 + w3
            d2 = d2+ w4
        return [d1.u.s, d1.v.s, d2.u.s, d2.v.s]
    # combine pks to generate one common pk
    def _combine_pks(self,pks: Tuple[List[int], ...]) -> List[int]:
        if len(pks) < 1:
            return [0,0]
        pk_p = babyjubjub.Point(babyjubjub.Fq(pks[0][0]), babyjubjub.Fq(pks[0][1]))
        for pk in pks[1:]:
            pk_p2 = babyjubjub.Point(babyjubjub.Fq(pk[0]), babyjubjub.Fq(pk[1]))
            pk_p = pk_p + pk_p2
        pk_all = [pk_p.u.s, pk_p.v.s]
        return pk_all
