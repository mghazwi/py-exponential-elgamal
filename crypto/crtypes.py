from typing import Optional, Collection, Any, Dict, Tuple, List, Union, Callable

from params import CryptoParams


class Value(tuple):
    def __new__(cls, contents: Collection):
        return super(Value, cls).__new__(cls, contents)

    def __str__(self):
        return f'{type(self).__name__}({super().__str__()})'

    def __eq__(self, other):
        return isinstance(other, type(self)) and super().__eq__(other)

    def __hash__(self):
        return self[:].__hash__()

    @staticmethod
    def unwrap_values(v: Union[int, bool, 'Value', List, Dict]) -> Union[int, List, Dict]:
        if isinstance(v, List):
            return list(map(Value.unwrap_values, v))
        elif isinstance(v, AddressValue):
            return v.val
        elif isinstance(v, Dict):
            return {key: Value.unwrap_values(vals) for key, vals in v.items()}
        else:
            return list(v[:]) if isinstance(v, Value) else v

    @staticmethod
    def flatten(v: Collection) -> List:
        out = []
        for elem in v:
            if isinstance(elem, Collection):
                out += Value.flatten(elem)
            else:
                out.append(elem)
        return out

    @staticmethod
    def collection_to_string(v: Union[int, bool, 'Value', Dict, List, Tuple]) -> str:
        if isinstance(v, List):
            return f"[{', '.join(map(Value.collection_to_string, v))}]"
        elif isinstance(v, Tuple):
            return f"({', '.join(map(Value.collection_to_string, v))})"
        elif isinstance(v, Dict):
            return f"{{{', '.join([f'{key}: {Value.collection_to_string(val)}' for key, val in v.items()])}}}"
        else:
            return str(v)
    @staticmethod
    def get_params(params: CryptoParams = None, crypto_backend: str = None) -> CryptoParams:
        return CryptoParams('elgamal') 


class CipherValue(Value):
    def __new__(cls, contents: Optional[Collection] = None, *,
                params: CryptoParams = None, crypto_backend: str = None):
        params = Value.get_params(params, crypto_backend)
        content = [0] * params.cipher_len
        if contents:
            content[:len(contents)] = contents[:]
        ret = super(CipherValue, cls).__new__(cls, content)
        ret.params = params
        return ret

    def __len__(self) -> int:
        return self.params.cipher_payload_len


class PrivateKeyValue(Value):
    def __new__(cls, sk: Optional[Any] = None):
        return super(PrivateKeyValue, cls).__new__(cls, [sk])

    @property
    def val(self):
        return self[0]


class PublicKeyValue(Value):
    def __new__(cls, contents: Optional[Collection] = None, *,
                params: CryptoParams = None, crypto_backend: str = None):
        params = Value.get_params(params, crypto_backend)
        if contents is None:
            return super(PublicKeyValue, cls).__new__(cls, [0] * params.key_len)
        else:
            assert len(contents) == params.key_len
            return super(PublicKeyValue, cls).__new__(cls, contents)


class RandomnessValue(Value):
    def __new__(cls, contents: Optional[Collection] = None, *,
                params: CryptoParams = None, crypto_backend: str = None):
        params = Value.get_params(params, crypto_backend)
        if contents is None:
            return super(RandomnessValue, cls).__new__(cls, [0] * params.randomness_len)
        else:
            assert len(contents) == params.randomness_len
            return super(RandomnessValue, cls).__new__(cls, contents)


class AddressValue(Value):
    get_balance: Optional[Callable[['AddressValue'], int]] = None

    def __new__(cls, val: Union[str, int, bytes]):
        if isinstance(val, AddressValue):
            val = val.val
        if not isinstance(val, bytes):
            if isinstance(val, str):
                val = int(val, 16)
            val = val.to_bytes(20, byteorder='big')
        return super(AddressValue, cls).__new__(cls, [val])

    @property
    def val(self):
        return self[0]

    def transfer(self, amount):
        return

    def send(self, amount) -> bool:
        return True

    def __str__(self):
        return self.val.hex()

    @property
    def balance(self) -> int:
        return self.get_balance(self)


class KeyPair:
    def __init__(self, pk: PublicKeyValue, sk: PrivateKeyValue):
        self.pk = pk
        self.sk = sk


