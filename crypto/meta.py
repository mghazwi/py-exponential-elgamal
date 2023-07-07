cryptoparams = {

    'elgamal': {
        'key_bits': 2*254,                  # two BabyJubJub coordinates (fit into 254 bits each)
        'cipher_payload_bytes': 128,        # four BabyJubJub coordinates
        'cipher_chunk_size': 32,            # one BabyJubJub coordinate
        'symmetric': False,
        'rnd_bytes': 32,                    # one element from the BabyJubJub scalar field
        'rnd_chunk_size': 32,
        'enc_signed_as_unsigned': False,
    }
}
