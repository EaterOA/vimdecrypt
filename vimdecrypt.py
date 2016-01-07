from argparse import ArgumentParser

crc32_table = [0]*256
invcrc32_table = [0]*256

def init_crc32_tables():
    for i in range(256):
        v = i
        for _ in range(8):
            v = (v >> 1) ^ ((v & 1) * 0xedb88320)
        v &= 0xffffffff
        crc32_table[i] = v
        invcrc32_table[v >> 24] = (v << 8) & 0xffffffff ^ i
init_crc32_tables()

def i2b(i):
    return i.to_bytes(1, byteorder='little')

def crc32(key, char):
    return crc32_table[(key ^ char) & 0xff] ^ (key >> 8)

def decrypt_byte(keys):
    # 16 MSB and 2 LSB do not affect temp
    temp = (keys[2] & 0xfffc) | 3
    # return key3
    return ((temp * (temp ^ 1)) >> 8) & 0xff

def update_keys(keys, char):
    keys[0] = crc32(keys[0], char)
    keys[1] = keys[1] + (keys[0] & 0xff)
    keys[1] = (keys[1] * 134775813 + 1) & 0xffffffff
    keys[2] = crc32(keys[2], keys[1] >> 24)

def decrypt(cipher, password):
    keys = [305419896,
            591751049,
            878082192]
    for c in password:
        update_keys(keys, c)
    s = b''
    for c in cipher:
        temp = c ^ decrypt_byte(keys)
        #print(hex(keys[0]), hex(keys[1]), hex(keys[2]))
        update_keys(keys, temp)
        s += i2b(temp)
    return s

def find_init_key2list(c, p):
    # PLACEHOLDER FOR TESTING
    return [0xec29eca7]

def reduce_init_key2list(ciphertext, plaintext, key2list):
    # PLACEHOLDER FOR TESTING
    return key2list

def find_full_key2list(init_key2list):
    return []

def find_msb_key1list(full_key2list):
    return []

def find_full_key1list(msb_key1list):
    return []

def find_key0(full_key1list):
    return None

def find_starting_keys(key0n, key1n, key2n):
    return None, None, None

def parse_args():
    parser = ArgumentParser()
    parser.add_argument(
        "file", help="file to decrypt")
    parser.add_argument(
        "password", help="password to decrypt with")
    return parser.parse_args()

def main():
    args = parse_args()

    with open(args.file, 'rb') as f:
        ciphertext = f.read()[12:]

    plaintext = 'watwatwatwatwat\n'
    init_key2list = find_init_key2list(ciphertext[1], plaintext[-1])
    init_key2list = reduce_init_key2list(ciphertext, plaintext, init_key2list)

    for init_key2 in init_key2list:
        full_key2list = find_full_key2list(init_key2list)
        msb_key1list = find_msb_key1list(full_key2list)
        full_key1list = find_full_key1list(full_key2list)
        key0n = find_key0(full_key1list)
        key1n = full_key1list[-1]
        key2n = full_key2list[-1]
        key0, key1, key2 = find_starting_keys(key0n, key1n, key2n)

    #plaintext = decrypt(ciphertext, args.password.encode('utf-8'))
    #print(plaintext)

if __name__ == "__main__":
    main()
