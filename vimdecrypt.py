import sys
from argparse import ArgumentParser

crc32_table = []

def init_crc32_table():
    for v in range(256):
        for _ in range(8):
            v = (v >> 1) ^ ((v & 1) * 0xedb88320)
        crc32_table.append(v)
init_crc32_table()

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
        update_keys(keys, temp)
        s += i2b(temp)
    return s

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
    plaintext = decrypt(ciphertext, args.password.encode('utf-8'))
    print(plaintext)

if __name__ == "__main__":
    main()
