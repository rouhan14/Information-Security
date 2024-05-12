class SHA1:
    def __init__(self):
        self.__H = [
            0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
        ]

    def __ROTL(self, n, x, w=32):
        return ((x << n) | (x >> w - n)) & 0xFFFFFFFF

    def __padding(self, stream):
        l = len(stream)
        hl = [(l*8 >> i) & 0xFF for i in range(120, -1, -8)]  # Change length representation from 64 bits to 128 bits
        l0 = (120 - l) % 64
        if not l0:
            l0 = 64

        stream += b'\x80'
        stream += b'\x00' * (l0 - 1)
        stream += bytes(hl)
        return stream

    def __prepare(self, stream):
        M = []
        n_blocks = len(stream) // 64
        for i in range(n_blocks):
            m = []
            for j in range(16):
                n = 0
                for k in range(4):
                    n <<= 8
                    n += stream[i*64 + j*4 + k]
                m.append(n)
            M.append(m[:])
        return M

    def __process_block(self, block):
        for i in range(16, 80):
            block.append(self.__ROTL(1, (block[i-3] ^ block[i-8] ^ block[i-14] ^ block[i-16])))

        a, b, c, d, e = self.__H[:]

        for i in range(80):
            if i < 20:
                f = (b & c) | ((~b) & d)
                K = 0x5A827999
            elif 20 <= i < 40:
                f = b ^ c ^ d
                K = 0x6ED9EBA1
            elif 40 <= i < 60:
                f = (b & c) | (b & d) | (c & d)
                K = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                K = 0xCA62C1D6

            a, b, c, d, e = (
                (self.__ROTL(5, a) + f + e + K + block[i]) & 0xFFFFFFFF,
                a,
                self.__ROTL(30, b),
                c,
                d
            )

        # Modify the processing of internal state
        self.__H[0] = (self.__H[0] * 33 + a) & 0xFFFFFFFF
        self.__H[1] = (self.__H[1] * 33 + b) & 0xFFFFFFFF
        self.__H[2] = (self.__H[2] * 33 + c) & 0xFFFFFFFF
        self.__H[3] = (self.__H[3] * 33 + d) & 0xFFFFFFFF
        self.__H[4] = (self.__H[4] * 33 + e) & 0xFFFFFFFF

    def update(self, stream):
        stream = self.__padding(stream)
        stream = self.__prepare(stream)

        for block in stream:
            self.__process_block(block)

    def digest(self):
        return b''.join(x.to_bytes(4, 'big') for x in self.__H)

    def hexdigest(self):
        return ''.join(format(x, '08x') for x in self.__H)

def usage():
    print('Usage: python hash_file.py <file> [<file> ...]')

def main():
    import sys

    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    for filename in sys.argv[1:]:
        try:
            with open(filename, 'rb') as f:
                content = f.read()

            h = SHA1()
            h.update(content)
            hex_sha = h.hexdigest()
            print("SHA1 Hash for {0}: {1}".format(filename, hex_sha))

        except Exception as e:
            print(f"Error hashing file {filename}: {e}")

if __name__ == '__main__':
    main()
