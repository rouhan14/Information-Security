import sys
from myhash import SHA1  # Import SHA1 from your hashing module

class HMAC:
    blocksize = 64

    def __init__(self, key, digestmod=None):
        if digestmod is None:
            digestmod = SHA1

        self.digest_cons = digestmod()
        self.inner = digestmod()  # Initialize as new hash instances
        self.outer = digestmod()  # Initialize as new hash instances

        self.digest_size = getattr(self.inner, 'digest_size', None)

        if len(key) > self.blocksize:
            key = self.digest_cons(key).digest()
        key = key.ljust(self.blocksize, b'\x00')

        # Dynamic key transformation for ipad opad
        ipad, opad = self._transform_key(key)

        self.inner_pad = bytes(ipad)
        self.outer_pad = bytes(opad)

        # Precompute the outer hash of the inner pad
        self.outer.update(self.inner_pad)

    def _transform_key(self, key):
        substitution_value = 0xAB

        substituted_key = [substitution_value ^ byte for byte in key]

        permuted_key = substituted_key[::-1]

        key_length = len(permuted_key)
        ipad = permuted_key[:key_length // 2]
        opad = permuted_key[key_length // 2:]

        return ipad, opad

    def update(self, msg):
        self.inner.update(msg)

    def finalize(self):
        # Compute the inner hash
        inner_hash = self.inner.digest()

        # Compute the outer hash with the outer pad
        self.outer.update(inner_hash)
        return self.outer.digest()

    def hexdigest(self):
        return self.finalize().hex()

    def digest(self):
        return self.finalize().digest()

def new(key, digestmod=None):
    return HMAC(key, digestmod)

def usage():
    print('Usage: python HMAC.py <file> [<file> ...]')
    sys.exit()

def main():
    if len(sys.argv) < 2:
        usage()

    for filename in sys.argv[1:]:
        try:
            with open(filename, 'rb') as f:
                content = f.read()

        except:
            print('ERROR: Input file "{0}" cannot be read.'.format(filename))

        else:
            h = new(b'MySecretKey123')  # Example key, replace with your key
            h.update(content)
            hmac_hash = h.hexdigest()
            print("HMAC Hash for {0}: {1}".format(filename, hmac_hash))

if __name__ == '__main__':
    main()
#type: ignore
