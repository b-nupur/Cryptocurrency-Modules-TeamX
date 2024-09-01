from helper import (
    bits_to_target,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
)

class Block:

    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    @classmethod
    def parse(cls, s):  #parse the string and return the Block object
        # s.read(n) will read n bytes from the stream
        version = little_endian_to_int(s.read(4)) # version - 4 bytes, little endian, interpret as int
        prev_block = s.read(32)[::-1] # prev_block - 32 bytes, little endian ([::-1] to reverse)
        merkle_root = s.read(32)[::-1] # merkle_root - 32 bytes, little endian
        timestamp = little_endian_to_int(s.read(4)) # timestamp - 4 bytes, little endian, interpret as int
        bits = s.read(4) # bits - 4 bytes
        nonce = s.read(4) # nonce - 4 bytes
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    #appending all the block header info then later we'll hash it
    def serialize(self):
        #Returns the 80 byte block header
        result = int_to_little_endian(self.version, 4)
        result += self.prev_block[::-1]
        result += self.merkle_root[::-1]
        result += int_to_little_endian(self.timestamp, 4)
        result += self.bits
        result += self.nonce
        return result
    
    #hashing the block header info
    def hash(self):
        #Returns the hash256 interpreted little endian of the block
        s = self.serialize()
        h256 = hash256(s)
        return h256[::-1]
    
    #we compute the hash256 of the block header and If this number is lower than the target, we have a valid proof-of-work
    def target(self):
        #Returns the proof-of-work target based on the bits
        return bits_to_target(self.bits)

    def difficulty(self):
        #Returns the block difficulty based on the bits
        # difficulty = (target of lowest difficulty) / (self's target)
        # lowest difficulty has bits that equal 0xffff001d
        lowest = 0xffff * 256**(0x1d - 3)
        return lowest / self.target()

    def check_pow(self):
        #whether this block satisfies proof of work
        #proof-of-work can be calculated by computing the hash256 of the block header and interpreting this as a little-endian integer.
        #If this number is lower than the target, we have a valid proof-of-work. If not, the block is not valid as it doesn’t have proof-of-work.

        h256 = hash256(self.serialize())
        proof = little_endian_to_int(h256)
        return proof < self.target()


