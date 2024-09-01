import hashlib
from ecc import (
    S256Point,
    Signature,
)

# OP_CHECKSEQUENCEVERIFY
# OP_CHECKLOCKTIMEVERIFY, 

from helper import (
    hash256,
    hash160,
)

# encode the integer value into byte representation
def encode_number(value):
    if value == 0:
        return b''
    
    negative = value < 0
    abs_value = abs(value)

    result = bytearray()    # creates an empty byte array
    while abs_value:
        result.append(abs_value & 0xff)
        abs_value = abs_value >> 8

    if result[-1] & 0x80: # access the last element and check if sign bit is set
        if negative:
            result.append(0x80)
        else:
            result.append(0)

    elif negative:
        result[-1] |= 0x80

    return bytes(result) 

def decode_number(element):
    if element == b'':
        return 0
    big_endian = element[::-1]
    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7f
    else:
        negative = False
        result = big_endian[0]
    for c in big_endian[1:]:
        result <<= 8
        result += c
    if negative:
        return -result
    else:
        return result
    


def op_0(stack):
    stack.append(encode_number(0))
    return True
# end::source3[]


def op_1negate(stack):
    stack.append(encode_number(-1))
    return True


def op_1(stack):
    stack.append(encode_number(1))
    return True


def op_2(stack):
    stack.append(encode_number(2))
    return True


def op_3(stack):
    stack.append(encode_number(3))
    return True


def op_4(stack):
    stack.append(encode_number(4))
    return True


def op_5(stack):
    stack.append(encode_number(5))
    return True


def op_6(stack):
    stack.append(encode_number(6))
    return True


def op_7(stack):
    stack.append(encode_number(7))
    return True


def op_8(stack):
    stack.append(encode_number(8))
    return True


def operation_9(stack):
    stack.append(encode_number(9))
    return True


def op_10(stack):
    stack.append(encode_number(10))
    return True


def op_11(stack):
    stack.append(encode_number(11))
    return True


def op_12(stack):
    stack.append(encode_number(12))
    return True


def op_13(stack):
    stack.append(encode_number(13))
    return True


def op_14(stack):
    stack.append(encode_number(14))
    return True


def op_15(stack):
    stack.append(encode_number(15))
    return True


def op_16(stack):
    stack.append(encode_number(16))
    return True
# what is the need of these above ops??



# flow control
def op_nop(stack):
    return True


# def op_if():


def op_verify(stack):
    if len(stack) < 1:
        return False
    ele = stack.pop()
    # scipt is valid if top is non zero
    if decode_number(ele) == 0:
        return False
    else:
        True

def op_return(stack):
    return False

def op_2drop(stack):
    if len(stack) < 2:
        return False
    stack.pop()
    stack.pop()
    return True

def op_2dup(stack):
    if len(stack) < 2:
        return False
    stack.extend(stack[-2])
    return True

#---end of flow of control 

def op_dup(stack):
    if len(stack) < 1:
        return False
    stack.append(stack[-1]) # append the last element of the stack
    return True
def op_hash256(stack):
    if len(stack) < 1:
        return False
    val = stack.pop()
    stack.append(hash256(val))
    return True

def op_hash160(stack):
    if len(stack) < 1:
        return False
    val = stack.pop()
    stack.append(hash160(val))
    return True
    

def op_checksig(stack, z):
    if len(stack)<2:
        return False
    pub_key = stack.pop()
    signature = stack.pop()[:-1]
    try:
        point = S256Point.parse(pub_key)
        sig = signature.parse(signature)
    except (ValueError, SyntaxError) as e:
        return False
    if point.verify(z, sig):
        stack.append(encode_number(1))
    else:
        stack.append(encode_number(0))
    return True

def op_if(stack, items):
    if len(stack) < 1:
        return False
    # go through and re-make the items array based on the top stack element
    true_items = []
    false_items = []
    current_array = true_items
    found = False
    num_endifs_needed = 1
    while len(items) > 0:
        item = items.pop(0)
        if item in (99, 100):
            # nested if, we have to go another endif
            num_endifs_needed += 1
            current_array.append(item)
        elif num_endifs_needed == 1 and item == 103:
            current_array = false_items
        elif item == 104:
            if num_endifs_needed == 1:
                found = True
                break
            else:
                num_endifs_needed -= 1
                current_array.append(item)
        else:
            current_array.append(item)
    if not found:
        return False
    element = stack.pop()
    if decode_number(element) == 0:
        items[:0] = false_items
    else:
        items[:0] = true_items
    return True

def op_notif(stack, items):
    if len(stack) < 1:
        return False
    # go through and re-make the items array based on the top stack element
    true_items = []
    false_items = []
    current_array = true_items
    found = False
    num_endifs_needed = 1
    while len(items) > 0:
        item = items.pop(0)
        if item in (99, 100):
            # nested if, we have to go another endif
            num_endifs_needed += 1
            current_array.append(item)
        elif num_endifs_needed == 1 and item == 103:
            current_array = false_items
        elif item == 104:
            if num_endifs_needed == 1:
                found = True
                break
            else:
                num_endifs_needed -= 1
                current_array.append(item)
        else:
            current_array.append(item)
    if not found:
        return False
    element = stack.pop()
    if decode_number(element) == 0:
        items[:0] = true_items
    else:
        items[:0] = false_items
    return True

def op_toaltstack(stack, altstack):
    if len(stack) < 1:
        return False
    altstack.append(stack.pop())
    return True


def op_fromaltstack(stack, altstack):
    if len(altstack) < 1:
        return False
    stack.append(altstack.pop())
    return True

def op_equal(stack):
    if len(stack) < 2:
        return False
    element1 = stack.pop()
    element2 = stack.pop()
    if element1 == element2:
        stack.append(encode_number(1))
    else:
        stack.append(encode_number(0))
    return True


def op_equalverify(stack):
    return op_equal(stack) and op_verify(stack)



def op_negate(stack):
    if len(stack) < 1:
        return False
    element = decode_number(stack.pop())
    stack.append(encode_number(-element))
    return True



def op_abs(stack):
    if len(stack) < 1:
        return False
    element = decode_number(stack.pop())
    if element < 0:
        stack.append(encode_number(-element))
    else:
        stack.append(encode_number(element))
    return True


def op_not(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_number(element) == 0:
        stack.append(encode_number(1))
    else:
        stack.append(encode_number(0))
    return True

def op_add(stack):
    if len(stack) < 2:
        return False
    element1 = decode_number(stack.pop())
    element2 = decode_number(stack.pop())
    stack.append(encode_number(element1 + element2))
    return True


def op_sub(stack):
    if len(stack) < 2:
        return False
    element1 = decode_number(stack.pop())
    element2 = decode_number(stack.pop())
    stack.append(encode_number(element2 - element1))
    return True


def op_ripemd160(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.new('ripemd160', element).digest())
    return True

def op_sha1(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha1(element).digest())
    return True


def op_sha256(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha256(element).digest())
    return True

def op_checksigverify(stack, z):
    return op_checksig(stack, z) and op_verify(stack)



 
OP_CODE_FUNCTIONS = {
0: op_0, 
79: op_1negate, 
81: op_1, 
82: op_2, 
83: op_3, 
84: op_4, 
85: op_5, 
86: op_6, 
87: op_7, 
88: op_8, 
90: op_10, 
91: op_11, 
92: op_12, 
93: op_13, 
94: op_14, 
95: op_15, 
96: op_16,
97: op_nop, 
99: op_if, 
100: op_notif, 
105: op_verify, 
107: op_toaltstack, 
108: op_fromaltstack, 
118: op_dup, 
135: op_equal, 
136: op_equalverify, 
143: op_negate, 
144: op_abs, 
145: op_not, 
147: op_add, 
148: op_sub, 
166: op_ripemd160, 
167: op_sha1, 
168: op_sha256, 
169: op_hash160, 
170: op_hash256, 
172: op_checksig, 
173: op_checksigverify, 



}
OPCODE_NAMES = {
   0: 'OP_0',
    76: 'OP_PUSHDATA1',
    77: 'OP_PUSHDATA2',
    78: 'OP_PUSHDATA4',
    79: 'OP_1NEGATE',
    81: 'OP_1',
    82: 'OP_2',
    83: 'OP_3',
    84: 'OP_4',
    85: 'OP_5',
    86: 'OP_6',
    87: 'OP_7',
    88: 'OP_8',
    89: 'OP_9',
    90: 'OP_10',
    91: 'OP_11',
    92: 'OP_12',
    93: 'OP_13',
    94: 'OP_14',
    95: 'OP_15',
    96: 'OP_16',
    97: 'OP_NOP',
    99: 'OP_IF',
    100: 'OP_NOTIF',
    105: 'OP_VERIFY',
    107: 'OP_TOALTSTACK',
    108: 'OP_FROMALTSTACK',
    118: 'OP_DUP',
    135: 'OP_EQUAL',
    136: 'OP_EQUALVERIFY',
    143: 'OP_NEGATE',
    144: 'OP_ABS',
    145: 'OP_NOT',
    147: 'OP_ADD',
    148: 'OP_SUB',
    166: 'OP_RIPEMD160',
    167: 'OP_SHA1',
    168: 'OP_SHA256',
    169: 'OP_HASH160',
    170: 'OP_HASH256',
    172: 'OP_CHECKSIG',
    173: 'OP_CHECKSIGVERIFY',

}
