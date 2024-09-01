from io import BytesIO



from helper import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from operation import (
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)


 #  creates a logger object specific to the module where this line of code is located. This logger can then be used throughout the module to 
#log messages, warnings, errors, etc., providing a convenient way to manage and track the flow of information during program execution.
#duplicates top element of the stack 
class script:

    # command is either a an opcode or element to be pushed on to the stack
    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

        #string representation of the object
    
    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)
    
     
    
    @classmethod
    def parse(cls, s):
        length =read_varint(s) # to get the size of input to be read in the field
        cmds = []
        count = 0
        while count < length:
            current_byte = s.read(1)[0]
            count = count + 1
            if current_byte >= 1 and current_byte <= 75:  
                n = current_byte
                cmds.append(s.read(n))
                count += n
            elif current_byte == 76: 
                data_length = little_endian_to_int(s.read(1)) # next byte = number of bytes to read
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:  
                data_length = little_endian_to_int(s.read(2))# next 2 byte = number of bytes to read
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:   # operation present 
                op_code = current_byte
                cmds.append(op_code)

        if count != length: 
            raise SyntaxError('parsing script failed')
        return cls(cmds)
    
    
    def raw_serialize(self):
        result = b''
        for cmd in self.cmds:
            if type(cmd) == int: 
                result += int_to_little_endian(cmd, 1)
            else:
                length = len(cmd)
                if length < 75:
                    result += int_to_little_endian(length, 1)
                elif length > 75 and length < 256:  
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length >= 256 and length <= 520:
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else: 
                    raise ValueError('too long an cmd')
                result += cmd
        return result
    


    
    def serialize(self):
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result  

    # combines the scripts to evalaute them together
    def __add__(self, other):
        return script(self.cmds + other.cmds) #returns the combined script object
    

    def evaluate(self, z):
        cmds = self.cmds[:]  
        stack = []
        altstack = []
        while len(cmds) > 0:  
            cmd = cmds.pop(0)
            if type(cmd) == int:
                operation = OP_CODE_FUNCTIONS[cmd]  
                if cmd in (99, 100):  
                    if not operation(stack, cmds): 
                        return False
                elif cmd in (107, 108):  
                    if not operation(stack, altstack):
                        return False
                elif cmd in (172, 173, 174, 175):  
                    if not operation(stack, z):
                        return False
                else:
                    if not operation(stack):
                        return False
            else:
                stack.append(cmd)  
        if len(stack) == 0:
            return False  
        if stack.pop() == b'':
            return False  
        return True  