import numpy as np

np.set_printoptions(formatter={'int': hex})


class AES128:

    def __init__(self):
        # Block size in 32bit words (4 * 32 = 128b)
        self.Nb = 4
        # Key length in 32bit words (4 * 32 = 128b)
        self.Nk = 4
        # Number of Rounds
        self.Nr = 10

        # Substitution box
        self.sbox = [
            [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
            [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
            [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
            [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
            [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
            [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
            [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
            [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
            [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
            [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
            [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
            [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
            [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
            [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
            [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
            [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
        ]

        # Reverse Substitution box
        self.rsbox = [
            [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
            [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
            [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
            [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
            [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
            [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
            [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
            [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
            [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
            [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
            [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
            [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
            [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
            [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
            [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
            [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
        ]

        # Rcon
        self.rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    def parse_key(self, key_hex):
        """
        Checks length of key and transforms key into array of 4 byte arrays
        :param key_hex: Text key in hexadecimal format
        :return: initial byte key
        """

        # Attempt to translate hex string into bytes
        try:
            binary = bytearray.fromhex(key_hex)
        except ValueError:
            binary = []

        # Check if length of translated array is 16
        if len(binary) is not 16:
            return None

        # TODO: vyřešit jak udělat efektivnější split

        # Create empty initial key
        initial_key = list()
        # We create 4 blocks of 4 byte (16bytes = 128bit)
        for a in range(0, 4):
            low = 4 * a
            high = low + 4
            initial_key.append(binary[low:high])

        return initial_key

    def rot_word(self, word):
        """
        Takes input of 1 block of 4 bytes (32bit)
        and transforms it such as array
        [a0,a1,a2,a3] become [a1,a2,a3,a0]
        (where aX are bytes cyclically rotated)

        :param word: block of 4 bytes
        :return: cyclically rotated block of 4 bytes
        """
        return word[1:] + word[0:1]

    def sub_word(self, word):
        """
        Takes input of 1 block of 4 bytes (32bit)
        for every byte function applies sbox transformation
        such as when byte in hex is "53", value from row "5" and column "3"
        is used

        :param word: 1 block of 4 bytes (32bit)
        :return: sbox transformed block of 4 bytes
        """
        for i in range(0, 4):
            # Take one byte from block
            byte = word[i]
            # Format it so it creates hex string without 0x
            hex_string = "{0:0{1}x}".format(byte, 2)
            # Use first digit of such string as row
            row = int(hex_string[0], 16)
            # Use second digit of such string as column
            column = int(hex_string[1], 16)
            # Apply transformation to byte
            word[i] = self.sbox[row][column]

        # Return transformed block of bytes
        return word

    def xor_rcon(self, word, rcon):
        """
        Takes 4 byte block world and one byte block
        rcon. For every byte in block world performs
        XOR operation

        :param word:
        :param rcon:
        :return:
        """
        word[0] = word[0] ^ rcon
        return word

    def xor_words(self, word1, word2):
        """
        Performs XOR between two blocks
        of 4 bytes. For every byte in block
        perform XOR

        :param word1:
        :param word2:
        :return:
        """
        result = bytearray()
        for i in range(0, 4):
            byte = word1[i] ^ word2[i]
            result.append(byte)
        return result

    def expand_key(self, key_binary):
        """
        Expands AES128 Key
        Takes array of 4 blocks of 4 bytes as input key
        :param key_binary: 4 blocks of 4 bytes (16 bytes = 128bit)
        :return:
        """
        i = self.Nk

        while i < self.Nb * (self.Nr + 1):
            # Get previous block
            temp = key_binary[i - 1]
            if i % self.Nk == 0:
                # Rotate block
                rotated = self.rot_word(temp)
                # Apply substitution
                subbed = self.sub_word(rotated)
                # Get rcon value
                rcon = self.rcon[i // self.Nk]
                # XOR
                temp = self.xor_rcon(subbed, rcon)
            # XOR old block with new one
            xor = self.xor_words(key_binary[i - self.Nk], temp)
            # Add to expanded key
            key_binary.append(xor)
            # Move to next iteration
            i = i + 1

        return key_binary

    def parse_data_16(self, data):
        """
        Takes block of 16 bytes of data [a1, a2, ..., a16]
        and transforms it to list of 4 blocks of 4 bytes
        [[a1,a2,a3,a4], [a5, ..., ...], ..., [..., a16]]
        :param data: 16 byte data
        :return:
        """
        # Create empty result data
        parsed_data = list()
        # We create 4 blocks of 4 byte (16bytes = 128bit)
        for a in range(0, 4):
            low = 4 * a
            high = low + 4
            parsed_data.append(data[low:high])
        return parsed_data

    def add_round_key(self, data, key):
        """
        Performs XOR between every byte of input data
        and next 16 bytes of expanded key
        :param data: block of 16 byte of input data
        :param key: block of 16 byte of key
        :return: transformed data
        """
        result = list()
        for x in range(4):
            w1 = data[x]
            w2 = key[x]
            r = self.xor_words(w1, w2)
            result.append(r)
        return np.array(result)
    def sub_bytes_16B(self, data):
        """
        Takes input of 4 blocks of 4 bytes (16 Byte)
        and for every block it performs sub_bytes operation
        and returns result

        :param data: 16 bytes (4 blocks of 4 bytes)
        :return: result of sub_bytes
        """
        result = list()
        for i in range(4):
            transform = self.sub_word(data[i])
            result.append(transform)
        return np.array(result)

    def print_16B(self, data16B):
        """
        Prints 4 blocks of 4 bytes (16B)

        :param data16B:
        :return:
        """
        for block in data16B:
            for byte in block:
                print(hex(byte), end=" ")
            print()

    def shift_rows(self, data):
        """
        Takes data and shifts its rows.
        shift first row by 0
        shift second row by 1 to left
        shift third row by 2 to left
        shift fourth row by 3 to left
        :param data:
        :return:
        """
        # Create empty result storage
        result = list()
        # Get input data and transpose them to format we need
        matrix = np.array(data).reshape(4, 4).transpose()
        # For every block of 4 bytes oi
        for i in range(0, 4):
            r = matrix[i]
            r = np.roll(r, -1 * i)
            result.append(r)
        # Transform data back to keep consistent format
        result = np.array(result).reshape(4, 4).transpose()
        return result

    def galois(self, a, b):
        """
        I dont really understand what this does.
        It is supposed to do Galois multiplication on GF(2^8)
        but god knows what this mean

        :param a: byte a
        :param b: byte b
        :return: result?
        """
        overflow = 0x100
        mod = 0x11B

        result = 0
        while b > 0:
            if b & 1:
                result ^= a
            b >>= 1
            a <<= 1
            if a & overflow:
                a ^= mod
        return result

    def matrix_mul(self, matrix, vector):
        """
        Calculates  4*4 matrix *  1*4 vector
        in galois field

        :param matrix: 4 * 4 matrix
        :param vector: 1 * 4 vector
        :return: 1 * 4 vector
        """
        result = list()

        for row in range(4):
            res = 0
            for cell in range(4):
                    res = res ^ self.galois(matrix[row][cell], vector[cell])
            result.append(res)
        return result

    def mix_colums(self, data):
        data = np.array(data).reshape(4, 4)
        matrix = np.array([[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]).reshape(4, 4)

        res = list()
        for column in range(0,4):
            calc = self.matrix_mul(matrix, data[column])
            res.append(calc)

        return np.array(res).reshape(4,4)

    def inv_shift_rows(self, data):
        """
        Takes data and shifts its rows.
        shift first row by 0
        shift second row by 1 to right
        shift third row by 2 to right
        shift fourth row by 3 to right
        :param data:
        :return:
        """
        # Create empty result storage
        result = list()
        # Get input data and transpose them to format we need
        matrix = np.array(data).reshape(4, 4).transpose()
        # For every block of 4 bytes oi
        for i in range(0, 4):
            r = matrix[i]
            r = np.roll(r, i)
            result.append(r)
        # Transform data back to keep consistent format
        result = np.array(result).reshape(4, 4).transpose()
        return result

    def inv_sub_word(self, word):
        """
        Takes input of 1 block of 4 bytes (32bit)
        for every byte function applies sbox transformation
        such as when byte in hex is "53", value from row "5" and column "3"
        is used

        :param word: 1 block of 4 bytes (32bit)
        :return: sbox transformed block of 4 bytes
        """
        for i in range(0, 4):
            # Take one byte from block
            byte = word[i]
            # Format it so it creates hex string without 0x
            hex_string = "{0:0{1}x}".format(byte, 2)
            # Use first digit of such string as row
            row = int(hex_string[0], 16)
            # Use second digit of such string as column
            column = int(hex_string[1], 16)
            # Apply transformation to byte
            word[i] = self.rsbox[row][column]

        # Return transformed block of bytes
        return word

    def inv_sub_bytes_16B(self, data):
        """
        Takes input of 4 blocks of 4 bytes (16 Byte)
        and for every block it performs sub_bytes operation
        and returns result

        :param data: 16 bytes (4 blocks of 4 bytes)
        :return: result of sub_bytes
        """
        result = list()
        for i in range(4):
            transform = self.inv_sub_word(data[i])
            result.append(transform)
        return np.array(result)

    def inv_mix_colums(self, data):
        data = np.array(data).reshape(4, 4)
        matrix = np.array([[0x0e, 0x0b, 0x0d, 0x09], [0x09, 0x0e, 0x0b, 0x0d], [0x0d, 0x09, 0x0e, 0x0b], [0x0b, 0x0d, 0x09, 0x0e]]).reshape(4, 4)

        res = list()
        for column in range(0,4):
            calc = self.matrix_mul(matrix, data[column])
            res.append(calc)

        return np.array(res).reshape(4,4)

    def cipher(self, expanded_key, data):
        """
        Takes block of 16 bytes of data and expanded key and uses
        them to cipher it

        :param expanded_key: array of 43 blocks of 4 bytes
        :param data: 16 bytes of input
        :return: ciphered 16 bytes
        """
        # Takes first 16 bytes of expanded key ...
        key_first = expanded_key[0:self.Nb]
        # ... and peform XOR operation with initial data
        data = self.add_round_key(data, key_first)

        # Performs algorithm rounds
        for current_round in range(1, self.Nr):
            # Performs sub_bytes for 16 byte data
            data = self.sub_bytes_16B(data)
            # Shift rows in last three rows of data
            data = self.shift_rows(data)
            # Mix columns
            data = self.mix_colums(data)
            # Add round key
            key = expanded_key[current_round*self.Nb:current_round*self.Nb+self.Nb]
            data = self.add_round_key(data, key)

        # Final sub bytes
        data = self.sub_bytes_16B(data)
        # Final Shift rows
        data = self.shift_rows(data)
        # Final add round key
        key_final = expanded_key[-4:]
        data = self.add_round_key(data, key_final)

        # Return ciphered block
        return data

    def decipher(self, expanded_key, data):
        """
        Takes block of 16 bytes of data and expanded key and uses them
        to decipher data

        :param expanded_key: array of 43 blocks of 4 bytes
        :param data: 16 bytes of input
        :return: 16 bytes deciphered
        """

        # Takes last 16 bytes of expanded key ...
        key_last = expanded_key[-self.Nb:]
        # Uses them to perform XOR operation with initial data
        data = self.add_round_key(data, key_last)

        # Performs algorithm rounds in reversed order
        for current_round in range(self.Nr-1, 0, -1):
            # Perform inverse operation to shift rows
            data = self.inv_shift_rows(data)
            # Perform inverse operation to sub bytes
            data = self.inv_sub_bytes_16B(data)
            # Add round key in by current round
            key = expanded_key[current_round*self.Nb:current_round*self.Nb+self.Nb]
            data = self.add_round_key(data, key)
            # Inverse to mix columns
            data = self.inv_mix_colums(data)

        # Perform final reverse shift rows
        data = self.inv_shift_rows(data)
        # Perform final reverse sub bytes
        data = self.inv_sub_bytes_16B(data)
        # Add first round key
        key_first = expanded_key[0:self.Nb]
        data = self.add_round_key(data, key_first)

        # return result
        return data


def test():
    a = AES128()
    key = "6a6f73656676656e6361736c6164656b"
    key_binary = a.parse_key(key)
    key_expanded = a.expand_key(key_binary)

    data_hex = "4142434445464748494a4b4c4d4e4f50"
    data = a.parse_data_16(bytearray.fromhex(data_hex))
    ciphered = a.cipher(key_expanded, data)

    decipher_test = a.decipher(key_expanded, ciphered)

    print(data)
    print(decipher_test)


if __name__ == '__main__':
    test()
