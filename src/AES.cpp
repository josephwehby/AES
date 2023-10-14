#include "AES.hpp" 

AES::AES(int mode) {
    if (mode == 128) {
        this->mode = mode;
        this->nk = 4;
        this->nr = 10;
    } else if (mode == 192) {
        this->mode = mode;
        this->nk = 6;
        this->nr = 12;
    } else {
        this->mode = mode;
        this->nk = 8;
        this->nr = 14;
    }
}

void AES::Encrypt(vector <unsigned char> text, vector <unsigned char> key) {
    int i, num_states, state_index, key_index;
    vector<vector<unsigned char>> state;
    vector<vector<unsigned char>> key_state;
    vector<vector<unsigned char>> expanded_keys;
    
    expanded_keys = KeyExpansion(key);
    
    num_states = text.size() / 16;
    state_index = 0;
    key_index = 0;

    state.resize(4);
    for (i = 0; i < (int)state.size(); i++) state[i].resize(4);

    key_state.resize(4);
    for (i = 0; i < (int)key_state.size(); i++) key_state[i].resize(4);

    for (i = 0; i < num_states; i++) {
        // copy 16 bytes into state array
        buildState(state, state_index, text);
        buildKeyState(key_state, key_index, expanded_keys);
        addRoundKey(state, key_state);
        
        for (int round = 1; round < nr; round++) {

            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            buildKeyState(key_state, key_index, expanded_keys);
            addRoundKey(state, key_state);
        }
        subBytes(state);
        shiftRows(state);
        buildKeyState(key_state, key_index, expanded_keys);
        addRoundKey(state, key_state);
        key_index = 0;
        

    }

    print(state);    
}

void AES::Decrypt(vector <unsigned char> text, vector <unsigned char> key) {
    int i, num_states, state_index, key_index;
    vector<vector<unsigned char>> state;
    vector<vector<unsigned char>> key_state;
    vector<vector<unsigned char>> expanded_keys;
    
    expanded_keys = KeyExpansion(key);
    num_states = text.size() / 16;
    state_index = 0;
    key_index = expanded_keys.size()-4;
    
    state.resize(4);
    for (i = 0; i < (int)state.size(); i++) state[i].resize(4);

    key_state.resize(4);
    for (i = 0; i < (int)key_state.size(); i++) key_state[i].resize(4);

    for (i = 0; i < num_states; i++) {
        // copy 16 bytes into state array
        buildState(state, state_index, text);
        buildKeyState(key_state, key_index, expanded_keys);
        key_index -= 8;
        addRoundKey(state, key_state);

        for (int round = 1; round < nr; round++) {
            invShiftRows(state);
            invSubBytes(state);
            buildKeyState(key_state, key_index, expanded_keys);
            key_index = (key_index == 4) ? key_index-4 : key_index-8;
            addRoundKey(state, key_state);
            invMixColumns(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        buildKeyState(key_state, key_index, expanded_keys);
        addRoundKey(state, key_state);
        key_index = expanded_keys.size()-4;
  
    }
    print(state);
}


unsigned char AES::xtimes(unsigned char b) {
    // shifting a char will remove last bit so store the last bit in seperate variable
    char one = 1 & (b >> 7);
    unsigned char result = b << 1;
    
    if (one) result = result ^ 0x11b;

    return result;
}

unsigned char AES::ffMultiply(unsigned char a, unsigned char b) {
    unsigned char sum = 0;
    
    for (int i = 0; i < 8; i++) {
        if (a & (1 << i)) sum = sum ^ b;
        b = xtimes(b);
    }

    return sum;
}

unsigned char AES::ffAdd(unsigned char a, unsigned char b) {
    return (a ^ b);
}

vector<vector<unsigned char>> AES::KeyExpansion(vector <unsigned char> key) {
    int i, j;
    int current_letter = 0;
    vector<vector<unsigned char>> expanded;

    expanded.resize(nb*(nr+1));
    for (i = 0; i < (int)expanded.size(); i++) expanded[i].resize(nb);
    
    // convert key into 4 words of 4 bytes each
    for (i = 0; i < nk; i++) {
        for (j = 0; j < 4; j++) {
            expanded[i][j] = key[current_letter];
            current_letter++;
        }
    }

    // expand key
    for (i = nk; i < nb*(nr+1); i++) {
        
        auto temp_key = expanded[i-1];

        if (i%nk == 0) {
            temp_key = RotWord(temp_key);
            temp_key = SubWord(temp_key);
            unsigned int rcon = Rcon[i / nk];

            temp_key[0] = temp_key[0] ^ (unsigned char)((rcon >> 24) & 0xFFFF);
            temp_key[1] = temp_key[1] ^ (unsigned char)((rcon >> 16) & 0xFFFF);
            temp_key[2] = temp_key[2] ^ (unsigned char)((rcon >> 8) & 0xFFFF);
            temp_key[3] = temp_key[3] ^ (unsigned char)((rcon >> 0) & 0xFFFF);
        } else if (nk > 6 && i%nk == 4) {
            temp_key = SubWord(temp_key);
        } else {
            // do nothing
        }

        expanded[i][0] = expanded[i-nk][0] ^ temp_key[0];
        expanded[i][1] = expanded[i-nk][1] ^ temp_key[1];
        expanded[i][2] = expanded[i-nk][2] ^ temp_key[2];
        expanded[i][3] = expanded[i-nk][3] ^ temp_key[3];
    }   

    return expanded;
}

vector <unsigned char> AES::SubWord(vector<unsigned char> word) {
    for (int i = 0; i < 4; i++) {
        int col = word[i] & 0x0F;
        int row = word[i] >> 4;

        word[i] = Sbox[row][col];
    }

    return word;
}

vector <unsigned char> AES::RotWord(vector <unsigned char> word) {
    unsigned char temp = word[0];

    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;

    return word;
}

void AES::subBytes(vector<vector<unsigned char>>& state) {
    unsigned int row, col;
    int r, c;
    
    for (row = 0; row < state.size(); row++) {
        for (col = 0; col < state[row].size(); col++) {
            c = state[row][col] & 0x0F;
            r = state[row][col] >> 4;
            state[row][col] = Sbox[r][c];
        }
    }
}

void AES::shiftRows(vector<vector<unsigned char>>& state) {
    int row;

    for (row = 1; row < (int)state.size(); row++) {
        auto temp = state[row];
        if (row == 1) {
            temp.erase(temp.begin());
            temp.push_back(state[row][0]);
        } else if (row == 2) {
            temp.erase(temp.begin(), temp.begin()+2);
            temp.push_back(state[row][0]);
            temp.push_back(state[row][1]);
        } else {
            temp.pop_back();
            temp.insert(temp.begin(), state[row][state[row].size()-1]);
        }

        state[row] = temp;
    }
}

void AES::mixColumns(vector<vector<unsigned char>>& state) {
    int col;

    auto temp = state;
    for (col = 0; col < (int)state.size(); col++) {
        state[0][col] = ffMultiply(temp[0][col], 0x02) ^ ffMultiply(temp[1][col], 0x03) ^ temp[2][col] ^ temp[3][col];
        state[1][col] = temp[0][col] ^ ffMultiply(temp[1][col], 0x02) ^ ffMultiply(temp[2][col], 0x03) ^ temp[3][col];
        state[2][col] = temp[0][col] ^ temp[1][col] ^ ffMultiply(temp[2][col], 0x02) ^ ffMultiply(temp[3][col], 0x03);
        state[3][col] = ffMultiply(temp[0][col], 0x03) ^ temp[1][col] ^ temp[2][col] ^ ffMultiply(temp[3][col], 0x02);
    }

}

void AES::invSubBytes(vector<vector<unsigned char>>& state) {
    unsigned int row, col;
    int r, c;
    
    for (row = 0; row < state.size(); row++) {
        for (col = 0; col < state[row].size(); col++) {
            c = state[row][col] & 0x0F;
            r = state[row][col] >> 4;
            state[row][col] = InvSbox[r][c];
        }
    }
}
void AES::invShiftRows(vector<vector<unsigned char>>& state) {
    int row;

    for (row = 1; row < nb; row++) {
        auto temp = state[row];
        if (row == 1) {
            temp.pop_back();
            temp.insert(temp.begin(), state[row][3]);
        } else if (row == 2) {
            temp.erase(temp.begin(), temp.begin() + 2);
            temp.push_back(state[row][0]);
            temp.push_back(state[row][1]);
        } else {
            temp.erase(temp.begin(), temp.begin() + 1);
            temp.push_back(state[row][0]);
        }
        state[row] = temp;
    }
}

void AES::invMixColumns(vector<vector<unsigned char>>& state) {
    int col;

    auto temp = state;
    for (col = 0; col < (int)state.size(); col++) {
        state[0][col] = ffMultiply(temp[0][col], 0x0e) ^ ffMultiply(temp[1][col], 0x0b) ^ ffMultiply(temp[2][col], 0x0d) ^ ffMultiply(temp[3][col], 0x09);
        state[1][col] = ffMultiply(temp[0][col], 0x09) ^ ffMultiply(temp[1][col], 0x0e) ^ ffMultiply(temp[2][col], 0x0b) ^ ffMultiply(temp[3][col], 0x0d);
        state[2][col] = ffMultiply(temp[0][col], 0x0d) ^ ffMultiply(temp[1][col], 0x09) ^ ffMultiply(temp[2][col], 0x0e) ^ ffMultiply(temp[3][col], 0x0b);
        state[3][col] = ffMultiply(temp[0][col], 0x0b) ^ ffMultiply(temp[1][col], 0x0d) ^ ffMultiply(temp[2][col], 0x09) ^ ffMultiply(temp[3][col], 0x0e);
    }
}

void AES::print(vector<vector<unsigned char>>& state) const {
    int row,col;
    for (col = 0; col < (int)state.size(); col++) {
        for (row = 0; row < (int)state[col].size(); row++) {
            cout << setfill('0') << setw(2) << hex << (0xFF & state[row][col]);
        }
    }
    cout << endl;
}

void AES::addRoundKey(vector<vector<unsigned char>>& state, vector<vector<unsigned char>>& key_state) {
    for (int row = 0; row < (int)state.size(); row++) {
        for (int col = 0; col < (int)state[row].size(); col++) {
            state[row][col] = state[row][col] ^ key_state[row][col];
        }
    }
}

void AES::buildState(vector<vector<unsigned char>>& state, int& index, vector <unsigned char>& text) {
    for (int col = 0; col < (int)state.size(); col++) {
        for (int row = 0; row < (int)state[col].size(); row++) {
            state[row][col] = text[index];
            index++;
        }
    }
}

void AES::buildKeyState(vector<vector<unsigned char>>& key_state, int& index, vector<vector<unsigned char>>& expanded_keys) {
    
     for (int col = 0; col < nb; col++) {            
        key_state[0][col] = expanded_keys[index][0];
        key_state[1][col] = expanded_keys[index][1];
        key_state[2][col] = expanded_keys[index][2];
        key_state[3][col] = expanded_keys[index][3];
        index++;
    }
}

void AES::printIntro(vector<unsigned char>& text, vector<unsigned char>& key) const {
    unsigned int j;
    
    printf("PLAINTEXT:          ");
    for (j = 0; j < text.size(); j++) {
        printf("%02x", (unsigned int)(text[j]&0xFF));
    }
    printf("\nKEY:                ");
    for (j = 0; j < key.size(); j++) {
        printf("%02x", (unsigned int)(key[j]&0xFF));
    }
}