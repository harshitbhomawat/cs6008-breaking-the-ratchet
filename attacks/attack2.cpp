#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <cstring>
#include <thread>
#include <mutex>

// POSIX socket headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// OpenSSL crypto headers (for the X3DH / Double Ratchet decrypt/encrypt later)
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
using namespace std;

mutex state_mutex;
unordered_map<string, string> client_states;
unordered_map<string, vector<string>> stored_opks, mailboxes;

//Helpers

bool read_complete_line(int socket, string &line) {
    line.clear();
    char c;
    while (true) {
        ssize_t n = recv(socket, &c, 1, 0);
        if (n <= 0) {
            return false; 
        }
        if(c == '\n') {
            break; 
        }
        line += c;
    }
    return true;
}

bool send_complete_line(int socket, const string &line) {
    string msg = line + '\n';
    ssize_t sent = send(socket, msg.c_str(), msg.size(),0);
    return sent == (ssize_t)msg.size();
}

string get_json_value(const string& json, const string& key){
    string target = "\"" + key + "\":";
    size_t pos = json.find(target);
    if (pos == string::npos) {
        return "";
    }
    size_t start = json.find_first_not_of("\t", pos + target.length());
    if (start == string::npos) {
        return "";
    }

    if(json[start] == '\"'){
        start++;
        size_t end = json.find('\"', start);
        if (end == string::npos) {
            return "";
        }
        return json.substr(start, end - start);
    }
    else{
        size_t end = json.find_first_of(",}\n",start);
        if(end == string::npos) end = json.length();
        return json.substr(start, end - start);
    }
}

string get_json_object(const string& json, const string& key){
    string target = "\"" + key + "\":";
    size_t pos = json.find(target);
    if (pos == string::npos) {
        return "";
    }
    size_t start = json.find('{',pos);
    if (start == string::npos) {
        return "";
    }
    int brace_count = 0;
    for(size_t i = start; i < json.length(); i++){
        if(json[i] == '{') brace_count++;
        else if(json[i] == '}') brace_count--;
        if(brace_count == 0){
            return json.substr(start, i - start + 1);
        }
    }
    return "";
}

vector<uint8_t> base64_decode(const string &b64) {
    BIO *bio = BIO_new_mem_buf(b64.data(), b64.size());
    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64_bio, bio);
    vector<uint8_t> out(b64.size());
    int decoded_len = BIO_read(bio, out.data(), out.size());
    BIO_free_all(bio);
    if (decoded_len > 0) out.resize(decoded_len);
    else out.clear();
    return out;
}

string base64_encode(const vector<uint8_t> &data) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BUF_MEM *bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    string res(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return res;
}


// 1. Derives X25519 public key from a 32-byte private key
vector<uint8_t> x25519_get_public(const uint8_t priv[32]) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    vector<uint8_t> pub(32);
    size_t len = 32;
    EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len);
    EVP_PKEY_free(pkey);
    return pub;
}

// 2. Computes X25519 DH shared secret: DH(my_priv, peer_pub)
vector<uint8_t> x25519_dh(const uint8_t my_priv[32], const uint8_t peer_pub[32]) {
    EVP_PKEY *priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, my_priv, 32);
    EVP_PKEY *pub_key  = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, pub_key);

    vector<uint8_t> secret(32);
    size_t len = 32;
    EVP_PKEY_derive(ctx, secret.data(), &len);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(pub_key);
    return secret;
}

// 3. HKDF-SHA256 derivation
vector<uint8_t> hkdf_sha256(const vector<uint8_t> &salt, const vector<uint8_t> &ikm, const string &info, size_t out_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    char digest[] = "SHA256";
    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", digest, sizeof(digest));
    params[1] = OSSL_PARAM_construct_octet_string("salt", (void*)salt.data(), salt.size());
    params[2] = OSSL_PARAM_construct_octet_string("key", (void*)ikm.data(), ikm.size());
    params[3] = OSSL_PARAM_construct_octet_string("info", (void*)info.data(), info.size());
    params[4] = OSSL_PARAM_construct_end();

    vector<uint8_t> out(out_len);
    EVP_KDF_derive(kctx, out.data(), out_len, params);
    EVP_KDF_CTX_free(kctx);
    return out;
}

// 4. HMAC-SHA256 (for symmetric ratchet chains)
vector<uint8_t> hmac_sha256(const vector<uint8_t> &key, const vector<uint8_t> &data) {
    vector<uint8_t> out(32);
    unsigned int len = 32;
    HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), out.data(), &len);
    return out;
}

// 5. ChaCha20-Poly1305 Decrypt
bool chacha20poly1305_decrypt(const vector<uint8_t> &key, const vector<uint8_t> &ct, const vector<uint8_t> &ad, string &plaintext) {
    if (ct.size() < 16) return false;
    
    // In Go AEAD, the last 16 bytes of ct are the Poly1305 tag
    size_t tag_len = 16;
    size_t cipher_len = ct.size() - tag_len;
    const uint8_t *tag = ct.data() + cipher_len;

    // Fixed 12-byte zero nonce from protocol.md
    uint8_t nonce[12] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce);

    // Feed associated data (AD)
    int len = 0;
    if (!ad.empty()) {
        EVP_DecryptUpdate(ctx, NULL, &len, ad.data(), ad.size());
    }

    // Feed ciphertext
    vector<uint8_t> out(cipher_len);
    EVP_DecryptUpdate(ctx, out.data(), &len, ct.data(), cipher_len);

    // Set expected tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag);

    // Finalize and verify tag
    int ret = EVP_DecryptFinal_ex(ctx, out.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext = string(out.begin(), out.end());
        return true;
    }
    return false;
}

//constants

const uint8_t MALLORY_IK_PRIV[32]  = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
const uint8_t MALLORY_SPK_PRIV[32] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
const uint8_t MALLORY_OPK_PRIV[32] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f};

//Client Connection handler

void handle_client_connection(int client_socket, int mode) {
    string line;
    string session_user = "";
    while (read_complete_line(client_socket, line)) {
        string type = get_json_value(line, "type");
        if(type == "register"){
            session_user = get_json_value(line, "user");
            cout<< "[Malicious Server] Client Registering as : " << session_user << endl;
            send_complete_line(client_socket, "{\"type\":\"ok\",\"ok\":true}");
        }
        else if(type == "publish"){
            string bundle = get_json_object(line, "bundle");
            {
                lock_guard<mutex> lock(state_mutex);
                client_states[session_user] = bundle;
            }
            cout<< "[Malicious Server] Published prekey bundle for : " << session_user << endl;
            send_complete_line(client_socket, "{\"type\":\"ok\",\"ok\":true,\"count\":5}");
        }
        else if(type == "fetch_bundle"){
            string target = get_json_value(line, "user");
            cout<< "[Malicious Server] Fetching prekey bundle for : " << target << endl;
            if(mode == 2){
                cout<<"MITM Attack: Substituting Mallory's prekey bundle for " << target << endl;
                string fake_bundle = "{\"type\":\"bundle\",\"bundle\":{"
                    "\"user\":\"" + target + "\","
                    "\"ik_sig\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
                    "\"ik_dh\":\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\","
                    "\"spk\":\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\","
                    "\"spk_sig\":\"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=\","
                    "\"opk\":\"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=\","
                    "\"opk_id\":1"
                    "},\"count\":5}";
                send_complete_line(client_socket, fake_bundle);
            }
            else{
                string real_bundle;
                {
                    lock_guard<mutex> lock(state_mutex);
                    if(client_states.find(target) != client_states.end()){
                        real_bundle = client_states[target];
                    }
                }

                if(!real_bundle.empty()){
                    string resp = "{\"type\":\"bundle\",\"bundle\":" + real_bundle + ",\"count\":5}";
                    send_complete_line(client_socket, resp);    
                }
                else{
                    send_complete_line(client_socket, "{\"type\":\"err\",\"err\":\"user not found\"}");
                }
            }
        }
        else if(type == "send"){
            string frame = get_json_object(line, "frame");
            string to_user = get_json_value(frame, "to");
            string from_user = get_json_value(frame, "from");
            cout<< "[Malicious Server] Received message from " << from_user << " to "<< to_user << endl;
            if(mode == 3){
                cout << "[MODE 3 - TAMPER] Corrupting ciphertext to demonstrate Auth Failure..." << endl;
                size_t ct_pos = frame.find("\"ct\":");
                if(ct_pos != string::npos){
                    size_t start = frame.find_first_of("\"", ct_pos + 5);
                    if(start != string::npos && start + 2 < frame.length()){
                        frame[start + 1] = (frame[start + 1] == 'A') ? 'B' : 'A'; // Simple corruption
                    }
                }
            }
            else if(mode == 1){
                cout<<"[MODE1 - RELAY] encrypted message, server cannot read it"<< endl;
            }
            else if(mode == 2){
                cout<<"[MODE2 - MITM] Decrypting and re-encrypting message, server can read it"<< endl;
            }
            {
                lock_guard<mutex> lock(state_mutex);
                mailboxes[to_user].push_back(frame);
            }
            send_complete_line(client_socket, "{\"type\":\"ok\",\"ok\":true}");
        }
        else if(type == "poll"){
            string user = get_json_value(line, "user");
            if(user.empty()) user = session_user;

            vector<string> frames_to_send;
            {
                lock_guard<mutex> lock(state_mutex);
                if(mailboxes.find(user) != mailboxes.end()){
                    frames_to_send = mailboxes[user];
                    mailboxes[user].clear();
                }
            }

            if(frames_to_send.empty()){
                send_complete_line(client_socket, "{\"type\":\"frames\",\"frames\":[]}");
            }
            else{
                string resp = "{\"type\":\"frames\",\"frames\":[";
                for(size_t i = 0; i < frames_to_send.size(); i++){
                    if(i > 0) resp += ",";
                    resp += frames_to_send[i];
                }
                resp += "]}";
                send_complete_line(client_socket, resp);
            }
        }
    }

    cout << "[Malicious Server] Client " << session_user << " disconnected." << endl;

    close(client_socket);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <listen_port> [mode: 1=relay, 2=mitm, 3=fail]" << endl;
        return 1;
    }

    int port = stoi(argv[1]);
    int mode = (argc >= 3) ? stoi(argv[2]) : 2; // Default to MITM mode

    cout << "[Malicious Server] Starting on port " << port << " in mode " << mode << "..." << endl;

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        return 1;
    }

    if (listen(server_sock, 10) < 0) {
        perror("Listen failed");
        close(server_sock);
        return 1;
    }

    cout << "[Malicious Server] Listening for incoming connections on port " << port << "..." << endl;
    
    while(true){
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }

        cout << "[Malicious Server] new client connected from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << endl;

        thread client_thread(handle_client_connection, client_sock, mode);
        client_thread.detach(); 
    }
    close(server_sock);
    return 0;
}