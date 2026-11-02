# CS6008 — Breaking the Ratchet

## Setup

```bash
cd /home/harshit/NetworkSecurity/Assignment3/as3
docker compose pull
```

# How to Run Attack 0

**Terminal 1 — Server**
```bash
docker compose up as3_server
```

**To Compile: attack0.cpp**
g++ -std=c++17 -O2 -pthread -o attacks/attack0.exe attacks/attack0.cpp


Terminal 4 (Mallory) — Run your proxy with n, pn:

```bash
./attacks/attack0 9001 127.0.0.1 9000 n_val pn_val
```

**Terminal 2 — Bob** (must run before Alice)
```bash
docker compose run --rm bob /client --server-addr host.docker.internal --port 9001
```

**Terminal 3 — Alice**
```bash
docker compose run --rm alice
```

**Terminal 5 - Start Snapshot Storing Script**
```bash
./storesnapshots
```

## Send a Message

In Alice's terminal: select `1` → enter `bob` → type message → `Ctrl+D` to exit chat.  

## Reset

**Terminal 5 - STOP!! Snapshot Storing Script**
```bash
ctrl+c
```

**rewrite filename to a different name**
Name file according to n and pn.


**Reset docker**
```bash
# Full reset (server + client state)
docker compose down -v
```



# How to Run Attack 1

## What this attack shows

Bob stores five public one-time prekeys, called OPKs, on the server. A new user needs one of these keys to start an X3DH session with Bob. Mallory is a user who repeatedly asks the server for Bob's bundle. The lab server gives Mallory one OPK for every request and removes that key from Bob's list. After five requests, no OPKs remain. Alice then cannot start a new session with Bob.

This is a attack on availability.

## Step 1 Clear old data and start the server

Use Terminal 1:

```bash
docker compose -f as3/docker-compose.yml down -v
docker compose -f as3/docker-compose.yml up as3_server
```

Leave this terminal running. Open a new terminal for the next step.

## Step 2 Bob publish his five OPKs

Use Terminal 2:

```bash
docker compose -f as3/docker-compose.yml run --rm bob
```

Bob publishes his key bundle when he starts. Choose the Exit option after the bundle is published. Bob should now be offline, but the server still holds his five public OPKs.

## Step 3 Build the Attack 1 program

Use Terminal 3:

```bash
g++ -std=c++17 -O2 -pthread -o attacks/attack1 attacks/attack1.cpp
```

If this command finishes without an error, the program was built successfully.

## Step 4 Run the attack

Still in Terminal 3,

Sequential experiment:

```bash
./attacks/attack1 127.0.0.1 9000 bob mallory 10 1 | tee attack1-sequential.log
```

The words and numbers after `attack1` mean:

- `127.0.0.1` is the server address.
- `9000` is the server port.
- `bob` is the target.
- `mallory` is the attacker's name.
- `10` is the maximum number of requests. The program stops earlier when no OPKs remain.
- `1` means how many requests are sent concurrently.

Concurrent-allocation experiment using five independent Mallory connections:

```bash
./attacks/attack1 127.0.0.1 9000 bob mallory 10 5 | tee attack1-concurrent.log
```

## Step 5 Show that Alice is affected

Use Terminal 4:

```bash
docker compose -f as3/docker-compose.yml run --rm alice
```

In Alice's menu:

1. Choose to message a user.
2. Enter `bob` as the username.
3. Record the error shown by Alice.

Alice should be unable to fetch a new bundle because Mallory used all of Bob's OPKs. The attack blocks only a new X3DH session. An old session between Alice and Bob would continue to work.


## Files used in this phase

- `attack1.cpp` performs the attack.
- `attack1_Prevention.py` gives simple pseudocode for a possible fix.
- `attack1-sequential.log` contains the main sequential attack evidence.
- `attack1-concurrent.log` contains concurrent attack evidence.


# How to Run Attack 2

**Terminal 1 — Compile and Start Server**
Set **do_complete_mitm = true;** for complete MITM in attack2.cpp

```bash
g++ -std=c++17 -O2 -pthread -o attacks/attack2.exe attacks/attack2.cpp -lcrypto
```

To run:
```bash
./attacks/attack2.exe 9000 2
```



**Terminal 2 — Bob** (must run before Alice)
```bash
docker compose run --rm bob /client --server-addr host.docker.internal --port 9000
```

**Terminal 3 — Alice**
```bash
docker compose run --rm alice /client --server-addr host.docker.internal --port 9000
```


## Send a Message

In Alice's terminal: select `1` → enter `bob` → type message → `Ctrl+D` to exit chat.  

## Reset

**Reset docker**
```bash
# Full reset (server + client state)
docker compose down -v
```