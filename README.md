# CS6008 — Breaking the Ratchet

## Setup

```bash
cd /home/harshit/NetworkSecurity/Assignment3/as3
docker compose pull
```

## Start the Lab

**To Perform Attack0**

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

**Attack0 Completed**



**To Perform Attack2**

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

**Attack2 Completed**