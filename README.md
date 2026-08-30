# Team IOBits — Secure Chat Application

## Group Members
- [Lakshyaraj Dash](https://github.com/lakshyaraj2006) - Implemented `.h` (header files)
- [Omm Prakash Satapathy](https://github.com/ommsatapathy2006) - Implemented client + Testing
- [Rudra Pratap Sahoo](https://github.com/Rudrapratapsahoo) - Implemented server + Testing

## Project Structure & File Hierarchy

```text
CLI-Chat-Application/
├── config/
│   └── constants.h          # Global constants, buffer limits, and port definitions
├── crypto/
│   └── cipher.h             # Repeated XOR encryption/decryption and key generation
├── parser/
│   ├── client_parser.h      # Client-side input and command parsing (e.g., SENDFILE)
│   └── server_parser.h      # Server-side protocol parsing (REGISTER, SEND TO, etc.)
├── user/
│   └── user_manager.h       # In-memory user database and session management
├── utils/
│   └── file_utils.h         # File validation (.txt check) and path/basename helpers
├── client.c                 # Multi-threaded interactive CLI client application
├── server.c                 # I/O multiplexed (select-based) chat & routing server
├── client_input.txt         # Automated sample commands for client testing
└── README.md                # Project documentation and architecture guide
```

### Module Breakdown
- **`config/`**: Contains central configuration definitions such as `PORT`, `MAX_MSG_SIZE`, `MAX_FILE_SIZE`, `BUFFER_SIZE`, and `KEY_LENGTH`.
- **`crypto/`**: Implements the Repeated XOR symmetric encryption/decryption routines and random key generator.
- **`parser/`**: Modular parsers for extracting commands and tokens for both client (`client_parser.h`) and server (`server_parser.h`).
- **`user/`**: Implements the server's in-memory linked list data structure for tracking online users, usernames, keys, and socket addresses.
- **`utils/`**: Helper utilities for filesystem and string manipulations, such as validating `.txt` files and resolving file basenames.
- **`client.c`**: Client-side application using multithreading (`_beginthreadex`) to decouple keyboard inputs from background socket receive events.
- **`server.c`**: Server application using `select()` I/O multiplexing to manage concurrent clients, registration, authentication, and encrypted message routing.

## How to Build

### Prerequisites & Dependencies
- C Compiler (GCC / MinGW or MSVC)
- Windows Sockets 2 library (`ws2_32`)

### Compilation Commands
Using GCC (MinGW):
```bash
# Compile Server
gcc server.c -o server.exe -lws2_32

# Compile Client
gcc client.c -o client.exe -lws2_32
```

Using MSVC:
```cmd
cl server.c ws2_32.lib
cl client.c ws2_32.lib
```

## How to Run

### 1. Start the Server
```bash
./server.exe <port>
```
* (Default configured port is `8080` in `config/constants.h`)*

### 2. Start the Client(s)
```bash
./client.exe <server_ip> <port>
```
* Example:*
```bash
./client.exe 127.0.0.1 8080
```

## Cipher Choice
We chose **Repeated XOR** (with a 6-character key) because:
- It provides a lightweight, symmetric encryption mechanism operating byte-by-byte with identical operations for both encryption and decryption ($C = P \oplus K$, $P = C \oplus K$).
- It introduces zero size padding overhead and handles both plain text chat messages and arbitrary byte buffers (for `.txt` file transfer) seamlessly without character set constraints.

**Known weakness:**
- Vulnerable to **Known Plaintext Attacks (KPA)** and frequency analysis. Since the key is short (6 characters) and repeated cyclically, knowing any 6-byte predictable plaintext prefix (such as `"REGIST"`) allows an eavesdropper or server to immediately derive the secret key ($K = C \oplus P$). Additionally, reusing the key across multiple messages allows an adversary to XOR two ciphertexts together ($C_1 \oplus C_2 = P_1 \oplus P_2$), removing the key and leaking plaintext differences.

## Design Notes
- **Hop-by-hop (not end-to-end) encryption:** The server decrypts incoming payloads using the sender's registered key, parses the destination user, and re-encrypts the payload using the recipient's registered key before forwarding.
- **File transfer size cap:** `1` MB (`MAX_FILE_SIZE = 1024 * 1024` bytes). Supported for `.txt` files; received files are saved automatically with a `received_<filename>` prefix.
- **Concurrency model:**
  - **Server:** `select` (I/O multiplexing via Winsock `select()` with `fd_set`). Chosen because it enables single-threaded asynchronous handling of multiple client connections without the synchronization, lock contention, or memory overhead of multi-threading.
  - **Client:** `threads` (multi-threaded via `_beginthreadex`). Chosen to decouple blocking user console input (`fgets` on stdin) from asynchronous background message receiving (`recv()` socket loop) for a responsive interactive chat UI.

## Supported Commands
| Command | Syntax | Description |
| :--- | :--- | :--- |
| **Register** | `REGISTER <username> KEY <6-char-key>` | Registers client username (max 8 chars) and symmetric key |
| **Direct Message** | `SEND TO <user>: <message>` or `SEND TO <user> <message>` | Sends an encrypted direct message to a target user |
| **File Transfer** | `SENDFILE TO <user>: <filepath>` or `SENDFILE TO <user> <filepath>` | Sends a `.txt` file (up to 1 MB) to a target user |
| **List Users** | `LIST` | Returns a list of all currently registered online users |
| **Quit** | `QUIT` | Gracefully closes the session and disconnects from server |
