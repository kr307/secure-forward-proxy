# Technical Interview Preparation Guide: Secure Forward Proxy & SWG

This guide covers the top 12 questions software engineering and security infrastructure interviewers will ask you about this project.

---

### Q1: What is the fundamental difference between a Forward Proxy and a Reverse Proxy?
- **Answer:** 
  - A **Forward Proxy** acts on behalf of the **client** (internal user or workstation). It intercepts outbound requests headed to arbitrary external servers on the Internet to enforce security, URL filtering, authentication, and data compliance (e.g., Zscaler, BlueCoat, Squid).
  - A **Reverse Proxy** acts on behalf of the **origin server** (e.g., NGINX, Cloudflare CDN, Envoy). It sits in front of backend application servers to handle SSL termination, load balancing, caching, and DDoS defense. Clients know the public IP of the reverse proxy, but do not know the internal origin servers.

---

### Q2: How does the HTTP `CONNECT` method work in an HTTPS proxy?
- **Answer:**
  1. Because HTTPS is end-to-end encrypted with TLS, a normal proxy cannot read the HTTP path or modify headers directly without breaking encryption.
  2. The client sends an HTTP request using the `CONNECT` method: `CONNECT target.com:443 HTTP/1.1`.
  3. The proxy parses the requested hostname and port, verifies authentication and policies, and opens a raw TCP socket to `target.com:443`.
  4. If successful, the proxy responds with `HTTP/1.1 200 Connection Established\r\n\r\n`.
  5. After this handshake, the proxy treats both sockets as a dumb bidirectional byte pipe (`tunnel.pipe()`), relaying raw encrypted TLS packets without terminating the TLS layer.

---

### Q3: How did you implement domain filtering for HTTPS if the payload is encrypted?
- **Answer:**
  - In our architecture, domain filtering occurs at two inspection points:
    1. **Pre-Tunneling:** In the initial cleartext `CONNECT target.com:443 HTTP/1.1` request line.
    2. **Post-Connect TLS SNI Inspection:** To prevent *Domain Fronting* (where a client claims `CONNECT allowed.com:443` but requests `evil.com` in the TLS handshake), we built a custom binary parser (`sni_parser.py`) for the TLS 1.2/1.3 `ClientHello` message.
    3. We parse the binary record (`0x16`), locate the Server Name Indication (SNI) extension (`0x0000`, RFC 6066), and extract the true requested hostname before piping the stream. If the SNI fails policy, we immediately terminate the TCP socket.

---

### Q4: Why did you choose Python `asyncio` instead of a multi-threaded or multi-process architecture?
- **Answer:**
  - Proxies are almost purely **I/O bound** (waiting on network sockets to read/write packets).
  - A thread-per-connection model incurs heavy OS memory overhead (~1MB stack per thread on Linux/Windows) and massive context-switching overhead when scaling to thousands of concurrent users.
  - Using Python's asynchronous event loop (`asyncio.start_server` and `StreamReader`/`StreamWriter`), thousands of idle or streaming connections can be managed by a single thread with minimal CPU overhead and ~2-4 KB memory per socket.
  - In benchmarks, our async implementation handles **>2,600 req/sec** with **~18ms median latency**.

---

### Q5: How do you prevent blocking the event loop when logging access records to a database?
- **Answer:**
  - SQLite disk writes are synchronous I/O operations and would block the event loop, causing latency spikes for all concurrent proxy clients.
  - To solve this, we decoupled proxy processing from database persistence using an asynchronous memory queue (`asyncio.Queue`).
  - The proxy connection handler pushes audit events to the queue in `O(1)` non-blocking time (`put_nowait`).
  - A background consumer task drains the queue in batches (up to 100 entries at a time) and writes them to SQLite using `executemany` inside a dedicated worker thread via `asyncio.to_thread()`.

---

### Q6: How do you handle half-closed TCP sockets and prevent connection/file descriptor leaks?
- **Answer:**
  - When either the client or the remote server closes its side of the connection, the reader returns EOF (`b""`).
  - In `tunnel.py`, we launch two concurrent forwarding tasks (`client_to_remote` and `remote_to_client`) wrapped in `asyncio.wait(..., return_when=asyncio.FIRST_COMPLETED)`.
  - As soon as one direction finishes or encounters an error (e.g. `ConnectionResetError` or idle timeout), the other task is immediately cancelled, and both socket writers are cleanly closed and drained in a `finally` block.

---

### Q7: What headers must a forward proxy strip or modify?
- **Answer:**
  - A forward proxy must strip **Hop-by-Hop headers** (defined in RFC 7230 § 6.1) that are meant only for a single transport link and must not be forwarded to upstream servers.
  - These include: `Proxy-Connection`, `Proxy-Authorization`, `Keep-Alive`, `Transfer-Encoding`, `TE`, and `Upgrade`.
  - In standard HTTP proxying, the proxy also transforms absolute URIs (`http://example.com/api/v1`) into relative origin-form URIs (`/api/v1`) in the outgoing request line.

---

### Q8: How is URL category matching optimized for scale?
- **Answer:**
  - URL matching uses a hierarchical look-up table:
    1. Exact hash map lookup (`O(1)` time complexity).
    2. Subdomain walk (e.g. for `sub.corp.facebook.com`, checking `facebook.com` and `corp.facebook.com` in `O(K)` where $K$ is domain depth, usually < 5).
    3. Wildcards via `fnmatch` and pre-compiled regex trees.
  - This allows sub-millisecond evaluation per request.

---

### Q9: What HTTP status codes are specific to proxies?
- **Answer:**
  - `407 Proxy Authentication Required`: The client must authenticate with the proxy (using `Proxy-Authorization: Basic`).
  - `502 Bad Gateway`: The proxy was unable to establish a connection to the upstream destination (DNS failure, destination down, TCP timeout).
  - `504 Gateway Timeout`: The proxy connected, but the upstream server timed out while sending data.
  - `403 Forbidden`: Returned when corporate security policies block access to the requested URL or category.

---

### Q10: How would you scale this forward proxy to enterprise production (e.g., 500,000 users)?
- **Answer:**
  1. **Horizontal Scaling:** Deploy multiple stateless container instances behind a Layer 4 Load Balancer (AWS NLB, Maglev, or HAProxy) using Anycast IP routing.
  2. **Distributed Cache / Storage:** Replace local SQLite with distributed Redis for policy cache and Kafka + ClickHouse/Elasticsearch for real-time audit log streaming.
  3. **Event Loop Optimization:** Use `uvloop` (C-based libuv event loop for Python) or implement the core packet streaming loop in Go / C++ (eBPF / DPDK) for zero-copy socket transfers.
  4. **PAC (Proxy Auto-Config) / WPAD:** Distribute proxy settings to corporate endpoints via WPAD DHCP/DNS records or endpoint agents.
