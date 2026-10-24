# SentinelNet

SentinelNet is a network monitoring, threat analysis, and system simulation platform designed to demonstrate key Operating Systems (OS) and Database Management Systems (DBMS) concepts in an integrated framework.

The project combines a multi-threaded data pipeline for real-time packet processing and threat logging with dedicated algorithmic modules that model foundational systems and database principles.

---

## Key Capabilities

### Operating Systems
- Concurrency & Synchronization: Producer-consumer pipeline utilizing fixed-size ring buffers, POSIX threads, mutexes, semaphores, and atomic operations.
- Deadlock Management: Deadlock detection using Wait-For-Graph (WFG) cycle analysis, prevention strategies, and deadlock avoidance via Banker's Algorithm.
- Storage & Disk Scheduling: Performance evaluation of FCFS, SSTF, SCAN, C-SCAN, and LOOK disk head scheduling algorithms.
- Memory Management: Custom memory pool allocators implementing First-Fit, Best-Fit, and Worst-Fit algorithms, alongside demand paging and page replacement policies.

### Database Management & Security
- Automated Threat Triggers: SQL and PL/SQL database triggers and stored procedures that evaluate incoming network traffic against security thresholds to isolate suspicious IP addresses.
- Schema Design & Optimization: Fully normalized relational schemas with B-tree and composite indexing to optimize query execution and data retrieval.
- Transaction Control & Concurrency: Lock-based concurrency control, transaction isolation levels, and ACID property verification under high-throughput conditions.
- Crash Recovery & Logging: Redo/undo logging mechanisms, checkpoint management, and data persistence routines for system recovery.

---

## Project Structure

SentinelNet/
├── src/                # C source code for pipeline modules and OS algorithms
├── include/            # Shared header files and system data structures
├── scripts/            # Database initialization and support scripts
├── dashboard/          # Web dashboard for real-time traffic and security monitoring
├── static/             # Dashboard styles and assets
├── templates/          # Web interface templates
└── Makefile            # Build configuration