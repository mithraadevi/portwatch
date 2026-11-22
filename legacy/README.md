# Legacy: the original simulator

`network_port_scanner_simulator.ipynb` is the first version of PortWatch: a Google Colab notebook titled "Network Port Scanner Simulator".

**It does not scan anything.** Port states are chosen with random numbers, so a result such as "port 53 open on google.com" says nothing about the real target. It is kept here only to show where the project started.

What carried over into PortWatch: the idea of a service and severity table, recommendations per service, and a combined report. What was replaced: the random results (now real TCP connections), the port-number-only service guess (now banner evidence with a confidence level), and the one-time output (now stored history, drift detection and a verifiable log).

Use the real tool in the repository root instead (`python run_scan.py`).
