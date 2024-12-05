# Log Analysis Script

This Python script analyzes web server log files to extract and analyze key information, helping to detect suspicious activity and gain insights into user behavior.

---

## Features

The script performs the following tasks:
1. **Count Requests per IP Address**:
   - Extracts IP addresses from the log file.
   - Counts the number of requests made by each IP.
   - Displays the results in descending order of request counts.

2. **Identify the Most Frequently Accessed Endpoint**:
   - Extracts resource paths (endpoints) from the log file.
   - Identifies the most accessed endpoint along with its access count.

3. **Detect Suspicious Activity**:
   - Detects potential brute force login attempts by:
     - Searching for failed login entries (e.g., HTTP status code `401` or messages like "Invalid credentials").
     - Flagging IPs with failed attempts exceeding a configurable threshold (default: 10).

4. **Output Results**:
   - Displays results in the terminal.
   - Saves results to a CSV file (`log_analysis_results.csv`) with structured sections:
     - **Requests per IP**
     - **Most Accessed Endpoint**
     - **Suspicious Activity**

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/abbbhhiii/Python_Intern_VRV_Assignment.git
   cd Python_Intern_VRV_Assignment
2. Install necessary Python packages:
   pip install matplotlib ipywidgets
