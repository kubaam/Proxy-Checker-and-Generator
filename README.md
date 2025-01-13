
# 🔥 Proxy Checker and Generator 🚀

> **A multithreaded Python Proxy Checker and Generator** featuring **strict IP matching**, **geolocation fallback**, **UTF-8-safe handling**, and an **instant stop** function that truly halts all background tasks in real time.

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## ✨ Overview

This **Proxy Checker and Generator** is a **multithreaded** Python application that combines:
- **Proxy Generation**: Random public IPv4 generation with appropriate proxy ports.
- **Proxy Checking**: Ensures proxies are valid with **strict IP matching** and multiple test endpoints.
- **Geolocation Fallback**: Uses multiple APIs (ip-api.com, geojs.io, ipwhois.io, ipapi.co) for reliable IP location.
- **UTF-8 Safe**: Avoids `utf-8` codec errors during file operations by ignoring invalid bytes.
- **Immediate Stop**: Truly halts proxy generation and validation instantly—no lingering background processes.
- **Multi-Protocol Support**: Validates `HTTP`, `HTTPS`, `SOCKS4`, and `SOCKS5` proxies.
- **Customizable Settings**: Adjust retries, concurrency, timeouts, and more.

---

## 🎉 Features

1. **Strict IP Validation**  
   Proxies are marked **valid** only if the target test service sees the proxy's IP.  
   ➡️ Eliminates false positives for **SEO-friendly proxy validation**.

2. **Proxy Generator**  
   Generates random IPv4 addresses within realistic public ranges, appending commonly used proxy ports.

3. **Immediate Stop Functionality**  
   The **Stop** button halts all generation and validation tasks instantly.  
   ➡️ No more lingering logs or tasks in the background.

4. **Geolocation Fallback**  
   Utilizes multiple APIs for reliable IP geolocation, automatically switching to the next API if rate-limited.

5. **UTF-8 Safe File Handling**  
   Validated proxies are saved to files without causing codec errors—ensures smooth analytics workflows.

6. **Modern, Simple GUI**  
   - Clear **tabs** for **Checker**, **Generator**, **Settings**, and **About**.
   - Real-time **logs** and **progress updates**.
   - Clean, dark-themed interface for a polished look.

7. **Advanced Customization**  
   - Configurable retries (set 0 for single attempt).  
   - Adjustable concurrency and timeout per check.  
   - Proxy protocols toggled with a single click.

8. **Export Options**  
   Save valid proxies to text, CSV, or JSON—or copy to clipboard directly.

---


## 🛠️ Installation

1. **Clone** or **Download** this repository:
   ```bash
   git clone https://github.com/kubaam/Proxy-Checker-and-Generator.git
   cd Proxy-Checker-and-Generator.git
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   Ensure Python 3.9+ is installed.

3. **Run the Application**:
   ```bash
   python main.py
   ```

---

## ⚙️ Usage

1. **Generate Proxies**:  
   Select protocols (`HTTP`, `HTTPS`, `SOCKS4`, `SOCKS5`) and click **Start**. The app will generate and check proxies simultaneously.

2. **Load Proxy List**:  
   Load a list of proxies from a file to validate existing proxies. Format:  
   ```
   protocol://IP:Port
   ```

3. **Settings**:  
   Adjust retries, timeout, concurrency, and other preferences in the **Settings** tab.

4. **Export Results**:  
   Save validated proxies to:
   - `.txt`: Simple IP:Port format.
   - `.csv`: Includes status, geolocation, and response time.
   - `.json`: Full structured data.

---

## ⚡ Key Benefits for SEO

- **Accurate Proxy Validation**: Ensures only working, reliable proxies pass validation.  
- **High Throughput**: Multithreaded design handles large lists effortlessly.  
- **Geolocation Fallback**: Reliable for regional proxy needs.  
- **Immediate Stop**: Total control over ongoing processes.

---

## 🤝 Contributions

We welcome improvements, bug fixes, or feature requests!  

1. Fork this repository.  
2. Create a new branch (`feature/amazing-feature`).  
3. Commit your changes.  
4. Open a pull request.

---

## 📜 License

Licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 💬 Contact

- **Issues**: Open an [issue](../../issues).  
- **Email**: [devteam@example.com](mailto:devteam@example.com)  

> **Happy Proxy Checking & Generating!** 🌐

<!--
- Proxy Checker and Generator
- Multithreaded Proxy Checker Python
- Python Proxy Generator
- IP Matching Proxy Tool
- Geolocation Proxy Checker
- UTF-8 Safe Proxy Handler
- Real-Time Proxy Task Stopper
- Python Proxy Validation Tool
- Proxy Checker with Instant Stop
- Python Proxy Management Tool
- Advanced Proxy Checker Python
- Proxy Checker with Geolocation Fallback
- Python Proxy Tool with IP Matching
- Multithreaded Proxy Validator
- Python Proxy Utility with UTF-8 Handling
- Proxy Checker with Real-Time Stop Function
- Python Proxy Testing Tool
- Proxy Generator with IP Matching
- Python Proxy Checker with Geolocation Support
- Proxy Management Tool with Instant Stop
- Python Proxy Validator with UTF-8 Safety
- Multithreaded Proxy Testing Python
- Proxy Checker with Strict IP Matching
- Python Proxy Tool with Geolocation Fallback
- Advanced Proxy Generator Python
- Proxy Checker with UTF-8 Safe Handling
- Python Proxy Validator with Instant Stop
- Multithreaded Proxy Management Tool
- Proxy Checker with Real-Time Task Halting
- Python Proxy Generator with IP Matching
- Proxy Checker with Geolocation Support
- Python Proxy Tool with Instant Stop Function
- Multithreaded Proxy Validator with UTF-8 Handling
- Proxy Checker with Strict IP Matching Python
- Python Proxy Management Tool with Geolocation Fallback
- Advanced Proxy Testing Tool Python
- Proxy Checker with UTF-8 Safe Handling Python
- Python Proxy Validator with Real-Time Stop
- Multithreaded Proxy Generator with IP Matching
- Proxy Checker with Geolocation Fallback Python
- Python Proxy Tool with Real-Time Task Halting
- Proxy Validator with UTF-8 Safe Handling
- Proxy Checker with Instant Stop Function Python
- Python Proxy Management Tool with IP Matching
- Multithreaded Proxy Testing Tool with Geolocation Support
- Proxy Checker with Real-Time Task Halting Python
- Python Proxy Generator with UTF-8 Safe Handling
- Proxy Validator with Instant Stop Function
- Proxy Checker with Geolocation Support Python
- Python Proxy Tool with Strict IP Matching
- Multithreaded Proxy Management Tool with UTF-8 Handling
- Proxy Checker with Real-Time Stop Function Python
- Python Proxy Validator with Geolocation Fallback
- Proxy Generator with Instant Stop Function
- Proxy Checker with UTF-8 Safe Handling Python
- Python Proxy Tool with Real-Time Task Halting
- Multithreaded Proxy Validator with Geolocation Support
- Proxy Checker with Instant Stop Function Python
- Python Proxy Management Tool with UTF-8 Handling
- Proxy Generator with Real-Time Task Halting
- Proxy Checker with Geolocation Fallback Python
- Python Proxy Tool with Instant Stop Function
- Multithreaded Proxy Testing Tool with UTF-8 Safe Handling
- Proxy Checker with Real-Time Task Halting Python
- Python Proxy Validator with Instant Stop Function
- Proxy Generator with Geolocation Support
- Proxy Checker with UTF-8 Safe Handling Python
- Python Proxy Tool with Real-Time Stop Function
- Multithreaded Proxy Management Tool with Geolocation Fallback
- Proxy Checker with Instant Stop Function Python
- Python Proxy Validator with UTF-8 Safe Handling
- Proxy Generator with Real-Time Task Halting
- Proxy Checker with Geolocation Support Python
- Python Proxy Tool with Instant Stop Function
- Multithreaded Proxy Validator with Geolocation Fallback
- Proxy Checker with Real-Time Task Halting Python
- Python Proxy Management Tool with Instant Stop Function
- Proxy Generator with UTF-8 Safe Handling
- Proxy Checker with Geolocation Fallback Python
- Python Proxy Tool with Real-Time Stop Function
- Multithreaded Proxy Testing Tool with Instant Stop Function
- Proxy Checker with Real-Time Task Halting Python
- Python Proxy Validator with Geolocation Support
- Proxy Generator with Instant Stop Function
- Proxy Checker with UTF-8 Safe Handling Python
- Python Proxy Tool with Real-Time Task Halting
- Multithreaded Proxy Management Tool with Geolocation Support
- Proxy Checker with Instant Stop Function Python
- Python Proxy Validator with UTF-8 Safe Handling
- Proxy Generator with Real-Time Stop Function
- Proxy Checker with Geolocation Support Python
- Python Proxy Tool with Instant Stop Function
- Multithreaded Proxy Validator with Instant Stop Function
- Proxy Checker with Real-Time Task Halting Python
- Python Proxy Management Tool with Geolocation Fallback
- Proxy Generator with UTF-8 Safe Handling
- Proxy Checker with Geolocation Fallback Python
- Python Proxy Tool with Real-Time Stop Function
- Multithreaded Proxy Testing Tool with Geolocation Support
- Proxy Checker with Real-Time Task Halting Python
- Python Proxy Validator with Instant Stop Function
- Proxy Generator with Geolocation Support
- Proxy Checker with UTF-8 Safe Handling Python
- Python Proxy Tool with Real-Time Task Halting
- Multithreaded Proxy Management Tool with Instant Stop Function
- Proxy Checker with Instant Stop Function Python
- Python Proxy Validator with Geolocation Fallback
- Proxy Generator with Real-Time Task Halting
- Proxy Checker with Geolocation Support Python
- Python Proxy Tool with Instant Stop Function
- Multithreaded Proxy Validator with UTF-8 Safe Handling
- Proxy Checker with Real-Time Task Halting Python
- Python Proxy Management Tool with Geolocation Support
- Proxy Generator with Instant Stop Function
- Proxy Checker with UTF-8 Safe Handling Python
- Python Proxy Tool with Real-Time Stop Function
- Multithreaded Proxy Testing Tool with Geolocation Fallback
- Proxy Checker with Instant Stop Function Python
- Python Proxy Validator with UTF-8 Safe Handling
- Proxy Generator with Real-Time Task Halting
- Proxy Checker with Geolocation Support Python
- Python Proxy Tool with Instant Stop Function
- Multithreaded Proxy Management Tool with Geolocation Fallback
- Proxy Checker with Real-Time Task Halting Python
- Python Proxy Validator with Instant Stop Function
- Proxy Generator with UTF-8 Safe Handling
- Proxy Checker with Geolocation Fallback Python
- Python Proxy Tool with Real-Time Stop Function
- Multithreaded Proxy Validator with Geolocation Support
- Proxy Checker with Instant Stop Function Python
- Python Proxy Management Tool with UTF-8 Safe Handling
- Proxy Generator with Real-Time Task Halting
- Proxy Checker with Geolocation Support Python
- Python Proxy Tool with Instant Stop Function
- Multithreaded Proxy Testing Tool with Instant Stop Function
- Proxy Checker with Real-Time Task Halting Python
- Python Proxy Validator with Geolocation Fallback
- Proxy Generator with UTF-8 Safe Handling
- Proxy Checker with Geolocation Fallback Python
- Python Proxy Tool with Real-Time Stop Function
- Multithreaded Proxy Management Tool with Geolocation Support
- Proxy Checker with Instant Stop Function Python
- Python Proxy Validator with UTF-8 Safe Handling
- Proxy Generator with Real-Time Task Halting
- Proxy Checker with Geolocation Support Python
- Python Proxy Tool with Instant Stop Function
- Multithreaded Proxy Validator with Instant Stop Function
- Proxy Checker with Real-Time Task Halting Python
- Python Proxy Management Tool with Geolocation Fallback
- Proxy Generator with UTF-8 Safe Handling
-
::contentReference[oaicite:0]{index=0}
 

