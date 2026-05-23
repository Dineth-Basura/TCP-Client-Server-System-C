

IE2102_IT24102370/
│
├── client_2370.py          # Python client application
├── server_2370.c           # C server application
├── Makefile_2370           # Makefile for compiling server
├── server_IT24102370.log   # Server log file
└── IE2102_Assignment_Report_IT24102370.docx

````

## Technologies Used

- C Programming
- Python
- Socket Programming
- Makefile

## Features

- Client-server communication
- Socket-based networking
- Server logging functionality
- Cross-language communication (Python client and C server)

## How to Run

### Compile the Server

```bash
make -f Makefile_2370
````

or

```bash
gcc server_2370.c -o server
```

### Run the Server

```bash
./server
```

### Run the Client

```bash
python client_2370.py
```

## Author

Dineth

## Module

IE2102

````

---

# How to Upload to GitHub

1. Create a new repository on GitHub.
2. Extract your ZIP file.
3. Open the project folder in terminal.
4. Run these commands:

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/yourusername/repository-name.git
git push -u origin main
````

Replace:

* `yourusername` with your GitHub username
* `repository-name` with your selected repository name
