import socket

HOST = '127.0.0.1'
PORT = 50370

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
current_token = ""

print(f"Connected to {HOST}:{PORT}")
print("Commands: REGISTER <u > <p> | LOGIN <u> <p> | PING | WHOAMI | STORE <file> <txt> | LOGOUT | exit")

while True:
    try:
        cmd_input = input("\nEnter command: ").strip()
        if cmd_input == "exit":
            break
            
        parts = cmd_input.split()
        if not parts:
            continue
            
        base_cmd = parts[0].upper()
        
        # Auto-inject token for protected commands!
        if base_cmd in ["PING", "WHOAMI", "STORE", "LOGOUT"]:
            if len(parts) > 1:
                cmd_input = f"{base_cmd} {current_token} {' '.join(parts[1:])}"
            else:
                cmd_input = f"{base_cmd} {current_token}"

        data = f"LEN:{len(cmd_input)}\n{cmd_input}"
        client.sendall(data.encode())

        response = client.recv(4096).decode().strip()
        print("Server:", response)
        
        if "TOKEN:" in response:
            current_token = response.split("TOKEN:")[1].strip()
            print(f"[System: Token saved!]")
        elif "Logout" in response or "Session Expired" in response:
            current_token = ""
            
    except Exception as e:
        print(f"Error: {e}")

client.close()
