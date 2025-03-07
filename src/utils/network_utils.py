import socket

def resolve_hostname(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return ""
