import threading

console_lock = threading.Lock()

def safe_print(*args, **kwargs):
    kwargs.setdefault("flush", True)

    with console_lock:
        print("\n", end="")  # baja línea limpia
        print(*args, **kwargs)
        print("soc> ", end="", flush=True)

def color(text, c):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "end": "\033[0m"
    }
    return colors.get(c, "") + str(text) + colors["end"]