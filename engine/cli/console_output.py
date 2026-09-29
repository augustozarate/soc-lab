from rich.console import Console
from rich.panel import Panel
import queue
import threading

console = Console()
output_queue = queue.Queue()

def log(msg):
    output_queue.put(msg)

def start_output_worker():
    def worker():
        while True:
            msg = output_queue.get()

            console.print()  # espacio limpio
            console.print(msg)
            console.print("[dim]soc> [/dim]", end="")

    t = threading.Thread(target=worker, daemon=True)
    t.start()
