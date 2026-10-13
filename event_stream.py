"""
Server-Sent Events (SSE) Real-Time Pub/Sub Dispatcher for Login After Dark
Enables real-time push events to Desktop SOC and Mobile Companion (<100ms latency),
eliminating constant HTTP polling.
"""

import json
import time
import queue
from typing import Generator

class EventDispatcher:
    def __init__(self):
        self.listeners = []

    def subscribe(self) -> queue.Queue:
        """Register a new connected client stream."""
        q = queue.Queue(maxsize=100)
        self.listeners.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        """Remove a disconnected client stream."""
        if q in self.listeners:
            try:
                self.listeners.remove(q)
            except ValueError:
                pass

    def broadcast(self, event_type: str, data: dict):
        """Broadcast a structured event to all active SSE client streams."""
        message = json.dumps({
            "type": event_type,
            "data": data,
            "timestamp": time.time()
        })
        payload = f"event: message\ndata: {message}\n\n"
        
        dead_queues = []
        for q in list(self.listeners):
            try:
                q.put_nowait(payload)
            except queue.Full:
                dead_queues.append(q)
            except Exception:
                dead_queues.append(q)

        for q in dead_queues:
            self.unsubscribe(q)

    def stream(self, client_queue: queue.Queue) -> Generator[str, None, None]:
        """Generator yielding SSE formatted strings to a connected HTTP response."""
        yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'clients': len(self.listeners)})}\n\n"
        try:
            while True:
                try:
                    # Wait up to 20 seconds for an event; send keepalive ping if idle
                    msg = client_queue.get(timeout=20.0)
                    yield msg
                except queue.Empty:
                    yield ": ping\n\n"
        except GeneratorExit:
            self.unsubscribe(client_queue)
        finally:
            self.unsubscribe(client_queue)

# Global event bus singleton
event_dispatcher = EventDispatcher()
