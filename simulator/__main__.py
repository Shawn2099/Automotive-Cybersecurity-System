"""python -m simulator --server ws://127.0.0.1:8000/ws/ingest --port 8100 --cars 1"""

import argparse
import os

import uvicorn

from simulator.controller import Simulator, create_app


def main() -> None:
    p = argparse.ArgumentParser(description="Virtual car + product module + controller UI")
    p.add_argument("--server", default=f"ws://127.0.0.1:{os.getenv('TELEMETRY_HTTP_PORT', '8000')}/ws/ingest",
                   help="server ingest URL; the default follows TELEMETRY_HTTP_PORT (e.g. ws://127.0.0.1:8001/ws/ingest)")
    p.add_argument("--port", type=int, default=8100)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--cars", default="1", help="comma-separated device ids (all use the Sonata profile; id n>1 reads PSK_DEVICE_<n>)")
    a = p.parse_args()
    ids = [int(x) for x in a.cars.split(",") if x.strip()]
    app = create_app(Simulator(a.server, ids))
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
