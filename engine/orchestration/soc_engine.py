#!/usr/bin/env python3

from engine.bootstrap.app_factory import (
    create_app
)

def main():

    app = create_app()

    try:
        app.start()

    except KeyboardInterrupt:
        app.stop()

if __name__ == "__main__":
    main()