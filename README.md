# fps-unlocker-windows

A lightweight command line tool to unlock the frame rate in Elden Ring (and Sekiro) by scanning active process memory and patching the hardcoded 60.0 FPS float value.

Since the game engine resets this value on certain loading screens and transitions, the tool can run in a lightweight background loop to ensure the limit stays patched.

## Prerequisites

- Windows 10 or 11 (64-bit)
- Python 3.8+
- Administrator privileges (required to write to another process's memory space)

## Installation

No external packages or dependencies are required. Just download the script and run it with your local Python installation.

```cmd
git clone https://github.com/username/fps-unlocker-windows.git
cd fps-unlocker-windows
```

## Usage

You must run your command prompt or terminal as Administrator for the tool to access the game process.

```cmd
python fps_unlocker.py --fps 144
```

### Options

```
usage: fps_unlocker.py [-h] [--fps FPS] [--process PROCESS] [--loop] [--interval INTERVAL]

options:
  -h, --help           show this help message and exit
  --fps FPS            target frame rate (default: 120)
  --process PROCESS    target executable name (default: eldenring.exe)
  --loop               keep running and re-patch if the limit gets reset
  --interval INTERVAL  seconds to sleep between checks when looping (default: 2.0)
```

To run it in the background while playing, keeping the frame rate unlocked across loads:

```cmd
python fps_unlocker.py --fps 165 --loop
```

<!-- checked: 2026-09-16 -->
