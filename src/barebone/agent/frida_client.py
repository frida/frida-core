#!/usr/bin/env python3

import mmap
import struct
import sys
import time
from typing import Any, Dict, List, Union


def main(args: List[str]):
    client = FridaBareboneClient()

    try:
        if not client.connect():
            print("Failed to connect to QEMU monitor")
            return

        # client.ping()
        # client.execute_javascript("function add(a, b) { return a + b; }")

        result = client.execute_javascript(args[0])
        print(result)

        # client.shutdown()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
    finally:
        client.disconnect()


class FridaBareboneClient:
    CMD_IDLE = 0
    CMD_PING = 1
    CMD_EXEC_JS = 2
    CMD_SHUTDOWN = 3

    STATUS_IDLE = 0
    STATUS_BUSY = 1
    STATUS_DATA_READY = 2
    STATUS_ERROR = 3

    MAGIC_NUMBER = 0x46524944

    def __init__(self, buffer_addr=0x8ECA44FCC, dram_base=0x800000000):
        self.buffer_offset = buffer_addr - dram_base
        self.buffer_size = 4096
        self.memory_map = None
        self.memory_fd = None

    def connect(self) -> bool:
        try:
            self._open_shared_memory()

            if not self._verify_buffer():
                print("✗ Shared buffer verification failed")
                return False

            return True
        except Exception as e:
            print(f"Failed to connect: {e}")
            return False

    def disconnect(self):
        if self.memory_map:
            self.memory_map.close()
            self.memory_map = None
        if self.memory_fd:
            self.memory_fd.close()
            self.memory_fd = None

    def _open_shared_memory(self):
        path = "/Volumes/RAM Disk/ios-dram"
        self.memory_fd = open(path, "r+b")
        self.memory_map = mmap.mmap(self.memory_fd.fileno(), 0)

    def _read_memory(self, offset: int, size: int) -> bytes:
        return bytes(self.memory_map[offset : offset + size])

    def _write_memory(self, offset: int, data: bytes):
        self.memory_map[offset : offset + len(data)] = data
        self.memory_map.flush()

    def _verify_buffer(self) -> bool:
        try:
            magic_bytes = self._read_memory(self.buffer_offset, 4)
            magic = struct.unpack("<I", magic_bytes)[0]
            return magic == self.MAGIC_NUMBER
        except Exception as e:
            print(f"Buffer verification failed: {e}")
            return False

    def _read_buffer_field(self, offset: int, size: int, format_str: str):
        data = self._read_memory(self.buffer_offset + offset, size)
        return struct.unpack(format_str, data)[0]

    def _write_buffer_field(self, offset: int, value: int, size: int, format_str: str):
        data = struct.pack(format_str, value)
        self._write_memory(self.buffer_offset + offset, data)

    def _get_buffer_status(self) -> Dict[str, Any]:
        return {
            "magic": self._read_buffer_field(0, 4, "<I"),
            "status": self._read_buffer_field(4, 1, "<B"),
            "command": self._read_buffer_field(5, 1, "<B"),
            "data_size": self._read_buffer_field(8, 4, "<I"),
            "result_code": self._read_buffer_field(12, 4, "<I"),
            "result_size": self._read_buffer_field(16, 4, "<I"),
        }

    def _wait_for_completion(self, timeout: float = 5.0) -> bool:
        start_time = time.time()

        while time.time() - start_time < timeout:
            status = self._get_buffer_status()
            if status["status"] == self.STATUS_DATA_READY:
                return True
            elif status["status"] == self.STATUS_ERROR:
                return False
            time.sleep(0.01)

        return False

    def ping(self) -> bool:
        result = self._execute_command(self.CMD_PING, "PING")
        return result is not None

    def execute_javascript(self, code: str) -> Union[int, str, None]:
        code_bytes = code.encode("utf-8")
        return self._execute_command(
            self.CMD_EXEC_JS, "JavaScript execution", code_bytes
        )

    def shutdown(self) -> bool:
        result = self._execute_command(self.CMD_SHUTDOWN, "SHUTDOWN")
        return result is not None

    def _execute_command(
        self, command: int, command_name: str, data: bytes = b""
    ) -> Union[int, str, None]:
        if data:
            if len(data) > 4096:
                print(f"✗ {command_name} data too long (max 4096 bytes)")
                return None
            self._write_memory(self.buffer_offset + 20, data)
        self._write_buffer_field(8, len(data), 4, "<I")

        self._write_buffer_field(5, command, 1, "<B")

        if not self._wait_for_completion():
            print(f"✗ {command_name} timeout")
            return None

        status = self._get_buffer_status()
        if status["result_code"] == 0:
            result_size = status["result_size"]
            if result_size > 0:
                result_data = self._read_memory(self.buffer_offset + 20, result_size)
                result = result_data.decode("utf-8", errors="replace")
                return result
            else:
                return ""
        else:
            error_size = status["result_size"]
            if error_size > 0:
                error_data = self._read_memory(self.buffer_offset + 20, error_size)
                error_msg = error_data.decode("utf-8", errors="replace")
                print(f"✗ {command_name} failed: {error_msg}")
            else:
                print(f"✗ {command_name} failed with code {status['result_code']}")
            return None


if __name__ == "__main__":
    main(sys.argv[1:])
