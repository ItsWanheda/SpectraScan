import asyncio
import unittest

from modules.async_scanner import AsyncPortScanner


class TestAsyncPortScanner(unittest.TestCase):
    def test_invalid_configuration(self):
        with self.assertRaises(ValueError):
            AsyncPortScanner("127.0.0.1", ports=[80], timeout=0)

        with self.assertRaises(ValueError):
            AsyncPortScanner("127.0.0.1", ports=[80], concurrency=0)

    def test_invalid_ports_are_rejected(self):
        for invalid in (0, -1, 65536, "abc"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    AsyncPortScanner("127.0.0.1", ports=[invalid])

    def test_empty_ports_are_rejected(self):
        with self.assertRaises(ValueError):
            AsyncPortScanner("127.0.0.1", ports=[])

    def test_concurrency_upper_bound_is_enforced(self):
        with self.assertRaises(ValueError):
            AsyncPortScanner("127.0.0.1", ports=[80], concurrency=513)

    def test_async_tcp_scan_finds_local_listener(self):
        async def scenario():
            async def handle(reader, writer):
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_server(
                handle,
                "127.0.0.1",
                0,
            )
            port = server.sockets[0].getsockname()[1]

            try:
                scanner = AsyncPortScanner(
                    "127.0.0.1",
                    ports=[port],
                    timeout=0.5,
                    concurrency=10,
                    check_http=False,
                )
                results = await scanner.scan_async()

                self.assertEqual(scanner.resolved_ip, "127.0.0.1")
                self.assertEqual(len(results), 1)
                self.assertEqual(results[0]["port"], port)
                self.assertEqual(results[0]["state"], "open")
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
