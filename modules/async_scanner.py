"""Bounded asynchronous TCP scanner with verified HTTP/TLS enrichment."""
from __future__ import annotations

import asyncio
import ipaddress
import math
import socket
import time
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional

import aiohttp

HTTP_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888}
MAX_CONCURRENCY = 512
MAX_TIMEOUT = 120.0


class AsyncPortScanner:
    """Concurrent TCP scanner with optional read-only HTTP metadata collection."""

    def __init__(
        self,
        target: str,
        ports: Optional[Iterable[int]] = None,
        timeout: float = 1.0,
        concurrency: int = 100,
        check_http: bool = True,
        user_agent: str = "SpectraScan/async",
    ) -> None:
        if not target or not str(target).strip():
            raise ValueError("target must not be empty")
        if not math.isfinite(float(timeout)) or not 0 < float(timeout) <= MAX_TIMEOUT:
            raise ValueError(f"timeout must be between 0 and {MAX_TIMEOUT:g} seconds")
        if isinstance(concurrency, bool) or not 1 <= int(concurrency) <= MAX_CONCURRENCY:
            raise ValueError(f"concurrency must be between 1 and {MAX_CONCURRENCY}")
        raw_ports = list(ports or [])
        if any(isinstance(port, bool) for port in raw_ports):
            raise ValueError("ports must be integers in the range 1..65535")
        try:
            normalized_ports = sorted({int(port) for port in raw_ports})
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("ports must be integers in the range 1..65535") from exc
        if not normalized_ports:
            raise ValueError("at least one port must be supplied")
        if any(isinstance(port, bool) or port < 1 or port > 65535 for port in normalized_ports):
            raise ValueError("ports must be in the range 1..65535")
        self.target = str(target).strip()
        self.ports = normalized_ports
        self.timeout = float(timeout)
        self.concurrency = int(concurrency)
        self.check_http = bool(check_http)
        self.user_agent = user_agent
        self.resolved_ip: Optional[str] = None
        self.results: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.start_time: Optional[float] = None

    def _hostname(self) -> str:
        value = self.target.strip()
        if "://" in value:
            hostname = urllib.parse.urlsplit(value).hostname
            if not hostname:
                raise ValueError(f"Invalid target URL: {self.target}")
            return hostname
        if value.startswith("[") and "]" in value:
            return value[1:value.index("]")]
        try:
            ipaddress.IPv6Address(value)
            return value
        except ValueError:
            pass
        if value.count(":") == 1:
            host, port = value.rsplit(":", 1)
            if port.isdigit() and host:
                return host
        return value.rstrip("/")

    async def resolve(self) -> str:
        """Resolve IPv4 or IPv6 asynchronously."""
        hostname = self._hostname()
        try:
            ipaddress.ip_address(hostname)
            self.resolved_ip = hostname
            return hostname
        except ValueError:
            pass
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(
                hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise ValueError(f"Cannot resolve target: {hostname}") from exc
        if not infos:
            raise ValueError(f"Cannot resolve target: {hostname}")
        self.resolved_ip = infos[0][4][0]
        return self.resolved_ip

    async def _probe_tcp(self, port: int, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "port": port, "protocol": "tcp", "state": "closed",
            "service": self._service_name(port), "banner": "", "error": None,
        }
        async with semaphore:
            writer: Optional[asyncio.StreamWriter] = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.resolved_ip, port), timeout=self.timeout
                )
                result["state"] = "open"
                if port in HTTP_PORTS and port not in {443, 8443}:
                    host = self._hostname()
                    request = (
                        f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
                        f"User-Agent: {self.user_agent}\r\n"
                        "Connection: close\r\n\r\n"
                    )
                    writer.write(request.encode("ascii", errors="replace"))
                    await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=min(self.timeout, 1.5))
                    result["banner"] = data.decode("utf-8", errors="replace").strip()[:4096]
                except asyncio.TimeoutError:
                    pass
            except asyncio.TimeoutError:
                result["state"] = "filtered"
            except (ConnectionRefusedError, ConnectionResetError):
                result["state"] = "closed"
            except OSError as exc:
                if getattr(exc, "errno", None) in {111, 61, 10061}:
                    result["state"] = "closed"
                else:
                    result["state"] = "error"
                    result["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (AttributeError, OSError, asyncio.CancelledError):
                        pass
        return result

    async def _http_enrich(
        self, result: Dict[str, Any], session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
    ) -> Dict[str, Any]:
        port = int(result["port"])
        scheme = "https" if port in {443, 8443} else "http"
        hostname = self._hostname()
        formatted_host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
        url = f"{scheme}://{formatted_host}:{port}/"
        async with semaphore:
            try:
                async with session.get(
                    url, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    result["http"] = {
                        "status_code": response.status,
                        "server": response.headers.get("Server"),
                        "content_type": response.headers.get("Content-Type"),
                        "location": response.headers.get("Location"),
                        "tls_verified": scheme == "https",
                        "security_headers": {
                            name: response.headers.get(name)
                            for name in (
                                "Strict-Transport-Security", "Content-Security-Policy",
                                "X-Frame-Options", "X-Content-Type-Options",
                                "Referrer-Policy", "Permissions-Policy",
                            ) if response.headers.get(name) is not None
                        },
                    }
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                result["http_error"] = f"{type(exc).__name__}: {exc}"
        return result

    async def scan_async(self) -> List[Dict[str, Any]]:
        """Run a bounded scan; task count is bounded by configured concurrency."""
        self.start_time = time.monotonic()
        self.results = []
        self.vulnerabilities = []
        await self.resolve()
        semaphore = asyncio.Semaphore(self.concurrency)
        work_queue: asyncio.Queue[Optional[int]] = asyncio.Queue(maxsize=max(1, self.concurrency * 2))
        worker_count = min(self.concurrency, len(self.ports))
        results: List[Dict[str, Any]] = []

        async def worker() -> None:
            while True:
                port = await work_queue.get()
                try:
                    if port is None:
                        return
                    result = await self._probe_tcp(port, semaphore)
                    if result["state"] == "open":
                        results.append(result)
                finally:
                    work_queue.task_done()

        async def producer() -> None:
            for port in self.ports:
                await work_queue.put(port)
            for _ in range(worker_count):
                await work_queue.put(None)

        workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
        producer_task = asyncio.create_task(producer())
        try:
            await producer_task
            await work_queue.join()
            await asyncio.gather(*workers)
        except BaseException:
            producer_task.cancel()
            for task in workers:
                task.cancel()
            await asyncio.gather(producer_task, *workers, return_exceptions=True)
            raise
        results.sort(key=lambda item: item["port"])
        if self.check_http and results:
            http_results = [item for item in results if item["port"] in HTTP_PORTS]
            if http_results:
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                # aiohttp certificate verification stays enabled by default.
                connector = aiohttp.TCPConnector(limit=self.concurrency)
                async with aiohttp.ClientSession(
                    connector=connector, timeout=timeout,
                    headers={"User-Agent": self.user_agent},
                ) as session:
                    await asyncio.gather(
                        *(self._http_enrich(item, session, semaphore) for item in http_results)
                    )
        self.results = results
        return self.results

    def scan(self) -> List[Dict[str, Any]]:
        """Synchronous API; call scan_async from an existing event loop."""
        return asyncio.run(self.scan_async())

    def get_results(self) -> Dict[str, Any]:
        return {
            "target": self.target, "resolved_ip": self.resolved_ip,
            "scan_type": "async-tcp", "timestamp": time.time(),
            "duration": time.monotonic() - self.start_time if self.start_time is not None else 0.0,
            "open_ports": self.results, "vulnerabilities": self.vulnerabilities,
        }

    @staticmethod
    def _service_name(port: int) -> str:
        return {
            21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
        }.get(port, "unknown")


async def scan(
    target: str, ports: Iterable[int], timeout: float = 1.0,
    concurrency: int = 100, check_http: bool = True,
) -> List[Dict[str, Any]]:
    """Functional API for callers that already run an event loop."""
    scanner = AsyncPortScanner(target, ports, timeout, concurrency, check_http)
    return await scanner.scan_async()
