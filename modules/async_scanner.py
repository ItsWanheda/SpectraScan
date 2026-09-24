"""Asynchronous TCP/HTTP scanning engine for SpectraScan.

This module is additive: the legacy PortScanner remains unchanged and callers
can opt into AsyncPortScanner when they want asyncio/aiohttp concurrency.
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

import aiohttp


HTTP_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888}


class AsyncPortScanner:
    """Concurrent TCP scanner with optional aiohttp HTTP enrichment.

    The result schema intentionally mirrors the useful subset of PortScanner:
    target, resolved_ip, scan_type, timestamp, duration, open_ports and
    vulnerabilities.
    """

    def __init__(
        self,
        target: str,
        ports: Optional[Iterable[int]] = None,
        timeout: float = 1.0,
        concurrency: int = 100,
        check_http: bool = True,
        user_agent: str = "SpectraScan/async",
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than 0")
        if concurrency <= 0:
            raise ValueError("concurrency must be greater than 0")

        self.target = target
        self.ports = sorted({int(port) for port in (ports or [])})
        self.timeout = float(timeout)
        self.concurrency = int(concurrency)
        self.check_http = check_http
        self.user_agent = user_agent
        self.resolved_ip: Optional[str] = None
        self.results: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.start_time: Optional[float] = None

    async def resolve(self) -> str:
        """Resolve the target without blocking the event loop."""
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            self.target,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
        if not infos:
            raise ValueError(f"Cannot resolve target: {self.target}")

        self.resolved_ip = infos[0][4][0]
        return self.resolved_ip

    async def _probe_tcp(
        self,
        port: int,
        semaphore: asyncio.Semaphore,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "port": port,
            "protocol": "tcp",
            "state": "closed",
            "service": self._service_name(port),
            "banner": "",
            "error": None,
        }

        async with semaphore:
            writer: Optional[asyncio.StreamWriter] = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.resolved_ip, port),
                    timeout=self.timeout,
                )
                result["state"] = "open"

                if port in HTTP_PORTS:
                    request = (
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {self.target}\r\n"
                        f"User-Agent: {self.user_agent}\r\n"
                        "Connection: close\r\n\r\n"
                    )
                    writer.write(request.encode("ascii", errors="ignore"))
                    await writer.drain()

                try:
                    data = await asyncio.wait_for(
                        reader.read(1024),
                        timeout=min(self.timeout, 1.5),
                    )
                    result["banner"] = data.decode(
                        "utf-8", errors="replace"
                    ).strip()[:4096]
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
                    result["error"] = str(exc)
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (AttributeError, OSError):
                        pass

        return result

    async def _http_enrich(
        self,
        result: Dict[str, Any],
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
    ) -> Dict[str, Any]:
        port = int(result["port"])
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{self.target}:{port}/"

        async with semaphore:
            try:
                async with session.get(
                    url,
                    allow_redirects=False,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    result["http"] = {
                        "status_code": response.status,
                        "server": response.headers.get("Server"),
                        "content_type": response.headers.get("Content-Type"),
                        "location": response.headers.get("Location"),
                        "security_headers": {
                            name: response.headers.get(name)
                            for name in (
                                "Strict-Transport-Security",
                                "Content-Security-Policy",
                                "X-Frame-Options",
                                "X-Content-Type-Options",
                            )
                            if response.headers.get(name) is not None
                        },
                    }
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                result["http_error"] = str(exc)

        return result

    async def scan_async(self) -> List[Dict[str, Any]]:
        """Run the asynchronous scan and return open-port results."""
        self.start_time = time.monotonic()
        await self.resolve()

        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [
            asyncio.create_task(self._probe_tcp(port, semaphore))
            for port in self.ports
        ]
        scanned = await asyncio.gather(*tasks)

        open_results = [
            result for result in scanned if result["state"] == "open"
        ]

        if self.check_http and open_results:
            http_results = [r for r in open_results if r["port"] in HTTP_PORTS]
            if http_results:
                connector = aiohttp.TCPConnector(
                    limit=self.concurrency,
                    ssl=False,
                )
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers={"User-Agent": self.user_agent},
                ) as session:
                    await asyncio.gather(
                        *(
                            self._http_enrich(r, session, semaphore)
                            for r in http_results
                        )
                    )

        self.results = open_results
        return self.results

    def scan(self) -> List[Dict[str, Any]]:
        """Synchronous compatibility entry point for scripts."""
        return asyncio.run(self.scan_async())

    def get_results(self) -> Dict[str, Any]:
        duration = (
            time.monotonic() - self.start_time
            if self.start_time is not None
            else 0.0
        )
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "scan_type": "async-tcp",
            "timestamp": time.time(),
            "duration": duration,
            "open_ports": self.results,
            "vulnerabilities": self.vulnerabilities,
        }

    @staticmethod
    def _service_name(port: int) -> str:
        services = {
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
        }
        return services.get(port, "unknown")


async def scan(
    target: str,
    ports: Iterable[int],
    timeout: float = 1.0,
    concurrency: int = 100,
    check_http: bool = True,
) -> List[Dict[str, Any]]:
    """Small functional API for callers that already run an event loop."""
    scanner = AsyncPortScanner(
        target,
        ports=ports,
        timeout=timeout,
        concurrency=concurrency,
        check_http=check_http,
    )
    return await scanner.scan_async()
