"""Bounded asynchronous TCP/HTTP scanner."""
from __future__ import annotations

import asyncio
import socket
import time
from typing import Any, Dict, Iterable, List, Optional

import aiohttp

HTTP_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888}
MAX_PORTS = 65535
MAX_CONCURRENCY = 512


class AsyncPortScanner:
    def __init__(self, target: str, ports: Optional[Iterable[int]] = None,
                 timeout: float = 1.0, concurrency: int = 100,
                 check_http: bool = True, user_agent: str = "SpectraScan/async") -> None:
        if not target or not target.strip():
            raise ValueError("target must not be empty")
        if not 0 < float(timeout) <= 60:
            raise ValueError("timeout must be between 0 and 60 seconds")
        if not 0 < int(concurrency) <= MAX_CONCURRENCY:
            raise ValueError(f"concurrency must be between 1 and {MAX_CONCURRENCY}")
        normalized = sorted({int(port) for port in (ports or [])})
        if any(port < 1 or port > MAX_PORTS for port in normalized):
            raise ValueError("ports must be in the range 1..65535")
        self.target = target.strip()
        self.ports = normalized
        self.timeout = float(timeout)
        self.concurrency = int(concurrency)
        self.check_http = bool(check_http)
        self.user_agent = user_agent
        self.resolved_ip: Optional[str] = None
        self.results: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.start_time: Optional[float] = None

    async def resolve(self) -> str:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(self.target, None, type=socket.SOCK_STREAM)
        if not infos:
            raise ValueError(f"Cannot resolve target: {self.target}")
        self.resolved_ip = infos[0][4][0]
        return self.resolved_ip

    async def _probe_tcp(self, port: int, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        result = {"port": port, "protocol": "tcp", "state": "closed",
                  "service": self._service_name(port), "banner": "", "error": None}
        async with semaphore:
            writer = None
            try:
                use_tls = port in {443, 8443}
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.resolved_ip, port, ssl=use_tls,
                                            server_hostname=self.target if use_tls else None),
                    timeout=self.timeout)
                result["state"] = "open"
                if port in HTTP_PORTS:
                    request = (f"HEAD / HTTP/1.1\r\nHost: {self.target}\r\n"
                               f"User-Agent: {self.user_agent}\r\nConnection: close\r\n\r\n")
                    writer.write(request.encode("ascii", errors="ignore"))
                    await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=min(self.timeout, 1.5))
                    result["banner"] = data.decode("utf-8", errors="replace").strip()[:4096]
                except asyncio.TimeoutError:
                    pass
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                result["state"] = "filtered"
            except (ConnectionRefusedError, ConnectionResetError):
                result["state"] = "closed"
            except (OSError, ssl.SSLError) as exc:
                result["state"] = "error"
                result["error"] = type(exc).__name__
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (AttributeError, OSError, asyncio.CancelledError):
                        pass
        return result

    async def _http_enrich(self, result: Dict[str, Any], session: aiohttp.ClientSession,
                           semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        port = int(result["port"])
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{self.target}:{port}/"
        async with semaphore:
            try:
                async with session.get(url, allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    result["http"] = {
                        "status_code": response.status,
                        "server": response.headers.get("Server"),
                        "content_type": response.headers.get("Content-Type"),
                        "location": response.headers.get("Location"),
                        "security_headers": {name: response.headers[name] for name in (
                            "Strict-Transport-Security", "Content-Security-Policy",
                            "X-Frame-Options", "X-Content-Type-Options") if name in response.headers},
                    }
            except asyncio.CancelledError:
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                result["http_error"] = type(exc).__name__
        return result

    async def scan_async(self) -> List[Dict[str, Any]]:
        self.start_time = time.monotonic()
        await self.resolve()
        semaphore = asyncio.Semaphore(self.concurrency)
        # A fixed worker pool avoids allocating one Task per port for large scans.
        queue: asyncio.Queue = asyncio.Queue(maxsize=max(self.concurrency * 2, 1))
        scanned: List[Dict[str, Any]] = []

        async def worker() -> None:
            while True:
                port = await queue.get()
                try:
                    if port is None:
                        return
                    scanned.append(await self._probe_tcp(port, semaphore))
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(min(self.concurrency, max(1, len(self.ports))))]
        try:
            for port in self.ports:
                await queue.put(port)
            for _ in workers:
                await queue.put(None)
            await queue.join()
            await asyncio.gather(*workers)
        except BaseException:
            for task in workers:
                task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            raise

        open_results = [r for r in scanned if r["state"] == "open"]
        if self.check_http and open_results:
            http_results = [r for r in open_results if r["port"] in HTTP_PORTS]
            if http_results:
                connector = aiohttp.TCPConnector(limit=self.concurrency)
                async with aiohttp.ClientSession(connector=connector,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        headers={"User-Agent": self.user_agent}) as session:
                    await asyncio.gather(*(self._http_enrich(r, session, semaphore) for r in http_results))
        self.results = sorted(open_results, key=lambda item: item["port"])
        return self.results

    def scan(self) -> List[Dict[str, Any]]:
        return asyncio.run(self.scan_async())

    def get_results(self) -> Dict[str, Any]:
        return {"target": self.target, "resolved_ip": self.resolved_ip,
                "scan_type": "async-tcp", "timestamp": time.time(),
                "duration": time.monotonic() - self.start_time if self.start_time is not None else 0.0,
                "open_ports": self.results, "vulnerabilities": self.vulnerabilities}

    @staticmethod
    def _service_name(port: int) -> str:
        return {21:"FTP",22:"SSH",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",
                443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",1433:"MSSQL",3306:"MySQL",
                3389:"RDP",5432:"PostgreSQL",5900:"VNC",6379:"Redis",8080:"HTTP-Alt",
                8443:"HTTPS-Alt",27017:"MongoDB"}.get(port, "unknown")


async def scan(target: str, ports: Iterable[int], timeout: float = 1.0,
               concurrency: int = 100, check_http: bool = True) -> List[Dict[str, Any]]:
    return await AsyncPortScanner(target, ports, timeout, concurrency, check_http).scan_async()
