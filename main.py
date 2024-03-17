import asyncio
import base64
import binascii
import os
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


pass_dir = Path(os.getenv("PASSWORD_STORE_DIR", "~/.password-store"))


@dataclass(kw_only=True, frozen=True)
class OTPInfo:
    period: str = "30"
    issuer: str = "???"
    digits: str = "6"
    algorithm: str = "SHA1"
    secret: str

    async def get_code(self) -> str:
        process = await asyncio.subprocess.create_subprocess_exec(
            "oathtool",
            f"--totp={self.algorithm}",
            "--digits",
            self.digits,
            self.secret,
            "--time-step-size",
            self.period,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        await process.wait()
        assert process.returncode == 0

        assert process.stdout

        return (await process.stdout.read()).decode().strip()

    def remaining(self) -> int:
        period = int(self.period)

        return period - (int(time.time()) % period)


otp_expirations = defaultdict[int, list[OTPInfo]](list)
otp_codes: dict[OTPInfo, str] = {}


def parse_totp_url(url):
    params = dict(parse_qsl(urlparse(url).query))
    secret = params.pop("secret")

    try:
        secret = base64.b32decode(secret).hex()

    except binascii.Error:
        # TODO: this logic doesn't seem to be right
        secret = base64.b64decode(secret).hex()

    return OTPInfo(**params, secret=secret)


async def refresh_otp(otp: OTPInfo) -> None:
    expires_at = int(time.time()) + otp.remaining()

    otp_expirations[expires_at].append(otp)

    otp_codes[otp] = await otp.get_code()


def get_pass_names(dir=pass_dir):
    for file in dir.iterdir():
        if file.is_file() and "otp" in file.name:
            yield file

        if file.is_dir():
            yield from get_pass_names(file)


async def pass_decrypt(f: Path) -> str:
    process = await asyncio.subprocess.create_subprocess_exec(
        "pass",
        "ls",
        str(f.relative_to(pass_dir).with_suffix("")),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    await process.wait()
    assert process.returncode == 0

    assert process.stdout

    return (await process.stdout.read()).decode().strip()


async def tick():
    now = int(time.time())

    print("\x1b[H\x1b[2J", end="")

    for expiration, otps in otp_expirations.copy().items():
        if now >= expiration:
            for otp in otps:
                await refresh_otp(otp)

            del otp_expirations[expiration]

        for otp in otps:
            print(f"{otp.remaining():2} {otp_codes[otp]:8} {otp.issuer}")


async def main():
    files = list(get_pass_names())

    if not files:
        return

    async def display():
        while True:
            await tick()

            await asyncio.sleep(0.5)

    main_loop = asyncio.create_task(display())

    for f in files:
        url = await pass_decrypt(f)

        otp = parse_totp_url(url)

        await refresh_otp(otp)

    await main_loop


asyncio.run(main())
