import logging
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import NamedTemporaryFile
from typing import Iterable

from google.protobuf import text_format

from sandbox import DEBUG
from sandbox.config import NsJailConfig
from sandbox.langs import langs
from sandbox.fs import userland_resolve
from sandbox.env import USERLAND_PATH

log = logging.getLogger(__name__)

# [level][timestamp][PID]? function_signature:line_no? message
LOG_PATTERN = re.compile(
    r"\[(?P<level>(I)|[DWEF])\]\[.+?\](?(2)|(?P<func>\[\d+\] .+?:\d+ )) ?(?P<msg>.+)"
)
LOG_BLACKLIST = ("Process will be ",)

NSJAIL_PATH = os.getenv("NSJAIL_PATH", "/usr/sbin/nsjail")
NSJAIL_SANDBOX_CFG = os.getenv("NSJAIL_SANDBOX_CFG", "./config/sandbox.cfg")
NSJAIL_SYSTEM_CFG = os.getenv("NSJAIL_SYSTEM_CFG", "./config/system.cfg")

# Limit of stdout bytes we consume before terminating nsjail
OUTPUT_MAX = 1_000_000  # 1 MB
READ_CHUNK_SIZE = 10_000  # chars


class NsJail:
    """
    Core Sandbox functionality, providing safe execution of code.

    See config/sandbox.cfg for the default NsJail configuration.
    """

    def __init__(
        self,
        nsjail_binary: str = NSJAIL_PATH,
        nsjail_config: str = NSJAIL_SANDBOX_CFG,
    ):
        self.nsjail_binary = nsjail_binary
        self.nsjail_config = nsjail_config
        self.config = self._read_config(self.nsjail_config)

    def _read_config(self, nsjail_config: str) -> NsJailConfig:
        """Read the NsJail config at `nsjail_config` and return a protobuf Message object."""
        config = NsJailConfig()

        try:
            with open(nsjail_config, encoding="utf-8") as f:
                config_text = f.read()
        except FileNotFoundError:
            log.fatal(
                f"The NsJail config at {nsjail_config!r} could not be found."
            )
            sys.exit(1)
        except OSError as e:
            log.fatal(
                f"The NsJail config at {nsjail_config!r} could not be read.",
                exc_info=e,
            )
            sys.exit(1)

        try:
            text_format.Parse(config_text, config)
        except text_format.ParseError as e:
            log.fatal(
                f"The NsJail config at {nsjail_config!r} could not be parsed.",
                exc_info=e,
            )
            sys.exit(1)

        return config

    def _create_dynamic_cgroups(self) -> str:
        """
        Create a PID and memory cgroup for NsJail to use as the parent cgroup.

        Returns the name of the cgroup, located in the cgroup root.

        NsJail doesn't do this automatically because it requires privileges NsJail usually doesn't
        have.

        Disables memory swapping.
        """
        # Pick a name for the cgroup
        cgroup = "sandbox-" + str(uuid.uuid4())

        pids = Path(self.config.cgroup_pids_mount, cgroup)
        mem = Path(self.config.cgroup_mem_mount, cgroup)
        mem_max = str(self.config.cgroup_mem_max)

        pids.mkdir(parents=True, exist_ok=True)
        mem.mkdir(parents=True, exist_ok=True)

        # Swap limit cannot be set to a value lower than memory.limit_in_bytes.
        # Therefore, this must be set before the swap limit.
        #
        # Since child cgroups are dynamically created, the swap limit has to be set on the parent
        # instead so that children inherit it. Given the swap's dependency on the memory limit,
        # the memory limit must also be set on the parent. NsJail only sets the memory limit for
        # child cgroups, not the parent.
        (mem / "memory.limit_in_bytes").write_text(mem_max, encoding="utf-8")

        try:
            # Swap limit is specified as the sum of the memory and swap limits.
            # Therefore, setting it equal to the memory limit effectively disables swapping.
            (mem / "memory.memsw.limit_in_bytes").write_text(
                mem_max, encoding="utf-8"
            )
        except PermissionError:
            log.warning(
                "Failed to set the memory swap limit for the cgroup. "
                "This is probably because CONFIG_MEMCG_SWAP or CONFIG_MEMCG_SWAP_ENABLED is unset. "
                "Please ensure swap memory is disabled on the system."
            )

        return cgroup

    @staticmethod
    def _parse_log(log_lines: Iterable[str]) -> None:
        """Parse and log NsJail's log messages."""
        for line in log_lines:
            match = LOG_PATTERN.fullmatch(line)
            if match is None:
                log.warning(f"Failed to parse log line '{line}'")
                continue

            msg = match["msg"]
            if not DEBUG and any(msg.startswith(s) for s in LOG_BLACKLIST):
                # Skip blacklisted messages if not debugging.
                continue

            if DEBUG and match["func"]:
                # Prepend PID, function signature, and line number if debugging.
                msg = f"{match['func']}{msg}"

            if match["level"] == "D":
                log.debug(msg)
            elif match["level"] == "I":
                if DEBUG or msg.startswith("pid="):
                    # Skip messages unrelated to process exit if not debugging.
                    log.info(msg)
            elif match["level"] == "W":
                log.warning(msg)
            else:
                # Treat fatal as error.
                log.error(msg)

    @staticmethod
    def _consume_stdout(nsjail: subprocess.Popen) -> str:
        """
        Consume STDOUT, stopping when the output limit is reached or NsJail has exited.

        The aim of this function is to limit the size of the output received from
        NsJail to prevent container from claiming too much memory. If the output
        received from STDOUT goes over the OUTPUT_MAX limit, the NsJail subprocess
        is asked to terminate with a SIGKILL.

        Once the subprocess has exited, either naturally or because it was terminated,
        we return the output as a single string.
        """
        output_size = 0
        output = []

        # Context manager will wait for process to terminate and close file descriptors.
        with nsjail:
            # We'll consume STDOUT as long as the NsJail subprocess is running.
            while nsjail.poll() is None:
                chars = nsjail.stdout.read(READ_CHUNK_SIZE)
                output_size += sys.getsizeof(chars)
                output.append(chars)

                if output_size > OUTPUT_MAX:
                    # Terminate the NsJail subprocess with SIGTERM.
                    # This in turn reaps and kills children with SIGKILL.
                    log.info(
                        "Output exceeded the output limit, sending SIGTERM to NsJail."
                    )
                    nsjail.terminate()
                    break

        return "".join(output)

    def system(self, args: Iterable[str] = ()) -> CompletedProcess:
        compact_args = list(filter(None, args))
        return self.jail(args=compact_args)

    def run(self, filename: str, username: str) -> CompletedProcess:
        _, extension = os.path.splitext(filename)
        lang = langs.get(extension)

        # This language is not supported
        if lang is None:
            return CompletedProcess('', 0, "Language is not supported", None)

        fullname = userland_resolve(filename)
        nsjail_args = (
            "--bindmount",
            f"{USERLAND_PATH}/{username}:{USERLAND_PATH}",
        )

        if lang.get("compile"):
            compile_args = (
                lang["compile"],
                *lang.get("compile_args", ()),
                fullname,
            )
            compact_compile_args = list(filter(None, compile_args))
            self.jail(args=compact_compile_args, nsjail_args=nsjail_args)

        args = (
            lang["run"],
            *lang.get("args", ()),
            fullname,
        )
        compact_args = list(filter(None, args))

        return self.jail(args=compact_args, nsjail_args=nsjail_args)

    def jail(
        self, nsjail_args: Iterable[str] = (), args: Iterable[str] = ()
    ) -> CompletedProcess:
        """
        Execute cmd from args in an isolated environment and return
        the completed process.

        The `nsjail_args` passed will be used to override the values
        in the NsJail config. These arguments are only options for
        NsJail; they do not affect programming laguage's arguments.

        `args` are arguments to pass to the programming laguage
        subprocess before the code, which is the last argument.
        """
        cgroup = self._create_dynamic_cgroups()

        with NamedTemporaryFile() as nsj_log:
            args = (
                self.nsjail_binary,
                "--config",
                self.nsjail_config,
                "--log",
                nsj_log.name,
                # Set our dynamically created parent cgroups
                "--cgroup_mem_parent",
                cgroup,
                "--cgroup_pids_parent",
                cgroup,
                *nsjail_args,
                "--",
                *args,
            )

            msg = f"Executing {args}..."
            log.info(msg)

            try:
                nsjail = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            except ValueError:
                return CompletedProcess(
                    args, None, "ValueError: embedded null byte", None
                )

            try:
                output = self._consume_stdout(nsjail)
            except UnicodeDecodeError:
                return CompletedProcess(
                    args,
                    None,
                    "UnicodeDecodeError: invalid Unicode in output pipe",
                    None,
                )

            # When you send signal `N` to a subprocess to terminate it using Popen, it
            # will return `-N` as its exit code. As we normally get `N + 128` back, we
            # convert negative exit codes to the `N + 128` form.
            returncode = (
                -nsjail.returncode + 128
                if nsjail.returncode < 0
                else nsjail.returncode
            )

            log_lines = nsj_log.read().decode("utf-8").splitlines()
            if not log_lines and returncode == 255:
                # NsJail probably failed to parse arguments so log output will still be in stdout
                log_lines = output.splitlines()

            self._parse_log(log_lines)

        log.info(f"nsjail return code: {returncode}")

        # Remove the dynamically created cgroups once we're done
        try:
            Path(self.config.cgroup_mem_mount, cgroup).rmdir()
            Path(self.config.cgroup_pids_mount, cgroup).rmdir()
        except OSError:
            # Perhaps nsjail failed and it didn't create them
            log.error("Could not remove temporary cgroup/pids")

        return CompletedProcess(args, returncode, output, None)
