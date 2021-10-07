import argparse

from sandbox.nsjail import NsJail, NSJAIL_SYSTEM_CFG


def parse_args() -> argparse.Namespace:
    """Parse the command-line arguments and return the populated namespace."""
    parser = argparse.ArgumentParser(
        prog="sandbox", usage="%(prog)s username filename"
    )
    parser.add_argument("--username", "-u", help="username")
    parser.add_argument("--filename", "-f", help="filename to evaluate")
    parser.add_argument("--command", "-c", help="a command to execute")
    parser.add_argument("--system", "-s", help="use system or user nsjail", action=argparse.BooleanOptionalAction)

    args = parser.parse_args()
    return args


def main() -> None:
    """Evaluate file through NsJail."""
    args = parse_args()

    if args.system is True:
        nsjail = NsJail(nsjail_config=NSJAIL_SYSTEM_CFG)
        result = nsjail.system(args.command.split(' '))
    else:
        nsjail = NsJail()
        result = nsjail.run(username=args.username, filename=args.filename)

    print(result.stdout)


if __name__ == "__main__":
    main()
