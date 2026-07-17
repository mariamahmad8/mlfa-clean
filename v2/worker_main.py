"""Dedicated process entry point for the email polling worker."""

from dotenv import load_dotenv

load_dotenv()

from worker.loop import run


if __name__ == "__main__":
    run()
