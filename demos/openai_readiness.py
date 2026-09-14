from pathlib import Path
import os
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


print()
print("=" * 72)
print("ELIAS OPENAI ADAPTER READINESS TEST")
print("=" * 72)

try:
    import openai

    print("OPENAI PACKAGE: INSTALLED")
    print(
        "OPENAI PACKAGE VERSION:",
        getattr(
            openai,
            "__version__",
            "UNKNOWN",
        ),
    )

except ImportError:
    print("OPENAI PACKAGE: NOT INSTALLED")

if os.environ.get("OPENAI_API_KEY"):
    print("OPENAI API KEY: PRESENT")
else:
    print("OPENAI API KEY: NOT SET")

print(
    "ELIAS MODEL:",
    os.environ.get(
        "ELIAS_MODEL",
        "gpt-5.6",
    ),
)

print()
print(
    "NOTE: THE SECRET KEY VALUE IS NEVER PRINTED."
)
