from pathlib import Path


def test_run_engine_replaces_shell_with_python_process():
    script = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "run_engine.sh"
    )

    lines = [
        line.strip()
        for line in script.read_text(encoding="utf-8").splitlines()
    ]

    assert (
        "exec python3 -m engine.orchestration.soc_engine"
        in lines
    ), (
        "run_engine.sh must replace the wrapper shell with the "
        "SOC Engine process so terminal signals reach Python directly"
    )
