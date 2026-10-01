from inspect import getsource

from engine.cli.console_io import safe_print
from engine.cli.console_output import start_output_worker


def test_safe_print_does_not_reprint_interactive_prompt(
    capsys,
):
    safe_print("message")

    captured = capsys.readouterr().out

    assert captured == "\nmessage\n"
    assert "soc>" not in captured


def test_async_output_worker_does_not_own_interactive_prompt():
    source = getsource(start_output_worker)

    assert "soc>" not in source
