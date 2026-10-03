from pathlib import Path

from engine.presentation.report_exporter import (
    ReportExporter,
)


def exporter(
    tmp_path,
):
    return ReportExporter(
        tmp_path
        / "reports"
    )


def test_export_json_creates_expected_file(
    tmp_path,
):
    target = exporter(
        tmp_path
    ).export(
        '{"ok": true}\n',
        "json",
        "executive-report",
    )

    assert target.name == (
        "executive-report.json"
    )

    assert target.read_text(
        encoding="utf-8"
    ) == '{"ok": true}\n'


def test_export_markdown_uses_md_extension(
    tmp_path,
):
    target = exporter(
        tmp_path
    ).export(
        "# Report\n",
        "markdown",
        "technical-report",
    )

    assert target.name == (
        "technical-report.md"
    )


def test_export_creates_output_directory(
    tmp_path,
):
    output = (
        tmp_path
        / "missing"
        / "reports"
    )

    assert not output.exists()

    target = ReportExporter(
        output
    ).export(
        "{}\n",
        "json",
        "report",
    )

    assert output.is_dir()
    assert target.exists()


def test_export_returns_resolved_path(
    tmp_path,
):
    output = (
        tmp_path
        / "reports"
    )

    target = ReportExporter(
        output
    ).export(
        "{}\n",
        "json",
        "report",
    )

    assert (
        target
        == target.resolve()
    )


def test_export_rejects_parent_traversal(
    tmp_path,
):
    instance = exporter(
        tmp_path
    )

    for basename in (
        "../secret",
        "..\\secret",
    ):
        try:
            instance.export(
                "{}\n",
                "json",
                basename,
            )

        except ValueError as exc:
            assert (
                "path separators"
                in str(
                    exc
                )
            )

        else:
            raise AssertionError(
                "Traversal filename accepted"
            )


def test_export_rejects_absolute_path(
    tmp_path,
):
    instance = exporter(
        tmp_path
    )

    try:
        instance.export(
            "{}\n",
            "json",
            "/tmp/report",
        )

    except ValueError as exc:
        assert (
            "path separators"
            in str(
                exc
            )
        )

    else:
        raise AssertionError(
            "Absolute filename accepted"
        )


def test_export_rejects_empty_filename(
    tmp_path,
):
    instance = exporter(
        tmp_path
    )

    try:
        instance.export(
            "{}\n",
            "json",
            "   ",
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Report filename is required"
        )

    else:
        raise AssertionError(
            "Empty filename accepted"
        )


def test_export_rejects_dot_names(
    tmp_path,
):
    instance = exporter(
        tmp_path
    )

    for basename in (
        ".",
        "..",
    ):
        try:
            instance.export(
                "{}\n",
                "json",
                basename,
            )

        except ValueError as exc:
            assert str(
                exc
            ) == (
                "Invalid report filename"
            )

        else:
            raise AssertionError(
                "Dot filename accepted"
            )


def test_export_normalizes_filename_characters(
    tmp_path,
):
    target = exporter(
        tmp_path
    ).export(
        "{}\n",
        "json",
        "SOC Report: Shift A",
    )

    assert target.name == (
        "SOC-Report-Shift-A.json"
    )


def test_export_does_not_allow_extension_injection(
    tmp_path,
):
    target = exporter(
        tmp_path
    ).export(
        "{}\n",
        "json",
        "report.exe",
    )

    assert target.name == (
        "report.exe.json"
    )


def test_export_rejects_unsupported_format(
    tmp_path,
):
    try:
        exporter(
            tmp_path
        ).export(
            "data",
            "html",
            "report",
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Unsupported report export format"
        )

    else:
        raise AssertionError(
            "Unsupported format accepted"
        )


def test_export_rejects_binary_content(
    tmp_path,
):
    try:
        exporter(
            tmp_path
        ).export(
            b"data",
            "json",
            "report",
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Rendered report content "
            "must be text"
        )

    else:
        raise AssertionError(
            "Binary content accepted"
        )


def test_export_overwrites_existing_target_atomically(
    tmp_path,
):
    instance = exporter(
        tmp_path
    )

    first = instance.export(
        "first\n",
        "json",
        "report",
    )

    second = instance.export(
        "second\n",
        "json",
        "report",
    )

    assert first == second

    assert second.read_text(
        encoding="utf-8"
    ) == "second\n"


def test_atomic_export_leaves_no_temp_files(
    tmp_path,
):
    output = (
        tmp_path
        / "reports"
    )

    ReportExporter(
        output
    ).export(
        "{}\n",
        "json",
        "report",
    )

    leftovers = [
        path.name
        for path in output.iterdir()
        if path.name.startswith(
            ".report_"
        )
    ]

    assert leftovers == []


def test_basename_length_is_bounded(
    tmp_path,
):
    instance = exporter(
        tmp_path
    )

    target = instance.export(
        "{}\n",
        "json",
        "a" * 500,
    )

    assert len(
        target.stem
    ) == (
        instance.MAX_BASENAME_LENGTH
    )


def test_destination_stays_under_output_directory(
    tmp_path,
):
    output = (
        tmp_path
        / "reports"
    )

    instance = ReportExporter(
        output
    )

    target = instance.export(
        "{}\n",
        "json",
        "report",
    )

    assert (
        output.resolve()
        in target.parents
    )


def test_existing_unrelated_files_are_untouched(
    tmp_path,
):
    output = (
        tmp_path
        / "reports"
    )

    output.mkdir(
        parents=True
    )

    unrelated = (
        output
        / "keep.txt"
    )

    unrelated.write_text(
        "KEEP",
        encoding="utf-8",
    )

    ReportExporter(
        output
    ).export(
        "{}\n",
        "json",
        "report",
    )

    assert unrelated.read_text(
        encoding="utf-8"
    ) == "KEEP"


def test_exported_utf8_content_is_preserved(
    tmp_path,
):
    target = exporter(
        tmp_path
    ).export(
        "Revisión técnica\n",
        "markdown",
        "report",
    )

    assert target.read_text(
        encoding="utf-8"
    ) == "Revisión técnica\n"


def test_export_pdf_creates_expected_file(
    tmp_path,
):
    payload = (
        b"%PDF-1.4\n"
        + b"x" * 600
    )

    target = exporter(
        tmp_path
    ).export(
        payload,
        "pdf",
        "advanced-report",
    )

    assert target.name == (
        "advanced-report.pdf"
    )

    assert target.read_bytes() == payload


def test_pdf_export_requires_bytes(
    tmp_path,
):
    try:
        exporter(
            tmp_path
        ).export(
            "%PDF-invalid-text",
            "pdf",
            "report",
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Rendered PDF content "
            "must be bytes"
        )

    else:
        raise AssertionError(
            "Text PDF payload accepted"
        )


def test_pdf_export_requires_pdf_signature(
    tmp_path,
):
    try:
        exporter(
            tmp_path
        ).export(
            b"NOT-A-PDF",
            "pdf",
            "report",
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Invalid PDF payload"
        )

    else:
        raise AssertionError(
            "Invalid PDF payload accepted"
        )


def test_text_formats_still_reject_bytes(
    tmp_path,
):
    for output_format in (
        "json",
        "markdown",
    ):
        try:
            exporter(
                tmp_path
            ).export(
                b"binary",
                output_format,
                "report",
            )

        except ValueError as exc:
            assert str(
                exc
            ) == (
                "Rendered report content "
                "must be text"
            )

        else:
            raise AssertionError(
                "Binary text report accepted"
            )


def test_export_json_does_not_duplicate_existing_extension(
    tmp_path,
):

    target = exporter(
        tmp_path
    ).export(
        '{"ok": true}\n',
        "json",
        "soc_report.json",
    )

    assert target.name == (
        "soc_report.json"
    )


def test_export_markdown_does_not_duplicate_existing_extension(
    tmp_path,
):

    target = exporter(
        tmp_path
    ).export(
        "# Report\n",
        "markdown",
        "soc_report.md",
    )

    assert target.name == (
        "soc_report.md"
    )


def test_export_pdf_does_not_duplicate_existing_extension(
    tmp_path,
):

    target = exporter(
        tmp_path
    ).export(
        b"%PDF-1.4\n% test\n",
        "pdf",
        "soc_report.pdf",
    )

    assert target.name == (
        "soc_report.pdf"
    )


def test_export_preserves_different_existing_extension(
    tmp_path,
):

    target = exporter(
        tmp_path
    ).export(
        '{"ok": true}\n',
        "json",
        "report.exe",
    )

    assert target.name == (
        "report.exe.json"
    )
