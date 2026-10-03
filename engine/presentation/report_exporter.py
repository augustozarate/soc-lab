import os
import re
import tempfile
from pathlib import Path


class ReportExporter:

    EXTENSIONS = {
        "json": ".json",
        "markdown": ".md",
        "pdf": ".pdf",
    }

    MAX_BASENAME_LENGTH = 96

    def __init__(
        self,
        output_directory,
    ):
        self.output_directory = (
            Path(
                output_directory
            )
            .expanduser()
            .resolve()
        )

    def export(
        self,
        content,
        output_format,
        basename,
    ):
        extension = self._extension(
            output_format
        )

        safe_basename = (
            self._normalize_basename(
                basename
            )
        )

        directory = (
            self.output_directory
        )

        directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        filename = (
            safe_basename
            if safe_basename.lower().endswith(
                extension
            )
            else (
                safe_basename
                + extension
            )
        )

        destination = (
            directory
            / filename
        ).resolve()

        self._assert_within_output_directory(
            destination
        )

        payload = self._normalize_content(
            content,
            output_format,
        )

        self._atomic_write(
            destination,
            payload,
        )

        return destination

    def _extension(
        self,
        output_format,
    ):
        normalized = str(
            output_format
            if output_format is not None
            else ""
        ).strip().lower()

        try:
            return self.EXTENSIONS[
                normalized
            ]

        except KeyError as exc:
            raise ValueError(
                "Unsupported report export format"
            ) from exc

    def _normalize_basename(
        self,
        value,
    ):
        raw = str(
            value
            if value is not None
            else ""
        ).strip()

        if not raw:
            raise ValueError(
                "Report filename is required"
            )

        raw = raw.replace(
            "\\",
            "/",
        )

        if "/" in raw:
            raise ValueError(
                "Report filename must not "
                "contain path separators"
            )

        if raw in {
            ".",
            "..",
        }:
            raise ValueError(
                "Invalid report filename"
            )

        normalized = re.sub(
            r"[^A-Za-z0-9._-]+",
            "-",
            raw,
        )

        normalized = normalized.strip(
            ".-_"
        )

        if not normalized:
            raise ValueError(
                "Invalid report filename"
            )

        normalized = normalized[
            :self.MAX_BASENAME_LENGTH
        ]

        return normalized

    @staticmethod
    def _normalize_content(
        content,
        output_format,
    ):
        normalized = str(
            output_format
            if output_format is not None
            else ""
        ).strip().lower()

        if normalized == "pdf":
            if not isinstance(
                content,
                bytes,
            ):
                raise ValueError(
                    "Rendered PDF content "
                    "must be bytes"
                )

            if not content.startswith(
                b"%PDF-"
            ):
                raise ValueError(
                    "Invalid PDF payload"
                )

            return content

        if not isinstance(
            content,
            str,
        ):
            raise ValueError(
                "Rendered report content "
                "must be text"
            )

        return content

    def _assert_within_output_directory(
        self,
        destination,
    ):
        directory = (
            self.output_directory
        )

        try:
            destination.relative_to(
                directory
            )

        except ValueError as exc:
            raise ValueError(
                "Report export path escapes "
                "output directory"
            ) from exc

    def _atomic_write(
        self,
        destination,
        content,
    ):
        directory = (
            self.output_directory
        )

        fd = None
        temporary_path = None

        try:
            binary = isinstance(
                content,
                bytes,
            )

            fd, temporary_name = (
                tempfile.mkstemp(
                    dir=directory,
                    prefix=".report_",
                    suffix=".tmp",
                    text=not binary,
                )
            )

            temporary_path = Path(
                temporary_name
            )

            if binary:
                with os.fdopen(
                    fd,
                    "wb",
                ) as handle:
                    fd = None

                    handle.write(
                        content
                    )

                    handle.flush()

                    os.fsync(
                        handle.fileno()
                    )

            else:
                with os.fdopen(
                    fd,
                    "w",
                    encoding="utf-8",
                    newline="\n",
                ) as handle:
                    fd = None

                    handle.write(
                        content
                    )

                    handle.flush()

                    os.fsync(
                        handle.fileno()
                    )

            os.replace(
                temporary_path,
                destination,
            )

            temporary_path = None

        finally:
            if fd is not None:
                os.close(
                    fd
                )

            if (
                temporary_path
                is not None
                and temporary_path.exists()
            ):
                temporary_path.unlink()
