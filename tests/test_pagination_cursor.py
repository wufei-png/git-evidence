from __future__ import annotations

import unittest
from io import BytesIO
from typing import Self
from unittest.mock import patch
from urllib.error import HTTPError

from git_evidence.providers.transport import (
    HEADER_CURSOR_PAGINATION,
    LINK_PAGINATION,
    ApiError,
    ApiResponse,
    MappingTransport,
    PaginationCursor,
    UrllibTransport,
    paginate,
)


def two_page_transport() -> MappingTransport:
    return MappingTransport(
        {
            "/a": ApiResponse(
                "https://example.test/a?page=1",
                200,
                {"Link": '<https://example.test/a?page=2>; rel="next"'},
                [{"id": "a1"}],
            ),
            "https://example.test/a?page=2": ApiResponse(
                "https://example.test/a?page=2",
                200,
                {},
                [],
            ),
            "/b": ApiResponse(
                "https://example.test/b?page=1",
                200,
                {"Link": '<https://example.test/b?page=2>; rel="next"'},
                [{"id": "b1"}],
            ),
            "https://example.test/b?page=2": ApiResponse(
                "https://example.test/b?page=2",
                200,
                {},
                [],
            ),
        }
    )


class PaginationCursorTests(unittest.TestCase):
    def test_each_step_performs_at_most_one_request_and_can_be_interleaved(
        self,
    ) -> None:
        transport = two_page_transport()
        first = PaginationCursor(transport, "/a", per_page=1)
        second = PaginationCursor(transport, "/b", per_page=1)

        for cursor in (first, second, first, second):
            before = len(transport.calls)
            cursor.step()
            self.assertEqual(len(transport.calls), before + 1)

        self.assertTrue(first.done)
        self.assertTrue(second.done)
        self.assertEqual(first.result().items, [{"id": "a1"}])
        self.assertEqual(second.result().items, [{"id": "b1"}])
        self.assertEqual(
            [path for path, _ in transport.calls],
            [
                "/a",
                "/b",
                "https://example.test/a?page=2",
                "https://example.test/b?page=2",
            ],
        )

    def test_paginate_wrapper_is_behaviorally_equivalent_to_completed_cursor(
        self,
    ) -> None:
        cursor_transport = two_page_transport()
        cursor = PaginationCursor(cursor_transport, "/a", per_page=1)
        while not cursor.done:
            cursor.step()

        wrapper = paginate(two_page_transport(), "/a", per_page=1)
        self.assertEqual(cursor.result(), wrapper)

    def test_cursor_lifecycle_and_max_page_outcome_are_explicit(self) -> None:
        cursor = PaginationCursor(two_page_transport(), "/a", per_page=1, max_pages=1)
        with self.assertRaisesRegex(RuntimeError, "has not completed"):
            cursor.result()
        cursor.step()
        result = cursor.result()
        self.assertFalse(result.complete)
        self.assertEqual(result.pages, 1)
        self.assertEqual(
            result.diagnostics,
            {
                "budget_exhausted": True,
                "pagination": {
                    "complete": False,
                    "outcome": "max_pages_reached",
                },
            },
        )
        with self.assertRaisesRegex(RuntimeError, "already complete"):
            cursor.step()

    def test_failed_step_is_terminal_and_preserves_original_error(self) -> None:
        transport = MappingTransport(
            {
                "/items": ApiResponse(
                    "https://example.test/items?page=1", 200, {}, {"bad": True}
                )
            }
        )
        cursor = PaginationCursor(transport, "/items")

        with self.assertRaisesRegex(ApiError, "expected a JSON array") as first:
            cursor.step()
        self.assertTrue(cursor.done)
        self.assertEqual(cursor.pages, 0)
        self.assertEqual(cursor.items, [])
        with self.assertRaises(ApiError) as second:
            cursor.step()
        self.assertIs(second.exception, first.exception)
        with self.assertRaises(ApiError) as result_error:
            cursor.result()
        self.assertIs(result_error.exception, first.exception)

    def test_headerless_full_page_continues_after_explicit_page_jump(self) -> None:
        transport = MappingTransport(
            {
                "/items": [
                    ApiResponse(
                        "https://example.test/items?page=1",
                        200,
                        {"x-next-page": "5"},
                        [{"id": 1}],
                    ),
                    ApiResponse(
                        "https://example.test/items?page=5",
                        200,
                        {},
                        [{"id": 5}],
                    ),
                    ApiResponse(
                        "https://example.test/items?page=6",
                        200,
                        {},
                        [],
                    ),
                ],
            }
        )

        result = paginate(transport, "/items", per_page=1)

        self.assertTrue(result.complete)
        self.assertEqual(result.items, [{"id": 1}, {"id": 5}])
        self.assertEqual([params["page"] for _, params in transport.calls], [1, 5, 6])

    def test_urllib_retry_is_one_physical_attempt_per_cursor_step(self) -> None:
        retry_error = HTTPError(
            "https://example.test/items",
            429,
            "rate limited",
            {"Retry-After": "0"},
            BytesIO(b"rate limited"),
        )

        class JsonResponse:
            status = 200

            def __init__(self) -> None:
                self.headers: dict[str, str] = {}

            def __enter__(self) -> Self:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, size: int = -1) -> bytes:
                body = b"[]"
                return body if size < 0 else body[:size]

        transport = UrllibTransport(
            "https://example.test",
            max_retries=1,
            retry_backoff=0,
            retry_jitter=0,
            sleep_fn=lambda _: None,
        )
        cursor = PaginationCursor(transport, "/items")
        with patch(
            "git_evidence.providers.transport.urlopen",
            side_effect=[retry_error, JsonResponse()],
        ) as urlopen:
            cursor.step()
            self.assertEqual(urlopen.call_count, 1)
            self.assertFalse(cursor.done)
            cursor.step()
            self.assertEqual(urlopen.call_count, 2)
        self.assertTrue(cursor.done)
        self.assertEqual(transport.metrics()["retry_count"], 1)

    def test_cursor_snapshots_parameters_and_result_containers(self) -> None:
        labels = ["one"]
        transport = MappingTransport(
            {"/items": ApiResponse("https://example.test/items?page=1", 200, {}, [])}
        )
        cursor = PaginationCursor(transport, "/items", {"labels": labels})
        labels.append("two")
        cursor.step()
        self.assertEqual(transport.calls[0][1]["labels"], ["one"])

        result = cursor.result()
        result.items.append({"id": "external"})
        self.assertEqual(
            result.diagnostics,
            {
                "pagination": {
                    "complete": True,
                    "outcome": "documented_short_page",
                }
            },
        )
        self.assertEqual(cursor.result().items, [])

    def test_provider_strategies_record_their_own_completion_proof(self) -> None:
        full_page = [{"id": index} for index in range(2)]
        link_result = paginate(
            MappingTransport(
                {
                    "/items": ApiResponse(
                        "https://example.test/items", 200, {}, full_page
                    )
                }
            ),
            "/items",
            per_page=2,
            strategy=LINK_PAGINATION,
        )
        self.assertEqual(link_result.pages, 1)
        self.assertEqual(
            link_result.diagnostics,
            {"pagination": {"complete": True, "outcome": "link_exhausted"}},
        )

        cursor_result = paginate(
            MappingTransport(
                {
                    "/items": [
                        ApiResponse(
                            "https://example.test/items?page=1",
                            200,
                            {"x-next-page": "2"},
                            full_page,
                        ),
                        ApiResponse(
                            "https://example.test/items?page=2",
                            200,
                            {},
                            [],
                        ),
                    ]
                }
            ),
            "/items",
            per_page=2,
            strategy=HEADER_CURSOR_PAGINATION,
        )
        self.assertEqual(cursor_result.pages, 2)
        self.assertEqual(
            cursor_result.diagnostics,
            {"pagination": {"complete": True, "outcome": "cursor_exhausted"}},
        )


if __name__ == "__main__":
    unittest.main()
