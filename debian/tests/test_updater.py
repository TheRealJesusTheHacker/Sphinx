"""The list updater (Phase 2): the spec's update rules, enforced —
HTTPS only with hand-followed, per-hop-vetted redirects; every
source parsed and gated; the merged set gated on unique domains;
the swap atomic; and failure all-or-nothing (nothing swapped,
'last updated' untouched), because a half-fresh set reported as an
update would be a lie about what is in force."""
import email.message
import urllib.error

from sphinx_deb.core.store import Store
from sphinx_deb.core.updater import ListUpdater, download
from sphinx_deb.core.validation import redirect_target


def _body(count, start=0, fmt="0.0.0.0 ads{}.example.com"):
    return ("\n".join(fmt.format(i) for i in range(start, start + count)) + "\n").encode()


def _store(tmp_path):
    bundled = tmp_path / "bundled.txt"
    bundled.write_text(_body(1500).decode())
    return Store(tmp_path / "state", bundled)


class FakeDownload:
    def __init__(self, by_url):
        self.by_url = by_url
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        return self.by_url.get(url)


def _both_good(store, overlap=0):
    first, second = store.sources()
    return {
        first.url: _body(1200),
        second.url: _body(1200, start=1200 - overlap),
    }


def test_happy_path_swaps_both_and_records_the_update(tmp_path):
    store = _store(tmp_path)
    result = ListUpdater(store, download_fn=FakeDownload(_both_good(store, overlap=200))).update_all(777)
    assert result.success
    assert result.total_domains == 2200  # 1200 + 1200 - 200 shared, counted once
    status = store.status()
    assert status.using_downloaded is True
    assert status.active_domains == 2200
    assert status.last_updated_ms == 777
    assert all(o.refreshed for o in result.outcomes)


def test_one_failed_source_fails_the_whole_update_and_swaps_nothing(tmp_path):
    store = _store(tmp_path)
    # A previous good update is in force.
    assert ListUpdater(store, download_fn=FakeDownload(_both_good(store))).update_all(100).success
    before = {
        source.url: store.saved_file(source).read_bytes() for source in store.sources()
    }
    # Now one source goes down; the other's fresh bytes must NOT land.
    first, second = store.sources()
    failing = {first.url: _body(1300, start=5000), second.url: None}
    result = ListUpdater(store, download_fn=FakeDownload(failing)).update_all(200)
    assert not result.success
    assert store.last_updated_ms() == 100  # untouched
    for source in store.sources():
        assert store.saved_file(source).read_bytes() == before[source.url]
    outcomes = {o.source.url: o for o in result.outcomes}
    assert outcomes[first.url].refreshed  # it downloaded fine — and still wasn't swapped in
    assert not outcomes[second.url].refreshed


def test_a_garbage_source_fails_the_whole_update(tmp_path):
    store = _store(tmp_path)
    first, second = store.sources()
    bad = {first.url: _body(1200), second.url: b"<html>404 not found</html>"}
    result = ListUpdater(store, download_fn=FakeDownload(bad)).update_all(50)
    assert not result.success
    assert store.last_updated_ms() == 0
    assert store.saved_file(first) is None  # nothing written at all
    assert store.status().using_downloaded is False  # the bundled floor holds


def test_first_run_failure_leaves_the_bundled_floor(tmp_path):
    store = _store(tmp_path)
    result = ListUpdater(store, download_fn=FakeDownload({})).update_all(1)
    assert not result.success
    assert store.load_effective_lists().is_blocked("ads0.example.com")


def test_custom_entries_survive_an_update(tmp_path):
    store = _store(tmp_path)
    store.save_custom_block_entries(["mine.example.net"])
    assert ListUpdater(store, download_fn=FakeDownload(_both_good(store))).update_all(9).success
    lists = store.load_effective_lists()
    assert lists.is_blocked("mine.example.net")
    assert lists.is_blocked("ads0.example.com")


# --- the download itself: HTTPS and redirect discipline ---------------


class _Response:
    def __init__(self, body):
        self._body = body

    def read(self, _n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    """Routes by URL: bytes → 200 with that body; ("redirect", loc)
    → an HTTPError carrying the Location, as urllib raises for a
    redirect the no-redirect opener refuses to follow."""

    def __init__(self, routes):
        self.routes = routes
        self.seen = []

    def open(self, request, timeout=None):
        url = request.full_url
        self.seen.append(url)
        route = self.routes.get(url)
        if route is None:
            raise urllib.error.URLError("no route (fake)")
        if isinstance(route, tuple):
            headers = email.message.Message()
            headers["Location"] = route[1]
            raise urllib.error.HTTPError(url, route[0], "redirect", headers, None)
        return _Response(route)


def test_download_refuses_plain_http_outright():
    opener = FakeOpener({})
    assert download("http://example.com/hosts", opener=opener) is None
    assert opener.seen == []  # never even attempted


def test_download_follows_an_https_redirect_to_another_host():
    opener = FakeOpener(
        {
            "https://a.example/hosts": (302, "https://cdn.example.net/hosts"),
            "https://cdn.example.net/hosts": b"0.0.0.0 ads.example.com\n",
        }
    )
    assert download("https://a.example/hosts", opener=opener) == b"0.0.0.0 ads.example.com\n"
    assert opener.seen == ["https://a.example/hosts", "https://cdn.example.net/hosts"]


def test_download_refuses_a_redirect_that_downgrades_to_http():
    opener = FakeOpener(
        {"https://a.example/hosts": (301, "http://a.example/hosts")}
    )
    assert download("https://a.example/hosts", opener=opener) is None
    assert opener.seen == ["https://a.example/hosts"]  # the bad hop was never followed


def test_download_gives_up_after_the_redirect_cap():
    routes = {
        f"https://a.example/{i}": (302, f"https://a.example/{i + 1}") for i in range(10)
    }
    opener = FakeOpener(routes)
    assert download("https://a.example/0", opener=opener) is None
    assert len(opener.seen) == 6  # the original + MAX_REDIRECTS follows


def test_redirect_target_vetting():
    assert (
        redirect_target("https://a.example/x", "https://b.example/y")
        == "https://b.example/y"
    )
    assert redirect_target("https://a.example/x", "http://a.example/y") is None
    assert redirect_target("https://a.example/x", "//evil.example/y") == "https://evil.example/y"
    assert redirect_target("https://a.example/x", "/same-host") == "https://a.example/same-host"
    assert redirect_target("https://a.example/x", None) is None
    assert redirect_target("https://a.example/x", "  ") is None
