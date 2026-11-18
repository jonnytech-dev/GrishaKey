from core import match


class Test_Match:
    def test_same_site(self):
        assert match.url_matches("https://github.com", "https://github.com/login")

    def test_www_ignored(self):
        assert match.url_matches("https://www.github.com", "https://github.com/")
        assert match.url_matches("github.com", "https://www.github.com/")

    def test_subdomain_of_saved(self):
        assert match.url_matches("https://github.com", "https://gist.github.com/")

    def test_saved_subdomain_does_not_match_parent(self):
        assert not match.url_matches("https://accounts.google.com", "https://google.com/")

    def test_lookalikes_never_match(self):
        assert not match.url_matches("https://github.com", "https://githuub.com/")
        assert not match.url_matches("https://github.com", "https://github.com.evil.io/")
        assert not match.url_matches("https://github.com", "https://notgithub.com/")

    def test_case_and_port(self):
        assert match.url_matches("https://GitHub.com", "https://github.com:8443/x")

    def test_non_web_pages(self):
        assert not match.url_matches("https://github.com", "chrome://settings")
        assert not match.url_matches("https://github.com", "file:///C:/github.com")

    def test_empty(self):
        assert not match.url_matches("", "https://github.com")
        assert not match.url_matches("https://github.com", "")
