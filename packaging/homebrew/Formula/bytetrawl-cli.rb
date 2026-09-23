class BytetrawlCli < Formula
  desc "Static application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/bytetrawl"
  url "https://github.com/everettjf/homebrew-tap/releases/download/bytetrawl-v1.1.16/bytetrawl-cli-1.1.16-aarch64-apple-darwin.tar.gz"
  sha256 "822d8bc6ba52003873bdeae906903f01af01cad00b85c1561130c016af285de7"
  license "Apache-2.0"

  depends_on arch: :arm64

  def install
    bin.install "bytetrawl-cli"
  end

  test do
    (testpath/"fixture.json").write('{"bytetrawl":true}')
    output = shell_output("#{bin}/bytetrawl-cli inspect #{testpath}/fixture.json --json")
    report = JSON.parse(output)
    assert_equal 1, report.fetch("schema_version")
    assert_equal false, report.dig("run", "partial")
  end
end
