class BytetrawlCli < Formula
  desc "Static application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/bytetrawl"
  url "https://github.com/everettjf/homebrew-tap/releases/download/bytetrawl-v1.0.0/bytetrawl-cli-1.0.0-aarch64-apple-darwin.tar.gz"
  sha256 "ad2a485514841c5b0e2a7007ba40633663ee3f342a6080b4988bf609095df7d9"
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
