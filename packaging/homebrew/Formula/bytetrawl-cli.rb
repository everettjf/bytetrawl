class BytetrawlCli < Formula
  desc "Static application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/bytetrawl"
  url "https://github.com/everettjf/homebrew-tap/releases/download/bytetrawl-v1.1.8/bytetrawl-cli-1.1.8-aarch64-apple-darwin.tar.gz"
  sha256 "8ac8f56e56bab205de297d7c1b3df6bc55d63c0980baaa1b3bc2f66798df8404"
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
