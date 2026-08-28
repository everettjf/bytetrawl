cask "bytetrawl" do
  version "1.1.2"
  sha256 "5c33eaa2fbc85aa6142a52a0024742f7a2b228ab8c70dfe57b3240c4841490d3"

  url "https://github.com/everettjf/homebrew-tap/releases/download/bytetrawl-v#{version}/ByteTrawl-#{version}-macos.zip"
  name "ByteTrawl"
  desc "Application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/bytetrawl"

  depends_on macos: :ventura
  depends_on arch: :arm64

  app "ByteTrawl.app"

  zap trash: "~/Library/Application Support/ByteTrawl"
end
