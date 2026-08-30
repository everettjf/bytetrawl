cask "bytetrawl" do
  version "1.1.5"
  sha256 "fa57f7595df1836c4f765043e65d53b48d93a53d8f6c1b85308e51e22712f6b2"

  url "https://github.com/everettjf/homebrew-tap/releases/download/bytetrawl-v#{version}/ByteTrawl-#{version}-macos.zip"
  name "ByteTrawl"
  desc "Application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/bytetrawl"

  depends_on macos: :ventura
  depends_on arch: :arm64

  app "ByteTrawl.app"

  zap trash: "~/Library/Application Support/ByteTrawl"
end
