cask "bytetrawl" do
  version "1.1.8"
  sha256 "eb97b253287490cda2356e8db13637fd0a31ba5b9cee131929cab4ec44a82a5e"

  url "https://github.com/everettjf/homebrew-tap/releases/download/bytetrawl-v#{version}/ByteTrawl-#{version}-macos.zip"
  name "ByteTrawl"
  desc "Application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/bytetrawl"

  depends_on macos: :ventura
  depends_on arch: :arm64

  app "ByteTrawl.app"

  zap trash: "~/Library/Application Support/ByteTrawl"
end
