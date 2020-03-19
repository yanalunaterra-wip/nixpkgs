{ lib
, fetchFromGitHub
, buildGoModule
}:

buildGoModule rec {
  pname = "acme-dns";
  version = "0.8";

  src = fetchFromGitHub {
    owner = "joohoi";
    repo = pname;
    rev = "v${version}";
    hash = "sha256:1v2k8kfws4a0hmi1almmdjd6rdihbr3zifji623wwnml00mjrplf";
  };

  modSha256 = "08y2v0na856wmc7mwjlnqqlbd22p7a7ichzqgcbl8zdzy6b7cbn8";

  meta = {
    description = "Limited DNS server to handle ACME DNS challenges easily and securely";
    inherit (src.meta) homepage;
    changelog = "${meta.homepage}/blob/v${version}/README.md#changelog";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ emily ];
    platforms = lib.platforms.all;
  };
}
