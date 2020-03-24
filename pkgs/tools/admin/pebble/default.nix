{ buildGoModule
, fetchFromGitHub
, lib
}:

let
  version = "v2.3.0";
  pname = "pebble";
in buildGoModule {
  inherit pname version;

  src = fetchFromGitHub {
    owner = "letsencrypt";
    repo = pname;
    rev = version;
    sha256 = "1piwzzfqsdx6s2niczzp4mf4r3qn9nfdgpn7882g52cmmm0vzks2";
  };

  modSha256 = "0n5s5y2gnz4lrla7a52lgmnzkqda1dblhnmv069zcvdfwmf79ac9";

  meta = {
    homepage = "https://github.com/letsencrypt/pebble";
    description = "A miniature version of Boulder, Pebble is a small RFC 8555 ACME test server not suited for a production CA";
    license = [ lib.licenses.mpl20 ];
    maintainers = with lib.maintainers; [ emily ];
  };
}
