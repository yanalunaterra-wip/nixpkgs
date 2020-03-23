{ lib, nodes, pkgs, ... }:

let
  acme-ca = nodes.acme.config.test-support.acme.caCert;
in

{
  security.acme.acceptTerms = true;
  security.acme.email = "webmaster@example.com";

  security.pki.certificateFiles = [ acme-ca ];
}
